import Summary from '../models/Summary.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { cacheService } from '../services/cache.service.js';
import { metricsCollector } from '../utils/metrics.js';
import { eventEmitter } from '../events/events.js';
import mongoose from 'mongoose';
import { marked } from 'marked';
import DOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';

class FormattingService {
    constructor() {
        this.model = Summary;
        this.defaultCacheTTL = 300; // 5 minutes
        this.formattingStyles = this.initializeFormattingStyles();
    }

    /**
     * Apply formatting to summary content
     */
    async applyFormatting(summaryId, userId, formatType, content, options) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const summary = await this.model.findById(summaryId).session(session);
            if (!summary) {
                throw new AppError('Summary not found', 404);
            }

            // Check access
            if (!this.checkAccess(summary, userId)) {
                throw new AppError('Access denied', 403);
            }

            // Apply formatting
            const formattedContent = this.formatContent(content, formatType, options);

            // Create new version
            const newVersion = {
                versionNumber: summary.versions.length + 1,
                content: formattedContent,
                title: summary.title,
                changeType: 'formatting',
                isActive: true,
                createdAt: new Date(),
                stats: {
                    characterCount: formattedContent.length,
                    wordCount: formattedContent.trim().split(/\s+/).length,
                    paragraphCount: formattedContent.split('\n\n').length,
                    sentenceCount: formattedContent.split(/[.!?]+/).length - 1,
                },
                formatting: {
                    type: formatType,
                    options,
                    appliedBy: userId,
                    appliedAt: new Date(),
                },
            };

            // Deactivate previous versions
            summary.versions.forEach(v => (v.isActive = false));
            summary.versions.push(newVersion);

            // Limit versions
            if (summary.versions.length > summary.settings.maxVersions) {
                summary.versions = summary.versions.slice(-summary.settings.maxVersions);
            }

            // Update content and metadata
            summary.content = formattedContent;
            summary.metadata.wordCount = formattedContent.trim().split(/\s+/).length;
            summary.metadata.characterCount = formattedContent.length;
            summary.metadata.lastFormattedBy = { userId, timestamp: new Date() };

            const updatedSummary = await summary.save({ session });

            // Update user stats
            await this.updateUserStats(userId, 'formatting', session);

            await session.commitTransaction();

            // Clear cache
            await this.clearSummaryCache(summaryId, userId);

            // Schedule async processing
            this.scheduleAsyncProcessing(summaryId, formattedContent);

            return formattedContent;
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Formatting failed for summary ${summaryId}:`, error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    /**
     * Preview formatting without saving
     */
    async previewFormatting(summaryId, formatType, content, options) {
        try {
            const summary = await this.model.findById(summaryId).select('_id').lean();
            if (!summary) {
                throw new AppError('Summary not found', 404);
            }

            const formattedContent = this.formatContent(content, formatType, options);
            return {
                formattedContent,
                stats: {
                    characterCount: formattedContent.length,
                    wordCount: formattedContent.trim().split(/\s+/).length,
                    paragraphCount: formattedContent.split('\n\n').length,
                    sentenceCount: formattedContent.split(/[.!?]+/).length - 1,
                },
            };
        } catch (error) {
            logger.error(`Formatting preview failed for summary ${summaryId}:`, error);
            throw error;
        }
    }

    /**
     * Get available formatting styles
     */
    async getFormattingStyles(summaryId, userId) {
        try {
            const summary = await this.model.findById(summaryId).select('_id userId').lean();
            if (!summary) {
                throw new AppError('Summary not found', 404);
            }

            if (!this.checkAccess(summary, userId)) {
                throw new AppError('Access denied', 403);
            }

            return this.formattingStyles;
        } catch (error) {
            logger.error(`Formatting styles fetch failed for summary ${summaryId}:`, error);
            throw error;
        }
    }

    /**
     * Bulk apply formatting
     */
    async bulkApplyFormatting(summaryIds, userId, formatType, options) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const query = { _id: { $in: summaryIds }, userId, 'flags.isDeleted': false };
            const summaries = await this.model.find(query).session(session);

            if (summaries.length === 0) {
                throw new AppError('No summaries found', 404);
            }

            if (summaries.length !== summaryIds.length) {
                throw new AppError('Some summaries not found or access denied', 403);
            }

            const formattedSummaries = await Promise.all(
                summaries.map(async summary => {
                    const formattedContent = this.formatContent(summary.content, formatType, options);
                    const newVersion = {
                        versionNumber: summary.versions.length + 1,
                        content: formattedContent,
                        title: summary.title,
                        changeType: 'formatting',
                        isActive: true,
                        createdAt: new Date(),
                        stats: {
                            characterCount: formattedContent.length,
                            wordCount: formattedContent.trim().split(/\s+/).length,
                            paragraphCount: formattedContent.split('\n\n').length,
                            sentenceCount: formattedContent.split(/[.!?]+/).length - 1,
                        },
                        formatting: {
                            type: formatType,
                            options,
                            appliedBy: userId,
                            appliedAt: new Date(),
                        },
                    };

                    summary.versions.forEach(v => (v.isActive = false));
                    summary.versions.push(newVersion);
                    summary.content = formattedContent;
                    summary.metadata.wordCount = formattedContent.trim().split(/\s+/).length;
                    summary.metadata.characterCount = formattedContent.length;
                    summary.metadata.lastFormattedBy = { userId, timestamp: new Date() };

                    return summary.save({ session });
                })
            );

            // Update user stats
            await this.updateUserStats(userId, 'bulk_formatting', session);

            await session.commitTransaction();

            // Clear cache
            await Promise.all(summaryIds.map(id => this.clearSummaryCache(id, userId)));

            return {
                requested: summaryIds.length,
                matched: summaries.length,
                modified: formattedSummaries.length,
            };
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk formatting failed for user ${userId}:`, error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    /**
     * Get formatting history
     */
    async getFormattingHistory(summaryId, userId, { page, limit }) {
        try {
            const summary = await this.model.findById(summaryId).lean();
            if (!summary) {
                throw new AppError('Summary not found', 404);
            }

            if (!this.checkAccess(summary, userId)) {
                throw new AppError('Access denied', 403);
            }

            const skip = (page - 1) * limit;
            const formattingVersions = summary.versions
                .filter(v => v.formatting)
                .sort((a, b) => b.createdAt - a.createdAt)
                .slice(skip, skip + limit)
                .map(v => ({
                    formatId: v._id,
                    versionNumber: v.versionNumber,
                    content: v.content,
                    formatType: v.formatting.type,
                    options: v.formatting.options,
                    appliedBy: v.formatting.appliedBy,
                    appliedAt: v.formatting.appliedAt,
                }));

            const totalCount = summary.versions.filter(v => v.formatting).length;
            const totalPages = Math.ceil(totalCount / limit);

            return {
                history: formattingVersions,
                pagination: {
                    page,
                    limit,
                    totalCount,
                    totalPages,
                    hasNext: page < totalPages,
                    hasPrev: page > 1,
                },
            };
        } catch (error) {
            logger.error(`Formatting history fetch failed for summary ${summaryId}:`, error);
            throw error;
        }
    }

    /**
     * Revert to previous formatting
     */
    async revertFormatting(summaryId, userId, formatId) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const summary = await this.model.findById(summaryId).session(session);
            if (!summary) {
                throw new AppError('Summary not found', 404);
            }

            if (!this.checkAccess(summary, userId)) {
                throw new AppError('Access denied', 403);
            }

            const formatVersion = summary.versions.find(v => v._id.toString() === formatId && v.formatting);
            if (!formatVersion) {
                throw new AppError('Format version not found', 404);
            }

            summary.versions.forEach(v => (v.isActive = false));
            formatVersion.isActive = true;
            summary.content = formatVersion.content;
            summary.metadata.wordCount = formatVersion.stats.wordCount;
            summary.metadata.characterCount = formatVersion.stats.characterCount;
            summary.metadata.lastFormattedBy = { userId, timestamp: new Date() };

            const updatedSummary = await summary.save({ session });

            await this.updateUserStats(userId, 'revert_formatting', session);

            await session.commitTransaction();

            await this.clearSummaryCache(summaryId, userId);

            return updatedSummary;
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Formatting revert failed for summary ${summaryId}:`, error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    // Helper Methods

    /**
     * Format content based on type
     */
    formatContent(content, formatType, options) {
        switch (formatType) {
            case 'markdown':
                return this.formatMarkdown(content, options);
            case 'html':
                return this.formatHTML(content, options);
            case 'custom':
                return this.formatCustom(content, options);
            default:
                throw new AppError('Invalid format type', 400);
        }
    }

    /**
     * Format markdown content
     */
    formatMarkdown(content, options) {
        try {
            const renderer = options.renderer ? new marked.Renderer() : undefined;
            const markedOptions = {
                gfm: true,
                breaks: options.breaks || false,
                renderer,
            };
            let formatted = marked(content, markedOptions);
            if (options.sanitize) {
                const { window } = new JSDOM('');
                formatted = DOMPurify(window).sanitize(formatted);
            }
            return formatted;
        } catch (error) {
            logger.error('Markdown formatting failed:', error);
            throw new AppError('Failed to format markdown', 500);
        }
    }

    /**
     * Format HTML content
     */
    formatHTML(content, options) {
        try {
            let formatted = content;
            if (options.sanitize) {
                const { window } = new JSDOM('');
                formatted = DOMPurify(window).sanitize(content, {
                    ALLOWED_TAGS: options.allowedTags || ['p', 'b', 'i', 'ul', 'li', 'h1', 'h2', 'h3'],
                });
            }
            return formatted;
        } catch (error) {
            logger.error('HTML formatting failed:', error);
            throw new AppError('Failed to format HTML', 500);
        }
    }

    /**
     * Format custom styles
     */
    formatCustom(content, options) {
        try {
            const { styleName, parameters } = options;
            const style = this.formattingStyles.custom.find(s => s.name === styleName);
            if (!style) {
                throw new AppError('Invalid custom style', 400);
            }

            let formatted = content;
            if (style.transform) {
                formatted = style.transform(content, parameters);
            }
            return formatted;
        } catch (error) {
            logger.error('Custom formatting failed:', error);
            throw error;
        }
    }

    /**
     * Initialize formatting styles
     */
    initializeFormattingStyles() {
        return {
            markdown: {
                name: 'markdown',
                description: 'GitHub Flavored Markdown formatting',
                options: ['gfm', 'breaks', 'sanitize', 'renderer'],
            },
            html: {
                name: 'html',
                description: 'HTML formatting with sanitization',
                options: ['sanitize', 'allowedTags'],
            },
            custom: [
                {
                    name: 'uppercase',
                    description: 'Convert text to uppercase',
                    transform: (content) => content.toUpperCase(),
                },
                {
                    name: 'bullet-points',
                    description: 'Convert paragraphs to bullet points',
                    transform: (content) => content.split('\n').map(line => `- ${line}`).join('\n'),
                },
            ],
        };
    }

    /**
     * Check access permissions
     */
    checkAccess(summary, userId) {
        if (summary.sharing?.isPublic) return true;
        if (summary.userId === userId) return true;
        if (summary.sharing?.collaborators?.some(c => c.userId === userId && c.status === 'accepted')) {
            return true;
        }
        return false;
    }

    /**
     * Update user stats
     */
    async updateUserStats(userId, action, session) {
        try {
            metricsCollector.increment(`formatting.${action}`, { userId });
        } catch (error) {
            logger.error(`Failed to update user stats for ${userId}:`, error);
        }
    }

    /**
     * Clear summary cache
     */
    async clearSummaryCache(summaryId, userId) {
        try {
            const patterns = [
                `summary:${summaryId}:*`,
                `summaries:${userId}:*`,
                `formatting_history:${summaryId}:*`,
            ];
            await Promise.all(patterns.map(pattern => cacheService.deletePattern(pattern)));
        } catch (error) {
            logger.error(`Cache clearing failed for summary ${summaryId}:`, error);
        }
    }

    /**
     * Schedule async processing
     */
    scheduleAsyncProcessing(summaryId, content) {
        setTimeout(async () => {
            try {
                // Placeholder for async tasks (e.g., quality analysis)
                logger.info(`Async processing completed for summary ${summaryId}`);
            } catch (error) {
                logger.error(`Async processing failed for summary ${summaryId}:`, error);
            }
        }, 1000);
    }
}

export default FormattingService;