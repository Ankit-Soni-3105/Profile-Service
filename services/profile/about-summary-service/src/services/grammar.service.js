import Summary from '../models/Summary.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { cacheService } from '../services/cache.service.js';
import { metricsCollector } from '../utils/metrics.js';
import { eventEmitter } from '../events/events.js';
import mongoose from 'mongoose';
import grammarApi from '../services/grammar.api.js'; // Hypothetical grammar API client

class GrammarService {
    constructor() {
        this.model = Summary;
        this.defaultCacheTTL = 300; // 5 minutes
    }

    /**
     * Check grammar and style for summary content
     */
    async checkGrammar(summaryId, userId, language, checkType) {
        try {
            const summary = await this.model.findById(summaryId).lean();
            if (!summary) {
                throw new AppError('Summary not found', 404);
            }

            // Check access
            if (!this.checkAccess(summary, userId)) {
                throw new AppError('Access denied', 403);
            }

            // Check grammar
            const grammarIssues = await grammarApi.check({
                text: summary.content,
                language,
                checkType,
            });

            // Store issues
            const session = await mongoose.startSession();
            session.startTransaction();
            try {
                const updatedSummary = await this.model.findById(summaryId).session(session);
                updatedSummary.quality = updatedSummary.quality || { issues: [] };
                updatedSummary.quality.issues.push(
                    ...grammarIssues.map(i => ({
                        issueId: mongoose.Types.ObjectId(),
                        type: i.type,
                        description: i.description,
                        suggestion: i.suggestion,
                        position: i.position,
                        createdAt: new Date(),
                        status: 'pending',
                        createdBy: userId,
                    }))
                );

                // Limit issues
                if (updatedSummary.quality.issues.length > 50) {
                    updatedSummary.quality.issues = updatedSummary.quality.issues.slice(-50);
                }

                await updatedSummary.save({ session });
                await this.updateUserStats(userId, 'check_grammar', session);
                await session.commitTransaction();
            } catch (error) {
                await session.abortTransaction();
                throw error;
            } finally {
                session.endSession();
            }

            // Schedule async processing
            this.scheduleAsyncProcessing(summaryId, grammarIssues);

            return grammarIssues.map(i => ({
                issueId: i.issueId || mongoose.Types.ObjectId(),
                type: i.type,
                description: i.description,
                suggestion: i.suggestion,
                position: i.position,
                createdAt: new Date(),
            }));
        } catch (error) {
            logger.error(`Grammar check failed for summary ${summaryId}:`, error);
            throw error;
        }
    }

    /**
     * Apply a grammar correction
     */
    async applyGrammarCorrection(summaryId, userId, issueId, correction) {
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

            // Find issue
            const issue = summary.quality?.issues.find(
                i => i.issueId.toString() === issueId && i.status === 'pending'
            );
            if (!issue) {
                throw new AppError('Issue not found or already processed', 404);
            }

            // Apply correction
            const newContent = this.applyCorrection(summary.content, issue.position, correction);

            // Create new version
            const newVersion = {
                versionNumber: summary.versions.length + 1,
                content: newContent,
                title: summary.title,
                changeType: 'grammar',
                isActive: true,
                createdAt: new Date(),
                stats: {
                    characterCount: newContent.length,
                    wordCount: newContent.trim().split(/\s+/).length,
                    paragraphCount: newContent.split('\n\n').length,
                    sentenceCount: newContent.split(/[.!?]+/).length - 1,
                },
                grammar: {
                    issueId,
                    type: issue.type,
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

            // Update issue status
            issue.status = 'applied';
            issue.appliedAt = new Date();
            issue.appliedBy = userId;

            // Update summary
            summary.content = newContent;
            summary.metadata.wordCount = newContent.trim().split(/\s+/).length;
            summary.metadata.characterCount = newContent.length;
            summary.metadata.lastEditedBy = { userId, timestamp: new Date() };

            const updatedSummary = await summary.save({ session });

            // Update user stats
            await this.updateUserStats(userId, 'apply_grammar', session);

            await session.commitTransaction();

            // Clear cache
            await this.clearSummaryCache(summaryId, userId);

            return updatedSummary;
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Grammar correction application failed for summary ${summaryId}:`, error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    /**
     * Get grammar check history
     */
    async getGrammarHistory(summaryId, userId, { page, limit }) {
        try {
            const summary = await this.model.findById(summaryId).lean();
            if (!summary) {
                throw new AppError('Summary not found', 404);
            }

            // Check access
            if (!this.checkAccess(summary, userId)) {
                throw new AppError('Access denied', 403);
            }

            const skip = (page - 1) * limit;
            const issues = (summary.quality?.issues || [])
                .sort((a, b) => b.createdAt - a.createdAt)
                .slice(skip, skip + limit)
                .map(i => ({
                    issueId: i.issueId,
                    type: i.type,
                    description: i.description,
                    suggestion: i.suggestion,
                    position: i.position,
                    status: i.status,
                    createdAt: i.createdAt,
                    appliedAt: i.appliedAt,
                    appliedBy: i.appliedBy,
                }));

            const totalCount = summary.quality?.issues.length || 0;
            const totalPages = Math.ceil(totalCount / limit);

            return {
                history: issues,
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
            logger.error(`Grammar history fetch failed for summary ${summaryId}:`, error);
            throw error;
        }
    }

    /**
     * Bulk apply grammar corrections
     */
    async bulkApplyGrammarCorrections(summaryIds, userId, issueIds, corrections) {
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

            const updatedSummaries = await Promise.all(
                summaries.map(async summary => {
                    const issue = summary.quality?.issues.find(
                        i => issueIds.includes(i.issueId.toString()) && i.status === 'pending'
                    );
                    if (!issue) {
                        return null;
                    }

                    const correction = corrections[issueIds.indexOf(issue.issueId.toString())];
                    if (!correction) return null;

                    const newContent = this.applyCorrection(summary.content, issue.position, correction);

                    const newVersion = {
                        versionNumber: summary.versions.length + 1,
                        content: newContent,
                        title: summary.title,
                        changeType: 'grammar',
                        isActive: true,
                        createdAt: new Date(),
                        stats: {
                            characterCount: newContent.length,
                            wordCount: newContent.trim().split(/\s+/).length,
                            paragraphCount: newContent.split('\n\n').length,
                            sentenceCount: newContent.split(/[.!?]+/).length - 1,
                        },
                        grammar: {
                            issueId: issue.issueId,
                            type: issue.type,
                            appliedBy: userId,
                            appliedAt: new Date(),
                        },
                    };

                    summary.versions.forEach(v => (v.isActive = false));
                    summary.versions.push(newVersion);
                    summary.content = newContent;
                    summary.metadata.wordCount = newContent.trim().split(/\s+/).length;
                    summary.metadata.characterCount = newContent.length;
                    summary.metadata.lastEditedBy = { userId, timestamp: new Date() };
                    issue.status = 'applied';
                    issue.appliedAt = new Date();
                    issue.appliedBy = userId;

                    return summary.save({ session });
                })
            );

            // Update user stats
            await this.updateUserStats(userId, 'bulk_apply_grammar', session);

            await session.commitTransaction();

            // Clear cache
            await Promise.all(summaryIds.map(id => this.clearSummaryCache(id, userId)));

            return {
                requested: summaryIds.length,
                matched: summaries.length,
                modified: updatedSummaries.filter(s => s !== null).length,
            };
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk grammar correction application failed for user ${userId}:`, error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    /**
     * Discard a grammar issue
     */
    async discardGrammarIssue(summaryId, userId, issueId) {
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

            const issue = summary.quality?.issues.find(
                i => i.issueId.toString() === issueId && i.status === 'pending'
            );
            if (!issue) {
                throw new AppError('Issue not found or already processed', 404);
            }

            issue.status = 'discarded';
            issue.discardedAt = new Date();
            issue.discardedBy = userId;

            await summary.save({ session });
            await this.updateUserStats(userId, 'discard_grammar', session);

            await session.commitTransaction();
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Grammar issue discard failed for summary ${summaryId}:`, error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    // Helper Methods

    /**
     * Apply grammar correction to content
     */
    applyCorrection(content, position, correction) {
        const before = content.substring(0, position.start);
        const after = content.substring(position.end);
        return `${before}${correction}${after}`;
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
            metricsCollector.increment(`grammar.${action}`, { userId });
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
                `grammar:${summaryId}:*`,
            ];
            await Promise.all(patterns.map(pattern => cacheService.deletePattern(pattern)));
        } catch (error) {
            logger.error(`Cache clearing failed for summary ${summaryId}:`, error);
        }
    }

    /**
     * Schedule async processing
     */
    scheduleAsyncProcessing(summaryId, issues) {
        setTimeout(async () => {
            try {
                // Placeholder for async tasks (e.g., refine issues, update analytics)
                logger.info(`Async processing completed for summary ${summaryId}`);
            } catch (error) {
                logger.error(`Async processing failed for summary ${summaryId}:`, error);
            }
        }, 1000);
    }
}

export default GrammarService;