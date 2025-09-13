import Summary from '../models/Summary.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { cacheService } from '../services/cache.service.js';
import { metricsCollector } from '../utils/metrics.js';
import { eventEmitter } from '../events/events.js';
import mongoose from 'mongoose';
import aiService from '../services/ai.service.js'; // Hypothetical AI service for suggestions

class SuggestionService {
    constructor() {
        this.model = Summary;
        this.defaultCacheTTL = 300; // 5 minutes
    }

    /**
     * Generate AI suggestions for summary content
     */
    async generateSuggestions(summaryId, userId, type, maxSuggestions) {
        try {
            const summary = await this.model.findById(summaryId).lean();
            if (!summary) {
                throw new AppError('Summary not found', 404);
            }

            // Check access
            if (!this.checkAccess(summary, userId)) {
                throw new AppError('Access denied', 403);
            }

            // Generate suggestions
            const suggestions = await aiService.generateSuggestions({
                content: summary.content,
                type,
                maxSuggestions,
                context: {
                    title: summary.title,
                    metadata: summary.metadata,
                },
            });

            // Store suggestions
            const session = await mongoose.startSession();
            session.startTransaction();
            try {
                const updatedSummary = await this.model.findById(summaryId).session(session);
                updatedSummary.ai = updatedSummary.ai || { enhancements: [] };
                updatedSummary.ai.enhancements.push(
                    ...suggestions.map(s => ({
                        suggestionId: mongoose.Types.ObjectId(),
                        type: s.type,
                        content: s.content,
                        confidence: s.confidence,
                        createdAt: new Date(),
                        status: 'pending',
                        createdBy: userId,
                    }))
                );

                // Limit enhancements
                if (updatedSummary.ai.enhancements.length > 50) {
                    updatedSummary.ai.enhancements = updatedSummary.ai.enhancements.slice(-50);
                }

                await updatedSummary.save({ session });
                await this.updateUserStats(userId, 'generate_suggestions', session);
                await session.commitTransaction();
            } catch (error) {
                await session.abortTransaction();
                throw error;
            } finally {
                session.endSession();
            }

            // Schedule async processing
            this.scheduleAsyncProcessing(summaryId, suggestions);

            return suggestions.map(s => ({
                suggestionId: s.suggestionId || mongoose.Types.ObjectId(),
                type: s.type,
                content: s.content,
                confidence: s.confidence,
                createdAt: new Date(),
            }));
        } catch (error) {
            logger.error(`Suggestion generation failed for summary ${summaryId}:`, error);
            throw error;
        }
    }

    /**
     * Apply a suggestion to summary content
     */
    async applySuggestion(summaryId, userId, suggestionId, applyOptions) {
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

            // Find suggestion
            const suggestion = summary.ai?.enhancements.find(
                s => s.suggestionId.toString() === suggestionId && s.status === 'pending'
            );
            if (!suggestion) {
                throw new AppError('Suggestion not found or already applied', 404);
            }

            // Apply suggestion
            let newContent;
            switch (applyOptions.mode || 'replace') {
                case 'replace':
                    newContent = suggestion.content;
                    break;
                case 'merge':
                    newContent = this.mergeContent(summary.content, suggestion.content);
                    break;
                case 'append':
                    newContent = `${summary.content}\n${suggestion.content}`;
                    break;
                default:
                    throw new AppError('Invalid apply mode', 400);
            }

            // Create new version
            const newVersion = {
                versionNumber: summary.versions.length + 1,
                content: newContent,
                title: summary.title,
                changeType: 'suggestion',
                isActive: true,
                createdAt: new Date(),
                stats: {
                    characterCount: newContent.length,
                    wordCount: newContent.trim().split(/\s+/).length,
                    paragraphCount: newContent.split('\n\n').length,
                    sentenceCount: newContent.split(/[.!?]+/).length - 1,
                },
                suggestion: {
                    suggestionId,
                    type: suggestion.type,
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

            // Update suggestion status
            suggestion.status = 'applied';
            suggestion.appliedAt = new Date();
            suggestion.appliedBy = userId;

            // Update summary
            summary.content = newContent;
            summary.metadata.wordCount = newContent.trim().split(/\s+/).length;
            summary.metadata.characterCount = newContent.length;
            summary.metadata.lastEditedBy = { userId, timestamp: new Date() };

            const updatedSummary = await summary.save({ session });

            // Update user stats
            await this.updateUserStats(userId, 'apply_suggestion', session);

            await session.commitTransaction();

            // Clear cache
            await this.clearSummaryCache(summaryId, userId);

            return updatedSummary;
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Suggestion application failed for summary ${summaryId}:`, error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    /**
     * Get suggestion history
     */
    async getSuggestionHistory(summaryId, userId, { page, limit }) {
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
            const suggestions = (summary.ai?.enhancements || [])
                .sort((a, b) => b.createdAt - a.createdAt)
                .slice(skip, skip + limit)
                .map(s => ({
                    suggestionId: s.suggestionId,
                    type: s.type,
                    content: s.content,
                    confidence: s.confidence,
                    status: s.status,
                    createdAt: s.createdAt,
                    appliedAt: s.appliedAt,
                    appliedBy: s.appliedBy,
                }));

            const totalCount = summary.ai?.enhancements.length || 0;
            const totalPages = Math.ceil(totalCount / limit);

            return {
                history: suggestions,
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
            logger.error(`Suggestion history fetch failed for summary ${summaryId}:`, error);
            throw error;
        }
    }

    /**
     * Bulk apply suggestions
     */
    async bulkApplySuggestions(summaryIds, userId, suggestionIds, applyOptions) {
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
                    const suggestion = summary.ai?.enhancements.find(
                        s => suggestionIds.includes(s.suggestionId.toString()) && s.status === 'pending'
                    );
                    if (!suggestion) {
                        return null;
                    }

                    let newContent;
                    switch (applyOptions.mode || 'replace') {
                        case 'replace':
                            newContent = suggestion.content;
                            break;
                        case 'merge':
                            newContent = this.mergeContent(summary.content, suggestion.content);
                            break;
                        case 'append':
                            newContent = `${summary.content}\n${suggestion.content}`;
                            break;
                        default:
                            throw new AppError('Invalid apply mode', 400);
                    }

                    const newVersion = {
                        versionNumber: summary.versions.length + 1,
                        content: newContent,
                        title: summary.title,
                        changeType: 'suggestion',
                        isActive: true,
                        createdAt: new Date(),
                        stats: {
                            characterCount: newContent.length,
                            wordCount: newContent.trim().split(/\s+/).length,
                            paragraphCount: newContent.split('\n\n').length,
                            sentenceCount: newContent.split(/[.!?]+/).length - 1,
                        },
                        suggestion: {
                            suggestionId: suggestion.suggestionId,
                            type: suggestion.type,
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
                    suggestion.status = 'applied';
                    suggestion.appliedAt = new Date();
                    suggestion.appliedBy = userId;

                    return summary.save({ session });
                })
            );

            // Update user stats
            await this.updateUserStats(userId, 'bulk_apply_suggestions', session);

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
            logger.error(`Bulk suggestion application failed for user ${userId}:`, error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    /**
     * Discard a suggestion
     */
    async discardSuggestion(summaryId, userId, suggestionId) {
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

            const suggestion = summary.ai?.enhancements.find(
                s => s.suggestionId.toString() === suggestionId && s.status === 'pending'
            );
            if (!suggestion) {
                throw new AppError('Suggestion not found or already processed', 404);
            }

            suggestion.status = 'discarded';
            suggestion.discardedAt = new Date();
            suggestion.discardedBy = userId;

            await summary.save({ session });
            await this.updateUserStats(userId, 'discard_suggestion', session);

            await session.commitTransaction();
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Suggestion discard failed for summary ${summaryId}:`, error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    // Helper Methods

    /**
     * Merge content with suggestion
     */
    mergeContent(original, suggestion) {
        // Simple merge: combine sentences, avoiding duplicates
        const originalSentences = original.split(/[.!?]+/).map(s => s.trim()).filter(s => s);
        const suggestionSentences = suggestion.split(/[.!?]+/).map(s => s.trim()).filter(s => s);
        const merged = [...new Set([...originalSentences, ...suggestionSentences])].join('. ');
        return merged;
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
            metricsCollector.increment(`suggestions.${action}`, { userId });
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
                `suggestions:${summaryId}:*`,
            ];
            await Promise.all(patterns.map(pattern => cacheService.deletePattern(pattern)));
        } catch (error) {
            logger.error(`Cache clearing failed for summary ${summaryId}:`, error);
        }
    }

    /**
     * Schedule async processing
     */
    scheduleAsyncProcessing(summaryId, suggestions) {
        setTimeout(async () => {
            try {
                // Placeholder for async tasks (e.g., refine suggestions, update analytics)
                logger.info(`Async processing completed for summary ${summaryId}`);
            } catch (error) {
                logger.error(`Async processing failed for summary ${summaryId}:`, error);
            }
        }, 1000);
    }
}

export default SuggestionService;