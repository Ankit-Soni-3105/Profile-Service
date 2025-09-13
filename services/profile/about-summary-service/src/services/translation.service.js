import Summary from '../models/Summary.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { cacheService } from '../services/cache.service.js';
import { metricsCollector } from '../utils/metrics.js';
import { eventEmitter } from '../events/events.js';
import mongoose from 'mongoose';
import translationApi from '../services/translation.api.js'; // Hypothetical translation API client

class TranslationService {
    constructor() {
        this.model = Summary;
        this.defaultCacheTTL = 3600; // 1 hour
    }

    /**
     * Translate summary content
     */
    async translateContent(summaryId, userId, targetLanguage, options) {
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

            // Translate content
            const translatedContent = await translationApi.translate({
                text: summary.content,
                targetLanguage,
                options,
            });

            // Store translation
            summary.translations = summary.translations || [];
            const translation = {
                translationId: mongoose.Types.ObjectId(),
                targetLanguage,
                content: translatedContent,
                createdAt: new Date(),
                createdBy: userId,
                status: 'pending',
            };
            summary.translations.push(translation);

            // Limit translations
            if (summary.translations.length > 20) {
                summary.translations = summary.translations.slice(-20);
            }

            await summary.save({ session });
            await this.updateUserStats(userId, 'translate', session);

            await session.commitTransaction();

            // Schedule async processing
            this.scheduleAsyncProcessing(summaryId, translation);

            return translation;
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Translation failed for summary ${summaryId}:`, error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    /**
     * Get supported languages
     */
    async getSupportedLanguages(summaryId, userId) {
        try {
            const summary = await this.model.findById(summaryId).select('_id userId').lean();
            if (!summary) {
                throw new AppError('Summary not found', 404);
            }

            if (!this.checkAccess(summary, userId)) {
                throw new AppError('Access denied', 403);
            }

            return translationApi.getSupportedLanguages();
        } catch (error) {
            logger.error(`Supported languages fetch failed for summary ${summaryId}:`, error);
            throw error;
        }
    }

    /**
     * Get translation history
     */
    async getTranslationHistory(summaryId, userId, { page, limit }) {
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
            const translations = (summary.translations || [])
                .sort((a, b) => b.createdAt - a.createdAt)
                .slice(skip, skip + limit)
                .map(t => ({
                    translationId: t.translationId,
                    targetLanguage: t.targetLanguage,
                    content: t.content,
                    status: t.status,
                    createdAt: t.createdAt,
                    createdBy: t.createdBy,
                    appliedAt: t.appliedAt,
                    appliedBy: t.appliedBy,
                }));

            const totalCount = summary.translations?.length || 0;
            const totalPages = Math.ceil(totalCount / limit);

            return {
                history: translations,
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
            logger.error(`Translation history fetch failed for summary ${summaryId}:`, error);
            throw error;
        }
    }

    /**
     * Apply translation to summary
     */
    async applyTranslation(summaryId, userId, translationId) {
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

            const translation = summary.translations?.find(
                t => t.translationId.toString() === translationId && t.status === 'pending'
            );
            if (!translation) {
                throw new AppError('Translation not found or already applied', 404);
            }

            // Create new version
            const newVersion = {
                versionNumber: summary.versions.length + 1,
                content: translation.content,
                title: summary.title,
                changeType: 'translation',
                isActive: true,
                createdAt: new Date(),
                stats: {
                    characterCount: translation.content.length,
                    wordCount: translation.content.trim().split(/\s+/).length,
                    paragraphCount: translation.content.split('\n\n').length,
                    sentenceCount: translation.content.split(/[.!?]+/).length - 1,
                },
                translation: {
                    translationId,
                    targetLanguage: translation.targetLanguage,
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

            // Update translation status
            translation.status = 'applied';
            translation.appliedAt = new Date();
            translation.appliedBy = userId;

            // Update summary
            summary.content = translation.content;
            summary.metadata.wordCount = translation.content.trim().split(/\s+/).length;
            summary.metadata.characterCount = translation.content.length;
            summary.metadata.lastEditedBy = { userId, timestamp: new Date() };

            const updatedSummary = await summary.save({ session });

            // Update user stats
            await this.updateUserStats(userId, 'apply_translation', session);

            await session.commitTransaction();

            // Clear cache
            await this.clearSummaryCache(summaryId, userId);

            return updatedSummary;
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Translation application failed for summary ${summaryId}:`, error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    /**
     * Bulk translate summaries
     */
    async bulkTranslate(summaryIds, userId, targetLanguage, options) {
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

            const translatedSummaries = await Promise.all(
                summaries.map(async summary => {
                    const translatedContent = await translationApi.translate({
                        text: summary.content,
                        targetLanguage,
                        options,
                    });

                    summary.translations = summary.translations || [];
                    const translation = {
                        translationId: mongoose.Types.ObjectId(),
                        targetLanguage,
                        content: translatedContent,
                        createdAt: new Date(),
                        createdBy: userId,
                        status: 'pending',
                    };
                    summary.translations.push(translation);

                    // Limit translations
                    if (summary.translations.length > 20) {
                        summary.translations = summary.translations.slice(-20);
                    }

                    return summary.save({ session });
                })
            );

            // Update user stats
            await this.updateUserStats(userId, 'bulk_translate', session);

            await session.commitTransaction();

            // Clear cache
            await Promise.all(summaryIds.map(id => this.clearSummaryCache(id, userId)));

            return {
                requested: summaryIds.length,
                matched: summaries.length,
                modified: translatedSummaries.length,
            };
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk translation failed for user ${userId}:`, error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    // Helper Methods

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
            metricsCollector.increment(`translation.${action}`, { userId });
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
                `translation:${summaryId}:*`,
            ];
            await Promise.all(patterns.map(pattern => cacheService.deletePattern(pattern)));
        } catch (error) {
            logger.error(`Cache clearing failed for summary ${summaryId}:`, error);
        }
    }

    /**
     * Schedule async processing
     */
    scheduleAsyncProcessing(summaryId, translation) {
        setTimeout(async () => {
            try {
                // Placeholder for async tasks (e.g., validate translation quality)
                logger.info(`Async processing completed for translation in summary ${summaryId}`);
            } catch (error) {
                logger.error(`Async processing failed for summary ${summaryId}:`, error);
            }
        }, 1000);
    }
}

export default TranslationService;