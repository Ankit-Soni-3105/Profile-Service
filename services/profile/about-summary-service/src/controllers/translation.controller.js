import TranslationService from '../services/TranslationService.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { catchAsync } from '../handler/catchAsync.js';
import { ApiResponse } from '../utils/response.js';
import { createRateLimiter } from '../utils/rateLimiter.js';
import { cacheService } from '../services/cache.service.js';
import { metricsCollector } from '../utils/metrics.js';
import { eventEmitter } from '../events/events.js';
import { validateTranslationInput } from '../validations/translation.validation.js';
import { sanitizeInput } from '../utils/sanitizer.js';

// Rate limiters for translation operations
const translateLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 10, // 10 translations per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `translate_${req.user.id}_${req.params.summaryId}`,
});

class TranslationController {
    constructor() {
        this.translationService = new TranslationService();
    }

    /**
     * Translate summary content
     * POST /api/v1/translation/:userId/:summaryId
     */
    translateContent = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, summaryId } = req.params;
        const requestingUserId = req.user.id;
        const { targetLanguage, options = {} } = req.body;

        // Apply rate limiting
        await translateLimiter(req, res, () => { });

        // Validate input
        const validation = validateTranslationInput({ targetLanguage, options });
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        // Sanitize input
        const sanitizedData = sanitizeInput({ options });

        try {
            // Verify access
            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            // Cache key
            const cacheKey = `translation:${summaryId}:${requestingUserId}:${targetLanguage}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('translation.cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, {
                    message: 'Translation retrieved from cache',
                    data: cached,
                });
            }

            // Translate content
            const translation = await this.translationService.translateContent(
                summaryId,
                requestingUserId,
                targetLanguage,
                sanitizedData.options
            );

            // Cache result
            await cacheService.set(cacheKey, translation, 3600); // 1 hour

            // Emit event
            eventEmitter.emit('translation.created', {
                summaryId,
                userId: requestingUserId,
                targetLanguage,
            });

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('translation.created', {
                userId: requestingUserId,
                summaryId,
                targetLanguage,
            });
            logger.info(`Translated summary ${summaryId} to ${targetLanguage} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Translation completed successfully',
                data: translation,
            });
        } catch (error) {
            logger.error(`Translation failed for summary ${summaryId}:`, error);
            metricsCollector.increment('translation.create_failed', { userId: requestingUserId });
            if (error.message.includes('not found')) {
                return next(new AppError('Summary not found', 404));
            }
            return next(new AppError('Failed to translate content', 500));
        }
    });

    /**
     * Get supported languages
     * GET /api/v1/translation/:userId/:summaryId/languages
     */
    getSupportedLanguages = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, summaryId } = req.params;
        const requestingUserId = req.user.id;

        try {
            // Verify access
            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            // Cache key
            const cacheKey = `translation_languages:${summaryId}:${requestingUserId}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('translation.languages_cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, {
                    message: 'Supported languages retrieved from cache',
                    data: cached,
                });
            }

            // Get languages
            const languages = await this.translationService.getSupportedLanguages(summaryId, requestingUserId);

            // Cache result
            await cacheService.set(cacheKey, languages, 86400); // 1 day

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('translation.languages_fetched', {
                userId: requestingUserId,
                summaryId,
            });
            logger.info(`Fetched supported languages for summary ${summaryId} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Supported languages retrieved successfully',
                data: languages,
            });
        } catch (error) {
            logger.error(`Supported languages fetch failed for summary ${summaryId}:`, error);
            metricsCollector.increment('translation.languages_fetch_failed', { userId: requestingUserId });
            if (error.message.includes('not found')) {
                return next(new AppError('Summary not found', 404));
            }
            return next(new AppError('Failed to fetch supported languages', 500));
        }
    });

    /**
     * Get translation history
     * GET /api/v1/translation/:userId/:summaryId/history
     */
    getTranslationHistory = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, summaryId } = req.params;
        const requestingUserId = req.user.id;
        const { page = 1, limit = 10 } = req.query;

        try {
            // Verify access
            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            // Get history
            const history = await this.translationService.getTranslationHistory(
                summaryId,
                requestingUserId,
                { page: parseInt(page), limit: parseInt(limit) }
            );

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('translation.history_fetched', {
                userId: requestingUserId,
                summaryId,
            });
            logger.info(`Fetched translation history for summary ${summaryId} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Translation history retrieved successfully',
                data: history,
            });
        } catch (error) {
            logger.error(`Translation history fetch failed for summary ${summaryId}:`, error);
            metricsCollector.increment('translation.history_fetch_failed', { userId: requestingUserId });
            if (error.message.includes('not found')) {
                return next(new AppError('Summary not found', 404));
            }
            return next(new AppError('Failed to fetch translation history', 500));
        }
    });

    /**
     * Apply translation to summary
     * PATCH /api/v1/translation/:userId/:summaryId/apply
     */
    applyTranslation = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, summaryId } = req.params;
        const requestingUserId = req.user.id;
        const { translationId } = req.body;

        // Validate input
        const validation = validateTranslationInput({ translationId });
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        try {
            // Verify access
            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            // Apply translation
            const updatedSummary = await this.translationService.applyTranslation(
                summaryId,
                requestingUserId,
                translationId
            );

            // Clear cache
            await cacheService.deletePattern(`summary:${summaryId}:*`);
            await cacheService.deletePattern(`translation:${summaryId}:*`);

            // Emit event
            eventEmitter.emit('translation.applied', {
                summaryId,
                userId: requestingUserId,
                translationId,
            });

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('translation.applied', {
                userId: requestingUserId,
                summaryId,
            });
            logger.info(`Translation ${translationId} applied to summary ${summaryId} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Translation applied successfully',
                data: {
                    summaryId,
                    content: updatedSummary.content,
                    version: updatedSummary.versions[updatedSummary.versions.length - 1].versionNumber,
                },
            });
        } catch (error) {
            logger.error(`Translation application failed for summary ${summaryId}:`, error);
            metricsCollector.increment('translation.apply_failed', { userId: requestingUserId });
            if (error.message.includes('not found')) {
                return next(new AppError('Summary or translation not found', 404));
            }
            return next(new AppError('Failed to apply translation', 500));
        }
    });

    /**
     * Bulk translate summaries
     * POST /api/v1/translation/:userId/bulk
     */
    bulkTranslate = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { summaryIds, targetLanguage, options = {} } = req.body;

        // Validate input
        if (!Array.isArray(summaryIds) || summaryIds.length === 0 || summaryIds.length > 100) {
            return next(new AppError('Invalid summary IDs array (1-100 IDs required)', 400));
        }

        // Sanitize input
        const sanitizedData = sanitizeInput({ options });

        try {
            // Verify access
            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            // Bulk translate
            const result = await this.translationService.bulkTranslate(
                summaryIds,
                requestingUserId,
                targetLanguage,
                sanitizedData.options
            );

            // Clear cache
            await Promise.all(summaryIds.map(id => cacheService.deletePattern(`summary:${id}:*`)));
            await cacheService.deletePattern(`translation:${summaryIds.join(',')}:*`);

            // Emit event
            eventEmitter.emit('translation.bulk_translated', {
                userId: requestingUserId,
                summaryIds,
                targetLanguage,
            });

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('translation.bulk_translated', {
                userId: requestingUserId,
                count: result.modified,
            });
            logger.info(`Bulk translated ${result.modified} summaries in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Bulk translation completed successfully',
                data: {
                    requested: summaryIds.length,
                    matched: result.matched,
                    modified: result.modified,
                },
            });
        } catch (error) {
            logger.error(`Bulk translation failed for user ${requestingUserId}:`, error);
            metricsCollector.increment('translation.bulk_translate_failed', { userId: requestingUserId });
            return next(new AppError('Failed to perform bulk translation', 500));
        }
    });

    // Helper Methods

    /**
     * Check summary access
     */
    checkSummaryAccess(summary, userId, isAdmin) {
        if (isAdmin) return true;
        if (summary.userId === userId) return true;
        if (summary.sharing?.isPublic) return true;
        if (summary.sharing?.collaborators?.some(c => c.userId === userId && c.status === 'accepted')) {
            return true;
        }
        return false;
    }

    /**
     * Validate translation options
     */
    validateOptions(options) {
        const allowedOptions = ['formal', 'informal', 'preserveFormatting'];
        return Object.keys(options).every(key => allowedOptions.includes(key));
    }
}

export default new TranslationController();