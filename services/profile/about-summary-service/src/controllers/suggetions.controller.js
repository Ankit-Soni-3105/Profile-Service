import SuggestionService from '../services/SuggestionService.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { catchAsync } from '../handler/catchAsync.js';
import { ApiResponse } from '../utils/response.js';
import { createRateLimiter } from '../utils/rateLimiter.js';
import { cacheService } from '../services/cache.service.js';
import { metricsCollector } from '../utils/metrics.js';
import { eventEmitter } from '../events/events.js';
import { validateSuggestionInput } from '../validations/suggestion.validation.js';
import { sanitizeInput } from '../utils/sanitizer.js';

// Rate limiters for suggestion operations
const generateSuggestionLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 20, // 20 suggestion requests per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `suggestion_generate_${req.user.id}_${req.params.summaryId}`,
});

const applySuggestionLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 50, // 50 apply operations per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `suggestion_apply_${req.user.id}_${req.params.summaryId}`,
});

class SuggestionController {
    constructor() {
        this.suggestionService = new SuggestionService();
    }

    /**
     * Generate AI suggestions for summary content
     * GET /api/v1/suggestions/:userId/:summaryId
     */
    generateSuggestions = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, summaryId } = req.params;
        const requestingUserId = req.user.id;
        const { type = 'all', maxSuggestions = 5 } = req.query;

        // Apply rate limiting
        await generateSuggestionLimiter(req, res, () => { });

        // Validate input
        const validation = validateSuggestionInput({ type, maxSuggestions });
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        try {
            // Verify access
            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            // Cache key
            const cacheKey = `suggestions:${summaryId}:${requestingUserId}:${type}:${maxSuggestions}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('suggestions.cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, {
                    message: 'Suggestions retrieved from cache',
                    data: cached,
                });
            }

            // Generate suggestions
            const suggestions = await this.suggestionService.generateSuggestions(
                summaryId,
                requestingUserId,
                type,
                parseInt(maxSuggestions)
            );

            // Cache result
            await cacheService.set(cacheKey, suggestions, 300); // 5 minutes

            // Emit event
            eventEmitter.emit('suggestions.generated', {
                summaryId,
                userId: requestingUserId,
                type,
                count: suggestions.length,
            });

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('suggestions.generated', {
                userId: requestingUserId,
                summaryId,
                type,
                count: suggestions.length,
            });
            logger.info(`Generated ${suggestions.length} suggestions for summary ${summaryId} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Suggestions generated successfully',
                data: suggestions,
            });
        } catch (error) {
            logger.error(`Suggestion generation failed for summary ${summaryId}:`, error);
            metricsCollector.increment('suggestions.generate_failed', { userId: requestingUserId });
            if (error.message.includes('not found')) {
                return next(new AppError('Summary not found', 404));
            }
            return next(new AppError('Failed to generate suggestions', 500));
        }
    });

    /**
     * Apply a specific suggestion to summary content
     * PATCH /api/v1/suggestions/:userId/:summaryId/apply
     */
    applySuggestion = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, summaryId } = req.params;
        const requestingUserId = req.user.id;
        const { suggestionId, applyOptions = {} } = req.body;

        // Apply rate limiting
        await applySuggestionLimiter(req, res, () => { });

        // Validate input
        const validation = validateSuggestionInput({ suggestionId, applyOptions });
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        // Sanitize input
        const sanitizedData = sanitizeInput({ applyOptions });

        try {
            // Verify access
            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            // Apply suggestion
            const updatedSummary = await this.suggestionService.applySuggestion(
                summaryId,
                requestingUserId,
                suggestionId,
                sanitizedData.applyOptions
            );

            // Clear cache
            await cacheService.deletePattern(`summary:${summaryId}:*`);
            await cacheService.deletePattern(`suggestions:${summaryId}:*`);

            // Emit event
            eventEmitter.emit('suggestions.applied', {
                summaryId,
                userId: requestingUserId,
                suggestionId,
            });

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('suggestions.applied', {
                userId: requestingUserId,
                summaryId,
            });
            logger.info(`Suggestion ${suggestionId} applied to summary ${summaryId} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Suggestion applied successfully',
                data: {
                    summaryId,
                    content: updatedSummary.content,
                    version: updatedSummary.versions[updatedSummary.versions.length - 1].versionNumber,
                },
            });
        } catch (error) {
            logger.error(`Suggestion application failed for summary ${summaryId}:`, error);
            metricsCollector.increment('suggestions.apply_failed', { userId: requestingUserId });
            if (error.message.includes('not found')) {
                return next(new AppError('Summary or suggestion not found', 404));
            }
            return next(new AppError('Failed to apply suggestion', 500));
        }
    });

    /**
     * Get suggestion history
     * GET /api/v1/suggestions/:userId/:summaryId/history
     */
    getSuggestionHistory = catchAsync(async (req, res, next) => {
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
            const history = await this.suggestionService.getSuggestionHistory(
                summaryId,
                requestingUserId,
                { page: parseInt(page), limit: parseInt(limit) }
            );

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('suggestions.history_fetched', {
                userId: requestingUserId,
                summaryId,
            });
            logger.info(`Fetched suggestion history for summary ${summaryId} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Suggestion history retrieved successfully',
                data: history,
            });
        } catch (error) {
            logger.error(`Suggestion history fetch failed for summary ${summaryId}:`, error);
            metricsCollector.increment('suggestions.history_fetch_failed', { userId: requestingUserId });
            if (error.message.includes('not found')) {
                return next(new AppError('Summary not found', 404));
            }
            return next(new AppError('Failed to fetch suggestion history', 500));
        }
    });

    /**
     * Bulk apply suggestions to multiple summaries
     * POST /api/v1/suggestions/:userId/bulk
     */
    bulkApplySuggestions = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { summaryIds, suggestionIds, applyOptions = {} } = req.body;

        // Validate input
        if (!Array.isArray(summaryIds) || summaryIds.length === 0 || summaryIds.length > 100) {
            return next(new AppError('Invalid summary IDs array (1-100 IDs required)', 400));
        }
        if (!Array.isArray(suggestionIds) || suggestionIds.length === 0) {
            return next(new AppError('Invalid suggestion IDs array', 400));
        }

        // Sanitize input
        const sanitizedData = sanitizeInput({ applyOptions });

        try {
            // Verify access
            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            // Apply bulk suggestions
            const result = await this.suggestionService.bulkApplySuggestions(
                summaryIds,
                requestingUserId,
                suggestionIds,
                sanitizedData.applyOptions
            );

            // Clear cache
            await Promise.all(summaryIds.map(id => cacheService.deletePattern(`summary:${id}:*`)));
            await cacheService.deletePattern(`suggestions:${summaryIds.join(',')}:*`);

            // Emit event
            eventEmitter.emit('suggestions.bulk_applied', {
                userId: requestingUserId,
                summaryIds,
                suggestionIds,
            });

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('suggestions.bulk_applied', {
                userId: requestingUserId,
                count: result.modified,
            });
            logger.info(`Bulk applied ${result.modified} suggestions in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Bulk suggestions applied successfully',
                data: {
                    requested: summaryIds.length,
                    matched: result.matched,
                    modified: result.modified,
                },
            });
        } catch (error) {
            logger.error(`Bulk suggestion application failed for user ${requestingUserId}:`, error);
            metricsCollector.increment('suggestions.bulk_apply_failed', { userId: requestingUserId });
            return next(new AppError('Failed to apply bulk suggestions', 500));
        }
    });

    /**
     * Discard a suggestion
     * DELETE /api/v1/suggestions/:userId/:summaryId/:suggestionId
     */
    discardSuggestion = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, summaryId, suggestionId } = req.params;
        const requestingUserId = req.user.id;

        try {
            // Verify access
            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            // Discard suggestion
            await this.suggestionService.discardSuggestion(summaryId, requestingUserId, suggestionId);

            // Clear cache
            await cacheService.deletePattern(`suggestions:${summaryId}:*`);

            // Emit event
            eventEmitter.emit('suggestions.discarded', {
                summaryId,
                userId: requestingUserId,
                suggestionId,
            });

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('suggestions.discarded', {
                userId: requestingUserId,
                summaryId,
            });
            logger.info(`Suggestion ${suggestionId} discarded for summary ${summaryId} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Suggestion discarded successfully',
            });
        } catch (error) {
            logger.error(`Suggestion discard failed for summary ${summaryId}:`, error);
            metricsCollector.increment('suggestions.discard_failed', { userId: requestingUserId });
            if (error.message.includes('not found')) {
                return next(new AppError('Summary or suggestion not found', 404));
            }
            return next(new AppError('Failed to discard suggestion', 500));
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
     * Validate suggestion types
     */
    validateSuggestionType(type) {
        const allowedTypes = ['clarity', 'engagement', 'seo', 'all'];
        return allowedTypes.includes(type);
    }

    /**
     * Get allowed apply options
     */
    getAllowedApplyOptions() {
        return ['replace', 'merge', 'append'];
    }
}

export default new SuggestionController();