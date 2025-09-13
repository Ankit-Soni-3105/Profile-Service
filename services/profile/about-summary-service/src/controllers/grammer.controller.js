import GrammarService from '../services/GrammarService.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { catchAsync } from '../handler/catchAsync.js';
import { ApiResponse } from '../utils/response.js';
import { createRateLimiter } from '../utils/rateLimiter.js';
import { cacheService } from '../services/cache.service.js';
import { metricsCollector } from '../utils/metrics.js';
import { eventEmitter } from '../events/events.js';
import { validateGrammarInput } from '../validations/grammar.validation.js';
import { sanitizeInput } from '../utils/sanitizer.js';

// Rate limiters for grammar operations
const checkGrammarLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 20, // 20 grammar checks per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `grammar_check_${req.user.id}_${req.params.summaryId}`,
});

const applyGrammarLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 50, // 50 apply operations per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `grammar_apply_${req.user.id}_${req.params.summaryId}`,
});

class GrammarController {
    constructor() {
        this.grammarService = new GrammarService();
    }

    /**
     * Check grammar and style for summary content
     * GET /api/v1/grammar/:userId/:summaryId
     */
    checkGrammar = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, summaryId } = req.params;
        const requestingUserId = req.user.id;
        const { language = 'en-US', checkType = 'all' } = req.query;

        // Apply rate limiting
        await checkGrammarLimiter(req, res, () => { });

        // Validate input
        const validation = validateGrammarInput({ language, checkType });
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        try {
            // Verify access
            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            // Cache key
            const cacheKey = `grammar:${summaryId}:${requestingUserId}:${language}:${checkType}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('grammar.cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, {
                    message: 'Grammar check retrieved from cache',
                    data: cached,
                });
            }

            // Check grammar
            const grammarIssues = await this.grammarService.checkGrammar(
                summaryId,
                requestingUserId,
                language,
                checkType
            );

            // Cache result
            await cacheService.set(cacheKey, grammarIssues, 300); // 5 minutes

            // Emit event
            eventEmitter.emit('grammar.checked', {
                summaryId,
                userId: requestingUserId,
                language,
                checkType,
                issueCount: grammarIssues.length,
            });

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('grammar.checked', {
                userId: requestingUserId,
                summaryId,
                language,
                issueCount: grammarIssues.length,
            });
            logger.info(`Grammar checked for summary ${summaryId} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Grammar check completed successfully',
                data: grammarIssues,
            });
        } catch (error) {
            logger.error(`Grammar check failed for summary ${summaryId}:`, error);
            metricsCollector.increment('grammar.check_failed', { userId: requestingUserId });
            if (error.message.includes('not found')) {
                return next(new AppError('Summary not found', 404));
            }
            return next(new AppError('Failed to check grammar', 500));
        }
    });

    /**
     * Apply grammar corrections to summary content
     * PATCH /api/v1/grammar/:userId/:summaryId/apply
     */
    applyGrammarCorrection = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, summaryId } = req.params;
        const requestingUserId = req.user.id;
        const { issueId, correction } = req.body;

        // Apply rate limiting
        await applyGrammarLimiter(req, res, () => { });

        // Validate input
        const validation = validateGrammarInput({ issueId, correction });
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        // Sanitize input
        const sanitizedData = sanitizeInput({ correction });

        try {
            // Verify access
            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            // Apply correction
            const updatedSummary = await this.grammarService.applyGrammarCorrection(
                summaryId,
                requestingUserId,
                issueId,
                sanitizedData.correction
            );

            // Clear cache
            await cacheService.deletePattern(`summary:${summaryId}:*`);
            await cacheService.deletePattern(`grammar:${summaryId}:*`);

            // Emit event
            eventEmitter.emit('grammar.applied', {
                summaryId,
                userId: requestingUserId,
                issueId,
            });

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('grammar.applied', {
                userId: requestingUserId,
                summaryId,
            });
            logger.info(`Grammar correction applied to summary ${summaryId} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Grammar correction applied successfully',
                data: {
                    summaryId,
                    content: updatedSummary.content,
                    version: updatedSummary.versions[updatedSummary.versions.length - 1].versionNumber,
                },
            });
        } catch (error) {
            logger.error(`Grammar correction application failed for summary ${summaryId}:`, error);
            metricsCollector.increment('grammar.apply_failed', { userId: requestingUserId });
            if (error.message.includes('not found')) {
                return next(new AppError('Summary or issue not found', 404));
            }
            return next(new AppError('Failed to apply grammar correction', 500));
        }
    });

    /**
     * Get grammar check history
     * GET /api/v1/grammar/:userId/:summaryId/history
     */
    getGrammarHistory = catchAsync(async (req, res, next) => {
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
            const history = await this.grammarService.getGrammarHistory(
                summaryId,
                requestingUserId,
                { page: parseInt(page), limit: parseInt(limit) }
            );

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('grammar.history_fetched', {
                userId: requestingUserId,
                summaryId,
            });
            logger.info(`Fetched grammar history for summary ${summaryId} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Grammar history retrieved successfully',
                data: history,
            });
        } catch (error) {
            logger.error(`Grammar history fetch failed for summary ${summaryId}:`, error);
            metricsCollector.increment('grammar.history_fetch_failed', { userId: requestingUserId });
            if (error.message.includes('not found')) {
                return next(new AppError('Summary not found', 404));
            }
            return next(new AppError('Failed to fetch grammar history', 500));
        }
    });

    /**
     * Bulk apply grammar corrections
     * POST /api/v1/grammar/:userId/bulk
     */
    bulkApplyGrammarCorrections = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { summaryIds, issueIds, corrections } = req.body;

        // Validate input
        if (!Array.isArray(summaryIds) || summaryIds.length === 0 || summaryIds.length > 100) {
            return next(new AppError('Invalid summary IDs array (1-100 IDs required)', 400));
        }
        if (!Array.isArray(issueIds) || issueIds.length === 0) {
            return next(new AppError('Invalid issue IDs array', 400));
        }

        // Sanitize input
        const sanitizedData = sanitizeInput({ corrections });

        try {
            // Verify access
            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            // Apply bulk corrections
            const result = await this.grammarService.bulkApplyGrammarCorrections(
                summaryIds,
                requestingUserId,
                issueIds,
                sanitizedData.corrections
            );

            // Clear cache
            await Promise.all(summaryIds.map(id => cacheService.deletePattern(`summary:${id}:*`)));
            await cacheService.deletePattern(`grammar:${summaryIds.join(',')}:*`);

            // Emit event
            eventEmitter.emit('grammar.bulk_applied', {
                userId: requestingUserId,
                summaryIds,
                issueIds,
            });

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('grammar.bulk_applied', {
                userId: requestingUserId,
                count: result.modified,
            });
            logger.info(`Bulk applied ${result.modified} grammar corrections in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Bulk grammar corrections applied successfully',
                data: {
                    requested: summaryIds.length,
                    matched: result.matched,
                    modified: result.modified,
                },
            });
        } catch (error) {
            logger.error(`Bulk grammar correction application failed for user ${requestingUserId}:`, error);
            metricsCollector.increment('grammar.bulk_apply_failed', { userId: requestingUserId });
            return next(new AppError('Failed to apply bulk grammar corrections', 500));
        }
    });

    /**
     * Discard a grammar issue
     * DELETE /api/v1/grammar/:userId/:summaryId/:issueId
     */
    discardGrammarIssue = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, summaryId, issueId } = req.params;
        const requestingUserId = req.user.id;

        try {
            // Verify access
            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            // Discard issue
            await this.grammarService.discardGrammarIssue(summaryId, requestingUserId, issueId);

            // Clear cache
            await cacheService.deletePattern(`grammar:${summaryId}:*`);

            // Emit event
            eventEmitter.emit('grammar.discarded', {
                summaryId,
                userId: requestingUserId,
                issueId,
            });

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('grammar.discarded', {
                userId: requestingUserId,
                summaryId,
            });
            logger.info(`Grammar issue ${issueId} discarded for summary ${summaryId} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Grammar issue discarded successfully',
            });
        } catch (error) {
            logger.error(`Grammar issue discard failed for summary ${summaryId}:`, error);
            metricsCollector.increment('grammar.discard_failed', { userId: requestingUserId });
            if (error.message.includes('not found')) {
                return next(new AppError('Summary or issue not found', 404));
            }
            return next(new AppError('Failed to discard grammar issue', 500));
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
     * Validate grammar check types
     */
    validateCheckType(type) {
        const allowedTypes = ['grammar', 'style', 'all'];
        return allowedTypes.includes(type);
    }

    /**
     * Get supported languages
     */
    getSupportedLanguages() {
        return ['en-US', 'en-GB', 'es', 'fr', 'de'];
    }
}

export default new GrammarController();