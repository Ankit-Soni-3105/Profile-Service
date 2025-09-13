import FormattingService from '../services/FormattingService.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { catchAsync } from '../handler/catchAsync.js';
import { ApiResponse } from '../utils/response.js';
import { createRateLimiter } from '../utils/rateLimiter.js';
import { cacheService } from '../services/cache.service.js';
import { metricsCollector } from '../utils/metrics.js';
import { eventEmitter } from '../events/events.js';
import { validateFormattingInput } from '../validations/formatting.validation.js';
import { sanitizeInput } from '../utils/sanitizer.js';
import { marked } from 'marked';
import DOMPurify from 'dompurify';

// Rate limiters for formatting operations
const applyFormatLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 100, // 100 format applications per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `format_apply_${req.user.id}_${req.params.summaryId}`,
});

const previewFormatLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 200, // 200 format previews per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `format_preview_${req.user.id}_${req.params.summaryId}`,
});

class FormattingController {
    constructor() {
        this.formattingService = new FormattingService();
    }

    /**
     * Apply formatting to summary content
     * PATCH /api/v1/formatting/:userId/:summaryId
     */
    applyFormatting = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, summaryId } = req.params;
        const requestingUserId = req.user.id;
        const { formatType, content, options = {} } = req.body;

        // Apply rate limiting
        await applyFormatLimiter(req, res, () => { });

        // Validate input
        const validation = validateFormattingInput({ formatType, content, options });
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        // Sanitize input
        const sanitizedData = sanitizeInput({ content, options });

        try {
            // Verify access
            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            // Apply formatting
            const formattedContent = await this.formattingService.applyFormatting(
                summaryId,
                requestingUserId,
                formatType,
                sanitizedData.content,
                sanitizedData.options
            );

            // Clear cache
            await cacheService.deletePattern(`summary:${summaryId}:*`);

            // Emit event for real-time updates
            eventEmitter.emit('formatting.applied', {
                summaryId,
                userId: requestingUserId,
                formatType,
            });

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('formatting.applied', {
                userId: requestingUserId,
                summaryId,
                formatType,
            });
            logger.info(`Formatting applied to summary ${summaryId} (${formatType}) in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Formatting applied successfully',
                data: {
                    summaryId,
                    formattedContent,
                },
            });
        } catch (error) {
            logger.error(`Formatting failed for summary ${summaryId}:`, error);
            metricsCollector.increment('formatting.apply_failed', { userId: requestingUserId });
            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.message.includes('not found')) {
                return next(new AppError('Summary not found', 404));
            }
            return next(new AppError('Failed to apply formatting', 500));
        }
    });

    /**
     * Preview formatting without saving
     * POST /api/v1/formatting/:userId/:summaryId/preview
     */
    previewFormatting = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, summaryId } = req.params;
        const requestingUserId = req.user.id;
        const { formatType, content, options = {} } = req.body;

        // Apply rate limiting
        await previewFormatLimiter(req, res, () => { });

        // Validate input
        const validation = validateFormattingInput({ formatType, content, options });
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        // Sanitize input
        const sanitizedData = sanitizeInput({ content, options });

        try {
            // Verify access
            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            // Cache key for preview
            const cacheKey = `format_preview:${summaryId}:${requestingUserId}:${formatType}:${JSON.stringify(sanitizedData.options)}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('formatting.preview_cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, {
                    message: 'Formatting preview retrieved from cache',
                    data: cached,
                });
            }

            // Preview formatting
            const preview = await this.formattingService.previewFormatting(
                summaryId,
                formatType,
                sanitizedData.content,
                sanitizedData.options
            );

            // Cache result
            await cacheService.set(cacheKey, preview, 300); // 5 minutes

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('formatting.previewed', {
                userId: requestingUserId,
                summaryId,
                formatType,
            });
            logger.info(`Formatting previewed for summary ${summaryId} (${formatType}) in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Formatting preview generated successfully',
                data: preview,
            });
        } catch (error) {
            logger.error(`Formatting preview failed for summary ${summaryId}:`, error);
            metricsCollector.increment('formatting.preview_failed', { userId: requestingUserId });
            return next(new AppError('Failed to preview formatting', 500));
        }
    });

    /**
     * Get available formatting styles
     * GET /api/v1/formatting/:userId/:summaryId/styles
     */
    getFormattingStyles = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, summaryId } = req.params;
        const requestingUserId = req.user.id;

        try {
            // Verify access
            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            // Cache key
            const cacheKey = `formatting_styles:${summaryId}:${requestingUserId}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('formatting.styles_cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, {
                    message: 'Formatting styles retrieved from cache',
                    data: cached,
                });
            }

            // Get styles
            const styles = await this.formattingService.getFormattingStyles(summaryId, requestingUserId);

            // Cache result
            await cacheService.set(cacheKey, styles, 3600); // 1 hour

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('formatting.styles_fetched', {
                userId: requestingUserId,
                summaryId,
            });
            logger.info(`Formatting styles fetched for summary ${summaryId} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Formatting styles retrieved successfully',
                data: styles,
            });
        } catch (error) {
            logger.error(`Formatting styles fetch failed for summary ${summaryId}:`, error);
            metricsCollector.increment('formatting.styles_fetch_failed', { userId: requestingUserId });
            if (error.message.includes('not found')) {
                return next(new AppError('Summary not found', 404));
            }
            return next(new AppError('Failed to fetch formatting styles', 500));
        }
    });

    /**
     * Bulk apply formatting to multiple summaries
     * POST /api/v1/formatting/:userId/bulk
     */
    bulkApplyFormatting = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { summaryIds, formatType, options = {} } = req.body;

        // Validate input
        if (!Array.isArray(summaryIds) || summaryIds.length === 0 || summaryIds.length > 100) {
            return next(new AppError('Invalid summary IDs array (1-100 IDs required)', 400));
        }

        const validation = validateFormattingInput({ formatType, options });
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        try {
            // Verify access
            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            // Apply bulk formatting
            const result = await this.formattingService.bulkApplyFormatting(
                summaryIds,
                requestingUserId,
                formatType,
                options
            );

            // Clear cache
            await Promise.all(summaryIds.map(id => cacheService.deletePattern(`summary:${id}:*`)));

            // Emit event
            eventEmitter.emit('formatting.bulk_applied', {
                userId: requestingUserId,
                summaryIds,
                formatType,
            });

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('formatting.bulk_applied', {
                userId: requestingUserId,
                count: result.modified,
            });
            logger.info(`Bulk formatting applied to ${result.modified} summaries in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: `Bulk formatting (${formatType}) applied successfully`,
                data: {
                    requested: summaryIds.length,
                    matched: result.matched,
                    modified: result.modified,
                },
            });
        } catch (error) {
            logger.error(`Bulk formatting failed for user ${requestingUserId}:`, error);
            metricsCollector.increment('formatting.bulk_apply_failed', { userId: requestingUserId });
            return next(new AppError('Failed to apply bulk formatting', 500));
        }
    });

    /**
     * Get formatting history
     * GET /api/v1/formatting/:userId/:summaryId/history
     */
    getFormattingHistory = catchAsync(async (req, res, next) => {
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
            const history = await this.formattingService.getFormattingHistory(
                summaryId,
                requestingUserId,
                { page: parseInt(page), limit: parseInt(limit) }
            );

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('formatting.history_fetched', {
                userId: requestingUserId,
                summaryId,
            });
            logger.info(`Formatting history fetched for summary ${summaryId} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Formatting history retrieved successfully',
                data: history,
            });
        } catch (error) {
            logger.error(`Formatting history fetch failed for summary ${summaryId}:`, error);
            metricsCollector.increment('formatting.history_fetch_failed', { userId: requestingUserId });
            if (error.message.includes('not found')) {
                return next(new AppError('Summary not found', 404));
            }
            return next(new AppError('Failed to fetch formatting history', 500));
        }
    });

    /**
     * Revert to previous formatting
     * POST /api/v1/formatting/:userId/:summaryId/revert
     */
    revertFormatting = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, summaryId } = req.params;
        const requestingUserId = req.user.id;
        const { formatId } = req.body;

        // Validate input
        if (!formatId) {
            return next(new AppError('Format ID is required', 400));
        }

        try {
            // Verify access
            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            // Revert formatting
            const updatedSummary = await this.formattingService.revertFormatting(
                summaryId,
                requestingUserId,
                formatId
            );

            // Clear cache
            await cacheService.deletePattern(`summary:${summaryId}:*`);

            // Emit event
            eventEmitter.emit('formatting.reverted', {
                summaryId,
                userId: requestingUserId,
                formatId,
            });

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('formatting.reverted', {
                userId: requestingUserId,
                summaryId,
            });
            logger.info(`Formatting reverted for summary ${summaryId} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Formatting reverted successfully',
                data: {
                    summaryId,
                    content: updatedSummary.content,
                },
            });
        } catch (error) {
            logger.error(`Formatting revert failed for summary ${summaryId}:`, error);
            metricsCollector.increment('formatting.revert_failed', { userId: requestingUserId });
            if (error.message.includes('not found')) {
                return next(new AppError('Summary or format not found', 404));
            }
            return next(new AppError('Failed to revert formatting', 500));
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
     * Validate formatting options
     */
    validateOptions(options, formatType) {
        const allowedOptions = {
            markdown: ['renderer', 'sanitize'],
            html: ['sanitize', 'allowedTags'],
            custom: ['styleName', 'parameters'],
        };
        return Object.keys(options).every(key => allowedOptions[formatType]?.includes(key));
    }

    /**
     * Get allowed format types
     */
    getAllowedFormatTypes() {
        return ['markdown', 'html', 'custom'];
    }
}

export default new FormattingController();