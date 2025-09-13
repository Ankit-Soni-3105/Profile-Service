import VoiceInputService from '../services/voiceInput.service.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { catchAsync } from '../handler/catchAsync.js';
import { ApiResponse } from '../utils/response.js';
import { createRateLimiter } from '../utils/rateLimiter.js';
import { cacheService } from '../services/redis.service.js';
import { metricsCollector } from '../utils/metrics.js';
import { eventEmitter } from '../events/events.js';
import { validateVoiceInput } from '../validations/voiceInput.validation.js';
import { sanitizeInput } from '../utils/sanitizer.js';

// Rate limiters for voice input operations
const processVoiceLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 10, // 10 voice inputs per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `voice_process_${req.user.id}_${req.params.summaryId || 'new'}`,
});

class VoiceInputController {
    constructor() {
        this.voiceInputService = new VoiceInputService();
    }

    /**
     * Process voice input to create or update a summary
     * POST /api/v1/voice/:userId/:summaryId?
     */
    processVoiceInput = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, summaryId } = req.params;
        const requestingUserId = req.user.id;
        const { audioData, language = 'en-US', options = {} } = req.body;

        // Apply rate limiting
        await processVoiceLimiter(req, res, () => { });

        // Validate input
        const validation = validateVoiceInput({ audioData, language, options });
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
            const cacheKey = `voice:${summaryId || 'new'}:${requestingUserId}:${language}`;
            const cached = await cacheService.get(cacheKey);
            if (cached && !summaryId) {
                metricsCollector.increment('voice.cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, {
                    message: 'Voice input transcription retrieved from cache',
                    data: cached,
                });
            }

            // Process voice input
            const result = await this.voiceInputService.processVoiceInput(
                summaryId,
                requestingUserId,
                audioData,
                language,
                sanitizedData.options
            );

            // Cache result (only for new summaries)
            if (!summaryId) {
                await cacheService.set(cacheKey, result, 300); // 5 minutes
            }

            // Emit event
            eventEmitter.emit('voice.processed', {
                summaryId: result.summaryId,
                userId: requestingUserId,
                language,
            });

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('voice.processed', {
                userId: requestingUserId,
                summaryId: result.summaryId,
            });
            logger.info(`Voice input processed for summary ${result.summaryId} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: summaryId ? 'Voice input updated successfully' : 'Voice input created successfully',
                data: {
                    summaryId: result.summaryId,
                    content: result.content,
                },
            });
        } catch (error) {
            logger.error(`Voice input processing failed for summary ${summaryId || 'new'}:`, error);
            metricsCollector.increment('voice.process_failed', { userId: requestingUserId });
            if (error.message.includes('not found')) {
                return next(new AppError('Summary not found', 404));
            }
            return next(new AppError('Failed to process voice input', 500));
        }
    });

    /**
     * Get supported voice input languages
     * GET /api/v1/voice/:userId/languages
     */
    getSupportedLanguages = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;

        try {
            // Verify access
            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            // Cache key
            const cacheKey = `voice_languages:${requestingUserId}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('voice.languages_cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, {
                    message: 'Supported languages retrieved from cache',
                    data: cached,
                });
            }

            // Get languages
            const languages = await this.voiceInputService.getSupportedLanguages(requestingUserId);

            // Cache result
            await cacheService.set(cacheKey, languages, 86400); // 1 day

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('voice.languages_fetched', {
                userId: requestingUserId,
            });
            logger.info(`Fetched supported voice languages in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Supported languages retrieved successfully',
                data: languages,
            });
        } catch (error) {
            logger.error(`Supported languages fetch failed:`, error);
            metricsCollector.increment('voice.languages_fetch_failed', { userId: requestingUserId });
            return next(new AppError('Failed to fetch supported languages', 500));
        }
    });

    /**
     * Get voice input history
     * GET /api/v1/voice/:userId/:summaryId/history
     */
    getVoiceInputHistory = catchAsync(async (req, res, next) => {
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
            const history = await this.voiceInputService.getVoiceInputHistory(
                summaryId,
                requestingUserId,
                { page: parseInt(page), limit: parseInt(limit) }
            );

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('voice.history_fetched', {
                userId: requestingUserId,
                summaryId,
            });
            logger.info(`Fetched voice input history for summary ${summaryId} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Voice input history retrieved successfully',
                data: history,
            });
        } catch (error) {
            logger.error(`Voice input history fetch failed for summary ${summaryId}:`, error);
            metricsCollector.increment('voice.history_fetch_failed', { userId: requestingUserId });
            if (error.message.includes('not found')) {
                return next(new AppError('Summary not found', 404));
            }
            return next(new AppError('Failed to fetch voice input history', 500));
        }
    });

    /**
     * Bulk process voice inputs
     * POST /api/v1/voice/:userId/bulk
     */
    bulkProcessVoiceInputs = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { inputs, language = 'en-US', options = {} } = req.body;

        // Validate input
        if (!Array.isArray(inputs) || inputs.length === 0 || inputs.length > 100) {
            return next(new AppError('Invalid inputs array (1-100 inputs required)', 400));
        }

        // Sanitize input
        const sanitizedData = sanitizeInput({ options });

        try {
            // Verify access
            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            // Process bulk voice inputs
            const result = await this.voiceInputService.bulkProcessVoiceInputs(
                inputs,
                requestingUserId,
                language,
                sanitizedData.options
            );

            // Clear cache
            await Promise.all(result.summaries.map(s => cacheService.deletePattern(`summary:${s.summaryId}:*`)));

            // Emit event
            eventEmitter.emit('voice.bulk_processed', {
                userId: requestingUserId,
                summaryIds: result.summaries.map(s => s.summaryId),
            });

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('voice.bulk_processed', {
                userId: requestingUserId,
                count: result.created,
            });
            logger.info(`Bulk processed ${result.created} voice inputs in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Bulk voice inputs processed successfully',
                data: {
                    requested: inputs.length,
                    created: result.created,
                    summaries: result.summaries,
                },
            });
        } catch (error) {
            logger.error(`Bulk voice input processing failed for user ${requestingUserId}:`, error);
            metricsCollector.increment('voice.bulk_process_failed', { userId: requestingUserId });
            return next(new AppError('Failed to process bulk voice inputs', 500));
        }
    });

    /**
     * Delete a voice input
     * DELETE /api/v1/voice/:userId/:summaryId/:voiceInputId
     */
    deleteVoiceInput = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, summaryId, voiceInputId } = req.params;
        const requestingUserId = req.user.id;

        try {
            // Verify access
            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            // Delete voice input
            await this.voiceInputService.deleteVoiceInput(summaryId, requestingUserId, voiceInputId);

            // Clear cache
            await cacheService.deletePattern(`voice:${summaryId}:*`);

            // Emit event
            eventEmitter.emit('voice.deleted', {
                summaryId,
                userId: requestingUserId,
                voiceInputId,
            });

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('voice.deleted', {
                userId: requestingUserId,
                summaryId,
            });
            logger.info(`Voice input ${voiceInputId} deleted for summary ${summaryId} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Voice input deleted successfully',
            });
        } catch (error) {
            logger.error(`Voice input deletion failed for summary ${summaryId}:`, error);
            metricsCollector.increment('voice.delete_failed', { userId: requestingUserId });
            if (error.message.includes('not found')) {
                return next(new AppError('Summary or voice input not found', 404));
            }
            return next(new AppError('Failed to delete voice input', 500));
        }
    });

    // Helper Methods

    /**
     * Check summary access
     */
    checkSummaryAccess(summary, userId, isAdmin) {
        if (!summary) return false;
        if (isAdmin) return true;
        if (summary.userId === userId) return true;
        if (summary.sharing?.isPublic) return true;
        if (summary.sharing?.collaborators?.some(c => c.userId === userId && c.status === 'accepted')) {
            return true;
        }
        return false;
    }

    /**
     * Validate voice input options
     */
    validateOptions(options) {
        const allowedOptions = ['noiseCancellation', 'accent', 'speechRate'];
        return Object.keys(options).every(key => allowedOptions.includes(key));
    }
}

export default new VoiceInputController();