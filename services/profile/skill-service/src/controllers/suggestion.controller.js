import Suggestion from '../models/Suggestion.js';
import SuggestionService from '../services/SuggestionService.js';
import VerificationService from '../services/VerificationService.js';
import MediaService from '../services/MediaService.js';
import NotificationService from '../services/NotificationService.js';
import { validateSuggestion, sanitizeInput } from '../validations/suggestion.validation.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { catchAsync } from '../handler/catchAsync.js';
import { ApiResponse } from '../utils/response.js';
import { createRateLimiter } from '../utils/rateLimiter.js';
import { cacheService } from '../services/cache.service.js';
import { eventEmitter } from '../events/events.js';
import { metricsCollector } from '../utils/metrics.js';
import mongoose from 'mongoose';
import sanitizeHtml from 'sanitize-html';

// Rate limiters for scalability
const createSuggestionLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 15, // 15 creates per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_suggestion_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const updateSuggestionLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 25, // 25 updates per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_suggestion_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const verificationLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 5, // 5 verification requests per 30 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `verify_suggestion_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const bulkOperationsLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // 3 bulk operations per hour
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_suggestion_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const mediaUploadLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 10, // 10 media uploads per 10 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `media_suggestion_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

class SuggestionController {
    constructor() {
        this.suggestionService = new SuggestionService();
        this.verificationService = new VerificationService();
        this.mediaService = new MediaService();
        this.notificationService = new NotificationService();
    }

    /**
     * Create a new suggestion
     * POST /api/v1/suggestions/:userId
     */
    createSuggestion = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const suggestionData = req.body;
        const requestingUserId = req.user.id;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied: Cannot create suggestion for another user', 403));
        }

        await createSuggestionLimiter(req, res, () => { });

        const validation = validateSuggestion(suggestionData);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        const sanitizedData = sanitizeInput(suggestionData);

        const userSuggestionCount = await Suggestion.countDocuments({
            userId,
            'status.isDeleted': false,
        }).cache({ ttl: 300, key: `user_suggestion_count_${userId}` });

        const limits = this.getUserLimits(req.user.accountType);
        if (userSuggestionCount >= limits.maxSuggestions) {
            return next(new AppError(`Suggestion limit reached (${limits.maxSuggestions})`, 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const suggestion = await this.suggestionService.createSuggestion({
                ...sanitizedData,
                userId,
                metadata: {
                    ...sanitizedData.metadata,
                    createdBy: {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        location: req.geoip,
                    },
                },
            }, { session });

            this.processNewSuggestionAsync(suggestion._id, requestingUserId)
                .catch((err) => logger.error(`Async processing failed for suggestion ${suggestion._id}:`, err));

            metricsCollector.increment('suggestion.created', {
                userId,
                category: suggestion.category,
            });

            eventEmitter.emit('suggestion.created', {
                suggestionId: suggestion._id,
                userId,
                category: suggestion.category,
            });

            if (suggestion.settings?.autoBackup) {
                this.suggestionService.createBackup(suggestion._id, 'create', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for suggestion ${suggestion._id}:`, err));
            }

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`Suggestion created successfully: ${suggestion._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Suggestion created successfully',
                data: {
                    id: suggestion._id,
                    userId: suggestion.userId,
                    title: suggestion.title,
                    status: suggestion.status,
                    createdAt: suggestion.createdAt,
                    processingStatus: 'started',
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Suggestion creation failed for user ${userId}:`, error);
            metricsCollector.increment('suggestion.create_failed', { userId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.code === 11000) {
                return next(new AppError('Suggestion with this title already exists', 409));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out', 504));
            }
            return next(new AppError('Failed to create suggestion', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get user's suggestions with filtering and pagination
     * GET /api/v1/suggestions/:userId
     */
    getSuggestions = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const {
            page = 1,
            limit = 20,
            status,
            category,
            search,
            sortBy = 'recent',
            priority,
            tags,
            includeAnalytics = 'false',
        } = req.query;

        const query = this.buildSuggestionQuery({
            userId,
            status,
            category,
            search,
            priority,
            tags,
        });

        const sortOption = this.buildSortOption(sortBy);
        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
        const skip = (pageNum - 1) * limitNum;

        const cacheKey = `suggestions:${userId}:${JSON.stringify({
            page: pageNum,
            limit: limitNum,
            status,
            category,
            search,
            sortBy,
            priority,
            tags,
        })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('suggestion.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const [suggestions, totalCount] = await Promise.all([
                Suggestion.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select(this.getSelectFields(includeAnalytics === 'true'))
                    .lean(),
                Suggestion.countDocuments(query).cache({ ttl: 300, key: `suggestion_count_${userId}` }),
            ]);

            const processedSuggestions = await Promise.all(
                suggestions.map((suggestion) => this.processSuggestionData(suggestion, includeAnalytics === 'true')),
            );

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                suggestions: processedSuggestions,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages,
                    hasNext: pageNum < totalPages,
                    hasPrev: pageNum > 1,
                    nextPage: pageNum < totalPages ? pageNum + 1 : null,
                    prevPage: pageNum > 1 ? pageNum - 1 : null,
                },
                filters: {
                    status: status || 'all',
                    category: category || 'all',
                    sortBy,
                    search: search || null,
                },
            };

            await cacheService.set(cacheKey, result, 300);
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('suggestion.fetched', {
                userId,
                count: suggestions.length,
                cached: false,
            });
            logger.info(`Fetched ${suggestions.length} suggestions for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch suggestions for user ${userId}:`, error);
            metricsCollector.increment('suggestion.fetch_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid query parameters', 400));
            }
            return next(new AppError('Failed to fetch suggestions', 500));
        }
    });

    /**
     * Get single suggestion by ID
     * GET /api/v1/suggestions/:userId/:id
     */
    getSuggestionById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { includeAnalytics = 'false', includeVerification = 'false' } = req.query;

        try {
            const cacheKey = `suggestion:${id}:${userId}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('suggestion.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const suggestion = await Suggestion.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .cache({ ttl: 600, key: cacheKey });

            if (!suggestion) {
                return next(new AppError('Suggestion not found', 404));
            }

            const hasAccess = this.checkSuggestionAccess(suggestion, requestingUserId, req.user.isAdmin);
            if (!hasAccess) {
                return next(new AppError('Access denied', 403));
            }

            if (requestingUserId !== userId) {
                suggestion.analytics.viewCount += 1;
                suggestion.analytics.lastViewed = new Date();
                await suggestion.save();
            }

            const responseData = this.processSuggestionData(suggestion.toObject(), includeAnalytics === 'true', includeVerification === 'true');

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('suggestion.viewed', {
                userId,
                viewerId: requestingUserId,
                isOwner: userId === requestingUserId,
            });
            logger.info(`Fetched suggestion ${id} for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: responseData });
        } catch (error) {
            logger.error(`Failed to fetch suggestion ${id}:`, error);
            metricsCollector.increment('suggestion.view_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid suggestion ID', 400));
            }
            return next(new AppError('Failed to fetch suggestion', 500));
        }
    });

    /**
     * Update suggestion
     * PUT /api/v1/suggestions/:userId/:id
     */
    updateSuggestion = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const updates = req.body;

        await updateSuggestionLimiter(req, res, () => { });

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const suggestion = await Suggestion.findOne({ _id: id, userId }).session(session);
            if (!suggestion) {
                return next(new AppError('Suggestion not found', 404));
            }

            const allowedUpdates = this.getAllowedUpdateFields();
            const sanitizedUpdates = this.sanitizeUpdates(updates, allowedUpdates);

            if (Object.keys(sanitizedUpdates).length === 0) {
                return next(new AppError('No valid update fields provided', 400));
            }

            let versionCreated = false;
            if (sanitizedUpdates.description && sanitizedUpdates.description !== suggestion.description) {
                await suggestion.createVersion(sanitizedUpdates.description, sanitizedUpdates.title || suggestion.title, 'edit', {
                    userId: requestingUserId,
                }, { session });
                versionCreated = true;
            }

            Object.assign(suggestion, sanitizedUpdates);

            suggestion.metadata.lastModifiedBy = {
                userId: requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date(),
            };

            if (sanitizedUpdates.title || sanitizedUpdates.category) {
                suggestion.verification.status = 'pending';
                this.processExternalVerification(suggestion._id, requestingUserId)
                    .catch((err) => logger.error(`Re-verification failed for suggestion ${id}:`, err));
            }

            await suggestion.save({ session });

            if (sanitizedUpdates.description) {
                await suggestion.calculateQualityScore({ session });
            }

            if (suggestion.settings?.autoBackup) {
                this.suggestionService.createBackup(suggestion._id, 'update', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for suggestion ${id}:`, err));
            }

            await cacheService.deletePattern(`suggestion:${id}:*`);
            await cacheService.deletePattern(`suggestions:${userId}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('suggestion.updated', {
                userId,
                versionCreated,
                fieldsUpdated: Object.keys(sanitizedUpdates).length,
            });

            eventEmitter.emit('suggestion.updated', {
                suggestionId: suggestion._id,
                userId,
                changes: Object.keys(sanitizedUpdates),
                versionCreated,
            });

            logger.info(`Suggestion updated successfully: ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Suggestion updated successfully',
                data: {
                    id: suggestion._id,
                    title: suggestion.title,
                    status: suggestion.status,
                    updatedAt: suggestion.updatedAt,
                    versionCreated,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Suggestion update failed for ${id}:`, error);
            metricsCollector.increment('suggestion.update_failed', { userId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out', 504));
            }
            return next(new AppError('Failed to update suggestion', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete suggestion (soft or permanent)
     * DELETE /api/v1/suggestions/:userId/:id
     */
    deleteSuggestion = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { permanent = 'false' } = req.query;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const suggestion = await Suggestion.findOne({ _id: id, userId }).session(session);
            if (!suggestion) {
                return next(new AppError('Suggestion not found', 404));
            }

            if (permanent === 'true') {
                await Suggestion.findByIdAndDelete(id, { session });
                await this.mediaService.deleteAllMedia(id, 'suggestion', { session });
                this.suggestionService.deleteAllBackups(id)
                    .catch((err) => logger.error(`Failed to delete backups for ${id}:`, err));
                metricsCollector.increment('suggestion.permanently_deleted', { userId });
            } else {
                suggestion.status.isDeleted = true;
                suggestion.status.deletedAt = new Date();
                suggestion.metadata.lastModifiedBy = {
                    userId: requestingUserId,
                    ip: req.ip,
                    userAgent: req.get('User-Agent'),
                    timestamp: new Date(),
                };
                await suggestion.save({ session });
                metricsCollector.increment('suggestion.soft_deleted', { userId });
            }

            await cacheService.deletePattern(`suggestion:${id}:*`);
            await cacheService.deletePattern(`suggestions:${userId}:*`);

            eventEmitter.emit('suggestion.deleted', {
                suggestionId: id,
                userId,
                permanent: permanent === 'true',
            });

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`Suggestion ${id} deleted (permanent: ${permanent}) in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: permanent === 'true' ? 'Suggestion permanently deleted' : 'Suggestion moved to trash',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Suggestion deletion failed for ${id}:`, error);
            metricsCollector.increment('suggestion.delete_failed', { userId });
            return next(new AppError('Failed to delete suggestion', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Bulk operations on suggestions
     * POST /api/v1/suggestions/:userId/bulk
     */
    bulkOperations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { operation, suggestionIds, data = {} } = req.body;

        await bulkOperationsLimiter(req, res, () => { });

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        if (!Array.isArray(suggestionIds) || suggestionIds.length === 0) {
            return next(new AppError('Suggestion IDs array is required', 400));
        }
        if (suggestionIds.length > 100) {
            return next(new AppError('Maximum 100 suggestions can be processed at once', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const query = { _id: { $in: suggestionIds }, userId };
            const { message } = await this.handleBulkOperation(operation, query, data, requestingUserId, req, { session });

            await Promise.all([
                cacheService.deletePattern(`suggestions:${userId}:*`),
                ...suggestionIds.map((id) => cacheService.deletePattern(`suggestion:${id}:*`)),
            ]);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('suggestion.bulk_operation', {
                userId,
                operation,
                count: suggestionIds.length,
            });
            logger.info(`Bulk operation ${operation} completed for ${suggestionIds.length} suggestions in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message,
                data: {
                    operation,
                    requested: suggestionIds.length,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk operation failed for user ${userId}:`, error);
            metricsCollector.increment('suggestion.bulk_operation_failed', { userId, operation });
            return next(new AppError('Bulk operation failed', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get suggestion analytics
     * GET /api/v1/suggestions/:userId/:id/analytics
     */
    getAnalytics = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { timeframe = '30d', metrics = 'basic' } = req.query;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        try {
            const cacheKey = `analytics:suggestion:${id}:${timeframe}:${metrics}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('suggestion.analytics_cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const suggestion = await Suggestion.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('analytics verification metadata createdAt')
                .cache({ ttl: 900, key: cacheKey });

            if (!suggestion) {
                return next(new AppError('Suggestion not found', 404));
            }

            const analytics = this.processAnalyticsData(suggestion, timeframe, metrics);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('suggestion.analytics_viewed', { userId });
            logger.info(`Fetched analytics for suggestion ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: analytics });
        } catch (error) {
            logger.error(`Analytics fetch failed for ${id}:`, error);
            metricsCollector.increment('suggestion.analytics_fetch_failed', { userId });
            return next(new AppError('Failed to fetch analytics', 500));
        }
    });

    /**
     * Duplicate suggestion
     * POST /api/v1/suggestions/:userId/:id/duplicate
     */
    duplicateSuggestion = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { title, includeVersions = 'false' } = req.body;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const originalSuggestion = await Suggestion.findOne({ _id: id, userId }).session(session);
            if (!originalSuggestion) {
                return next(new AppError('Suggestion not found', 404));
            }

            const userSuggestionCount = await Suggestion.countDocuments({
                userId,
                'status.isDeleted': false,
            }).cache({ ttl: 300, key: `user_suggestion_count_${userId}` });

            const limits = this.getUserLimits(req.user.accountType);
            if (userSuggestionCount >= limits.maxSuggestions) {
                return next(new AppError(`Suggestion limit reached (${limits.maxSuggestions})`, 403));
            }

            const duplicateData = originalSuggestion.toObject();
            delete duplicateData._id;
            delete duplicateData.createdAt;
            delete duplicateData.updatedAt;
            delete duplicateData.analytics;

            duplicateData.title = title || `${originalSuggestion.title} (Copy)`;
            duplicateData.status.isActive = true;
            duplicateData.status.isDeleted = false;
            duplicateData.metadata.createdBy = {
                userId: requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date(),
            };

            if (includeVersions !== 'true') {
                duplicateData.versions = [{
                    versionNumber: 1,
                    description: duplicateData.description,
                    title: duplicateData.title,
                    changeType: 'create',
                    isActive: true,
                }];
            }

            const duplicate = new Suggestion(duplicateData);
            await duplicate.save({ session });

            if (duplicate.settings?.autoBackup) {
                this.suggestionService.createBackup(duplicate._id, 'duplicate', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for duplicate ${duplicate._id}:`, err));
            }

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('suggestion.duplicated', { userId });
            logger.info(`Suggestion ${id} duplicated as ${duplicate._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Suggestion duplicated successfully',
                data: {
                    originalId: id,
                    duplicateId: duplicate._id,
                    title: duplicate.title,
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Suggestion duplication failed for ${id}:`, error);
            metricsCollector.increment('suggestion.duplicate_failed', { userId });
            return next(new AppError('Failed to duplicate suggestion', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Verify suggestion
     * POST /api/v1/suggestions/:userId/:id/verify
     */
    verifySuggestion = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        await verificationLimiter(req, res, () => { });

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const suggestion = await Suggestion.findOne({ _id: id, userId }).session(session);
            if (!suggestion) {
                return next(new AppError('Suggestion not found', 404));
            }

            const verificationResult = await this.processExternalVerification(suggestion._id, requestingUserId);
            if (!verificationResult.success) {
                return next(new AppError('Verification failed: ' + verificationResult.message, 424));
            }

            suggestion.verification = {
                status: verificationResult.status,
                confidence: verificationResult.confidence,
                verifiedBy: verificationResult.verifiedBy,
                verifiedAt: new Date(),
                details: verificationResult.details,
            };

            await suggestion.save({ session });

            this.notificationService.notifyUser(userId, {
                type: 'verification_completed',
                message: `Suggestion "${suggestion.title}" verification ${verificationResult.status}`,
                data: { suggestionId: id },
            }).catch((err) => logger.error(`Notification failed for suggestion ${id}:`, err));

            await cacheService.deletePattern(`suggestion:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('suggestion.verified', {
                userId,
                status: verificationResult.status,
            });
            logger.info(`Suggestion ${id} verified in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Suggestion verification completed',
                data: suggestion.verification,
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Verification failed for suggestion ${id}:`, error);
            metricsCollector.increment('suggestion.verify_failed', { userId });
            if (error.message.includes('timeout')) {
                return next(new AppError('External API timeout', 503));
            }
            return next(new AppError('Failed to verify suggestion', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Upload media for suggestion
     * POST /api/v1/suggestions/:userId/:id/media
     */
    uploadMedia = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const files = req.files;

        await mediaUploadLimiter(req, res, () => { });

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const suggestion = await Suggestion.findOne({ _id: id, userId }).session(session);
            if (!suggestion) {
                return next(new AppError('Suggestion not found', 404));
            }

            const validation = this.validateMediaUpload(files, suggestion.media);
            if (!validation.valid) {
                return next(new AppError(validation.message, 422));
            }

            const mediaResults = await this.mediaService.uploadMedia({
                files,
                entityId: id,
                entityType: 'suggestion',
                userId,
            }, { session });

            const scanResults = await this.mediaService.scanMedia(mediaResults);
            if (scanResults.some((result) => result.infected)) {
                return next(new AppError('Media upload failed: Infected file detected', 422));
            }

            suggestion.media.push(...mediaResults);
            await suggestion.save({ session });

            await cacheService.deletePattern(`suggestion:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('suggestion.media_uploaded', {
                userId,
                count: mediaResults.length,
            });
            logger.info(`Uploaded ${mediaResults.length} media files for suggestion ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Media uploaded successfully',
                data: { media: mediaResults },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Media upload failed for suggestion ${id}:`, error);
            metricsCollector.increment('suggestion.media_upload_failed', { userId });
            return next(new AppError('Failed to upload media', 422));
        } finally {
            session.endSession();
        }
    });

    /**
     * Share suggestion
     * POST /api/v1/suggestions/:userId/:id/share
     */
    shareSuggestion = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { platform } = req.body;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const suggestion = await Suggestion.findOne({ _id: id, userId }).session(session);
            if (!suggestion) {
                return next(new AppError('Suggestion not found', 404));
            }

            const hasAccess = this.checkSuggestionAccess(suggestion, requestingUserId, req.user.isAdmin);
            if (!hasAccess) {
                return next(new AppError('Access denied', 403));
            }

            const shareLink = this.generateShareableLink(suggestion, platform);

            suggestion.analytics.shares = suggestion.analytics.shares || { total: 0, byPlatform: {} };
            suggestion.analytics.shares.total += 1;
            suggestion.analytics.shares.byPlatform[platform] = (suggestion.analytics.shares.byPlatform[platform] || 0) + 1;
            await suggestion.save({ session });

            await cacheService.deletePattern(`suggestion:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('suggestion.shared', { userId, platform });
            logger.info(`Suggestion ${id} shared on ${platform} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Suggestion shared successfully',
                data: { shareLink },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Share failed for suggestion ${id}:`, error);
            metricsCollector.increment('suggestion.share_failed', { userId });
            return next(new AppError('Failed to share suggestion', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Endorse suggestion
     * POST /api/v1/suggestions/:userId/:id/endorse
     */
    endorseSuggestion = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const suggestion = await Suggestion.findOne({ _id: id, userId }).session(session);
            if (!suggestion) {
                return next(new AppError('Suggestion not found', 404));
            }

            const isConnected = await this.suggestionService.checkConnectionLevel(userId, requestingUserId);
            if (!isConnected) {
                return next(new AppError('Must be connected to endorse', 403));
            }

            if (suggestion.endorsements.some((e) => e.userId.toString() === requestingUserId)) {
                return next(new AppError('Suggestion already endorsed by this user', 409));
            }

            suggestion.endorsements.push({
                userId: requestingUserId,
                endorsedAt: new Date(),
            });
            await suggestion.save({ session });

            this.notificationService.notifyUser(userId, {
                type: 'endorsement',
                message: `Your suggestion "${suggestion.title}" was endorsed`,
                data: { suggestionId: id, endorserId: requestingUserId },
            }).catch((err) => logger.error(`Notification failed for endorsement ${id}:`, err));

            await cacheService.deletePattern(`suggestion:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('suggestion.endorsed', { userId, endorserId: requestingUserId });
            logger.info(`Suggestion ${id} endorsed in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Suggestion endorsed successfully',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Endorsement failed for suggestion ${id}:`, error);
            metricsCollector.increment('suggestion.endorse_failed', { userId });
            return next(new AppError('Failed to endorse suggestion', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get verification status
     * GET /api/v1/suggestions/:userId/:id/verification
     */
    getVerificationStatus = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        try {
            const cacheKey = `verification:suggestion:${id}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('suggestion.verification_cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const suggestion = await Suggestion.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('verification')
                .cache({ ttl: 60, key: cacheKey });

            if (!suggestion) {
                return next(new AppError('Suggestion not found', 404));
            }

            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('suggestion.verification_viewed', { userId });
            logger.info(`Fetched verification status for suggestion ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                data: suggestion.verification,
            });
        } catch (error) {
            logger.error(`Verification status fetch failed for ${id}:`, error);
            metricsCollector.increment('suggestion.verification_fetch_failed', { userId });
            return next(new AppError('Failed to fetch verification status', 500));
        }
    });

    /**
     * Get trending suggestions
     * GET /api/v1/suggestions/trending
     */
    getTrendingSuggestions = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { timeframe = '7d', category, limit = 20 } = req.query;

        const cacheKey = `trending:suggestions:${timeframe}:${category || 'all'}:${limit}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('suggestion.trending_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const suggestions = await this.suggestionService.getTrendingSuggestions(timeframe, category, parseInt(limit));
            const processedSuggestions = await Promise.all(
                suggestions.map((suggestion) => this.processSuggestionData(suggestion, false)),
            );

            const result = { suggestions: processedSuggestions };
            await cacheService.set(cacheKey, result, 3600);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('suggestion.trending_viewed', { count: suggestions.length });
            logger.info(`Fetched ${suggestions.length} trending suggestions in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch trending suggestions:`, error);
            metricsCollector.increment('suggestion.trending_fetch_failed');
            return next(new AppError('Failed to fetch trending suggestions', 500));
        }
    });

    /**
     * Get suggestions by category
     * GET /api/v1/suggestions/categories/:category
     */
    getSuggestionsByCategory = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { category } = req.params;
        const { page = 1, limit = 20, sortBy = 'recent' } = req.query;

        const cacheKey = `suggestions:category:${category}:${page}:${limit}:${sortBy}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('suggestion.category_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const query = this.buildSuggestionQuery({ category });
            const sortOption = this.buildSortOption(sortBy);
            const pageNum = Math.max(1, parseInt(page));
            const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
            const skip = (pageNum - 1) * limitNum;

            const [suggestions, totalCount] = await Promise.all([
                Suggestion.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select(this.getSelectFields(false))
                    .lean(),
                Suggestion.countDocuments(query).cache({ ttl: 300, key: `suggestion_category_count_${category}` }),
            ]);

            const processedSuggestions = await Promise.all(
                suggestions.map((suggestion) => this.processSuggestionData(suggestion, false)),
            );

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                suggestions: processedSuggestions,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages,
                },
            };

            await cacheService.set(cacheKey, result, 1800);
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('suggestion.category_viewed', { category, count: suggestions.length });
            logger.info(`Fetched ${suggestions.length} suggestions for category ${category} in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch suggestions for category ${category}:`, error);
            metricsCollector.increment('suggestion.category_fetch_failed', { category });
            return next(new AppError('Failed to fetch suggestions by category', 500));
        }
    });

    /**
     * Search suggestions
     * GET /api/v1/suggestions/search
     */
    searchSuggestions = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { query, page = 1, limit = 20, filters = {} } = req.query;

        const cacheKey = `search:suggestions:${query}:${JSON.stringify(filters)}:${page}:${limit}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('suggestion.search_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const searchResults = await this.suggestionService.searchSuggestions(query, filters, {
                page: parseInt(page),
                limit: parseInt(limit),
            });

            const result = {
                suggestions: searchResults.hits,
                totalCount: searchResults.total,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    totalPages: Math.ceil(searchResults.total / parseInt(limit)),
                },
            };

            await cacheService.set(cacheKey, result, 300);
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('suggestion.searched', { query, count: searchResults.hits.length });
            logger.info(`Search returned ${searchResults.hits.length} suggestions in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Search failed for query ${query}:`, error);
            metricsCollector.increment('suggestion.search_failed');
            return next(new AppError('Failed to search suggestions', 500));
        }
    });

    /**
     * Export suggestions as CSV
     * GET /api/v1/suggestions/:userId/export
     */
    exportSuggestions = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { format = 'csv', fields = 'title,description,category,priority' } = req.query;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        try {
            const suggestions = await Suggestion.find({ userId, 'status.isDeleted': false })
                .read('secondaryPreferred')
                .select(fields.split(',').join(' '))
                .lean();

            const csvData = this.convertToCSV(suggestions, fields.split(','));
            const filename = `suggestions_${userId}_${Date.now()}.csv`;

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('suggestion.exported', { userId, format });
            logger.info(`Exported ${suggestions.length} suggestions for user ${userId} in ${responseTime}ms`);

            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            return res.send(csvData);
        } catch (error) {
            logger.error(`Export failed for user ${userId}:`, error);
            metricsCollector.increment('suggestion.export_failed', { userId });
            return next(new AppError('Failed to export suggestions', 500));
        }
    });

    // Helper Methods

    async processNewSuggestionAsync(suggestionId, userId) {
        try {
            const session = await mongoose.startSession();
            session.startTransaction();

            const suggestion = await Suggestion.findById(suggestionId).session(session);
            if (!suggestion) {
                await session.abortTransaction();
                session.endSession();
                return;
            }

            const skillsExtracted = await this.suggestionService.extractSkills(suggestion.description);
            suggestion.skills = skillsExtracted.slice(0, 20);

            await suggestion.calculateQualityScore({ session });

            await this.processExternalVerification(suggestionId, userId);

            await this.suggestionService.indexForSearch(suggestion);

            await this.suggestionService.updateUserStats(userId, { session });

            await suggestion.save({ session });
            await session.commitTransaction();
            logger.info(`Async processing completed for suggestion ${suggestionId}`);
        } catch (error) {
            logger.error(`Async processing failed for suggestion ${suggestionId}:`, error);
        } finally {
            session.endSession();
        }
    }

    checkSuggestionAccess(suggestion, requestingUserId, isAdmin) {
        if (isAdmin) return true;
        if (suggestion.userId.toString() === requestingUserId) return true;
        if (suggestion.visibility === 'public') return true;
        return false;
    }

    getAllowedUpdateFields() {
        return [
            'title',
            'description',
            'category',
            'tags',
            'skills',
            'priority',
            'visibility',
            'status',
        ];
    }

    sanitizeUpdates(updates, allowedFields) {
        const sanitized = {};
        allowedFields.forEach((field) => {
            if (updates[field] !== undefined) {
                sanitized[field] = field === 'description' ? sanitizeHtml(updates[field]) : sanitizeInput(updates[field]);
            }
        });
        return sanitized;
    }

    processAnalyticsData(suggestion, timeframe, metrics) {
        const analytics = suggestion.analytics || {};
        const timeframeDate = new Date();

        switch (timeframe) {
            case '7d':
                timeframeDate.setDate(timeframeDate.getDate() - 7);
                break;
            case '30d':
                timeframeDate.setDate(timeframeDate.getDate() - 30);
                break;
            case '90d':
                timeframeDate.setDate(timeframeDate.getDate() - 90);
                break;
            default:
                timeframeDate.setDate(timeframeDate.getDate() - 30);
        }

        const filteredAnalytics = {
            viewCount: analytics.viewCount || 0,
            shares: {
                total: analytics.shares?.total || 0,
                byPlatform: analytics.shares?.byPlatform || {},
            },
            endorsements: suggestion.endorsements?.length || 0,
        };

        if (metrics === 'detailed') {
            filteredAnalytics.verification = suggestion.verification;
        }

        return filteredAnalytics;
    }

    getUserLimits(accountType) {
        const limits = {
            free: { maxSuggestions: 20, maxMedia: 5, maxSizeMB: 50 },
            premium: { maxSuggestions: 100, maxMedia: 20, maxSizeMB: 200 },
            enterprise: { maxSuggestions: 500, maxMedia: 50, maxSizeMB: 500 },
        };
        return limits[accountType] || limits.free;
    }

    buildSuggestionQuery({ userId, status, category, search, priority, tags }) {
        const query = { userId, 'status.isDeleted': false };

        if (status && status !== 'all') {
            query['status.isActive'] = status === 'active';
        }
        if (category && category !== 'all') {
            query.category = category;
        }
        if (priority) {
            query.priority = priority;
        }
        if (tags) {
            const tagArray = tags.split(',').map((tag) => tag.trim().toLowerCase());
            query.tags = { $in: tagArray };
        }
        if (search) {
            query.$text = { $search: search };
        }

        return query;
    }

    buildSortOption(sortBy) {
        const sortOptions = {
            recent: { updatedAt: -1 },
            oldest: { createdAt: 1 },
            title: { title: 1 },
            popular: { 'analytics.viewCount': -1 },
            quality: { 'metadata.qualityScore': -1 },
            verified: { 'verification.confidence': -1 },
        };
        return sortOptions[sortBy] || sortOptions.recent;
    }

    getSelectFields(includeAnalytics) {
        const baseFields = 'title description category tags skills priority visibility status createdAt updatedAt';
        return includeAnalytics ? baseFields + ' analytics' : baseFields;
    }

    async processSuggestionData(suggestion, includeAnalytics = false, includeVerification = false) {
        const processed = { ...suggestion };

        if (!includeAnalytics) {
            delete processed.analytics;
        }
        if (!includeVerification) {
            delete processed.verification;
        }

        return processed;
    }

    calculateTrendingScore(suggestion) {
        const viewsWeight = 0.4;
        const sharesWeight = 0.3;
        const endorsementsWeight = 0.2;
        const recencyWeight = 0.1;

        const daysSinceCreated = (Date.now() - new Date(suggestion.createdAt)) / (1000 * 60 * 60 * 24);
        const recencyScore = Math.max(0, 10 - daysSinceCreated);

        return (
            (suggestion.analytics.viewCount * viewsWeight) +
            ((suggestion.analytics.shares?.total || 0) * sharesWeight) +
            (suggestion.endorsements.length * endorsementsWeight) +
            (recencyScore * recencyWeight)
        );
    }

    validateMediaUpload(files, existingMedia) {
        const limits = this.getUserLimits('premium');
        const totalSize = files.reduce((sum, file) => sum + file.size, 0);
        const totalMedia = existingMedia.length + files.length;

        if (totalMedia > limits.maxMedia) {
            return { valid: false, message: `Maximum ${limits.maxMedia} media files allowed` };
        }
        if (totalSize > limits.maxSizeMB * 1024 * 1024) {
            return { valid: false, message: `Total media size exceeds ${limits.maxSizeMB}MB` };
        }

        return { valid: true };
    }

    async processExternalVerification(suggestionId, userId) {
        try {
            const suggestion = await Suggestion.findById(suggestionId);
            const result = await this.verificationService.verifySuggestion({
                suggestionId,
                userId,
                title: suggestion.title,
                category: suggestion.category,
                priority: suggestion.priority,
            });

            return result;
        } catch (error) {
            logger.error(`External verification failed for suggestion ${suggestionId}:`, error);
            return { success: false, message: error.message };
        }
    }

    generateShareableLink(suggestion, platform) {
        const baseUrl = process.env.APP_URL || 'https://app.example.com';
        return `${baseUrl}/suggestions/${suggestion._id}/share?platform=${platform}`;
    }

    async handleBulkOperation(operation, query, data, requestingUserId, req, options = {}) {
        let updateData = {};
        let message = '';

        switch (operation) {
            case 'delete':
                updateData = {
                    'status.isDeleted': true,
                    'status.deletedAt': new Date(),
                    updatedAt: new Date(),
                    'metadata.lastModifiedBy': {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = 'Suggestions moved to trash';
                break;
            case 'archive':
                updateData = {
                    'status.isActive': false,
                    updatedAt: new Date(),
                    'metadata.lastModifiedBy': {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = 'Suggestions archived';
                break;
            case 'publish':
                updateData = {
                    'status.isActive': true,
                    visibility: 'public',
                    updatedAt: new Date(),
                    'metadata.lastModifiedBy': {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = 'Suggestions published';
                break;
            case 'updateCategory':
                if (!data.category) {
                    throw new AppError('Category is required', 400);
                }
                updateData = {
                    category: data.category,
                    updatedAt: new Date(),
                    'metadata.lastModifiedBy': {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = `Category updated to ${data.category}`;
                break;
            case 'updateTags':
                if (!Array.isArray(data.tags)) {
                    throw new AppError('Tags array is required', 400);
                }
                updateData = {
                    $addToSet: {
                        tags: { $each: data.tags.map((tag) => tag.trim().toLowerCase()).slice(0, 15) },
                    },
                    updatedAt: new Date(),
                    'metadata.lastModifiedBy': {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = 'Tags updated';
                break;
            case 'updateVisibility':
                if (!data.visibility) {
                    throw new AppError('Visibility is required', 400);
                }
                updateData = {
                    visibility: data.visibility,
                    updatedAt: new Date(),
                    'metadata.lastModifiedBy': {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = `Visibility updated to ${data.visibility}`;
                break;
        }

        const result = await Suggestion.updateMany(query, updateData, options);
        return { message, result };
    }

    convertToCSV(data, fields) {
        const headers = fields.join(',');
        const rows = data.map((item) => {
            return fields.map((field) => {
                const value = item[field] || '';
                return `"${value.toString().replace(/"/g, '""')}"`;
            }).join(',');
        });
        return `${headers}\n${rows.join('\n')}`;
    }
}

export default new SuggestionController();