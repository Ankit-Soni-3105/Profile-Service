import Trend from '../models/Trend.js';
import TrendService from '../services/TrendService.js';
import VerificationService from '../services/VerificationService.js';
import MediaService from '../services/MediaService.js';
import NotificationService from '../services/NotificationService.js';
import { validateTrend, sanitizeInput } from '../validations/trend.validation.js';
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
const createTrendLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 15, // 15 creates per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_trend_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const updateTrendLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 25, // 25 updates per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_trend_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const verificationLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 5, // 5 verification requests per 30 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `verify_trend_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const bulkOperationsLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // 3 bulk operations per hour
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_trend_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const mediaUploadLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 10, // 10 media uploads per 10 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `media_trend_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

class TrendController {
    constructor() {
        this.trendService = new TrendService();
        this.verificationService = new VerificationService();
        this.mediaService = new MediaService();
        this.notificationService = new NotificationService();
    }

    /**
     * Create a new trend
     * POST /api/v1/trends/:userId
     */
    createTrend = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const trendData = req.body;
        const requestingUserId = req.user.id;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied: Cannot create trend for another user', 403));
        }

        await createTrendLimiter(req, res, () => { });

        const validation = validateTrend(trendData);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        const sanitizedData = sanitizeInput(trendData);

        const userTrendCount = await Trend.countDocuments({
            userId,
            'status.isDeleted': false,
        }).cache({ ttl: 300, key: `user_trend_count_${userId}` });

        const limits = this.getUserLimits(req.user.accountType);
        if (userTrendCount >= limits.maxTrends) {
            return next(new AppError(`Trend limit reached (${limits.maxTrends})`, 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const trend = await this.trendService.createTrend({
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

            this.processNewTrendAsync(trend._id, requestingUserId)
                .catch((err) => logger.error(`Async processing failed for trend ${trend._id}:`, err));

            metricsCollector.increment('trend.created', {
                userId,
                category: trend.category,
            });

            eventEmitter.emit('trend.created', {
                trendId: trend._id,
                userId,
                category: trend.category,
            });

            if (trend.settings?.autoBackup) {
                this.trendService.createBackup(trend._id, 'create', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for trend ${trend._id}:`, err));
            }

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`Trend created successfully: ${trend._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Trend created successfully',
                data: {
                    id: trend._id,
                    userId: trend.userId,
                    title: trend.title,
                    status: trend.status,
                    createdAt: trend.createdAt,
                    processingStatus: 'started',
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Trend creation failed for user ${userId}:`, error);
            metricsCollector.increment('trend.create_failed', { userId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.code === 11000) {
                return next(new AppError('Trend with this title already exists', 409));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out', 504));
            }
            return next(new AppError('Failed to create trend', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get user's trends with filtering and pagination
     * GET /api/v1/trends/:userId
     */
    getTrends = catchAsync(async (req, res, next) => {
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
            impact,
            tags,
            includeAnalytics = 'false',
        } = req.query;

        const query = this.buildTrendQuery({
            userId,
            status,
            category,
            search,
            impact,
            tags,
        });

        const sortOption = this.buildSortOption(sortBy);
        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
        const skip = (pageNum - 1) * limitNum;

        const cacheKey = `trends:${userId}:${JSON.stringify({
            page: pageNum,
            limit: limitNum,
            status,
            category,
            search,
            sortBy,
            impact,
            tags,
        })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('trend.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const [trends, totalCount] = await Promise.all([
                Trend.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select(this.getSelectFields(includeAnalytics === 'true'))
                    .lean(),
                Trend.countDocuments(query).cache({ ttl: 300, key: `trend_count_${userId}` }),
            ]);

            const processedTrends = await Promise.all(
                trends.map((trend) => this.processTrendData(trend, includeAnalytics === 'true')),
            );

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                trends: processedTrends,
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
            metricsCollector.increment('trend.fetched', {
                userId,
                count: trends.length,
                cached: false,
            });
            logger.info(`Fetched ${trends.length} trends for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch trends for user ${userId}:`, error);
            metricsCollector.increment('trend.fetch_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid query parameters', 400));
            }
            return next(new AppError('Failed to fetch trends', 500));
        }
    });

    /**
     * Get single trend by ID
     * GET /api/v1/trends/:userId/:id
     */
    getTrendById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { includeAnalytics = 'false', includeVerification = 'false' } = req.query;

        try {
            const cacheKey = `trend:${id}:${userId}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('trend.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const trend = await Trend.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .cache({ ttl: 600, key: cacheKey });

            if (!trend) {
                return next(new AppError('Trend not found', 404));
            }

            const hasAccess = this.checkTrendAccess(trend, requestingUserId, req.user.isAdmin);
            if (!hasAccess) {
                return next(new AppError('Access denied', 403));
            }

            if (requestingUserId !== userId) {
                trend.analytics.viewCount += 1;
                trend.analytics.lastViewed = new Date();
                await trend.save();
            }

            const responseData = this.processTrendData(trend.toObject(), includeAnalytics === 'true', includeVerification === 'true');

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('trend.viewed', {
                userId,
                viewerId: requestingUserId,
                isOwner: userId === requestingUserId,
            });
            logger.info(`Fetched trend ${id} for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: responseData });
        } catch (error) {
            logger.error(`Failed to fetch trend ${id}:`, error);
            metricsCollector.increment('trend.view_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid trend ID', 400));
            }
            return next(new AppError('Failed to fetch trend', 500));
        }
    });

    /**
     * Update trend
     * PUT /api/v1/trends/:userId/:id
     */
    updateTrend = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const updates = req.body;

        await updateTrendLimiter(req, res, () => { });

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const trend = await Trend.findOne({ _id: id, userId }).session(session);
            if (!trend) {
                return next(new AppError('Trend not found', 404));
            }

            const allowedUpdates = this.getAllowedUpdateFields();
            const sanitizedUpdates = this.sanitizeUpdates(updates, allowedUpdates);

            if (Object.keys(sanitizedUpdates).length === 0) {
                return next(new AppError('No valid update fields provided', 400));
            }

            let versionCreated = false;
            if (sanitizedUpdates.description && sanitizedUpdates.description !== trend.description) {
                await trend.createVersion(sanitizedUpdates.description, sanitizedUpdates.title || trend.title, 'edit', {
                    userId: requestingUserId,
                }, { session });
                versionCreated = true;
            }

            Object.assign(trend, sanitizedUpdates);

            trend.metadata.lastModifiedBy = {
                userId: requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date(),
            };

            if (sanitizedUpdates.title || sanitizedUpdates.category) {
                trend.verification.status = 'pending';
                this.processExternalVerification(trend._id, requestingUserId)
                    .catch((err) => logger.error(`Re-verification failed for trend ${id}:`, err));
            }

            await trend.save({ session });

            if (sanitizedUpdates.description) {
                await trend.calculateQualityScore({ session });
            }

            if (trend.settings?.autoBackup) {
                this.trendService.createBackup(trend._id, 'update', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for trend ${id}:`, err));
            }

            await cacheService.deletePattern(`trend:${id}:*`);
            await cacheService.deletePattern(`trends:${userId}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('trend.updated', {
                userId,
                versionCreated,
                fieldsUpdated: Object.keys(sanitizedUpdates).length,
            });

            eventEmitter.emit('trend.updated', {
                trendId: trend._id,
                userId,
                changes: Object.keys(sanitizedUpdates),
                versionCreated,
            });

            logger.info(`Trend updated successfully: ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Trend updated successfully',
                data: {
                    id: trend._id,
                    title: trend.title,
                    status: trend.status,
                    updatedAt: trend.updatedAt,
                    versionCreated,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Trend update failed for ${id}:`, error);
            metricsCollector.increment('trend.update_failed', { userId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out', 504));
            }
            return next(new AppError('Failed to update trend', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete trend (soft or permanent)
     * DELETE /api/v1/trends/:userId/:id
     */
    deleteTrend = catchAsync(async (req, res, next) => {
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

            const trend = await Trend.findOne({ _id: id, userId }).session(session);
            if (!trend) {
                return next(new AppError('Trend not found', 404));
            }

            if (permanent === 'true') {
                await Trend.findByIdAndDelete(id, { session });
                await this.mediaService.deleteAllMedia(id, 'trend', { session });
                this.trendService.deleteAllBackups(id)
                    .catch((err) => logger.error(`Failed to delete backups for ${id}:`, err));
                metricsCollector.increment('trend.permanently_deleted', { userId });
            } else {
                trend.status.isDeleted = true;
                trend.status.deletedAt = new Date();
                trend.metadata.lastModifiedBy = {
                    userId: requestingUserId,
                    ip: req.ip,
                    userAgent: req.get('User-Agent'),
                    timestamp: new Date(),
                };
                await trend.save({ session });
                metricsCollector.increment('trend.soft_deleted', { userId });
            }

            await cacheService.deletePattern(`trend:${id}:*`);
            await cacheService.deletePattern(`trends:${userId}:*`);

            eventEmitter.emit('trend.deleted', {
                trendId: id,
                userId,
                permanent: permanent === 'true',
            });

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`Trend ${id} deleted (permanent: ${permanent}) in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: permanent === 'true' ? 'Trend permanently deleted' : 'Trend moved to trash',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Trend deletion failed for ${id}:`, error);
            metricsCollector.increment('trend.delete_failed', { userId });
            return next(new AppError('Failed to delete trend', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Bulk operations on trends
     * POST /api/v1/trends/:userId/bulk
     */
    bulkOperations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { operation, trendIds, data = {} } = req.body;

        await bulkOperationsLimiter(req, res, () => { });

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        if (!Array.isArray(trendIds) || trendIds.length === 0) {
            return next(new AppError('Trend IDs array is required', 400));
        }
        if (trendIds.length > 100) {
            return next(new AppError('Maximum 100 trends can be processed at once', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const query = { _id: { $in: trendIds }, userId };
            const { message } = await this.handleBulkOperation(operation, query, data, requestingUserId, req, { session });

            await Promise.all([
                cacheService.deletePattern(`trends:${userId}:*`),
                ...trendIds.map((id) => cacheService.deletePattern(`trend:${id}:*`)),
            ]);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('trend.bulk_operation', {
                userId,
                operation,
                count: trendIds.length,
            });
            logger.info(`Bulk operation ${operation} completed for ${trendIds.length} trends in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message,
                data: {
                    operation,
                    requested: trendIds.length,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk operation failed for user ${userId}:`, error);
            metricsCollector.increment('trend.bulk_operation_failed', { userId, operation });
            return next(new AppError('Bulk operation failed', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get trend analytics
     * GET /api/v1/trends/:userId/:id/analytics
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
            const cacheKey = `analytics:trend:${id}:${timeframe}:${metrics}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('trend.analytics_cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const trend = await Trend.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('analytics verification metadata createdAt')
                .cache({ ttl: 900, key: cacheKey });

            if (!trend) {
                return next(new AppError('Trend not found', 404));
            }

            const analytics = this.processAnalyticsData(trend, timeframe, metrics);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('trend.analytics_viewed', { userId });
            logger.info(`Fetched analytics for trend ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: analytics });
        } catch (error) {
            logger.error(`Analytics fetch failed for ${id}:`, error);
            metricsCollector.increment('trend.analytics_fetch_failed', { userId });
            return next(new AppError('Failed to fetch analytics', 500));
        }
    });

    /**
     * Duplicate trend
     * POST /api/v1/trends/:userId/:id/duplicate
     */
    duplicateTrend = catchAsync(async (req, res, next) => {
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

            const originalTrend = await Trend.findOne({ _id: id, userId }).session(session);
            if (!originalTrend) {
                return next(new AppError('Trend not found', 404));
            }

            const userTrendCount = await Trend.countDocuments({
                userId,
                'status.isDeleted': false,
            }).cache({ ttl: 300, key: `user_trend_count_${userId}` });

            const limits = this.getUserLimits(req.user.accountType);
            if (userTrendCount >= limits.maxTrends) {
                return next(new AppError(`Trend limit reached (${limits.maxTrends})`, 403));
            }

            const duplicateData = originalTrend.toObject();
            delete duplicateData._id;
            delete duplicateData.createdAt;
            delete duplicateData.updatedAt;
            delete duplicateData.analytics;

            duplicateData.title = title || `${originalTrend.title} (Copy)`;
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

            const duplicate = new Trend(duplicateData);
            await duplicate.save({ session });

            if (duplicate.settings?.autoBackup) {
                this.trendService.createBackup(duplicate._id, 'duplicate', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for duplicate ${duplicate._id}:`, err));
            }

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('trend.duplicated', { userId });
            logger.info(`Trend ${id} duplicated as ${duplicate._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Trend duplicated successfully',
                data: {
                    originalId: id,
                    duplicateId: duplicate._id,
                    title: duplicate.title,
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Trend duplication failed for ${id}:`, error);
            metricsCollector.increment('trend.duplicate_failed', { userId });
            return next(new AppError('Failed to duplicate trend', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Verify trend
     * POST /api/v1/trends/:userId/:id/verify
     */
    verifyTrend = catchAsync(async (req, res, next) => {
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

            const trend = await Trend.findOne({ _id: id, userId }).session(session);
            if (!trend) {
                return next(new AppError('Trend not found', 404));
            }

            const verificationResult = await this.processExternalVerification(trend._id, requestingUserId);
            if (!verificationResult.success) {
                return next(new AppError('Verification failed: ' + verificationResult.message, 424));
            }

            trend.verification = {
                status: verificationResult.status,
                confidence: verificationResult.confidence,
                verifiedBy: verificationResult.verifiedBy,
                verifiedAt: new Date(),
                details: verificationResult.details,
            };

            await trend.save({ session });

            this.notificationService.notifyUser(userId, {
                type: 'verification_completed',
                message: `Trend "${trend.title}" verification ${verificationResult.status}`,
                data: { trendId: id },
            }).catch((err) => logger.error(`Notification failed for trend ${id}:`, err));

            await cacheService.deletePattern(`trend:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('trend.verified', {
                userId,
                status: verificationResult.status,
            });
            logger.info(`Trend ${id} verified in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Trend verification completed',
                data: trend.verification,
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Verification failed for trend ${id}:`, error);
            metricsCollector.increment('trend.verify_failed', { userId });
            if (error.message.includes('timeout')) {
                return next(new AppError('External API timeout', 503));
            }
            return next(new AppError('Failed to verify trend', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Upload media for trend
     * POST /api/v1/trends/:userId/:id/media
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

            const trend = await Trend.findOne({ _id: id, userId }).session(session);
            if (!trend) {
                return next(new AppError('Trend not found', 404));
            }

            const validation = this.validateMediaUpload(files, trend.media);
            if (!validation.valid) {
                return next(new AppError(validation.message, 422));
            }

            const mediaResults = await this.mediaService.uploadMedia({
                files,
                entityId: id,
                entityType: 'trend',
                userId,
            }, { session });

            const scanResults = await this.mediaService.scanMedia(mediaResults);
            if (scanResults.some((result) => result.infected)) {
                return next(new AppError('Media upload failed: Infected file detected', 422));
            }

            trend.media.push(...mediaResults);
            await trend.save({ session });

            await cacheService.deletePattern(`trend:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('trend.media_uploaded', {
                userId,
                count: mediaResults.length,
            });
            logger.info(`Uploaded ${mediaResults.length} media files for trend ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Media uploaded successfully',
                data: { media: mediaResults },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Media upload failed for trend ${id}:`, error);
            metricsCollector.increment('trend.media_upload_failed', { userId });
            return next(new AppError('Failed to upload media', 422));
        } finally {
            session.endSession();
        }
    });

    /**
     * Share trend
     * POST /api/v1/trends/:userId/:id/share
     */
    shareTrend = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { platform } = req.body;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const trend = await Trend.findOne({ _id: id, userId }).session(session);
            if (!trend) {
                return next(new AppError('Trend not found', 404));
            }

            const hasAccess = this.checkTrendAccess(trend, requestingUserId, req.user.isAdmin);
            if (!hasAccess) {
                return next(new AppError('Access denied', 403));
            }

            const shareLink = this.generateShareableLink(trend, platform);

            trend.analytics.shares = trend.analytics.shares || { total: 0, byPlatform: {} };
            trend.analytics.shares.total += 1;
            trend.analytics.shares.byPlatform[platform] = (trend.analytics.shares.byPlatform[platform] || 0) + 1;
            await trend.save({ session });

            await cacheService.deletePattern(`trend:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('trend.shared', { userId, platform });
            logger.info(`Trend ${id} shared on ${platform} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Trend shared successfully',
                data: { shareLink },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Share failed for trend ${id}:`, error);
            metricsCollector.increment('trend.share_failed', { userId });
            return next(new AppError('Failed to share trend', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Endorse trend
     * POST /api/v1/trends/:userId/:id/endorse
     */
    endorseTrend = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const trend = await Trend.findOne({ _id: id, userId }).session(session);
            if (!trend) {
                return next(new AppError('Trend not found', 404));
            }

            const isConnected = await this.trendService.checkConnectionLevel(userId, requestingUserId);
            if (!isConnected) {
                return next(new AppError('Must be connected to endorse', 403));
            }

            if (trend.endorsements.some((e) => e.userId.toString() === requestingUserId)) {
                return next(new AppError('Trend already endorsed by this user', 409));
            }

            trend.endorsements.push({
                userId: requestingUserId,
                endorsedAt: new Date(),
            });
            await trend.save({ session });

            this.notificationService.notifyUser(userId, {
                type: 'endorsement',
                message: `Your trend "${trend.title}" was endorsed`,
                data: { trendId: id, endorserId: requestingUserId },
            }).catch((err) => logger.error(`Notification failed for endorsement ${id}:`, err));

            await cacheService.deletePattern(`trend:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('trend.endorsed', { userId, endorserId: requestingUserId });
            logger.info(`Trend ${id} endorsed in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Trend endorsed successfully',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Endorsement failed for trend ${id}:`, error);
            metricsCollector.increment('trend.endorse_failed', { userId });
            return next(new AppError('Failed to endorse trend', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get verification status
     * GET /api/v1/trends/:userId/:id/verification
     */
    getVerificationStatus = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        try {
            const cacheKey = `verification:trend:${id}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('trend.verification_cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const trend = await Trend.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('verification')
                .cache({ ttl: 60, key: cacheKey });

            if (!trend) {
                return next(new AppError('Trend not found', 404));
            }

            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('trend.verification_viewed', { userId });
            logger.info(`Fetched verification status for trend ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                data: trend.verification,
            });
        } catch (error) {
            logger.error(`Verification status fetch failed for ${id}:`, error);
            metricsCollector.increment('trend.verification_fetch_failed', { userId });
            return next(new AppError('Failed to fetch verification status', 500));
        }
    });

    /**
     * Get trending trends
     * GET /api/v1/trends/trending
     */
    getTrendingTrends = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { timeframe = '7d', category, limit = 20 } = req.query;

        const cacheKey = `trending:trends:${timeframe}:${category || 'all'}:${limit}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('trend.trending_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const trends = await this.trendService.getTrendingTrends(timeframe, category, parseInt(limit));
            const processedTrends = await Promise.all(
                trends.map((trend) => this.processTrendData(trend, false)),
            );

            const result = { trends: processedTrends };
            await cacheService.set(cacheKey, result, 3600);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('trend.trending_viewed', { count: trends.length });
            logger.info(`Fetched ${trends.length} trending trends in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch trending trends:`, error);
            metricsCollector.increment('trend.trending_fetch_failed');
            return next(new AppError('Failed to fetch trending trends', 500));
        }
    });

    /**
     * Get trends by category
     * GET /api/v1/trends/categories/:category
     */
    getTrendsByCategory = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { category } = req.params;
        const { page = 1, limit = 20, sortBy = 'recent' } = req.query;

        const cacheKey = `trends:category:${category}:${page}:${limit}:${sortBy}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('trend.category_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const query = this.buildTrendQuery({ category });
            const sortOption = this.buildSortOption(sortBy);
            const pageNum = Math.max(1, parseInt(page));
            const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
            const skip = (pageNum - 1) * limitNum;

            const [trends, totalCount] = await Promise.all([
                Trend.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select(this.getSelectFields(false))
                    .lean(),
                Trend.countDocuments(query).cache({ ttl: 300, key: `trend_category_count_${category}` }),
            ]);

            const processedTrends = await Promise.all(
                trends.map((trend) => this.processTrendData(trend, false)),
            );

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                trends: processedTrends,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages,
                },
            };

            await cacheService.set(cacheKey, result, 1800);
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('trend.category_viewed', { category, count: trends.length });
            logger.info(`Fetched ${trends.length} trends for category ${category} in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch trends for category ${category}:`, error);
            metricsCollector.increment('trend.category_fetch_failed', { category });
            return next(new AppError('Failed to fetch trends by category', 500));
        }
    });

    /**
     * Search trends
     * GET /api/v1/trends/search
     */
    searchTrends = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { query, page = 1, limit = 20, filters = {} } = req.query;

        const cacheKey = `search:trends:${query}:${JSON.stringify(filters)}:${page}:${limit}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('trend.search_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const searchResults = await this.trendService.searchTrends(query, filters, {
                page: parseInt(page),
                limit: parseInt(limit),
            });

            const result = {
                trends: searchResults.hits,
                totalCount: searchResults.total,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    totalPages: Math.ceil(searchResults.total / parseInt(limit)),
                },
            };

            await cacheService.set(cacheKey, result, 300);
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('trend.searched', { query, count: searchResults.hits.length });
            logger.info(`Search returned ${searchResults.hits.length} trends in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Search failed for query ${query}:`, error);
            metricsCollector.increment('trend.search_failed');
            return next(new AppError('Failed to search trends', 500));
        }
    });

    /**
     * Export trends as CSV
     * GET /api/v1/trends/:userId/export
     */
    exportTrends = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { format = 'csv', fields = 'title,description,category,impact' } = req.query;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        try {
            const trends = await Trend.find({ userId, 'status.isDeleted': false })
                .read('secondaryPreferred')
                .select(fields.split(',').join(' '))
                .lean();

            const csvData = this.convertToCSV(trends, fields.split(','));
            const filename = `trends_${userId}_${Date.now()}.csv`;

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('trend.exported', { userId, format });
            logger.info(`Exported ${trends.length} trends for user ${userId} in ${responseTime}ms`);

            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            return res.send(csvData);
        } catch (error) {
            logger.error(`Export failed for user ${userId}:`, error);
            metricsCollector.increment('trend.export_failed', { userId });
            return next(new AppError('Failed to export trends', 500));
        }
    });

    // Helper Methods

    async processNewTrendAsync(trendId, userId) {
        try {
            const session = await mongoose.startSession();
            session.startTransaction();

            const trend = await Trend.findById(trendId).session(session);
            if (!trend) {
                await session.abortTransaction();
                session.endSession();
                return;
            }

            const skillsExtracted = await this.trendService.extractSkills(trend.description);
            trend.skills = skillsExtracted.slice(0, 20);

            await trend.calculateQualityScore({ session });

            await this.processExternalVerification(trendId, userId);

            await this.trendService.indexForSearch(trend);

            await this.trendService.updateUserStats(userId, { session });

            await trend.save({ session });
            await session.commitTransaction();
            logger.info(`Async processing completed for trend ${trendId}`);
        } catch (error) {
            logger.error(`Async processing failed for trend ${trendId}:`, error);
        } finally {
            session.endSession();
        }
    }

    checkTrendAccess(trend, requestingUserId, isAdmin) {
        if (isAdmin) return true;
        if (trend.userId.toString() === requestingUserId) return true;
        if (trend.visibility === 'public') return true;
        return false;
    }

    getAllowedUpdateFields() {
        return [
            'title',
            'description',
            'category',
            'tags',
            'skills',
            'impact',
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

    processAnalyticsData(trend, timeframe, metrics) {
        const analytics = trend.analytics || {};
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
            endorsements: trend.endorsements?.length || 0,
        };

        if (metrics === 'detailed') {
            filteredAnalytics.verification = trend.verification;
        }

        return filteredAnalytics;
    }

    getUserLimits(accountType) {
        const limits = {
            free: { maxTrends: 20, maxMedia: 5, maxSizeMB: 50 },
            premium: { maxTrends: 100, maxMedia: 20, maxSizeMB: 200 },
            enterprise: { maxTrends: 500, maxMedia: 50, maxSizeMB: 500 },
        };
        return limits[accountType] || limits.free;
    }

    buildTrendQuery({ userId, status, category, search, impact, tags }) {
        const query = { userId, 'status.isDeleted': false };

        if (status && status !== 'all') {
            query['status.isActive'] = status === 'active';
        }
        if (category && category !== 'all') {
            query.category = category;
        }
        if (impact) {
            query.impact = impact;
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
        const baseFields = 'title description category tags skills impact visibility status createdAt updatedAt';
        return includeAnalytics ? baseFields + ' analytics' : baseFields;
    }

    async processTrendData(trend, includeAnalytics = false, includeVerification = false) {
        const processed = { ...trend };

        if (!includeAnalytics) {
            delete processed.analytics;
        }
        if (!includeVerification) {
            delete processed.verification;
        }

        return processed;
    }

    calculateTrendingScore(trend) {
        const viewsWeight = 0.4;
        const sharesWeight = 0.3;
        const endorsementsWeight = 0.2;
        const recencyWeight = 0.1;

        const daysSinceCreated = (Date.now() - new Date(trend.createdAt)) / (1000 * 60 * 60 * 24);
        const recencyScore = Math.max(0, 10 - daysSinceCreated);

        return (
            (trend.analytics.viewCount * viewsWeight) +
            ((trend.analytics.shares?.total || 0) * sharesWeight) +
            (trend.endorsements.length * endorsementsWeight) +
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

    async processExternalVerification(trendId, userId) {
        try {
            const trend = await Trend.findById(trendId);
            const result = await this.verificationService.verifyTrend({
                trendId,
                userId,
                title: trend.title,
                category: trend.category,
                impact: trend.impact,
            });

            return result;
        } catch (error) {
            logger.error(`External verification failed for trend ${trendId}:`, error);
            return { success: false, message: error.message };
        }
    }

    generateShareableLink(trend, platform) {
        const baseUrl = process.env.APP_URL || 'https://app.example.com';
        return `${baseUrl}/trends/${trend._id}/share?platform=${platform}`;
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
                message = 'Trends moved to trash';
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
                message = 'Trends archived';
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
                message = 'Trends published';
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

        const result = await Trend.updateMany(query, updateData, options);
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

export default new TrendController();