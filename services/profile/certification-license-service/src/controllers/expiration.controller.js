import Expiration from '../models/Expiration.js';
import ExpirationService from '../services/ExpirationService.js';
import NotificationService from '../services/NotificationService.js';
import MediaService from '../services/MediaService.js';
import AnalyticsService from '../services/AnalyticsService.js';
import { validateExpiration, validateBulkExpiration, validateSearch, sanitizeInput } from '../validations/expiration.validation.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { catchAsync } from '../handler/catchAsync.js';
import { ApiResponse } from '../utils/response.js';
import { createRateLimiter } from '../utils/rateLimiter.js';
import { cacheService } from '../services/cache.service.js';
import { eventEmitter } from '../events/events.js';
import { metricsCollector } from '../utils/metrics.js';
import mongoose from 'mongoose';
import AWS from 'aws-sdk';
import { v4 as uuidv4 } from 'uuid';
import { queueService } from '../services/queue.service.js';

// Initialize AWS S3 for media and backups
const s3 = new AWS.S3({
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    region: process.env.AWS_REGION,
});

// Rate limiters for high-traffic endpoints (optimized for 1M users)
const createExpirationLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 5, // 5 creates per 10 minutes per user
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_expiration_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const updateExpirationLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 10, // 10 updates per 5 minutes per user
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_expiration_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const mediaUploadLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 media uploads per 15 minutes per user
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `media_expiration_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const bulkOperationLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 3, // 3 bulk operations per 30 minutes per user
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_expiration_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const searchLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 30, // 30 searches per 5 minutes per user
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `search_expiration_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const reminderLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 10, // 10 reminder triggers per hour per user
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `reminder_expiration_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

class ExpirationController {
    constructor() {
        this.expirationService = ExpirationService;
        this.notificationService = NotificationService;
        this.mediaService = MediaService;
        this.analyticsService = AnalyticsService;
    }

    /**
     * Create a new expiration record
     * POST /api/v1/expirations
     */
    createExpiration = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const expirationData = req.body;
        const requestingUserId = req.user.id;

        await createExpirationLimiter(req, res, () => { });

        const validation = validateExpiration(expirationData);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        const sanitizedData = this.sanitizeInput(expirationData);
        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const expiration = await this.expirationService.createExpiration({
                ...sanitizedData,
                metadata: {
                    ...sanitizedData.metadata,
                    createdBy: {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                },
            }, { session });

            // Queue async tasks for search indexing, analytics, and reminders
            await queueService.addJob('processExpiration', {
                expirationId: expiration._id,
                userId: requestingUserId,
                action: 'create',
            });

            // Create backup
            await this.createBackup(expiration._id, 'create', requestingUserId, { session });

            eventEmitter.emit('expiration.created', {
                expirationId: expiration._id,
                userId: requestingUserId,
                entityType: expiration.entityType,
                entityId: expiration.entityId,
            });

            metricsCollector.increment('expiration.created', { userId: requestingUserId });
            await session.commitTransaction();
            logger.info(`Expiration created: ${expiration._id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Expiration record created successfully',
                data: {
                    id: expiration._id,
                    entityType: expiration.entityType,
                    entityId: expiration.entityId,
                    expirationDate: expiration.expirationDate,
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Expiration creation failed for user ${requestingUserId}:`, error);
            metricsCollector.increment('expiration.create_failed', { userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get expiration record by ID
     * GET /api/v1/expirations/:id
     */
    getExpirationById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;
        const cacheKey = `expiration:${id}:${requestingUserId}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('expiration.cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const expiration = await this.expirationService.getExpirationById(id, requestingUserId);
            if (!expiration) {
                return next(new AppError('Expiration record not found', 404));
            }

            await this.analyticsService.incrementView(id, 'expiration', requestingUserId);
            await cacheService.set(cacheKey, expiration, 300); // Shorter TTL for high-traffic
            metricsCollector.increment('expiration.fetched', { id, userId: requestingUserId });
            logger.info(`Fetched expiration ${id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, { data: expiration });
        } catch (error) {
            logger.error(`Failed to fetch expiration ${id}:`, error);
            metricsCollector.increment('expiration.fetch_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        }
    });

    /**
     * Update expiration record
     * PUT /api/v1/expirations/:id
     */
    updateExpiration = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const updates = req.body;
        const requestingUserId = req.user.id;

        await updateExpirationLimiter(req, res, () => { });

        const validation = validateExpiration(updates, true);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const sanitizedUpdates = this.sanitizeUpdates(updates);
            const expiration = await this.expirationService.updateExpiration(id, requestingUserId, sanitizedUpdates, {
                session,
                requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
            });

            await queueService.addJob('processExpiration', {
                expirationId: id,
                userId: requestingUserId,
                action: 'update',
            });

            await this.createBackup(id, 'update', requestingUserId, { session });
            await cacheService.deletePattern(`expiration:${id}:*`);

            eventEmitter.emit('expiration.updated', {
                expirationId: id,
                userId: requestingUserId,
                changes: Object.keys(sanitizedUpdates),
            });

            metricsCollector.increment('expiration.updated', { id, userId: requestingUserId });
            await session.commitTransaction();
            logger.info(`Expiration updated: ${id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Expiration record updated successfully',
                data: {
                    id,
                    entityType: expiration.entityType,
                    entityId: expiration.entityId,
                    expirationDate: expiration.expirationDate,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Expiration update failed for ${id}:`, error);
            metricsCollector.increment('expiration.update_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete expiration record
     * DELETE /api/v1/expirations/:id
     */
    deleteExpiration = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const { permanent = false } = req.query;
        const requestingUserId = req.user.id;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            await this.expirationService.deleteExpiration(id, requestingUserId, permanent, { session });
            await cacheService.deletePattern(`expiration:${id}:*`);

            eventEmitter.emit('expiration.deleted', {
                expirationId: id,
                userId: requestingUserId,
                permanent,
            });

            metricsCollector.increment(permanent ? 'expiration.permanently_deleted' : 'expiration.soft_deleted', {
                id,
                userId: requestingUserId,
            });
            await session.commitTransaction();
            logger.info(`Expiration ${id} deleted (permanent: ${permanent}) in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: `Expiration record ${permanent ? 'permanently' : 'soft'} deleted successfully`,
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Expiration deletion failed for ${id}:`, error);
            metricsCollector.increment('expiration.delete_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Upload media for expiration record
     * POST /api/v1/expirations/:id/media
     */
    uploadMedia = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const files = req.files;
        const requestingUserId = req.user.id;

        await mediaUploadLimiter(req, res, () => { });

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const expiration = await Expiration.findById(id).session(session);
            if (!expiration) {
                return next(new AppError('Expiration record not found', 404));
            }

            const validation = this.expirationService.validateMediaUpload(files, expiration.media || []);
            if (!validation.valid) {
                return next(new AppError(validation.message, 422));
            }

            const mediaResults = await this.mediaService.uploadMedia({
                files,
                entityId: id,
                entityType: 'expiration',
                userId: requestingUserId,
            }, { session });

            expiration.media = expiration.media || [];
            expiration.media.push(...mediaResults);
            await expiration.save({ session });

            await cacheService.deletePattern(`expiration:${id}:*`);

            eventEmitter.emit('expiration.media_uploaded', {
                expirationId: id,
                userId: requestingUserId,
                mediaCount: mediaResults.length,
            });

            metricsCollector.increment('expiration.media_uploaded', { id, count: mediaResults.length });
            await session.commitTransaction();
            logger.info(`Uploaded ${mediaResults.length} media for expiration ${id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Media uploaded successfully',
                data: { media: mediaResults },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Media upload failed for expiration ${id}:`, error);
            metricsCollector.increment('expiration.media_upload_failed', { id });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get expiration records with filtering and pagination
     * GET /api/v1/expirations
     */
    getExpirations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { page = 1, limit = 20, status, entityType, entityId, search, sortBy = 'expirationDate' } = req.query;
        const requestingUserId = req.user.id;
        const cacheKey = `expirations:${requestingUserId}:${JSON.stringify({ page, limit, status, entityType, entityId, search, sortBy })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('expiration.cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const query = this.buildExpirationQuery({ status, entityType, entityId, search });
            const sortOption = this.buildSortOption(sortBy);
            const pageNum = Math.max(1, parseInt(page));
            const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
            const skip = (pageNum - 1) * limitNum;

            const [expirations, totalCount] = await Promise.all([
                Expiration.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select('entityType entityId expirationDate status analytics')
                    .lean(),
                Expiration.countDocuments(query).cache({ ttl: 300, key: `expiration_count_${requestingUserId}` }),
            ]);

            const processedExpirations = expirations.map((expiration) => ({
                ...expiration,
                isExpired: new Date(expiration.expirationDate) < new Date(),
            }));

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                expirations: processedExpirations,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages,
                    hasNext: pageNum < totalPages,
                    hasPrev: pageNum > 1,
                },
                filters: { status, entityType, entityId, search, sortBy },
            };

            await cacheService.set(cacheKey, result, 300);
            metricsCollector.increment('expiration.fetched', { count: expirations.length, userId: requestingUserId });
            logger.info(`Fetched ${expirations.length} expiration records in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch expiration records:`, error);
            metricsCollector.increment('expiration.fetch_failed', { userId: requestingUserId });
            return next(this.handleError(error));
        }
    });

    /**
     * Search expiration records
     * GET /api/v1/expirations/search
     */
    searchExpirations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { query, filters = {}, page = 1, limit = 20 } = req.body;
        const requestingUserId = req.user.id;

        await searchLimiter(req, res, () => { });

        const validation = validateSearch({ query, filters });
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        const cacheKey = `expiration_search:${requestingUserId}:${JSON.stringify({ query, filters, page, limit })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('expiration.search_cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const result = await this.expirationService.searchExpirations(query, filters, { page, limit });
            await cacheService.set(cacheKey, result, 300);

            metricsCollector.increment('expiration.searched', { count: result.hits.length, userId: requestingUserId });
            logger.info(`Search returned ${result.hits.length} expiration records in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Search completed successfully',
                data: result,
            });
        } catch (error) {
            logger.error(`Search failed for query ${query}:`, error);
            metricsCollector.increment('expiration.search_failed', { userId: requestingUserId });
            return next(new AppError('Failed to search expiration records', 500));
        }
    });

    /**
     * Get upcoming expirations
     * GET /api/v1/expirations/upcoming
     */
    getUpcomingExpirations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { days = 30, entityType, limit = 20 } = req.query;
        const requestingUserId = req.user.id;
        const cacheKey = `upcoming_expirations:${requestingUserId}:${days}:${entityType || 'all'}:${limit}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('expiration.upcoming_cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const cutoffDate = new Date();
            cutoffDate.setDate(cutoffDate.getDate() + parseInt(days));

            const query = {
                'status.isDeleted': false,
                expirationDate: { $gte: new Date(), $lte: cutoffDate },
            };
            if (entityType) query.entityType = entityType;

            const expirations = await Expiration.find(query)
                .read('secondaryPreferred')
                .sort({ expirationDate: 1 })
                .limit(parseInt(limit))
                .select('entityType entityId expirationDate status')
                .lean();

            await cacheService.set(cacheKey, expirations, 300);
            metricsCollector.increment('expiration.upcoming_fetched', { count: expirations.length, userId: requestingUserId });
            logger.info(`Fetched ${expirations.length} upcoming expiration records in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Upcoming expiration records fetched successfully',
                data: expirations,
            });
        } catch (error) {
            logger.error(`Failed to fetch upcoming expirations:`, error);
            metricsCollector.increment('expiration.upcoming_fetch_failed', { userId: requestingUserId });
            return next(new AppError('Failed to fetch upcoming expirations', 500));
        }
    });

    /**
     * Renew expiration record
     * POST /api/v1/expirations/:id/renew
     */
    renewExpiration = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const { newExpirationDate } = req.body;
        const requestingUserId = req.user.id;

        if (!newExpirationDate || isNaN(new Date(newExpirationDate))) {
            return next(new AppError('Invalid expiration date', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const expiration = await Expiration.findById(id).session(session);
            if (!expiration) {
                return next(new AppError('Expiration record not found', 404));
            }

            expiration.expirationDate = new Date(newExpirationDate);
            expiration.status.workflow = 'active';
            expiration.status.isActive = true;
            expiration.metadata.lastModifiedBy = {
                userId: requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date(),
            };

            await expiration.save({ session });
            await cacheService.deletePattern(`expiration:${id}:*`);

            await queueService.addJob('processExpiration', {
                expirationId: id,
                userId: requestingUserId,
                action: 'renew',
            });

            await this.createBackup(id, 'renew', requestingUserId, { session });

            eventEmitter.emit('expiration.renewed', {
                expirationId: id,
                userId: requestingUserId,
                newExpirationDate,
            });

            metricsCollector.increment('expiration.renewed', { id, userId: requestingUserId });
            await session.commitTransaction();
            logger.info(`Expiration ${id} renewed in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Expiration record renewed successfully',
                data: {
                    id,
                    entityType: expiration.entityType,
                    entityId: expiration.entityId,
                    expirationDate: expiration.expirationDate,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Renewal failed for expiration ${id}:`, error);
            metricsCollector.increment('expiration.renew_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Trigger expiration reminders
     * POST /api/v1/expirations/:id/remind
     */
    triggerReminder = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;

        await reminderLimiter(req, res, () => { });

        try {
            const expiration = await Expiration.findById(id).lean();
            if (!expiration) {
                return next(new AppError('Expiration record not found', 404));
            }

            await queueService.addJob('sendExpirationReminder', {
                expirationId: id,
                userId: requestingUserId,
                entityType: expiration.entityType,
                entityId: expiration.entityId,
                expirationDate: expiration.expirationDate,
            });

            metricsCollector.increment('expiration.reminder_triggered', { id, userId: requestingUserId });
            logger.info(`Reminder triggered for expiration ${id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Expiration reminder queued successfully',
            });
        } catch (error) {
            logger.error(`Failed to trigger reminder for expiration ${id}:`, error);
            metricsCollector.increment('expiration.reminder_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        }
    });

    /**
     * Bulk create expiration records
     * POST /api/v1/expirations/bulk
     */
    bulkCreateExpirations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const expirationsData = req.body.expirations;
        const requestingUserId = req.user.id;

        await bulkOperationLimiter(req, res, () => { });

        const validation = validateBulkExpiration(expirationsData);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const sanitizedData = expirationsData.map((expiration) => this.sanitizeInput(expiration));
            const createdExpirations = await Promise.all(
                sanitizedData.map((expiration) =>
                    this.expirationService.createExpiration({
                        ...expiration,
                        metadata: {
                            ...expiration.metadata,
                            createdBy: {
                                userId: requestingUserId,
                                ip: req.ip,
                                userAgent: req.get('User-Agent'),
                                timestamp: new Date(),
                            },
                        },
                    }, { session })
                )
            );

            await Promise.all(
                createdExpirations.map((expiration) =>
                    queueService.addJob('processExpiration', {
                        expirationId: expiration._id,
                        userId: requestingUserId,
                        action: 'create',
                    })
                )
            );

            await Promise.all(
                createdExpirations.map((expiration) =>
                    this.createBackup(expiration._id, 'create', requestingUserId, { session })
                )
            );

            eventEmitter.emit('expiration.bulk_created', {
                expirationIds: createdExpirations.map((expiration) => expiration._id),
                userId: requestingUserId,
            });

            metricsCollector.increment('expiration.bulk_created', { count: createdExpirations.length, userId: requestingUserId });
            await session.commitTransaction();
            logger.info(`Bulk created ${createdExpirations.length} expiration records in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Expiration records created successfully',
                data: createdExpirations.map((expiration) => ({
                    id: expiration._id,
                    entityType: expiration.entityType,
                    entityId: expiration.entityId,
                    expirationDate: expiration.expirationDate,
                })),
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk expiration creation failed:`, error);
            metricsCollector.increment('expiration.bulk_create_failed', { userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Bulk update expiration records
     * PUT /api/v1/expirations/bulk
     */
    bulkUpdateExpirations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const updates = req.body.updates;
        const requestingUserId = req.user.id;

        await bulkOperationLimiter(req, res, () => { });

        const validation = validateBulkExpiration(updates);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const sanitizedUpdates = updates.map((update) => ({
                id: update.id,
                data: this.sanitizeUpdates(update.data),
            }));

            const updatedExpirations = await Promise.all(
                sanitizedUpdates.map(({ id, data }) =>
                    this.expirationService.updateExpiration(id, requestingUserId, data, {
                        session,
                        requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                    })
                )
            );

            await Promise.all(
                updatedExpirations.map((expiration) =>
                    queueService.addJob('processExpiration', {
                        expirationId: expiration._id,
                        userId: requestingUserId,
                        action: 'update',
                    })
                )
            );

            await Promise.all(
                updatedExpirations.map((expiration) =>
                    this.createBackup(expiration._id, 'update', requestingUserId, { session })
                )
            );

            await Promise.all(
                updatedExpirations.map((expiration) => cacheService.deletePattern(`expiration:${expiration._id}:*`))
            );

            eventEmitter.emit('expiration.bulk_updated', {
                expirationIds: updatedExpirations.map((expiration) => expiration._id),
                userId: requestingUserId,
            });

            metricsCollector.increment('expiration.bulk_updated', { count: updatedExpirations.length, userId: requestingUserId });
            await session.commitTransaction();
            logger.info(`Bulk updated ${updatedExpirations.length} expiration records in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Expiration records updated successfully',
                data: updatedExpirations.map((expiration) => ({
                    id: expiration._id,
                    entityType: expiration.entityType,
                    entityId: expiration.entityId,
                    expirationDate: expiration.expirationDate,
                })),
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk expiration update failed:`, error);
            metricsCollector.increment('expiration.bulk_update_failed', { userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get expiration analytics
     * GET /api/v1/expirations/:id/analytics
     */
    getExpirationAnalytics = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const { timeframe = '30d' } = req.query;
        const requestingUserId = req.user.id;
        const cacheKey = `expiration_analytics:${id}:${timeframe}:${requestingUserId}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('expiration.analytics_cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const analytics = await this.analyticsService.getExpirationAnalytics(id, timeframe);
            await cacheService.set(cacheKey, analytics, 300);

            metricsCollector.increment('expiration.analytics_fetched', { id, userId: requestingUserId });
            logger.info(`Fetched analytics for expiration ${id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Expiration analytics fetched successfully',
                data: analytics,
            });
        } catch (error) {
            logger.error(`Failed to fetch analytics for expiration ${id}:`, error);
            metricsCollector.increment('expiration.analytics_fetch_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        }
    });

    /**
     * Export expiration data
     * GET /api/v1/expirations/:id/export
     */
    exportExpiration = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const { format = 'json' } = req.query;
        const requestingUserId = req.user.id;

        try {
            const expiration = await Expiration.findById(id)
                .select('entityType entityId expirationDate status analytics metadata')
                .lean();

            if (!expiration) {
                return next(new AppError('Expiration record not found', 404));
            }

            let exportData;
            let contentType;
            let extension;

            switch (format.toLowerCase()) {
                case 'json':
                    exportData = JSON.stringify(expiration, null, 2);
                    contentType = 'application/json';
                    extension = 'json';
                    break;
                case 'csv':
                    exportData = this.convertToCSV(expiration);
                    contentType = 'text/csv';
                    extension = 'csv';
                    break;
                default:
                    return next(new AppError('Unsupported export format', 400));
            }

            const exportKey = `expiration_export_${id}_${uuidv4()}.${extension}`;
            await s3.upload({
                Bucket: process.env.S3_EXPORT_BUCKET,
                Key: exportKey,
                Body: exportData,
                ContentType: contentType,
                ServerSideEncryption: 'AES256',
            }).promise();

            const signedUrl = await s3.getSignedUrlPromise('getObject', {
                Bucket: process.env.S3_EXPORT_BUCKET,
                Key: exportKey,
                Expires: 3600, // 1 hour
            });

            metricsCollector.increment('expiration.exported', { id, format, userId: requestingUserId });
            logger.info(`Exported expiration ${id} as ${format} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Expiration record exported successfully',
                data: { url: signedUrl },
            });
        } catch (error) {
            logger.error(`Export failed for expiration ${id}:`, error);
            metricsCollector.increment('expiration.export_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        }
    });

    /**
     * Get expiration statistics
     * GET /api/v1/expirations/:id/stats
     */
    getExpirationStats = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;
        const cacheKey = `expiration_stats:${id}:${requestingUserId}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('expiration.stats_cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const stats = await this.expirationService.getExpirationStats(id);
            await cacheService.set(cacheKey, stats, 3600);

            metricsCollector.increment('expiration.stats_fetched', { id, userId: requestingUserId });
            logger.info(`Fetched stats for expiration ${id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Expiration stats fetched successfully',
                data: stats,
            });
        } catch (error) {
            logger.error(`Failed to fetch stats for expiration ${id}:`, error);
            metricsCollector.increment('expiration.stats_fetch_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        }
    });

    /**
     * Archive expiration record
     * POST /api/v1/expirations/:id/archive
     */
    archiveExpiration = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const expiration = await Expiration.findById(id).session(session);
            if (!expiration) {
                return next(new AppError('Expiration record not found', 404));
            }

            expiration.status.isActive = false;
            expiration.status.isArchived = true;
            expiration.status.archivedAt = new Date();
            await expiration.save({ session });

            await cacheService.deletePattern(`expiration:${id}:*`);

            eventEmitter.emit('expiration.archived', {
                expirationId: id,
                userId: requestingUserId,
            });

            metricsCollector.increment('expiration.archived', { id, userId: requestingUserId });
            await session.commitTransaction();
            logger.info(`Expiration ${id} archived in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Expiration record archived successfully',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Archiving failed for expiration ${id}:`, error);
            metricsCollector.increment('expiration.archive_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Restore expiration record
     * POST /api/v1/expirations/:id/restore
     */
    restoreExpiration = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const expiration = await Expiration.findById(id).session(session);
            if (!expiration) {
                return next(new AppError('Expiration record not found', 404));
            }

            expiration.status.isActive = true;
            expiration.status.isArchived = false;
            expiration.status.restoredAt = new Date();
            await expiration.save({ session });

            await cacheService.deletePattern(`expiration:${id}:*`);

            eventEmitter.emit('expiration.restored', {
                expirationId: id,
                userId: requestingUserId,
            });

            metricsCollector.increment('expiration.restored', { id, userId: requestingUserId });
            await session.commitTransaction();
            logger.info(`Expiration ${id} restored in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Expiration record restored successfully',
                data: {
                    id,
                    entityType: expiration.entityType,
                    entityId: expiration.entityId,
                    expirationDate: expiration.expirationDate,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Restoring failed for expiration ${id}:`, error);
            metricsCollector.increment('expiration.restore_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get expiration audit logs
     * GET /api/v1/expirations/:id/audit
     */
    getAuditLogs = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const { page = 1, limit = 20, action } = req.query;
        const requestingUserId = req.user.id;
        const cacheKey = `expiration_audit:${id}:${page}:${limit}:${action || 'all'}:${requestingUserId}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('expiration.audit_cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const pageNum = Math.max(1, parseInt(page));
            const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
            const skip = (pageNum - 1) * limitNum;

            const query = { expirationId: id };
            if (action) query.action = action;

            const [logs, totalCount] = await Promise.all([
                this.expirationService.getAuditLogs(id, { page: pageNum, limit: limitNum, action }),
                this.expirationService.countAuditLogs(id, action),
            ]);

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                logs,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages,
                },
            };

            await cacheService.set(cacheKey, result, 300);
            metricsCollector.increment('expiration.audit_fetched', { count: logs.length, userId: requestingUserId });
            logger.info(`Fetched ${logs.length} audit logs for expiration ${id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Audit logs fetched successfully',
                data: result,
            });
        } catch (error) {
            logger.error(`Failed to fetch audit logs for expiration ${id}:`, error);
            metricsCollector.increment('expiration.audit_fetch_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        }
    });

    /**
     * Create backup of expiration record
     * @param {string} expirationId - Expiration ID
     * @param {string} action - Action type
     * @param {string} userId - User ID
     * @param {Object} options - Additional options
     */
    async createBackup(expirationId, action, userId, options = {}) {
        const startTime = Date.now();
        try {
            const expiration = await Expiration.findById(expirationId).lean();
            if (!expiration) {
                throw new AppError('Expiration record not found', 404);
            }

            const backupKey = `expiration_backup_${expirationId}_${Date.now()}_${uuidv4()}`;
            await s3.upload({
                Bucket: process.env.S3_BACKUP_BUCKET,
                Key: backupKey,
                Body: JSON.stringify({
                    expiration,
                    action,
                    userId,
                    timestamp: new Date(),
                }),
                ContentType: 'application/json',
                ServerSideEncryption: 'AES256',
            }).promise();

            metricsCollector.increment('expiration.backup_created', { userId, action });
            logger.info(`Backup created for expiration ${expirationId} (${action}) in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to create backup for expiration ${expirationId}:`, error);
            metricsCollector.increment('expiration.backup_failed', { userId });
            throw error;
        }
    }

    /**
     * Handle errors
     * @param {Error} error - Error object
     * @returns {AppError}
     */
    handleError(error) {
        if (error.name === 'ValidationError') {
            return new AppError('Validation failed: ' + error.message, 400);
        }
        if (error.code === 11000) {
            return new AppError('Expiration record already exists', 409);
        }
        if (error.name === 'CastError') {
            return new AppError('Invalid expiration ID', 400);
        }
        if (error.message.includes('timeout')) {
            return new AppError('Operation timed out', 504);
        }
        return new AppError('Operation failed', 500);
    }

    /**
     * Sanitize input data
     * @param {Object} data - Input data
     * @returns {Object} - Sanitized data
     */
    sanitizeInput(data) {
        return {
            ...sanitizeInput(data),
            entityType: sanitizeHtml(data.entityType || ''),
            entityId: sanitizeHtml(data.entityId || ''),
            description: sanitizeHtml(data.description || ''),
        };
    }

    /**
     * Sanitize updates
     * @param {Object} updates - Update data
     * @returns {Object} - Sanitized updates
     */
    sanitizeUpdates(updates) {
        const allowedFields = ['entityType', 'entityId', 'expirationDate', 'status', 'description'];
        const sanitized = {};
        allowedFields.forEach((field) => {
            if (updates[field] !== undefined) {
                sanitized[field] = ['entityType', 'entityId', 'description'].includes(field)
                    ? sanitizeHtml(updates[field])
                    : sanitizeInput(updates[field]);
            }
        });
        return sanitized;
    }

    /**
     * Build MongoDB query
     * @param {Object} params - Query parameters
     * @returns {Object} - MongoDB query
     */
    buildExpirationQuery({ status, entityType, entityId, search }) {
        const query = { 'status.isDeleted': false };
        if (status) query['status.workflow'] = status;
        if (entityType) query.entityType = entityType;
        if (entityId) query.entityId = entityId;
        if (search) query.$text = { $search: search };
        return query;
    }

    /**
     * Build sort option
     * @param {string} sortBy - Sort criteria
     * @returns {Object} - Sort option
     */
    buildSortOption(sortBy) {
        const sortOptions = {
            expirationDate: { expirationDate: 1 },
            recent: { createdAt: -1 },
            entityType: { entityType: 1 },
            popularity: { 'analytics.views': -1 },
        };
        return sortOptions[sortBy] || sortOptions.expirationDate;
    }

    /**
     * Convert expiration to CSV
     * @param {Object} expiration - Expiration data
     * @returns {string} - CSV string
     */
    convertToCSV(expiration) {
        const headers = ['id', 'entityType', 'entityId', 'expirationDate', 'status', 'created_at'];
        const row = [
            expiration._id,
            `"${expiration.entityType.replace(/"/g, '""')}"`,
            `"${expiration.entityId.replace(/"/g, '""')}"`,
            expiration.expirationDate,
            expiration.status.workflow,
            expiration.createdAt,
        ];
        return [headers.join(','), row.join(',')].join('\n');
    }
}

export default new ExpirationController();