import Media from '../models/Media.js';
import MediaService from '../services/MediaService.js';
import NotificationService from '../services/NotificationService.js';
import VerificationService from '../services/VerificationService.js';
import { validateMedia, sanitizeInput } from '../validations/media.validation.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { catchAsync } from '../handler/catchAsync.js';
import { ApiResponse } from '../utils/response.js';
import { createRateLimiter } from '../utils/rateLimiter.js';
import { cacheService } from '../services/cache.service.js';
import { eventEmitter } from '../events/events.js';
import { metricsCollector } from '../utils/metrics.js';
import mongoose from 'mongoose';
import { CircuitBreaker } from '../utils/circuitBreaker.js';
import { retry } from '../utils/retry.js';
import { elasticsearchClient } from '../config/elasticsearch.js';
import { s3Client } from '../config/s3.js';
import moment from 'moment';

// Rate limiters for high concurrency and abuse prevention
const uploadMediaLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000, // 10-minute window
    max: 10, // Allow 10 uploads per user per IP
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `upload_media_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
    legacyHeaders: false,
});

const updateMediaLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5-minute window
    max: 20, // Allow 20 updates
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_media_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const scanMediaLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30-minute window
    max: 5, // Strict limit for external scan API calls
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `scan_media_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const bulkUploadLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // Hourly limit
    max: 3, // Conservative limit for bulk uploads
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_media_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const searchLimiter = createRateLimiter({
    windowMs: 1 * 60 * 1000, // 1-minute window
    max: 50, // Allow frequent searches
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `search_media_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const analyticsLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5-minute window
    max: 20, // Moderate limit for analytics requests
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `analytics_media_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

class MediaController {
    constructor() {
        this.mediaService = MediaService;
        this.notificationService = NotificationService;
        this.verificationService = VerificationService;
        this.circuitBreaker = new CircuitBreaker({
            timeout: 10000,
            errorThresholdPercentage: 50,
            resetTimeout: 30000,
        });
        this.retryConfig = {
            retries: 3,
            delay: 100,
            backoff: 'exponential',
        };
    }

    /**
     * Upload media
     * POST /api/v1/media/:entityType/:entityId
     * Uploads media for a specific entity (e.g., course, organization).
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    uploadMedia = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { entityType, entityId } = req.params;
        const requestingUserId = req.user.id;
        const files = req.files || [];
        const { category } = req.body;

        if (!req.user.isAdmin && !req.user.permissions.includes(`upload_${entityType}_media`)) {
            return next(new AppError('Access denied', 403));
        }

        await uploadMediaLimiter(req, res, () => { });

        if (files.length === 0) {
            return next(new AppError('No files provided', 400));
        }

        const validation = validateMedia({ files, entityType, category });
        if (!validation.valid) {
            metricsCollector.increment('media.validation_failed', { userId: requestingUserId, errors: validation.errors.length });
            return next(new AppError(`Validation failed: ${validation.message}`, 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const entityModel = this.getEntityModel(entityType);
            const entity = await entityModel.findById(entityId).session(session);
            if (!entity || entity.status === 'deleted') {
                return next(new AppError(`${entityType} not found`, 404));
            }

            const mediaResults = await this.mediaService.uploadMedia({
                files,
                entityId,
                entityType,
                userId: requestingUserId,
                category: sanitizeInput(category) || 'general',
            }, { session });

            const scanResults = await this.circuitBreaker.fire(async () => {
                return await retry(() => this.mediaService.scanMedia(mediaResults), this.retryConfig);
            });
            const infected = scanResults.filter(r => r.infected);
            if (infected.length > 0) {
                await this.mediaService.deleteMedia(infected.map(m => m.id), { session });
                metricsCollector.increment('media.scan_failed', { entityId, infectedCount: infected.length });
                return next(new AppError(`Media upload failed: ${infected.length} infected files detected`, 422));
            }

            const mediaRecords = mediaResults.map(file => ({
                entityId,
                entityType,
                userId: requestingUserId,
                fileName: file.fileName,
                fileType: file.fileType,
                fileSize: file.fileSize,
                url: file.url,
                category: file.category,
                status: 'active',
                metadata: {
                    createdBy: {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        location: req.geoip || { country: 'unknown', city: 'unknown' },
                        referrer: req.get('Referer') || 'direct',
                    },
                    version: 1,
                    updateCount: 0,
                },
                analytics: {
                    views: { total: 0, unique: 0, byDate: [] },
                    downloads: { total: 0, byDate: [] },
                },
            }));

            const insertedMedia = await Media.insertMany(mediaRecords, { session });
            entity.media = [...(entity.media || []), ...insertedMedia.map(m => m._id)];
            await entity.save({ session });

            for (const media of insertedMedia) {
                this.processNewMediaAsync(media._id, requestingUserId).catch((err) => {
                    logger.error(`Async processing failed for media ${media._id}:`, err);
                });
            }

            metricsCollector.increment('media.uploaded', { entityId, entityType, mediaCount: files.length });
            metricsCollector.timing('media.upload_time', Date.now() - startTime);
            eventEmitter.emit('media.uploaded', { entityId, entityType, mediaCount: files.length });

            await session.commitTransaction();
            return ApiResponse.success(res, {
                message: 'Media uploaded successfully',
                data: { entityId, entityType, mediaCount: insertedMedia.length, mediaIds: insertedMedia.map(m => m._id) },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Media upload failed for ${entityType} ${entityId}:`, { error: error.message });
            metricsCollector.increment('media.upload_failed', { entityId, entityType });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Get media for an entity
     * GET /api/v1/media/:entityType/:entityId
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    getMedia = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { entityType, entityId } = req.params;
        const requestingUserId = req.user.id;
        const { page = 1, limit = 20, category, status, sortBy = 'recent' } = req.query;

        if (!req.user.isAdmin && !req.user.permissions.includes(`view_${entityType}_media`)) {
            const hasAccess = await this.checkAccess(entityType, entityId, requestingUserId);
            if (!hasAccess) {
                return next(new AppError('Access denied', 403));
            }
        }

        await searchLimiter(req, res, () => { });

        const query = this.buildMediaQuery({ entityType, entityId, category, status });
        const sortOption = this.buildSortOption(sortBy);
        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
        const skip = (pageNum - 1) * limitNum;

        const cacheKey = `media:${entityType}:${entityId}:${JSON.stringify({ page, limit, category, status, sortBy })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('media.cache_hit', { entityId, entityType });
                return ApiResponse.success(res, cached);
            }

            const [media, totalCount] = await Promise.all([
                Media.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select('-__v')
                    .lean({ virtuals: true }),
                Media.countDocuments(query).cache({ ttl: 300 }),
            ]);

            const result = {
                media,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages: Math.ceil(totalCount / limitNum),
                    hasNext: pageNum < Math.ceil(totalCount / limitNum),
                    hasPrev: pageNum > 1,
                },
            };

            await cacheService.set(cacheKey, result, 300, [`media:${entityType}:${entityId}`]);
            metricsCollector.increment('media.fetched', { entityId, entityType, count: media.length });
            metricsCollector.timing('media.get_list_time', Date.now() - startTime);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch media for ${entityType} ${entityId}:`, { error: error.message });
            metricsCollector.increment('media.fetch_failed', { entityId, entityType });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        }
    });

    /**
     * Get single media by ID
     * GET /api/v1/media/:id
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    getMediaById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;

        const media = await Media.findById(id).select('entityType entityId').lean();
        if (!media || media.status === 'deleted') {
            return next(new AppError('Media not found', 404));
        }

        if (!req.user.isAdmin && !req.user.permissions.includes(`view_${media.entityType}_media`)) {
            const hasAccess = await this.checkAccess(media.entityType, media.entityId, requestingUserId);
            if (!hasAccess) {
                return next(new AppError('Access denied', 403));
            }
        }

        const cacheKey = `media:${id}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('media.cache_hit', { id });
                return ApiResponse.success(res, cached);
            }

            const mediaRecord = await Media.findById(id)
                .read('secondaryPreferred')
                .select('-__v')
                .lean({ virtuals: true });

            if (!mediaRecord || mediaRecord.status === 'deleted') {
                return next(new AppError('Media not found', 404));
            }

            await this.updateAnalytics(mediaRecord, requestingUserId);
            await cacheService.set(cacheKey, mediaRecord, 600, [`media:id:${id}`]);
            metricsCollector.increment('media.viewed', { id, entityType: mediaRecord.entityType });
            metricsCollector.timing('media.get_by_id_time', Date.now() - startTime);

            return ApiResponse.success(res, { data: mediaRecord });
        } catch (error) {
            logger.error(`Failed to fetch media ${id}:`, { error: error.message });
            metricsCollector.increment('media.view_failed', { id });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        }
    });

    /**
     * Update media metadata
     * PUT /api/v1/media/:id
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    updateMedia = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;
        const updates = req.body;

        const media = await Media.findById(id).select('entityType entityId userId').lean();
        if (!media || media.status === 'deleted') {
            return next(new AppError('Media not found', 404));
        }

        if (!req.user.isAdmin && media.userId !== requestingUserId) {
            return next(new AppError('Access denied', 403));
        }

        await updateMediaLimiter(req, res, () => { });

        const sanitizedUpdates = this.sanitizeUpdates(updates, this.getAllowedUpdateFields());
        if (Object.keys(sanitizedUpdates).length === 0) {
            return next(new AppError('No valid update fields provided', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const mediaRecord = await Media.findById(id).session(session);
            if (!mediaRecord || mediaRecord.status === 'deleted') {
                return next(new AppError('Media not found', 404));
            }

            Object.assign(mediaRecord, sanitizedUpdates);
            mediaRecord.metadata.version += 1;
            mediaRecord.metadata.updateCount += 1;
            mediaRecord.metadata.lastModifiedBy = {
                userId: requestingUserId,
                timestamp: new Date(),
                changes: Object.keys(sanitizedUpdates),
            };

            await mediaRecord.save({ session });
            await cacheService.deletePattern(`media:${id}:*`);

            metricsCollector.increment('media.updated', { id, entityType: mediaRecord.entityType });
            metricsCollector.timing('media.update_time', Date.now() - startTime);
            eventEmitter.emit('media.updated', { mediaId: id, entityType: mediaRecord.entityType, changes: Object.keys(sanitizedUpdates) });

            await session.commitTransaction();
            return ApiResponse.success(res, {
                message: 'Media updated successfully',
                data: { id: mediaRecord._id, fileName: mediaRecord.fileName, category: mediaRecord.category },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Media update failed for ${id}:`, { error: error.message });
            metricsCollector.increment('media.update_failed', { id });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete media
     * DELETE /api/v1/media/:id
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    deleteMedia = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;
        const { permanent = 'false' } = req.query;

        const media = await Media.findById(id).select('entityType entityId userId').lean();
        if (!media || media.status === 'deleted') {
            return next(new AppError('Media not found', 404));
        }

        if (!req.user.isAdmin && media.userId !== requestingUserId) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const mediaRecord = await Media.findById(id).session(session);
            if (!mediaRecord || mediaRecord.status === 'deleted') {
                return next(new AppError('Media not found', 404));
            }

            const entityModel = this.getEntityModel(mediaRecord.entityType);
            const entity = await entityModel.findById(mediaRecord.entityId).session(session);
            if (!entity) {
                return next(new AppError(`${mediaRecord.entityType} not found`, 404));
            }

            if (permanent === 'true') {
                await this.mediaService.deleteMedia([id], { session });
                await Media.findByIdAndDelete(id, { session });
            } else {
                mediaRecord.status = 'deleted';
                await mediaRecord.save({ session });
            }

            entity.media = entity.media.filter(m => m.toString() !== id);
            await entity.save({ session });

            await cacheService.deletePattern(`media:${id}:*`);
            await cacheService.deletePattern(`media:${mediaRecord.entityType}:${mediaRecord.entityId}:*`);
            metricsCollector.increment(`media.${permanent ? 'permanently_deleted' : 'soft_deleted'}`, { id, entityType: mediaRecord.entityType });
            metricsCollector.timing('media.delete_time', Date.now() - startTime);
            eventEmitter.emit('media.deleted', { mediaId: id, entityType: mediaRecord.entityType, permanent });

            await session.commitTransaction();
            return ApiResponse.success(res, {
                message: permanent === 'true' ? 'Media permanently deleted' : 'Media soft deleted',
                data: { id },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Media deletion failed for ${id}:`, { error: error.message });
            metricsCollector.increment('media.delete_failed', { id });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Scan media for security
     * POST /api/v1/media/:id/scan
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    scanMedia = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;

        const media = await Media.findById(id).select('entityType entityId userId').lean();
        if (!media || media.status === 'deleted') {
            return next(new AppError('Media not found', 404));
        }

        if (!req.user.isAdmin && media.userId !== requestingUserId) {
            return next(new AppError('Access denied', 403));
        }

        await scanMediaLimiter(req, res, () => { });

        try {
            const scanResult = await this.circuitBreaker.fire(async () => {
                return await retry(() => this.mediaService.scanMedia([{ id, url: media.url }]), this.retryConfig);
            });

            const session = await mongoose.startSession();
            try {
                session.startTransaction();

                const mediaRecord = await Media.findById(id).session(session);
                if (!mediaRecord) {
                    return next(new AppError('Media not found', 404));
                }

                mediaRecord.metadata.scan = {
                    status: scanResult[0].infected ? 'infected' : 'clean',
                    details: scanResult[0].details || [],
                    scannedAt: new Date(),
                };

                if (scanResult[0].infected) {
                    mediaRecord.status = 'quarantined';
                    await this.notificationService.notifyUser({
                        userId: requestingUserId,
                        message: `Media ${mediaRecord.fileName} has been quarantined due to security concerns`,
                        type: 'security_alert',
                    }, { session });
                }

                await mediaRecord.save({ session });
                await cacheService.deletePattern(`media:${id}:*`);

                metricsCollector.increment('media.scanned', { id, status: scanResult[0].infected ? 'infected' : 'clean' });
                metricsCollector.timing('media.scan_time', Date.now() - startTime);
                eventEmitter.emit('media.scanned', { mediaId: id, status: scanResult[0].infected ? 'infected' : 'clean' });

                await session.commitTransaction();
                return ApiResponse.success(res, {
                    message: `Media scan completed: ${scanResult[0].infected ? 'infected' : 'clean'}`,
                    data: { id, scanStatus: mediaRecord.metadata.scan.status },
                });
            } catch (error) {
                await session.abortTransaction();
                throw error;
            } finally {
                session.endSession();
            }
        } catch (error) {
            logger.error(`Media scan failed for ${id}:`, { error: error.message });
            metricsCollector.increment('media.scan_failed', { id });
            throw error instanceof AppError ? error : new AppError('Failed to scan media', 424);
        }
    });

    /**
     * Bulk upload media
     * POST /api/v1/media/:entityType/:entityId/bulk
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    bulkUploadMedia = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { entityType, entityId } = req.params;
        const requestingUserId = req.user.id;
        const files = req.files || [];
        const { category } = req.body;

        if (!req.user.isAdmin && !req.user.permissions.includes(`upload_${entityType}_media`)) {
            return next(new AppError('Access denied', 403));
        }

        await bulkUploadLimiter(req, res, () => { });

        if (files.length === 0 || files.length > 20) {
            return next(new AppError('No files provided or too many files (max 20)', 400));
        }

        const validation = validateMedia({ files, entityType, category });
        if (!validation.valid) {
            metricsCollector.increment('media.bulk_validation_failed', { userId: requestingUserId, errors: validation.errors.length });
            return next(new AppError(`Validation failed: ${validation.message}`, 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const entityModel = this.getEntityModel(entityType);
            const entity = await entityModel.findById(entityId).session(session);
            if (!entity || entity.status === 'deleted') {
                return next(new AppError(`${entityType} not found`, 404));
            }

            const mediaResults = await this.mediaService.uploadMedia({
                files,
                entityId,
                entityType,
                userId: requestingUserId,
                category: sanitizeInput(category) || 'general',
            }, { session });

            const scanResults = await this.circuitBreaker.fire(async () => {
                return await retry(() => this.mediaService.scanMedia(mediaResults), this.retryConfig);
            });
            const infected = scanResults.filter(r => r.infected);
            if (infected.length > 0) {
                await this.mediaService.deleteMedia(infected.map(m => m.id), { session });
                metricsCollector.increment('media.bulk_scan_failed', { entityId, infectedCount: infected.length });
                return next(new AppError(`Bulk upload failed: ${infected.length} infected files detected`, 422));
            }

            const mediaRecords = mediaResults.map(file => ({
                entityId,
                entityType,
                userId: requestingUserId,
                fileName: file.fileName,
                fileType: file.fileType,
                fileSize: file.fileSize,
                url: file.url,
                category: file.category,
                status: 'active',
                metadata: {
                    createdBy: {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        location: req.geoip || { country: 'unknown', city: 'unknown' },
                        referrer: req.get('Referer') || 'direct',
                    },
                    version: 1,
                    updateCount: 0,
                },
                analytics: {
                    views: { total: 0, unique: 0, byDate: [] },
                    downloads: { total: 0, byDate: [] },
                },
            }));

            const insertedMedia = await Media.insertMany(mediaRecords, { session });
            entity.media = [...(entity.media || []), ...insertedMedia.map(m => m._id)];
            await entity.save({ session });

            for (const media of insertedMedia) {
                this.processNewMediaAsync(media._id, requestingUserId).catch((err) => {
                    logger.error(`Async processing failed for media ${media._id}:`, err);
                });
            }

            metricsCollector.increment('media.bulk_uploaded', { entityId, entityType, mediaCount: files.length });
            metricsCollector.timing('media.bulk_upload_time', Date.now() - startTime);
            eventEmitter.emit('media.bulk_uploaded', { entityId, entityType, mediaCount: files.length });

            await session.commitTransaction();
            return ApiResponse.success(res, {
                message: `Successfully uploaded ${insertedMedia.length} media files`,
                data: { entityId, entityType, mediaCount: insertedMedia.length, mediaIds: insertedMedia.map(m => m._id) },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk media upload failed for ${entityType} ${entityId}:`, { error: error.message });
            metricsCollector.increment('media.bulk_upload_failed', { entityId, entityType });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Get media analytics
     * GET /api/v1/media/:id/analytics
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    getMediaAnalytics = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;

        const media = await Media.findById(id).select('entityType entityId userId').lean();
        if (!media || media.status === 'deleted') {
            return next(new AppError('Media not found', 404));
        }

        if (!req.user.isAdmin && media.userId !== requestingUserId) {
            return next(new AppError('Access denied', 403));
        }

        await analyticsLimiter(req, res, () => { });

        const cacheKey = `media_analytics:${id}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('media.analytics_cache_hit', { id });
                return ApiResponse.success(res, cached);
            }

            const mediaRecord = await Media.findById(id)
                .select('analytics')
                .lean();

            if (!mediaRecord || mediaRecord.status === 'deleted') {
                return next(new AppError('Media not found', 404));
            }

            const analytics = await this.computeAnalytics(mediaRecord.analytics);
            await cacheService.set(cacheKey, analytics, 300, [`media_analytics:${id}`]);

            metricsCollector.increment('media.analytics_fetched', { id });
            metricsCollector.timing('media.analytics_time', Date.now() - startTime);

            return ApiResponse.success(res, { data: analytics });
        } catch (error) {
            logger.error(`Failed to fetch analytics for media ${id}:`, { error: error.message });
            metricsCollector.increment('media.analytics_failed', { id });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        }
    });

    /**
     * Search media
     * GET /api/v1/media/search
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    searchMedia = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const requestingUserId = req.user.id;
        const {
            query,
            page = 1,
            limit = 20,
            entityType,
            category,
            sortBy = 'relevance',
        } = req.query;

        await searchLimiter(req, res, () => { });

        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
        const from = (pageNum - 1) * limitNum;

        const cacheKey = `media_search:${requestingUserId}:${JSON.stringify({ query, page, limit, entityType, category, sortBy })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('media.search_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const esQuery = this.buildElasticsearchQuery({ query, entityType, category });
            const sortOption = this.buildSearchSortOption(sortBy);

            const esResponse = await elasticsearchClient.search({
                index: 'media',
                from,
                size: limitNum,
                body: {
                    query: esQuery,
                    sort: sortOption,
                },
            });

            const mediaIds = esResponse.hits.hits.map(hit => hit._id);
            const media = await Media.find({ _id: { $in: mediaIds }, status: { $ne: 'deleted' } })
                .read('secondaryPreferred')
                .select('-__v')
                .lean({ virtuals: true });

            const accessibleMedia = [];
            for (const mediaItem of media) {
                if (req.user.isAdmin || mediaItem.userId === requestingUserId || await this.checkAccess(mediaItem.entityType, mediaItem.entityId, requestingUserId)) {
                    accessibleMedia.push(mediaItem);
                }
            }

            const totalCount = esResponse.hits.total.value;
            const result = {
                media: accessibleMedia,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages: Math.ceil(totalCount / limitNum),
                    hasNext: pageNum < Math.ceil(totalCount / limitNum),
                    hasPrev: pageNum > 1,
                },
            };

            await cacheService.set(cacheKey, result, 300, ['media_search']);
            metricsCollector.increment('media.search', { count: accessibleMedia.length });
            metricsCollector.timing('media.search_time', Date.now() - startTime);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Media search failed:`, { error: error.message });
            metricsCollector.increment('media.search_failed');
            throw error instanceof AppError ? error : new AppError('Search failed', 500);
        }
    });

    /**
     * Export media metadata
     * GET /api/v1/media/export
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    exportMedia = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const requestingUserId = req.user.id;
        const { format = 'json', entityType, entityId } = req.query;

        if (!req.user.isAdmin && !req.user.permissions.includes('export_media')) {
            return next(new AppError('Access denied', 403));
        }

        const query = { status: { $ne: 'deleted' } };
        if (entityType) query.entityType = entityType;
        if (entityId) query.entityId = mongoose.Types.ObjectId(entityId);

        try {
            const media = await Media.find(query)
                .read('secondaryPreferred')
                .select('-__v')
                .lean();

            const accessibleMedia = [];
            for (const mediaItem of media) {
                if (req.user.isAdmin || mediaItem.userId === requestingUserId || await this.checkAccess(mediaItem.entityType, mediaItem.entityId, requestingUserId)) {
                    accessibleMedia.push(mediaItem);
                }
            }

            const exportData = this.formatExportData(accessibleMedia, format);
            const fileName = `media_${requestingUserId}_${Date.now()}.${format}`;
            const s3Key = `exports/media/${requestingUserId}/${fileName}`;

            await s3Client.upload({
                Bucket: 'user-exports',
                Key: s3Key,
                Body: Buffer.from(JSON.stringify(exportData)),
                ContentType: format === 'json' ? 'application/json' : 'text/csv',
            }).promise();

            const downloadUrl = await s3Client.getSignedUrlPromise('getObject', {
                Bucket: 'user-exports',
                Key: s3Key,
                Expires: 3600, // 1 hour
            });

            metricsCollector.increment('media.exported', { userId: requestingUserId, format, count: accessibleMedia.length });
            metricsCollector.timing('media.export_time', Date.now() - startTime);
            eventEmitter.emit('media.exported', { userId: requestingUserId, fileName, format });

            return ApiResponse.success(res, {
                message: 'Media metadata exported successfully',
                data: { downloadUrl, fileName },
            });
        } catch (error) {
            logger.error(`Media export failed for user ${requestingUserId}:`, { error: error.message });
            metricsCollector.increment('media.export_failed', { userId: requestingUserId });
            throw error instanceof AppError ? error : new AppError('Export failed', 500);
        }
    });

    // Helper methods
    getEntityModel(entityType) {
        const models = {
            course: require('../models/Course').default,
            organization: require('../models/Organization').default,
            project: require('../models/Project').default,
            // Add other entity types as needed
        };
        const model = models[entityType.toLowerCase()];
        if (!model) {
            throw new AppError(`Invalid entity type: ${entityType}`, 400);
        }
        return model;
    }

    getAllowedUpdateFields() {
        return ['category', 'status'];
    }

    sanitizeUpdates(updates, allowedFields) {
        const sanitized = {};
        for (const [key, value] of Object.entries(updates)) {
            if (allowedFields.includes(key)) {
                sanitized[key] = sanitizeInput(value);
            }
        }
        return sanitized;
    }

    buildMediaQuery({ entityType, entityId, category, status }) {
        const query = { entityId, entityType, status: { $ne: 'deleted' } };
        if (category) query.category = sanitizeInput(category);
        if (status) query.status = status;
        return query;
    }

    buildSortOption(sortBy) {
        const sortOptions = {
            recent: { createdAt: -1 },
            fileName: { fileName: 1 },
        };
        return sortOptions[sortBy] || sortOptions.recent;
    }

    buildElasticsearchQuery({ query, entityType, category }) {
        const boolQuery = {
            must: [],
            filter: [{ term: { status: 'active' } }],
        };
        if (query) {
            boolQuery.must.push({
                multi_match: {
                    query,
                    fields: ['fileName^2', 'category'],
                    fuzziness: 'AUTO',
                },
            });
        }
        if (entityType) boolQuery.filter.push({ term: { entityType } });
        if (category) boolQuery.filter.push({ match: { category } });
        return { bool: boolQuery };
    }

    buildSearchSortOption(sortBy) {
        const sortOptions = {
            relevance: { _score: 'desc' },
            recent: { createdAt: 'desc' },
            fileName: { fileName: 'asc' },
        };
        return sortOptions[sortBy] || sortOptions.relevance;
    }

    async indexForSearch(media) {
        try {
            await elasticsearchClient.index({
                index: 'media',
                id: media._id.toString(),
                body: {
                    entityId: media.entityId,
                    entityType: media.entityType,
                    userId: media.userId,
                    fileName: media.fileName,
                    category: media.category,
                    status: media.status,
                    createdAt: media.createdAt,
                },
            });
            metricsCollector.increment('media.indexed', { mediaId: media._id });
        } catch (error) {
            logger.error(`Failed to index media ${media._id}:`, { error: error.message });
        }
    }

    async createBackup(mediaId, action, userId, options = {}) {
        try {
            const media = await Media.findById(mediaId).session(options.session);
            if (!media) return;

            const backupKey = `backups/media/${mediaId}/${Date.now()}.json`;
            await s3Client.upload({
                Bucket: 'user-backups',
                Key: backupKey,
                Body: Buffer.from(JSON.stringify(media)),
                ContentType: 'application/json',
            }).promise();

            logger.info(`Backup created for media ${mediaId} by ${userId} for action ${action}`);
            metricsCollector.increment('media.backup_created', { mediaId, action });
        } catch (error) {
            logger.error(`Backup failed for media ${mediaId}:`, { error: error.message });
        }
    }

    async checkAccess(entityType, entityId, userId) {
        const entityModel = this.getEntityModel(entityType);
        const entity = await entityModel.findById(entityId).select('userId createdBy privacy').lean();
        if (!entity) return false;
        return entity.userId === userId || entity.createdBy === userId || entity.privacy?.isPublic || req.user.isAdmin;
    }

    async processNewMediaAsync(mediaId, userId) {
        try {
            const media = await Media.findById(mediaId);
            if (!media) return;

            await this.circuitBreaker.fire(async () => {
                await retry(() => this.verificationService.verifyMedia({
                    mediaId,
                    fileName: media.fileName,
                    fileType: media.fileType,
                    url: media.url,
                }), this.retryConfig);
            });

            await this.indexForSearch(media);
            metricsCollector.increment('media.async_processed', { mediaId });
        } catch (error) {
            logger.error(`Async processing failed for media ${mediaId}:`, { error: error.message });
        }
    }

    async updateAnalytics(media, viewerId) {
        try {
            media.analytics.views.total += 1;
            if (!media.analytics.views.byDate) media.analytics.views.byDate = [];
            const today = moment().startOf('day').toDate();
            const viewEntry = media.analytics.views.byDate.find(v => v.date.toDateString() === today.toDateString());
            if (viewEntry) {
                viewEntry.count += 1;
            } else {
                media.analytics.views.byDate.push({ date: today, count: 1 });
            }
            await media.save();
        } catch (error) {
            logger.error(`Failed to update analytics for media ${media._id}:`, { error: error.message });
        }
    }

    async computeAnalytics(analytics) {
        const viewsByMonth = analytics.views.byDate.reduce((acc, entry) => {
            const month = moment(entry.date).format('YYYY-MM');
            acc[month] = (acc[month] || 0) + entry.count;
            return acc;
        }, {});

        const downloadsByMonth = analytics.downloads.byDate.reduce((acc, entry) => {
            const month = moment(entry.date).format('YYYY-MM');
            acc[month] = (acc[month] || 0) + entry.count;
            return acc;
        }, {});

        return {
            totalViews: analytics.views.total,
            uniqueViews: analytics.views.unique,
            viewsByMonth,
            totalDownloads: analytics.downloads.total,
            downloadsByMonth,
        };
    }

    formatExportData(media, format) {
        if (format === 'csv') {
            const headers = ['id', 'entityType', 'entityId', 'fileName', 'fileType', 'fileSize', 'category', 'status'];
            const csvRows = [headers.join(',')];
            for (const m of media) {
                const row = [
                    m._id,
                    m.entityType,
                    m.entityId,
                    `"${m.fileName}"`,
                    m.fileType,
                    m.fileSize,
                    m.category || '',
                    m.status,
                ];
                csvRows.push(row.join(','));
            }
            return csvRows.join('\n');
        }
        return media; // Default JSON
    }
}

export default new MediaController();