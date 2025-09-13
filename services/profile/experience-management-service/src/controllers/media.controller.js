import { Media } from '../models/Media.js';
import { Experience } from '../models/Experience.js';
import MediaService from '../services/MediaService.js';
import { validateMedia } from '../validations/media.validation.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { catchAsync } from '../handler/catchAsync.js';
import { ApiResponse } from '../utils/response.js';
import { createRateLimiter } from '../utils/rateLimiter.js';
import { cacheService } from '../services/cache.service.js';
import { eventEmitter } from '../events/events.js';
import { metricsCollector } from '../utils/metrics.js';
import mongoose from 'mongoose';
import { S3Client, PutObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import sanitizeHtml from 'sanitize-html';
import { v4 as uuidv4 } from 'uuid';

// Rate limiters
const uploadMediaLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 10, // 10 uploads per 10 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `media_upload_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const updateMediaLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 25, // 25 updates per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `media_update_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const deleteMediaLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 15, // 15 deletes per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `media_delete_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const bulkOperationsLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // 3 bulk operations per hour
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `media_bulk_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

// Initialize S3 client
const s3Client = new S3Client({
    region: process.env.AWS_REGION,
    credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    },
});

class MediaController {
    constructor() {
        this.mediaService = MediaService;
    }

    /**
     * Upload new media
     * POST /api/v1/media/:entityType/:entityId
     */
    uploadMedia = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { entityType, entityId } = req.params;
        const { visibility, context } = req.body;
        const files = req.files;
        const userId = req.user.id;

        // Apply rate limiting
        await uploadMediaLimiter(req, res, () => { });

        // Validate access
        if (!this.checkEntityAccess(entityType, entityId, userId, req.user.isAdmin)) {
            return next(new AppError('Access denied', 403));
        }

        // Validate input
        if (!files || files.length === 0) {
            return next(new AppError('No files uploaded', 400));
        }

        const validation = validateMedia(files);
        if (!validation.valid) {
            return next(new AppError(validation.message, 422));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            // Process media uploads
            const mediaResults = await Promise.all(
                files.map(async (file) => {
                    // Generate system filename
                    const systemName = `${uuidv4()}.${file.name.split('.').pop()}`;

                    // Upload to S3
                    const uploadParams = {
                        Bucket: process.env.S3_BUCKET,
                        Key: `media/${systemName}`,
                        Body: file.buffer,
                        ContentType: file.mimetype,
                    };
                    await s3Client.send(new PutObjectCommand(uploadParams));

                    // Create media document
                    const media = new Media({
                        owner: {
                            userId,
                            userType: req.user.type || 'individual',
                        },
                        associatedWith: {
                            entityType,
                            entityId,
                            context: sanitizeHtml(context || 'default'),
                        },
                        file: {
                            originalName: file.name,
                            systemName,
                            extension: file.name.split('.').pop(),
                            mimeType: file.mimetype,
                            size: file.size,
                        },
                        storage: {
                            primary: {
                                provider: 'aws-s3',
                                bucket: process.env.S3_BUCKET,
                                key: `media/${systemName}`,
                                region: process.env.AWS_REGION,
                                url: `https://${process.env.S3_BUCKET}.s3.${process.env.AWS_REGION}.amazonaws.com/media/${systemName}`,
                            },
                            cdn: {
                                provider: 'cloudfront',
                                baseUrl: process.env.CLOUDFRONT_URL,
                                cachedUrls: {
                                    original: `${process.env.CLOUDFRONT_URL}/media/${systemName}`,
                                },
                            },
                        },
                        permissions: {
                            visibility: visibility || 'private',
                        },
                    });

                    await media.save({ session });

                    // Update associated experience
                    if (entityType === 'experience') {
                        await Experience.findByIdAndUpdate(
                            entityId,
                            { $push: { 'achievements.$[ach].mediaAttachments': media._id } },
                            { arrayFilters: [{ 'ach.isPublic': true }], session }
                        );
                    }

                    return media;
                })
            );

            // Async processing (virus scan, image processing, etc.)
            this.processMediaAsync(mediaResults, userId)
                .catch((err) => logger.error(`Async media processing failed:`, err));

            // Emit event
            eventEmitter.emit('media.uploaded', {
                mediaIds: mediaResults.map((m) => m._id),
                userId,
                entityType,
                entityId,
            });

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('media.uploaded', {
                userId,
                count: mediaResults.length,
                entityType,
            });
            logger.info(`Uploaded ${mediaResults.length} media files for ${entityType}:${entityId} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Media uploaded successfully',
                data: mediaResults.map((media) => ({
                    id: media._id,
                    url: media.storage.primary.url,
                    thumbnailUrl: media.getThumbnailUrl(),
                    fileType: media.file.mimeType,
                })),
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Media upload failed for ${entityType}:${entityId}:`, error);
            metricsCollector.increment('media.upload_failed', { userId, entityType });
            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            return next(new AppError('Failed to upload media', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get media by ID
     * GET /api/v1/media/:id
     */
    getMediaById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const userId = req.user.id;

        try {
            const cacheKey = `media:${id}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('media.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const media = await Media.findById(id)
                .populate('owner.userId', 'name profilePicture')
                .lean({ virtuals: true });

            if (!media) {
                return next(new AppError('Media not found', 404));
            }

            if (!this.checkMediaAccess(media, userId, req.user.isAdmin)) {
                return next(new AppError('Access denied', 403));
            }

            // Update analytics
            await Media.updateOne(
                { _id: id },
                {
                    $inc: { 'analytics.views.total': 1, 'analytics.views.unique': 1 },
                    $set: { 'analytics.views.lastViewed': new Date() },
                }
            );

            const responseData = {
                ...media,
                publicUrl: media.storage.primary.url,
                thumbnailUrl: media.getThumbnailUrl(),
            };

            await cacheService.set(cacheKey, responseData, 600); // 10 minutes

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('media.viewed', { userId });
            logger.info(`Fetched media ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: responseData });
        } catch (error) {
            logger.error(`Failed to fetch media ${id}:`, error);
            metricsCollector.increment('media.fetch_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid media ID', 400));
            }
            return next(new AppError('Failed to fetch media', 500));
        }
    });

    /**
     * Update media metadata
     * PUT /api/v1/media/:id
     */
    updateMedia = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const userId = req.user.id;
        const updates = req.body;

        // Apply rate limiting
        await updateMediaLimiter(req, res, () => { });

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const media = await Media.findById(id).session(session);
            if (!media) {
                return next(new AppError('Media not found', 404));
            }

            if (!this.checkMediaAccess(media, userId, req.user.isAdmin, 'edit')) {
                return next(new AppError('Access denied', 403));
            }

            // Validate and sanitize updates
            const allowedUpdates = this.getAllowedUpdateFields();
            const sanitizedUpdates = this.sanitizeUpdates(updates, allowedUpdates);

            if (Object.keys(sanitizedUpdates).length === 0) {
                return next(new AppError('No valid update fields provided', 400));
            }

            Object.assign(media, sanitizedUpdates);
            media.metadata.lastModifiedBy = {
                userId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date(),
            };

            await media.save({ session });

            // Clear cache
            await cacheService.deletePattern(`media:${id}:*`);

            // Emit event
            eventEmitter.emit('media.updated', {
                mediaId: id,
                userId,
                changes: Object.keys(sanitizedUpdates),
            });

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('media.updated', {
                userId,
                fieldsUpdated: Object.keys(sanitizedUpdates).length,
            });
            logger.info(`Media ${id} updated in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Media updated successfully',
                data: {
                    id: media._id,
                    metadata: media.metadata,
                    permissions: media.permissions,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Media update failed for ${id}:`, error);
            metricsCollector.increment('media.update_failed', { userId });
            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            return next(new AppError('Failed to update media', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete media
     * DELETE /api/v1/media/:id
     */
    deleteMedia = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const userId = req.user.id;
        const { permanent = 'false' } = req.query;

        // Apply rate limiting
        await deleteMediaLimiter(req, res, () => { });

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const media = await Media.findById(id).session(session);
            if (!media) {
                return next(new AppError('Media not found', 404));
            }

            if (!this.checkMediaAccess(media, userId, req.user.isAdmin, 'edit')) {
                return next(new AppError('Access denied', 403));
            }

            if (permanent === 'true') {
                // Delete from S3
                await s3Client.send(new DeleteObjectCommand({
                    Bucket: process.env.S3_BUCKET,
                    Key: media.storage.primary.key,
                }));

                // Remove from associated experience
                if (media.associatedWith.entityType === 'experience') {
                    await Experience.findByIdAndUpdate(
                        media.associatedWith.entityId,
                        { $pull: { 'achievements.$[].mediaAttachments': media._id } },
                        { session }
                    );
                }

                await Media.findByIdAndDelete(id, { session });
                metricsCollector.increment('media.permanently_deleted', { userId });
            } else {
                // Soft delete
                media.status = 'deleted';
                media.permissions.visibility = 'private';
                media.metadata.lastModifiedBy = {
                    userId,
                    ip: req.ip,
                    userAgent: req.get('User-Agent'),
                    timestamp: new Date(),
                };
                await media.save({ session });
                metricsCollector.increment('media.soft_deleted', { userId });
            }

            // Clear cache
            await cacheService.deletePattern(`media:${id}:*`);

            // Emit event
            eventEmitter.emit('media.deleted', {
                mediaId: id,
                userId,
                permanent: permanent === 'true',
            });

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`Media ${id} deleted (permanent: ${permanent}) in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: permanent === 'true' ? 'Media permanently deleted' : 'Media moved to trash',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Media deletion failed for ${id}:`, error);
            metricsCollector.increment('media.delete_failed', { userId });
            return next(new AppError('Failed to delete media', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get media for an entity
     * GET /api/v1/media/:entityType/:entityId
     */
    getMediaByEntity = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { entityType, entityId } = req.params;
        const userId = req.user.id;
        const {
            page = 1,
            limit = 20,
            mimeType,
            category,
            search,
            sortBy = 'recent',
        } = req.query;

        // Validate access
        if (!this.checkEntityAccess(entityType, entityId, userId, req.user.isAdmin)) {
            return next(new AppError('Access denied', 403));
        }

        const cacheKey = `media:${entityType}:${entityId}:${page}:${limit}:${mimeType || 'all'}:${category || 'all'}:${sortBy}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('media.entity_cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const query = this.buildMediaQuery({ entityType, entityId, mimeType, category, search });
            const sortOption = this.buildSortOption(sortBy);
            const pageNum = Math.max(1, parseInt(page));
            const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
            const skip = (pageNum - 1) * limitNum;

            const [mediaItems, totalCount] = await Promise.all([
                Media.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select('file metadata permissions storage analytics')
                    .populate('owner.userId', 'name profilePicture')
                    .lean({ virtuals: true }),
                Media.countDocuments(query).cache({ ttl: 300, key: `media_count_${entityType}_${entityId}` }),
            ]);

            const processedMedia = mediaItems.map((media) => ({
                ...media,
                publicUrl: media.storage.primary.url,
                thumbnailUrl: media.getThumbnailUrl(),
            }));

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                media: processedMedia,
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
                    mimeType: mimeType || 'all',
                    category: category || 'all',
                    sortBy,
                    search: search || null,
                },
            };

            await cacheService.set(cacheKey, result, 300); // 5 minutes

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('media.fetched', { userId, count: mediaItems.length });
            logger.info(`Fetched ${mediaItems.length} media for ${entityType}:${entityId} in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch media for ${entityType}:${entityId}:`, error);
            metricsCollector.increment('media.fetch_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid query parameters', 400));
            }
            return next(new AppError('Failed to fetch media', 500));
        }
    });

    /**
     * Bulk operations on media
     * POST /api/v1/media/bulk
     */
    bulkOperations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const userId = req.user.id;
        const { operation, mediaIds, data = {} } = req.body;

        // Apply rate limiting
        await bulkOperationsLimiter(req, res, () => { });

        // Validate input
        if (!Array.isArray(mediaIds) || mediaIds.length === 0) {
            return next(new AppError('Media IDs array is required', 400));
        }
        if (mediaIds.length > 100) {
            return next(new AppError('Maximum 100 media items can be processed at once', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const query = { _id: { $in: mediaIds }, 'owner.userId': userId };
            const { message } = await this.handleBulkOperation(operation, query, data, userId, req, { session });

            // Clear cache
            await Promise.all([
                ...mediaIds.map((id) => cacheService.deletePattern(`media:${id}:*`)),
                cacheService.deletePattern(`media:${data.entityType || '*'}:${data.entityId || '*'}:*`),
            ]);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('media.bulk_operation', {
                userId,
                operation,
                count: mediaIds.length,
            });
            logger.info(`Bulk operation ${operation} completed for ${mediaIds.length} media items in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message,
                data: {
                    operation,
                    requested: mediaIds.length,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk operation failed for user ${userId}:`, error);
            metricsCollector.increment('media.bulk_operation_failed', { userId, operation });
            return next(new AppError('Bulk operation failed', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get signed URL for media
     * GET /api/v1/media/:id/signed-url
     */
    getSignedMediaUrl = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const userId = req.user.id;

        try {
            const media = await Media.findById(id);
            if (!media) {
                return next(new AppError('Media not found', 404));
            }

            if (!this.checkMediaAccess(media, userId, req.user.isAdmin)) {
                return next(new AppError('Access denied', 403));
            }

            const signedUrl = await getSignedUrl(
                s3Client,
                new PutObjectCommand({
                    Bucket: process.env.S3_BUCKET,
                    Key: media.storage.primary.key,
                }),
                { expiresIn: 3600 }
            );

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('media.signed_url_generated', { userId });
            logger.info(`Generated signed URL for media ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Signed URL generated successfully',
                data: {
                    url: signedUrl,
                    expiresIn: 3600,
                },
            });
        } catch (error) {
            logger.error(`Failed to generate signed URL for media ${id}:`, error);
            metricsCollector.increment('media.signed_url_failed', { userId });
            return next(new AppError('Failed to generate signed URL', 500));
        }
    });

    /**
     * Get trending media
     * GET /api/v1/media/trending
     */
    getTrendingMedia = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { timeframe = '7d', category, limit = 20 } = req.query;

        const cacheKey = `trending:media:${timeframe}:${category || 'all'}:${limit}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('media.trending_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const mediaItems = await this.mediaService.getTrendingMedia(timeframe, category, parseInt(limit));
            const processedMedia = mediaItems.map((media) => ({
                ...media,
                publicUrl: media.storage.primary.url,
                thumbnailUrl: media.getThumbnailUrl(),
            }));

            const result = { media: processedMedia };
            await cacheService.set(cacheKey, result, 3600); // 1 hour

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('media.trending_viewed', { count: mediaItems.length });
            logger.info(`Fetched ${mediaItems.length} trending media in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch trending media:`, error);
            metricsCollector.increment('media.trending_fetch_failed');
            return next(new AppError('Failed to fetch trending media', 500));
        }
    });

    /**
     * Search media
     * GET /api/v1/media/search
     */
    searchMedia = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { query, page = 1, limit = 20, filters = {} } = req.query;
        const userId = req.user.id;

        const cacheKey = `search:media:${query}:${JSON.stringify(filters)}:${page}:${limit}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('media.search_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const searchResults = await this.mediaService.searchMedia(query, {
                ...filters,
                userId,
            }, {
                page: parseInt(page),
                limit: parseInt(limit),
            });

            const result = {
                media: searchResults.hits.map((media) => ({
                    ...media,
                    publicUrl: media.storage.primary.url,
                    thumbnailUrl: media.getThumbnailUrl(),
                })),
                totalCount: searchResults.total,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    totalPages: Math.ceil(searchResults.total / parseInt(limit)),
                },
            };

            await cacheService.set(cacheKey, result, 300); // 5 minutes

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('media.searched', { userId, count: searchResults.hits.length });
            logger.info(`Search returned ${searchResults.hits.length} media items in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Search failed for query ${query}:`, error);
            metricsCollector.increment('media.search_failed', { userId });
            return next(new AppError('Failed to search media', 500));
        }
    });

    // Helper Methods

    /**
     * Process media asynchronously
     */
    async processMediaAsync(mediaItems, userId) {
        try {
            const session = await mongoose.startSession();
            session.startTransaction();

            for (const media of mediaItems) {
                const mediaDoc = await Media.findById(media._id).session(session);
                if (!mediaDoc) continue;

                // Perform virus scan
                const scanResult = await this.mediaService.scanMedia([media]);
                if (scanResult[0].infected) {
                    mediaDoc.status = 'quarantined';
                    mediaDoc.security.virusScan = {
                        status: 'infected',
                        scannedAt: new Date(),
                        scanner: 'custom-scanner',
                    };
                } else {
                    // Process image if applicable
                    if (mediaDoc.file.mimeType.startsWith('image/')) {
                        const processed = await this.mediaService.processImage(mediaDoc);
                        mediaDoc.file.dimensions = processed.dimensions;
                        mediaDoc.file.technical = processed.technical;
                    }
                }

                await mediaDoc.save({ session });
            }

            await session.commitTransaction();
            logger.info(`Async processing completed for ${mediaItems.length} media items`);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Async media processing failed:`, error);
        } finally {
            session.endSession();
        }
    }

    /**
     * Check media access
     */
    checkMediaAccess(media, userId, isAdmin, action = 'view') {
        if (isAdmin) return true;
        if (media.owner.userId.toString() === userId) return true;
        if (action === 'view' && media.permissions.visibility === 'public') return true;
        return false;
    }

    /**
     * Check entity access
     */
    checkEntityAccess(entityType, entityId, userId, isAdmin) {
        if (isAdmin) return true;
        if (entityType === 'experience') {
            // Additional checks could be added here for experience-specific access
            return true; // Simplified for this example
        }
        return false;
    }

    /**
     * Get allowed update fields
     */
    getAllowedUpdateFields() {
        return ['metadata.title', 'metadata.description', 'metadata.altText', 'metadata.tags', 'permissions.visibility'];
    }

    /**
     * Sanitize updates
     */
    sanitizeUpdates(updates, allowedFields) {
        const sanitized = {};
        allowedFields.forEach((field) => {
            if (updates[field] !== undefined) {
                const value = field.includes('metadata') ? sanitizeHtml(updates[field]) : sanitizeInput(updates[field]);
                const fieldParts = field.split('.');
                if (fieldParts.length > 1) {
                    sanitized[fieldParts[0]] = sanitized[fieldParts[0]] || {};
                    sanitized[fieldParts[0]][fieldParts[1]] = value;
                } else {
                    sanitized[field] = value;
                }
            }
        });
        return sanitized;
    }

    /**
     * Build query for fetching media
     */
    buildMediaQuery({ entityType, entityId, mimeType, category, search }) {
        const query = {
            'associatedWith.entityType': entityType,
            'associatedWith.entityId': entityId,
            status: { $ne: 'deleted' },
        };

        if (mimeType && mimeType !== 'all') {
            query['file.mimeType'] = mimeType;
        }
        if (category && category !== 'all') {
            query['metadata.category'] = category;
        }
        if (search) {
            query.$text = { $search: search };
        }

        return query;
    }

    /**
     * Build sort option
     */
    buildSortOption(sortBy) {
        const sortOptions = {
            recent: { createdAt: -1 },
            oldest: { createdAt: 1 },
            name: { 'file.originalName': 1 },
            popular: { 'analytics.views.total': -1 },
        };
        return sortOptions[sortBy] || sortOptions.recent;
    }

    /**
     * Handle bulk operation
     */
    async handleBulkOperation(operation, query, data, userId, req, options = {}) {
        let updateData = {};
        let message = '';

        switch (operation) {
            case 'delete':
                updateData = {
                    status: 'deleted',
                    'permissions.visibility': 'private',
                    updatedAt: new Date(),
                    'metadata.lastModifiedBy': {
                        userId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = 'Media items moved to trash';
                break;
            case 'updateVisibility':
                if (!data.visibility) {
                    throw new AppError('Visibility is required', 400);
                }
                updateData = {
                    'permissions.visibility': data.visibility,
                    updatedAt: new Date(),
                    'metadata.lastModifiedBy': {
                        userId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = `Visibility updated to ${data.visibility}`;
                break;
            case 'updateTags':
                if (!Array.isArray(data.tags)) {
                    throw new AppError('Tags array is required', 400);
                }
                updateData = {
                    $addToSet: {
                        'metadata.tags': { $each: data.tags.map((tag) => tag.trim().toLowerCase()).slice(0, 15) },
                    },
                    updatedAt: new Date(),
                    'metadata.lastModifiedBy': {
                        userId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = 'Tags updated';
                break;
        }

        const result = await Media.updateMany(query, updateData, options);
        return { message, result };
    }
}

export default new MediaController();