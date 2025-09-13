import Education from '../models/Education.js';
import EducationService from '../services/EducationService.js';
import VerificationService from '../services/VerificationService.js';
import NotificationService from '../services/NotificationService.js';
import MediaService from '../services/MediaService.js';
import AnalyticsService from '../services/AnalyticsService.js';
import { validateEducation, validateBulkEducation, validateSearch, sanitizeInput } from '../validations/education.validation.js';
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
import AWS from 'aws-sdk';
import { v4 as uuidv4 } from 'uuid';

// Initialize AWS S3 for media and backups
const s3 = new AWS.S3({
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    region: process.env.AWS_REGION,
});

// Rate limiters for various endpoints
const createEducationLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // 10 creates per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_education_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const updateEducationLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 20, // 20 updates per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_education_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const mediaUploadLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 10, // 10 media uploads per 10 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `media_education_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const bulkOperationLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 5, // 5 bulk operations per 30 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_education_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const searchLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 50, // 50 searches per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `search_education_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

class EducationController {
    constructor() {
        this.educationService = EducationService;
        this.verificationService = VerificationService;
        this.notificationService = NotificationService;
        this.mediaService = MediaService;
        this.analyticsService = AnalyticsService;
    }

    /**
     * Create a new education record
     * POST /api/v1/educations
     */
    createEducation = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const educationData = req.body;
        const requestingUserId = req.user.id;

        await createEducationLimiter(req, res, () => { });

        const validation = validateEducation(educationData);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        const sanitizedData = this.sanitizeInput(educationData);
        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const education = await this.educationService.createEducation({
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

            // Async processing for search indexing and analytics
            this.processEducationAsync(education._id, requestingUserId, 'create')
                .catch((err) => logger.error(`Async processing failed for education ${education._id}:`, err));

            // Create backup
            await this.createBackup(education._id, 'create', requestingUserId, { session });

            eventEmitter.emit('education.created', {
                educationId: education._id,
                userId: requestingUserId,
                title: education.title,
            });

            metricsCollector.increment('education.created', { userId: requestingUserId });
            await session.commitTransaction();
            logger.info(`Education created: ${education._id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Education record created successfully',
                data: {
                    id: education._id,
                    title: education.title,
                    status: education.status,
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Education creation failed for user ${requestingUserId}:`, error);
            metricsCollector.increment('education.create_failed', { userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get education record by ID
     * GET /api/v1/educations/:id
     */
    getEducationById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;
        const cacheKey = `education:${id}:${requestingUserId}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('education.cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const education = await this.educationService.getEducationById(id, requestingUserId);
            if (!education) {
                return next(new AppError('Education record not found', 404));
            }

            await this.analyticsService.incrementView(id, 'education', requestingUserId);
            await cacheService.set(cacheKey, education, 600);
            metricsCollector.increment('education.fetched', { id, userId: requestingUserId });
            logger.info(`Fetched education ${id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, { data: education });
        } catch (error) {
            logger.error(`Failed to fetch education ${id}:`, error);
            metricsCollector.increment('education.fetch_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        }
    });

    /**
     * Update education record
     * PUT /api/v1/educations/:id
     */
    updateEducation = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const updates = req.body;
        const requestingUserId = req.user.id;

        await updateEducationLimiter(req, res, () => { });

        const validation = validateEducation(updates, true);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const sanitizedUpdates = this.sanitizeUpdates(updates);
            const education = await this.educationService.updateEducation(id, requestingUserId, sanitizedUpdates, {
                session,
                requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
            });

            this.processEducationAsync(id, requestingUserId, 'update')
                .catch((err) => logger.error(`Async processing failed for education ${id}:`, err));

            await this.createBackup(id, 'update', requestingUserId, { session });
            await cacheService.deletePattern(`education:${id}:*`);

            eventEmitter.emit('education.updated', {
                educationId: id,
                userId: requestingUserId,
                changes: Object.keys(sanitizedUpdates),
            });

            metricsCollector.increment('education.updated', { id, userId: requestingUserId });
            await session.commitTransaction();
            logger.info(`Education updated: ${id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Education record updated successfully',
                data: {
                    id,
                    title: education.title,
                    status: education.status,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Education update failed for ${id}:`, error);
            metricsCollector.increment('education.update_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete education record
     * DELETE /api/v1/educations/:id
     */
    deleteEducation = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const { permanent = false } = req.query;
        const requestingUserId = req.user.id;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            await this.educationService.deleteEducation(id, requestingUserId, permanent, { session });
            await cacheService.deletePattern(`education:${id}:*`);

            eventEmitter.emit('education.deleted', {
                educationId: id,
                userId: requestingUserId,
                permanent,
            });

            metricsCollector.increment(permanent ? 'education.permanently_deleted' : 'education.soft_deleted', {
                id,
                userId: requestingUserId,
            });
            await session.commitTransaction();
            logger.info(`Education ${id} deleted (permanent: ${permanent}) in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: `Education record ${permanent ? 'permanently' : 'soft'} deleted successfully`,
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Education deletion failed for ${id}:`, error);
            metricsCollector.increment('education.delete_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Upload media for education record
     * POST /api/v1/educations/:id/media
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

            const education = await Education.findById(id).session(session);
            if (!education) {
                return next(new AppError('Education record not found', 404));
            }

            const validation = this.educationService.validateMediaUpload(files, education.media || []);
            if (!validation.valid) {
                return next(new AppError(validation.message, 422));
            }

            const mediaResults = await this.mediaService.uploadMedia({
                files,
                entityId: id,
                entityType: 'education',
                userId: requestingUserId,
            }, { session });

            education.media = education.media || [];
            education.media.push(...mediaResults);
            await education.save({ session });

            await cacheService.deletePattern(`education:${id}:*`);

            eventEmitter.emit('education.media_uploaded', {
                educationId: id,
                userId: requestingUserId,
                mediaCount: mediaResults.length,
            });

            metricsCollector.increment('education.media_uploaded', { id, count: mediaResults.length });
            await session.commitTransaction();
            logger.info(`Uploaded ${mediaResults.length} media for education ${id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Media uploaded successfully',
                data: { media: mediaResults },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Media upload failed for education ${id}:`, error);
            metricsCollector.increment('education.media_upload_failed', { id });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get education records with filtering and pagination
     * GET /api/v1/educations
     */
    getEducations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { page = 1, limit = 20, status, categoryId, search, sortBy = 'recent' } = req.query;
        const requestingUserId = req.user.id;
        const cacheKey = `educations:${requestingUserId}:${JSON.stringify({ page, limit, status, categoryId, search, sortBy })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('education.cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const query = this.buildEducationQuery({ status, categoryId, search });
            const sortOption = this.buildSortOption(sortBy);
            const pageNum = Math.max(1, parseInt(page));
            const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
            const skip = (pageNum - 1) * limitNum;

            const [educations, totalCount] = await Promise.all([
                Education.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select('title institution categoryId verification status createdAt analytics')
                    .lean(),
                Education.countDocuments(query).cache({ ttl: 300, key: `education_count_${requestingUserId}` }),
            ]);

            const processedEducations = educations.map((education) => ({
                ...education,
                isVerified: education.verification?.status === 'verified',
            }));

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                educations: processedEducations,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages,
                    hasNext: pageNum < totalPages,
                    hasPrev: pageNum > 1,
                },
                filters: { status, categoryId, search, sortBy },
            };

            await cacheService.set(cacheKey, result, 300);
            metricsCollector.increment('education.fetched', { count: educations.length, userId: requestingUserId });
            logger.info(`Fetched ${educations.length} education records in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch education records:`, error);
            metricsCollector.increment('education.fetch_failed', { userId: requestingUserId });
            return next(this.handleError(error));
        }
    });

    /**
     * Search education records
     * GET /api/v1/educations/search
     */
    searchEducations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { query, filters = {}, page = 1, limit = 20 } = req.body;
        const requestingUserId = req.user.id;

        await searchLimiter(req, res, () => { });

        const validation = validateSearch({ query, filters });
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        const cacheKey = `education_search:${requestingUserId}:${JSON.stringify({ query, filters, page, limit })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('education.search_cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const result = await this.educationService.searchEducations(query, filters, { page, limit });
            await cacheService.set(cacheKey, result, 300);

            metricsCollector.increment('education.searched', { count: result.hits.length, userId: requestingUserId });
            logger.info(`Search returned ${result.hits.length} education records in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Search completed successfully',
                data: result,
            });
        } catch (error) {
            logger.error(`Search failed for query ${query}:`, error);
            metricsCollector.increment('education.search_failed', { userId: requestingUserId });
            return next(new AppError('Failed to search education records', 500));
        }
    });

    /**
     * Get trending education records
     * GET /api/v1/educations/trending
     */
    getTrendingEducations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { timeframe = '30d', categoryId, limit = 20 } = req.query;
        const requestingUserId = req.user.id;
        const cacheKey = `trending_educations:${requestingUserId}:${timeframe}:${categoryId || 'all'}:${limit}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('education.trending_cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const educations = await this.educationService.getTrendingEducations(timeframe, categoryId, parseInt(limit));
            await cacheService.set(cacheKey, educations, 300);

            metricsCollector.increment('education.trending_fetched', { count: educations.length, userId: requestingUserId });
            logger.info(`Fetched ${educations.length} trending education records in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Trending education records fetched successfully',
                data: educations,
            });
        } catch (error) {
            logger.error(`Failed to fetch trending education records:`, error);
            metricsCollector.increment('education.trending_fetch_failed', { userId: requestingUserId });
            return next(new AppError('Failed to fetch trending education records', 500));
        }
    });

    /**
     * Bulk create education records
     * POST /api/v1/educations/bulk
     */
    bulkCreateEducations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const educationsData = req.body.educations;
        const requestingUserId = req.user.id;

        await bulkOperationLimiter(req, res, () => { });

        const validation = validateBulkEducation(educationsData);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const sanitizedData = educationsData.map((education) => this.sanitizeInput(education));
            const createdEducations = await Promise.all(
                sanitizedData.map((education) =>
                    this.educationService.createEducation({
                        ...education,
                        metadata: {
                            ...education.metadata,
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

            createdEducations.forEach((education) => {
                this.processEducationAsync(education._id, requestingUserId, 'create')
                    .catch((err) => logger.error(`Async processing failed for education ${education._id}:`, err));
            });

            await Promise.all(
                createdEducations.map((education) =>
                    this.createBackup(education._id, 'create', requestingUserId, { session })
                )
            );

            eventEmitter.emit('education.bulk_created', {
                educationIds: createdEducations.map((education) => education._id),
                userId: requestingUserId,
            });

            metricsCollector.increment('education.bulk_created', { count: createdEducations.length, userId: requestingUserId });
            await session.commitTransaction();
            logger.info(`Bulk created ${createdEducations.length} education records in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Education records created successfully',
                data: createdEducations.map((education) => ({
                    id: education._id,
                    title: education.title,
                    status: education.status,
                })),
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk education creation failed:`, error);
            metricsCollector.increment('education.bulk_create_failed', { userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Bulk update education records
     * PUT /api/v1/educations/bulk
     */
    bulkUpdateEducations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const updates = req.body.updates;
        const requestingUserId = req.user.id;

        await bulkOperationLimiter(req, res, () => { });

        const validation = validateBulkEducation(updates);
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

            const updatedEducations = await Promise.all(
                sanitizedUpdates.map(({ id, data }) =>
                    this.educationService.updateEducation(id, requestingUserId, data, {
                        session,
                        requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                    })
                )
            );

            await Promise.all(
                updatedEducations.map((education) => {
                    this.processEducationAsync(education._id, requestingUserId, 'update')
                        .catch((err) => logger.error(`Async processing failed for education ${education._id}:`, err));
                    return this.createBackup(education._id, 'update', requestingUserId, { session });
                })
            );

            await Promise.all(
                updatedEducations.map((education) => cacheService.deletePattern(`education:${education._id}:*`))
            );

            eventEmitter.emit('education.bulk_updated', {
                educationIds: updatedEducations.map((education) => education._id),
                userId: requestingUserId,
            });

            metricsCollector.increment('education.bulk_updated', { count: updatedEducations.length, userId: requestingUserId });
            await session.commitTransaction();
            logger.info(`Bulk updated ${updatedEducations.length} education records in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Education records updated successfully',
                data: updatedEducations.map((education) => ({
                    id: education._id,
                    title: education.title,
                    status: education.status,
                })),
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk education update failed:`, error);
            metricsCollector.increment('education.bulk_update_failed', { userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get education analytics
     * GET /api/v1/educations/:id/analytics
     */
    getEducationAnalytics = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const { timeframe = '30d' } = req.query;
        const requestingUserId = req.user.id;
        const cacheKey = `education_analytics:${id}:${timeframe}:${requestingUserId}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('education.analytics_cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const analytics = await this.analyticsService.getEducationAnalytics(id, timeframe);
            await cacheService.set(cacheKey, analytics, 300);

            metricsCollector.increment('education.analytics_fetched', { id, userId: requestingUserId });
            logger.info(`Fetched analytics for education ${id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Education analytics fetched successfully',
                data: analytics,
            });
        } catch (error) {
            logger.error(`Failed to fetch analytics for education ${id}:`, error);
            metricsCollector.increment('education.analytics_fetch_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        }
    });

    /**
     * Export education data
     * GET /api/v1/educations/:id/export
     */
    exportEducation = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const { format = 'json' } = req.query;
        const requestingUserId = req.user.id;

        try {
            const education = await Education.findById(id)
                .select('title institution categoryId verification status analytics metadata')
                .lean();

            if (!education) {
                return next(new AppError('Education record not found', 404));
            }

            let exportData;
            let contentType;
            let extension;

            switch (format.toLowerCase()) {
                case 'json':
                    exportData = JSON.stringify(education, null, 2);
                    contentType = 'application/json';
                    extension = 'json';
                    break;
                case 'csv':
                    exportData = this.convertToCSV(education);
                    contentType = 'text/csv';
                    extension = 'csv';
                    break;
                default:
                    return next(new AppError('Unsupported export format', 400));
            }

            const exportKey = `education_export_${id}_${uuidv4()}.${extension}`;
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

            metricsCollector.increment('education.exported', { id, format, userId: requestingUserId });
            logger.info(`Exported education ${id} as ${format} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Education record exported successfully',
                data: { url: signedUrl },
            });
        } catch (error) {
            logger.error(`Export failed for education ${id}:`, error);
            metricsCollector.increment('education.export_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        }
    });

    /**
     * Get education statistics
     * GET /api/v1/educations/:id/stats
     */
    getEducationStats = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;
        const cacheKey = `education_stats:${id}:${requestingUserId}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('education.stats_cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const stats = await this.educationService.getEducationStats(id);
            await cacheService.set(cacheKey, stats, 3600);

            metricsCollector.increment('education.stats_fetched', { id, userId: requestingUserId });
            logger.info(`Fetched stats for education ${id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Education stats fetched successfully',
                data: stats,
            });
        } catch (error) {
            logger.error(`Failed to fetch stats for education ${id}:`, error);
            metricsCollector.increment('education.stats_fetch_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        }
    });

    /**
     * Archive education record
     * POST /api/v1/educations/:id/archive
     */
    archiveEducation = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const education = await Education.findById(id).session(session);
            if (!education) {
                return next(new AppError('Education record not found', 404));
            }

            education.status.isActive = false;
            education.status.isArchived = true;
            education.status.archivedAt = new Date();
            await education.save({ session });

            await cacheService.deletePattern(`education:${id}:*`);

            eventEmitter.emit('education.archived', {
                educationId: id,
                userId: requestingUserId,
            });

            metricsCollector.increment('education.archived', { id, userId: requestingUserId });
            await session.commitTransaction();
            logger.info(`Education ${id} archived in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Education record archived successfully',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Archiving failed for education ${id}:`, error);
            metricsCollector.increment('education.archive_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Restore education record
     * POST /api/v1/educations/:id/restore
     */
    restoreEducation = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const education = await Education.findById(id).session(session);
            if (!education) {
                return next(new AppError('Education record not found', 404));
            }

            education.status.isActive = true;
            education.status.isArchived = false;
            education.status.restoredAt = new Date();
            await education.save({ session });

            await cacheService.deletePattern(`education:${id}:*`);

            eventEmitter.emit('education.restored', {
                educationId: id,
                userId: requestingUserId,
            });

            metricsCollector.increment('education.restored', { id, userId: requestingUserId });
            await session.commitTransaction();
            logger.info(`Education ${id} restored in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Education record restored successfully',
                data: {
                    id,
                    title: education.title,
                    status: education.status,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Restoring failed for education ${id}:`, error);
            metricsCollector.increment('education.restore_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get education audit logs
     * GET /api/v1/educations/:id/audit
     */
    getAuditLogs = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const { page = 1, limit = 20, action } = req.query;
        const requestingUserId = req.user.id;
        const cacheKey = `education_audit:${id}:${page}:${limit}:${action || 'all'}:${requestingUserId}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('education.audit_cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const pageNum = Math.max(1, parseInt(page));
            const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
            const skip = (pageNum - 1) * limitNum;

            const query = { educationId: id };
            if (action) query.action = action;

            const [logs, totalCount] = await Promise.all([
                this.educationService.getAuditLogs(id, { page: pageNum, limit: limitNum, action }),
                this.educationService.countAuditLogs(id, action),
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
            metricsCollector.increment('education.audit_fetched', { count: logs.length, userId: requestingUserId });
            logger.info(`Fetched ${logs.length} audit logs for education ${id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Audit logs fetched successfully',
                data: result,
            });
        } catch (error) {
            logger.error(`Failed to fetch audit logs for education ${id}:`, error);
            metricsCollector.increment('education.audit_fetch_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        }
    });

    /**
     * Create backup of education record
     * @param {string} educationId - Education ID
     * @param {string} action - Action type
     * @param {string} userId - User ID
     * @param {Object} options - Additional options
     */
    async createBackup(educationId, action, userId, options = {}) {
        const startTime = Date.now();
        try {
            const education = await Education.findById(educationId).lean();
            if (!education) {
                throw new AppError('Education record not found', 404);
            }

            const backupKey = `education_backup_${educationId}_${Date.now()}_${uuidv4()}`;
            await s3.upload({
                Bucket: process.env.S3_BACKUP_BUCKET,
                Key: backupKey,
                Body: JSON.stringify({
                    education,
                    action,
                    userId,
                    timestamp: new Date(),
                }),
                ContentType: 'application/json',
                ServerSideEncryption: 'AES256',
            }).promise();

            metricsCollector.increment('education.backup_created', { userId, action });
            logger.info(`Backup created for education ${educationId} (${action}) in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to create backup for education ${educationId}:`, error);
            metricsCollector.increment('education.backup_failed', { userId });
            throw error;
        }
    }

    /**
     * Process education record asynchronously
     * @param {string} educationId - Education ID
     * @param {string} userId - User ID
     * @param {string} action - Action type
     */
    async processEducationAsync(educationId, userId, action) {
        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const education = await Education.findById(educationId).session(session);
            if (!education) {
                throw new AppError('Education record not found', 404);
            }

            await this.educationService.indexForSearch(education);
            await this.analyticsService.updateEducationAnalytics(educationId, { session });

            await session.commitTransaction();
            logger.info(`Async processing completed for education ${educationId} (${action})`);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Async processing failed for education ${educationId}:`, error);
            metricsCollector.increment('education.async_processing_failed', { educationId });
        } finally {
            session.endSession();
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
            return new AppError('Education record already exists', 409);
        }
        if (error.name === 'CastError') {
            return new AppError('Invalid education ID', 400);
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
            title: sanitizeHtml(data.title || ''),
            institution: sanitizeHtml(data.institution || ''),
            description: sanitizeHtml(data.description || ''),
        };
    }

    /**
     * Sanitize updates
     * @param {Object} updates - Update data
     * @returns {Object} - Sanitized updates
     */
    sanitizeUpdates(updates) {
        const allowedFields = ['title', 'institution', 'description', 'status', 'categoryId', 'startDate', 'endDate'];
        const sanitized = {};
        allowedFields.forEach((field) => {
            if (updates[field] !== undefined) {
                sanitized[field] = ['title', 'institution', 'description'].includes(field)
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
    buildEducationQuery({ status, categoryId, search }) {
        const query = { 'status.isDeleted': false };
        if (status) query['status.workflow'] = status;
        if (categoryId) query.categoryId = categoryId;
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
            recent: { createdAt: -1 },
            title: { title: 1 },
            popularity: { 'analytics.views': -1 },
        };
        return sortOptions[sortBy] || sortOptions.recent;
    }

    /**
     * Convert education to CSV
     * @param {Object} education - Education data
     * @returns {string} - CSV string
     */
    convertToCSV(education) {
        const headers = ['id', 'title', 'institution', 'categoryId', 'verification_status', 'created_at'];
        const row = [
            education._id,
            `"${education.title.replace(/"/g, '""')}"`,
            `"${education.institution.replace(/"/g, '""')}"`,
            education.categoryId || '',
            education.verification?.status || 'pending',
            education.createdAt,
        ];
        return [headers.join(','), row.join(',')].join('\n');
    }
}

export default new EducationController();