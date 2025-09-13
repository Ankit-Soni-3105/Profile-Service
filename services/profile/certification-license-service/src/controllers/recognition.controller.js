import Recognition from '../models/Recognition.js';
import RecognitionService from '../services/RecognitionService.js';
import NotificationService from '../services/NotificationService.js';
import MediaService from '../services/MediaService.js';
import AnalyticsService from '../services/AnalyticsService.js';
import { validateRecognition, validateBulkRecognition, validateSearch, sanitizeInput } from '../validations/recognition.validation.js';
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
const createRecognitionLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 5, // 5 creates per 10 minutes per user
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_recognition_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const updateRecognitionLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 10, // 10 updates per 5 minutes per user
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_recognition_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const mediaUploadLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 media uploads per 15 minutes per user
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `media_recognition_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const bulkOperationLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 3, // 3 bulk operations per 30 minutes per user
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_recognition_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const searchLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 30, // 30 searches per 5 minutes per user
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `search_recognition_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const verifyLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 10, // 10 verification requests per hour per user
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `verify_recognition_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const shareLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 15, // 15 shares per 10 minutes per user
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `share_recognition_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

class RecognitionsController {
    constructor() {
        this.recognitionService = RecognitionService;
        this.notificationService = NotificationService;
        this.mediaService = MediaService;
        this.analyticsService = AnalyticsService;
    }

    /**
     * Create a new recognition record
     * POST /api/v1/recognitions
     */
    createRecognition = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const recognitionData = req.body;
        const requestingUserId = req.user.id;

        await createRecognitionLimiter(req, res, () => {});

        const validation = validateRecognition(recognitionData);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        const sanitizedData = this.sanitizeInput(recognitionData);
        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const recognition = await this.recognitionService.createRecognition({
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

            // Queue async tasks for search indexing, analytics, and notifications
            await queueService.addJob('processRecognition', {
                recognitionId: recognition._id,
                userId: requestingUserId,
                action: 'create',
            });

            // Create backup
            await this.createBackup(recognition._id, 'create', requestingUserId, { session });

            eventEmitter.emit('recognition.created', {
                recognitionId: recognition._id,
                userId: requestingUserId,
                title: recognition.title,
                recipientId: recognition.recipientId,
            });

            metricsCollector.increment('recognition.created', { userId: requestingUserId });
            await session.commitTransaction();
            logger.info(`Recognition created: ${recognition._id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Recognition record created successfully',
                data: {
                    id: recognition._id,
                    title: recognition.title,
                    recipientId: recognition.recipientId,
                    issueDate: recognition.issueDate,
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Recognition creation failed for user ${requestingUserId}:`, error);
            metricsCollector.increment('recognition.create_failed', { userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get recognition record by ID
     * GET /api/v1/recognitions/:id
     */
    getRecognitionById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;
        const cacheKey = `recognition:${id}:${requestingUserId}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('recognition.cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const recognition = await this.recognitionService.getRecognitionById(id, requestingUserId);
            if (!recognition) {
                return next(new AppError('Recognition record not found', 404));
            }

            await this.analyticsService.incrementView(id, 'recognition', requestingUserId);
            await cacheService.set(cacheKey, recognition, 300);
            metricsCollector.increment('recognition.fetched', { id, userId: requestingUserId });
            logger.info(`Fetched recognition ${id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, { data: recognition });
        } catch (error) {
            logger.error(`Failed to fetch recognition ${id}:`, error);
            metricsCollector.increment('recognition.fetch_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        }
    });

    /**
     * Update recognition record
     * PUT /api/v1/recognitions/:id
     */
    updateRecognition = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const updates = req.body;
        const requestingUserId = req.user.id;

        await updateRecognitionLimiter(req, res, () => {});

        const validation = validateRecognition(updates, true);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const sanitizedUpdates = this.sanitizeUpdates(updates);
            const recognition = await this.recognitionService.updateRecognition(id, requestingUserId, sanitizedUpdates, {
                session,
                requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
            });

            await queueService.addJob('processRecognition', {
                recognitionId: id,
                userId: requestingUserId,
                action: 'update',
            });

            await this.createBackup(id, 'update', requestingUserId, { session });
            await cacheService.deletePattern(`recognition:${id}:*`);

            eventEmitter.emit('recognition.updated', {
                recognitionId: id,
                userId: requestingUserId,
                changes: Object.keys(sanitizedUpdates),
            });

            metricsCollector.increment('recognition.updated', { id, userId: requestingUserId });
            await session.commitTransaction();
            logger.info(`Recognition updated: ${id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Recognition record updated successfully',
                data: {
                    id,
                    title: recognition.title,
                    recipientId: recognition.recipientId,
                    issueDate: recognition.issueDate,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Recognition update failed for ${id}:`, error);
            metricsCollector.increment('recognition.update_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete recognition record
     * DELETE /api/v1/recognitions/:id
     */
    deleteRecognition = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const { permanent = false } = req.query;
        const requestingUserId = req.user.id;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            await this.recognitionService.deleteRecognition(id, requestingUserId, permanent, { session });
            await cacheService.deletePattern(`recognition:${id}:*`);

            eventEmitter.emit('recognition.deleted', {
                recognitionId: id,
                userId: requestingUserId,
                permanent,
            });

            metricsCollector.increment(permanent ? 'recognition.permanently_deleted' : 'recognition.soft_deleted', {
                id,
                userId: requestingUserId,
            });
            await session.commitTransaction();
            logger.info(`Recognition ${id} deleted (permanent: ${permanent}) in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: `Recognition record ${permanent ? 'permanently' : 'soft'} deleted successfully`,
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Recognition deletion failed for ${id}:`, error);
            metricsCollector.increment('recognition.delete_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Upload media for recognition record
     * POST /api/v1/recognitions/:id/media
     */
    uploadMedia = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const files = req.files;
        const requestingUserId = req.user.id;

        await mediaUploadLimiter(req, res, () => {});

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const recognition = await Recognition.findById(id).session(session);
            if (!recognition) {
                return next(new AppError('Recognition record not found', 404));
            }

            const validation = this.recognitionService.validateMediaUpload(files, recognition.media || []);
            if (!validation.valid) {
                return next(new AppError(validation.message, 422));
            }

            const mediaResults = await this.mediaService.uploadMedia({
                files,
                entityId: id,
                entityType: 'recognition',
                userId: requestingUserId,
            }, { session });

            recognition.media = recognition.media || [];
            recognition.media.push(...mediaResults);
            await recognition.save({ session });

            await cacheService.deletePattern(`recognition:${id}:*`);

            eventEmitter.emit('recognition.media_uploaded', {
                recognitionId: id,
                userId: requestingUserId,
                mediaCount: mediaResults.length,
            });

            metricsCollector.increment('recognition.media_uploaded', { id, count: mediaResults.length });
            await session.commitTransaction();
            logger.info(`Uploaded ${mediaResults.length} media for recognition ${id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Media uploaded successfully',
                data: { media: mediaResults },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Media upload failed for recognition ${id}:`, error);
            metricsCollector.increment('recognition.media_upload_failed', { id });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get recognition records with filtering and pagination
     * GET /api/v1/recognitions
     */
    getRecognitions = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { page = 1, limit = 20, status, recipientId, categoryId, search, sortBy = 'issueDate' } = req.query;
        const requestingUserId = req.user.id;
        const cacheKey = `recognitions:${requestingUserId}:${JSON.stringify({ page, limit, status, recipientId, categoryId, search, sortBy })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('recognition.cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const query = this.buildRecognitionQuery({ status, recipientId, categoryId, search });
            const sortOption = this.buildSortOption(sortBy);
            const pageNum = Math.max(1, parseInt(page));
            const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
            const skip = (pageNum - 1) * limitNum;

            const [recognitions, totalCount] = await Promise.all([
                Recognition.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select('title issuer recipientId issueDate categoryId verification status createdAt analytics')
                    .lean(),
                Recognition.countDocuments(query).cache({ ttl: 300, key: `recognition_count_${requestingUserId}` }),
            ]);

            const processedRecognitions = recognitions.map((recognition) => ({
                ...recognition,
                isVerified: recognition.verification?.status === 'verified',
            }));

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                recognitions: processedRecognitions,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages,
                    hasNext: pageNum < totalPages,
                    hasPrev: pageNum > 1,
                },
                filters: { status, recipientId, categoryId, search, sortBy },
            };

            await cacheService.set(cacheKey, result, 300);
            metricsCollector.increment('recognition.fetched', { count: recognitions.length, userId: requestingUserId });
            logger.info(`Fetched ${recognitions.length} recognition records in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch recognition records:`, error);
            metricsCollector.increment('recognition.fetch_failed', { userId: requestingUserId });
            return next(this.handleError(error));
        }
    });

    /**
     * Search recognition records
     * GET /api/v1/recognitions/search
     */
    searchRecognitions = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { query, filters = {}, page = 1, limit = 20 } = req.body;
        const requestingUserId = req.user.id;

        await searchLimiter(req, res, () => {});

        const validation = validateSearch({ query, filters });
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        const cacheKey = `recognition_search:${requestingUserId}:${JSON.stringify({ query, filters, page, limit })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('recognition.search_cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const result = await this.recognitionService.searchRecognitions(query, filters, { page, limit });
            await cacheService.set(cacheKey, result, 300);

            metricsCollector.increment('recognition.searched', { count: result.hits.length, userId: requestingUserId });
            logger.info(`Search returned ${result.hits.length} recognition records in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Search completed successfully',
                data: result,
            });
        } catch (error) {
            logger.error(`Search failed for query ${query}:`, error);
            metricsCollector.increment('recognition.search_failed', { userId: requestingUserId });
            return next(new AppError('Failed to search recognition records', 500));
        }
    });

    /**
     * Verify recognition record
     * POST /api/v1/recognitions/:id/verify
     */
    verifyRecognition = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const { verificationStatus, verificationDetails } = req.body;
        const requestingUserId = req.user.id;

        await verifyLimiter(req, res, () => {});

        if (!req.user.isAdmin) {
            return next(new AppError('Only admins can verify recognitions', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const recognition = await Recognition.findById(id).session(session);
            if (!recognition) {
                return next(new AppError('Recognition record not found', 404));
            }

            recognition.verification = {
                status: verificationStatus,
                details: this.sanitizeInput(verificationDetails || {}),
                verifiedBy: {
                    userId: requestingUserId,
                    timestamp: new Date(),
                },
            };
            recognition.metadata.lastModifiedBy = {
                userId: requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date(),
            };

            await recognition.save({ session });
            await cacheService.deletePattern(`recognition:${id}:*`);

            await queueService.addJob('processRecognition', {
                recognitionId: id,
                userId: requestingUserId,
                action: 'verify',
            });

            await this.createBackup(id, 'verify', requestingUserId, { session });

            eventEmitter.emit('recognition.verified', {
                recognitionId: id,
                userId: requestingUserId,
                verificationStatus,
            });

            metricsCollector.increment('recognition.verified', { id, userId: requestingUserId });
            await session.commitTransaction();
            logger.info(`Recognition ${id} verified in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Recognition record verified successfully',
                data: {
                    id,
                    title: recognition.title,
                    verificationStatus: recognition.verification.status,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Verification failed for recognition ${id}:`, error);
            metricsCollector.increment('recognition.verify_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Share recognition record
     * POST /api/v1/recognitions/:id/share
     */
    shareRecognition = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;

        await shareLimiter(req, res, () => {});

        try {
            const recognition = await Recognition.findById(id).lean();
            if (!recognition) {
                return next(new AppError('Recognition record not found', 404));
            }

            if (!this.recognitionService.hasPermission(requestingUserId, recognition, 'share')) {
                return next(new AppError('Access denied', 403));
            }

            const shareToken = uuidv4();
            const shareUrl = `${process.env.APP_BASE_URL}/recognitions/share/${id}/${shareToken}`;
            await cacheService.set(`recognition_share:${id}:${shareToken}`, recognition, 24 * 60 * 60); // 24 hours TTL

            await queueService.addJob('notifyRecognitionShare', {
                recognitionId: id,
                userId: requestingUserId,
                shareUrl,
                recipientId: recognition.recipientId,
            });

            eventEmitter.emit('recognition.shared', {
                recognitionId: id,
                userId: requestingUserId,
                shareUrl,
            });

            metricsCollector.increment('recognition.shared', { id, userId: requestingUserId });
            logger.info(`Recognition ${id} shared in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Recognition record shared successfully',
                data: { shareUrl },
            });
        } catch (error) {
            logger.error(`Share failed for recognition ${id}:`, error);
            metricsCollector.increment('recognition.share_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        }
    });

    /**
     * Get recognition audit logs
     * GET /api/v1/recognitions/:id/audit
     */
    getAuditLogs = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const { page = 1, limit = 20, action } = req.query;
        const requestingUserId = req.user.id;
        const cacheKey = `recognition_audit:${id}:${page}:${limit}:${action || 'all'}:${requestingUserId}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('recognition.audit_cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const pageNum = Math.max(1, parseInt(page));
            const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
            const skip = (pageNum - 1) * limitNum;

            const query = { recognitionId: id };
            if (action) query.action = action;

            const [logs, totalCount] = await Promise.all([
                this.recognitionService.getAuditLogs(id, { page: pageNum, limit: limitNum, action }),
                this.recognitionService.countAuditLogs(id, action),
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
            metricsCollector.increment('recognition.audit_fetched', { count: logs.length, userId: requestingUserId });
            logger.info(`Fetched ${logs.length} audit logs for recognition ${id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Audit logs fetched successfully',
                data: result,
            });
        } catch (error) {
            logger.error(`Failed to fetch audit logs for recognition ${id}:`, error);
            metricsCollector.increment('recognition.audit_fetch_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        }
    });

    /**
     * Create backup of recognition record
     * @param {string} recognitionId - Recognition ID
     * @param {string} action - Action type
     * @param {string} userId - User ID
     * @param {Object} options - Additional options
     */
    async createBackup(recognitionId, action, userId, options = {}) {
        const startTime = Date.now();
        try {
            const recognition = await Recognition.findById(recognitionId).lean();
            if (!recognition) {
                throw new AppError('Recognition record not found', 404);
            }

            const backupKey = `recognition_backup_${recognitionId}_${Date.now()}_${uuidv4()}`;
            await s3.upload({
                Bucket: process.env.S3_BACKUP_BUCKET,
                Key: backupKey,
                Body: JSON.stringify({
                    recognition,
                    action,
                    userId,
                    timestamp: new Date(),
                }),
                ContentType: 'application/json',
                ServerSideEncryption: 'AES256',
            }).promise();

            metricsCollector.increment('recognition.backup_created', { userId, action });
            logger.info(`Backup created for recognition ${recognitionId} (${action}) in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to create backup for recognition ${recognitionId}:`, error);
            metricsCollector.increment('recognition.backup_failed', { userId });
            throw error;
        }
    }

    /**
     * Process recognition record asynchronously
     * @param {string} recognitionId - Recognition ID
     * @param {string} userId - User ID
     * @param {string} action - Action type
     */
    async processRecognitionAsync(recognitionId, userId, action) {
        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const recognition = await Recognition.findById(recognitionId).session(session);
            if (!recognition) {
                throw new AppError('Recognition record not found', 404);
            }

            await this.recognitionService.indexForSearch(recognition);
            await this.analyticsService.updateRecognitionAnalytics(recognitionId, { session });

            await session.commitTransaction();
            logger.info(`Async processing completed for recognition ${recognitionId} (${action})`);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Async processing failed for recognition ${recognitionId}:`, error);
            metricsCollector.increment('recognition.async_processing_failed', { recognitionId });
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
            return new AppError('Recognition record already exists', 409);
        }
        if (error.name === 'CastError') {
            return new AppError('Invalid recognition ID', 400);
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
            description: sanitizeHtml(data.description || ''),
            categoryId: sanitizeHtml(data.categoryId || ''),
        };
    }

    /**
     * Sanitize updates
     * @param {Object} updates - Update data
     * @returns {Object} - Sanitized updates
     */
    sanitizeUpdates(updates) {
        const allowedFields = ['title', 'issuer', 'recipientId', 'issueDate', 'description', 'categoryId', 'status'];
        const sanitized = {};
        allowedFields.forEach((field) => {
            if (updates[field] !== undefined) {
                sanitized[field] = ['title', 'description'].includes(field)
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
    buildRecognitionQuery({ status, recipientId, categoryId, search }) {
        const query = { 'status.isDeleted': false };
        if (status) query['status.workflow'] = status;
        if (recipientId) query.recipientId = recipientId;
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
            issueDate: { issueDate: -1 },
            recent: { createdAt: -1 },
            title: { title: 1 },
            popularity: { 'analytics.views': -1 },
        };
        return sortOptions[sortBy] || sortOptions.issueDate;
    }

    /**
     * Convert recognition to CSV
     * @param {Object} recognition - Recognition data
     * @returns {string} - CSV string
     */
    convertToCSV(recognition) {
        const headers = ['id', 'title', 'issuer', 'recipientId', 'issueDate', 'verification_status', 'created_at'];
        const row = [
            recognition._id,
            `"${recognition.title.replace(/"/g, '""')}"`,
            `"${recognition.issuer.replace(/"/g, '""')}"`,
            recognition.recipientId,
            recognition.issueDate,
            recognition.verification?.status || 'pending',
            recognition.createdAt,
        ];
        return [headers.join(','), row.join(',')].join('\n');
    }
}

export default new RecognitionsController();