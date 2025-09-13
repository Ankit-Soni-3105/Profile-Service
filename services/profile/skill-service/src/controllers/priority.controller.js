import Priority from '../models/Priority.js';
import PriorityService from '../services/PriorityService.js';
import VerificationService from '../services/VerificationService.js';
import MediaService from '../services/MediaService.js';
import NotificationService from '../services/NotificationService.js';
import { validatePriority, sanitizeInput } from '../validations/priority.validation.js';
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
const createPriorityLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 15, // 15 creates per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_priority_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const updatePriorityLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 25, // 25 updates per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_priority_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const verificationLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 5, // 5 verification requests per 30 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `verify_priority_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const bulkOperationsLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // 3 bulk operations per hour
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_priority_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const mediaUploadLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 10, // 10 media uploads per 10 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `media_priority_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

class PriorityController {
    constructor() {
        this.priorityService = new PriorityService();
        this.verificationService = new VerificationService();
        this.mediaService = new MediaService();
        this.notificationService = new NotificationService();
    }

    /**
     * Create a new priority
     * POST /api/v1/priorities/:userId
     */
    createPriority = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const priorityData = req.body;
        const requestingUserId = req.user.id;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied: Cannot create priority for another user', 403));
        }

        await createPriorityLimiter(req, res, () => { });

        const validation = validatePriority(priorityData);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        const sanitizedData = sanitizeInput(priorityData);

        const userPriorityCount = await Priority.countDocuments({
            userId,
            'status.isDeleted': false,
        }).cache({ ttl: 300, key: `user_priority_count_${userId}` });

        const limits = this.getUserLimits(req.user.accountType);
        if (userPriorityCount >= limits.maxPriorities) {
            return next(new AppError(`Priority limit reached (${limits.maxPriorities})`, 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const priority = await this.priorityService.createPriority({
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

            this.processNewPriorityAsync(priority._id, requestingUserId)
                .catch((err) => logger.error(`Async processing failed for priority ${priority._id}:`, err));

            metricsCollector.increment('priority.created', {
                userId,
                category: priority.category,
            });

            eventEmitter.emit('priority.created', {
                priorityId: priority._id,
                userId,
                category: priority.category,
            });

            if (priority.settings?.autoBackup) {
                this.priorityService.createBackup(priority._id, 'create', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for priority ${priority._id}:`, err));
            }

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`Priority created successfully: ${priority._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Priority created successfully',
                data: {
                    id: priority._id,
                    userId: priority.userId,
                    title: priority.title,
                    status: priority.status,
                    createdAt: priority.createdAt,
                    processingStatus: 'started',
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Priority creation failed for user ${userId}:`, error);
            metricsCollector.increment('priority.create_failed', { userId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.code === 11000) {
                return next(new AppError('Priority with this title already exists', 409));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out', 504));
            }
            return next(new AppError('Failed to create priority', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get user's priorities with filtering and pagination
     * GET /api/v1/priorities/:userId
     */
    getPriorities = catchAsync(async (req, res, next) => {
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
            level,
            tags,
            includeAnalytics = 'false',
        } = req.query;

        const query = this.buildPriorityQuery({
            userId,
            status,
            category,
            search,
            level,
            tags,
        });

        const sortOption = this.buildSortOption(sortBy);
        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
        const skip = (pageNum - 1) * limitNum;

        const cacheKey = `priorities:${userId}:${JSON.stringify({
            page: pageNum,
            limit: limitNum,
            status,
            category,
            search,
            sortBy,
            level,
            tags,
        })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('priority.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const [priorities, totalCount] = await Promise.all([
                Priority.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select(this.getSelectFields(includeAnalytics === 'true'))
                    .lean(),
                Priority.countDocuments(query).cache({ ttl: 300, key: `priority_count_${userId}` }),
            ]);

            const processedPriorities = await Promise.all(
                priorities.map((priority) => this.processPriorityData(priority, includeAnalytics === 'true')),
            );

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                priorities: processedPriorities,
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
            metricsCollector.increment('priority.fetched', {
                userId,
                count: priorities.length,
                cached: false,
            });
            logger.info(`Fetched ${priorities.length} priorities for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch priorities for user ${userId}:`, error);
            metricsCollector.increment('priority.fetch_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid query parameters', 400));
            }
            return next(new AppError('Failed to fetch priorities', 500));
        }
    });

    /**
     * Get single priority by ID
     * GET /api/v1/priorities/:userId/:id
     */
    getPriorityById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { includeAnalytics = 'false', includeVerification = 'false' } = req.query;

        try {
            const cacheKey = `priority:${id}:${userId}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('priority.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const priority = await Priority.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .cache({ ttl: 600, key: cacheKey });

            if (!priority) {
                return next(new AppError('Priority not found', 404));
            }

            const hasAccess = this.checkPriorityAccess(priority, requestingUserId, req.user.isAdmin);
            if (!hasAccess) {
                return next(new AppError('Access denied', 403));
            }

            if (requestingUserId !== userId) {
                priority.analytics.viewCount += 1;
                priority.analytics.lastViewed = new Date();
                await priority.save();
            }

            const responseData = this.processPriorityData(priority.toObject(), includeAnalytics === 'true', includeVerification === 'true');

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('priority.viewed', {
                userId,
                viewerId: requestingUserId,
                isOwner: userId === requestingUserId,
            });
            logger.info(`Fetched priority ${id} for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: responseData });
        } catch (error) {
            logger.error(`Failed to fetch priority ${id}:`, error);
            metricsCollector.increment('priority.view_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid priority ID', 400));
            }
            return next(new AppError('Failed to fetch priority', 500));
        }
    });

    /**
     * Update priority
     * PUT /api/v1/priorities/:userId/:id
     */
    updatePriority = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const updates = req.body;

        await updatePriorityLimiter(req, res, () => { });

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const priority = await Priority.findOne({ _id: id, userId }).session(session);
            if (!priority) {
                return next(new AppError('Priority not found', 404));
            }

            const allowedUpdates = this.getAllowedUpdateFields();
            const sanitizedUpdates = this.sanitizeUpdates(updates, allowedUpdates);

            if (Object.keys(sanitizedUpdates).length === 0) {
                return next(new AppError('No valid update fields provided', 400));
            }

            let versionCreated = false;
            if (sanitizedUpdates.description && sanitizedUpdates.description !== priority.description) {
                await priority.createVersion(sanitizedUpdates.description, sanitizedUpdates.title || priority.title, 'edit', {
                    userId: requestingUserId,
                }, { session });
                versionCreated = true;
            }

            Object.assign(priority, sanitizedUpdates);

            priority.metadata.lastModifiedBy = {
                userId: requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date(),
            };

            if (sanitizedUpdates.title || sanitizedUpdates.category) {
                priority.verification.status = 'pending';
                this.processExternalVerification(priority._id, requestingUserId)
                    .catch((err) => logger.error(`Re-verification failed for priority ${id}:`, err));
            }

            await priority.save({ session });

            if (sanitizedUpdates.description) {
                await priority.calculateQualityScore({ session });
            }

            if (priority.settings?.autoBackup) {
                this.priorityService.createBackup(priority._id, 'update', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for priority ${id}:`, err));
            }

            await cacheService.deletePattern(`priority:${id}:*`);
            await cacheService.deletePattern(`priorities:${userId}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('priority.updated', {
                userId,
                versionCreated,
                fieldsUpdated: Object.keys(sanitizedUpdates).length,
            });

            eventEmitter.emit('priority.updated', {
                priorityId: priority._id,
                userId,
                changes: Object.keys(sanitizedUpdates),
                versionCreated,
            });

            logger.info(`Priority updated successfully: ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Priority updated successfully',
                data: {
                    id: priority._id,
                    title: priority.title,
                    status: priority.status,
                    updatedAt: priority.updatedAt,
                    versionCreated,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Priority update failed for ${id}:`, error);
            metricsCollector.increment('priority.update_failed', { userId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out', 504));
            }
            return next(new AppError('Failed to update priority', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete priority (soft or permanent)
     * DELETE /api/v1/priorities/:userId/:id
     */
    deletePriority = catchAsync(async (req, res, next) => {
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

            const priority = await Priority.findOne({ _id: id, userId }).session(session);
            if (!priority) {
                return next(new AppError('Priority not found', 404));
            }

            if (permanent === 'true') {
                await Priority.findByIdAndDelete(id, { session });
                await this.mediaService.deleteAllMedia(id, 'priority', { session });
                this.priorityService.deleteAllBackups(id)
                    .catch((err) => logger.error(`Failed to delete backups for ${id}:`, err));
                metricsCollector.increment('priority.permanently_deleted', { userId });
            } else {
                priority.status.isDeleted = true;
                priority.status.deletedAt = new Date();
                priority.metadata.lastModifiedBy = {
                    userId: requestingUserId,
                    ip: req.ip,
                    userAgent: req.get('User-Agent'),
                    timestamp: new Date(),
                };
                await priority.save({ session });
                metricsCollector.increment('priority.soft_deleted', { userId });
            }

            await cacheService.deletePattern(`priority:${id}:*`);
            await cacheService.deletePattern(`priorities:${userId}:*`);

            eventEmitter.emit('priority.deleted', {
                priorityId: id,
                userId,
                permanent: permanent === 'true',
            });

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`Priority ${id} deleted (permanent: ${permanent}) in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: permanent === 'true' ? 'Priority permanently deleted' : 'Priority moved to trash',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Priority deletion failed for ${id}:`, error);
            metricsCollector.increment('priority.delete_failed', { userId });
            return next(new AppError('Failed to delete priority', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Bulk operations on priorities
     * POST /api/v1/priorities/:userId/bulk
     */
    bulkOperations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { operation, priorityIds, data = {} } = req.body;

        await bulkOperationsLimiter(req, res, () => { });

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        if (!Array.isArray(priorityIds) || priorityIds.length === 0) {
            return next(new AppError('Priority IDs array is required', 400));
        }
        if (priorityIds.length > 100) {
            return next(new AppError('Maximum 100 priorities can be processed at once', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const query = { _id: { $in: priorityIds }, userId };
            const { message } = await this.handleBulkOperation(operation, query, data, requestingUserId, req, { session });

            await Promise.all([
                cacheService.deletePattern(`priorities:${userId}:*`),
                ...priorityIds.map((id) => cacheService.deletePattern(`priority:${id}:*`)),
            ]);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('priority.bulk_operation', {
                userId,
                operation,
                count: priorityIds.length,
            });
            logger.info(`Bulk operation ${operation} completed for ${priorityIds.length} priorities in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message,
                data: {
                    operation,
                    requested: priorityIds.length,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk operation failed for user ${userId}:`, error);
            metricsCollector.increment('priority.bulk_operation_failed', { userId, operation });
            return next(new AppError('Bulk operation failed', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get priority analytics
     * GET /api/v1/priorities/:userId/:id/analytics
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
            const cacheKey = `analytics:priority:${id}:${timeframe}:${metrics}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('priority.analytics_cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const priority = await Priority.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('analytics verification metadata createdAt')
                .cache({ ttl: 900, key: cacheKey });

            if (!priority) {
                return next(new AppError('Priority not found', 404));
            }

            const analytics = this.processAnalyticsData(priority, timeframe, metrics);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('priority.analytics_viewed', { userId });
            logger.info(`Fetched analytics for priority ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: analytics });
        } catch (error) {
            logger.error(`Analytics fetch failed for ${id}:`, error);
            metricsCollector.increment('priority.analytics_fetch_failed', { userId });
            return next(new AppError('Failed to fetch analytics', 500));
        }
    });

    /**
     * Duplicate priority
     * POST /api/v1/priorities/:userId/:id/duplicate
     */
    duplicatePriority = catchAsync(async (req, res, next) => {
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

            const originalPriority = await Priority.findOne({ _id: id, userId }).session(session);
            if (!originalPriority) {
                return next(new AppError('Priority not found', 404));
            }

            const userPriorityCount = await Priority.countDocuments({
                userId,
                'status.isDeleted': false,
            }).cache({ ttl: 300, key: `user_priority_count_${userId}` });

            const limits = this.getUserLimits(req.user.accountType);
            if (userPriorityCount >= limits.maxPriorities) {
                return next(new AppError(`Priority limit reached (${limits.maxPriorities})`, 403));
            }

            const duplicateData = originalPriority.toObject();
            delete duplicateData._id;
            delete duplicateData.createdAt;
            delete duplicateData.updatedAt;
            delete duplicateData.analytics;

            duplicateData.title = title || `${originalPriority.title} (Copy)`;
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

            const duplicate = new Priority(duplicateData);
            await duplicate.save({ session });

            if (duplicate.settings?.autoBackup) {
                this.priorityService.createBackup(duplicate._id, 'duplicate', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for duplicate ${duplicate._id}:`, err));
            }

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('priority.duplicated', { userId });
            logger.info(`Priority ${id} duplicated as ${duplicate._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Priority duplicated successfully',
                data: {
                    originalId: id,
                    duplicateId: duplicate._id,
                    title: duplicate.title,
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Priority duplication failed for ${id}:`, error);
            metricsCollector.increment('priority.duplicate_failed', { userId });
            return next(new AppError('Failed to duplicate priority', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Verify priority
     * POST /api/v1/priorities/:userId/:id/verify
     */
    verifyPriority = catchAsync(async (req, res, next) => {
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

            const priority = await Priority.findOne({ _id: id, userId }).session(session);
            if (!priority) {
                return next(new AppError('Priority not found', 404));
            }

            const verificationResult = await this.processExternalVerification(priority._id, requestingUserId);
            if (!verificationResult.success) {
                return next(new AppError('Verification failed: ' + verificationResult.message, 424));
            }

            priority.verification = {
                status: verificationResult.status,
                confidence: verificationResult.confidence,
                verifiedBy: verificationResult.verifiedBy,
                verifiedAt: new Date(),
                details: verificationResult.details,
            };

            await priority.save({ session });

            this.notificationService.notifyUser(userId, {
                type: 'verification_completed',
                message: `Priority "${priority.title}" verification ${verificationResult.status}`,
                data: { priorityId: id },
            }).catch((err) => logger.error(`Notification failed for priority ${id}:`, err));

            await cacheService.deletePattern(`priority:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('priority.verified', {
                userId,
                status: verificationResult.status,
            });
            logger.info(`Priority ${id} verified in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Priority verification completed',
                data: priority.verification,
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Verification failed for priority ${id}:`, error);
            metricsCollector.increment('priority.verify_failed', { userId });
            if (error.message.includes('timeout')) {
                return next(new AppError('External API timeout', 503));
            }
            return next(new AppError('Failed to verify priority', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Upload media for priority
     * POST /api/v1/priorities/:userId/:id/media
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

            const priority = await Priority.findOne({ _id: id, userId }).session(session);
            if (!priority) {
                return next(new AppError('Priority not found', 404));
            }

            const validation = this.validateMediaUpload(files, priority.media);
            if (!validation.valid) {
                return next(new AppError(validation.message, 422));
            }

            const mediaResults = await this.mediaService.uploadMedia({
                files,
                entityId: id,
                entityType: 'priority',
                userId,
            }, { session });

            const scanResults = await this.mediaService.scanMedia(mediaResults);
            if (scanResults.some((result) => result.infected)) {
                return next(new AppError('Media upload failed: Infected file detected', 422));
            }

            priority.media.push(...mediaResults);
            await priority.save({ session });

            await cacheService.deletePattern(`priority:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('priority.media_uploaded', {
                userId,
                count: mediaResults.length,
            });
            logger.info(`Uploaded ${mediaResults.length} media files for priority ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Media uploaded successfully',
                data: { media: mediaResults },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Media upload failed for priority ${id}:`, error);
            metricsCollector.increment('priority.media_upload_failed', { userId });
            return next(new AppError('Failed to upload media', 422));
        } finally {
            session.endSession();
        }
    });

    /**
     * Share priority
     * POST /api/v1/priorities/:userId/:id/share
     */
    sharePriority = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { platform } = req.body;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const priority = await Priority.findOne({ _id: id, userId }).session(session);
            if (!priority) {
                return next(new AppError('Priority not found', 404));
            }

            const hasAccess = this.checkPriorityAccess(priority, requestingUserId, req.user.isAdmin);
            if (!hasAccess) {
                return next(new AppError('Access denied', 403));
            }

            const shareLink = this.generateShareableLink(priority, platform);

            priority.analytics.shares = priority.analytics.shares || { total: 0, byPlatform: {} };
            priority.analytics.shares.total += 1;
            priority.analytics.shares.byPlatform[platform] = (priority.analytics.shares.byPlatform[platform] || 0) + 1;
            await priority.save({ session });

            await cacheService.deletePattern(`priority:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('priority.shared', { userId, platform });
            logger.info(`Priority ${id} shared on ${platform} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Priority shared successfully',
                data: { shareLink },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Share failed for priority ${id}:`, error);
            metricsCollector.increment('priority.share_failed', { userId });
            return next(new AppError('Failed to share priority', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Endorse priority
     * POST /api/v1/priorities/:userId/:id/endorse
     */
    endorsePriority = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const priority = await Priority.findOne({ _id: id, userId }).session(session);
            if (!priority) {
                return next(new AppError('Priority not found', 404));
            }

            const isConnected = await this.priorityService.checkConnectionLevel(userId, requestingUserId);
            if (!isConnected) {
                return next(new AppError('Must be connected to endorse', 403));
            }

            if (priority.endorsements.some((e) => e.userId.toString() === requestingUserId)) {
                return next(new AppError('Priority already endorsed by this user', 409));
            }

            priority.endorsements.push({
                userId: requestingUserId,
                endorsedAt: new Date(),
            });
            await priority.save({ session });

            this.notificationService.notifyUser(userId, {
                type: 'endorsement',
                message: `Your priority "${priority.title}" was endorsed`,
                data: { priorityId: id, endorserId: requestingUserId },
            }).catch((err) => logger.error(`Notification failed for endorsement ${id}:`, err));

            await cacheService.deletePattern(`priority:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('priority.endorsed', { userId, endorserId: requestingUserId });
            logger.info(`Priority ${id} endorsed in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Priority endorsed successfully',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Endorsement failed for priority ${id}:`, error);
            metricsCollector.increment('priority.endorse_failed', { userId });
            return next(new AppError('Failed to endorse priority', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get verification status
     * GET /api/v1/priorities/:userId/:id/verification
     */
    getVerificationStatus = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        try {
            const cacheKey = `verification:priority:${id}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('priority.verification_cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const priority = await Priority.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('verification')
                .cache({ ttl: 60, key: cacheKey });

            if (!priority) {
                return next(new AppError('Priority not found', 404));
            }

            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('priority.verification_viewed', { userId });
            logger.info(`Fetched verification status for priority ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                data: priority.verification,
            });
        } catch (error) {
            logger.error(`Verification status fetch failed for ${id}:`, error);
            metricsCollector.increment('priority.verification_fetch_failed', { userId });
            return next(new AppError('Failed to fetch verification status', 500));
        }
    });

    /**
     * Get trending priorities
     * GET /api/v1/priorities/trending
     */
    getTrendingPriorities = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { timeframe = '7d', category, limit = 20 } = req.query;

        const cacheKey = `trending:priorities:${timeframe}:${category || 'all'}:${limit}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('priority.trending_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const priorities = await this.priorityService.getTrendingPriorities(timeframe, category, parseInt(limit));
            const processedPriorities = await Promise.all(
                priorities.map((priority) => this.processPriorityData(priority, false)),
            );

            const result = { priorities: processedPriorities };
            await cacheService.set(cacheKey, result, 3600);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('priority.trending_viewed', { count: priorities.length });
            logger.info(`Fetched ${priorities.length} trending priorities in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch trending priorities:`, error);
            metricsCollector.increment('priority.trending_fetch_failed');
            return next(new AppError('Failed to fetch trending priorities', 500));
        }
    });

    /**
     * Get priorities by category
     * GET /api/v1/priorities/categories/:category
     */
    getPrioritiesByCategory = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { category } = req.params;
        const { page = 1, limit = 20, sortBy = 'recent' } = req.query;

        const cacheKey = `priorities:category:${category}:${page}:${limit}:${sortBy}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('priority.category_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const query = this.buildPriorityQuery({ category });
            const sortOption = this.buildSortOption(sortBy);
            const pageNum = Math.max(1, parseInt(page));
            const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
            const skip = (pageNum - 1) * limitNum;

            const [priorities, totalCount] = await Promise.all([
                Priority.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select(this.getSelectFields(false))
                    .lean(),
                Priority.countDocuments(query).cache({ ttl: 300, key: `priority_category_count_${category}` }),
            ]);

            const processedPriorities = await Promise.all(
                priorities.map((priority) => this.processPriorityData(priority, false)),
            );

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                priorities: processedPriorities,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages,
                },
            };

            await cacheService.set(cacheKey, result, 1800);
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('priority.category_viewed', { category, count: priorities.length });
            logger.info(`Fetched ${priorities.length} priorities for category ${category} in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch priorities for category ${category}:`, error);
            metricsCollector.increment('priority.category_fetch_failed', { category });
            return next(new AppError('Failed to fetch priorities by category', 500));
        }
    });

    /**
     * Search priorities
     * GET /api/v1/priorities/search
     */
    searchPriorities = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { query, page = 1, limit = 20, filters = {} } = req.query;

        const cacheKey = `search:priorities:${query}:${JSON.stringify(filters)}:${page}:${limit}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('priority.search_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const searchResults = await this.priorityService.searchPriorities(query, filters, {
                page: parseInt(page),
                limit: parseInt(limit),
            });

            const result = {
                priorities: searchResults.hits,
                totalCount: searchResults.total,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    totalPages: Math.ceil(searchResults.total / parseInt(limit)),
                },
            };

            await cacheService.set(cacheKey, result, 300);
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('priority.searched', { query, count: searchResults.hits.length });
            logger.info(`Search returned ${searchResults.hits.length} priorities in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Search failed for query ${query}:`, error);
            metricsCollector.increment('priority.search_failed');
            return next(new AppError('Failed to search priorities', 500));
        }
    });

    /**
     * Export priorities as CSV
     * GET /api/v1/priorities/:userId/export
     */
    exportPriorities = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { format = 'csv', fields = 'title,description,category,level' } = req.query;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        try {
            const priorities = await Priority.find({ userId, 'status.isDeleted': false })
                .read('secondaryPreferred')
                .select(fields.split(',').join(' '))
                .lean();

            const csvData = this.convertToCSV(priorities, fields.split(','));
            const filename = `priorities_${userId}_${Date.now()}.csv`;

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('priority.exported', { userId, format });
            logger.info(`Exported ${priorities.length} priorities for user ${userId} in ${responseTime}ms`);

            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            return res.send(csvData);
        } catch (error) {
            logger.error(`Export failed for user ${userId}:`, error);
            metricsCollector.increment('priority.export_failed', { userId });
            return next(new AppError('Failed to export priorities', 500));
        }
    });

    // Helper Methods

    async processNewPriorityAsync(priorityId, userId) {
        try {
            const session = await mongoose.startSession();
            session.startTransaction();

            const priority = await Priority.findById(priorityId).session(session);
            if (!priority) {
                await session.abortTransaction();
                session.endSession();
                return;
            }

            const skillsExtracted = await this.priorityService.extractSkills(priority.description);
            priority.skills = skillsExtracted.slice(0, 20);

            await priority.calculateQualityScore({ session });

            await this.processExternalVerification(priorityId, userId);

            await this.priorityService.indexForSearch(priority);

            await this.priorityService.updateUserStats(userId, { session });

            await priority.save({ session });
            await session.commitTransaction();
            logger.info(`Async processing completed for priority ${priorityId}`);
        } catch (error) {
            logger.error(`Async processing failed for priority ${priorityId}:`, error);
        } finally {
            session.endSession();
        }
    }

    checkPriorityAccess(priority, requestingUserId, isAdmin) {
        if (isAdmin) return true;
        if (priority.userId.toString() === requestingUserId) return true;
        if (priority.visibility === 'public') return true;
        return false;
    }

    getAllowedUpdateFields() {
        return [
            'title',
            'description',
            'category',
            'tags',
            'skills',
            'level',
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

    processAnalyticsData(priority, timeframe, metrics) {
        const analytics = priority.analytics || {};
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
            endorsements: priority.endorsements?.length || 0,
        };

        if (metrics === 'detailed') {
            filteredAnalytics.verification = priority.verification;
        }

        return filteredAnalytics;
    }

    getUserLimits(accountType) {
        const limits = {
            free: { maxPriorities: 20, maxMedia: 5, maxSizeMB: 50 },
            premium: { maxPriorities: 100, maxMedia: 20, maxSizeMB: 200 },
            enterprise: { maxPriorities: 500, maxMedia: 50, maxSizeMB: 500 },
        };
        return limits[accountType] || limits.free;
    }

    buildPriorityQuery({ userId, status, category, search, level, tags }) {
        const query = { userId, 'status.isDeleted': false };

        if (status && status !== 'all') {
            query['status.isActive'] = status === 'active';
        }
        if (category && category !== 'all') {
            query.category = category;
        }
        if (level) {
            query.level = level;
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
        const baseFields = 'title description category tags skills level visibility status createdAt updatedAt';
        return includeAnalytics ? baseFields + ' analytics' : baseFields;
    }

    async processPriorityData(priority, includeAnalytics = false, includeVerification = false) {
        const processed = { ...priority };

        if (!includeAnalytics) {
            delete processed.analytics;
        }
        if (!includeVerification) {
            delete processed.verification;
        }

        return processed;
    }

    calculateTrendingScore(priority) {
        const viewsWeight = 0.4;
        const sharesWeight = 0.3;
        const endorsementsWeight = 0.2;
        const recencyWeight = 0.1;

        const daysSinceCreated = (Date.now() - new Date(priority.createdAt)) / (1000 * 60 * 60 * 24);
        const recencyScore = Math.max(0, 10 - daysSinceCreated);

        return (
            (priority.analytics.viewCount * viewsWeight) +
            ((priority.analytics.shares?.total || 0) * sharesWeight) +
            (priority.endorsements.length * endorsementsWeight) +
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

    async processExternalVerification(priorityId, userId) {
        try {
            const priority = await Priority.findById(priorityId);
            const result = await this.verificationService.verifyPriority({
                priorityId,
                userId,
                title: priority.title,
                level: priority.level,
                category: priority.category,
            });

            return result;
        } catch (error) {
            logger.error(`External verification failed for priority ${priorityId}:`, error);
            return { success: false, message: error.message };
        }
    }

    generateShareableLink(priority, platform) {
        const baseUrl = process.env.APP_URL || 'https://app.example.com';
        return `${baseUrl}/priorities/${priority._id}/share?platform=${platform}`;
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
                message = 'Priorities moved to trash';
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
                message = 'Priorities archived';
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
                message = 'Priorities published';
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

        const result = await Priority.updateMany(query, updateData, options);
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

export default new PriorityController();