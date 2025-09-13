import Comparison from '../models/Comparison.js';
import ComparisonService from '../services/ComparisonService.js';
import VerificationService from '../services/VerificationService.js';
import MediaService from '../services/MediaService.js';
import NotificationService from '../services/NotificationService.js';
import { validateComparison, sanitizeInput } from '../validations/comparison.validation.js';
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
const createComparisonLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 15, // 15 creates per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_comparison_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const updateComparisonLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 25, // 25 updates per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_comparison_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const verificationLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 5, // 5 verification requests per 30 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `verify_comparison_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const bulkOperationsLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // 3 bulk operations per hour
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_comparison_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const mediaUploadLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 10, // 10 media uploads per 10 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `media_comparison_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

class ComparisonController {
    constructor() {
        this.comparisonService = new ComparisonService();
        this.verificationService = new VerificationService();
        this.mediaService = new MediaService();
        this.notificationService = new NotificationService();
    }

    /**
     * Create a new comparison
     * POST /api/v1/comparisons/:userId
     */
    createComparison = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const comparisonData = req.body;
        const requestingUserId = req.user.id;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied: Cannot create comparison for another user', 403));
        }

        await createComparisonLimiter(req, res, () => { });

        const validation = validateComparison(comparisonData);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        const sanitizedData = sanitizeInput(comparisonData);

        const userComparisonCount = await Comparison.countDocuments({
            userId,
            'status.isDeleted': false,
        }).cache({ ttl: 300, key: `user_comparison_count_${userId}` });

        const limits = this.getUserLimits(req.user.accountType);
        if (userComparisonCount >= limits.maxComparisons) {
            return next(new AppError(`Comparison limit reached (${limits.maxComparisons})`, 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const comparison = await this.comparisonService.createComparison({
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

            this.processNewComparisonAsync(comparison._id, requestingUserId)
                .catch((err) => logger.error(`Async processing failed for comparison ${comparison._id}:`, err));

            metricsCollector.increment('comparison.created', {
                userId,
                category: comparison.category,
            });

            eventEmitter.emit('comparison.created', {
                comparisonId: comparison._id,
                userId,
                category: comparison.category,
            });

            if (comparison.settings?.autoBackup) {
                this.comparisonService.createBackup(comparison._id, 'create', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for comparison ${comparison._id}:`, err));
            }

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`Comparison created successfully: ${comparison._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Comparison created successfully',
                data: {
                    id: comparison._id,
                    userId: comparison.userId,
                    title: comparison.title,
                    status: comparison.status,
                    createdAt: comparison.createdAt,
                    processingStatus: 'started',
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Comparison creation failed for user ${userId}:`, error);
            metricsCollector.increment('comparison.create_failed', { userId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.code === 11000) {
                return next(new AppError('Comparison with this title already exists', 409));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out', 504));
            }
            return next(new AppError('Failed to create comparison', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get user's comparisons with filtering and pagination
     * GET /api/v1/comparisons/:userId
     */
    getComparisons = catchAsync(async (req, res, next) => {
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
            tags,
            includeAnalytics = 'false',
        } = req.query;

        const query = this.buildComparisonQuery({
            userId,
            status,
            category,
            search,
            tags,
        });

        const sortOption = this.buildSortOption(sortBy);
        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
        const skip = (pageNum - 1) * limitNum;

        const cacheKey = `comparisons:${userId}:${JSON.stringify({
            page: pageNum,
            limit: limitNum,
            status,
            category,
            search,
            sortBy,
            tags,
        })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('comparison.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const [comparisons, totalCount] = await Promise.all([
                Comparison.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select(this.getSelectFields(includeAnalytics === 'true'))
                    .lean(),
                Comparison.countDocuments(query).cache({ ttl: 300, key: `comparison_count_${userId}` }),
            ]);

            const processedComparisons = await Promise.all(
                comparisons.map((comparison) => this.processComparisonData(comparison, includeAnalytics === 'true')),
            );

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                comparisons: processedComparisons,
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
            metricsCollector.increment('comparison.fetched', {
                userId,
                count: comparisons.length,
                cached: false,
            });
            logger.info(`Fetched ${comparisons.length} comparisons for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch comparisons for user ${userId}:`, error);
            metricsCollector.increment('comparison.fetch_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid query parameters', 400));
            }
            return next(new AppError('Failed to fetch comparisons', 500));
        }
    });

    /**
     * Get single comparison by ID
     * GET /api/v1/comparisons/:userId/:id
     */
    getComparisonById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { includeAnalytics = 'false', includeVerification = 'false' } = req.query;

        try {
            const cacheKey = `comparison:${id}:${userId}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('comparison.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const comparison = await Comparison.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .cache({ ttl: 600, key: cacheKey });

            if (!comparison) {
                return next(new AppError('Comparison not found', 404));
            }

            const hasAccess = this.checkComparisonAccess(comparison, requestingUserId, req.user.isAdmin);
            if (!hasAccess) {
                return next(new AppError('Access denied', 403));
            }

            if (requestingUserId !== userId) {
                comparison.analytics.viewCount += 1;
                comparison.analytics.lastViewed = new Date();
                await comparison.save();
            }

            const responseData = this.processComparisonData(comparison.toObject(), includeAnalytics === 'true', includeVerification === 'true');

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('comparison.viewed', {
                userId,
                viewerId: requestingUserId,
                isOwner: userId === requestingUserId,
            });
            logger.info(`Fetched comparison ${id} for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: responseData });
        } catch (error) {
            logger.error(`Failed to fetch comparison ${id}:`, error);
            metricsCollector.increment('comparison.view_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid comparison ID', 400));
            }
            return next(new AppError('Failed to fetch comparison', 500));
        }
    });

    /**
     * Update comparison
     * PUT /api/v1/comparisons/:userId/:id
     */
    updateComparison = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const updates = req.body;

        await updateComparisonLimiter(req, res, () => { });

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const comparison = await Comparison.findOne({ _id: id, userId }).session(session);
            if (!comparison) {
                return next(new AppError('Comparison not found', 404));
            }

            const allowedUpdates = this.getAllowedUpdateFields();
            const sanitizedUpdates = this.sanitizeUpdates(updates, allowedUpdates);

            if (Object.keys(sanitizedUpdates).length === 0) {
                return next(new AppError('No valid update fields provided', 400));
            }

            let versionCreated = false;
            if (sanitizedUpdates.description && sanitizedUpdates.description !== comparison.description) {
                await comparison.createVersion(sanitizedUpdates.description, sanitizedUpdates.title || comparison.title, 'edit', {
                    userId: requestingUserId,
                }, { session });
                versionCreated = true;
            }

            Object.assign(comparison, sanitizedUpdates);

            comparison.metadata.lastModifiedBy = {
                userId: requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date(),
            };

            if (sanitizedUpdates.title || sanitizedUpdates.category) {
                comparison.verification.status = 'pending';
                this.processExternalVerification(comparison._id, requestingUserId)
                    .catch((err) => logger.error(`Re-verification failed for comparison ${id}:`, err));
            }

            await comparison.save({ session });

            if (sanitizedUpdates.description) {
                await comparison.calculateQualityScore({ session });
            }

            if (comparison.settings?.autoBackup) {
                this.comparisonService.createBackup(comparison._id, 'update', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for comparison ${id}:`, err));
            }

            await cacheService.deletePattern(`comparison:${id}:*`);
            await cacheService.deletePattern(`comparisons:${userId}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('comparison.updated', {
                userId,
                versionCreated,
                fieldsUpdated: Object.keys(sanitizedUpdates).length,
            });

            eventEmitter.emit('comparison.updated', {
                comparisonId: comparison._id,
                userId,
                changes: Object.keys(sanitizedUpdates),
                versionCreated,
            });

            logger.info(`Comparison updated successfully: ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Comparison updated successfully',
                data: {
                    id: comparison._id,
                    title: comparison.title,
                    status: comparison.status,
                    updatedAt: comparison.updatedAt,
                    versionCreated,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Comparison update failed for ${id}:`, error);
            metricsCollector.increment('comparison.update_failed', { userId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out', 504));
            }
            return next(new AppError('Failed to update comparison', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete comparison (soft or permanent)
     * DELETE /api/v1/comparisons/:userId/:id
     */
    deleteComparison = catchAsync(async (req, res, next) => {
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

            const comparison = await Comparison.findOne({ _id: id, userId }).session(session);
            if (!comparison) {
                return next(new AppError('Comparison not found', 404));
            }

            if (permanent === 'true') {
                await Comparison.findByIdAndDelete(id, { session });
                await this.mediaService.deleteAllMedia(id, 'comparison', { session });
                this.comparisonService.deleteAllBackups(id)
                    .catch((err) => logger.error(`Failed to delete backups for ${id}:`, err));
                metricsCollector.increment('comparison.permanently_deleted', { userId });
            } else {
                comparison.status.isDeleted = true;
                comparison.status.deletedAt = new Date();
                comparison.metadata.lastModifiedBy = {
                    userId: requestingUserId,
                    ip: req.ip,
                    userAgent: req.get('User-Agent'),
                    timestamp: new Date(),
                };
                await comparison.save({ session });
                metricsCollector.increment('comparison.soft_deleted', { userId });
            }

            await cacheService.deletePattern(`comparison:${id}:*`);
            await cacheService.deletePattern(`comparisons:${userId}:*`);

            eventEmitter.emit('comparison.deleted', {
                comparisonId: id,
                userId,
                permanent: permanent === 'true',
            });

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`Comparison ${id} deleted (permanent: ${permanent}) in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: permanent === 'true' ? 'Comparison permanently deleted' : 'Comparison moved to trash',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Comparison deletion failed for ${id}:`, error);
            metricsCollector.increment('comparison.delete_failed', { userId });
            return next(new AppError('Failed to delete comparison', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Bulk operations on comparisons
     * POST /api/v1/comparisons/:userId/bulk
     */
    bulkOperations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { operation, comparisonIds, data = {} } = req.body;

        await bulkOperationsLimiter(req, res, () => { });

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        if (!Array.isArray(comparisonIds) || comparisonIds.length === 0) {
            return next(new AppError('Comparison IDs array is required', 400));
        }
        if (comparisonIds.length > 100) {
            return next(new AppError('Maximum 100 comparisons can be processed at once', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const query = { _id: { $in: comparisonIds }, userId };
            const { message } = await this.handleBulkOperation(operation, query, data, requestingUserId, req, { session });

            await Promise.all([
                cacheService.deletePattern(`comparisons:${userId}:*`),
                ...comparisonIds.map((id) => cacheService.deletePattern(`comparison:${id}:*`)),
            ]);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('comparison.bulk_operation', {
                userId,
                operation,
                count: comparisonIds.length,
            });
            logger.info(`Bulk operation ${operation} completed for ${comparisonIds.length} comparisons in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message,
                data: {
                    operation,
                    requested: comparisonIds.length,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk operation failed for user ${userId}:`, error);
            metricsCollector.increment('comparison.bulk_operation_failed', { userId, operation });
            return next(new AppError('Bulk operation failed', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get comparison analytics
     * GET /api/v1/comparisons/:userId/:id/analytics
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
            const cacheKey = `analytics:comparison:${id}:${timeframe}:${metrics}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('comparison.analytics_cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const comparison = await Comparison.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('analytics verification metadata createdAt')
                .cache({ ttl: 900, key: cacheKey });

            if (!comparison) {
                return next(new AppError('Comparison not found', 404));
            }

            const analytics = this.processAnalyticsData(comparison, timeframe, metrics);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('comparison.analytics_viewed', { userId });
            logger.info(`Fetched analytics for comparison ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: analytics });
        } catch (error) {
            logger.error(`Analytics fetch failed for ${id}:`, error);
            metricsCollector.increment('comparison.analytics_fetch_failed', { userId });
            return next(new AppError('Failed to fetch analytics', 500));
        }
    });

    /**
     * Duplicate comparison
     * POST /api/v1/comparisons/:userId/:id/duplicate
     */
    duplicateComparison = catchAsync(async (req, res, next) => {
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

            const originalComparison = await Comparison.findOne({ _id: id, userId }).session(session);
            if (!originalComparison) {
                return next(new AppError('Comparison not found', 404));
            }

            const userComparisonCount = await Comparison.countDocuments({
                userId,
                'status.isDeleted': false,
            }).cache({ ttl: 300, key: `user_comparison_count_${userId}` });

            const limits = this.getUserLimits(req.user.accountType);
            if (userComparisonCount >= limits.maxComparisons) {
                return next(new AppError(`Comparison limit reached (${limits.maxComparisons})`, 403));
            }

            const duplicateData = originalComparison.toObject();
            delete duplicateData._id;
            delete duplicateData.createdAt;
            delete duplicateData.updatedAt;
            delete duplicateData.analytics;

            duplicateData.title = title || `${originalComparison.title} (Copy)`;
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

            const duplicate = new Comparison(duplicateData);
            await duplicate.save({ session });

            if (duplicate.settings?.autoBackup) {
                this.comparisonService.createBackup(duplicate._id, 'duplicate', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for duplicate ${duplicate._id}:`, err));
            }

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('comparison.duplicated', { userId });
            logger.info(`Comparison ${id} duplicated as ${duplicate._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Comparison duplicated successfully',
                data: {
                    originalId: id,
                    duplicateId: duplicate._id,
                    title: duplicate.title,
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Comparison duplication failed for ${id}:`, error);
            metricsCollector.increment('comparison.duplicate_failed', { userId });
            return next(new AppError('Failed to duplicate comparison', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Verify comparison
     * POST /api/v1/comparisons/:userId/:id/verify
     */
    verifyComparison = catchAsync(async (req, res, next) => {
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

            const comparison = await Comparison.findOne({ _id: id, userId }).session(session);
            if (!comparison) {
                return next(new AppError('Comparison not found', 404));
            }

            const verificationResult = await this.processExternalVerification(comparison._id, requestingUserId);
            if (!verificationResult.success) {
                return next(new AppError('Verification failed: ' + verificationResult.message, 424));
            }

            comparison.verification = {
                status: verificationResult.status,
                confidence: verificationResult.confidence,
                verifiedBy: verificationResult.verifiedBy,
                verifiedAt: new Date(),
                details: verificationResult.details,
            };

            await comparison.save({ session });

            this.notificationService.notifyUser(userId, {
                type: 'verification_completed',
                message: `Comparison "${comparison.title}" verification ${verificationResult.status}`,
                data: { comparisonId: id },
            }).catch((err) => logger.error(`Notification failed for comparison ${id}:`, err));

            await cacheService.deletePattern(`comparison:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('comparison.verified', {
                userId,
                status: verificationResult.status,
            });
            logger.info(`Comparison ${id} verified in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Comparison verification completed',
                data: comparison.verification,
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Verification failed for comparison ${id}:`, error);
            metricsCollector.increment('comparison.verify_failed', { userId });
            if (error.message.includes('timeout')) {
                return next(new AppError('External API timeout', 503));
            }
            return next(new AppError('Failed to verify comparison', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Upload media for comparison
     * POST /api/v1/comparisons/:userId/:id/media
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

            const comparison = await Comparison.findOne({ _id: id, userId }).session(session);
            if (!comparison) {
                return next(new AppError('Comparison not found', 404));
            }

            const validation = this.validateMediaUpload(files, comparison.media);
            if (!validation.valid) {
                return next(new AppError(validation.message, 422));
            }

            const mediaResults = await this.mediaService.uploadMedia({
                files,
                entityId: id,
                entityType: 'comparison',
                userId,
            }, { session });

            const scanResults = await this.mediaService.scanMedia(mediaResults);
            if (scanResults.some((result) => result.infected)) {
                return next(new AppError('Media upload failed: Infected file detected', 422));
            }

            comparison.media.push(...mediaResults);
            await comparison.save({ session });

            await cacheService.deletePattern(`comparison:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('comparison.media_uploaded', {
                userId,
                count: mediaResults.length,
            });
            logger.info(`Uploaded ${mediaResults.length} media files for comparison ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Media uploaded successfully',
                data: { media: mediaResults },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Media upload failed for comparison ${id}:`, error);
            metricsCollector.increment('comparison.media_upload_failed', { userId });
            return next(new AppError('Failed to upload media', 422));
        } finally {
            session.endSession();
        }
    });

    /**
     * Share comparison
     * POST /api/v1/comparisons/:userId/:id/share
     */
    shareComparison = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { platform } = req.body;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const comparison = await Comparison.findOne({ _id: id, userId }).session(session);
            if (!comparison) {
                return next(new AppError('Comparison not found', 404));
            }

            const hasAccess = this.checkComparisonAccess(comparison, requestingUserId, req.user.isAdmin);
            if (!hasAccess) {
                return next(new AppError('Access denied', 403));
            }

            const shareLink = this.generateShareableLink(comparison, platform);

            comparison.analytics.shares = comparison.analytics.shares || { total: 0, byPlatform: {} };
            comparison.analytics.shares.total += 1;
            comparison.analytics.shares.byPlatform[platform] = (comparison.analytics.shares.byPlatform[platform] || 0) + 1;
            await comparison.save({ session });

            await cacheService.deletePattern(`comparison:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('comparison.shared', { userId, platform });
            logger.info(`Comparison ${id} shared on ${platform} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Comparison shared successfully',
                data: { shareLink },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Share failed for comparison ${id}:`, error);
            metricsCollector.increment('comparison.share_failed', { userId });
            return next(new AppError('Failed to share comparison', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Endorse comparison
     * POST /api/v1/comparisons/:userId/:id/endorse
     */
    endorseComparison = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const comparison = await Comparison.findOne({ _id: id, userId }).session(session);
            if (!comparison) {
                return next(new AppError('Comparison not found', 404));
            }

            const isConnected = await this.comparisonService.checkConnectionLevel(userId, requestingUserId);
            if (!isConnected) {
                return next(new AppError('Must be connected to endorse', 403));
            }

            if (comparison.endorsements.some((e) => e.userId.toString() === requestingUserId)) {
                return next(new AppError('Comparison already endorsed by this user', 409));
            }

            comparison.endorsements.push({
                userId: requestingUserId,
                endorsedAt: new Date(),
            });
            await comparison.save({ session });

            this.notificationService.notifyUser(userId, {
                type: 'endorsement',
                message: `Your comparison "${comparison.title}" was endorsed`,
                data: { comparisonId: id, endorserId: requestingUserId },
            }).catch((err) => logger.error(`Notification failed for endorsement ${id}:`, err));

            await cacheService.deletePattern(`comparison:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('comparison.endorsed', { userId, endorserId: requestingUserId });
            logger.info(`Comparison ${id} endorsed in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Comparison endorsed successfully',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Endorsement failed for comparison ${id}:`, error);
            metricsCollector.increment('comparison.endorse_failed', { userId });
            return next(new AppError('Failed to endorse comparison', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get verification status
     * GET /api/v1/comparisons/:userId/:id/verification
     */
    getVerificationStatus = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        try {
            const cacheKey = `verification:comparison:${id}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('comparison.verification_cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const comparison = await Comparison.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('verification')
                .cache({ ttl: 60, key: cacheKey });

            if (!comparison) {
                return next(new AppError('Comparison not found', 404));
            }

            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('comparison.verification_viewed', { userId });
            logger.info(`Fetched verification status for comparison ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                data: comparison.verification,
            });
        } catch (error) {
            logger.error(`Verification status fetch failed for ${id}:`, error);
            metricsCollector.increment('comparison.verification_fetch_failed', { userId });
            return next(new AppError('Failed to fetch verification status', 500));
        }
    });

    /**
     * Get trending comparisons
     * GET /api/v1/comparisons/trending
     */
    getTrendingComparisons = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { timeframe = '7d', category, limit = 20 } = req.query;

        const cacheKey = `trending:comparisons:${timeframe}:${category || 'all'}:${limit}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('comparison.trending_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const comparisons = await this.comparisonService.getTrendingComparisons(timeframe, category, parseInt(limit));
            const processedComparisons = await Promise.all(
                comparisons.map((comparison) => this.processComparisonData(comparison, false)),
            );

            const result = { comparisons: processedComparisons };
            await cacheService.set(cacheKey, result, 3600);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('comparison.trending_viewed', { count: comparisons.length });
            logger.info(`Fetched ${comparisons.length} trending comparisons in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch trending comparisons:`, error);
            metricsCollector.increment('comparison.trending_fetch_failed');
            return next(new AppError('Failed to fetch trending comparisons', 500));
        }
    });

    /**
     * Get comparisons by category
     * GET /api/v1/comparisons/categories/:category
     */
    getComparisonsByCategory = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { category } = req.params;
        const { page = 1, limit = 20, sortBy = 'recent' } = req.query;

        const cacheKey = `comparisons:category:${category}:${page}:${limit}:${sortBy}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('comparison.category_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const query = this.buildComparisonQuery({ category });
            const sortOption = this.buildSortOption(sortBy);
            const pageNum = Math.max(1, parseInt(page));
            const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
            const skip = (pageNum - 1) * limitNum;

            const [comparisons, totalCount] = await Promise.all([
                Comparison.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select(this.getSelectFields(false))
                    .lean(),
                Comparison.countDocuments(query).cache({ ttl: 300, key: `comparison_category_count_${category}` }),
            ]);

            const processedComparisons = await Promise.all(
                comparisons.map((comparison) => this.processComparisonData(comparison, false)),
            );

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                comparisons: processedComparisons,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages,
                },
            };

            await cacheService.set(cacheKey, result, 1800);
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('comparison.category_viewed', { category, count: comparisons.length });
            logger.info(`Fetched ${comparisons.length} comparisons for category ${category} in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch comparisons for category ${category}:`, error);
            metricsCollector.increment('comparison.category_fetch_failed', { category });
            return next(new AppError('Failed to fetch comparisons by category', 500));
        }
    });

    /**
     * Search comparisons
     * GET /api/v1/comparisons/search
     */
    searchComparisons = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { query, page = 1, limit = 20, filters = {} } = req.query;

        const cacheKey = `search:comparisons:${query}:${JSON.stringify(filters)}:${page}:${limit}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('comparison.search_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const searchResults = await this.comparisonService.searchComparisons(query, filters, {
                page: parseInt(page),
                limit: parseInt(limit),
            });

            const result = {
                comparisons: searchResults.hits,
                totalCount: searchResults.total,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    totalPages: Math.ceil(searchResults.total / parseInt(limit)),
                },
            };

            await cacheService.set(cacheKey, result, 300);
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('comparison.searched', { query, count: searchResults.hits.length });
            logger.info(`Search returned ${searchResults.hits.length} comparisons in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Search failed for query ${query}:`, error);
            metricsCollector.increment('comparison.search_failed');
            return next(new AppError('Failed to search comparisons', 500));
        }
    });

    /**
     * Export comparisons as CSV
     * GET /api/v1/comparisons/:userId/export
     */
    exportComparisons = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { format = 'csv', fields = 'title,description,category' } = req.query;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        try {
            const comparisons = await Comparison.find({ userId, 'status.isDeleted': false })
                .read('secondaryPreferred')
                .select(fields.split(',').join(' '))
                .lean();

            const csvData = this.convertToCSV(comparisons, fields.split(','));
            const filename = `comparisons_${userId}_${Date.now()}.csv`;

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('comparison.exported', { userId, format });
            logger.info(`Exported ${comparisons.length} comparisons for user ${userId} in ${responseTime}ms`);

            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            return res.send(csvData);
        } catch (error) {
            logger.error(`Export failed for user ${userId}:`, error);
            metricsCollector.increment('comparison.export_failed', { userId });
            return next(new AppError('Failed to export comparisons', 500));
        }
    });

    // Helper Methods

    async processNewComparisonAsync(comparisonId, userId) {
        try {
            const session = await mongoose.startSession();
            session.startTransaction();

            const comparison = await Comparison.findById(comparisonId).session(session);
            if (!comparison) {
                await session.abortTransaction();
                session.endSession();
                return;
            }

            const skillsExtracted = await this.comparisonService.extractSkills(comparison.description);
            comparison.skills = skillsExtracted.slice(0, 20);

            await comparison.calculateQualityScore({ session });

            await this.processExternalVerification(comparisonId, userId);

            await this.comparisonService.indexForSearch(comparison);

            await this.comparisonService.updateUserStats(userId, { session });

            await comparison.save({ session });
            await session.commitTransaction();
            logger.info(`Async processing completed for comparison ${comparisonId}`);
        } catch (error) {
            logger.error(`Async processing failed for comparison ${comparisonId}:`, error);
        } finally {
            session.endSession();
        }
    }

    checkComparisonAccess(comparison, requestingUserId, isAdmin) {
        if (isAdmin) return true;
        if (comparison.userId.toString() === requestingUserId) return true;
        if (comparison.visibility === 'public') return true;
        return false;
    }

    getAllowedUpdateFields() {
        return [
            'title',
            'description',
            'category',
            'tags',
            'skills',
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

    processAnalyticsData(comparison, timeframe, metrics) {
        const analytics = comparison.analytics || {};
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
            endorsements: comparison.endorsements?.length || 0,
        };

        if (metrics === 'detailed') {
            filteredAnalytics.verification = comparison.verification;
        }

        return filteredAnalytics;
    }

    getUserLimits(accountType) {
        const limits = {
            free: { maxComparisons: 20, maxMedia: 5, maxSizeMB: 50 },
            premium: { maxComparisons: 100, maxMedia: 20, maxSizeMB: 200 },
            enterprise: { maxComparisons: 500, maxMedia: 50, maxSizeMB: 500 },
        };
        return limits[accountType] || limits.free;
    }

    buildComparisonQuery({ userId, status, category, search, tags }) {
        const query = { userId, 'status.isDeleted': false };

        if (status && status !== 'all') {
            query['status.isActive'] = status === 'active';
        }
        if (category && category !== 'all') {
            query.category = category;
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
        const baseFields = 'title description category tags skills visibility status createdAt updatedAt';
        return includeAnalytics ? baseFields + ' analytics' : baseFields;
    }

    async processComparisonData(comparison, includeAnalytics = false, includeVerification = false) {
        const processed = { ...comparison };

        if (!includeAnalytics) {
            delete processed.analytics;
        }
        if (!includeVerification) {
            delete processed.verification;
        }

        return processed;
    }

    calculateTrendingScore(comparison) {
        const viewsWeight = 0.4;
        const sharesWeight = 0.3;
        const endorsementsWeight = 0.2;
        const recencyWeight = 0.1;

        const daysSinceCreated = (Date.now() - new Date(comparison.createdAt)) / (1000 * 60 * 60 * 24);
        const recencyScore = Math.max(0, 10 - daysSinceCreated);

        return (
            (comparison.analytics.viewCount * viewsWeight) +
            ((comparison.analytics.shares?.total || 0) * sharesWeight) +
            (comparison.endorsements.length * endorsementsWeight) +
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

    async processExternalVerification(comparisonId, userId) {
        try {
            const comparison = await Comparison.findById(comparisonId);
            const result = await this.verificationService.verifyComparison({
                comparisonId,
                userId,
                title: comparison.title,
                category: comparison.category,
            });

            return result;
        } catch (error) {
            logger.error(`External verification failed for comparison ${comparisonId}:`, error);
            return { success: false, message: error.message };
        }
    }

    generateShareableLink(comparison, platform) {
        const baseUrl = process.env.APP_URL || 'https://app.example.com';
        return `${baseUrl}/comparisons/${comparison._id}/share?platform=${platform}`;
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
                message = 'Comparisons moved to trash';
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
                message = 'Comparisons archived';
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
                message = 'Comparisons published';
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

        const result = await Comparison.updateMany(query, updateData, options);
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

export default new ComparisonController();