import Analysis from '../models/Analysis.js';
import AnalysisService from '../services/AnalysisService.js';
import VerificationService from '../services/VerificationService.js';
import MediaService from '../services/MediaService.js';
import NotificationService from '../services/NotificationService.js';
import { validateAnalysis, sanitizeInput } from '../validations/analysis.validation.js';
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
const createAnalysisLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 15, // 15 creates per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_analysis_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const updateAnalysisLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 25, // 25 updates per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_analysis_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const verificationLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 5, // 5 verification requests per 30 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `verify_analysis_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const bulkOperationsLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // 3 bulk operations per hour
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_analysis_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const mediaUploadLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 10, // 10 media uploads per 10 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `media_analysis_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

class AnalysisController {
    constructor() {
        this.analysisService = new AnalysisService();
        this.verificationService = new VerificationService();
        this.mediaService = new MediaService();
        this.notificationService = new NotificationService();
    }

    /**
     * Create a new analysis
     * POST /api/v1/analyses/:userId
     */
    createAnalysis = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const analysisData = req.body;
        const requestingUserId = req.user.id;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied: Cannot create analysis for another user', 403));
        }

        await createAnalysisLimiter(req, res, () => { });

        const validation = validateAnalysis(analysisData);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        const sanitizedData = sanitizeInput(analysisData);

        const userAnalysisCount = await Analysis.countDocuments({
            userId,
            'status.isDeleted': false,
        }).cache({ ttl: 300, key: `user_analysis_count_${userId}` });

        const limits = this.getUserLimits(req.user.accountType);
        if (userAnalysisCount >= limits.maxAnalyses) {
            return next(new AppError(`Analysis limit reached (${limits.maxAnalyses})`, 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const analysis = await this.analysisService.createAnalysis({
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

            this.processNewAnalysisAsync(analysis._id, requestingUserId)
                .catch((err) => logger.error(`Async processing failed for analysis ${analysis._id}:`, err));

            metricsCollector.increment('analysis.created', {
                userId,
                category: analysis.category,
            });

            eventEmitter.emit('analysis.created', {
                analysisId: analysis._id,
                userId,
                category: analysis.category,
            });

            if (analysis.settings?.autoBackup) {
                this.analysisService.createBackup(analysis._id, 'create', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for analysis ${analysis._id}:`, err));
            }

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`Analysis created successfully: ${analysis._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Analysis created successfully',
                data: {
                    id: analysis._id,
                    userId: analysis.userId,
                    title: analysis.title,
                    status: analysis.status,
                    createdAt: analysis.createdAt,
                    processingStatus: 'started',
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Analysis creation failed for user ${userId}:`, error);
            metricsCollector.increment('analysis.create_failed', { userId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.code === 11000) {
                return next(new AppError('Analysis with this title already exists', 409));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out', 504));
            }
            return next(new AppError('Failed to create analysis', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get user's analyses with filtering and pagination
     * GET /api/v1/analyses/:userId
     */
    getAnalyses = catchAsync(async (req, res, next) => {
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

        const query = this.buildAnalysisQuery({
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

        const cacheKey = `analyses:${userId}:${JSON.stringify({
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
                metricsCollector.increment('analysis.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const [analyses, totalCount] = await Promise.all([
                Analysis.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select(this.getSelectFields(includeAnalytics === 'true'))
                    .lean(),
                Analysis.countDocuments(query).cache({ ttl: 300, key: `analysis_count_${userId}` }),
            ]);

            const processedAnalyses = await Promise.all(
                analyses.map((analysis) => this.processAnalysisData(analysis, includeAnalytics === 'true')),
            );

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                analyses: processedAnalyses,
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
            metricsCollector.increment('analysis.fetched', {
                userId,
                count: analyses.length,
                cached: false,
            });
            logger.info(`Fetched ${analyses.length} analyses for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch analyses for user ${userId}:`, error);
            metricsCollector.increment('analysis.fetch_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid query parameters', 400));
            }
            return next(new AppError('Failed to fetch analyses', 500));
        }
    });

    /**
     * Get single analysis by ID
     * GET /api/v1/analyses/:userId/:id
     */
    getAnalysisById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { includeAnalytics = 'false', includeVerification = 'false' } = req.query;

        try {
            const cacheKey = `analysis:${id}:${userId}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('analysis.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const analysis = await Analysis.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .cache({ ttl: 600, key: cacheKey });

            if (!analysis) {
                return next(new AppError('Analysis not found', 404));
            }

            const hasAccess = this.checkAnalysisAccess(analysis, requestingUserId, req.user.isAdmin);
            if (!hasAccess) {
                return next(new AppError('Access denied', 403));
            }

            if (requestingUserId !== userId) {
                analysis.analytics.viewCount += 1;
                analysis.analytics.lastViewed = new Date();
                await analysis.save();
            }

            const responseData = this.processAnalysisData(analysis.toObject(), includeAnalytics === 'true', includeVerification === 'true');

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('analysis.viewed', {
                userId,
                viewerId: requestingUserId,
                isOwner: userId === requestingUserId,
            });
            logger.info(`Fetched analysis ${id} for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: responseData });
        } catch (error) {
            logger.error(`Failed to fetch analysis ${id}:`, error);
            metricsCollector.increment('analysis.view_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid analysis ID', 400));
            }
            return next(new AppError('Failed to fetch analysis', 500));
        }
    });

    /**
     * Update analysis
     * PUT /api/v1/analyses/:userId/:id
     */
    updateAnalysis = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const updates = req.body;

        await updateAnalysisLimiter(req, res, () => { });

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const analysis = await Analysis.findOne({ _id: id, userId }).session(session);
            if (!analysis) {
                return next(new AppError('Analysis not found', 404));
            }

            const allowedUpdates = this.getAllowedUpdateFields();
            const sanitizedUpdates = this.sanitizeUpdates(updates, allowedUpdates);

            if (Object.keys(sanitizedUpdates).length === 0) {
                return next(new AppError('No valid update fields provided', 400));
            }

            let versionCreated = false;
            if (sanitizedUpdates.description && sanitizedUpdates.description !== analysis.description) {
                await analysis.createVersion(sanitizedUpdates.description, sanitizedUpdates.title || analysis.title, 'edit', {
                    userId: requestingUserId,
                }, { session });
                versionCreated = true;
            }

            Object.assign(analysis, sanitizedUpdates);

            analysis.metadata.lastModifiedBy = {
                userId: requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date(),
            };

            if (sanitizedUpdates.title || sanitizedUpdates.category) {
                analysis.verification.status = 'pending';
                this.processExternalVerification(analysis._id, requestingUserId)
                    .catch((err) => logger.error(`Re-verification failed for analysis ${id}:`, err));
            }

            await analysis.save({ session });

            if (sanitizedUpdates.description) {
                await analysis.calculateQualityScore({ session });
            }

            if (analysis.settings?.autoBackup) {
                this.analysisService.createBackup(analysis._id, 'update', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for analysis ${id}:`, err));
            }

            await cacheService.deletePattern(`analysis:${id}:*`);
            await cacheService.deletePattern(`analyses:${userId}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('analysis.updated', {
                userId,
                versionCreated,
                fieldsUpdated: Object.keys(sanitizedUpdates).length,
            });

            eventEmitter.emit('analysis.updated', {
                analysisId: analysis._id,
                userId,
                changes: Object.keys(sanitizedUpdates),
                versionCreated,
            });

            logger.info(`Analysis updated successfully: ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Analysis updated successfully',
                data: {
                    id: analysis._id,
                    title: analysis.title,
                    status: analysis.status,
                    updatedAt: analysis.updatedAt,
                    versionCreated,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Analysis update failed for ${id}:`, error);
            metricsCollector.increment('analysis.update_failed', { userId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out', 504));
            }
            return next(new AppError('Failed to update analysis', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete analysis (soft or permanent)
     * DELETE /api/v1/analyses/:userId/:id
     */
    deleteAnalysis = catchAsync(async (req, res, next) => {
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

            const analysis = await Analysis.findOne({ _id: id, userId }).session(session);
            if (!analysis) {
                return next(new AppError('Analysis not found', 404));
            }

            if (permanent === 'true') {
                await Analysis.findByIdAndDelete(id, { session });
                await this.mediaService.deleteAllMedia(id, 'analysis', { session });
                this.analysisService.deleteAllBackups(id)
                    .catch((err) => logger.error(`Failed to delete backups for ${id}:`, err));
                metricsCollector.increment('analysis.permanently_deleted', { userId });
            } else {
                analysis.status.isDeleted = true;
                analysis.status.deletedAt = new Date();
                analysis.metadata.lastModifiedBy = {
                    userId: requestingUserId,
                    ip: req.ip,
                    userAgent: req.get('User-Agent'),
                    timestamp: new Date(),
                };
                await analysis.save({ session });
                metricsCollector.increment('analysis.soft_deleted', { userId });
            }

            await cacheService.deletePattern(`analysis:${id}:*`);
            await cacheService.deletePattern(`analyses:${userId}:*`);

            eventEmitter.emit('analysis.deleted', {
                analysisId: id,
                userId,
                permanent: permanent === 'true',
            });

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`Analysis ${id} deleted (permanent: ${permanent}) in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: permanent === 'true' ? 'Analysis permanently deleted' : 'Analysis moved to trash',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Analysis deletion failed for ${id}:`, error);
            metricsCollector.increment('analysis.delete_failed', { userId });
            return next(new AppError('Failed to delete analysis', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Bulk operations on analyses
     * POST /api/v1/analyses/:userId/bulk
     */
    bulkOperations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { operation, analysisIds, data = {} } = req.body;

        await bulkOperationsLimiter(req, res, () => { });

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        if (!Array.isArray(analysisIds) || analysisIds.length === 0) {
            return next(new AppError('Analysis IDs array is required', 400));
        }
        if (analysisIds.length > 100) {
            return next(new AppError('Maximum 100 analyses can be processed at once', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const query = { _id: { $in: analysisIds }, userId };
            const { message } = await this.handleBulkOperation(operation, query, data, requestingUserId, req, { session });

            await Promise.all([
                cacheService.deletePattern(`analyses:${userId}:*`),
                ...analysisIds.map((id) => cacheService.deletePattern(`analysis:${id}:*`)),
            ]);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('analysis.bulk_operation', {
                userId,
                operation,
                count: analysisIds.length,
            });
            logger.info(`Bulk operation ${operation} completed for ${analysisIds.length} analyses in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message,
                data: {
                    operation,
                    requested: analysisIds.length,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk operation failed for user ${userId}:`, error);
            metricsCollector.increment('analysis.bulk_operation_failed', { userId, operation });
            return next(new AppError('Bulk operation failed', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get analysis analytics
     * GET /api/v1/analyses/:userId/:id/analytics
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
            const cacheKey = `analytics:analysis:${id}:${timeframe}:${metrics}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('analysis.analytics_cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const analysis = await Analysis.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('analytics verification metadata createdAt')
                .cache({ ttl: 900, key: cacheKey });

            if (!analysis) {
                return next(new AppError('Analysis not found', 404));
            }

            const analytics = this.processAnalyticsData(analysis, timeframe, metrics);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('analysis.analytics_viewed', { userId });
            logger.info(`Fetched analytics for analysis ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: analytics });
        } catch (error) {
            logger.error(`Analytics fetch failed for ${id}:`, error);
            metricsCollector.increment('analysis.analytics_fetch_failed', { userId });
            return next(new AppError('Failed to fetch analytics', 500));
        }
    });

    /**
     * Duplicate analysis
     * POST /api/v1/analyses/:userId/:id/duplicate
     */
    duplicateAnalysis = catchAsync(async (req, res, next) => {
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

            const originalAnalysis = await Analysis.findOne({ _id: id, userId }).session(session);
            if (!originalAnalysis) {
                return next(new AppError('Analysis not found', 404));
            }

            const userAnalysisCount = await Analysis.countDocuments({
                userId,
                'status.isDeleted': false,
            }).cache({ ttl: 300, key: `user_analysis_count_${userId}` });

            const limits = this.getUserLimits(req.user.accountType);
            if (userAnalysisCount >= limits.maxAnalyses) {
                return next(new AppError(`Analysis limit reached (${limits.maxAnalyses})`, 403));
            }

            const duplicateData = originalAnalysis.toObject();
            delete duplicateData._id;
            delete duplicateData.createdAt;
            delete duplicateData.updatedAt;
            delete duplicateData.analytics;

            duplicateData.title = title || `${originalAnalysis.title} (Copy)`;
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

            const duplicate = new Analysis(duplicateData);
            await duplicate.save({ session });

            if (duplicate.settings?.autoBackup) {
                this.analysisService.createBackup(duplicate._id, 'duplicate', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for duplicate ${duplicate._id}:`, err));
            }

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('analysis.duplicated', { userId });
            logger.info(`Analysis ${id} duplicated as ${duplicate._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Analysis duplicated successfully',
                data: {
                    originalId: id,
                    duplicateId: duplicate._id,
                    title: duplicate.title,
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Analysis duplication failed for ${id}:`, error);
            metricsCollector.increment('analysis.duplicate_failed', { userId });
            return next(new AppError('Failed to duplicate analysis', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Verify analysis
     * POST /api/v1/analyses/:userId/:id/verify
     */
    verifyAnalysis = catchAsync(async (req, res, next) => {
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

            const analysis = await Analysis.findOne({ _id: id, userId }).session(session);
            if (!analysis) {
                return next(new AppError('Analysis not found', 404));
            }

            const verificationResult = await this.processExternalVerification(analysis._id, requestingUserId);
            if (!verificationResult.success) {
                return next(new AppError('Verification failed: ' + verificationResult.message, 424));
            }

            analysis.verification = {
                status: verificationResult.status,
                confidence: verificationResult.confidence,
                verifiedBy: verificationResult.verifiedBy,
                verifiedAt: new Date(),
                details: verificationResult.details,
            };

            await analysis.save({ session });

            this.notificationService.notifyUser(userId, {
                type: 'verification_completed',
                message: `Analysis "${analysis.title}" verification ${verificationResult.status}`,
                data: { analysisId: id },
            }).catch((err) => logger.error(`Notification failed for analysis ${id}:`, err));

            await cacheService.deletePattern(`analysis:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('analysis.verified', {
                userId,
                status: verificationResult.status,
            });
            logger.info(`Analysis ${id} verified in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Analysis verification completed',
                data: analysis.verification,
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Verification failed for analysis ${id}:`, error);
            metricsCollector.increment('analysis.verify_failed', { userId });
            if (error.message.includes('timeout')) {
                return next(new AppError('External API timeout', 503));
            }
            return next(new AppError('Failed to verify analysis', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Upload media for analysis
     * POST /api/v1/analyses/:userId/:id/media
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

            const analysis = await Analysis.findOne({ _id: id, userId }).session(session);
            if (!analysis) {
                return next(new AppError('Analysis not found', 404));
            }

            const validation = this.validateMediaUpload(files, analysis.media);
            if (!validation.valid) {
                return next(new AppError(validation.message, 422));
            }

            const mediaResults = await this.mediaService.uploadMedia({
                files,
                entityId: id,
                entityType: 'analysis',
                userId,
            }, { session });

            const scanResults = await this.mediaService.scanMedia(mediaResults);
            if (scanResults.some((result) => result.infected)) {
                return next(new AppError('Media upload failed: Infected file detected', 422));
            }

            analysis.media.push(...mediaResults);
            await analysis.save({ session });

            await cacheService.deletePattern(`analysis:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('analysis.media_uploaded', {
                userId,
                count: mediaResults.length,
            });
            logger.info(`Uploaded ${mediaResults.length} media files for analysis ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Media uploaded successfully',
                data: { media: mediaResults },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Media upload failed for analysis ${id}:`, error);
            metricsCollector.increment('analysis.media_upload_failed', { userId });
            return next(new AppError('Failed to upload media', 422));
        } finally {
            session.endSession();
        }
    });

    /**
     * Share analysis
     * POST /api/v1/analyses/:userId/:id/share
     */
    shareAnalysis = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { platform } = req.body;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const analysis = await Analysis.findOne({ _id: id, userId }).session(session);
            if (!analysis) {
                return next(new AppError('Analysis not found', 404));
            }

            const hasAccess = this.checkAnalysisAccess(analysis, requestingUserId, req.user.isAdmin);
            if (!hasAccess) {
                return next(new AppError('Access denied', 403));
            }

            const shareLink = this.generateShareableLink(analysis, platform);

            analysis.analytics.shares = analysis.analytics.shares || { total: 0, byPlatform: {} };
            analysis.analytics.shares.total += 1;
            analysis.analytics.shares.byPlatform[platform] = (analysis.analytics.shares.byPlatform[platform] || 0) + 1;
            await analysis.save({ session });

            await cacheService.deletePattern(`analysis:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('analysis.shared', { userId, platform });
            logger.info(`Analysis ${id} shared on ${platform} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Analysis shared successfully',
                data: { shareLink },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Share failed for analysis ${id}:`, error);
            metricsCollector.increment('analysis.share_failed', { userId });
            return next(new AppError('Failed to share analysis', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Endorse analysis
     * POST /api/v1/analyses/:userId/:id/endorse
     */
    endorseAnalysis = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const analysis = await Analysis.findOne({ _id: id, userId }).session(session);
            if (!analysis) {
                return next(new AppError('Analysis not found', 404));
            }

            const isConnected = await this.analysisService.checkConnectionLevel(userId, requestingUserId);
            if (!isConnected) {
                return next(new AppError('Must be connected to endorse', 403));
            }

            if (analysis.endorsements.some((e) => e.userId.toString() === requestingUserId)) {
                return next(new AppError('Analysis already endorsed by this user', 409));
            }

            analysis.endorsements.push({
                userId: requestingUserId,
                endorsedAt: new Date(),
            });
            await analysis.save({ session });

            this.notificationService.notifyUser(userId, {
                type: 'endorsement',
                message: `Your analysis "${analysis.title}" was endorsed`,
                data: { analysisId: id, endorserId: requestingUserId },
            }).catch((err) => logger.error(`Notification failed for endorsement ${id}:`, err));

            await cacheService.deletePattern(`analysis:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('analysis.endorsed', { userId, endorserId: requestingUserId });
            logger.info(`Analysis ${id} endorsed in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Analysis endorsed successfully',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Endorsement failed for analysis ${id}:`, error);
            metricsCollector.increment('analysis.endorse_failed', { userId });
            return next(new AppError('Failed to endorse analysis', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get verification status
     * GET /api/v1/analyses/:userId/:id/verification
     */
    getVerificationStatus = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        try {
            const cacheKey = `verification:analysis:${id}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('analysis.verification_cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const analysis = await Analysis.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('verification')
                .cache({ ttl: 60, key: cacheKey });

            if (!analysis) {
                return next(new AppError('Analysis not found', 404));
            }

            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('analysis.verification_viewed', { userId });
            logger.info(`Fetched verification status for analysis ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                data: analysis.verification,
            });
        } catch (error) {
            logger.error(`Verification status fetch failed for ${id}:`, error);
            metricsCollector.increment('analysis.verification_fetch_failed', { userId });
            return next(new AppError('Failed to fetch verification status', 500));
        }
    });

    /**
     * Get trending analyses
     * GET /api/v1/analyses/trending
     */
    getTrendingAnalyses = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { timeframe = '7d', category, limit = 20 } = req.query;

        const cacheKey = `trending:analyses:${timeframe}:${category || 'all'}:${limit}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('analysis.trending_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const analyses = await this.analysisService.getTrendingAnalyses(timeframe, category, parseInt(limit));
            const processedAnalyses = await Promise.all(
                analyses.map((analysis) => this.processAnalysisData(analysis, false)),
            );

            const result = { analyses: processedAnalyses };
            await cacheService.set(cacheKey, result, 3600);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('analysis.trending_viewed', { count: analyses.length });
            logger.info(`Fetched ${analyses.length} trending analyses in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch trending analyses:`, error);
            metricsCollector.increment('analysis.trending_fetch_failed');
            return next(new AppError('Failed to fetch trending analyses', 500));
        }
    });

    /**
     * Get analyses by category
     * GET /api/v1/analyses/categories/:category
     */
    getAnalysesByCategory = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { category } = req.params;
        const { page = 1, limit = 20, sortBy = 'recent' } = req.query;

        const cacheKey = `analyses:category:${category}:${page}:${limit}:${sortBy}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('analysis.category_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const query = this.buildAnalysisQuery({ category });
            const sortOption = this.buildSortOption(sortBy);
            const pageNum = Math.max(1, parseInt(page));
            const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
            const skip = (pageNum - 1) * limitNum;

            const [analyses, totalCount] = await Promise.all([
                Analysis.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select(this.getSelectFields(false))
                    .lean(),
                Analysis.countDocuments(query).cache({ ttl: 300, key: `analysis_category_count_${category}` }),
            ]);

            const processedAnalyses = await Promise.all(
                analyses.map((analysis) => this.processAnalysisData(analysis, false)),
            );

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                analyses: processedAnalyses,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages,
                },
            };

            await cacheService.set(cacheKey, result, 1800);
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('analysis.category_viewed', { category, count: analyses.length });
            logger.info(`Fetched ${analyses.length} analyses for category ${category} in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch analyses for category ${category}:`, error);
            metricsCollector.increment('analysis.category_fetch_failed', { category });
            return next(new AppError('Failed to fetch analyses by category', 500));
        }
    });

    /**
     * Search analyses
     * GET /api/v1/analyses/search
     */
    searchAnalyses = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { query, page = 1, limit = 20, filters = {} } = req.query;

        const cacheKey = `search:analyses:${query}:${JSON.stringify(filters)}:${page}:${limit}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('analysis.search_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const searchResults = await this.analysisService.searchAnalyses(query, filters, {
                page: parseInt(page),
                limit: parseInt(limit),
            });

            const result = {
                analyses: searchResults.hits,
                totalCount: searchResults.total,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    totalPages: Math.ceil(searchResults.total / parseInt(limit)),
                },
            };

            await cacheService.set(cacheKey, result, 300);
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('analysis.searched', { query, count: searchResults.hits.length });
            logger.info(`Search returned ${searchResults.hits.length} analyses in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Search failed for query ${query}:`, error);
            metricsCollector.increment('analysis.search_failed');
            return next(new AppError('Failed to search analyses', 500));
        }
    });

    /**
     * Export analyses as CSV
     * GET /api/v1/analyses/:userId/export
     */
    exportAnalyses = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { format = 'csv', fields = 'title,description,category' } = req.query;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        try {
            const analyses = await Analysis.find({ userId, 'status.isDeleted': false })
                .read('secondaryPreferred')
                .select(fields.split(',').join(' '))
                .lean();

            const csvData = this.convertToCSV(analyses, fields.split(','));
            const filename = `analyses_${userId}_${Date.now()}.csv`;

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('analysis.exported', { userId, format });
            logger.info(`Exported ${analyses.length} analyses for user ${userId} in ${responseTime}ms`);

            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            return res.send(csvData);
        } catch (error) {
            logger.error(`Export failed for user ${userId}:`, error);
            metricsCollector.increment('analysis.export_failed', { userId });
            return next(new AppError('Failed to export analyses', 500));
        }
    });

    // Helper Methods

    async processNewAnalysisAsync(analysisId, userId) {
        try {
            const session = await mongoose.startSession();
            session.startTransaction();

            const analysis = await Analysis.findById(analysisId).session(session);
            if (!analysis) {
                await session.abortTransaction();
                session.endSession();
                return;
            }

            const skillsExtracted = await this.analysisService.extractSkills(analysis.description);
            analysis.skills = skillsExtracted.slice(0, 20);

            await analysis.calculateQualityScore({ session });

            await this.processExternalVerification(analysisId, userId);

            await this.analysisService.indexForSearch(analysis);

            await this.analysisService.updateUserStats(userId, { session });

            await analysis.save({ session });
            await session.commitTransaction();
            logger.info(`Async processing completed for analysis ${analysisId}`);
        } catch (error) {
            logger.error(`Async processing failed for analysis ${analysisId}:`, error);
        } finally {
            session.endSession();
        }
    }

    checkAnalysisAccess(analysis, requestingUserId, isAdmin) {
        if (isAdmin) return true;
        if (analysis.userId.toString() === requestingUserId) return true;
        if (analysis.visibility === 'public') return true;
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

    processAnalyticsData(analysis, timeframe, metrics) {
        const analytics = analysis.analytics || {};
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
            endorsements: analysis.endorsements?.length || 0,
        };

        if (metrics === 'detailed') {
            filteredAnalytics.verification = analysis.verification;
        }

        return filteredAnalytics;
    }

    getUserLimits(accountType) {
        const limits = {
            free: { maxAnalyses: 20, maxMedia: 5, maxSizeMB: 50 },
            premium: { maxAnalyses: 100, maxMedia: 20, maxSizeMB: 200 },
            enterprise: { maxAnalyses: 500, maxMedia: 50, maxSizeMB: 500 },
        };
        return limits[accountType] || limits.free;
    }

    buildAnalysisQuery({ userId, status, category, search, tags }) {
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

    async processAnalysisData(analysis, includeAnalytics = false, includeVerification = false) {
        const processed = { ...analysis };

        if (!includeAnalytics) {
            delete processed.analytics;
        }
        if (!includeVerification) {
            delete processed.verification;
        }

        return processed;
    }

    calculateTrendingScore(analysis) {
        const viewsWeight = 0.4;
        const sharesWeight = 0.3;
        const endorsementsWeight = 0.2;
        const recencyWeight = 0.1;

        const daysSinceCreated = (Date.now() - new Date(analysis.createdAt)) / (1000 * 60 * 60 * 24);
        const recencyScore = Math.max(0, 10 - daysSinceCreated);

        return (
            (analysis.analytics.viewCount * viewsWeight) +
            ((analysis.analytics.shares?.total || 0) * sharesWeight) +
            (analysis.endorsements.length * endorsementsWeight) +
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

    async processExternalVerification(analysisId, userId) {
        try {
            const analysis = await Analysis.findById(analysisId);
            const result = await this.verificationService.verifyAnalysis({
                analysisId,
                userId,
                title: analysis.title,
                category: analysis.category,
            });

            return result;
        } catch (error) {
            logger.error(`External verification failed for analysis ${analysisId}:`, error);
            return { success: false, message: error.message };
        }
    }

    generateShareableLink(analysis, platform) {
        const baseUrl = process.env.APP_URL || 'https://app.example.com';
        return `${baseUrl}/analyses/${analysis._id}/share?platform=${platform}`;
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
                message = 'Analyses moved to trash';
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
                message = 'Analyses archived';
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
                message = 'Analyses published';
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

        const result = await Analysis.updateMany(query, updateData, options);
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

export default new AnalysisController();