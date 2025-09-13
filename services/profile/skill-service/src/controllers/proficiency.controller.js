import Proficiency from '../models/Proficiency.js';
import ProficiencyService from '../services/ProficiencyService.js';
import VerificationService from '../services/VerificationService.js';
import MediaService from '../services/MediaService.js';
import NotificationService from '../services/NotificationService.js';
import { validateProficiency, sanitizeInput } from '../validations/proficiency.validation.js';
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
const createProficiencyLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 15, // 15 creates per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_proficiency_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const updateProficiencyLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 25, // 25 updates per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_proficiency_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const verificationLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 5, // 5 verification requests per 30 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `verify_proficiency_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const bulkOperationsLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // 3 bulk operations per hour
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_proficiency_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const mediaUploadLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 10, // 10 media uploads per 10 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `media_proficiency_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

class ProficiencyController {
    constructor() {
        this.proficiencyService = new ProficiencyService();
        this.verificationService = new VerificationService();
        this.mediaService = new MediaService();
        this.notificationService = new NotificationService();
    }

    /**
     * Create a new proficiency
     * POST /api/v1/proficiencies/:userId
     */
    createProficiency = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const proficiencyData = req.body;
        const requestingUserId = req.user.id;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied: Cannot create proficiency for another user', 403));
        }

        await createProficiencyLimiter(req, res, () => { });

        const validation = validateProficiency(proficiencyData);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        const sanitizedData = sanitizeInput(proficiencyData);

        const userProficiencyCount = await Proficiency.countDocuments({
            userId,
            'status.isDeleted': false,
        }).cache({ ttl: 300, key: `user_proficiency_count_${userId}` });

        const limits = this.getUserLimits(req.user.accountType);
        if (userProficiencyCount >= limits.maxProficiencies) {
            return next(new AppError(`Proficiency limit reached (${limits.maxProficiencies})`, 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const proficiency = await this.proficiencyService.createProficiency({
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

            this.processNewProficiencyAsync(proficiency._id, requestingUserId)
                .catch((err) => logger.error(`Async processing failed for proficiency ${proficiency._id}:`, err));

            metricsCollector.increment('proficiency.created', {
                userId,
                category: proficiency.category,
            });

            eventEmitter.emit('proficiency.created', {
                proficiencyId: proficiency._id,
                userId,
                category: proficiency.category,
            });

            if (proficiency.settings?.autoBackup) {
                this.proficiencyService.createBackup(proficiency._id, 'create', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for proficiency ${proficiency._id}:`, err));
            }

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`Proficiency created successfully: ${proficiency._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Proficiency created successfully',
                data: {
                    id: proficiency._id,
                    userId: proficiency.userId,
                    name: proficiency.name,
                    status: proficiency.status,
                    createdAt: proficiency.createdAt,
                    processingStatus: 'started',
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Proficiency creation failed for user ${userId}:`, error);
            metricsCollector.increment('proficiency.create_failed', { userId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.code === 11000) {
                return next(new AppError('Proficiency with this name already exists', 409));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out', 504));
            }
            return next(new AppError('Failed to create proficiency', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get user's proficiencies with filtering and pagination
     * GET /api/v1/proficiencies/:userId
     */
    getProficiencies = catchAsync(async (req, res, next) => {
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

        const query = this.buildProficiencyQuery({
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

        const cacheKey = `proficiencies:${userId}:${JSON.stringify({
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
                metricsCollector.increment('proficiency.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const [proficiencies, totalCount] = await Promise.all([
                Proficiency.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select(this.getSelectFields(includeAnalytics === 'true'))
                    .lean(),
                Proficiency.countDocuments(query).cache({ ttl: 300, key: `proficiency_count_${userId}` }),
            ]);

            const processedProficiencies = await Promise.all(
                proficiencies.map((proficiency) => this.processProficiencyData(proficiency, includeAnalytics === 'true')),
            );

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                proficiencies: processedProficiencies,
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
            metricsCollector.increment('proficiency.fetched', {
                userId,
                count: proficiencies.length,
                cached: false,
            });
            logger.info(`Fetched ${proficiencies.length} proficiencies for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch proficiencies for user ${userId}:`, error);
            metricsCollector.increment('proficiency.fetch_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid query parameters', 400));
            }
            return next(new AppError('Failed to fetch proficiencies', 500));
        }
    });

    /**
     * Get single proficiency by ID
     * GET /api/v1/proficiencies/:userId/:id
     */
    getProficiencyById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { includeAnalytics = 'false', includeVerification = 'false' } = req.query;

        try {
            const cacheKey = `proficiency:${id}:${userId}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('proficiency.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const proficiency = await Proficiency.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .cache({ ttl: 600, key: cacheKey });

            if (!proficiency) {
                return next(new AppError('Proficiency not found', 404));
            }

            const hasAccess = this.checkProficiencyAccess(proficiency, requestingUserId, req.user.isAdmin);
            if (!hasAccess) {
                return next(new AppError('Access denied', 403));
            }

            if (requestingUserId !== userId) {
                proficiency.analytics.viewCount += 1;
                proficiency.analytics.lastViewed = new Date();
                await proficiency.save();
            }

            const responseData = this.processProficiencyData(proficiency.toObject(), includeAnalytics === 'true', includeVerification === 'true');

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('proficiency.viewed', {
                userId,
                viewerId: requestingUserId,
                isOwner: userId === requestingUserId,
            });
            logger.info(`Fetched proficiency ${id} for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: responseData });
        } catch (error) {
            logger.error(`Failed to fetch proficiency ${id}:`, error);
            metricsCollector.increment('proficiency.view_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid proficiency ID', 400));
            }
            return next(new AppError('Failed to fetch proficiency', 500));
        }
    });

    /**
     * Update proficiency
     * PUT /api/v1/proficiencies/:userId/:id
     */
    updateProficiency = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const updates = req.body;

        await updateProficiencyLimiter(req, res, () => { });

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const proficiency = await Proficiency.findOne({ _id: id, userId }).session(session);
            if (!proficiency) {
                return next(new AppError('Proficiency not found', 404));
            }

            const allowedUpdates = this.getAllowedUpdateFields();
            const sanitizedUpdates = this.sanitizeUpdates(updates, allowedUpdates);

            if (Object.keys(sanitizedUpdates).length === 0) {
                return next(new AppError('No valid update fields provided', 400));
            }

            let versionCreated = false;
            if (sanitizedUpdates.description && sanitizedUpdates.description !== proficiency.description) {
                await proficiency.createVersion(sanitizedUpdates.description, sanitizedUpdates.name || proficiency.name, 'edit', {
                    userId: requestingUserId,
                }, { session });
                versionCreated = true;
            }

            Object.assign(proficiency, sanitizedUpdates);

            proficiency.metadata.lastModifiedBy = {
                userId: requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date(),
            };

            if (sanitizedUpdates.level || sanitizedUpdates.category) {
                proficiency.verification.status = 'pending';
                this.processExternalVerification(proficiency._id, requestingUserId)
                    .catch((err) => logger.error(`Re-verification failed for proficiency ${id}:`, err));
            }

            await proficiency.save({ session });

            if (sanitizedUpdates.description) {
                await proficiency.calculateQualityScore({ session });
            }

            if (proficiency.settings?.autoBackup) {
                this.proficiencyService.createBackup(proficiency._id, 'update', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for proficiency ${id}:`, err));
            }

            await cacheService.deletePattern(`proficiency:${id}:*`);
            await cacheService.deletePattern(`proficiencies:${userId}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('proficiency.updated', {
                userId,
                versionCreated,
                fieldsUpdated: Object.keys(sanitizedUpdates).length,
            });

            eventEmitter.emit('proficiency.updated', {
                proficiencyId: proficiency._id,
                userId,
                changes: Object.keys(sanitizedUpdates),
                versionCreated,
            });

            logger.info(`Proficiency updated successfully: ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Proficiency updated successfully',
                data: {
                    id: proficiency._id,
                    name: proficiency.name,
                    status: proficiency.status,
                    updatedAt: proficiency.updatedAt,
                    versionCreated,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Proficiency update failed for ${id}:`, error);
            metricsCollector.increment('proficiency.update_failed', { userId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out', 504));
            }
            return next(new AppError('Failed to update proficiency', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete proficiency (soft or permanent)
     * DELETE /api/v1/proficiencies/:userId/:id
     */
    deleteProficiency = catchAsync(async (req, res, next) => {
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

            const proficiency = await Proficiency.findOne({ _id: id, userId }).session(session);
            if (!proficiency) {
                return next(new AppError('Proficiency not found', 404));
            }

            if (permanent === 'true') {
                await Proficiency.findByIdAndDelete(id, { session });
                await this.mediaService.deleteAllMedia(id, 'proficiency', { session });
                this.proficiencyService.deleteAllBackups(id)
                    .catch((err) => logger.error(`Failed to delete backups for ${id}:`, err));
                metricsCollector.increment('proficiency.permanently_deleted', { userId });
            } else {
                proficiency.status.isDeleted = true;
                proficiency.status.deletedAt = new Date();
                proficiency.metadata.lastModifiedBy = {
                    userId: requestingUserId,
                    ip: req.ip,
                    userAgent: req.get('User-Agent'),
                    timestamp: new Date(),
                };
                await proficiency.save({ session });
                metricsCollector.increment('proficiency.soft_deleted', { userId });
            }

            await cacheService.deletePattern(`proficiency:${id}:*`);
            await cacheService.deletePattern(`proficiencies:${userId}:*`);

            eventEmitter.emit('proficiency.deleted', {
                proficiencyId: id,
                userId,
                permanent: permanent === 'true',
            });

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`Proficiency ${id} deleted (permanent: ${permanent}) in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: permanent === 'true' ? 'Proficiency permanently deleted' : 'Proficiency moved to trash',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Proficiency deletion failed for ${id}:`, error);
            metricsCollector.increment('proficiency.delete_failed', { userId });
            return next(new AppError('Failed to delete proficiency', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Bulk operations on proficiencies
     * POST /api/v1/proficiencies/:userId/bulk
     */
    bulkOperations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { operation, proficiencyIds, data = {} } = req.body;

        await bulkOperationsLimiter(req, res, () => { });

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        if (!Array.isArray(proficiencyIds) || proficiencyIds.length === 0) {
            return next(new AppError('Proficiency IDs array is required', 400));
        }
        if (proficiencyIds.length > 100) {
            return next(new AppError('Maximum 100 proficiencies can be processed at once', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const query = { _id: { $in: proficiencyIds }, userId };
            const { message } = await this.handleBulkOperation(operation, query, data, requestingUserId, req, { session });

            await Promise.all([
                cacheService.deletePattern(`proficiencies:${userId}:*`),
                ...proficiencyIds.map((id) => cacheService.deletePattern(`proficiency:${id}:*`)),
            ]);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('proficiency.bulk_operation', {
                userId,
                operation,
                count: proficiencyIds.length,
            });
            logger.info(`Bulk operation ${operation} completed for ${proficiencyIds.length} proficiencies in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message,
                data: {
                    operation,
                    requested: proficiencyIds.length,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk operation failed for user ${userId}:`, error);
            metricsCollector.increment('proficiency.bulk_operation_failed', { userId, operation });
            return next(new AppError('Bulk operation failed', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get proficiency analytics
     * GET /api/v1/proficiencies/:userId/:id/analytics
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
            const cacheKey = `analytics:proficiency:${id}:${timeframe}:${metrics}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('proficiency.analytics_cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const proficiency = await Proficiency.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('analytics verification metadata createdAt')
                .cache({ ttl: 900, key: cacheKey });

            if (!proficiency) {
                return next(new AppError('Proficiency not found', 404));
            }

            const analytics = this.processAnalyticsData(proficiency, timeframe, metrics);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('proficiency.analytics_viewed', { userId });
            logger.info(`Fetched analytics for proficiency ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: analytics });
        } catch (error) {
            logger.error(`Analytics fetch failed for ${id}:`, error);
            metricsCollector.increment('proficiency.analytics_fetch_failed', { userId });
            return next(new AppError('Failed to fetch analytics', 500));
        }
    });

    /**
     * Duplicate proficiency
     * POST /api/v1/proficiencies/:userId/:id/duplicate
     */
    duplicateProficiency = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { name, includeVersions = 'false' } = req.body;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const originalProficiency = await Proficiency.findOne({ _id: id, userId }).session(session);
            if (!originalProficiency) {
                return next(new AppError('Proficiency not found', 404));
            }

            const userProficiencyCount = await Proficiency.countDocuments({
                userId,
                'status.isDeleted': false,
            }).cache({ ttl: 300, key: `user_proficiency_count_${userId}` });

            const limits = this.getUserLimits(req.user.accountType);
            if (userProficiencyCount >= limits.maxProficiencies) {
                return next(new AppError(`Proficiency limit reached (${limits.maxProficiencies})`, 403));
            }

            const duplicateData = originalProficiency.toObject();
            delete duplicateData._id;
            delete duplicateData.createdAt;
            delete duplicateData.updatedAt;
            delete duplicateData.analytics;

            duplicateData.name = name || `${originalProficiency.name} (Copy)`;
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
                    name: duplicateData.name,
                    changeType: 'create',
                    isActive: true,
                }];
            }

            const duplicate = new Proficiency(duplicateData);
            await duplicate.save({ session });

            if (duplicate.settings?.autoBackup) {
                this.proficiencyService.createBackup(duplicate._id, 'duplicate', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for duplicate ${duplicate._id}:`, err));
            }

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('proficiency.duplicated', { userId });
            logger.info(`Proficiency ${id} duplicated as ${duplicate._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Proficiency duplicated successfully',
                data: {
                    originalId: id,
                    duplicateId: duplicate._id,
                    name: duplicate.name,
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Proficiency duplication failed for ${id}:`, error);
            metricsCollector.increment('proficiency.duplicate_failed', { userId });
            return next(new AppError('Failed to duplicate proficiency', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Verify proficiency
     * POST /api/v1/proficiencies/:userId/:id/verify
     */
    verifyProficiency = catchAsync(async (req, res, next) => {
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

            const proficiency = await Proficiency.findOne({ _id: id, userId }).session(session);
            if (!proficiency) {
                return next(new AppError('Proficiency not found', 404));
            }

            const verificationResult = await this.processExternalVerification(proficiency._id, requestingUserId);
            if (!verificationResult.success) {
                return next(new AppError('Verification failed: ' + verificationResult.message, 424));
            }

            proficiency.verification = {
                status: verificationResult.status,
                confidence: verificationResult.confidence,
                verifiedBy: verificationResult.verifiedBy,
                verifiedAt: new Date(),
                details: verificationResult.details,
            };

            await proficiency.save({ session });

            this.notificationService.notifyUser(userId, {
                type: 'verification_completed',
                message: `Proficiency "${proficiency.name}" verification ${verificationResult.status}`,
                data: { proficiencyId: id },
            }).catch((err) => logger.error(`Notification failed for proficiency ${id}:`, err));

            await cacheService.deletePattern(`proficiency:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('proficiency.verified', {
                userId,
                status: verificationResult.status,
            });
            logger.info(`Proficiency ${id} verified in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Proficiency verification completed',
                data: proficiency.verification,
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Verification failed for proficiency ${id}:`, error);
            metricsCollector.increment('proficiency.verify_failed', { userId });
            if (error.message.includes('timeout')) {
                return next(new AppError('External API timeout', 503));
            }
            return next(new AppError('Failed to verify proficiency', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Upload media for proficiency
     * POST /api/v1/proficiencies/:userId/:id/media
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

            const proficiency = await Proficiency.findOne({ _id: id, userId }).session(session);
            if (!proficiency) {
                return next(new AppError('Proficiency not found', 404));
            }

            const validation = this.validateMediaUpload(files, proficiency.media);
            if (!validation.valid) {
                return next(new AppError(validation.message, 422));
            }

            const mediaResults = await this.mediaService.uploadMedia({
                files,
                entityId: id,
                entityType: 'proficiency',
                userId,
            }, { session });

            const scanResults = await this.mediaService.scanMedia(mediaResults);
            if (scanResults.some((result) => result.infected)) {
                return next(new AppError('Media upload failed: Infected file detected', 422));
            }

            proficiency.media.push(...mediaResults);
            await proficiency.save({ session });

            await cacheService.deletePattern(`proficiency:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('proficiency.media_uploaded', {
                userId,
                count: mediaResults.length,
            });
            logger.info(`Uploaded ${mediaResults.length} media files for proficiency ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Media uploaded successfully',
                data: { media: mediaResults },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Media upload failed for proficiency ${id}:`, error);
            metricsCollector.increment('proficiency.media_upload_failed', { userId });
            return next(new AppError('Failed to upload media', 422));
        } finally {
            session.endSession();
        }
    });

    /**
     * Share proficiency
     * POST /api/v1/proficiencies/:userId/:id/share
     */
    shareProficiency = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { platform } = req.body;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const proficiency = await Proficiency.findOne({ _id: id, userId }).session(session);
            if (!proficiency) {
                return next(new AppError('Proficiency not found', 404));
            }

            const hasAccess = this.checkProficiencyAccess(proficiency, requestingUserId, req.user.isAdmin);
            if (!hasAccess) {
                return next(new AppError('Access denied', 403));
            }

            const shareLink = this.generateShareableLink(proficiency, platform);

            proficiency.analytics.shares = proficiency.analytics.shares || { total: 0, byPlatform: {} };
            proficiency.analytics.shares.total += 1;
            proficiency.analytics.shares.byPlatform[platform] = (proficiency.analytics.shares.byPlatform[platform] || 0) + 1;
            await proficiency.save({ session });

            await cacheService.deletePattern(`proficiency:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('proficiency.shared', { userId, platform });
            logger.info(`Proficiency ${id} shared on ${platform} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Proficiency shared successfully',
                data: { shareLink },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Share failed for proficiency ${id}:`, error);
            metricsCollector.increment('proficiency.share_failed', { userId });
            return next(new AppError('Failed to share proficiency', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Endorse proficiency
     * POST /api/v1/proficiencies/:userId/:id/endorse
     */
    endorseProficiency = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const proficiency = await Proficiency.findOne({ _id: id, userId }).session(session);
            if (!proficiency) {
                return next(new AppError('Proficiency not found', 404));
            }

            const isConnected = await this.proficiencyService.checkConnectionLevel(userId, requestingUserId);
            if (!isConnected) {
                return next(new AppError('Must be connected to endorse', 403));
            }

            if (proficiency.endorsements.some((e) => e.userId.toString() === requestingUserId)) {
                return next(new AppError('Proficiency already endorsed by this user', 409));
            }

            proficiency.endorsements.push({
                userId: requestingUserId,
                endorsedAt: new Date(),
            });
            await proficiency.save({ session });

            this.notificationService.notifyUser(userId, {
                type: 'endorsement',
                message: `Your proficiency "${proficiency.name}" was endorsed`,
                data: { proficiencyId: id, endorserId: requestingUserId },
            }).catch((err) => logger.error(`Notification failed for endorsement ${id}:`, err));

            await cacheService.deletePattern(`proficiency:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('proficiency.endorsed', { userId, endorserId: requestingUserId });
            logger.info(`Proficiency ${id} endorsed in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Proficiency endorsed successfully',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Endorsement failed for proficiency ${id}:`, error);
            metricsCollector.increment('proficiency.endorse_failed', { userId });
            return next(new AppError('Failed to endorse proficiency', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get verification status
     * GET /api/v1/proficiencies/:userId/:id/verification
     */
    getVerificationStatus = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        try {
            const cacheKey = `verification:proficiency:${id}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('proficiency.verification_cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const proficiency = await Proficiency.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('verification')
                .cache({ ttl: 60, key: cacheKey });

            if (!proficiency) {
                return next(new AppError('Proficiency not found', 404));
            }

            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('proficiency.verification_viewed', { userId });
            logger.info(`Fetched verification status for proficiency ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                data: proficiency.verification,
            });
        } catch (error) {
            logger.error(`Verification status fetch failed for ${id}:`, error);
            metricsCollector.increment('proficiency.verification_fetch_failed', { userId });
            return next(new AppError('Failed to fetch verification status', 500));
        }
    });

    /**
     * Get trending proficiencies
     * GET /api/v1/proficiencies/trending
     */
    getTrendingProficiencies = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { timeframe = '7d', category, limit = 20 } = req.query;

        const cacheKey = `trending:proficiencies:${timeframe}:${category || 'all'}:${limit}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('proficiency.trending_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const proficiencies = await this.proficiencyService.getTrendingProficiencies(timeframe, category, parseInt(limit));
            const processedProficiencies = await Promise.all(
                proficiencies.map((proficiency) => this.processProficiencyData(proficiency, false)),
            );

            const result = { proficiencies: processedProficiencies };
            await cacheService.set(cacheKey, result, 3600);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('proficiency.trending_viewed', { count: proficiencies.length });
            logger.info(`Fetched ${proficiencies.length} trending proficiencies in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch trending proficiencies:`, error);
            metricsCollector.increment('proficiency.trending_fetch_failed');
            return next(new AppError('Failed to fetch trending proficiencies', 500));
        }
    });

    /**
     * Get proficiencies by category
     * GET /api/v1/proficiencies/categories/:category
     */
    getProficienciesByCategory = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { category } = req.params;
        const { page = 1, limit = 20, sortBy = 'recent' } = req.query;

        const cacheKey = `proficiencies:category:${category}:${page}:${limit}:${sortBy}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('proficiency.category_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const query = this.buildProficiencyQuery({ category });
            const sortOption = this.buildSortOption(sortBy);
            const pageNum = Math.max(1, parseInt(page));
            const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
            const skip = (pageNum - 1) * limitNum;

            const [proficiencies, totalCount] = await Promise.all([
                Proficiency.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select(this.getSelectFields(false))
                    .lean(),
                Proficiency.countDocuments(query).cache({ ttl: 300, key: `proficiency_category_count_${category}` }),
            ]);

            const processedProficiencies = await Promise.all(
                proficiencies.map((proficiency) => this.processProficiencyData(proficiency, false)),
            );

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                proficiencies: processedProficiencies,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages,
                },
            };

            await cacheService.set(cacheKey, result, 1800);
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('proficiency.category_viewed', { category, count: proficiencies.length });
            logger.info(`Fetched ${proficiencies.length} proficiencies for category ${category} in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch proficiencies for category ${category}:`, error);
            metricsCollector.increment('proficiency.category_fetch_failed', { category });
            return next(new AppError('Failed to fetch proficiencies by category', 500));
        }
    });

    /**
     * Search proficiencies
     * GET /api/v1/proficiencies/search
     */
    searchProficiencies = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { query, page = 1, limit = 20, filters = {} } = req.query;

        const cacheKey = `search:proficiencies:${query}:${JSON.stringify(filters)}:${page}:${limit}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('proficiency.search_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const searchResults = await this.proficiencyService.searchProficiencies(query, filters, {
                page: parseInt(page),
                limit: parseInt(limit),
            });

            const result = {
                proficiencies: searchResults.hits,
                totalCount: searchResults.total,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    totalPages: Math.ceil(searchResults.total / parseInt(limit)),
                },
            };

            await cacheService.set(cacheKey, result, 300);
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('proficiency.searched', { query, count: searchResults.hits.length });
            logger.info(`Search returned ${searchResults.hits.length} proficiencies in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Search failed for query ${query}:`, error);
            metricsCollector.increment('proficiency.search_failed');
            return next(new AppError('Failed to search proficiencies', 500));
        }
    });

    /**
     * Export proficiencies as CSV
     * GET /api/v1/proficiencies/:userId/export
     */
    exportProficiencies = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { format = 'csv', fields = 'name,description,category,level' } = req.query;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        try {
            const proficiencies = await Proficiency.find({ userId, 'status.isDeleted': false })
                .read('secondaryPreferred')
                .select(fields.split(',').join(' '))
                .lean();

            const csvData = this.convertToCSV(proficiencies, fields.split(','));
            const filename = `proficiencies_${userId}_${Date.now()}.csv`;

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('proficiency.exported', { userId, format });
            logger.info(`Exported ${proficiencies.length} proficiencies for user ${userId} in ${responseTime}ms`);

            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            return res.send(csvData);
        } catch (error) {
            logger.error(`Export failed for user ${userId}:`, error);
            metricsCollector.increment('proficiency.export_failed', { userId });
            return next(new AppError('Failed to export proficiencies', 500));
        }
    });

    // Helper Methods

    async processNewProficiencyAsync(proficiencyId, userId) {
        try {
            const session = await mongoose.startSession();
            session.startTransaction();

            const proficiency = await Proficiency.findById(proficiencyId).session(session);
            if (!proficiency) {
                await session.abortTransaction();
                session.endSession();
                return;
            }

            const skillsExtracted = await this.proficiencyService.extractSkills(proficiency.description);
            proficiency.skills = skillsExtracted.slice(0, 20);

            await proficiency.calculateQualityScore({ session });

            await this.processExternalVerification(proficiencyId, userId);

            await this.proficiencyService.indexForSearch(proficiency);

            await this.proficiencyService.updateUserStats(userId, { session });

            await proficiency.save({ session });
            await session.commitTransaction();
            logger.info(`Async processing completed for proficiency ${proficiencyId}`);
        } catch (error) {
            logger.error(`Async processing failed for proficiency ${proficiencyId}:`, error);
        } finally {
            session.endSession();
        }
    }

    checkProficiencyAccess(proficiency, requestingUserId, isAdmin) {
        if (isAdmin) return true;
        if (proficiency.userId.toString() === requestingUserId) return true;
        if (proficiency.visibility === 'public') return true;
        return false;
    }

    getAllowedUpdateFields() {
        return [
            'name',
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

    processAnalyticsData(proficiency, timeframe, metrics) {
        const analytics = proficiency.analytics || {};
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
            endorsements: proficiency.endorsements?.length || 0,
        };

        if (metrics === 'detailed') {
            filteredAnalytics.verification = proficiency.verification;
        }

        return filteredAnalytics;
    }

    getUserLimits(accountType) {
        const limits = {
            free: { maxProficiencies: 20, maxMedia: 5, maxSizeMB: 50 },
            premium: { maxProficiencies: 100, maxMedia: 20, maxSizeMB: 200 },
            enterprise: { maxProficiencies: 500, maxMedia: 50, maxSizeMB: 500 },
        };
        return limits[accountType] || limits.free;
    }

    buildProficiencyQuery({ userId, status, category, search, level, tags }) {
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
            name: { name: 1 },
            popular: { 'analytics.viewCount': -1 },
            quality: { 'metadata.qualityScore': -1 },
            verified: { 'verification.confidence': -1 },
        };
        return sortOptions[sortBy] || sortOptions.recent;
    }

    getSelectFields(includeAnalytics) {
        const baseFields = 'name description category tags skills level visibility status createdAt updatedAt';
        return includeAnalytics ? baseFields + ' analytics' : baseFields;
    }

    async processProficiencyData(proficiency, includeAnalytics = false, includeVerification = false) {
        const processed = { ...proficiency };

        if (!includeAnalytics) {
            delete processed.analytics;
        }
        if (!includeVerification) {
            delete processed.verification;
        }

        return processed;
    }

    calculateTrendingScore(proficiency) {
        const viewsWeight = 0.4;
        const sharesWeight = 0.3;
        const endorsementsWeight = 0.2;
        const recencyWeight = 0.1;

        const daysSinceCreated = (Date.now() - new Date(proficiency.createdAt)) / (1000 * 60 * 60 * 24);
        const recencyScore = Math.max(0, 10 - daysSinceCreated);

        return (
            (proficiency.analytics.viewCount * viewsWeight) +
            ((proficiency.analytics.shares?.total || 0) * sharesWeight) +
            (proficiency.endorsements.length * endorsementsWeight) +
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

    async processExternalVerification(proficiencyId, userId) {
        try {
            const proficiency = await Proficiency.findById(proficiencyId);
            const result = await this.verificationService.verifyProficiency({
                proficiencyId,
                userId,
                name: proficiency.name,
                level: proficiency.level,
                category: proficiency.category,
            });

            return result;
        } catch (error) {
            logger.error(`External verification failed for proficiency ${proficiencyId}:`, error);
            return { success: false, message: error.message };
        }
    }

    generateShareableLink(proficiency, platform) {
        const baseUrl = process.env.APP_URL || 'https://app.example.com';
        return `${baseUrl}/proficiencies/${proficiency._id}/share?platform=${platform}`;
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
                message = 'Proficiencies moved to trash';
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
                message = 'Proficiencies archived';
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
                message = 'Proficiencies published';
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

        const result = await Proficiency.updateMany(query, updateData, options);
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

export default new ProficiencyController();