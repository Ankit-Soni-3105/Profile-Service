import Synonym from '../models/Synonym.js';
import SynonymService from '../services/SynonymService.js';
import VerificationService from '../services/VerificationService.js';
import NotificationService from '../services/NotificationService.js';
import { validateSynonym, sanitizeInput } from '../validations/synonym.validation.js';
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
const createSynonymLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 20, // 20 creates per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_synonym_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const updateSynonymLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 30, // 30 updates per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_synonym_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const verificationLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 5, // 5 verification requests per 30 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `verify_synonym_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const bulkOperationsLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // 3 bulk operations per hour
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_synonym_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

class SynonymController {
    constructor() {
        this.synonymService = new SynonymService();
        this.verificationService = new VerificationService();
        this.notificationService = new NotificationService();
    }

    /**
     * Create a new synonym
     * POST /api/v1/synonyms/:userId
     */
    createSynonym = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const synonymData = req.body;
        const requestingUserId = req.user.id;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied: Cannot create synonym for another user', 403));
        }

        await createSynonymLimiter(req, res, () => { });

        const validation = validateSynonym(synonymData);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        const sanitizedData = sanitizeInput(synonymData);

        const userSynonymCount = await Synonym.countDocuments({
            userId,
            'status.isDeleted': false,
        }).cache({ ttl: 300, key: `user_synonym_count_${userId}` });

        const limits = this.getUserLimits(req.user.accountType);
        if (userSynonymCount >= limits.maxSynonyms) {
            return next(new AppError(`Synonym limit reached (${limits.maxSynonyms})`, 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const synonym = await this.synonymService.createSynonym({
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

            this.processNewSynonymAsync(synonym._id, requestingUserId)
                .catch((err) => logger.error(`Async processing failed for synonym ${synonym._id}:`, err));

            metricsCollector.increment('synonym.created', {
                userId,
                category: synonym.category,
            });

            eventEmitter.emit('synonym.created', {
                synonymId: synonym._id,
                userId,
                category: synonym.category,
            });

            if (synonym.settings?.autoBackup) {
                this.synonymService.createBackup(synonym._id, 'create', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for synonym ${synonym._id}:`, err));
            }

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`Synonym created successfully: ${synonym._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Synonym created successfully',
                data: {
                    id: synonym._id,
                    userId: synonym.userId,
                    term: synonym.term,
                    status: synonym.status,
                    createdAt: synonym.createdAt,
                    processingStatus: 'started',
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Synonym creation failed for user ${userId}:`, error);
            metricsCollector.increment('synonym.create_failed', { userId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.code === 11000) {
                return next(new AppError('Synonym for this term already exists', 409));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out', 504));
            }
            return next(new AppError('Failed to create synonym', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get user's synonyms with filtering and pagination
     * GET /api/v1/synonyms/:userId
     */
    getSynonyms = catchAsync(async (req, res, next) => {
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

        const query = this.buildSynonymQuery({
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

        const cacheKey = `synonyms:${userId}:${JSON.stringify({
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
                metricsCollector.increment('synonym.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const [synonyms, totalCount] = await Promise.all([
                Synonym.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select(this.getSelectFields(includeAnalytics === 'true'))
                    .lean(),
                Synonym.countDocuments(query).cache({ ttl: 300, key: `synonym_count_${userId}` }),
            ]);

            const processedSynonyms = await Promise.all(
                synonyms.map((synonym) => this.processSynonymData(synonym, includeAnalytics === 'true')),
            );

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                synonyms: processedSynonyms,
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
            metricsCollector.increment('synonym.fetched', {
                userId,
                count: synonyms.length,
                cached: false,
            });
            logger.info(`Fetched ${synonyms.length} synonyms for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch synonyms for user ${userId}:`, error);
            metricsCollector.increment('synonym.fetch_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid query parameters', 400));
            }
            return next(new AppError('Failed to fetch synonyms', 500));
        }
    });

    /**
     * Get single synonym by ID
     * GET /api/v1/synonyms/:userId/:id
     */
    getSynonymById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { includeAnalytics = 'false', includeVerification = 'false' } = req.query;

        try {
            const cacheKey = `synonym:${id}:${userId}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('synonym.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const synonym = await Synonym.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .cache({ ttl: 600, key: cacheKey });

            if (!synonym) {
                return next(new AppError('Synonym not found', 404));
            }

            const hasAccess = this.checkSynonymAccess(synonym, requestingUserId, req.user.isAdmin);
            if (!hasAccess) {
                return next(new AppError('Access denied', 403));
            }

            if (requestingUserId !== userId) {
                synonym.analytics.viewCount += 1;
                synonym.analytics.lastViewed = new Date();
                await synonym.save();
            }

            const responseData = this.processSynonymData(synonym.toObject(), includeAnalytics === 'true', includeVerification === 'true');

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('synonym.viewed', {
                userId,
                viewerId: requestingUserId,
                isOwner: userId === requestingUserId,
            });
            logger.info(`Fetched synonym ${id} for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: responseData });
        } catch (error) {
            logger.error(`Failed to fetch synonym ${id}:`, error);
            metricsCollector.increment('synonym.view_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid synonym ID', 400));
            }
            return next(new AppError('Failed to fetch synonym', 500));
        }
    });

    /**
     * Update synonym
     * PUT /api/v1/synonyms/:userId/:id
     */
    updateSynonym = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const updates = req.body;

        await updateSynonymLimiter(req, res, () => { });

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const synonym = await Synonym.findOne({ _id: id, userId }).session(session);
            if (!synonym) {
                return next(new AppError('Synonym not found', 404));
            }

            const allowedUpdates = this.getAllowedUpdateFields();
            const sanitizedUpdates = this.sanitizeUpdates(updates, allowedUpdates);

            if (Object.keys(sanitizedUpdates).length === 0) {
                return next(new AppError('No valid update fields provided', 400));
            }

            let versionCreated = false;
            if (sanitizedUpdates.synonyms && JSON.stringify(sanitizedUpdates.synonyms) !== JSON.stringify(synonym.synonyms)) {
                await synonym.createVersion(sanitizedUpdates.synonyms, sanitizedUpdates.term || synonym.term, 'edit', {
                    userId: requestingUserId,
                }, { session });
                versionCreated = true;
            }

            Object.assign(synonym, sanitizedUpdates);

            synonym.metadata.lastModifiedBy = {
                userId: requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date(),
            };

            if (sanitizedUpdates.term || sanitizedUpdates.category) {
                synonym.verification.status = 'pending';
                this.processExternalVerification(synonym._id, requestingUserId)
                    .catch((err) => logger.error(`Re-verification failed for synonym ${id}:`, err));
            }

            await synonym.save({ session });

            if (sanitizedUpdates.synonyms) {
                await synonym.calculateQualityScore({ session });
            }

            if (synonym.settings?.autoBackup) {
                this.synonymService.createBackup(synonym._id, 'update', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for synonym ${id}:`, err));
            }

            await cacheService.deletePattern(`synonym:${id}:*`);
            await cacheService.deletePattern(`synonyms:${userId}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('synonym.updated', {
                userId,
                versionCreated,
                fieldsUpdated: Object.keys(sanitizedUpdates).length,
            });

            eventEmitter.emit('synonym.updated', {
                synonymId: synonym._id,
                userId,
                changes: Object.keys(sanitizedUpdates),
                versionCreated,
            });

            logger.info(`Synonym updated successfully: ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Synonym updated successfully',
                data: {
                    id: synonym._id,
                    term: synonym.term,
                    status: synonym.status,
                    updatedAt: synonym.updatedAt,
                    versionCreated,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Synonym update failed for ${id}:`, error);
            metricsCollector.increment('synonym.update_failed', { userId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out', 504));
            }
            return next(new AppError('Failed to update synonym', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete synonym (soft or permanent)
     * DELETE /api/v1/synonyms/:userId/:id
     */
    deleteSynonym = catchAsync(async (req, res, next) => {
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

            const synonym = await Synonym.findOne({ _id: id, userId }).session(session);
            if (!synonym) {
                return next(new AppError('Synonym not found', 404));
            }

            if (permanent === 'true') {
                await Synonym.findByIdAndDelete(id, { session });
                this.synonymService.deleteAllBackups(id)
                    .catch((err) => logger.error(`Failed to delete backups for ${id}:`, err));
                metricsCollector.increment('synonym.permanently_deleted', { userId });
            } else {
                synonym.status.isDeleted = true;
                synonym.status.deletedAt = new Date();
                synonym.metadata.lastModifiedBy = {
                    userId: requestingUserId,
                    ip: req.ip,
                    userAgent: req.get('User-Agent'),
                    timestamp: new Date(),
                };
                await synonym.save({ session });
                metricsCollector.increment('synonym.soft_deleted', { userId });
            }

            await cacheService.deletePattern(`synonym:${id}:*`);
            await cacheService.deletePattern(`synonyms:${userId}:*`);

            eventEmitter.emit('synonym.deleted', {
                synonymId: id,
                userId,
                permanent: permanent === 'true',
            });

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`Synonym ${id} deleted (permanent: ${permanent}) in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: permanent === 'true' ? 'Synonym permanently deleted' : 'Synonym moved to trash',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Synonym deletion failed for ${id}:`, error);
            metricsCollector.increment('synonym.delete_failed', { userId });
            return next(new AppError('Failed to delete synonym', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Bulk operations on synonyms
     * POST /api/v1/synonyms/:userId/bulk
     */
    bulkOperations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { operation, synonymIds, data = {} } = req.body;

        await bulkOperationsLimiter(req, res, () => { });

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        if (!Array.isArray(synonymIds) || synonymIds.length === 0) {
            return next(new AppError('Synonym IDs array is required', 400));
        }
        if (synonymIds.length > 100) {
            return next(new AppError('Maximum 100 synonyms can be processed at once', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const query = { _id: { $in: synonymIds }, userId };
            const { message } = await this.handleBulkOperation(operation, query, data, requestingUserId, req, { session });

            await Promise.all([
                cacheService.deletePattern(`synonyms:${userId}:*`),
                ...synonymIds.map((id) => cacheService.deletePattern(`synonym:${id}:*`)),
            ]);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('synonym.bulk_operation', {
                userId,
                operation,
                count: synonymIds.length,
            });
            logger.info(`Bulk operation ${operation} completed for ${synonymIds.length} synonyms in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message,
                data: {
                    operation,
                    requested: synonymIds.length,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk operation failed for user ${userId}:`, error);
            metricsCollector.increment('synonym.bulk_operation_failed', { userId, operation });
            return next(new AppError('Bulk operation failed', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get synonym analytics
     * GET /api/v1/synonyms/:userId/:id/analytics
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
            const cacheKey = `analytics:synonym:${id}:${timeframe}:${metrics}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('synonym.analytics_cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const synonym = await Synonym.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('analytics verification metadata createdAt')
                .cache({ ttl: 900, key: cacheKey });

            if (!synonym) {
                return next(new AppError('Synonym not found', 404));
            }

            const analytics = this.processAnalyticsData(synonym, timeframe, metrics);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('synonym.analytics_viewed', { userId });
            logger.info(`Fetched analytics for synonym ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: analytics });
        } catch (error) {
            logger.error(`Analytics fetch failed for ${id}:`, error);
            metricsCollector.increment('synonym.analytics_fetch_failed', { userId });
            return next(new AppError('Failed to fetch analytics', 500));
        }
    });

    /**
     * Duplicate synonym
     * POST /api/v1/synonyms/:userId/:id/duplicate
     */
    duplicateSynonym = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { term, includeVersions = 'false' } = req.body;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const originalSynonym = await Synonym.findOne({ _id: id, userId }).session(session);
            if (!originalSynonym) {
                return next(new AppError('Synonym not found', 404));
            }

            const userSynonymCount = await Synonym.countDocuments({
                userId,
                'status.isDeleted': false,
            }).cache({ ttl: 300, key: `user_synonym_count_${userId}` });

            const limits = this.getUserLimits(req.user.accountType);
            if (userSynonymCount >= limits.maxSynonyms) {
                return next(new AppError(`Synonym limit reached (${limits.maxSynonyms})`, 403));
            }

            const duplicateData = originalSynonym.toObject();
            delete duplicateData._id;
            delete duplicateData.createdAt;
            delete duplicateData.updatedAt;
            delete duplicateData.analytics;

            duplicateData.term = term || `${originalSynonym.term} (Copy)`;
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
                    synonyms: duplicateData.synonyms,
                    term: duplicateData.term,
                    changeType: 'create',
                    isActive: true,
                }];
            }

            const duplicate = new Synonym(duplicateData);
            await duplicate.save({ session });

            if (duplicate.settings?.autoBackup) {
                this.synonymService.createBackup(duplicate._id, 'duplicate', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for duplicate ${duplicate._id}:`, err));
            }

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('synonym.duplicated', { userId });
            logger.info(`Synonym ${id} duplicated as ${duplicate._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Synonym duplicated successfully',
                data: {
                    originalId: id,
                    duplicateId: duplicate._id,
                    term: duplicate.term,
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Synonym duplication failed for ${id}:`, error);
            metricsCollector.increment('synonym.duplicate_failed', { userId });
            return next(new AppError('Failed to duplicate synonym', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Verify synonym
     * POST /api/v1/synonyms/:userId/:id/verify
     */
    verifySynonym = catchAsync(async (req, res, next) => {
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

            const synonym = await Synonym.findOne({ _id: id, userId }).session(session);
            if (!synonym) {
                return next(new AppError('Synonym not found', 404));
            }

            const verificationResult = await this.processExternalVerification(synonym._id, requestingUserId);
            if (!verificationResult.success) {
                return next(new AppError('Verification failed: ' + verificationResult.message, 424));
            }

            synonym.verification = {
                status: verificationResult.status,
                confidence: verificationResult.confidence,
                verifiedBy: verificationResult.verifiedBy,
                verifiedAt: new Date(),
                details: verificationResult.details,
            };

            await synonym.save({ session });

            this.notificationService.notifyUser(userId, {
                type: 'verification_completed',
                message: `Synonym "${synonym.term}" verification ${verificationResult.status}`,
                data: { synonymId: id },
            }).catch((err) => logger.error(`Notification failed for synonym ${id}:`, err));

            await cacheService.deletePattern(`synonym:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('synonym.verified', {
                userId,
                status: verificationResult.status,
            });
            logger.info(`Synonym ${id} verified in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Synonym verification completed',
                data: synonym.verification,
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Verification failed for synonym ${id}:`, error);
            metricsCollector.increment('synonym.verify_failed', { userId });
            if (error.message.includes('timeout')) {
                return next(new AppError('External API timeout', 503));
            }
            return next(new AppError('Failed to verify synonym', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Share synonym
     * POST /api/v1/synonyms/:userId/:id/share
     */
    shareSynonym = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { platform } = req.body;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const synonym = await Synonym.findOne({ _id: id, userId }).session(session);
            if (!synonym) {
                return next(new AppError('Synonym not found', 404));
            }

            const hasAccess = this.checkSynonymAccess(synonym, requestingUserId, req.user.isAdmin);
            if (!hasAccess) {
                return next(new AppError('Access denied', 403));
            }

            const shareLink = this.generateShareableLink(synonym, platform);

            synonym.analytics.shares = synonym.analytics.shares || { total: 0, byPlatform: {} };
            synonym.analytics.shares.total += 1;
            synonym.analytics.shares.byPlatform[platform] = (synonym.analytics.shares.byPlatform[platform] || 0) + 1;
            await synonym.save({ session });

            await cacheService.deletePattern(`synonym:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('synonym.shared', { userId, platform });
            logger.info(`Synonym ${id} shared on ${platform} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Synonym shared successfully',
                data: { shareLink },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Share failed for synonym ${id}:`, error);
            metricsCollector.increment('synonym.share_failed', { userId });
            return next(new AppError('Failed to share synonym', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Endorse synonym
     * POST /api/v1/synonyms/:userId/:id/endorse
     */
    endorseSynonym = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const synonym = await Synonym.findOne({ _id: id, userId }).session(session);
            if (!synonym) {
                return next(new AppError('Synonym not found', 404));
            }

            const isConnected = await this.synonymService.checkConnectionLevel(userId, requestingUserId);
            if (!isConnected) {
                return next(new AppError('Must be connected to endorse', 403));
            }

            if (synonym.endorsements.some((e) => e.userId.toString() === requestingUserId)) {
                return next(new AppError('Synonym already endorsed by this user', 409));
            }

            synonym.endorsements.push({
                userId: requestingUserId,
                endorsedAt: new Date(),
            });
            await synonym.save({ session });

            this.notificationService.notifyUser(userId, {
                type: 'endorsement',
                message: `Your synonym "${synonym.term}" was endorsed`,
                data: { synonymId: id, endorserId: requestingUserId },
            }).catch((err) => logger.error(`Notification failed for endorsement ${id}:`, err));

            await cacheService.deletePattern(`synonym:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('synonym.endorsed', { userId, endorserId: requestingUserId });
            logger.info(`Synonym ${id} endorsed in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Synonym endorsed successfully',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Endorsement failed for synonym ${id}:`, error);
            metricsCollector.increment('synonym.endorse_failed', { userId });
            return next(new AppError('Failed to endorse synonym', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get verification status
     * GET /api/v1/synonyms/:userId/:id/verification
     */
    getVerificationStatus = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        try {
            const cacheKey = `verification:synonym:${id}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('synonym.verification_cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const synonym = await Synonym.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('verification')
                .cache({ ttl: 60, key: cacheKey });

            if (!synonym) {
                return next(new AppError('Synonym not found', 404));
            }

            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('synonym.verification_viewed', { userId });
            logger.info(`Fetched verification status for synonym ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                data: synonym.verification,
            });
        } catch (error) {
            logger.error(`Verification status fetch failed for ${id}:`, error);
            metricsCollector.increment('synonym.verification_fetch_failed', { userId });
            return next(new AppError('Failed to fetch verification status', 500));
        }
    });

    /**
     * Get trending synonyms
     * GET /api/v1/synonyms/trending
     */
    getTrendingSynonyms = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { timeframe = '7d', category, limit = 20 } = req.query;

        const cacheKey = `trending:synonyms:${timeframe}:${category || 'all'}:${limit}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('synonym.trending_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const synonyms = await this.synonymService.getTrendingSynonyms(timeframe, category, parseInt(limit));
            const processedSynonyms = await Promise.all(
                synonyms.map((synonym) => this.processSynonymData(synonym, false)),
            );

            const result = { synonyms: processedSynonyms };
            await cacheService.set(cacheKey, result, 3600);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('synonym.trending_viewed', { count: synonyms.length });
            logger.info(`Fetched ${synonyms.length} trending synonyms in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch trending synonyms:`, error);
            metricsCollector.increment('synonym.trending_fetch_failed');
            return next(new AppError('Failed to fetch trending synonyms', 500));
        }
    });

    /**
     * Get synonyms by category
     * GET /api/v1/synonyms/categories/:category
     */
    getSynonymsByCategory = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { category } = req.params;
        const { page = 1, limit = 20, sortBy = 'recent' } = req.query;

        const cacheKey = `synonyms:category:${category}:${page}:${limit}:${sortBy}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('synonym.category_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const query = this.buildSynonymQuery({ category });
            const sortOption = this.buildSortOption(sortBy);
            const pageNum = Math.max(1, parseInt(page));
            const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
            const skip = (pageNum - 1) * limitNum;

            const [synonyms, totalCount] = await Promise.all([
                Synonym.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select(this.getSelectFields(false))
                    .lean(),
                Synonym.countDocuments(query).cache({ ttl: 300, key: `synonym_category_count_${category}` }),
            ]);

            const processedSynonyms = await Promise.all(
                synonyms.map((synonym) => this.processSynonymData(synonym, false)),
            );

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                synonyms: processedSynonyms,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages,
                },
            };

            await cacheService.set(cacheKey, result, 1800);
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('synonym.category_viewed', { category, count: synonyms.length });
            logger.info(`Fetched ${synonyms.length} synonyms for category ${category} in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch synonyms for category ${category}:`, error);
            metricsCollector.increment('synonym.category_fetch_failed', { category });
            return next(new AppError('Failed to fetch synonyms by category', 500));
        }
    });

    /**
     * Search synonyms
     * GET /api/v1/synonyms/search
     */
    searchSynonyms = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { query, page = 1, limit = 20, filters = {} } = req.query;

        const cacheKey = `search:synonyms:${query}:${JSON.stringify(filters)}:${page}:${limit}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('synonym.search_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const searchResults = await this.synonymService.searchSynonyms(query, filters, {
                page: parseInt(page),
                limit: parseInt(limit),
            });

            const result = {
                synonyms: searchResults.hits,
                totalCount: searchResults.total,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    totalPages: Math.ceil(searchResults.total / parseInt(limit)),
                },
            };

            await cacheService.set(cacheKey, result, 300);
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('synonym.searched', { query, count: searchResults.hits.length });
            logger.info(`Search returned ${searchResults.hits.length} synonyms in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Search failed for query ${query}:`, error);
            metricsCollector.increment('synonym.search_failed');
            return next(new AppError('Failed to search synonyms', 500));
        }
    });

    /**
     * Export synonyms as CSV
     * GET /api/v1/synonyms/:userId/export
     */
    exportSynonyms = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { format = 'csv', fields = 'term,synonyms,category' } = req.query;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        try {
            const synonyms = await Synonym.find({ userId, 'status.isDeleted': false })
                .read('secondaryPreferred')
                .select(fields.split(',').join(' '))
                .lean();

            const csvData = this.convertToCSV(synonyms, fields.split(','));
            const filename = `synonyms_${userId}_${Date.now()}.csv`;

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('synonym.exported', { userId, format });
            logger.info(`Exported ${synonyms.length} synonyms for user ${userId} in ${responseTime}ms`);

            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            return res.send(csvData);
        } catch (error) {
            logger.error(`Export failed for user ${userId}:`, error);
            metricsCollector.increment('synonym.export_failed', { userId });
            return next(new AppError('Failed to export synonyms', 500));
        }
    });

    // Helper Methods

    async processNewSynonymAsync(synonymId, userId) {
        try {
            const session = await mongoose.startSession();
            session.startTransaction();

            const synonym = await Synonym.findById(synonymId).session(session);
            if (!synonym) {
                await session.abortTransaction();
                session.endSession();
                return;
            }

            await synonym.calculateQualityScore({ session });

            await this.processExternalVerification(synonymId, userId);

            await this.synonymService.indexForSearch(synonym);

            await this.synonymService.updateUserStats(userId, { session });

            await synonym.save({ session });
            await session.commitTransaction();
            logger.info(`Async processing completed for synonym ${synonymId}`);
        } catch (error) {
            logger.error(`Async processing failed for synonym ${synonymId}:`, error);
        } finally {
            session.endSession();
        }
    }

    checkSynonymAccess(synonym, requestingUserId, isAdmin) {
        if (isAdmin) return true;
        if (synonym.userId.toString() === requestingUserId) return true;
        if (synonym.visibility === 'public') return true;
        return false;
    }

    getAllowedUpdateFields() {
        return [
            'term',
            'synonyms',
            'category',
            'tags',
            'visibility',
            'status',
        ];
    }

    sanitizeUpdates(updates, allowedFields) {
        const sanitized = {};
        allowedFields.forEach((field) => {
            if (updates[field] !== undefined) {
                if (field === 'synonyms') {
                    sanitized[field] = Array.isArray(updates[field])
                        ? updates[field].map((item) => sanitizeHtml(item))
                        : updates[field];
                } else {
                    sanitized[field] = sanitizeInput(updates[field]);
                }
            }
        });
        return sanitized;
    }

    processAnalyticsData(synonym, timeframe, metrics) {
        const analytics = synonym.analytics || {};
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
            endorsements: synonym.endorsements?.length || 0,
        };

        if (metrics === 'detailed') {
            filteredAnalytics.verification = synonym.verification;
        }

        return filteredAnalytics;
    }

    getUserLimits(accountType) {
        const limits = {
            free: { maxSynonyms: 50, maxMedia: 0, maxSizeMB: 0 },
            premium: { maxSynonyms: 200, maxMedia: 0, maxSizeMB: 0 },
            enterprise: { maxSynonyms: 1000, maxMedia: 0, maxSizeMB: 0 },
        };
        return limits[accountType] || limits.free;
    }

    buildSynonymQuery({ userId, status, category, search, tags }) {
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
            term: { term: 1 },
            popular: { 'analytics.viewCount': -1 },
            quality: { 'metadata.qualityScore': -1 },
            verified: { 'verification.confidence': -1 },
        };
        return sortOptions[sortBy] || sortOptions.recent;
    }

    getSelectFields(includeAnalytics) {
        const baseFields = 'term synonyms category tags visibility status createdAt updatedAt';
        return includeAnalytics ? baseFields + ' analytics' : baseFields;
    }

    async processSynonymData(synonym, includeAnalytics = false, includeVerification = false) {
        const processed = { ...synonym };

        if (!includeAnalytics) {
            delete processed.analytics;
        }
        if (!includeVerification) {
            delete processed.verification;
        }

        return processed;
    }

    calculateTrendingScore(synonym) {
        const viewsWeight = 0.4;
        const sharesWeight = 0.3;
        const endorsementsWeight = 0.2;
        const recencyWeight = 0.1;

        const daysSinceCreated = (Date.now() - new Date(synonym.createdAt)) / (1000 * 60 * 60 * 24);
        const recencyScore = Math.max(0, 10 - daysSinceCreated);

        return (
            (synonym.analytics.viewCount * viewsWeight) +
            ((synonym.analytics.shares?.total || 0) * sharesWeight) +
            (synonym.endorsements.length * endorsementsWeight) +
            (recencyScore * recencyWeight)
        );
    }

    async processExternalVerification(synonymId, userId) {
        try {
            const synonym = await Synonym.findById(synonymId);
            const result = await this.verificationService.verifySynonym({
                synonymId,
                userId,
                term: synonym.term,
                category: synonym.category,
            });

            return result;
        } catch (error) {
            logger.error(`External verification failed for synonym ${synonymId}:`, error);
            return { success: false, message: error.message };
        }
    }

    generateShareableLink(synonym, platform) {
        const baseUrl = process.env.APP_URL || 'https://app.example.com';
        return `${baseUrl}/synonyms/${synonym._id}/share?platform=${platform}`;
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
                message = 'Synonyms moved to trash';
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
                message = 'Synonyms archived';
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
                message = 'Synonyms published';
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

        const result = await Synonym.updateMany(query, updateData, options);
        return { message, result };
    }

    convertToCSV(data, fields) {
        const headers = fields.join(',');
        const rows = data.map((item) => {
            return fields.map((field) => {
                const value = Array.isArray(item[field]) ? item[field].join(';') : item[field] || '';
                return `"${value.toString().replace(/"/g, '""')}"`;
            }).join(',');
        });
        return `${headers}\n${rows.join('\n')}`;
    }
}

export default new SynonymController();