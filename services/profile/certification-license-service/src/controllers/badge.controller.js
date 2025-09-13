import Badge from '../models/Badge.js';
import BadgeService from '../services/BadgeService.js';
import VerificationService from '../services/VerificationService.js';
import NotificationService from '../services/NotificationService.js';
import MediaService from '../services/MediaService.js';
import AnalyticsService from '../services/AnalyticsService.js';
import { validateBadge, validateBulkBadges, validateIssueBadge, validateSearch, sanitizeInput } from '../validations/badge.validation.js';
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
const createBadgeLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // 10 creates per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_badge_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const updateBadgeLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 20, // 20 updates per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_badge_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const issueBadgeLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 5, // 5 issuance requests per 30 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `issue_badge_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const mediaUploadLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 10, // 10 media uploads per 10 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `media_badge_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const bulkOperationLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 5, // 5 bulk operations per 30 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_badge_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const searchLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 50, // 50 searches per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `search_badge_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

class BadgeController {
    constructor() {
        this.badgeService = BadgeService;
        this.verificationService = VerificationService;
        this.notificationService = NotificationService;
        this.mediaService = MediaService;
        this.analyticsService = AnalyticsService;
    }

    /**
     * Create a new badge
     * POST /api/v1/badges
     */
    createBadge = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const badgeData = req.body;
        const requestingUserId = req.user.id;

        await createBadgeLimiter(req, res, () => { });

        const validation = validateBadge(badgeData);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        const sanitizedData = this.sanitizeInput(badgeData);
        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const badge = await this.badgeService.createBadge({
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
            this.processBadgeAsync(badge._id, requestingUserId, 'create')
                .catch((err) => logger.error(`Async processing failed for badge ${badge._id}:`, err));

            // Create backup
            await this.createBackup(badge._id, 'create', requestingUserId, { session });

            eventEmitter.emit('badge.created', {
                badgeId: badge._id,
                userId: requestingUserId,
                name: badge.name,
            });

            metricsCollector.increment('badge.created', { userId: requestingUserId });
            await session.commitTransaction();
            logger.info(`Badge created: ${badge._id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Badge created successfully',
                data: {
                    id: badge._id,
                    name: badge.name,
                    status: badge.status,
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Badge creation failed for user ${requestingUserId}:`, error);
            metricsCollector.increment('badge.create_failed', { userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get badge by ID
     * GET /api/v1/badges/:id
     */
    getBadgeById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;
        const cacheKey = `badge:${id}:${requestingUserId}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('badge.cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const badge = await this.badgeService.getBadgeById(id, requestingUserId);
            if (!badge) {
                return next(new AppError('Badge not found', 404));
            }

            await this.analyticsService.incrementView(id, 'badge', requestingUserId);
            await cacheService.set(cacheKey, badge, 600);
            metricsCollector.increment('badge.fetched', { id, userId: requestingUserId });
            logger.info(`Fetched badge ${id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, { data: badge });
        } catch (error) {
            logger.error(`Failed to fetch badge ${id}:`, error);
            metricsCollector.increment('badge.fetch_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        }
    });

    /**
     * Update badge
     * PUT /api/v1/badges/:id
     */
    updateBadge = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const updates = req.body;
        const requestingUserId = req.user.id;

        await updateBadgeLimiter(req, res, () => { });

        const validation = validateBadge(updates, true);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const sanitizedUpdates = this.sanitizeUpdates(updates);
            const badge = await this.badgeService.updateBadge(id, requestingUserId, sanitizedUpdates, {
                session,
                requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
            });

            this.processBadgeAsync(id, requestingUserId, 'update')
                .catch((err) => logger.error(`Async processing failed for badge ${id}:`, err));

            await this.createBackup(id, 'update', requestingUserId, { session });
            await cacheService.deletePattern(`badge:${id}:*`);

            eventEmitter.emit('badge.updated', {
                badgeId: id,
                userId: requestingUserId,
                changes: Object.keys(sanitizedUpdates),
            });

            metricsCollector.increment('badge.updated', { id, userId: requestingUserId });
            await session.commitTransaction();
            logger.info(`Badge updated: ${id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Badge updated successfully',
                data: {
                    id,
                    name: badge.name,
                    status: badge.status,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Badge update failed for ${id}:`, error);
            metricsCollector.increment('badge.update_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete badge
     * DELETE /api/v1/badges/:id
     */
    deleteBadge = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const { permanent = false } = req.query;
        const requestingUserId = req.user.id;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            await this.badgeService.deleteBadge(id, requestingUserId, permanent, { session });
            await cacheService.deletePattern(`badge:${id}:*`);

            eventEmitter.emit('badge.deleted', {
                badgeId: id,
                userId: requestingUserId,
                permanent,
            });

            metricsCollector.increment(permanent ? 'badge.permanently_deleted' : 'badge.soft_deleted', {
                id,
                userId: requestingUserId,
            });
            await session.commitTransaction();
            logger.info(`Badge ${id} deleted (permanent: ${permanent}) in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: `Badge ${permanent ? 'permanently' : 'soft'} deleted successfully`,
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Badge deletion failed for ${id}:`, error);
            metricsCollector.increment('badge.delete_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Issue badge to user
     * POST /api/v1/badges/:id/issue
     */
    issueBadge = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const { recipientId } = req.body;
        const requestingUserId = req.user.id;

        await issueBadgeLimiter(req, res, () => { });

        const validation = validateIssueBadge({ recipientId });
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const badge = await this.badgeService.issueBadge(id, recipientId, requestingUserId, {
                session,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
            });

            this.processBadgeAsync(id, requestingUserId, 'issue')
                .catch((err) => logger.error(`Async processing failed for badge issuance ${id}:`, err));

            await this.notificationService.notifyUser(recipientId, {
                type: 'badge_issued',
                message: `You have been issued badge ${badge.name}`,
                data: { badgeId: id },
            });

            eventEmitter.emit('badge.issued', {
                badgeId: id,
                recipientId,
                userId: requestingUserId,
            });

            metricsCollector.increment('badge.issued', { id, recipientId });
            await session.commitTransaction();
            logger.info(`Badge ${id} issued to ${recipientId} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Badge issued successfully',
                data: { badgeId: id, recipientId },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Badge issuance failed for ${id}:`, error);
            metricsCollector.increment('badge.issue_failed', { id, recipientId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Revoke badge from user
     * POST /api/v1/badges/:id/revoke
     */
    revokeBadge = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const { recipientId } = req.body;
        const requestingUserId = req.user.id;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            await this.badgeService.revokeBadge(id, recipientId, requestingUserId, { session });
            await cacheService.deletePattern(`badge:${id}:*`);

            await this.notificationService.notifyUser(recipientId, {
                type: 'badge_revoked',
                message: `Badge ${id} has been revoked`,
                data: { badgeId: id },
            });

            eventEmitter.emit('badge.revoked', {
                badgeId: id,
                recipientId,
                userId: requestingUserId,
            });

            metricsCollector.increment('badge.revoked', { id, recipientId });
            await session.commitTransaction();
            logger.info(`Badge ${id} revoked from ${recipientId} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Badge revoked successfully',
                data: { badgeId: id, recipientId },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Badge revocation failed for ${id}:`, error);
            metricsCollector.increment('badge.revoke_failed', { id, recipientId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Verify badge
     * POST /api/v1/badges/:id/verify
     */
    verifyBadge = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const badge = await Badge.findById(id).session(session);
            if (!badge) {
                return next(new AppError('Badge not found', 404));
            }

            const verificationResult = await this.verificationService.verifyBadge({
                badgeId: id,
                name: badge.name,
                userId: requestingUserId,
            });

            badge.verification = {
                status: verificationResult.status,
                verificationScore: verificationResult.confidence,
                verifiedBy: verificationResult.verifiedBy,
                verificationDate: new Date(),
            };

            await badge.save({ session });
            await cacheService.deletePattern(`badge:${id}:*`);

            await this.notificationService.notifyUser(requestingUserId, {
                type: 'badge_verified',
                message: `Badge ${id} verification ${verificationResult.status}`,
                data: { badgeId: id, verificationStatus: verificationResult.status },
            });

            eventEmitter.emit('badge.verified', {
                badgeId: id,
                userId: requestingUserId,
                status: verificationResult.status,
            });

            metricsCollector.increment('badge.verified', { id, status: verificationResult.status });
            await session.commitTransaction();
            logger.info(`Badge ${id} verified in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Badge verification completed',
                data: badge.verification,
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Verification failed for badge ${id}:`, error);
            metricsCollector.increment('badge.verify_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Upload media for badge
     * POST /api/v1/badges/:id/media
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

            const badge = await Badge.findById(id).session(session);
            if (!badge) {
                return next(new AppError('Badge not found', 404));
            }

            const validation = this.badgeService.validateMediaUpload(files, badge.media || []);
            if (!validation.valid) {
                return next(new AppError(validation.message, 422));
            }

            const mediaResults = await this.mediaService.uploadMedia({
                files,
                entityId: id,
                entityType: 'badge',
                userId: requestingUserId,
            }, { session });

            badge.media = badge.media || [];
            badge.media.push(...mediaResults);
            await badge.save({ session });

            await cacheService.deletePattern(`badge:${id}:*`);

            eventEmitter.emit('badge.media_uploaded', {
                badgeId: id,
                userId: requestingUserId,
                mediaCount: mediaResults.length,
            });

            metricsCollector.increment('badge.media_uploaded', { id, count: mediaResults.length });
            await session.commitTransaction();
            logger.info(`Uploaded ${mediaResults.length} media for badge ${id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Media uploaded successfully',
                data: { media: mediaResults },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Media upload failed for badge ${id}:`, error);
            metricsCollector.increment('badge.media_upload_failed', { id });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get badges with filtering and pagination
     * GET /api/v1/badges
     */
    getBadges = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { page = 1, limit = 20, status, type, search, sortBy = 'recent' } = req.query;
        const requestingUserId = req.user.id;
        const cacheKey = `badges:${requestingUserId}:${JSON.stringify({ page, limit, status, type, search, sortBy })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('badge.cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const query = this.buildBadgeQuery({ status, type, search });
            const sortOption = this.buildSortOption(sortBy);
            const pageNum = Math.max(1, parseInt(page));
            const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
            const skip = (pageNum - 1) * limitNum;

            const [badges, totalCount] = await Promise.all([
                Badge.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select('name image type verification status createdAt analytics')
                    .lean(),
                Badge.countDocuments(query).cache({ ttl: 300, key: `badge_count_${requestingUserId}` }),
            ]);

            const processedBadges = badges.map((badge) => ({
                ...badge,
                isVerified: badge.verification?.status === 'verified',
            }));

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                badges: processedBadges,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages,
                    hasNext: pageNum < totalPages,
                    hasPrev: pageNum > 1,
                },
                filters: { status, type, search, sortBy },
            };

            await cacheService.set(cacheKey, result, 300);
            metricsCollector.increment('badge.fetched', { count: badges.length, userId: requestingUserId });
            logger.info(`Fetched ${badges.length} badges in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch badges:`, error);
            metricsCollector.increment('badge.fetch_failed', { userId: requestingUserId });
            return next(this.handleError(error));
        }
    });

    /**
     * Search badges
     * GET /api/v1/badges/search
     */
    searchBadges = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { query, filters = {}, page = 1, limit = 20 } = req.body;
        const requestingUserId = req.user.id;

        await searchLimiter(req, res, () => { });

        const validation = validateSearch({ query, filters });
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        const cacheKey = `badge_search:${requestingUserId}:${JSON.stringify({ query, filters, page, limit })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('badge.search_cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const result = await this.badgeService.searchBadges(query, filters, { page, limit });
            await cacheService.set(cacheKey, result, 300);

            metricsCollector.increment('badge.searched', { count: result.hits.length, userId: requestingUserId });
            logger.info(`Search returned ${result.hits.length} badges in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Search completed successfully',
                data: result,
            });
        } catch (error) {
            logger.error(`Search failed for query ${query}:`, error);
            metricsCollector.increment('badge.search_failed', { userId: requestingUserId });
            return next(new AppError('Failed to search badges', 500));
        }
    });

    /**
     * Get trending badges
     * GET /api/v1/badges/trending
     */
    getTrendingBadges = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { timeframe = '30d', type, limit = 20 } = req.query;
        const requestingUserId = req.user.id;
        const cacheKey = `trending_badges:${requestingUserId}:${timeframe}:${type || 'all'}:${limit}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('badge.trending_cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const badges = await this.badgeService.getTrendingBadges(timeframe, type, parseInt(limit));
            await cacheService.set(cacheKey, badges, 300);

            metricsCollector.increment('badge.trending_fetched', { count: badges.length, userId: requestingUserId });
            logger.info(`Fetched ${badges.length} trending badges in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Trending badges fetched successfully',
                data: badges,
            });
        } catch (error) {
            logger.error(`Failed to fetch trending badges:`, error);
            metricsCollector.increment('badge.trending_fetch_failed', { userId: requestingUserId });
            return next(new AppError('Failed to fetch trending badges', 500));
        }
    });

    /**
     * Bulk create badges
     * POST /api/v1/badges/bulk
     */
    bulkCreateBadges = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const badgesData = req.body.badges;
        const requestingUserId = req.user.id;

        await bulkOperationLimiter(req, res, () => { });

        const validation = validateBulkBadges(badgesData);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const sanitizedData = badgesData.map((badge) => this.sanitizeInput(badge));
            const createdBadges = await Promise.all(
                sanitizedData.map((badge) =>
                    this.badgeService.createBadge({
                        ...badge,
                        metadata: {
                            ...badge.metadata,
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

            createdBadges.forEach((badge) => {
                this.processBadgeAsync(badge._id, requestingUserId, 'create')
                    .catch((err) => logger.error(`Async processing failed for badge ${badge._id}:`, err));
            });

            await Promise.all(
                createdBadges.map((badge) =>
                    this.createBackup(badge._id, 'create', requestingUserId, { session })
                )
            );

            eventEmitter.emit('badge.bulk_created', {
                badgeIds: createdBadges.map((badge) => badge._id),
                userId: requestingUserId,
            });

            metricsCollector.increment('badge.bulk_created', { count: createdBadges.length, userId: requestingUserId });
            await session.commitTransaction();
            logger.info(`Bulk created ${createdBadges.length} badges in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Badges created successfully',
                data: createdBadges.map((badge) => ({
                    id: badge._id,
                    name: badge.name,
                    status: badge.status,
                })),
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk badge creation failed:`, error);
            metricsCollector.increment('badge.bulk_create_failed', { userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Bulk update badges
     * PUT /api/v1/badges/bulk
     */
    bulkUpdateBadges = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const updates = req.body.updates;
        const requestingUserId = req.user.id;

        await bulkOperationLimiter(req, res, () => { });

        const validation = validateBulkBadges(updates);
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

            const updatedBadges = await Promise.all(
                sanitizedUpdates.map(({ id, data }) =>
                    this.badgeService.updateBadge(id, requestingUserId, data, {
                        session,
                        requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                    })
                )
            );

            await Promise.all(
                updatedBadges.map((badge) => {
                    this.processBadgeAsync(badge._id, requestingUserId, 'update')
                        .catch((err) => logger.error(`Async processing failed for badge ${badge._id}:`, err));
                    return this.createBackup(badge._id, 'update', requestingUserId, { session });
                })
            );

            await Promise.all(
                updatedBadges.map((badge) => cacheService.deletePattern(`badge:${badge._id}:*`))
            );

            eventEmitter.emit('badge.bulk_updated', {
                badgeIds: updatedBadges.map((badge) => badge._id),
                userId: requestingUserId,
            });

            metricsCollector.increment('badge.bulk_updated', { count: updatedBadges.length, userId: requestingUserId });
            await session.commitTransaction();
            logger.info(`Bulk updated ${updatedBadges.length} badges in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Badges updated successfully',
                data: updatedBadges.map((badge) => ({
                    id: badge._id,
                    name: badge.name,
                    status: badge.status,
                })),
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk badge update failed:`, error);
            metricsCollector.increment('badge.bulk_update_failed', { userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get badge analytics
     * GET /api/v1/badges/:id/analytics
     */
    getBadgeAnalytics = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const { timeframe = '30d' } = req.query;
        const requestingUserId = req.user.id;
        const cacheKey = `badge_analytics:${id}:${timeframe}:${requestingUserId}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('badge.analytics_cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const analytics = await this.analyticsService.getBadgeAnalytics(id, timeframe);
            await cacheService.set(cacheKey, analytics, 300);

            metricsCollector.increment('badge.analytics_fetched', { id, userId: requestingUserId });
            logger.info(`Fetched analytics for badge ${id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Badge analytics fetched successfully',
                data: analytics,
            });
        } catch (error) {
            logger.error(`Failed to fetch analytics for badge ${id}:`, error);
            metricsCollector.increment('badge.analytics_fetch_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        }
    });

    /**
     * Export badge data
     * GET /api/v1/badges/:id/export
     */
    exportBadge = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const { format = 'json' } = req.query;
        const requestingUserId = req.user.id;

        try {
            const badge = await Badge.findById(id)
                .select('name image type verification status analytics metadata recipients')
                .lean();

            if (!badge) {
                return next(new AppError('Badge not found', 404));
            }

            let exportData;
            let contentType;
            let extension;

            switch (format.toLowerCase()) {
                case 'json':
                    exportData = JSON.stringify(badge, null, 2);
                    contentType = 'application/json';
                    extension = 'json';
                    break;
                case 'csv':
                    exportData = this.convertToCSV(badge);
                    contentType = 'text/csv';
                    extension = 'csv';
                    break;
                default:
                    return next(new AppError('Unsupported export format', 400));
            }

            const exportKey = `badge_export_${id}_${uuidv4()}.${extension}`;
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

            metricsCollector.increment('badge.exported', { id, format, userId: requestingUserId });
            logger.info(`Exported badge ${id} as ${format} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Badge exported successfully',
                data: { url: signedUrl },
            });
        } catch (error) {
            logger.error(`Export failed for badge ${id}:`, error);
            metricsCollector.increment('badge.export_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        }
    });

    /**
     * Get badge statistics
     * GET /api/v1/badges/:id/stats
     */
    getBadgeStats = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;
        const cacheKey = `badge_stats:${id}:${requestingUserId}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('badge.stats_cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const stats = await this.badgeService.getBadgeStats(id);
            await cacheService.set(cacheKey, stats, 3600);

            metricsCollector.increment('badge.stats_fetched', { id, userId: requestingUserId });
            logger.info(`Fetched stats for badge ${id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Badge stats fetched successfully',
                data: stats,
            });
        } catch (error) {
            logger.error(`Failed to fetch stats for badge ${id}:`, error);
            metricsCollector.increment('badge.stats_fetch_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        }
    });

    /**
     * Archive badge
     * POST /api/v1/badges/:id/archive
     */
    archiveBadge = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const badge = await Badge.findById(id).session(session);
            if (!badge) {
                return next(new AppError('Badge not found', 404));
            }

            badge.status.isActive = false;
            badge.status.isArchived = true;
            badge.status.archivedAt = new Date();
            await badge.save({ session });

            await cacheService.deletePattern(`badge:${id}:*`);

            eventEmitter.emit('badge.archived', {
                badgeId: id,
                userId: requestingUserId,
            });

            metricsCollector.increment('badge.archived', { id, userId: requestingUserId });
            await session.commitTransaction();
            logger.info(`Badge ${id} archived in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Badge archived successfully',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Archiving failed for badge ${id}:`, error);
            metricsCollector.increment('badge.archive_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Restore badge
     * POST /api/v1/badges/:id/restore
     */
    restoreBadge = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const badge = await Badge.findById(id).session(session);
            if (!badge) {
                return next(new AppError('Badge not found', 404));
            }

            badge.status.isActive = true;
            badge.status.isArchived = false;
            badge.status.restoredAt = new Date();
            await badge.save({ session });

            await cacheService.deletePattern(`badge:${id}:*`);

            eventEmitter.emit('badge.restored', {
                badgeId: id,
                userId: requestingUserId,
            });

            metricsCollector.increment('badge.restored', { id, userId: requestingUserId });
            await session.commitTransaction();
            logger.info(`Badge ${id} restored in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Badge restored successfully',
                data: {
                    id,
                    name: badge.name,
                    status: badge.status,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Restoring failed for badge ${id}:`, error);
            metricsCollector.increment('badge.restore_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get badge audit logs
     * GET /api/v1/badges/:id/audit
     */
    getAuditLogs = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const { page = 1, limit = 20, action } = req.query;
        const requestingUserId = req.user.id;
        const cacheKey = `badge_audit:${id}:${page}:${limit}:${action || 'all'}:${requestingUserId}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('badge.audit_cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const pageNum = Math.max(1, parseInt(page));
            const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
            const skip = (pageNum - 1) * limitNum;

            const query = { badgeId: id };
            if (action) query.action = action;

            const [logs, totalCount] = await Promise.all([
                this.badgeService.getAuditLogs(id, { page: pageNum, limit: limitNum, action }),
                this.badgeService.countAuditLogs(id, action),
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
            metricsCollector.increment('badge.audit_fetched', { count: logs.length, userId: requestingUserId });
            logger.info(`Fetched ${logs.length} audit logs for badge ${id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Audit logs fetched successfully',
                data: result,
            });
        } catch (error) {
            logger.error(`Failed to fetch audit logs for badge ${id}:`, error);
            metricsCollector.increment('badge.audit_fetch_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        }
    });

    /**
     * Create backup of badge
     * @param {string} badgeId - Badge ID
     * @param {string} action - Action type
     * @param {string} userId - User ID
     * @param {Object} options - Additional options
     */
    async createBackup(badgeId, action, userId, options = {}) {
        const startTime = Date.now();
        try {
            const badge = await Badge.findById(badgeId).lean();
            if (!badge) {
                throw new AppError('Badge not found', 404);
            }

            const backupKey = `badge_backup_${badgeId}_${Date.now()}_${uuidv4()}`;
            await s3.upload({
                Bucket: process.env.S3_BACKUP_BUCKET,
                Key: backupKey,
                Body: JSON.stringify({
                    badge,
                    action,
                    userId,
                    timestamp: new Date(),
                }),
                ContentType: 'application/json',
                ServerSideEncryption: 'AES256',
            }).promise();

            metricsCollector.increment('badge.backup_created', { userId, action });
            logger.info(`Backup created for badge ${badgeId} (${action}) in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to create backup for badge ${badgeId}:`, error);
            metricsCollector.increment('badge.backup_failed', { userId });
            throw error;
        }
    }

    /**
     * Process badge asynchronously
     * @param {string} badgeId - Badge ID
     * @param {string} userId - User ID
     * @param {string} action - Action type
     */
    async processBadgeAsync(badgeId, userId, action) {
        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const badge = await Badge.findById(badgeId).session(session);
            if (!badge) {
                throw new AppError('Badge not found', 404);
            }

            await this.badgeService.indexForSearch(badge);
            await this.analyticsService.updateBadgeAnalytics(badgeId, { session });
            await this.badgeService.updateUserStats(userId, { session });

            await session.commitTransaction();
            logger.info(`Async processing completed for badge ${badgeId} (${action})`);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Async processing failed for badge ${badgeId}:`, error);
            metricsCollector.increment('badge.async_processing_failed', { badgeId });
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
            return new AppError('Badge already exists', 409);
        }
        if (error.name === 'CastError') {
            return new AppError('Invalid badge ID', 400);
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
            name: sanitizeHtml(data.name || ''),
            description: sanitizeHtml(data.description || ''),
            type: sanitizeHtml(data.type || ''),
            image: data.image ? sanitizeHtml(data.image) : undefined,
        };
    }

    /**
     * Sanitize updates
     * @param {Object} updates - Update data
     * @returns {Object} - Sanitized updates
     */
    sanitizeUpdates(updates) {
        const allowedFields = ['name', 'image', 'type', 'description', 'status', 'criteria'];
        const sanitized = {};
        allowedFields.forEach((field) => {
            if (updates[field] !== undefined) {
                sanitized[field] = ['name', 'description', 'type'].includes(field)
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
    buildBadgeQuery({ status, type, search }) {
        const query = { 'status.isDeleted': false };
        if (status) query['status.workflow'] = status;
        if (type) query.type = type;
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
            name: { name: 1 },
            popularity: { 'analytics.views': -1 },
        };
        return sortOptions[sortBy] || sortOptions.recent;
    }

    /**
     * Convert badge to CSV
     * @param {Object} badge - Badge data
     * @returns {string} - CSV string
     */
    convertToCSV(badge) {
        const headers = ['id', 'name', 'type', 'verification_status', 'created_at', 'recipient_count'];
        const row = [
            badge._id,
            `"${badge.name.replace(/"/g, '""')}"`,
            `"${badge.type?.replace(/"/g, '""') || ''}"`,
            badge.verification?.status || 'pending',
            badge.createdAt,
            badge.recipients?.length || 0,
        ];
        return [headers.join(','), row.join(',')].join('\n');
    }
}

export default new BadgeController();