import Honor from '../models/Honor.js';
import VerificationService from '../services/VerificationService.js';
import MediaService from '../services/MediaService.js';
import NotificationService from '../services/NotificationService.js';
import SchoolService from '../services/SchoolService.js';
import EducationService from '../services/EducationService.js';
import DegreeService from '../services/DegreeService.js';
import { validateHonor, sanitizeInput } from '../validations/honor.validation.js';
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
import { CircuitBreaker } from '../utils/circuitBreaker.js';
import { retry } from '../utils/retry.js';
import { elasticsearchClient } from '../config/elasticsearch.js';
import { s3Client } from '../config/s3.js';
import crypto from 'crypto';

// Rate limiters for high concurrency and abuse prevention
const createHonorLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15-minute window
    max: 10, // Allow 10 creates
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_honor_${req.user.id}_${req.ip} `,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
    legacyHeaders: false,
});

const updateHonorLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5-minute window
    max: 20, // Allow 20 updates
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_honor_${req.user.id}_${req.ip} `,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const verificationLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30-minute window
    max: 5, // Strict limit for external API calls
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `verify_honor_${req.user.id}_${req.ip} `,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const bulkOperationsLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // Hourly limit
    max: 3, // Conservative limit
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_honor_${req.user.id} `,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const mediaUploadLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000, // 10-minute window
    max: 10, // Limit uploads
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `media_honor_${req.user.id}_${req.ip} `,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const searchLimiter = createRateLimiter({
    windowMs: 1 * 60 * 1000, // 1-minute window
    max: 50, // Allow frequent searches
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `search_honor_${req.user.id} `,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const analyticsLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5-minute window
    max: 20, // Moderate limit
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `analytics_honor_${req.user.id} `,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

class HonorsController {
    constructor() {
        this.verificationService = VerificationService;
        this.mediaService = MediaService;
        this.notificationService = NotificationService;
        this.schoolService = SchoolService;
        this.educationService = EducationService;
        this.degreeService = DegreeService;
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
     * Create a new honor
     * POST /api/v1/honors/:userId
     * Creates an honor record with validation and async processing.
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    createHonor = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const honorData = req.body;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied: Cannot create honor for another user', 403));
        }

        await createHonorLimiter(req, res, () => { });

        const validation = validateHonor(honorData);
        if (!validation.valid) {
            metricsCollector.increment('honor.validation_failed', { userId, errors: validation.errors.length });
            return next(new AppError(`Validation failed: ${validation.message} `, 400));
        }

        const sanitizedData = sanitizeInput(honorData);
        sanitizedData.title = sanitizedData.title?.trim();
        sanitizedData.awardDate = new Date(sanitizedData.awardDate) || null;

        const userHonorCount = await Honor.countDocuments({
            userId,
            'status': { $ne: 'deleted' },
        }).cache({ ttl: 300, key: `user_honor_count_${userId} ` });

        const limits = this.getUserLimits(req.user.accountType);
        if (userHonorCount >= limits.maxHonors) {
            metricsCollector.increment('honor.limit_exceeded', { userId });
            return next(new AppError(`Honor limit reached(${limits.maxHonors})`, 403));
        }

        if (sanitizedData.schoolId) {
            const school = await this.schoolService.getSchoolById(sanitizedData.schoolId);
            if (!school || school.status !== 'active') {
                return next(new AppError('Invalid or inactive school association', 400));
            }
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const honor = await Honor.create([{
                ...sanitizedData,
                userId,
                metadata: {
                    ...sanitizedData.metadata,
                    createdBy: {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        location: req.geoip || { country: 'unknown', city: 'unknown' },
                        referrer: req.get('Referer') || 'direct',
                    },
                    importSource: sanitizedData.metadata?.importSource || 'manual',
                    version: 1,
                },
                analytics: {
                    views: { total: 0, unique: 0, byDate: [] },
                    endorsements: { total: 0, byUser: [] },
                },
                verification: {
                    status: 'pending',
                    confidence: 0,
                    verifiedBy: null,
                    verifiedAt: null,
                    details: [],
                },
                status: 'draft',
                privacy: {
                    isPublic: false,
                    showDetails: true,
                    searchable: true,
                    visibleToConnections: true,
                    visibleToAlumni: true,
                },
            }], { session });

            this.processNewHonorAsync(honor[0]._id, requestingUserId)
                .catch((err) => {
                    logger.error(`Async processing failed for honor ${honor[0]._id}: `, err);
                    metricsCollector.increment('honor.async_processing_failed', { honorId: honor[0]._id });
                });

            metricsCollector.increment('honor.created', {
                userId,
                title: honor[0].title,
                schoolAssociated: !!honor[0].schoolId,
                accountType: req.user.accountType,
            });
            metricsCollector.timing('honor.create_time', Date.now() - startTime);

            eventEmitter.emit('honor.created', {
                honorId: honor[0]._id,
                userId,
                schoolId: honor[0].schoolId,
                title: honor[0].title,
            });

            if (honor[0].settings?.autoBackup) {
                this.createBackup(honor[0]._id, 'create', requestingUserId, { session })
                    .catch((err) => {
                        logger.error(`Auto backup failed for honor ${honor[0]._id}: `, err);
                    });
            }

            await session.commitTransaction();
            logger.info(`Honor created successfully: ${honor[0]._id} in ${Date.now() - startTime} ms`);

            return ApiResponse.success(res, {
                message: 'Honor created successfully',
                data: {
                    id: honor[0]._id,
                    userId: honor[0].userId,
                    title: honor[0].title,
                    status: honor[0].status,
                    createdAt: honor[0].createdAt,
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Honor creation failed for user ${userId}: `, { error: error.message });
            metricsCollector.increment('honor.create_failed', { userId });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Get user's honors with filtering and pagination
     * GET /api/v1/honors/:userId
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    getHonors = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            const hasConnectionAccess = await this.checkConnectionAccess(userId, requestingUserId);
            if (!hasConnectionAccess) {
                return next(new AppError('Access denied', 403));
            }
        }

        const {
            page = 1,
            limit = 20,
            status,
            title,
            schoolId,
            awardDateStart,
            awardDateEnd,
            search,
            sortBy = 'recent',
            tags,
        } = req.query;

        const query = this.buildHonorQuery({ userId, status, title, schoolId, awardDateStart, awardDateEnd, search, tags });
        const sortOption = this.buildSortOption(sortBy);
        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
        const skip = (pageNum - 1) * limitNum;

        const cacheKey = `honors:${userId}:${JSON.stringify({ page, limit, status, title, schoolId, sortBy, tags })} `;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('honor.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const [honors, totalCount] = await Promise.all([
                Honor.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select('-__v')
                    .populate('schoolId', 'name type')
                    .lean({ virtuals: true }),
                Honor.countDocuments(query).cache({ ttl: 300 }),
            ]);

            const result = {
                honors,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages: Math.ceil(totalCount / limitNum),
                    hasNext: pageNum < Math.ceil(totalCount / limitNum),
                    hasPrev: pageNum > 1,
                },
            };

            await cacheService.set(cacheKey, result, 300, ['honors:user:' + userId]);
            metricsCollector.increment('honor.fetched', { userId, count: honors.length });
            metricsCollector.timing('honor.get_list_time', Date.now() - startTime);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch honors for user ${userId}: `, { error: error.message });
            metricsCollector.increment('honor.fetch_failed', { userId });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        }
    });

    /**
     * Get single honor by ID
     * GET /api/v1/honors/:userId/:id
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    getHonorById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            const hasConnectionAccess = await this.checkConnectionAccess(userId, requestingUserId);
            if (!hasConnectionAccess) {
                return next(new AppError('Access denied', 403));
            }
        }

        const cacheKey = `honor:${id} `;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('honor.cache_hit', { id });
                return ApiResponse.success(res, cached);
            }

            const honor = await Honor.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('-__v')
                .populate('schoolId', 'name type')
                .lean({ virtuals: true });

            if (!honor) {
                return next(new AppError('Honor not found', 404));
            }

            await cacheService.set(cacheKey, honor, 600, ['honors:id:' + id]);
            metricsCollector.increment('honor.viewed', { id, userId });
            metricsCollector.timing('honor.get_by_id_time', Date.now() - startTime);

            return ApiResponse.success(res, { data: honor });
        } catch (error) {
            logger.error(`Failed to fetch honor ${id}: `, { error: error.message });
            metricsCollector.increment('honor.view_failed', { id });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        }
    });

    /**
     * Update honor
     * PUT /api/v1/honors/:userId/:id
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    updateHonor = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const updates = req.body;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        await updateHonorLimiter(req, res, () => { });

        const sanitizedUpdates = this.sanitizeUpdates(updates, this.getAllowedUpdateFields());
        if (Object.keys(sanitizedUpdates).length === 0) {
            return next(new AppError('No valid update fields provided', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const honor = await Honor.findOne({ _id: id, userId }).session(session);
            if (!honor) {
                return next(new AppError('Honor not found', 404));
            }

            if (sanitizedUpdates.title) {
                honor.versions = honor.versions || [];
                honor.versions.push({
                    versionNumber: honor.metadata.version + 1,
                    title: sanitizedUpdates.title,
                    changeType: 'edit',
                    timestamp: new Date(),
                });
            }

            Object.assign(honor, sanitizedUpdates);
            honor.metadata.version += 1;
            honor.metadata.updateCount += 1;

            await honor.save({ session });
            await cacheService.deletePattern(`honor:${id}:* `);

            metricsCollector.increment('honor.updated', { id });
            metricsCollector.timing('honor.update_time', Date.now() - startTime);
            eventEmitter.emit('honor.updated', { honorId: id, changes: Object.keys(sanitizedUpdates) });

            await session.commitTransaction();
            return ApiResponse.success(res, {
                message: 'Honor updated successfully',
                data: { id: honor._id, title: honor.title, status: honor.status },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Honor update failed for ${id}: `, { error: error.message });
            metricsCollector.increment('honor.update_failed', { id });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete honor
     * DELETE /api/v1/honors/:userId/:id
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    deleteHonor = catchAsync(async (req, res, next) => {
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

            const honor = await Honor.findOne({ _id: id, userId }).session(session);
            if (!honor) {
                return next(new AppError('Honor not found', 404));
            }

            if (permanent === 'true') {
                await Honor.findByIdAndDelete(id, { session });
                await this.mediaService.deleteAllMedia(id, 'honor', { session });
            } else {
                honor.status = 'deleted';
                honor.privacy.isPublic = false;
                await honor.save({ session });
            }

            await cacheService.deletePattern(`honor:${id}:* `);
            metricsCollector.increment(`honor.${permanent ? 'permanently_deleted' : 'soft_deleted'} `, { id });
            metricsCollector.timing('honor.delete_time', Date.now() - startTime);
            eventEmitter.emit('honor.deleted', { honorId: id, permanent });

            await session.commitTransaction();
            return ApiResponse.success(res, {
                message: permanent === 'true' ? 'Honor permanently deleted' : 'Honor soft deleted',
                data: { id },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Honor deletion failed for ${id}: `, { error: error.message });
            metricsCollector.increment('honor.delete_failed', { id });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Verify honor
     * POST /api/v1/honors/:userId/:id/verify
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @_returns {Promise<void>}
     */
    verifyHonor = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied for verification', 403));
        }

        await verificationLimiter(req, res, () => { });

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const honor = await Honor.findOne({ _id: id, userId }).session(session);
            if (!honor) {
                return next(new AppError('Honor not found', 404));
            }

            const verificationResult = await this.circuitBreaker.fire(async () => {
                return await this.verificationService.verifyHonor({
                    honorId: honor._id,
                    userId,
                    title: honor.title,
                    schoolId: honor.schoolId,
                });
            });

            honor.verification = {
                status: verificationResult.success ? 'verified' : 'failed',
                confidence: verificationResult.confidence || 0,
                verifiedBy: verificationResult.verifiedBy || 'external_api',
                verifiedAt: new Date(),
                details: verificationResult.details || [],
            };
            await honor.save({ session });

            await this.indexForSearch(honor);
            await cacheService.deletePattern(`honor:${id}:* `);

            eventEmitter.emit('honor.verified', {
                honorId: id,
                userId,
                verificationStatus: verificationResult.success ? 'verified' : 'failed',
            });

            await session.commitTransaction();
            metricsCollector.increment('honor.verified', { id, status: verificationResult.status });
            metricsCollector.timing('honor.verify_time', Date.now() - startTime);

            return ApiResponse.success(res, {
                message: `Honor ${verificationResult.success ? 'verified' : 'verification failed'} `,
                data: { id: honor._id, verificationStatus: honor.verification.status },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Verification failed for honor ${id}: `, { error: error.message });
            metricsCollector.increment('honor.verify_failed', { id });
            throw error instanceof AppError ? error : new AppError('Failed to verify honor', 424);
        } finally {
            session.endSession();
        }
    });

    // Helper methods
    getUserLimits(accountType) {
        const limits = {
            free: { maxHonors: 20, maxMedia: 5 },
            premium: { maxHonors: 100, maxMedia: 20 },
            enterprise: { maxHonors: 1000, maxMedia: 100 },
        };
        return limits[accountType] || limits.free;
    }

    buildHonorQuery({ userId, status, title, schoolId, awardDateStart, awardDateEnd, search, tags }) {
        const query = { userId, status: { $ne: 'deleted' } };
        if (status) query.status = status;
        if (title) query.title = { $regex: title, $options: 'i' };
        if (schoolId) query.schoolId = mongoose.Types.ObjectId(schoolId);
        if (awardDateStart) query.awardDate = { $gte: new Date(awardDateStart) };
        if (awardDateEnd) query.awardDate = { ...query.awardDate, $lte: new Date(awardDateEnd) };
        if (search) query.$text = { $search: search };
        if (tags) query.tags = { $all: tags.split(',').map(t => t.trim()) };
        return query;
    }

    buildSortOption(sortBy) {
        const sortOptions = {
            recent: { createdAt: -1 },
            title: { title: 1 },
        };
        return sortOptions[sortBy] || sortOptions.recent;
    }

    async indexForSearch(honor) {
        try {
            await elasticsearchClient.index({
                index: 'honors',
                id: honor._id.toString(),
                body: {
                    userId: honor.userId,
                    title: honor.title,
                    schoolId: honor.schoolId,
                    status: honor.status,
                    searchable: honor.privacy.searchable,
                },
            });
            metricsCollector.increment('honor.indexed', { honorId: honor._id });
        } catch (error) {
            logger.error(`Failed to index honor ${honor._id}: `, { error: error.message });
        }
    }

    async createBackup(honorId, action, userId, options = {}) {
        logger.info(`Backup created for honor ${honorId} by ${userId} for action ${action}`);
        metricsCollector.increment('honor.backup_created', { honorId, action });
    }

    async checkConnectionAccess(ownerId, requesterId) {
        return ownerId === requesterId; // Placeholder
    }

    getAllowedUpdateFields() {
        return ['title', 'description', 'awardDate', 'schoolId', 'tags', 'privacy', 'settings'];
    }

    sanitizeUpdates(updates, allowedFields) {
        const sanitized = {};
        for (const [key, value] of Object.entries(updates)) {
            if (allowedFields.includes(key)) {
                sanitized[key] = key === 'description' ? sanitizeHtml(value) : value;
            }
        }
        return sanitized;
    }
}

export default new HonorsController();
