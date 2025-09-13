import Advisor from '../models/Advisor.js';
import VerificationService from '../services/VerificationService.js';
import MediaService from '../services/MediaService.js';
import NotificationService from '../services/NotificationService.js';
import SchoolService from '../services/SchoolService.js';
import EducationService from '../services/EducationService.js';
import DegreeService from '../services/DegreeService.js';
import { validateAdvisor, sanitizeInput } from '../validations/advisor.validation.js';
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
import moment from 'moment';

// Rate limiters for high concurrency and abuse prevention
const createAdvisorLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15-minute window
    max: 10, // Allow 10 creates per user per IP
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_advisor_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
    legacyHeaders: false,
});

const updateAdvisorLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5-minute window
    max: 20, // Allow 20 updates
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_advisor_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const verificationLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30-minute window
    max: 5, // Strict limit for external API calls
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `verify_advisor_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const bulkOperationsLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // Hourly limit
    max: 3, // Conservative limit for bulk operations
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_advisor_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const mediaUploadLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000, // 10-minute window
    max: 10, // Limit uploads
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `media_advisor_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const searchLimiter = createRateLimiter({
    windowMs: 1 * 60 * 1000, // 1-minute window
    max: 50, // Allow frequent searches
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `search_advisor_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const analyticsLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5-minute window
    max: 20, // Moderate limit for analytics requests
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `analytics_advisor_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

class AdvisorController {
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
     * Create a new advisor
     * POST /api/v1/advisors/:userId
     * Creates an advisor record with validation, async processing, and transaction support.
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    createAdvisor = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const advisorData = req.body;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied: Cannot create advisor for another user', 403));
        }

        await createAdvisorLimiter(req, res, () => { });

        const validation = validateAdvisor(advisorData);
        if (!validation.valid) {
            metricsCollector.increment('advisor.validation_failed', { userId, errors: validation.errors.length });
            return next(new AppError(`Validation failed: ${validation.message}`, 400));
        }

        const sanitizedData = sanitizeInput(advisorData);
        sanitizedData.name = sanitizedData.name?.trim();
        sanitizedData.startDate = new Date(sanitizedData.startDate) || null;
        sanitizedData.endDate = sanitizedData.endDate ? new Date(sanitizedData.endDate) : null;

        const userAdvisorCount = await Advisor.countDocuments({
            userId,
            'status': { $ne: 'deleted' },
        }).cache({ ttl: 300, key: `user_advisor_count_${userId}` });

        const limits = this.getUserLimits(req.user.accountType);
        if (userAdvisorCount >= limits.maxAdvisors) {
            metricsCollector.increment('advisor.limit_exceeded', { userId });
            return next(new AppError(`Advisor limit reached (${limits.maxAdvisors})`, 403));
        }

        if (sanitizedData.schoolId) {
            const school = await this.schoolService.getSchoolById(sanitizedData.schoolId);
            if (!school || school.status !== 'active') {
                return next(new AppError('Invalid or inactive school association', 400));
            }
        }

        if (sanitizedData.educationId) {
            const education = await this.educationService.getEducationById(sanitizedData.educationId);
            if (!education || education.userId.toString() !== userId) {
                return next(new AppError('Invalid education association', 400));
            }
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const advisor = await Advisor.create([{
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
                    updateCount: 0,
                },
                analytics: {
                    views: { total: 0, unique: 0, byDate: [] },
                    endorsements: { total: 0, byUser: [] },
                    interactions: { total: 0, byType: {} },
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

            this.processNewAdvisorAsync(advisor[0]._id, requestingUserId)
                .catch((err) => {
                    logger.error(`Async processing failed for advisor ${advisor[0]._id}:`, err);
                    metricsCollector.increment('advisor.async_processing_failed', { advisorId: advisor[0]._id });
                });

            metricsCollector.increment('advisor.created', {
                userId,
                name: advisor[0].name,
                schoolAssociated: !!advisor[0].schoolId,
                educationAssociated: !!advisor[0].educationId,
                accountType: req.user.accountType,
            });
            metricsCollector.timing('advisor.create_time', Date.now() - startTime);

            eventEmitter.emit('advisor.created', {
                advisorId: advisor[0]._id,
                userId,
                schoolId: advisor[0].schoolId,
                educationId: advisor[0].educationId,
                name: advisor[0].name,
            });

            if (advisor[0].settings?.autoBackup) {
                await this.createBackup(advisor[0]._id, 'create', requestingUserId, { session });
            }

            await session.commitTransaction();
            logger.info(`Advisor created successfully: ${advisor[0]._id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Advisor created successfully',
                data: {
                    id: advisor[0]._id,
                    userId: advisor[0].userId,
                    name: advisor[0].name,
                    status: advisor[0].status,
                    createdAt: advisor[0].createdAt,
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Advisor creation failed for user ${userId}:`, { error: error.message });
            metricsCollector.increment('advisor.create_failed', { userId });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Get user's advisors with filtering and pagination
     * GET /api/v1/advisors/:userId
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    getAdvisors = catchAsync(async (req, res, next) => {
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
            name,
            schoolId,
            educationId,
            startDate,
            endDate,
            search,
            sortBy = 'recent',
            tags,
        } = req.query;

        await searchLimiter(req, res, () => { });

        const query = this.buildAdvisorQuery({ userId, status, name, schoolId, educationId, startDate, endDate, search, tags });
        const sortOption = this.buildSortOption(sortBy);
        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
        const skip = (pageNum - 1) * limitNum;

        const cacheKey = `advisors:${userId}:${JSON.stringify({ page, limit, status, name, schoolId, educationId, sortBy, tags })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('advisor.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const [advisors, totalCount] = await Promise.all([
                Advisor.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select('-__v')
                    .populate('schoolId', 'name type')
                    .populate('educationId', 'degreeLevel fieldOfStudy')
                    .lean({ virtuals: true }),
                Advisor.countDocuments(query).cache({ ttl: 300 }),
            ]);

            const result = {
                advisors,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages: Math.ceil(totalCount / limitNum),
                    hasNext: pageNum < Math.ceil(totalCount / limitNum),
                    hasPrev: pageNum > 1,
                },
            };

            await cacheService.set(cacheKey, result, 300, ['advisors:user:' + userId]);
            metricsCollector.increment('advisor.fetched', { userId, count: advisors.length });
            metricsCollector.timing('advisor.get_list_time', Date.now() - startTime);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch advisors for user ${userId}:`, { error: error.message });
            metricsCollector.increment('advisor.fetch_failed', { userId });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        }
    });

    /**
     * Get single advisor by ID
     * GET /api/v1/advisors/:userId/:id
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    getAdvisorById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            const hasConnectionAccess = await this.checkConnectionAccess(userId, requestingUserId);
            if (!hasConnectionAccess) {
                return next(new AppError('Access denied', 403));
            }
        }

        const cacheKey = `advisor:${id}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('advisor.cache_hit', { id });
                return ApiResponse.success(res, cached);
            }

            const advisor = await Advisor.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('-__v')
                .populate('schoolId', 'name type')
                .populate('educationId', 'degreeLevel fieldOfStudy')
                .lean({ virtuals: true });

            if (!advisor) {
                return next(new AppError('Advisor not found', 404));
            }

            await this.updateAnalytics(advisor, requestingUserId);
            await cacheService.set(cacheKey, advisor, 600, ['advisors:id:' + id]);
            metricsCollector.increment('advisor.viewed', { id, userId });
            metricsCollector.timing('advisor.get_by_id_time', Date.now() - startTime);

            return ApiResponse.success(res, { data: advisor });
        } catch (error) {
            logger.error(`Failed to fetch advisor ${id}:`, { error: error.message });
            metricsCollector.increment('advisor.view_failed', { id });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        }
    });

    /**
     * Update advisor
     * PUT /api/v1/advisors/:userId/:id
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    updateAdvisor = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const updates = req.body;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        await updateAdvisorLimiter(req, res, () => { });

        const sanitizedUpdates = this.sanitizeUpdates(updates, this.getAllowedUpdateFields());
        if (Object.keys(sanitizedUpdates).length === 0) {
            return next(new AppError('No valid update fields provided', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const advisor = await Advisor.findOne({ _id: id, userId }).session(session);
            if (!advisor) {
                return next(new AppError('Advisor not found', 404));
            }

            if (sanitizedUpdates.name || sanitizedUpdates.email) {
                advisor.versions = advisor.versions || [];
                advisor.versions.push({
                    versionNumber: advisor.metadata.version + 1,
                    name: sanitizedUpdates.name || advisor.name,
                    email: sanitizedUpdates.email || advisor.email,
                    changeType: 'edit',
                    timestamp: new Date(),
                });
            }

            if (sanitizedUpdates.schoolId) {
                const school = await this.schoolService.getSchoolById(sanitizedUpdates.schoolId, { session });
                if (!school || school.status !== 'active') {
                    return next(new AppError('Invalid or inactive school association', 400));
                }
            }

            if (sanitizedUpdates.educationId) {
                const education = await this.educationService.getEducationById(sanitizedUpdates.educationId, { session });
                if (!education || education.userId.toString() !== userId) {
                    return next(new AppError('Invalid education association', 400));
                }
            }

            Object.assign(advisor, sanitizedUpdates);
            advisor.metadata.version += 1;
            advisor.metadata.updateCount += 1;
            advisor.metadata.lastModifiedBy = {
                userId: requestingUserId,
                timestamp: new Date(),
                changes: Object.keys(sanitizedUpdates),
            };

            if (['name', 'email', 'schoolId'].some(field => sanitizedUpdates[field])) {
                advisor.verification.status = 'pending';
                this.processExternalVerification(advisor._id, userId).catch((err) => {
                    logger.error(`Re-verification failed for advisor ${advisor._id}:`, err);
                });
            }

            await advisor.save({ session });
            await this.indexForSearch(advisor);
            await cacheService.deletePattern(`advisor:${id}:*`);

            metricsCollector.increment('advisor.updated', { id });
            metricsCollector.timing('advisor.update_time', Date.now() - startTime);
            eventEmitter.emit('advisor.updated', { advisorId: id, changes: Object.keys(sanitizedUpdates) });

            await session.commitTransaction();
            return ApiResponse.success(res, {
                message: 'Advisor updated successfully',
                data: { id: advisor._id, name: advisor.name, status: advisor.status },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Advisor update failed for ${id}:`, { error: error.message });
            metricsCollector.increment('advisor.update_failed', { id });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete advisor
     * DELETE /api/v1/advisors/:userId/:id
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    deleteAdvisor = catchAsync(async (req, res, next) => {
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

            const advisor = await Advisor.findOne({ _id: id, userId }).session(session);
            if (!advisor) {
                return next(new AppError('Advisor not found', 404));
            }

            if (permanent === 'true') {
                await Advisor.findByIdAndDelete(id, { session });
                await this.mediaService.deleteAllMedia(id, 'advisor', { session });
            } else {
                advisor.status = 'deleted';
                advisor.privacy.isPublic = false;
                advisor.privacy.searchable = false;
                await advisor.save({ session });
            }

            await cacheService.deletePattern(`advisor:${id}:*`);
            metricsCollector.increment(`advisor.${permanent ? 'permanently_deleted' : 'soft_deleted'}`, { id });
            metricsCollector.timing('advisor.delete_time', Date.now() - startTime);
            eventEmitter.emit('advisor.deleted', { advisorId: id, permanent });

            await session.commitTransaction();
            return ApiResponse.success(res, {
                message: permanent === 'true' ? 'Advisor permanently deleted' : 'Advisor soft deleted',
                data: { id },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Advisor deletion failed for ${id}:`, { error: error.message });
            metricsCollector.increment('advisor.delete_failed', { id });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Verify advisor
     * POST /api/v1/advisors/:userId/:id/verify
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    verifyAdvisor = catchAsync(async (req, res, next) => {
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

            const advisor = await Advisor.findOne({ _id: id, userId }).session(session);
            if (!advisor) {
                return next(new AppError('Advisor not found', 404));
            }

            const verificationResult = await this.circuitBreaker.fire(async () => {
                return await retry(() => this.verificationService.verifyAdvisor({
                    advisorId: advisor._id,
                    userId,
                    name: advisor.name,
                    email: advisor.email,
                    schoolId: advisor.schoolId,
                    educationId: advisor.educationId,
                }), this.retryConfig);
            });

            advisor.verification = {
                status: verificationResult.success ? 'verified' : 'failed',
                confidence: verificationResult.confidence || 0,
                verifiedBy: verificationResult.verifiedBy || 'external_api',
                verifiedAt: new Date(),
                details: verificationResult.details || [],
            };
            await advisor.save({ session });

            await this.indexForSearch(advisor);
            await cacheService.deletePattern(`advisor:${id}:*`);

            eventEmitter.emit('advisor.verified', {
                advisorId: id,
                userId,
                verificationStatus: verificationResult.success ? 'verified' : 'failed',
            });

            await session.commitTransaction();
            metricsCollector.increment('advisor.verified', { id, status: verificationResult.status });
            metricsCollector.timing('advisor.verify_time', Date.now() - startTime);

            return ApiResponse.success(res, {
                message: `Advisor ${verificationResult.success ? 'verified' : 'verification failed'}`,
                data: { id: advisor._id, verificationStatus: advisor.verification.status },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Verification failed for advisor ${id}:`, { error: error.message });
            metricsCollector.increment('advisor.verify_failed', { id });
            throw error instanceof AppError ? error : new AppError('Failed to verify advisor', 424);
        } finally {
            session.endSession();
        }
    });

    /**
     * Upload advisor media
     * POST /api/v1/advisors/:userId/:id/media
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    uploadAdvisorMedia = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const files = req.files || [];

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        await mediaUploadLimiter(req, res, () => { });

        if (files.length === 0) {
            return next(new AppError('No files provided', 400));
        }

        const mediaValidation = this.validateMediaUpload(files);
        if (!mediaValidation.valid) {
            return next(new AppError(mediaValidation.message, 422));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const advisor = await Advisor.findOne({ _id: id, userId }).session(session);
            if (!advisor) {
                return next(new AppError('Advisor not found', 404));
            }

            const mediaResults = await this.mediaService.uploadMedia({
                files,
                entityId: advisor._id,
                entityType: 'advisor',
                userId: requestingUserId,
                category: 'advisor_media',
            }, { session });

            const scanResults = await this.mediaService.scanMedia(mediaResults);
            const infected = scanResults.filter(r => r.infected);
            if (infected.length > 0) {
                await this.mediaService.deleteMedia(infected.map(m => m.id), { session });
                return next(new AppError(`Media upload failed: ${infected.length} infected files detected`, 422));
            }

            advisor.media = [...(advisor.media || []), ...mediaResults];
            await advisor.save({ session });

            await cacheService.deletePattern(`advisor:${id}:*`);
            metricsCollector.increment('advisor.media_uploaded', { id, mediaCount: files.length });
            metricsCollector.timing('advisor.media_upload_time', Date.now() - startTime);
            eventEmitter.emit('advisor.media_uploaded', { advisorId: id, mediaCount: files.length });

            await session.commitTransaction();
            return ApiResponse.success(res, {
                message: 'Media uploaded successfully',
                data: { id: advisor._id, mediaCount: mediaResults.length },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Media upload failed for advisor ${id}:`, { error: error.message });
            metricsCollector.increment('advisor.media_upload_failed', { id });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Bulk create advisors
     * POST /api/v1/advisors/:userId/bulk
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    bulkCreateAdvisors = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const advisorsData = req.body.advisors || [];

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        await bulkOperationsLimiter(req, res, () => { });

        if (!Array.isArray(advisorsData) || advisorsData.length === 0) {
            return next(new AppError('No advisors data provided', 400));
        }

        if (advisorsData.length > 50) {
            return next(new AppError('Cannot process more than 50 advisors at once', 400));
        }

        const userAdvisorCount = await Advisor.countDocuments({
            userId,
            'status': { $ne: 'deleted' },
        }).cache({ ttl: 300, key: `user_advisor_count_${userId}` });

        const limits = this.getUserLimits(req.user.accountType);
        if (userAdvisorCount + advisorsData.length > limits.maxAdvisors) {
            return next(new AppError(`Advisor limit would be exceeded (${limits.maxAdvisors})`, 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const validatedAdvisors = [];
            for (const advisorData of advisorsData) {
                const validation = validateAdvisor(advisorData);
                if (!validation.valid) {
                    throw new AppError(`Validation failed for advisor: ${validation.message}`, 400);
                }

                const sanitizedData = sanitizeInput(advisorData);
                sanitizedData.name = sanitizedData.name?.trim();
                sanitizedData.startDate = new Date(sanitizedData.startDate) || null;
                sanitizedData.endDate = sanitizedData.endDate ? new Date(sanitizedData.endDate) : null;

                if (sanitizedData.schoolId) {
                    const school = await this.schoolService.getSchoolById(sanitizedData.schoolId, { session });
                    if (!school || school.status !== 'active') {
                        throw new AppError(`Invalid school association for advisor: ${sanitizedData.name}`, 400);
                    }
                }

                validatedAdvisors.push({
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
                        importSource: sanitizedData.metadata?.importSource || 'bulk',
                        version: 1,
                        updateCount: 0,
                    },
                    analytics: {
                        views: { total: 0, unique: 0, byDate: [] },
                        endorsements: { total: 0, byUser: [] },
                        interactions: { total: 0, byType: {} },
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
                });
            }

            const advisors = await Advisor.insertMany(validatedAdvisors, { session });

            for (const advisor of advisors) {
                this.processNewAdvisorAsync(advisor._id, userId).catch((err) => {
                    logger.error(`Async processing failed for advisor ${advisor._id}:`, err);
                });
            }

            metricsCollector.increment('advisor.bulk_created', { userId, count: advisors.length });
            metricsCollector.timing('advisor.bulk_create_time', Date.now() - startTime);
            eventEmitter.emit('advisor.bulk_created', { userId, count: advisors.length });

            await session.commitTransaction();
            return ApiResponse.success(res, {
                message: `Successfully created ${advisors.length} advisors`,
                data: { count: advisors.length, advisorIds: advisors.map(a => a._id) },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk advisor creation failed for user ${userId}:`, { error: error.message });
            metricsCollector.increment('advisor.bulk_create_failed', { userId });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Get advisor analytics
     * GET /api/v1/advisors/:userId/:id/analytics
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    getAdvisorAnalytics = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        await analyticsLimiter(req, res, () => { });

        const cacheKey = `advisor_analytics:${id}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('advisor.analytics_cache_hit', { id });
                return ApiResponse.success(res, cached);
            }

            const advisor = await Advisor.findOne({ _id: id, userId })
                .select('analytics')
                .lean();

            if (!advisor) {
                return next(new AppError('Advisor not found', 404));
            }

            const analytics = await this.computeAnalytics(advisor.analytics);
            await cacheService.set(cacheKey, analytics, 300, ['advisor_analytics:' + id]);

            metricsCollector.increment('advisor.analytics_fetched', { id });
            metricsCollector.timing('advisor.analytics_time', Date.now() - startTime);

            return ApiResponse.success(res, { data: analytics });
        } catch (error) {
            logger.error(`Failed to fetch analytics for advisor ${id}:`, { error: error.message });
            metricsCollector.increment('advisor.analytics_failed', { id });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        }
    });

    /**
     * Search advisors
     * GET /api/v1/advisors/search
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    searchAdvisors = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const requestingUserId = req.user.id;
        const {
            query,
            page = 1,
            limit = 20,
            schoolId,
            fieldOfStudy,
            sortBy = 'relevance',
        } = req.query;

        await searchLimiter(req, res, () => { });

        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
        const from = (pageNum - 1) * limitNum;

        const cacheKey = `advisor_search:${requestingUserId}:${JSON.stringify({ query, page, limit, schoolId, fieldOfStudy, sortBy })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('advisor.search_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const esQuery = this.buildElasticsearchQuery({ query, schoolId, fieldOfStudy });
            const sortOption = this.buildSearchSortOption(sortBy);

            const esResponse = await elasticsearchClient.search({
                index: 'advisors',
                from,
                size: limitNum,
                body: {
                    query: esQuery,
                    sort: sortOption,
                },
            });

            const advisorIds = esResponse.hits.hits.map(hit => hit._id);
            const advisors = await Advisor.find({ _id: { $in: advisorIds } })
                .read('secondaryPreferred')
                .select('-__v')
                .populate('schoolId', 'name type')
                .populate('educationId', 'degreeLevel fieldOfStudy')
                .lean({ virtuals: true });

            const totalCount = esResponse.hits.total.value;
            const result = {
                advisors,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages: Math.ceil(totalCount / limitNum),
                    hasNext: pageNum < Math.ceil(totalCount / limitNum),
                    hasPrev: pageNum > 1,
                },
            };

            await cacheService.set(cacheKey, result, 300, ['advisor_search']);
            metricsCollector.increment('advisor.search', { count: advisors.length });
            metricsCollector.timing('advisor.search_time', Date.now() - startTime);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Advisor search failed:`, { error: error.message });
            metricsCollector.increment('advisor.search_failed');
            throw error instanceof AppError ? error : new AppError('Search failed', 500);
        }
    });

    /**
     * Export advisor data
     * GET /api/v1/advisors/:userId/export
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    exportAdvisors = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { format = 'json' } = req.query;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        try {
            const advisors = await Advisor.find({ userId, status: { $ne: 'deleted' } })
                .read('secondaryPreferred')
                .select('-__v')
                .populate('schoolId', 'name type')
                .populate('educationId', 'degreeLevel fieldOfStudy')
                .lean();

            const exportData = this.formatExportData(advisors, format);
            const fileName = `advisors_${userId}_${Date.now()}.${format}`;
            const s3Key = `exports/advisors/${userId}/${fileName}`;

            await s3Client.upload({
                Bucket: 'user-exports',
                Key: s3Key,
                Body: Buffer.from(JSON.stringify(exportData)),
                ContentType: format === 'json' ? 'application/json' : 'text/csv',
            }).promise();

            const downloadUrl = await s3Client.getSignedUrlPromise('getObject', {
                Bucket: 'user-exports',
                Key: s3Key,
                Expires: 3600, // 1 hour
            });

            metricsCollector.increment('advisor.exported', { userId, format });
            metricsCollector.timing('advisor.export_time', Date.now() - startTime);
            eventEmitter.emit('advisor.exported', { userId, fileName, format });

            return ApiResponse.success(res, {
                message: 'Advisors exported successfully',
                data: { downloadUrl, fileName },
            });
        } catch (error) {
            logger.error(`Advisor export failed for user ${userId}:`, { error: error.message });
            metricsCollector.increment('advisor.export_failed', { userId });
            throw error instanceof AppError ? error : new AppError('Export failed', 500);
        }
    });

    /**
     * Import advisors
     * POST /api/v1/advisors/:userId/import
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    importAdvisors = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { advisors, source } = req.body;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        await bulkOperationsLimiter(req, res, () => { });

        if (!Array.isArray(advisors) || advisors.length === 0) {
            return next(new AppError('No advisors data provided', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const validatedAdvisors = [];
            for (const advisorData of advisors) {
                const validation = validateAdvisor(advisorData);
                if (!validation.valid) {
                    throw new AppError(`Validation failed for advisor: ${validation.message}`, 400);
                }

                const sanitizedData = sanitizeInput(advisorData);
                validatedAdvisors.push({
                    ...sanitizedData,
                    userId,
                    metadata: {
                        createdBy: {
                            userId: requestingUserId,
                            ip: req.ip,
                            userAgent: req.get('User-Agent'),
                            location: req.geoip || { country: 'unknown', city: 'unknown' },
                        },
                        importSource: source || 'import',
                        version: 1,
                        updateCount: 0,
                    },
                    analytics: {
                        views: { total: 0, unique: 0, byDate: [] },
                        endorsements: { total: 0, byUser: [] },
                        interactions: { total: 0, byType: {} },
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
                });
            }

            const insertedAdvisors = await Advisor.insertMany(validatedAdvisors, { session });

            for (const advisor of insertedAdvisors) {
                this.processNewAdvisorAsync(advisor._id, userId).catch((err) => {
                    logger.error(`Async processing failed for advisor ${advisor._id}:`, err);
                });
            }

            metricsCollector.increment('advisor.imported', { userId, count: insertedAdvisors.length });
            metricsCollector.timing('advisor.import_time', Date.now() - startTime);
            eventEmitter.emit('advisor.imported', { userId, count: insertedAdvisors.length });

            await session.commitTransaction();
            return ApiResponse.success(res, {
                message: `Successfully imported ${insertedAdvisors.length} advisors`,
                data: { count: insertedAdvisors.length, advisorIds: insertedAdvisors.map(a => a._id) },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Advisor import failed for user ${userId}:`, { error: error.message });
            metricsCollector.increment('advisor.import_failed', { userId });
            throw error instanceof AppError ? error : new AppError('Import failed', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Get advisor recommendations
     * GET /api/v1/advisors/:userId/recommendations
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    getAdvisorRecommendations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { limit = 10 } = req.query;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        try {
            const userAdvisors = await Advisor.find({ userId, status: { $ne: 'deleted' } })
                .select('schoolId fieldOfStudy')
                .lean();

            const recommendations = await this.generateRecommendations(userAdvisors, parseInt(limit));
            metricsCollector.increment('advisor.recommendations_fetched', { userId, count: recommendations.length });
            metricsCollector.timing('advisor.recommendations_time', Date.now() - startTime);

            return ApiResponse.success(res, {
                message: 'Recommendations generated successfully',
                data: recommendations,
            });
        } catch (error) {
            logger.error(`Failed to fetch recommendations for user ${userId}:`, { error: error.message });
            metricsCollector.increment('advisor.recommendations_failed', { userId });
            throw error instanceof AppError ? error : new AppError('Failed to generate recommendations', 500);
        }
    });

    // Helper methods
    getUserLimits(accountType) {
        const limits = {
            free: { maxAdvisors: 10, maxMedia: 5 },
            premium: { maxAdvisors: 50, maxMedia: 20 },
            enterprise: { maxAdvisors: 500, maxMedia: 100 },
        };
        return limits[accountType] || limits.free;
    }

    buildAdvisorQuery({ userId, status, name, schoolId, educationId, startDate, endDate, search, tags }) {
        const query = { userId, status: { $ne: 'deleted' } };
        if (status) query.status = status;
        if (name) query.name = { $regex: name, $options: 'i' };
        if (schoolId) query.schoolId = mongoose.Types.ObjectId(schoolId);
        if (educationId) query.educationId = mongoose.Types.ObjectId(educationId);
        if (startDate) query.startDate = { $gte: new Date(startDate) };
        if (endDate) query.endDate = { $lte: new Date(endDate) };
        if (search) query.$text = { $search: search };
        if (tags) query.tags = { $all: tags.split(',').map(t => t.trim()) };
        return query;
    }

    buildSortOption(sortBy) {
        const sortOptions = {
            recent: { createdAt: -1 },
            name: { name: 1 },
            startDate: { startDate: -1 },
        };
        return sortOptions[sortBy] || sortOptions.recent;
    }

    buildElasticsearchQuery({ query, schoolId, fieldOfStudy }) {
        const boolQuery = {
            must: [],
            filter: [{ term: { searchable: true } }],
        };
        if (query) {
            boolQuery.must.push({
                multi_match: {
                    query,
                    fields: ['name^2', 'fieldOfStudy', 'description'],
                    fuzziness: 'AUTO',
                },
            });
        }
        if (schoolId) boolQuery.filter.push({ term: { schoolId } });
        if (fieldOfStudy) boolQuery.filter.push({ match: { fieldOfStudy } });
        return { bool: boolQuery };
    }

    buildSearchSortOption(sortBy) {
        const sortOptions = {
            relevance: { _score: 'desc' },
            recent: { createdAt: 'desc' },
            name: { name: 'asc' },
        };
        return sortOptions[sortBy] || sortOptions.relevance;
    }

    async indexForSearch(advisor) {
        try {
            await elasticsearchClient.index({
                index: 'advisors',
                id: advisor._id.toString(),
                body: {
                    userId: advisor.userId,
                    name: advisor.name,
                    email: advisor.email,
                    schoolId: advisor.schoolId,
                    educationId: advisor.educationId,
                    fieldOfStudy: advisor.fieldOfStudy,
                    status: advisor.status,
                    searchable: advisor.privacy.searchable,
                    createdAt: advisor.createdAt,
                },
            });
            metricsCollector.increment('advisor.indexed', { advisorId: advisor._id });
        } catch (error) {
            logger.error(`Failed to index advisor ${advisor._id}:`, { error: error.message });
        }
    }

    async createBackup(advisorId, action, userId, options = {}) {
        try {
            const advisor = await Advisor.findById(advisorId).session(options.session);
            if (!advisor) return;

            const backupKey = `backups/advisors/${advisorId}/${Date.now()}.json`;
            await s3Client.upload({
                Bucket: 'user-backups',
                Key: backupKey,
                Body: Buffer.from(JSON.stringify(advisor)),
                ContentType: 'application/json',
            }).promise();

            logger.info(`Backup created for advisor ${advisorId} by ${userId} for action ${action}`);
            metricsCollector.increment('advisor.backup_created', { advisorId, action });
        } catch (error) {
            logger.error(`Backup failed for advisor ${advisorId}:`, { error: error.message });
        }
    }

    async checkConnectionAccess(ownerId, requesterId) {
        // Placeholder for connection-based access logic
        return ownerId === requesterId;
    }

    getAllowedUpdateFields() {
        return [
            'name',
            'email',
            'description',
            'startDate',
            'endDate',
            'schoolId',
            'educationId',
            'fieldOfStudy',
            'tags',
            'privacy',
            'settings',
        ];
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

    validateMediaUpload(files) {
        const maxSize = 5 * 1024 * 1024; // 5MB
        const allowedTypes = ['image/jpeg', 'image/png', 'application/pdf'];
        for (const file of files) {
            if (file.size > maxSize) {
                return { valid: false, message: `File ${file.originalname} exceeds 5MB` };
            }
            if (!allowedTypes.includes(file.mimetype)) {
                return { valid: false, message: `File ${file.originalname} has invalid type` };
            }
        }
        return { valid: true };
    }

    async processNewAdvisorAsync(advisorId, userId) {
        try {
            const advisor = await Advisor.findById(advisorId);
            if (!advisor) return;

            await this.circuitBreaker.fire(async () => {
                await retry(() => this.verificationService.verifyAdvisor({
                    advisorId,
                    userId,
                    name: advisor.name,
                    email: advisor.email,
                    schoolId: advisor.schoolId,
                    educationId: advisor.educationId,
                }), this.retryConfig);
            });

            await this.indexForSearch(advisor);
            metricsCollector.increment('advisor.async_processed', { advisorId });
        } catch (error) {
            logger.error(`Async processing failed for advisor ${advisorId}:`, { error: error.message });
        }
    }

    async processExternalVerification(advisorId, userId) {
        try {
            const advisor = await Advisor.findById(advisorId);
            if (!advisor) return;

            await this.circuitBreaker.fire(async () => {
                await retry(() => this.verificationService.verifyAdvisor({
                    advisorId,
                    userId,
                    name: advisor.name,
                    email: advisor.email,
                    schoolId: advisor.schoolId,
                    educationId: advisor.educationId,
                }), this.retryConfig);
            });
            metricsCollector.increment('advisor.verification_processed', { advisorId });
        } catch (error) {
            logger.error(`External verification failed for advisor ${advisorId}:`, { error: error.message });
        }
    }

    async updateAnalytics(advisor, viewerId) {
        try {
            advisor.analytics.views.total += 1;
            if (!advisor.analytics.views.byDate) advisor.analytics.views.byDate = [];
            const today = moment().startOf('day').toDate();
            const viewEntry = advisor.analytics.views.byDate.find(v => v.date.toDateString() === today.toDateString());
            if (viewEntry) {
                viewEntry.count += 1;
            } else {
                advisor.analytics.views.byDate.push({ date: today, count: 1 });
            }
            await advisor.save();
        } catch (error) {
            logger.error(`Failed to update analytics for advisor ${advisor._id}:`, { error: error.message });
        }
    }

    async computeAnalytics(analytics) {
        const viewsByMonth = analytics.views.byDate.reduce((acc, entry) => {
            const month = moment(entry.date).format('YYYY-MM');
            acc[month] = (acc[month] || 0) + entry.count;
            return acc;
        }, {});

        return {
            totalViews: analytics.views.total,
            uniqueViews: analytics.views.unique,
            viewsByMonth,
            endorsements: analytics.endorsements.total,
            interactions: analytics.interactions.total,
        };
    }

    async generateRecommendations(userAdvisors, limit) {
        // Placeholder for recommendation logic based on schoolId and fieldOfStudy
        const schoolIds = userAdvisors.map(a => a.schoolId).filter(Boolean);
        const fields = userAdvisors.map(a => a.fieldOfStudy).filter(Boolean);

        const recommendedAdvisors = await Advisor.find({
            schoolId: { $in: schoolIds },
            fieldOfStudy: { $in: fields },
            status: { $ne: 'deleted' },
            'privacy.searchable': true,
        })
            .limit(limit)
            .select('name schoolId fieldOfStudy')
            .lean();

        return recommendedAdvisors;
    }

    formatExportData(advisors, format) {
        if (format === 'csv') {
            const headers = ['id', 'name', 'email', 'schoolId', 'educationId', 'fieldOfStudy', 'startDate', 'status'];
            const csvRows = [headers.join(',')];
            for (const advisor of advisors) {
                const row = [
                    advisor._id,
                    `"${advisor.name}"`,
                    advisor.email || '',
                    advisor.schoolId?._id || '',
                    advisor.educationId?._id || '',
                    advisor.fieldOfStudy || '',
                    advisor.startDate || '',
                    advisor.status,
                ];
                csvRows.push(row.join(','));
            }
            return csvRows.join('\n');
        }
        return advisors; // Default JSON
    }
}

export default new AdvisorController();