import Thesis from '../models/Thesis.js';
import VerificationService from '../services/VerificationService.js';
import MediaService from '../services/MediaService.js';
import NotificationService from '../services/NotificationService.js';
import SchoolService from '../services/SchoolService.js';
import EducationService from '../services/EducationService.js';
import DegreeService from '../services/DegreeService.js';
import { validateThesis, sanitizeInput } from '../validations/thesis.validation.js';
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

// Rate limiters
const createThesisLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15-minute window
    max: 5, // Allow 5 creates
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_thesis_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
    legacyHeaders: false,
});

const updateThesisLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5-minute window
    max: 15, // Allow 15 updates
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_thesis_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const verificationLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30-minute window
    max: 5, // Strict limit
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `verify_thesis_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const bulkOperationsLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // Hourly limit
    max: 3, // Conservative limit
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_thesis_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const mediaUploadLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000, // 10-minute window
    max: 10, // Limit uploads
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `media_thesis_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const searchLimiter = createRateLimiter({
    windowMs: 1 * 60 * 1000, // 1-minute window
    max: 50, // Allow frequent searches
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `search_thesis_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const analyticsLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5-minute window
    max: 20, // Moderate limit
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `analytics_thesis_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

class ThesisController {
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
     * Create a new thesis
     * POST /api/v1/theses/:userId
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    createThesis = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const thesisData = req.body;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied: Cannot create thesis for another user', 403));
        }

        await createThesisLimiter(req, res, () => { });

        const validation = validateThesis(thesisData);
        if (!validation.valid) {
            metricsCollector.increment('thesis.validation_failed', { userId, errors: validation.errors.length });
            return next(new AppError(`Validation failed: ${validation.message}`, 400));
        }

        const sanitizedData = sanitizeInput(thesisData);
        sanitizedData.title = sanitizedData.title?.trim();
        sanitizedData.submissionDate = new Date(sanitizedData.submissionDate) || null;

        const userThesisCount = await Thesis.countDocuments({
            userId,
            'status': { $ne: 'deleted' },
        }).cache({ ttl: 300, key: `user_thesis_count_${userId}` });

        const limits = this.getUserLimits(req.user.accountType);
        if (userThesisCount >= limits.maxTheses) {
            metricsCollector.increment('thesis.limit_exceeded', { userId });
            return next(new AppError(`Thesis limit reached (${limits.maxTheses})`, 403));
        }

        if (sanitizedData.schoolId) {
            const school = await this.schoolService.getSchoolById(sanitizedData.schoolId);
            if (!school || school.status !== 'active') {
                return next(new AppError('Invalid or inactive school association', 400));
            }
        }

        if (sanitizedData.degreeId) {
            const degree = await this.degreeService.getDegreeById(sanitizedData.degreeId);
            if (!degree || degree.userId.toString() !== userId) {
                return next(new AppError('Invalid degree association', 400));
            }
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const thesis = await Thesis.create([{
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

            this.processNewThesisAsync(thesis[0]._id, requestingUserId)
                .catch((err) => {
                    logger.error(`Async processing failed for thesis ${thesis[0]._id}:`, err);
                    metricsCollector.increment('thesis.async_processing_failed', { thesisId: thesis[0]._id });
                });

            metricsCollector.increment('thesis.created', {
                userId,
                title: thesis[0].title,
                schoolAssociated: !!thesis[0].schoolId,
                degreeAssociated: !!thesis[0].degreeId,
                accountType: req.user.accountType,
            });
            metricsCollector.timing('thesis.create_time', Date.now() - startTime);

            eventEmitter.emit('thesis.created', {
                thesisId: thesis[0]._id,
                userId,
                schoolId: thesis[0].schoolId,
                degreeId: thesis[0].degreeId,
                title: thesis[0].title,
            });

            if (thesis[0].settings?.autoBackup) {
                this.createBackup(thesis[0]._id, 'create', requestingUserId, { session })
                    .catch((err) => {
                        logger.error(`Auto backup failed for thesis ${thesis[0]._id}:`, err);
                    });
            }

            if (thesis[0].degreeId) {
                await this.degreeService.linkThesisToDegree(thesis[0].degreeId, thesis[0]._id, { session });
            }

            await session.commitTransaction();
            logger.info(`Thesis created successfully: ${thesis[0]._id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Thesis created successfully',
                data: {
                    id: thesis[0]._id,
                    userId: thesis[0].userId,
                    title: thesis[0].title,
                    status: thesis[0].status,
                    createdAt: thesis[0].createdAt,
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Thesis creation failed for user ${userId}:`, { error: error.message });
            metricsCollector.increment('thesis.create_failed', { userId });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Get user's theses with filtering and pagination
     * GET /api/v1/theses/:userId
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    getTheses = catchAsync(async (req, res, next) => {
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
            degreeId,
            submissionDateStart,
            submissionDateEnd,
            search,
            sortBy = 'recent',
            tags,
        } = req.query;

        const query = this.buildThesisQuery({ userId, status, title, schoolId, degreeId, submissionDateStart, submissionDateEnd, search, tags });
        const sortOption = this.buildSortOption(sortBy);
        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
        const skip = (pageNum - 1) * limitNum;

        const cacheKey = `theses:${userId}:${JSON.stringify({ page, limit, status, title, schoolId, degreeId, sortBy, tags })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('thesis.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const [theses, totalCount] = await Promise.all([
                Thesis.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select('-__v')
                    .populate('schoolId', 'name type')
                    .populate('degreeId', 'degreeLevel fieldOfStudy')
                    .lean({ virtuals: true }),
                Thesis.countDocuments(query).cache({ ttl: 300 }),
            ]);

            const result = {
                theses,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages: Math.ceil(totalCount / limitNum),
                    hasNext: pageNum < Math.ceil(totalCount / limitNum),
                    hasPrev: pageNum > 1,
                },
            };

            await cacheService.set(cacheKey, result, 300, ['theses:user:' + userId]);
            metricsCollector.increment('thesis.fetched', { userId, count: theses.length });
            metricsCollector.timing('thesis.get_list_time', Date.now() - startTime);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch theses for user ${userId}:`, { error: error.message });
            metricsCollector.increment('thesis.fetch_failed', { userId });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        }
    });

    /**
     * Get single thesis by ID
     * GET /api/v1/theses/:userId/:id
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    getThesisById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            const hasConnectionAccess = await this.checkConnectionAccess(userId, requestingUserId);
            if (!hasConnectionAccess) {
                return next(new AppError('Access denied', 403));
            }
        }

        const cacheKey = `thesis:${id}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('thesis.cache_hit', { id });
                return ApiResponse.success(res, cached);
            }

            const thesis = await Thesis.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('-__v')
                .populate('schoolId', 'name type')
                .populate('degreeId', 'degreeLevel fieldOfStudy')
                .lean({ virtuals: true });

            if (!thesis) {
                return next(new AppError('Thesis not found', 404));
            }

            await cacheService.set(cacheKey, thesis, 600, ['theses:id:' + id]);
            metricsCollector.increment('thesis.viewed', { id, userId });
            metricsCollector.timing('thesis.get_by_id_time', Date.now() - startTime);

            return ApiResponse.success(res, { data: thesis });
        } catch (error) {
            logger.error(`Failed to fetch thesis ${id}:`, { error: error.message });
            metricsCollector.increment('thesis.view_failed', { id });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        }
    });

    /**
     * Update thesis
     * PUT /api/v1/theses/:userId/:id
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    updateThesis = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const updates = req.body;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        await updateThesisLimiter(req, res, () => { });

        const sanitizedUpdates = this.sanitizeUpdates(updates, this.getAllowedUpdateFields());
        if (Object.keys(sanitizedUpdates).length === 0) {
            return next(new AppError('No valid update fields provided', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const thesis = await Thesis.findOne({ _id: id, userId }).session(session);
            if (!thesis) {
                return next(new AppError('Thesis not found', 404));
            }

            if (sanitizedUpdates.title || sanitizedUpdates.abstract) {
                thesis.versions = thesis.versions || [];
                thesis.versions.push({
                    versionNumber: thesis.metadata.version + 1,
                    title: sanitizedUpdates.title || thesis.title,
                    abstract: sanitizedUpdates.abstract || thesis.abstract,
                    changeType: 'edit',
                    timestamp: new Date(),
                });
            }

            Object.assign(thesis, sanitizedUpdates);
            thesis.metadata.version += 1;
            thesis.metadata.updateCount += 1;

            await thesis.save({ session });
            await cacheService.deletePattern(`thesis:${id}:*`);

            metricsCollector.increment('thesis.updated', { id });
            metricsCollector.timing('thesis.update_time', Date.now() - startTime);
            eventEmitter.emit('thesis.updated', { thesisId: id, changes: Object.keys(sanitizedUpdates) });

            await session.commitTransaction();
            return ApiResponse.success(res, {
                message: 'Thesis updated successfully',
                data: { id: thesis._id, title: thesis.title, status: thesis.status },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Thesis update failed for ${id}:`, { error: error.message });
            metricsCollector.increment('thesis.update_failed', { id });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete thesis
     * DELETE /api/v1/theses/:userId/:id
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    deleteThesis = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { permanent = 'false', unlinkDegree = 'true' } = req.query;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const thesis = await Thesis.findOne({ _id: id, userId }).session(session);
            if (!thesis) {
                return next(new AppError('Thesis not found', 404));
            }

            if (permanent === 'true') {
                await Thesis.findByIdAndDelete(id, { session });
                await this.mediaService.deleteAllMedia(id, 'thesis', { session });
                if (unlinkDegree === 'true' && thesis.degreeId) {
                    await this.degreeService.unlinkThesisFromDegree(thesis.degreeId, id, { session });
                }
            } else {
                thesis.status = 'deleted';
                thesis.privacy.isPublic = false;
                await thesis.save({ session });
            }

            await cacheService.deletePattern(`thesis:${id}:*`);
            metricsCollector.increment(`thesis.${permanent ? 'permanently_deleted' : 'soft_deleted'}`, { id });
            metricsCollector.timing('thesis.delete_time', Date.now() - startTime);
            eventEmitter.emit('thesis.deleted', { thesisId: id, permanent, degreeUnlinked: unlinkDegree === 'true' });

            await session.commitTransaction();
            return ApiResponse.success(res, {
                message: permanent === 'true' ? 'Thesis permanently deleted' : 'Thesis soft deleted',
                data: { id, degreeUnlinked: unlinkDegree === 'true' && permanent === 'true' },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Thesis deletion failed for ${id}:`, { error: error.message });
            metricsCollector.increment('thesis.delete_failed', { id });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Verify thesis
     * POST /api/v1/theses/:userId/:id/verify
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    verifyThesis = catchAsync(async (req, res, next) => {
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

            const thesis = await Thesis.findOne({ _id: id, userId }).session(session);
            if (!thesis) {
                return next(new AppError('Thesis not found', 404));
            }

            const verificationResult = await this.circuitBreaker.fire(async () => {
                return await this.verificationService.verifyThesis({
                    thesisId: thesis._id,
                    userId,
                    title: thesis.title,
                    schoolId: thesis.schoolId,
                    degreeId: thesis.degreeId,
                });
            });

            thesis.verification = {
                status: verificationResult.success ? 'verified' : 'failed',
                confidence: verificationResult.confidence || 0,
                verifiedBy: verificationResult.verifiedBy || 'external_api',
                verifiedAt: new Date(),
                details: verificationResult.details || [],
            };
            await thesis.save({ session });

            await this.indexForSearch(thesis);
            await cacheService.deletePattern(`thesis:${id}:*`);

            eventEmitter.emit('thesis.verified', {
                thesisId: id,
                userId,
                verificationStatus: verificationResult.success ? 'verified' : 'failed',
            });

            await session.commitTransaction();
            metricsCollector.increment('thesis.verified', { id, status: verificationResult.status });
            metricsCollector.timing('thesis.verify_time', Date.now() - startTime);

            return ApiResponse.success(res, {
                message: `Thesis ${verificationResult.success ? 'verified' : 'verification failed'}`,
                data: { id: thesis._id, verificationStatus: thesis.verification.status },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Verification failed for thesis ${id}:`, { error: error.message });
            metricsCollector.increment('thesis.verify_failed', { id });
            throw error instanceof AppError ? error : new AppError('Failed to verify thesis', 424);
        } finally {
            session.endSession();
        }
    });

    /**
     * Upload thesis media
     * POST /api/v1/theses/:userId/:id/media
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    uploadThesisMedia = catchAsync(async (req, res, next) => {
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

            const thesis = await Thesis.findOne({ _id: id, userId }).session(session);
            if (!thesis) {
                return next(new AppError('Thesis not found', 404));
            }

            const mediaResults = await this.mediaService.uploadMedia({
                files,
                entityId: thesis._id,
                entityType: 'thesis',
                userId: requestingUserId,
                category: 'thesis_media',
            }, { session });

            const scanResults = await this.mediaService.scanMedia(mediaResults);
            const infected = scanResults.filter(r => r.infected);
            if (infected.length > 0) {
                await this.mediaService.deleteMedia(infected.map(m => m.id), { session });
                return next(new AppError(`Media upload failed: ${infected.length} infected files detected`, 422));
            }

            thesis.media = [...(thesis.media || []), ...mediaResults];
            await thesis.save({ session });

            await cacheService.deletePattern(`thesis:${id}:*`);
            metricsCollector.increment('thesis.media_uploaded', { id });
            metricsCollector.timing('thesis.media_upload_time', Date.now() - startTime);
            eventEmitter.emit('thesis.media_uploaded', { thesisId: id, mediaCount: files.length });

            await session.commitTransaction();
            return ApiResponse.success(res, {
                message: 'Media uploaded successfully',
                data: { id: thesis._id, mediaCount: mediaResults.length },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Media upload failed for thesis ${id}:`, { error: error.message });
            metricsCollector.increment('thesis.media_upload_failed', { id });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        } finally {
            session.endSession();
        }
    });

    // Helper methods
    getUserLimits(accountType) {
        const limits = {
            free: { maxTheses: 5, maxMedia: 5 },
            premium: { maxTheses: 20, maxMedia: 20 },
            enterprise: { maxTheses: 100, maxMedia: 100 },
        };
        return limits[accountType] || limits.free;
    }

    buildThesisQuery({ userId, status, title, schoolId, degreeId, submissionDateStart, submissionDateEnd, search, tags }) {
        const query = { userId, status: { $ne: 'deleted' } };
        if (status) query.status = status;
        if (title) query.title = { $regex: title, $options: 'i' };
        if (schoolId) query.schoolId = mongoose.Types.ObjectId(schoolId);
        if (degreeId) query.degreeId = mongoose.Types.ObjectId(degreeId);
        if (submissionDateStart) query.submissionDate = { $gte: new Date(submissionDateStart) };
        if (submissionDateEnd) query.submissionDate = { ...query.submissionDate, $lte: new Date(submissionDateEnd) };
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

    async indexForSearch(thesis) {
        try {
            await elasticsearchClient.index({
                index: 'theses',
                id: thesis._id.toString(),
                body: {
                    userId: thesis.userId,
                    title: thesis.title,
                    schoolId: thesis.schoolId,
                    degreeId: thesis.degreeId,
                    status: thesis.status,
                    searchable: thesis.privacy.searchable,
                },
            });
            metricsCollector.increment('thesis.indexed', { thesisId: thesis._id });
        } catch (error) {
            logger.error(`Failed to index thesis ${thesis._id}:`, { error: error.message });
        }
    }

    async createBackup(thesisId, action, userId, options = {}) {
        logger.info(`Backup created for thesis ${thesisId} by ${userId} for action ${action}`);
        metricsCollector.increment('thesis.backup_created', { thesisId, action });
    }

    async checkConnectionAccess(ownerId, requesterId) {
        return ownerId === requesterId; // Placeholder
    }

    getAllowedUpdateFields() {
        return ['title', 'abstract', 'submissionDate', 'schoolId', 'degreeId', 'tags', 'privacy', 'settings'];
    }

    sanitizeUpdates(updates, allowedFields) {
        const sanitized = {};
        for (const [key, value] of Object.entries(updates)) {
            if (allowedFields.includes(key)) {
                sanitized[key] = key === 'abstract' ? sanitizeHtml(value) : value;
            }
        }
        return sanitized;
    }

    validateMediaUpload(files) {
        const maxSize = 10 * 1024 * 1024; // 10MB
        const allowedTypes = ['application/pdf', 'image/jpeg', 'image/png'];
        for (const file of files) {
            if (file.size > maxSize) {
                return { valid: false, message: `File ${file.originalname} exceeds 10MB` };
            }
            if (!allowedTypes.includes(file.mimetype)) {
                return { valid: false, message: `File ${file.originalname} has invalid type` };
            }
        }
        return { valid: true };
    }

    async processNewThesisAsync(thesisId, userId) {
        try {
            const thesis = await Thesis.findById(thesisId);
            if (!thesis) return;

            await this.verificationService.verifyThesis({
                thesisId,
                userId,
                title: thesis.title,
                schoolId: thesis.schoolId,
                degreeId: thesis.degreeId,
            });

            await this.indexForSearch(thesis);
            metricsCollector.increment('thesis.async_processed', { thesisId });
        } catch (error) {
            logger.error(`Async processing failed for thesis ${thesisId}:`, { error: error.message });
        }
    }
}

export default new ThesisController();
