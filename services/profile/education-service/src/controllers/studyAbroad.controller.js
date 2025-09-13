import StudyAbroad from '../models/StudyAbroad.js';
import VerificationService from '../services/VerificationService.js';
import MediaService from '../services/MediaService.js';
import NotificationService from '../services/NotificationService.js';
import SchoolService from '../services/SchoolService.js';
import EducationService from '../services/EducationService.js';
import { validateStudyAbroad, sanitizeInput } from '../validations/studyAbroad.validation.js';
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
const createStudyAbroadLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15-minute window
    max: 10, // Allow 10 creates per user per IP
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_study_abroad_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
    legacyHeaders: false,
});

const updateStudyAbroadLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5-minute window
    max: 20, // Allow 20 updates
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_study_abroad_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const verificationLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30-minute window
    max: 5, // Strict limit for external API calls
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `verify_study_abroad_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const bulkOperationsLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // Hourly limit
    max: 3, // Conservative limit for bulk operations
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_study_abroad_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const mediaUploadLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000, // 10-minute window
    max: 10, // Limit uploads
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `media_study_abroad_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const searchLimiter = createRateLimiter({
    windowMs: 1 * 60 * 1000, // 1-minute window
    max: 50, // Allow frequent searches
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `search_study_abroad_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const analyticsLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5-minute window
    max: 20, // Moderate limit for analytics requests
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `analytics_study_abroad_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

class StudyAbroadController {
    constructor() {
        this.verificationService = VerificationService;
        this.mediaService = MediaService;
        this.notificationService = NotificationService;
        this.schoolService = SchoolService;
        this.educationService = EducationService;
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
     * Create a new study abroad record
     * POST /api/v1/study-abroad/:userId
     * Creates a study abroad record with validation, async processing, and transaction support.
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    createStudyAbroad = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const studyAbroadData = req.body;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied: Cannot create study abroad record for another user', 403));
        }

        await createStudyAbroadLimiter(req, res, () => { });

        const validation = validateStudyAbroad(studyAbroadData);
        if (!validation.valid) {
            metricsCollector.increment('study_abroad.validation_failed', { userId, errors: validation.errors.length });
            return next(new AppError(`Validation failed: ${validation.message}`, 400));
        }

        const sanitizedData = sanitizeInput(studyAbroadData);
        sanitizedData.programName = sanitizedData.programName?.trim();
        sanitizedData.startDate = new Date(sanitizedData.startDate) || null;
        sanitizedData.endDate = sanitizedData.endDate ? new Date(sanitizedData.endDate) : null;

        const userStudyAbroadCount = await StudyAbroad.countDocuments({
            userId,
            'status': { $ne: 'deleted' },
        }).cache({ ttl: 300, key: `user_study_abroad_count_${userId}` });

        const limits = this.getUserLimits(req.user.accountType);
        if (userStudyAbroadCount >= limits.maxStudyAbroad) {
            metricsCollector.increment('study_abroad.limit_exceeded', { userId });
            return next(new AppError(`Study abroad limit reached (${limits.maxStudyAbroad})`, 403));
        }

        if (sanitizedData.institutionId) {
            const institution = await this.schoolService.getSchoolById(sanitizedData.institutionId);
            if (!institution || institution.status !== 'active') {
                return next(new AppError('Invalid or inactive institution association', 400));
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

            const studyAbroad = await StudyAbroad.create([{
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

            this.processNewStudyAbroadAsync(studyAbroad[0]._id, requestingUserId)
                .catch((err) => {
                    logger.error(`Async processing failed for study abroad ${studyAbroad[0]._id}:`, err);
                    metricsCollector.increment('study_abroad.async_processing_failed', { studyAbroadId: studyAbroad[0]._id });
                });

            metricsCollector.increment('study_abroad.created', {
                userId,
                programName: studyAbroad[0].programName,
                institutionAssociated: !!studyAbroad[0].institutionId,
                educationAssociated: !!studyAbroad[0].educationId,
                accountType: req.user.accountType,
            });
            metricsCollector.timing('study_abroad.create_time', Date.now() - startTime);

            eventEmitter.emit('study_abroad.created', {
                studyAbroadId: studyAbroad[0]._id,
                userId,
                institutionId: studyAbroad[0].institutionId,
                educationId: studyAbroad[0].educationId,
                programName: studyAbroad[0].programName,
                country: studyAbroad[0].country,
            });

            if (studyAbroad[0].settings?.autoBackup) {
                await this.createBackup(studyAbroad[0]._id, 'create', requestingUserId, { session });
            }

            await session.commitTransaction();
            logger.info(`Study abroad created successfully: ${studyAbroad[0]._id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Study abroad record created successfully',
                data: {
                    id: studyAbroad[0]._id,
                    userId: studyAbroad[0].userId,
                    programName: studyAbroad[0].programName,
                    country: studyAbroad[0].country,
                    status: studyAbroad[0].status,
                    createdAt: studyAbroad[0].createdAt,
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Study abroad creation failed for user ${userId}:`, { error: error.message });
            metricsCollector.increment('study_abroad.create_failed', { userId });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Get user's study abroad records with filtering and pagination
     * GET /api/v1/study-abroad/:userId
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    getStudyAbroadRecords = catchAsync(async (req, res, next) => {
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
            programName,
            country,
            institutionId,
            educationId,
            startDate,
            endDate,
            search,
            sortBy = 'recent',
            tags,
        } = req.query;

        await searchLimiter(req, res, () => { });

        const query = this.buildStudyAbroadQuery({ userId, status, programName, country, institutionId, educationId, startDate, endDate, search, tags });
        const sortOption = this.buildSortOption(sortBy);
        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
        const skip = (pageNum - 1) * limitNum;

        const cacheKey = `study_abroad:${userId}:${JSON.stringify({ page, limit, status, programName, country, institutionId, educationId, sortBy, tags })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('study_abroad.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const [studyAbroadRecords, totalCount] = await Promise.all([
                StudyAbroad.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select('-__v')
                    .populate('institutionId', 'name type')
                    .populate('educationId', 'degreeLevel fieldOfStudy')
                    .lean({ virtuals: true }),
                StudyAbroad.countDocuments(query).cache({ ttl: 300 }),
            ]);

            const result = {
                studyAbroadRecords,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages: Math.ceil(totalCount / limitNum),
                    hasNext: pageNum < Math.ceil(totalCount / limitNum),
                    hasPrev: pageNum > 1,
                },
            };

            await cacheService.set(cacheKey, result, 300, ['study_abroad:user:' + userId]);
            metricsCollector.increment('study_abroad.fetched', { userId, count: studyAbroadRecords.length });
            metricsCollector.timing('study_abroad.get_list_time', Date.now() - startTime);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch study abroad records for user ${userId}:`, { error: error.message });
            metricsCollector.increment('study_abroad.fetch_failed', { userId });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        }
    });

    /**
     * Get single study abroad record by ID
     * GET /api/v1/study-abroad/:userId/:id
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    getStudyAbroadById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            const hasConnectionAccess = await this.checkConnectionAccess(userId, requestingUserId);
            if (!hasConnectionAccess) {
                return next(new AppError('Access denied', 403));
            }
        }

        const cacheKey = `study_abroad:${id}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('study_abroad.cache_hit', { id });
                return ApiResponse.success(res, cached);
            }

            const studyAbroad = await StudyAbroad.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('-__v')
                .populate('institutionId', 'name type')
                .populate('educationId', 'degreeLevel fieldOfStudy')
                .lean({ virtuals: true });

            if (!studyAbroad) {
                return next(new AppError('Study abroad record not found', 404));
            }

            await this.updateAnalytics(studyAbroad, requestingUserId);
            await cacheService.set(cacheKey, studyAbroad, 600, ['study_abroad:id:' + id]);
            metricsCollector.increment('study_abroad.viewed', { id, userId });
            metricsCollector.timing('study_abroad.get_by_id_time', Date.now() - startTime);

            return ApiResponse.success(res, { data: studyAbroad });
        } catch (error) {
            logger.error(`Failed to fetch study abroad ${id}:`, { error: error.message });
            metricsCollector.increment('study_abroad.view_failed', { id });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        }
    });

    /**
     * Update study abroad record
     * PUT /api/v1/study-abroad/:userId/:id
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    updateStudyAbroad = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const updates = req.body;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        await updateStudyAbroadLimiter(req, res, () => { });

        const sanitizedUpdates = this.sanitizeUpdates(updates, this.getAllowedUpdateFields());
        if (Object.keys(sanitizedUpdates).length === 0) {
            return next(new AppError('No valid update fields provided', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const studyAbroad = await StudyAbroad.findOne({ _id: id, userId }).session(session);
            if (!studyAbroad) {
                return next(new AppError('Study abroad record not found', 404));
            }

            if (sanitizedUpdates.programName || sanitizedUpdates.country) {
                studyAbroad.versions = studyAbroad.versions || [];
                studyAbroad.versions.push({
                    versionNumber: studyAbroad.metadata.version + 1,
                    programName: sanitizedUpdates.programName || studyAbroad.programName,
                    country: sanitizedUpdates.country || studyAbroad.country,
                    changeType: 'edit',
                    timestamp: new Date(),
                });
            }

            if (sanitizedUpdates.institutionId) {
                const institution = await this.schoolService.getSchoolById(sanitizedUpdates.institutionId, { session });
                if (!institution || institution.status !== 'active') {
                    return next(new AppError('Invalid or inactive institution association', 400));
                }
            }

            if (sanitizedUpdates.educationId) {
                const education = await this.educationService.getEducationById(sanitizedUpdates.educationId, { session });
                if (!education || education.userId.toString() !== userId) {
                    return next(new AppError('Invalid education association', 400));
                }
            }

            Object.assign(studyAbroad, sanitizedUpdates);
            studyAbroad.metadata.version += 1;
            studyAbroad.metadata.updateCount += 1;
            studyAbroad.metadata.lastModifiedBy = {
                userId: requestingUserId,
                timestamp: new Date(),
                changes: Object.keys(sanitizedUpdates),
            };

            if (['programName', 'country', 'institutionId'].some(field => sanitizedUpdates[field])) {
                studyAbroad.verification.status = 'pending';
                this.processExternalVerification(studyAbroad._id, userId).catch((err) => {
                    logger.error(`Re-verification failed for study abroad ${studyAbroad._id}:`, err);
                });
            }

            await studyAbroad.save({ session });
            await this.indexForSearch(studyAbroad);
            await cacheService.deletePattern(`study_abroad:${id}:*`);

            metricsCollector.increment('study_abroad.updated', { id });
            metricsCollector.timing('study_abroad.update_time', Date.now() - startTime);
            eventEmitter.emit('study_abroad.updated', { studyAbroadId: id, changes: Object.keys(sanitizedUpdates) });

            await session.commitTransaction();
            return ApiResponse.success(res, {
                message: 'Study abroad record updated successfully',
                data: { id: studyAbroad._id, programName: studyAbroad.programName, status: studyAbroad.status },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Study abroad update failed for ${id}:`, { error: error.message });
            metricsCollector.increment('study_abroad.update_failed', { id });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete study abroad record
     * DELETE /api/v1/study-abroad/:userId/:id
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    deleteStudyAbroad = catchAsync(async (req, res, next) => {
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

            const studyAbroad = await StudyAbroad.findOne({ _id: id, userId }).session(session);
            if (!studyAbroad) {
                return next(new AppError('Study abroad record not found', 404));
            }

            if (permanent === 'true') {
                await StudyAbroad.findByIdAndDelete(id, { session });
                await this.mediaService.deleteAllMedia(id, 'study_abroad', { session });
            } else {
                studyAbroad.status = 'deleted';
                studyAbroad.privacy.isPublic = false;
                studyAbroad.privacy.searchable = false;
                await studyAbroad.save({ session });
            }

            await cacheService.deletePattern(`study_abroad:${id}:*`);
            metricsCollector.increment(`study_abroad.${permanent ? 'permanently_deleted' : 'soft_deleted'}`, { id });
            metricsCollector.timing('study_abroad.delete_time', Date.now() - startTime);
            eventEmitter.emit('study_abroad.deleted', { studyAbroadId: id, permanent });

            await session.commitTransaction();
            return ApiResponse.success(res, {
                message: permanent === 'true' ? 'Study abroad record permanently deleted' : 'Study abroad record soft deleted',
                data: { id },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Study abroad deletion failed for ${id}:`, { error: error.message });
            metricsCollector.increment('study_abroad.delete_failed', { id });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Verify study abroad record
     * POST /api/v1/study-abroad/:userId/:id/verify
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    verifyStudyAbroad = catchAsync(async (req, res, next) => {
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

            const studyAbroad = await StudyAbroad.findOne({ _id: id, userId }).session(session);
            if (!studyAbroad) {
                return next(new AppError('Study abroad record not found', 404));
            }

            const verificationResult = await this.circuitBreaker.fire(async () => {
                return await retry(() => this.verificationService.verifyStudyAbroad({
                    studyAbroadId: studyAbroad._id,
                    userId,
                    programName: studyAbroad.programName,
                    country: studyAbroad.country,
                    institutionId: studyAbroad.institutionId,
                    educationId: studyAbroad.educationId,
                }), this.retryConfig);
            });

            studyAbroad.verification = {
                status: verificationResult.success ? 'verified' : 'failed',
                confidence: verificationResult.confidence || 0,
                verifiedBy: verificationResult.verifiedBy || 'external_api',
                verifiedAt: new Date(),
                details: verificationResult.details || [],
            };
            await studyAbroad.save({ session });

            await this.indexForSearch(studyAbroad);
            await cacheService.deletePattern(`study_abroad:${id}:*`);

            eventEmitter.emit('study_abroad.verified', {
                studyAbroadId: id,
                userId,
                verificationStatus: verificationResult.success ? 'verified' : 'failed',
            });

            await session.commitTransaction();
            metricsCollector.increment('study_abroad.verified', { id, status: verificationResult.status });
            metricsCollector.timing('study_abroad.verify_time', Date.now() - startTime);

            return ApiResponse.success(res, {
                message: `Study abroad record ${verificationResult.success ? 'verified' : 'verification failed'}`,
                data: { id: studyAbroad._id, verificationStatus: studyAbroad.verification.status },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Verification failed for study abroad ${id}:`, { error: error.message });
            metricsCollector.increment('study_abroad.verify_failed', { id });
            throw error instanceof AppError ? error : new AppError('Failed to verify study abroad record', 424);
        } finally {
            session.endSession();
        }
    });

    /**
     * Upload study abroad media
     * POST /api/v1/study-abroad/:userId/:id/media
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    uploadStudyAbroadMedia = catchAsync(async (req, res, next) => {
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

            const studyAbroad = await StudyAbroad.findOne({ _id: id, userId }).session(session);
            if (!studyAbroad) {
                return next(new AppError('Study abroad record not found', 404));
            }

            const mediaResults = await this.mediaService.uploadMedia({
                files,
                entityId: studyAbroad._id,
                entityType: 'study_abroad',
                userId: requestingUserId,
                category: 'study_abroad_media',
            }, { session });

            const scanResults = await this.mediaService.scanMedia(mediaResults);
            const infected = scanResults.filter(r => r.infected);
            if (infected.length > 0) {
                await this.mediaService.deleteMedia(infected.map(m => m.id), { session });
                return next(new AppError(`Media upload failed: ${infected.length} infected files detected`, 422));
            }

            studyAbroad.media = [...(studyAbroad.media || []), ...mediaResults];
            await studyAbroad.save({ session });

            await cacheService.deletePattern(`study_abroad:${id}:*`);
            metricsCollector.increment('study_abroad.media_uploaded', { id, mediaCount: files.length });
            metricsCollector.timing('study_abroad.media_upload_time', Date.now() - startTime);
            eventEmitter.emit('study_abroad.media_uploaded', { studyAbroadId: id, mediaCount: files.length });

            await session.commitTransaction();
            return ApiResponse.success(res, {
                message: 'Media uploaded successfully',
                data: { id: studyAbroad._id, mediaCount: mediaResults.length },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Media upload failed for study abroad ${id}:`, { error: error.message });
            metricsCollector.increment('study_abroad.media_upload_failed', { id });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Bulk create study abroad records
     * POST /api/v1/study-abroad/:userId/bulk
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    bulkCreateStudyAbroad = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const studyAbroadData = req.body.studyAbroadRecords || [];

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        await bulkOperationsLimiter(req, res, () => { });

        if (!Array.isArray(studyAbroadData) || studyAbroadData.length === 0) {
            return next(new AppError('No study abroad data provided', 400));
        }

        if (studyAbroadData.length > 50) {
            return next(new AppError('Cannot process more than 50 study abroad records at once', 400));
        }

        const userStudyAbroadCount = await StudyAbroad.countDocuments({
            userId,
            'status': { $ne: 'deleted' },
        }).cache({ ttl: 300, key: `user_study_abroad_count_${userId}` });

        const limits = this.getUserLimits(req.user.accountType);
        if (userStudyAbroadCount + studyAbroadData.length > limits.maxStudyAbroad) {
            return next(new AppError(`Study abroad limit would be exceeded (${limits.maxStudyAbroad})`, 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const validatedRecords = [];
            for (const recordData of studyAbroadData) {
                const validation = validateStudyAbroad(recordData);
                if (!validation.valid) {
                    throw new AppError(`Validation failed for study abroad record: ${validation.message}`, 400);
                }

                const sanitizedData = sanitizeInput(recordData);
                sanitizedData.programName = sanitizedData.programName?.trim();
                sanitizedData.startDate = new Date(sanitizedData.startDate) || null;
                sanitizedData.endDate = sanitizedData.endDate ? new Date(sanitizedData.endDate) : null;

                if (sanitizedData.institutionId) {
                    const institution = await this.schoolService.getSchoolById(sanitizedData.institutionId, { session });
                    if (!institution || institution.status !== 'active') {
                        throw new AppError(`Invalid institution association for record: ${sanitizedData.programName}`, 400);
                    }
                }

                validatedRecords.push({
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

            const studyAbroadRecords = await StudyAbroad.insertMany(validatedRecords, { session });

            for (const record of studyAbroadRecords) {
                this.processNewStudyAbroadAsync(record._id, userId).catch((err) => {
                    logger.error(`Async processing failed for study abroad ${record._id}:`, err);
                });
            }

            metricsCollector.increment('study_abroad.bulk_created', { userId, count: studyAbroadRecords.length });
            metricsCollector.timing('study_abroad.bulk_create_time', Date.now() - startTime);
            eventEmitter.emit('study_abroad.bulk_created', { userId, count: studyAbroadRecords.length });

            await session.commitTransaction();
            return ApiResponse.success(res, {
                message: `Successfully created ${studyAbroadRecords.length} study abroad records`,
                data: { count: studyAbroadRecords.length, studyAbroadIds: studyAbroadRecords.map(a => a._id) },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk study abroad creation failed for user ${userId}:`, { error: error.message });
            metricsCollector.increment('study_abroad.bulk_create_failed', { userId });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Get study abroad analytics
     * GET /api/v1/study-abroad/:userId/:id/analytics
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    getStudyAbroadAnalytics = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        await analyticsLimiter(req, res, () => { });

        const cacheKey = `study_abroad_analytics:${id}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('study_abroad.analytics_cache_hit', { id });
                return ApiResponse.success(res, cached);
            }

            const studyAbroad = await StudyAbroad.findOne({ _id: id, userId })
                .select('analytics')
                .lean();

            if (!studyAbroad) {
                return next(new AppError('Study abroad record not found', 404));
            }

            const analytics = await this.computeAnalytics(studyAbroad.analytics);
            await cacheService.set(cacheKey, analytics, 300, ['study_abroad_analytics:' + id]);

            metricsCollector.increment('study_abroad.analytics_fetched', { id });
            metricsCollector.timing('study_abroad.analytics_time', Date.now() - startTime);

            return ApiResponse.success(res, { data: analytics });
        } catch (error) {
            logger.error(`Failed to fetch analytics for study abroad ${id}:`, { error: error.message });
            metricsCollector.increment('study_abroad.analytics_failed', { id });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        }
    });

    /**
     * Search study abroad records
     * GET /api/v1/study-abroad/search
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    searchStudyAbroad = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const requestingUserId = req.user.id;
        const {
            query,
            page = 1,
            limit = 20,
            country,
            institutionId,
            fieldOfStudy,
            sortBy = 'relevance',
        } = req.query;

        await searchLimiter(req, res, () => { });

        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
        const from = (pageNum - 1) * limitNum;

        const cacheKey = `study_abroad_search:${requestingUserId}:${JSON.stringify({ query, page, limit, country, institutionId, fieldOfStudy, sortBy })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('study_abroad.search_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const esQuery = this.buildElasticsearchQuery({ query, country, institutionId, fieldOfStudy });
            const sortOption = this.buildSearchSortOption(sortBy);

            const esResponse = await elasticsearchClient.search({
                index: 'study_abroad',
                from,
                size: limitNum,
                body: {
                    query: esQuery,
                    sort: sortOption,
                },
            });

            const studyAbroadIds = esResponse.hits.hits.map(hit => hit._id);
            const studyAbroadRecords = await StudyAbroad.find({ _id: { $in: studyAbroadIds } })
                .read('secondaryPreferred')
                .select('-__v')
                .populate('institutionId', 'name type')
                .populate('educationId', 'degreeLevel fieldOfStudy')
                .lean({ virtuals: true });

            const totalCount = esResponse.hits.total.value;
            const result = {
                studyAbroadRecords,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages: Math.ceil(totalCount / limitNum),
                    hasNext: pageNum < Math.ceil(totalCount / limitNum),
                    hasPrev: pageNum > 1,
                },
            };

            await cacheService.set(cacheKey, result, 300, ['study_abroad_search']);
            metricsCollector.increment('study_abroad.search', { count: studyAbroadRecords.length });
            metricsCollector.timing('study_abroad.search_time', Date.now() - startTime);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Study abroad search failed:`, { error: error.message });
            metricsCollector.increment('study_abroad.search_failed');
            throw error instanceof AppError ? error : new AppError('Search failed', 500);
        }
    });

    /**
     * Export study abroad data
     * GET /api/v1/study-abroad/:userId/export
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    exportStudyAbroad = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { format = 'json' } = req.query;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        try {
            const studyAbroadRecords = await StudyAbroad.find({ userId, status: { $ne: 'deleted' } })
                .read('secondaryPreferred')
                .select('-__v')
                .populate('institutionId', 'name type')
                .populate('educationId', 'degreeLevel fieldOfStudy')
                .lean();

            const exportData = this.formatExportData(studyAbroadRecords, format);
            const fileName = `study_abroad_${userId}_${Date.now()}.${format}`;
            const s3Key = `exports/study_abroad/${userId}/${fileName}`;

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

            metricsCollector.increment('study_abroad.exported', { userId, format });
            metricsCollector.timing('study_abroad.export_time', Date.now() - startTime);
            eventEmitter.emit('study_abroad.exported', { userId, fileName, format });

            return ApiResponse.success(res, {
                message: 'Study abroad records exported successfully',
                data: { downloadUrl, fileName },
            });
        } catch (error) {
            logger.error(`Study abroad export failed for user ${userId}:`, { error: error.message });
            metricsCollector.increment('study_abroad.export_failed', { userId });
            throw error instanceof AppError ? error : new AppError('Export failed', 500);
        }
    });

    /**
     * Import study abroad records
     * POST /api/v1/study-abroad/:userId/import
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    importStudyAbroad = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { studyAbroadRecords, source } = req.body;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        await bulkOperationsLimiter(req, res, () => { });

        if (!Array.isArray(studyAbroadRecords) || studyAbroadRecords.length === 0) {
            return next(new AppError('No study abroad data provided', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const validatedRecords = [];
            for (const recordData of studyAbroadRecords) {
                const validation = validateStudyAbroad(recordData);
                if (!validation.valid) {
                    throw new AppError(`Validation failed for study abroad record: ${validation.message}`, 400);
                }

                const sanitizedData = sanitizeInput(recordData);
                validatedRecords.push({
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

            const insertedRecords = await StudyAbroad.insertMany(validatedRecords, { session });

            for (const record of insertedRecords) {
                this.processNewStudyAbroadAsync(record._id, userId).catch((err) => {
                    logger.error(`Async processing failed for study abroad ${record._id}:`, err);
                });
            }

            metricsCollector.increment('study_abroad.imported', { userId, count: insertedRecords.length });
            metricsCollector.timing('study_abroad.import_time', Date.now() - startTime);
            eventEmitter.emit('study_abroad.imported', { userId, count: insertedRecords.length });

            await session.commitTransaction();
            return ApiResponse.success(res, {
                message: `Successfully imported ${insertedRecords.length} study abroad records`,
                data: { count: insertedRecords.length, studyAbroadIds: insertedRecords.map(a => a._id) },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Study abroad import failed for user ${userId}:`, { error: error.message });
            metricsCollector.increment('study_abroad.import_failed', { userId });
            throw error instanceof AppError ? error : new AppError('Import failed', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Get study abroad recommendations
     * GET /api/v1/study-abroad/:userId/recommendations
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    getStudyAbroadRecommendations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { limit = 10 } = req.query;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        try {
            const userStudyAbroadRecords = await StudyAbroad.find({ userId, status: { $ne: 'deleted' } })
                .select('institutionId country fieldOfStudy')
                .lean();

            const recommendations = await this.generateRecommendations(userStudyAbroadRecords, parseInt(limit));
            metricsCollector.increment('study_abroad.recommendations_fetched', { userId, count: recommendations.length });
            metricsCollector.timing('study_abroad.recommendations_time', Date.now() - startTime);

            return ApiResponse.success(res, {
                message: 'Recommendations generated successfully',
                data: recommendations,
            });
        } catch (error) {
            logger.error(`Failed to fetch recommendations for user ${userId}:`, { error: error.message });
            metricsCollector.increment('study_abroad.recommendations_failed', { userId });
            throw error instanceof AppError ? error : new AppError('Failed to generate recommendations', 500);
        }
    });

    // Helper methods
    getUserLimits(accountType) {
        const limits = {
            free: { maxStudyAbroad: 5, maxMedia: 5 },
            premium: { maxStudyAbroad: 20, maxMedia: 20 },
            enterprise: { maxStudyAbroad: 100, maxMedia: 100 },
        };
        return limits[accountType] || limits.free;
    }

    buildStudyAbroadQuery({ userId, status, programName, country, institutionId, educationId, startDate, endDate, search, tags }) {
        const query = { userId, status: { $ne: 'deleted' } };
        if (status) query.status = status;
        if (programName) query.programName = { $regex: programName, $options: 'i' };
        if (country) query.country = { $regex: country, $options: 'i' };
        if (institutionId) query.institutionId = mongoose.Types.ObjectId(institutionId);
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
            programName: { programName: 1 },
            startDate: { startDate: -1 },
        };
        return sortOptions[sortBy] || sortOptions.recent;
    }

    buildElasticsearchQuery({ query, country, institutionId, fieldOfStudy }) {
        const boolQuery = {
            must: [],
            filter: [{ term: { searchable: true } }],
        };
        if (query) {
            boolQuery.must.push({
                multi_match: {
                    query,
                    fields: ['programName^2', 'country', 'fieldOfStudy', 'description'],
                    fuzziness: 'AUTO',
                },
            });
        }
        if (country) boolQuery.filter.push({ match: { country } });
        if (institutionId) boolQuery.filter.push({ term: { institutionId } });
        if (fieldOfStudy) boolQuery.filter.push({ match: { fieldOfStudy } });
        return { bool: boolQuery };
    }

    buildSearchSortOption(sortBy) {
        const sortOptions = {
            relevance: { _score: 'desc' },
            recent: { createdAt: 'desc' },
            programName: { programName: 'asc' },
        };
        return sortOptions[sortBy] || sortOptions.relevance;
    }

    async indexForSearch(studyAbroad) {
        try {
            await elasticsearchClient.index({
                index: 'study_abroad',
                id: studyAbroad._id.toString(),
                body: {
                    userId: studyAbroad.userId,
                    programName: studyAbroad.programName,
                    country: studyAbroad.country,
                    institutionId: studyAbroad.institutionId,
                    educationId: studyAbroad.educationId,
                    fieldOfStudy: studyAbroad.fieldOfStudy,
                    status: studyAbroad.status,
                    searchable: studyAbroad.privacy.searchable,
                    createdAt: studyAbroad.createdAt,
                },
            });
            metricsCollector.increment('study_abroad.indexed', { studyAbroadId: studyAbroad._id });
        } catch (error) {
            logger.error(`Failed to index study abroad ${studyAbroad._id}:`, { error: error.message });
        }
    }

    async createBackup(studyAbroadId, action, userId, options = {}) {
        try {
            const studyAbroad = await StudyAbroad.findById(studyAbroadId).session(options.session);
            if (!studyAbroad) return;

            const backupKey = `backups/study_abroad/${studyAbroadId}/${Date.now()}.json`;
            await s3Client.upload({
                Bucket: 'user-backups',
                Key: backupKey,
                Body: Buffer.from(JSON.stringify(studyAbroad)),
                ContentType: 'application/json',
            }).promise();

            logger.info(`Backup created for study abroad ${studyAbroadId} by ${userId} for action ${action}`);
            metricsCollector.increment('study_abroad.backup_created', { studyAbroadId, action });
        } catch (error) {
            logger.error(`Backup failed for study abroad ${studyAbroadId}:`, { error: error.message });
        }
    }

    async checkConnectionAccess(ownerId, requesterId) {
        // Placeholder for connection-based access logic
        return ownerId === requesterId;
    }

    getAllowedUpdateFields() {
        return [
            'programName',
            'country',
            'description',
            'startDate',
            'endDate',
            'institutionId',
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

    async processNewStudyAbroadAsync(studyAbroadId, userId) {
        try {
            const studyAbroad = await StudyAbroad.findById(studyAbroadId);
            if (!studyAbroad) return;

            await this.circuitBreaker.fire(async () => {
                await retry(() => this.verificationService.verifyStudyAbroad({
                    studyAbroadId,
                    userId,
                    programName: studyAbroad.programName,
                    country: studyAbroad.country,
                    institutionId: studyAbroad.institutionId,
                    educationId: studyAbroad.educationId,
                }), this.retryConfig);
            });

            await this.indexForSearch(studyAbroad);
            metricsCollector.increment('study_abroad.async_processed', { studyAbroadId });
        } catch (error) {
            logger.error(`Async processing failed for study abroad ${studyAbroadId}:`, { error: error.message });
        }
    }

    async processExternalVerification(studyAbroadId, userId) {
        try {
            const studyAbroad = await StudyAbroad.findById(studyAbroadId);
            if (!studyAbroad) return;

            await this.circuitBreaker.fire(async () => {
                await retry(() => this.verificationService.verifyStudyAbroad({
                    studyAbroadId,
                    userId,
                    programName: studyAbroad.programName,
                    country: studyAbroad.country,
                    institutionId: studyAbroad.institutionId,
                    educationId: studyAbroad.educationId,
                }), this.retryConfig);
            });
            metricsCollector.increment('study_abroad.verification_processed', { studyAbroadId });
        } catch (error) {
            logger.error(`External verification failed for study abroad ${studyAbroadId}:`, { error: error.message });
        }
    }

    async updateAnalytics(studyAbroad, viewerId) {
        try {
            studyAbroad.analytics.views.total += 1;
            if (!studyAbroad.analytics.views.byDate) studyAbroad.analytics.views.byDate = [];
            const today = moment().startOf('day').toDate();
            const viewEntry = studyAbroad.analytics.views.byDate.find(v => v.date.toDateString() === today.toDateString());
            if (viewEntry) {
                viewEntry.count += 1;
            } else {
                studyAbroad.analytics.views.byDate.push({ date: today, count: 1 });
            }
            await studyAbroad.save();
        } catch (error) {
            logger.error(`Failed to update analytics for study abroad ${studyAbroad._id}:`, { error: error.message });
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

    async generateRecommendations(userStudyAbroadRecords, limit) {
        const institutionIds = userStudyAbroadRecords.map(a => a.institutionId).filter(Boolean);
        const countries = userStudyAbroadRecords.map(a => a.country).filter(Boolean);
        const fields = userStudyAbroadRecords.map(a => a.fieldOfStudy).filter(Boolean);

        const recommendedRecords = await StudyAbroad.find({
            $or: [
                { institutionId: { $in: institutionIds } },
                { country: { $in: countries } },
                { fieldOfStudy: { $in: fields } },
            ],
            status: { $ne: 'deleted' },
            'privacy.searchable': true,
        })
            .limit(limit)
            .select('programName country institutionId fieldOfStudy')
            .lean();

        return recommendedRecords;
    }

    formatExportData(studyAbroadRecords, format) {
        if (format === 'csv') {
            const headers = ['id', 'programName', 'country', 'institutionId', 'educationId', 'fieldOfStudy', 'startDate', 'status'];
            const csvRows = [headers.join(',')];
            for (const record of studyAbroadRecords) {
                const row = [
                    record._id,
                    `"${record.programName}"`,
                    record.country || '',
                    record.institutionId?._id || '',
                    record.educationId?._id || '',
                    record.fieldOfStudy || '',
                    record.startDate || '',
                    record.status,
                ];
                csvRows.push(row.join(','));
            }
            return csvRows.join('\n');
        }
        return studyAbroadRecords; // Default JSON
    }
}

export default new StudyAbroadController();