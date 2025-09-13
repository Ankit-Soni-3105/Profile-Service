import Course from '../models/Course.js';
import VerificationService from '../services/VerificationService.js';
import MediaService from '../services/MediaService.js';
import NotificationService from '../services/NotificationService.js';
import InstitutionService from '../services/InstitutionService.js';
import { validateCourse, sanitizeInput } from '../validations/course.validation.js';
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
import moment from 'moment';

// Rate limiters for high concurrency and abuse prevention
const createCourseLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15-minute window
    max: 10, // Allow 10 creates per user per IP
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_course_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
    legacyHeaders: false,
});

const updateCourseLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5-minute window
    max: 20, // Allow 20 updates
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_course_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const verificationLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30-minute window
    max: 5, // Strict limit for external API calls
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `verify_course_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const bulkOperationsLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // Hourly limit
    max: 3, // Conservative limit for bulk operations
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_course_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const mediaUploadLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000, // 10-minute window
    max: 10, // Limit uploads
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `media_course_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const searchLimiter = createRateLimiter({
    windowMs: 1 * 60 * 1000, // 1-minute window
    max: 50, // Allow frequent searches
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `search_course_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const analyticsLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5-minute window
    max: 20, // Moderate limit for analytics requests
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `analytics_course_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

class CourseController {
    constructor() {
        this.verificationService = VerificationService;
        this.mediaService = MediaService;
        this.notificationService = NotificationService;
        this.institutionService = InstitutionService;
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
     * Create a new course
     * POST /api/v1/courses/:userId
     * Creates a course record with validation, async processing, and transaction support.
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    createCourse = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const courseData = req.body;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied: Cannot create course for another user', 403));
        }

        await createCourseLimiter(req, res, () => { });

        const validation = validateCourse(courseData);
        if (!validation.valid) {
            metricsCollector.increment('course.validation_failed', { userId, errors: validation.errors.length });
            return next(new AppError(`Validation failed: ${validation.message}`, 400));
        }

        const sanitizedData = sanitizeInput(courseData);
        sanitizedData.title = sanitizedData.title?.trim();
        sanitizedData.startDate = new Date(sanitizedData.startDate) || null;
        sanitizedData.endDate = sanitizedData.endDate ? new Date(sanitizedData.endDate) : null;

        const userCourseCount = await Course.countDocuments({
            userId,
            'status': { $ne: 'deleted' },
        }).cache({ ttl: 300, key: `user_course_count_${userId}` });

        const limits = this.getUserLimits(req.user.accountType);
        if (userCourseCount >= limits.maxCourses) {
            metricsCollector.increment('course.limit_exceeded', { userId });
            return next(new AppError(`Course limit reached (${limits.maxCourses})`, 403));
        }

        if (sanitizedData.institutionId) {
            const institution = await this.institutionService.getInstitutionById(sanitizedData.institutionId);
            if (!institution || institution.status !== 'active') {
                return next(new AppError('Invalid or inactive institution association', 400));
            }
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const course = await Course.create([{
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

            this.processNewCourseAsync(course[0]._id, requestingUserId)
                .catch((err) => {
                    logger.error(`Async processing failed for course ${course[0]._id}:`, err);
                    metricsCollector.increment('course.async_processing_failed', { courseId: course[0]._id });
                });

            metricsCollector.increment('course.created', {
                userId,
                title: course[0].title,
                institutionAssociated: !!course[0].institutionId,
                accountType: req.user.accountType,
            });
            metricsCollector.timing('course.create_time', Date.now() - startTime);

            eventEmitter.emit('course.created', {
                courseId: course[0]._id,
                userId,
                institutionId: course[0].institutionId,
                title: course[0].title,
                category: course[0].category,
            });

            if (course[0].settings?.autoBackup) {
                await this.createBackup(course[0]._id, 'create', requestingUserId, { session });
            }

            await session.commitTransaction();
            logger.info(`Course created successfully: ${course[0]._id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Course created successfully',
                data: {
                    id: course[0]._id,
                    userId: course[0].userId,
                    title: course[0].title,
                    status: course[0].status,
                    createdAt: course[0].createdAt,
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Course creation failed for user ${userId}:`, { error: error.message });
            metricsCollector.increment('course.create_failed', { userId });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Get user's courses with filtering and pagination
     * GET /api/v1/courses/:userId
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    getCourses = catchAsync(async (req, res, next) => {
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
            category,
            provider,
            institutionId,
            startDate,
            endDate,
            search,
            sortBy = 'recent',
            tags,
        } = req.query;

        await searchLimiter(req, res, () => { });

        const query = this.buildCourseQuery({ userId, status, title, category, provider, institutionId, startDate, endDate, search, tags });
        const sortOption = this.buildSortOption(sortBy);
        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
        const skip = (pageNum - 1) * limitNum;

        const cacheKey = `courses:${userId}:${JSON.stringify({ page, limit, status, title, category, provider, institutionId, sortBy, tags })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('course.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const [courses, totalCount] = await Promise.all([
                Course.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select('-__v')
                    .populate('institutionId', 'name type')
                    .lean({ virtuals: true }),
                Course.countDocuments(query).cache({ ttl: 300 }),
            ]);

            const result = {
                courses,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages: Math.ceil(totalCount / limitNum),
                    hasNext: pageNum < Math.ceil(totalCount / limitNum),
                    hasPrev: pageNum > 1,
                },
            };

            await cacheService.set(cacheKey, result, 300, ['courses:user:' + userId]);
            metricsCollector.increment('course.fetched', { userId, count: courses.length });
            metricsCollector.timing('course.get_list_time', Date.now() - startTime);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch courses for user ${userId}:`, { error: error.message });
            metricsCollector.increment('course.fetch_failed', { userId });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        }
    });

    /**
     * Get single course by ID
     * GET /api/v1/courses/:userId/:id
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    getCourseById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            const hasConnectionAccess = await this.checkConnectionAccess(userId, requestingUserId);
            if (!hasConnectionAccess) {
                return next(new AppError('Access denied', 403));
            }
        }

        const cacheKey = `course:${id}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('course.cache_hit', { id });
                return ApiResponse.success(res, cached);
            }

            const course = await Course.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('-__v')
                .populate('institutionId', 'name type')
                .lean({ virtuals: true });

            if (!course) {
                return next(new AppError('Course not found', 404));
            }

            await this.updateAnalytics(course, requestingUserId);
            await cacheService.set(cacheKey, course, 600, ['courses:id:' + id]);
            metricsCollector.increment('course.viewed', { id, userId });
            metricsCollector.timing('course.get_by_id_time', Date.now() - startTime);

            return ApiResponse.success(res, { data: course });
        } catch (error) {
            logger.error(`Failed to fetch course ${id}:`, { error: error.message });
            metricsCollector.increment('course.view_failed', { id });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        }
    });

    /**
     * Update course
     * PUT /api/v1/courses/:userId/:id
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    updateCourse = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const updates = req.body;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        await updateCourseLimiter(req, res, () => { });

        const sanitizedUpdates = this.sanitizeUpdates(updates, this.getAllowedUpdateFields());
        if (Object.keys(sanitizedUpdates).length === 0) {
            return next(new AppError('No valid update fields provided', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const course = await Course.findOne({ _id: id, userId }).session(session);
            if (!course) {
                return next(new AppError('Course not found', 404));
            }

            if (sanitizedUpdates.title || sanitizedUpdates.category || sanitizedUpdates.provider) {
                course.versions = course.versions || [];
                course.versions.push({
                    versionNumber: course.metadata.version + 1,
                    title: sanitizedUpdates.title || course.title,
                    category: sanitizedUpdates.category || course.category,
                    provider: sanitizedUpdates.provider || course.provider,
                    changeType: 'edit',
                    timestamp: new Date(),
                });
            }

            if (sanitizedUpdates.institutionId) {
                const institution = await this.institutionService.getInstitutionById(sanitizedUpdates.institutionId, { session });
                if (!institution || institution.status !== 'active') {
                    return next(new AppError('Invalid or inactive institution association', 400));
                }
            }

            Object.assign(course, sanitizedUpdates);
            course.metadata.version += 1;
            course.metadata.updateCount += 1;
            course.metadata.lastModifiedBy = {
                userId: requestingUserId,
                timestamp: new Date(),
                changes: Object.keys(sanitizedUpdates),
            };

            if (['title', 'category', 'provider', 'institutionId'].some(field => sanitizedUpdates[field])) {
                course.verification.status = 'pending';
                this.processExternalVerification(course._id, userId).catch((err) => {
                    logger.error(`Re-verification failed for course ${course._id}:`, err);
                });
            }

            await course.save({ session });
            await this.indexForSearch(course);
            await cacheService.deletePattern(`course:${id}:*`);

            metricsCollector.increment('course.updated', { id });
            metricsCollector.timing('course.update_time', Date.now() - startTime);
            eventEmitter.emit('course.updated', { courseId: id, changes: Object.keys(sanitizedUpdates) });

            await session.commitTransaction();
            return ApiResponse.success(res, {
                message: 'Course updated successfully',
                data: { id: course._id, title: course.title, status: course.status },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Course update failed for ${id}:`, { error: error.message });
            metricsCollector.increment('course.update_failed', { id });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete course
     * DELETE /api/v1/courses/:userId/:id
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    deleteCourse = catchAsync(async (req, res, next) => {
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

            const course = await Course.findOne({ _id: id, userId }).session(session);
            if (!course) {
                return next(new AppError('Course not found', 404));
            }

            if (permanent === 'true') {
                await Course.findByIdAndDelete(id, { session });
                await this.mediaService.deleteAllMedia(id, 'course', { session });
            } else {
                course.status = 'deleted';
                course.privacy.isPublic = false;
                course.privacy.searchable = false;
                await course.save({ session });
            }

            await cacheService.deletePattern(`course:${id}:*`);
            metricsCollector.increment(`course.${permanent ? 'permanently_deleted' : 'soft_deleted'}`, { id });
            metricsCollector.timing('course.delete_time', Date.now() - startTime);
            eventEmitter.emit('course.deleted', { courseId: id, permanent });

            await session.commitTransaction();
            return ApiResponse.success(res, {
                message: permanent === 'true' ? 'Course permanently deleted' : 'Course soft deleted',
                data: { id },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Course deletion failed for ${id}:`, { error: error.message });
            metricsCollector.increment('course.delete_failed', { id });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Verify course
     * POST /api/v1/courses/:userId/:id/verify
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    verifyCourse = catchAsync(async (req, res, next) => {
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

            const course = await Course.findOne({ _id: id, userId }).session(session);
            if (!course) {
                return next(new AppError('Course not found', 404));
            }

            const verificationResult = await this.circuitBreaker.fire(async () => {
                return await retry(() => this.verificationService.verifyCourse({
                    courseId: course._id,
                    userId,
                    title: course.title,
                    provider: course.provider,
                    category: course.category,
                    institutionId: course.institutionId,
                }), this.retryConfig);
            });

            course.verification = {
                status: verificationResult.success ? 'verified' : 'failed',
                confidence: verificationResult.confidence || 0,
                verifiedBy: verificationResult.verifiedBy || 'external_api',
                verifiedAt: new Date(),
                details: verificationResult.details || [],
            };
            await course.save({ session });

            await this.indexForSearch(course);
            await cacheService.deletePattern(`course:${id}:*`);

            eventEmitter.emit('course.verified', {
                courseId: id,
                userId,
                verificationStatus: verificationResult.success ? 'verified' : 'failed',
            });

            await session.commitTransaction();
            metricsCollector.increment('course.verified', { id, status: verificationResult.status });
            metricsCollector.timing('course.verify_time', Date.now() - startTime);

            return ApiResponse.success(res, {
                message: `Course ${verificationResult.success ? 'verified' : 'verification failed'}`,
                data: { id: course._id, verificationStatus: course.verification.status },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Verification failed for course ${id}:`, { error: error.message });
            metricsCollector.increment('course.verify_failed', { id });
            throw error instanceof AppError ? error : new AppError('Failed to verify course', 424);
        } finally {
            session.endSession();
        }
    });

    /**
     * Upload course media
     * POST /api/v1/courses/:userId/:id/media
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    uploadCourseMedia = catchAsync(async (req, res, next) => {
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

            const course = await Course.findOne({ _id: id, userId }).session(session);
            if (!course) {
                return next(new AppError('Course not found', 404));
            }

            const mediaResults = await this.mediaService.uploadMedia({
                files,
                entityId: course._id,
                entityType: 'course',
                userId: requestingUserId,
                category: 'course_media',
            }, { session });

            const scanResults = await this.mediaService.scanMedia(mediaResults);
            const infected = scanResults.filter(r => r.infected);
            if (infected.length > 0) {
                await this.mediaService.deleteMedia(infected.map(m => m.id), { session });
                return next(new AppError(`Media upload failed: ${infected.length} infected files detected`, 422));
            }

            course.media = [...(course.media || []), ...mediaResults];
            await course.save({ session });

            await cacheService.deletePattern(`course:${id}:*`);
            metricsCollector.increment('course.media_uploaded', { id, mediaCount: files.length });
            metricsCollector.timing('course.media_upload_time', Date.now() - startTime);
            eventEmitter.emit('course.media_uploaded', { courseId: id, mediaCount: files.length });

            await session.commitTransaction();
            return ApiResponse.success(res, {
                message: 'Media uploaded successfully',
                data: { id: course._id, mediaCount: mediaResults.length },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Media upload failed for course ${id}:`, { error: error.message });
            metricsCollector.increment('course.media_upload_failed', { id });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Bulk create courses
     * POST /api/v1/courses/:userId/bulk
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    bulkCreateCourses = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const coursesData = req.body.courses || [];

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        await bulkOperationsLimiter(req, res, () => { });

        if (!Array.isArray(coursesData) || coursesData.length === 0) {
            return next(new AppError('No courses data provided', 400));
        }

        if (coursesData.length > 50) {
            return next(new AppError('Cannot process more than 50 courses at once', 400));
        }

        const userCourseCount = await Course.countDocuments({
            userId,
            'status': { $ne: 'deleted' },
        }).cache({ ttl: 300, key: `user_course_count_${userId}` });

        const limits = this.getUserLimits(req.user.accountType);
        if (userCourseCount + coursesData.length > limits.maxCourses) {
            return next(new AppError(`Course limit would be exceeded (${limits.maxCourses})`, 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const validatedCourses = [];
            for (const courseData of coursesData) {
                const validation = validateCourse(courseData);
                if (!validation.valid) {
                    throw new AppError(`Validation failed for course: ${validation.message}`, 400);
                }

                const sanitizedData = sanitizeInput(courseData);
                sanitizedData.title = sanitizedData.title?.trim();
                sanitizedData.startDate = new Date(sanitizedData.startDate) || null;
                sanitizedData.endDate = sanitizedData.endDate ? new Date(sanitizedData.endDate) : null;

                if (sanitizedData.institutionId) {
                    const institution = await this.institutionService.getInstitutionById(sanitizedData.institutionId, { session });
                    if (!institution || institution.status !== 'active') {
                        throw new AppError(`Invalid institution association for course: ${sanitizedData.title}`, 400);
                    }
                }

                validatedCourses.push({
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

            const courses = await Course.insertMany(validatedCourses, { session });

            for (const course of courses) {
                this.processNewCourseAsync(course._id, userId).catch((err) => {
                    logger.error(`Async processing failed for course ${course._id}:`, err);
                });
            }

            metricsCollector.increment('course.bulk_created', { userId, count: courses.length });
            metricsCollector.timing('course.bulk_create_time', Date.now() - startTime);
            eventEmitter.emit('course.bulk_created', { userId, count: courses.length });

            await session.commitTransaction();
            return ApiResponse.success(res, {
                message: `Successfully created ${courses.length} courses`,
                data: { count: courses.length, courseIds: courses.map(c => c._id) },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk course creation failed for user ${userId}:`, { error: error.message });
            metricsCollector.increment('course.bulk_create_failed', { userId });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Get course analytics
     * GET /api/v1/courses/:userId/:id/analytics
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    getCourseAnalytics = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        await analyticsLimiter(req, res, () => { });

        const cacheKey = `course_analytics:${id}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('course.analytics_cache_hit', { id });
                return ApiResponse.success(res, cached);
            }

            const course = await Course.findOne({ _id: id, userId })
                .select('analytics')
                .lean();

            if (!course) {
                return next(new AppError('Course not found', 404));
            }

            const analytics = await this.computeAnalytics(course.analytics);
            await cacheService.set(cacheKey, analytics, 300, ['course_analytics:' + id]);

            metricsCollector.increment('course.analytics_fetched', { id });
            metricsCollector.timing('course.analytics_time', Date.now() - startTime);

            return ApiResponse.success(res, { data: analytics });
        } catch (error) {
            logger.error(`Failed to fetch analytics for course ${id}:`, { error: error.message });
            metricsCollector.increment('course.analytics_failed', { id });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        }
    });

    /**
     * Search courses
     * GET /api/v1/courses/search
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    searchCourses = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const requestingUserId = req.user.id;
        const {
            query,
            page = 1,
            limit = 20,
            category,
            provider,
            institutionId,
            sortBy = 'relevance',
        } = req.query;

        await searchLimiter(req, res, () => { });

        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
        const from = (pageNum - 1) * limitNum;

        const cacheKey = `course_search:${requestingUserId}:${JSON.stringify({ query, page, limit, category, provider, institutionId, sortBy })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('course.search_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const esQuery = this.buildElasticsearchQuery({ query, category, provider, institutionId });
            const sortOption = this.buildSearchSortOption(sortBy);

            const esResponse = await elasticsearchClient.search({
                index: 'courses',
                from,
                size: limitNum,
                body: {
                    query: esQuery,
                    sort: sortOption,
                },
            });

            const courseIds = esResponse.hits.hits.map(hit => hit._id);
            const courses = await Course.find({ _id: { $in: courseIds } })
                .read('secondaryPreferred')
                .select('-__v')
                .populate('institutionId', 'name type')
                .lean({ virtuals: true });

            const totalCount = esResponse.hits.total.value;
            const result = {
                courses,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages: Math.ceil(totalCount / limitNum),
                    hasNext: pageNum < Math.ceil(totalCount / limitNum),
                    hasPrev: pageNum > 1,
                },
            };

            await cacheService.set(cacheKey, result, 300, ['course_search']);
            metricsCollector.increment('course.search', { count: courses.length });
            metricsCollector.timing('course.search_time', Date.now() - startTime);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Course search failed:`, { error: error.message });
            metricsCollector.increment('course.search_failed');
            throw error instanceof AppError ? error : new AppError('Search failed', 500);
        }
    });

    /**
     * Export course data
     * GET /api/v1/courses/:userId/export
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    exportCourses = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { format = 'json' } = req.query;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        try {
            const courses = await Course.find({ userId, status: { $ne: 'deleted' } })
                .read('secondaryPreferred')
                .select('-__v')
                .populate('institutionId', 'name type')
                .lean();

            const exportData = this.formatExportData(courses, format);
            const fileName = `courses_${userId}_${Date.now()}.${format}`;
            const s3Key = `exports/courses/${userId}/${fileName}`;

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

            metricsCollector.increment('course.exported', { userId, format });
            metricsCollector.timing('course.export_time', Date.now() - startTime);
            eventEmitter.emit('course.exported', { userId, fileName, format });

            return ApiResponse.success(res, {
                message: 'Courses exported successfully',
                data: { downloadUrl, fileName },
            });
        } catch (error) {
            logger.error(`Course export failed for user ${userId}:`, { error: error.message });
            metricsCollector.increment('course.export_failed', { userId });
            throw error instanceof AppError ? error : new AppError('Export failed', 500);
        }
    });

    /**
     * Import courses
     * POST /api/v1/courses/:userId/import
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    importCourses = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { courses, source } = req.body;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        await bulkOperationsLimiter(req, res, () => { });

        if (!Array.isArray(courses) || courses.length === 0) {
            return next(new AppError('No courses data provided', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const validatedCourses = [];
            for (const courseData of courses) {
                const validation = validateCourse(courseData);
                if (!validation.valid) {
                    throw new AppError(`Validation failed for course: ${validation.message}`, 400);
                }

                const sanitizedData = sanitizeInput(courseData);
                validatedCourses.push({
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

            const insertedCourses = await Course.insertMany(validatedCourses, { session });

            for (const course of insertedCourses) {
                this.processNewCourseAsync(course._id, userId).catch((err) => {
                    logger.error(`Async processing failed for course ${course._id}:`, err);
                });
            }

            metricsCollector.increment('course.imported', { userId, count: insertedCourses.length });
            metricsCollector.timing('course.import_time', Date.now() - startTime);
            eventEmitter.emit('course.imported', { userId, count: insertedCourses.length });

            await session.commitTransaction();
            return ApiResponse.success(res, {
                message: `Successfully imported ${insertedCourses.length} courses`,
                data: { count: insertedCourses.length, courseIds: insertedCourses.map(c => c._id) },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Course import failed for user ${userId}:`, { error: error.message });
            metricsCollector.increment('course.import_failed', { userId });
            throw error instanceof AppError ? error : new AppError('Import failed', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Get course recommendations
     * GET /api/v1/courses/:userId/recommendations
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    getCourseRecommendations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { limit = 10 } = req.query;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        try {
            const userCourses = await Course.find({ userId, status: { $ne: 'deleted' } })
                .select('category provider institutionId')
                .lean();

            const recommendations = await this.generateRecommendations(userCourses, parseInt(limit));
            metricsCollector.increment('course.recommendations_fetched', { userId, count: recommendations.length });
            metricsCollector.timing('course.recommendations_time', Date.now() - startTime);

            return ApiResponse.success(res, {
                message: 'Recommendations generated successfully',
                data: recommendations,
            });
        } catch (error) {
            logger.error(`Failed to fetch recommendations for user ${userId}:`, { error: error.message });
            metricsCollector.increment('course.recommendations_failed', { userId });
            throw error instanceof AppError ? error : new AppError('Failed to generate recommendations', 500);
        }
    });

    // Helper methods
    getUserLimits(accountType) {
        const limits = {
            free: { maxCourses: 15, maxMedia: 5 },
            premium: { maxCourses: 50, maxMedia: 20 },
            enterprise: { maxCourses: 200, maxMedia: 100 },
        };
        return limits[accountType] || limits.free;
    }

    buildCourseQuery({ userId, status, title, category, provider, institutionId, startDate, endDate, search, tags }) {
        const query = { userId, status: { $ne: 'deleted' } };
        if (status) query.status = status;
        if (title) query.title = { $regex: title, $options: 'i' };
        if (category) query.category = { $regex: category, $options: 'i' };
        if (provider) query.provider = { $regex: provider, $options: 'i' };
        if (institutionId) query.institutionId = mongoose.Types.ObjectId(institutionId);
        if (startDate) query.startDate = { $gte: new Date(startDate) };
        if (endDate) query.endDate = { $lte: new Date(endDate) };
        if (search) query.$text = { $search: search };
        if (tags) query.tags = { $all: tags.split(',').map(t => t.trim()) };
        return query;
    }

    buildSortOption(sortBy) {
        const sortOptions = {
            recent: { createdAt: -1 },
            title: { title: 1 },
            startDate: { startDate: -1 },
        };
        return sortOptions[sortBy] || sortOptions.recent;
    }

    buildElasticsearchQuery({ query, category, provider, institutionId }) {
        const boolQuery = {
            must: [],
            filter: [{ term: { searchable: true } }],
        };
        if (query) {
            boolQuery.must.push({
                multi_match: {
                    query,
                    fields: ['title^2', 'category', 'provider', 'description'],
                    fuzziness: 'AUTO',
                },
            });
        }
        if (category) boolQuery.filter.push({ match: { category } });
        if (provider) boolQuery.filter.push({ match: { provider } });
        if (institutionId) boolQuery.filter.push({ term: { institutionId } });
        return { bool: boolQuery };
    }

    buildSearchSortOption(sortBy) {
        const sortOptions = {
            relevance: { _score: 'desc' },
            recent: { createdAt: 'desc' },
            title: { title: 'asc' },
        };
        return sortOptions[sortBy] || sortOptions.relevance;
    }

    async indexForSearch(course) {
        try {
            await elasticsearchClient.index({
                index: 'courses',
                id: course._id.toString(),
                body: {
                    userId: course.userId,
                    title: course.title,
                    category: course.category,
                    provider: course.provider,
                    institutionId: course.institutionId,
                    status: course.status,
                    searchable: course.privacy.searchable,
                    createdAt: course.createdAt,
                },
            });
            metricsCollector.increment('course.indexed', { courseId: course._id });
        } catch (error) {
            logger.error(`Failed to index course ${course._id}:`, { error: error.message });
        }
    }

    async createBackup(courseId, action, userId, options = {}) {
        try {
            const course = await Course.findById(courseId).session(options.session);
            if (!course) return;

            const backupKey = `backups/courses/${courseId}/${Date.now()}.json`;
            await s3Client.upload({
                Bucket: 'user-backups',
                Key: backupKey,
                Body: Buffer.from(JSON.stringify(course)),
                ContentType: 'application/json',
            }).promise();

            logger.info(`Backup created for course ${courseId} by ${userId} for action ${action}`);
            metricsCollector.increment('course.backup_created', { courseId, action });
        } catch (error) {
            logger.error(`Backup failed for course ${courseId}:`, { error: error.message });
        }
    }

    async checkConnectionAccess(ownerId, requesterId) {
        // Placeholder for connection-based access logic
        return ownerId === requesterId;
    }

    getAllowedUpdateFields() {
        return [
            'title',
            'description',
            'category',
            'provider',
            'startDate',
            'endDate',
            'institutionId',
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

    async processNewCourseAsync(courseId, userId) {
        try {
            const course = await Course.findById(courseId);
            if (!course) return;

            await this.circuitBreaker.fire(async () => {
                await retry(() => this.verificationService.verifyCourse({
                    courseId,
                    userId,
                    title: course.title,
                    provider: course.provider,
                    category: course.category,
                    institutionId: course.institutionId,
                }), this.retryConfig);
            });

            await this.indexForSearch(course);
            metricsCollector.increment('course.async_processed', { courseId });
        } catch (error) {
            logger.error(`Async processing failed for course ${courseId}:`, { error: error.message });
        }
    }

    async processExternalVerification(courseId, userId) {
        try {
            const course = await Course.findById(courseId);
            if (!course) return;

            await this.circuitBreaker.fire(async () => {
                await retry(() => this.verificationService.verifyCourse({
                    courseId,
                    userId,
                    title: course.title,
                    provider: course.provider,
                    category: course.category,
                    institutionId: course.institutionId,
                }), this.retryConfig);
            });
            metricsCollector.increment('course.verification_processed', { courseId });
        } catch (error) {
            logger.error(`External verification failed for course ${courseId}:`, { error: error.message });
        }
    }

    async updateAnalytics(course, viewerId) {
        try {
            course.analytics.views.total += 1;
            if (!course.analytics.views.byDate) course.analytics.views.byDate = [];
            const today = moment().startOf('day').toDate();
            const viewEntry = course.analytics.views.byDate.find(v => v.date.toDateString() === today.toDateString());
            if (viewEntry) {
                viewEntry.count += 1;
            } else {
                course.analytics.views.byDate.push({ date: today, count: 1 });
            }
            await course.save();
        } catch (error) {
            logger.error(`Failed to update analytics for course ${course._id}:`, { error: error.message });
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

    async generateRecommendations(userCourses, limit) {
        const institutionIds = userCourses.map(c => c.institutionId).filter(Boolean);
        const categories = userCourses.map(c => c.category).filter(Boolean);
        const providers = userCourses.map(c => c.provider).filter(Boolean);

        const recommendedCourses = await Course.find({
            $or: [
                { institutionId: { $in: institutionIds } },
                { category: { $in: categories } },
                { provider: { $in: providers } },
            ],
            status: { $ne: 'deleted' },
            'privacy.searchable': true,
        })
            .limit(limit)
            .select('title category provider institutionId')
            .lean();

        return recommendedCourses;
    }

    formatExportData(courses, format) {
        if (format === 'csv') {
            const headers = ['id', 'title', 'category', 'provider', 'institutionId', 'startDate', 'endDate', 'status'];
            const csvRows = [headers.join(',')];
            for (const course of courses) {
                const row = [
                    course._id,
                    `"${course.title}"`,
                    course.category || '',
                    course.provider || '',
                    course.institutionId?._id || '',
                    course.startDate || '',
                    course.endDate || '',
                    course.status,
                ];
                csvRows.push(row.join(','));
            }
            return csvRows.join('\n');
        }
        return courses; // Default JSON
    }
}

export default new CourseController();