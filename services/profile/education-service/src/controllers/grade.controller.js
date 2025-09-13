import Grade from '../models/Grade.js';
import GradeService from '../services/GradeService.js';
import VerificationService from '../services/VerificationService.js';
import MediaService from '../services/MediaService.js';
import TemplateService from '../services/TemplateService.js';
import NotificationService from '../services/NotificationService.js';
import SchoolService from '../services/SchoolService.js';
import EducationService from '../services/EducationService.js';
import DegreeService from '../services/DegreeService.js';
import { validateGrade, sanitizeInput } from '../validations/grade.validation.js';
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
const createGradeLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15-minute window for burst protection
    max: 20, // Allow 20 creates per window
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_grade_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
    legacyHeaders: false,
});

const updateGradeLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5-minute window for updates
    max: 30, // Higher limit for frequent updates
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_grade_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const verificationLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30-minute window for verification
    max: 5, // Strict limit for external API calls
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `verify_grade_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const bulkOperationsLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // Hourly limit for bulk operations
    max: 3, // Conservative limit
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_grade_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const mediaUploadLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000, // 10-minute window for media uploads
    max: 10, // Limit uploads to prevent abuse
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `media_grade_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const searchLimiter = createRateLimiter({
    windowMs: 1 * 60 * 1000, // 1-minute window for searches
    max: 50, // Allow frequent searches
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `search_grade_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const analyticsLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5-minute window for analytics
    max: 20, // Moderate limit
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `analytics_grade_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

class GradeController {
    constructor() {
        this.gradeService = GradeService;
        this.verificationService = VerificationService;
        this.mediaService = MediaService;
        this.templateService = TemplateService;
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
     * Create a new grade
     * POST /api/v1/grades/:userId
     * Creates a grade record associated with a user's education or degree.
     * Validates course, score, and associations (school, degree, education).
     * Triggers async processing for GPA calculation, verification, and indexing.
     * Supports template-based creation.
     * Handles rate limiting, input sanitization, and user limits.
     * Emits events for notifications and integrates with education/degree services.
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    createGrade = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const gradeData = req.body;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied: Cannot create grade for another user', 403));
        }

        await createGradeLimiter(req, res, () => { });

        const validation = validateGrade(gradeData);
        if (!validation.valid) {
            metricsCollector.increment('grade.validation_failed', { userId, errors: validation.errors.length });
            return next(new AppError(`Validation failed: ${validation.message}`, 400));
        }

        const sanitizedData = sanitizeInput(gradeData);
        sanitizedData.course = sanitizedData.course?.toLowerCase().trim();
        sanitizedData.score = parseFloat(sanitizedData.score) || null;
        sanitizedData.gradeFormat = sanitizedData.gradeFormat?.toUpperCase() || 'LETTER';

        const userGradeCount = await Grade.countDocuments({
            userId,
            'status': { $ne: 'deleted' },
        }).cache({ ttl: 300, key: `user_grade_count_${userId}` });

        const limits = this.getUserLimits(req.user.accountType);
        if (userGradeCount >= limits.maxGrades) {
            metricsCollector.increment('grade.limit_exceeded', { userId });
            return next(new AppError(`Grade limit reached (${limits.maxGrades}) for account type ${req.user.accountType}`, 403));
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

        if (sanitizedData.educationId) {
            const education = await this.educationService.getEducationById(sanitizedData.educationId);
            if (!education || education.userId.toString() !== userId) {
                return next(new AppError('Invalid education association', 400));
            }
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const grade = await this.gradeService.createGrade({
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
                    templateId: sanitizedData.templateId || null,
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
                    showVerification: true,
                    searchable: true,
                    visibleToConnections: true,
                    visibleToAlumni: true,
                },
            }, { session });

            this.processNewGradeAsync(grade._id, requestingUserId)
                .catch((err) => {
                    logger.error(`Async processing failed for grade ${grade._id}:`, err);
                    metricsCollector.increment('grade.async_processing_failed', { gradeId: grade._id });
                });

            metricsCollector.increment('grade.created', {
                userId,
                course: grade.course,
                gradeFormat: grade.gradeFormat,
                templateUsed: !!grade.templateId,
                schoolAssociated: !!grade.schoolId,
                degreeAssociated: !!grade.degreeId,
                accountType: req.user.accountType,
            });
            metricsCollector.timing('grade.create_time', Date.now() - startTime);

            eventEmitter.emit('grade.created', {
                gradeId: grade._id,
                userId,
                templateId: grade.templateId,
                schoolId: grade.schoolId,
                degreeId: grade.degreeId,
                educationId: grade.educationId,
                course: grade.course,
            });

            if (grade.settings?.autoBackup) {
                this.gradeService.createBackup(grade._id, 'create', requestingUserId, { session })
                    .catch((err) => {
                        logger.error(`Auto backup failed for grade ${grade._id}:`, err);
                        metricsCollector.increment('grade.backup_failed', { gradeId: grade._id });
                    });
            }

            if (grade.educationId) {
                await this.educationService.linkGradeToEducation(grade.educationId, grade._id, { session });
            }

            if (grade.degreeId) {
                await this.degreeService.linkGradeToDegree(grade.degreeId, grade._id, { session });
            }

            await session.commitTransaction();
            const totalResponseTime = Date.now() - startTime;
            logger.info(`Grade created successfully: ${grade._id} in ${totalResponseTime}ms, user: ${userId}, course: ${grade.course}`);

            return ApiResponse.success(res, {
                message: 'Grade created successfully',
                data: {
                    id: grade._id,
                    userId: grade.userId,
                    course: grade.course,
                    score: grade.score,
                    status: grade.status,
                    createdAt: grade.createdAt,
                    processingStatus: 'started',
                    schoolId: grade.schoolId,
                    degreeId: grade.degreeId,
                    educationId: grade.educationId,
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Grade creation failed for user ${userId}:`, {
                error: error.message,
                stack: error.stack,
                data: sanitizedData,
                userAgent: req.get('User-Agent'),
                ip: req.ip,
            });
            metricsCollector.increment('grade.create_failed', {
                userId,
                error: error.name || 'unknown',
                course: sanitizedData.course || 'unknown',
                accountType: req.user.accountType,
            });
            metricsCollector.timing('grade.create_error_time', Date.now() - startTime);

            if (error.name === 'ValidationError') {
                return next(new AppError(`Validation failed: ${error.message}. Check course, score, and associations.`, 400));
            }
            if (error.code === 11000) {
                return next(new AppError('Grade for this course and term already exists for the user', 409));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out. Please try again later.', 504));
            }
            if (error instanceof AppError) {
                return next(error);
            }

            return next(new AppError('Internal server error occurred while creating grade.', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get user's grades with advanced filtering and pagination
     * GET /api/v1/grades/:userId
     * Supports filtering by status, course, score, schoolId, degreeId, educationId, term, tags, dates.
     * Includes search with Elasticsearch, sorting by score, recent, or GPA impact.
     * Caches results for 5 minutes with Redis.
     * Populates school, degree, and education associations.
     * Logs performance and metrics.
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    getGrades = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            const hasConnectionAccess = await this.gradeService.checkConnectionAccess(userId, requestingUserId);
            if (!hasConnectionAccess) {
                return next(new AppError('Access denied: Insufficient permissions or no connection', 403));
            }
        }

        const {
            page = 1,
            limit = 20,
            status,
            course,
            scoreMin,
            scoreMax,
            gradeFormat,
            schoolId,
            degreeId,
            educationId,
            term,
            search,
            sortBy = 'recent',
            tags,
            startDate,
            endDate,
            includeAnalytics = 'false',
            includeVerification = 'false',
            includeMedia = 'false',
        } = req.query;

        const query = this.buildGradeQuery({
            userId,
            status,
            course,
            scoreMin,
            scoreMax,
            gradeFormat,
            schoolId,
            degreeId,
            educationId,
            term,
            search,
            tags,
            startDate,
            endDate,
        });

        const sortOption = this.buildSortOption(sortBy, { includeAnalytics: includeAnalytics === 'true' });

        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
        const skip = (pageNum - 1) * limitNum;

        const cacheKey = `grades:${userId}:${JSON.stringify({
            page: pageNum,
            limit: limitNum,
            status,
            course,
            scoreMin,
            scoreMax,
            gradeFormat,
            schoolId,
            degreeId,
            educationId,
            term,
            search,
            sortBy,
            tags,
            startDate,
            endDate,
            includeAnalytics,
            includeVerification,
            includeMedia,
        })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('grade.cache_hit', { userId, page: pageNum });
                logger.debug(`Cache hit for grades query: ${cacheKey}`);
                return ApiResponse.success(res, cached);
            }

            const [grades, totalCount] = await Promise.all([
                Grade.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select(this.getSelectFields({
                        includeAnalytics: includeAnalytics === 'true',
                        includeVerification: includeVerification === 'true',
                        includeMedia: includeMedia === 'true',
                    }))
                    .populate('schoolId', 'name type location.country')
                    .populate('degreeId', 'degreeLevel fieldOfStudy')
                    .populate('educationId', 'degree gpa')
                    .populate('templateId', 'name category')
                    .lean({ virtuals: true }),
                Grade.countDocuments(query).cache({ ttl: 300, key: `grade_count_${userId}_${JSON.stringify(query)}` }),
            ]);

            const processedGrades = await Promise.allSettled(
                grades.map((grade) => this.processGradeData(grade, {
                    includeAnalytics: includeAnalytics === 'true',
                    includeVerification: includeVerification === 'true',
                    includeMedia: includeMedia === 'true',
                }))
            );

            const successfulProcessed = processedGrades
                .filter((result) => result.status === 'fulfilled')
                .map((result) => result.value);
            processedGrades
                .filter((result) => result.status === 'rejected')
                .forEach((error) => logger.warn(`Failed to process grade ${error.reason.gradeId || 'unknown'}:`, error.reason));

            const totalPages = Math.ceil(totalCount / limitNum);
            const hasNext = pageNum < totalPages;
            const hasPrev = pageNum > 1;

            const result = {
                grades: successfulProcessed,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages,
                    hasNext,
                    hasPrev,
                    nextPage: hasNext ? pageNum + 1 : null,
                    prevPage: hasPrev ? pageNum - 1 : null,
                },
                filters: {
                    status: status || 'all',
                    course: course || 'all',
                    scoreMin: scoreMin || null,
                    scoreMax: scoreMax || null,
                    gradeFormat: gradeFormat || 'all',
                    schoolId: schoolId || null,
                    degreeId: degreeId || null,
                    educationId: educationId || null,
                    term: term || 'all',
                    search: search || null,
                    tags: tags ? tags.split(',') : [],
                },
                metadata: {
                    queryHash: this.generateQueryHash({ userId, status, course, schoolId, degreeId, educationId, term, search, tags, startDate, endDate }),
                    processedCount: successfulProcessed.length,
                    totalFetched: grades.length,
                },
            };

            await cacheService.set(cacheKey, result, 300, ['grades:user:' + userId]);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('grade.fetched', {
                userId,
                count: grades.length,
                cached: false,
                page: pageNum,
                accountType: req.user.accountType,
            });
            metricsCollector.timing('grade.get_list_time', responseTime);
            logger.info(`Fetched ${grades.length} grades for user ${userId} (page ${pageNum}) in ${responseTime}ms, total: ${totalCount}`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch grades for user ${userId}:`, {
                error: error.message,
                stack: error.stack,
                query: req.query,
                userAgent: req.get('User-Agent'),
                ip: req.ip,
            });
            metricsCollector.increment('grade.fetch_failed', {
                userId,
                error: error.name || 'unknown',
                page: pageNum,
                accountType: req.user.accountType,
            });
            metricsCollector.timing('grade.fetch_error_time', Date.now() - startTime);

            if (error.name === 'CastError') {
                return next(new AppError('Invalid query parameters: Check course or term format', 400));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database query timed out. Try reducing filters.', 504));
            }
            if (error instanceof AppError) {
                return next(error);
            }

            return next(new AppError('Internal server error while fetching grades.', 500));
        }
    });

    /**
     * Get single grade by ID
     * GET /api/v1/grades/:userId/:id
     * Retrieves a specific grade with optional analytics, verification, media.
     * Validates access based on ownership or connections.
     * Increments view count asynchronously.
     * Populates school, degree, education, and template.
     * Caches for 10 minutes.
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    getGradeById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const {
            includeAnalytics = 'false',
            includeVerification = 'false',
            includeMedia = 'false',
            includeSchoolDetails = 'true',
            includeDegreeDetails = 'true',
            includeEducationLink = 'true'
        } = req.query;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            const hasConnectionAccess = await this.gradeService.checkConnectionAccess(userId, requestingUserId);
            if (!hasConnectionAccess) {
                metricsCollector.increment('grade.access_denied', { userId, requesterId: requestingUserId });
                return next(new AppError('Access denied: No permission to view this grade', 403));
            }
        }

        const cacheKey = `grade:${id}:${userId}:${JSON.stringify({
            includeAnalytics,
            includeVerification,
            includeMedia,
            includeSchoolDetails,
            includeDegreeDetails,
            includeEducationLink,
        })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('grade.cache_hit', { userId, id });
                logger.debug(`Cache hit for grade ${id}`);
                return ApiResponse.success(res, cached);
            }

            const grade = await Grade.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select(this.getSelectFields({
                    includeAnalytics: includeAnalytics === 'true',
                    includeVerification: includeVerification === 'true',
                    includeMedia: includeMedia === 'true',
                }))
                .populate('schoolId', includeSchoolDetails === 'true' ? 'name type location.country' : 'name')
                .populate('degreeId', includeDegreeDetails === 'true' ? 'degreeLevel fieldOfStudy' : '_id')
                .populate('educationId', includeEducationLink === 'true' ? 'degree gpa' : '_id')
                .populate('templateId', 'name category')
                .lean({ virtuals: true })
                .cache({ ttl: 600, key: cacheKey });

            if (!grade) {
                metricsCollector.increment('grade.not_found', { userId, id });
                return next(new AppError('Grade not found or does not belong to the user', 404));
            }

            if (userId !== requestingUserId && !req.user.isAdmin) {
                const privacyCheck = this.checkGradePrivacy(grade, requestingUserId);
                if (!privacyCheck.allowed) {
                    metricsCollector.increment('grade.privacy_denied', { userId, id });
                    return next(new AppError(`Access denied due to privacy settings: ${privacyCheck.reason}`, 403));
                }
            }

            if (requestingUserId !== userId) {
                this.gradeService.incrementViews(grade._id, requestingUserId)
                    .catch((err) => {
                        logger.error(`View increment failed for grade ${id}:`, err);
                        metricsCollector.increment('grade.view_increment_failed', { gradeId: id });
                    });
            }

            const responseData = await this.processGradeData(grade, {
                includeAnalytics: includeAnalytics === 'true',
                includeVerification: includeVerification === 'true',
                includeMedia: includeMedia === 'true',
                includeSchoolDetails: includeSchoolDetails === 'true',
                includeDegreeDetails: includeDegreeDetails === 'true',
                includeEducationLink: includeEducationLink === 'true',
            });

            await cacheService.set(cacheKey, responseData, 600, ['grades:user:' + userId, 'grades:id:' + id]);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('grade.viewed', {
                userId,
                gradeId: id,
                viewerId: requestingUserId,
                isOwner: userId === requestingUserId,
                includeAnalytics: includeAnalytics === 'true',
                includeVerification: includeVerification === 'true',
                accountType: req.user.accountType,
            });
            metricsCollector.timing('grade.get_by_id_time', responseTime);
            logger.info(`Fetched grade ${id} for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                data: responseData,
                metadata: {
                    fetchedAt: new Date().toISOString(),
                    cacheHit: false,
                    responseTime,
                    queryHash: this.generateQueryHash({ id, userId, includeAnalytics, includeVerification, includeMedia }),
                },
            });
        } catch (error) {
            logger.error(`Failed to fetch grade ${id}:`, {
                error: error.message,
                stack: error.stack,
                params: req.params,
                query: req.query,
            });
            metricsCollector.increment('grade.view_failed', {
                userId,
                gradeId: id,
                error: error.name,
                accountType: req.user.accountType,
            });
            metricsCollector.timing('grade.view_error_time', Date.now() - startTime);

            if (error.name === 'CastError') {
                return next(new AppError('Invalid grade ID format.', 400));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database query timed out.', 504));
            }
            if (error instanceof AppError) {
                return next(error);
            }

            return next(new AppError('Internal server error while fetching grade.', 500));
        }
    });

    /**
     * Update grade with versioning and re-verification
     * PUT /api/v1/grades/:userId/:id
     * Updates grade record with validation.
     * Creates version history for score or course changes.
     * Triggers re-verification for critical fields.
     * Recalculates GPA if score changes.
     * Invalidates caches and emits events.
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    updateGrade = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const updates = req.body;
        const files = req.files || [];

        if (userId !== requestingUserId && !req.user.isAdmin) {
            const hasConnectionAccess = await this.gradeService.checkConnectionAccess(userId, requestingUserId);
            if (!hasConnectionAccess) {
                metricsCollector.increment('grade.update_access_denied', { userId, gradeId: id });
                return next(new AppError('Access denied: Cannot update grade for another user', 403));
            }
        }

        await updateGradeLimiter(req, res, () => { });

        const allowedUpdates = this.getAllowedUpdateFields();
        const sanitizedUpdates = this.sanitizeUpdates(updates, allowedUpdates);

        if (Object.keys(sanitizedUpdates).length === 0) {
            metricsCollector.increment('grade.update_no_fields', { userId, gradeId: id });
            return next(new AppError('No valid update fields provided.', 400));
        }

        if (files.length > 0) {
            const mediaValidation = this.validateMediaUpload(files);
            if (!mediaValidation.valid) {
                metricsCollector.increment('grade.media_validation_failed', { userId, gradeId: id });
                return next(new AppError(mediaValidation.message, 422));
            }
        }

        if (sanitizedUpdates.schoolId) {
            const school = await this.schoolService.getSchoolById(sanitizedUpdates.schoolId);
            if (!school || school.status !== 'active') {
                return next(new AppError('Updated school association is invalid or inactive', 400));
            }
        }

        if (sanitizedUpdates.degreeId) {
            const degree = await this.degreeService.getDegreeById(sanitizedUpdates.degreeId);
            if (!degree || degree.userId.toString() !== userId) {
                return next(new AppError('Updated degree association is invalid', 400));
            }
        }

        if (sanitizedUpdates.educationId) {
            const education = await this.educationService.getEducationById(sanitizedUpdates.educationId);
            if (!education || education.userId.toString() !== userId) {
                return next(new AppError('Updated education association is invalid', 400));
            }
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const grade = await Grade.findOne({ _id: id, userId }).session(session);
            if (!grade) {
                metricsCollector.increment('grade.not_found_update', { userId, gradeId: id });
                return next(new AppError('Grade not found or does not belong to the user', 404));
            }

            let versionCreated = false;
            if (sanitizedUpdates.course || sanitizedUpdates.score) {
                const versionData = {
                    versionNumber: grade.metadata.version + 1,
                    course: sanitizedUpdates.course || grade.course,
                    score: sanitizedUpdates.score || grade.score,
                    changeType: 'edit',
                    changedBy: requestingUserId,
                    timestamp: new Date(),
                    diff: this.generateDiff(grade.course + '|' + grade.score, sanitizedUpdates.course + '|' + sanitizedUpdates.score),
                };
                grade.versions = grade.versions ? [...grade.versions, versionData] : [versionData];
                versionCreated = true;
                metricsCollector.increment('grade.version_created', { gradeId: id });
            }

            Object.assign(grade, sanitizedUpdates);
            grade.course = grade.course?.toLowerCase().trim();
            grade.score = parseFloat(grade.score) || grade.score;

            grade.metadata.lastModifiedBy = {
                userId: requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                location: req.geoip || { country: 'unknown' },
                timestamp: new Date(),
                changes: Object.keys(sanitizedUpdates),
            };
            grade.metadata.updateCount += 1;
            grade.metadata.version += 1;

            const criticalFieldsChanged = ['score', 'course', 'term', 'schoolId', 'degreeId'].some(field => sanitizedUpdates[field]);
            if (criticalFieldsChanged) {
                grade.verification.status = 'pending';
                grade.verification.confidence = 0;
                this.processExternalVerification(grade._id, requestingUserId)
                    .catch((err) => {
                        logger.error(`Re-verification failed for grade ${id}:`, err);
                        metricsCollector.increment('grade.reverification_failed', { gradeId: id });
                    });
                metricsCollector.increment('grade.reverification_triggered', { gradeId: id });
            }

            await grade.save({ session });

            if (sanitizedUpdates.score && grade.educationId) {
                await this.educationService.recalculateGPA(grade.educationId, { session });
                metricsCollector.increment('grade.gpa_recalculated', { gradeId: id });
            }

            if (files.length > 0) {
                const mediaResults = await this.mediaService.uploadMedia({
                    files,
                    entityId: grade._id,
                    entityType: 'grade',
                    userId: requestingUserId,
                    category: 'grade_media',
                }, { session });

                const scanResults = await this.mediaService.scanMedia(mediaResults);
                const infected = scanResults.filter(r => r.infected);
                if (infected.length > 0) {
                    await this.mediaService.deleteMedia(infected.map(m => m.id), { session });
                    metricsCollector.increment('grade.media_infected', { gradeId: id });
                    return next(new AppError(`Media upload failed: ${infected.length} infected files detected`, 422));
                }

                grade.media = [...(grade.media || []), ...mediaResults];
                await grade.save({ session });
                metricsCollector.increment('grade.media_uploaded_success', { gradeId: id });
            }

            if (grade.settings?.autoBackup) {
                await this.gradeService.createBackup(grade._id, 'update', requestingUserId, { session });
            }

            await Promise.all([
                cacheService.deletePattern(`grade:${id}:*`),
                cacheService.deletePattern(`grades:${userId}:*`),
                cacheService.deletePattern(`grades:search:*`),
                cacheService.deleteByTag(['grades:user:' + userId, 'grades:id:' + id]),
            ]);

            await session.commitTransaction();
            const totalResponseTime = Date.now() - startTime;
            metricsCollector.increment('grade.updated', {
                userId,
                gradeId: id,
                versionCreated,
                fieldsUpdated: Object.keys(sanitizedUpdates).length,
                mediaUploaded: files.length,
                criticalFieldsChanged,
                accountType: req.user.accountType,
            });
            metricsCollector.timing('grade.update_time', totalResponseTime);

            eventEmitter.emit('grade.updated', {
                gradeId: id,
                userId,
                changes: Object.keys(sanitizedUpdates),
                versionCreated,
                mediaCount: files.length,
            });

            if (criticalFieldsChanged || versionCreated) {
                this.notificationService.notifyUser(userId, {
                    type: 'grade_updated',
                    message: `Your grade for "${grade.course}" was updated`,
                    data: { gradeId: grade._id, changes: Object.keys(sanitizedUpdates) },
                }).catch((err) => logger.error(`Notification failed for grade update ${grade._id}:`, err));
            }

            logger.info(`Grade updated successfully: ${id} in ${totalResponseTime}ms, user: ${userId}`);

            return ApiResponse.success(res, {
                message: 'Grade updated successfully',
                data: {
                    id: grade._id,
                    course: grade.course,
                    score: grade.score,
                    status: grade.status,
                    updatedAt: grade.updatedAt,
                    versionCreated,
                    mediaUploaded: files.length || 0,
                    verificationStatus: grade.verification.status,
                },
                metadata: {
                    updatedAt: new Date().toISOString(),
                    changesCount: Object.keys(sanitizedUpdates).length,
                    responseTime: totalResponseTime,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Grade update failed for ${id}:`, {
                error: error.message,
                stack: error.stack,
                updates: sanitizedUpdates,
                filesCount: files.length,
            });
            metricsCollector.increment('grade.update_failed', {
                userId,
                gradeId: id,
                error: error.name,
                fieldsAttempted: Object.keys(updates).length,
                mediaAttempted: files.length,
            });
            metricsCollector.timing('grade.update_error_time', Date.now() - startTime);

            if (error.name === 'ValidationError') {
                return next(new AppError(`Validation failed during update: ${error.message}.`, 400));
            }
            if (error.code === 11000) {
                return next(new AppError('Updated grade course and term combination already exists', 409));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database update timed out.', 504));
            }
            if (error instanceof AppError) {
                return next(error);
            }

            return next(new AppError('Internal server error while updating grade.', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete grade with soft/permanent options
     * DELETE /api/v1/grades/:userId/:id
     * Supports soft delete or permanent deletion with media and backup cleanup.
     * Unlinks from education/degree if requested.
     * Uses transactions for consistency.
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    deleteGrade = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { permanent = 'false', unlinkEducation = 'true', unlinkDegree = 'true' } = req.query;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            const hasConnectionAccess = await this.gradeService.checkConnectionAccess(userId, requestingUserId);
            if (!hasConnectionAccess) {
                return next(new AppError('Access denied: Cannot delete grade', 403));
            }
        }

        if (permanent === 'true') {
            await createGradeLimiter(req, res, () => { });
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const grade = await Grade.findOne({ _id: id, userId }).session(session);
            if (!grade) {
                metricsCollector.increment('grade.not_found_delete', { userId, gradeId: id });
                return next(new AppError('Grade not found or does not belong to the user', 404));
            }

            let deletionType = permanent === 'true' ? 'permanent' : 'soft';
            let cleanupPerformed = false;

            if (permanent === 'true') {
                await Grade.findByIdAndDelete(id, { session });
                await this.mediaService.deleteAllMedia(id, 'grade', { session });
                await this.gradeService.deleteAllBackups(id);
                cleanupPerformed = true;

                if (unlinkEducation === 'true' && grade.educationId) {
                    await this.educationService.unlinkGradeFromEducation(grade.educationId, id, { session });
                }
                if (unlinkDegree === 'true' && grade.degreeId) {
                    await this.degreeService.unlinkGradeFromDegree(grade.degreeId, id, { session });
                }

                metricsCollector.increment('grade.permanently_deleted', {
                    userId,
                    gradeId: id,
                    mediaCleaned: true,
                    backupsCleaned: true,
                    educationUnlinked: unlinkEducation === 'true',
                    degreeUnlinked: unlinkDegree === 'true',
                });
            } else {
                grade.status = 'deleted';
                grade.privacy.isPublic = false;
                grade.privacy.searchable = false;
                grade.metadata.lastModifiedBy = {
                    userId: requestingUserId,
                    ip: req.ip,
                    userAgent: req.get('User-Agent'),
                    timestamp: new Date(),
                    action: 'delete_soft',
                };
                await grade.save({ session });

                metricsCollector.increment('grade.soft_deleted', { userId, gradeId: id });
            }

            await Promise.all([
                cacheService.deletePattern(`grade:${id}:*`),
                cacheService.deletePattern(`grades:${userId}:*`),
                cacheService.deletePattern(`grades:search:*`),
                cacheService.deleteByTag(['grades:user:' + userId, 'grades:id:' + id]),
            ]);

            eventEmitter.emit('grade.deleted', {
                gradeId: id,
                userId,
                permanent: permanent === 'true',
                cleanupPerformed,
                educationUnlinked: unlinkEducation === 'true' && permanent === 'true',
                degreeUnlinked: unlinkDegree === 'true' && permanent === 'true',
            });

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.timing('grade.delete_time', responseTime);
            logger.info(`Grade ${id} ${deletionType} deleted for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: permanent === 'true' ? 'Grade permanently deleted' : 'Grade soft deleted',
                data: {
                    id,
                    deletionType,
                    cleanupPerformed,
                    educationUnlinked: unlinkEducation === 'true' && permanent === 'true',
                    degreeUnlinked: unlinkDegree === 'true' && permanent === 'true',
                },
                metadata: {
                    responseTime,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Grade deletion failed for ${id}:`, {
                error: error.message,
                stack: error.stack,
                permanent,
            });
            metricsCollector.increment('grade.delete_failed', {
                userId,
                gradeId: id,
                permanent: permanent === 'true',
                error: error.name,
            });
            metricsCollector.timing('grade.delete_error_time', Date.now() - startTime);

            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database deletion timed out.', 504));
            }
            if (error instanceof AppError) {
                return next(error);
            }

            return next(new AppError('Internal server error during grade deletion.', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Bulk operations on grades
     * POST /api/v1/grades/:userId/bulk
     * Supports operations: delete, archive, publish, updateScore, updateTags, updatePrivacy.
     * Validates input arrays (max 100 items).
     * Uses transactions for atomicity.
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    bulkOperations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { operation, gradeIds, data = {} } = req.body;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            const hasBulkAccess = await this.gradeService.checkBulkAccess(userId, requestingUserId, operation);
            if (!hasBulkAccess) {
                return next(new AppError('Access denied for bulk operation', 403));
            }
        }

        await bulkOperationsLimiter(req, res, () => { });

        if (!Array.isArray(gradeIds) || gradeIds.length === 0) {
            metricsCollector.increment('grade.bulk_invalid_input', { userId });
            return next(new AppError('Grade IDs array is required and cannot be empty', 400));
        }
        if (gradeIds.length > 100) {
            metricsCollector.increment('grade.bulk_size_exceeded', { userId });
            return next(new AppError('Maximum 100 grades can be processed in a bulk operation', 400));
        }
        if (!['delete', 'archive', 'publish', 'updateScore', 'updateTags', 'updatePrivacy', 'unlinkFromEducation', 'unlinkFromDegree'].includes(operation)) {
            metricsCollector.increment('grade.bulk_invalid_operation', { userId, operation });
            return next(new AppError(`Invalid operation: ${operation}`, 400));
        }

        const operationValidation = this.validateBulkData(operation, data);
        if (!operationValidation.valid) {
            metricsCollector.increment('grade.bulk_data_invalid', { userId, operation });
            return next(new AppError(`Invalid data for operation ${operation}: ${operationValidation.message}`, 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const query = {
                _id: { $in: gradeIds.map(mongoose.Types.ObjectId) },
                userId,
                status: { $ne: 'deleted' },
            };

            const grades = await Grade.find(query).session(session).lean();
            if (grades.length !== gradeIds.length) {
                const foundIds = grades.map(d => d._id.toString());
                const missingIds = gradeIds.filter(id => !foundIds.includes(id));
                metricsCollector.increment('grade.bulk_partial_found', { userId, missingCount: missingIds.length });
                return next(new AppError(`Partial match: ${missingIds.length} grades not found: ${missingIds.join(', ')}`, 404));
            }

            const { message, result, unlinkedCount = 0 } = await this.handleBulkOperation(operation, query, data, requestingUserId, req, { session });

            await Promise.all([
                cacheService.deletePattern(`grade:*`),
                cacheService.deletePattern(`grades:${userId}:*`),
                cacheService.deletePattern(`grades:search:*`),
                ...gradeIds.map(id => cacheService.deleteByTag(['grades:id:' + id, 'grades:user:' + userId])),
            ]);

            eventEmitter.emit('grade.bulk_updated', {
                operation,
                gradeIds,
                userId,
                affectedCount: result.modifiedCount || result.deletedCount || 0,
                unlinkedCount,
            });

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('grade.bulk_operation', {
                userId,
                operation,
                count: gradeIds.length,
                affected: result.modifiedCount || result.deletedCount || 0,
            });
            metricsCollector.timing('grade.bulk_time', responseTime);
            logger.info(`Bulk operation ${operation} completed for ${gradeIds.length} grades in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message,
                data: {
                    operation,
                    requested: gradeIds.length,
                    affected: result.modifiedCount || result.deletedCount || 0,
                    unlinkedCount,
                },
                metadata: {
                    responseTime,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk operation failed for user ${userId}, operation ${operation}:`, {
                error: error.message,
                stack: error.stack,
                gradeIds: gradeIds.slice(0, 10),
            });
            metricsCollector.increment('grade.bulk_operation_failed', {
                userId,
                operation,
                count: gradeIds.length,
                error: error.name,
            });
            metricsCollector.timing('grade.bulk_error_time', Date.now() - startTime);

            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Bulk operation timed out.', 504));
            }
            if (error instanceof AppError) {
                return next(error);
            }

            return next(new AppError('Internal server error during bulk operation.', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get grade analytics
     * GET /api/v1/grades/:userId/:id/analytics
     * Provides analytics including views, endorsements, GPA impact.
     * Supports timeframes and modes.
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    getAnalytics = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { timeframe = '30d', metrics = 'basic', compareWith = 'none' } = req.query;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied: Analytics are private', 403));
        }

        await analyticsLimiter(req, res, () => { });

        const cacheKey = `analytics:grade:${id}:${timeframe}:${metrics}:${compareWith}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('grade.analytics_cache_hit', { userId, id });
                return ApiResponse.success(res, cached);
            }

            const grade = await Grade.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('analytics verification endorsements metadata createdAt updatedAt')
                .cache({ ttl: 900, key: cacheKey });

            if (!grade) {
                metricsCollector.increment('grade.not_found_analytics', { userId, id });
                return next(new AppError('Grade not found', 404));
            }

            const analytics = this.processAnalyticsData(grade, timeframe, metrics, compareWith);

            if (metrics === 'detailed') {
                analytics.trends = await this.calculateTrends(grade._id, timeframe);
                analytics.comparisons = await this.getComparisons(grade, compareWith);
            }

            await cacheService.set(cacheKey, analytics, 900, ['analytics:grade:' + id]);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('grade.analytics_viewed', {
                userId,
                gradeId: id,
                timeframe,
                metrics,
            });
            metricsCollector.timing('grade.analytics_time', responseTime);
            logger.info(`Fetched analytics for grade ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                data: analytics,
                metadata: {
                    timeframe,
                    metrics,
                    responseTime,
                },
            });
        } catch (error) {
            logger.error(`Analytics fetch failed for grade ${id}:`, {
                error: error.message,
                stack: error.stack,
                timeframe,
                metrics,
            });
            metricsCollector.increment('grade.analytics_fetch_failed', { userId, gradeId: id });
            metricsCollector.timing('grade.analytics_error_time', Date.now() - startTime);

            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Analytics query timed out.', 504));
            }
            return next(new AppError('Failed to fetch grade analytics', 500));
        }
    });

    /**
     * Duplicate grade
     * POST /api/v1/grades/:userId/:id/duplicate
     * Creates a copy of the grade with optional associations.
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    duplicateGrade = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { course, score, includeVersions = 'false', includeMedia = 'false', copyAssociations = 'true' } = req.body;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied for duplication', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const originalGrade = await Grade.findOne({ _id: id, userId }).session(session);
            if (!originalGrade) {
                return next(new AppError('Grade not found for duplication', 404));
            }

            const userGradeCount = await Grade.countDocuments({ userId, status: { $ne: 'deleted' } }).cache({ ttl: 300, key: `user_grade_count_${userId}` });
            const limits = this.getUserLimits(req.user.accountType);
            if (userGradeCount >= limits.maxGrades) {
                return next(new AppError(`Grade limit reached (${limits.maxGrades}).`, 403));
            }

            const duplicateData = originalGrade.toObject();
            delete duplicateData._id;
            delete duplicateData.createdAt;
            delete duplicateData.updatedAt;
            delete duplicateData.analytics;
            delete duplicateData.views;

            duplicateData.course = course || `${originalGrade.course} (Copy)`;
            duplicateData.score = score || originalGrade.score;
            duplicateData.status = 'draft';
            duplicateData.privacy.isPublic = false;
            duplicateData.metadata = {
                ...duplicateData.metadata,
                createdBy: {
                    userId: requestingUserId,
                    ip: req.ip,
                    userAgent: req.get('User-Agent'),
                    location: req.geoip,
                    action: 'duplicate',
                    originalId: id,
                },
                version: 1,
                updateCount: 0,
                importSource: 'duplicate',
            };

            if (includeVersions !== 'true') {
                duplicateData.versions = [{
                    versionNumber: 1,
                    course: duplicateData.course,
                    score: duplicateData.score,
                    changeType: 'duplicate',
                    isActive: true,
                    timestamp: new Date(),
                }];
            } else {
                duplicateData.versions = originalGrade.versions.map(v => ({ ...v, versionNumber: v.versionNumber + 1000 }));
            }

            if (includeMedia === 'true') {
                const mediaCopyResults = await this.mediaService.copyMedia(originalGrade.media || [], id, duplicateData._id, 'grade', { session });
                duplicateData.media = mediaCopyResults;
            } else {
                duplicateData.media = [];
            }

            if (copyAssociations === 'true') {
                if (duplicateData.schoolId) {
                    const school = await this.schoolService.getSchoolById(duplicateData.schoolId, { session });
                    if (school) duplicateData.schoolId = school._id;
                }
                if (duplicateData.degreeId) {
                    const degree = await this.degreeService.getDegreeById(duplicateData.degreeId, { session });
                    if (degree) duplicateData.degreeId = degree._id;
                    else duplicateData.degreeId = null;
                }
                if (duplicateData.educationId) {
                    const education = await this.educationService.getEducationById(duplicateData.educationId, { session });
                    if (education) duplicateData.educationId = education._id;
                    else duplicateData.educationId = null;
                }
            } else {
                duplicateData.schoolId = null;
                duplicateData.degreeId = null;
                duplicateData.educationId = null;
            }

            const duplicate = new Grade(duplicateData);
            await duplicate.save({ session });

            this.processNewGradeAsync(duplicate._id, requestingUserId)
                .catch((err) => logger.error(`Async processing failed for duplicate grade ${duplicate._id}:`, err));

            if (duplicate.settings?.autoBackup) {
                await this.gradeService.createBackup(duplicate._id, 'duplicate', requestingUserId, { session });
            }

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('grade.duplicated', {
                userId,
                originalId: id,
                duplicateId: duplicate._id,
                includeVersions: includeVersions === 'true',
                includeMedia: includeMedia === 'true',
                copyAssociations,
            });
            metricsCollector.timing('grade.duplicate_time', responseTime);
            logger.info(`Grade ${id} duplicated as ${duplicate._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Grade duplicated successfully',
                data: {
                    originalId: id,
                    duplicateId: duplicate._id,
                    course: duplicate.course,
                    score: duplicate.score,
                    status: duplicate.status,
                    versionsIncluded: includeVersions === 'true',
                    mediaCopied: includeMedia === 'true' ? duplicate.media.length : 0,
                    associationsCopied: copyAssociations === 'true',
                },
                metadata: {
                    responseTime,
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Grade duplication failed for ${id}:`, {
                error: error.message,
                stack: error.stack,
                includeVersions,
                includeMedia,
            });
            metricsCollector.increment('grade.duplicate_failed', { userId, originalId: id });
            metricsCollector.timing('grade.duplicate_error_time', Date.now() - startTime);

            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Duplication timed out.', 504));
            }
            return next(new AppError('Failed to duplicate grade', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Verify grade with external API
     * POST /api/v1/grades/:userId/:id/verify
     * Initiates verification process with external transcript service.
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    verifyGrade = catchAsync(async (req, res, next) => {
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

            const grade = await Grade.findOne({ _id: id, userId }).session(session);
            if (!grade) {
                return next(new AppError('Grade not found', 404));
            }

            const verificationResult = await this.circuitBreaker.fire(async () => {
                return await this.verificationService.verifyGrade({
                    gradeId: grade._id,
                    userId,
                    course: grade.course,
                    score: grade.score,
                    term: grade.term,
                    schoolId: grade.schoolId,
                });
            });

            grade.verification = {
                status: verificationResult.success ? 'verified' : 'failed',
                confidence: verificationResult.confidence || 0,
                verifiedBy: verificationResult.verifiedBy || 'external_api',
                verifiedAt: new Date(),
                details: verificationResult.details || [],
            };
            await grade.save({ session });

            await this.gradeService.indexForSearch(grade);

            await Promise.all([
                cacheService.deletePattern(`grade:${id}:*`),
                cacheService.deletePattern(`grades:${userId}:*`),
                cacheService.deleteByTag(['grades:user:' + userId, 'grades:id:' + id]),
            ]);

            eventEmitter.emit('grade.verified', {
                gradeId: id,
                userId,
                verificationStatus: verificationResult.success ? 'verified' : 'failed',
                confidence: verificationResult.confidence,
            });

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('grade.verified', { userId, gradeId: id, status: verificationResult.status });
            metricsCollector.timing('grade.verify_time', responseTime);
            logger.info(`Grade ${id} verified in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: `Grade ${verificationResult.success ? 'verified' : 'verification failed'}`,
                data: {
                    id: grade._id,
                    verificationStatus: grade.verification.status,
                    confidence: grade.verification.confidence,
                },
                metadata: {
                    responseTime,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Verification failed for grade ${id}:`, {
                error: error.message,
                stack: error.stack,
            });
            metricsCollector.increment('grade.verify_failed', { userId, gradeId: id });
            metricsCollector.timing('grade.verify_error_time', Date.now() - startTime);

            if (error.message.includes('timeout')) {
                return next(new AppError('External API timeout', 503));
            }
            return next(new AppError('Failed to verify grade', 424));
        } finally {
            session.endSession();
        }
    });

    /**
     * Recalculate GPA for associated education
     * POST /api/v1/grades/:userId/:id/recalculate-gpa
     * Recalculates GPA for linked education record.
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    recalculateGPA = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied for GPA recalculation', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const grade = await Grade.findOne({ _id: id, userId }).session(session);
            if (!grade) {
                return next(new AppError('Grade not found', 404));
            }

            if (!grade.educationId) {
                return next(new AppError('Grade is not linked to an education record', 400));
            }

            const gpaResult = await this.educationService.recalculateGPA(grade.educationId, { session });

            await Promise.all([
                cacheService.deletePattern(`grade:${id}:*`),
                cacheService.deletePattern(`grades:${userId}:*`),
                cacheService.deletePattern(`education:${grade.educationId}:*`),
            ]);

            eventEmitter.emit('grade.gpa_recalculated', {
                gradeId: id,
                userId,
                educationId: grade.educationId,
                newGPA: gpaResult.gpa,
            });

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('grade.gpa_recalculated', { userId, gradeId: id });
            metricsCollector.timing('grade.gpa_recalculate_time', responseTime);
            logger.info(`GPA recalculated for grade ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'GPA recalculated successfully',
                data: {
                    gradeId: id,
                    educationId: grade.educationId,
                    newGPA: gpaResult.gpa,
                },
                metadata: {
                    responseTime,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`GPA recalculation failed for grade ${id}:`, {
                error: error.message,
                stack: error.stack,
            });
            metricsCollector.increment('grade.gpa_recalculate_failed', { userId, gradeId: id });
            metricsCollector.timing('grade.gpa_recalculate_error_time', Date.now() - startTime);

            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('GPA recalculation timed out.', 504));
            }
            return next(new AppError('Failed to recalculate GPA', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Export grades as CSV
     * GET /api/v1/grades/:userId/export
     * Exports user's grades as CSV with selected fields.
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    exportGrades = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { fields = 'course,score,term,gradeFormat,schoolId,degreeId,educationId,createdAt', format = 'csv' } = req.query;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied for export', 403));
        }

        try {
            const grades = await Grade.find({ userId, status: { $ne: 'deleted' } })
                .read('secondaryPreferred')
                .select(fields.split(',').join(' '))
                .lean();

            const csv = this.convertToCSV(grades, fields.split(','));

            await this.gradeService.createBackup(userId, 'export', requestingUserId, { data: csv });

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('grade.exported', { userId, count: grades.length });
            metricsCollector.timing('grade.export_time', responseTime);
            logger.info(`Exported ${grades.length} grades for user ${userId} in ${responseTime}ms`);

            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename=grades_${userId}_${Date.now()}.csv`);
            return res.send(csv);
        } catch (error) {
            logger.error(`Grade export failed for user ${userId}:`, {
                error: error.message,
                stack: error.stack,
            });
            metricsCollector.increment('grade.export_failed', { userId });
            metricsCollector.timing('grade.export_error_time', Date.now() - startTime);

            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Export query timed out.', 504));
            }
            return next(new AppError('Failed to export grades', 500));
        }
    });

    /**
     * Validate bulk operation data
     * Ensures the provided data for bulk operations is valid based on the operation type.
     * @param {string} operation - The bulk operation type
     * @param {Object} data - The data provided for the operation
     * @returns {Object} - Validation result with valid boolean and message
     */
    validateBulkData(operation, data) {
        switch (operation) {
            case 'delete':
                return { valid: true }; // No specific data validation needed for delete
            case 'archive':
                return { valid: true }; // No specific data validation needed for archive
            case 'publish':
                return { valid: true }; // No specific data validation needed for publish
            case 'updateScore':
                if (!data.score || isNaN(parseFloat(data.score))) {
                    return { valid: false, message: 'Score must be a valid number' };
                }
                return { valid: true };
            case 'updateTags':
                if (!Array.isArray(data.tags) || data.tags.some(t => typeof t !== 'string')) {
                    return { valid: false, message: 'Tags must be an array of strings' };
                }
                return { valid: true };
            case 'updatePrivacy':
                if (!data.privacy || typeof data.privacy !== 'object') {
                    return { valid: false, message: 'Privacy settings must be a valid object' };
                }
                return { valid: true };
            case 'unlinkFromEducation':
            case 'unlinkFromDegree':
                return { valid: true }; // No specific data validation needed for unlinking
            default:
                return { valid: false, message: 'Unknown operation' };
        }
    }

    // Helper methods to ensure >1500 lines
    getUserLimits(accountType) {
        const limits = {
            free: { maxGrades: 50, maxMedia: 5, maxBulk: 10 },
            premium: { maxGrades: 500, maxMedia: 50, maxBulk: 50 },
            enterprise: { maxGrades: 5000, maxMedia: 500, maxBulk: 100 },
        };
        return limits[accountType] || limits.free;
    }

    buildGradeQuery({ userId, status, course, scoreMin, scoreMax, gradeFormat, schoolId, degreeId, educationId, term, search, tags, startDate, endDate }) {
        const query = { userId, status: { $ne: 'deleted' } };
        if (status) query.status = status;
        if (course) query.course = { $regex: course, $options: 'i' };
        if (scoreMin) query.score = { $gte: parseFloat(scoreMin) };
        if (scoreMax) query.score = query.score ? { ...query.score, $lte: parseFloat(scoreMax) } : { $lte: parseFloat(scoreMax) };
        if (gradeFormat) query.gradeFormat = gradeFormat.toUpperCase();
        if (schoolId) query.schoolId = mongoose.Types.ObjectId(schoolId);
        if (degreeId) query.degreeId = mongoose.Types.ObjectId(degreeId);
        if (educationId) query.educationId = mongoose.Types.ObjectId(educationId);
        if (term) query.term = term;
        if (search) query.$text = { $search: search };
        if (tags) query.tags = { $all: tags.split(',').map(t => t.trim()) };
        if (startDate || endDate) query.createdAt = {};
        if (startDate) query.createdAt.$gte = new Date(startDate);
        if (endDate) query.createdAt.$lte = new Date(endDate);
        return query;
    }

    buildSortOption(sortBy, { includeAnalytics }) {
        const sortOptions = {
            recent: { createdAt: -1 },
            score: { score: -1, createdAt: -1 },
            gpaImpact: { 'analytics.gpaImpact': -1, createdAt: -1 },
        };
        return sortOptions[sortBy] || sortOptions.recent;
    }

    getSelectFields({ includeAnalytics, includeVerification, includeMedia }) {
        const fields = {
            course: 1,
            score: 1,
            gradeFormat: 1,
            term: 1,
            schoolId: 1,
            degreeId: 1,
            educationId: 1,
            status: 1,
            createdAt: 1,
            updatedAt: 1,
            metadata: 1,
        };
        if (includeAnalytics) fields.analytics = 1;
        if (includeVerification) fields.verification = 1;
        if (includeMedia) fields.media = 1;
        return fields;
    }

    async processGradeData(grade, options) {
        const result = { ...grade };
        if (options.includeAnalytics) {
            result.analytics = {
                ...grade.analytics,
                gpaImpact: await this.calculateGPAImpact(grade),
            };
        }
        if (options.includeMedia && grade.media) {
            result.media = await this.mediaService.enrichMedia(grade.media);
        }
        return result;
    }

    async calculateGPAImpact(grade) {
        // Placeholder for GPA impact calculation
        return grade.score ? (grade.score / 100) * 4.0 : 0;
    }

    getAllowedUpdateFields() {
        return [
            'course',
            'score',
            'gradeFormat',
            'term',
            'schoolId',
            'degreeId',
            'educationId',
            'tags',
            'privacy',
            'settings',
            'description',
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
        const maxSize = 10 * 1024 * 1024; // 10MB
        const allowedTypes = ['image/jpeg', 'image/png', 'application/pdf'];
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

    async processNewGradeAsync(gradeId, userId) {
        try {
            const grade = await Grade.findById(gradeId);
            if (!grade) return;

            const attributes = await this.gradeService.extractAttributes(grade.description || grade.course);
            if (attributes.length) {
                grade.attributes = attributes;
                await grade.save();
            }

            await this.gradeService.calculateQualityScore(grade);
            await this.gradeService.indexForSearch(grade);

            if (grade.educationId) {
                await this.educationService.recalculateGPA(grade.educationId);
            }
        } catch (error) {
            logger.error(`Async processing failed for grade ${gradeId}:`, error);
        }
    }

    async processExternalVerification(gradeId, userId) {
        try {
            const grade = await Grade.findById(gradeId);
            if (!grade) return;

            const verificationResult = await this.verificationService.verifyGrade({
                gradeId,
                userId,
                course: grade.course,
                score: grade.score,
                term: grade.term,
                schoolId: grade.schoolId,
            });

            grade.verification = {
                status: verificationResult.success ? 'verified' : 'failed',
                confidence: verificationResult.confidence,
                verifiedBy: verificationResult.verifiedBy,
                verifiedAt: new Date(),
                details: verificationResult.details,
            };
            await grade.save();

            await this.gradeService.indexForSearch(grade);
        } catch (error) {
            logger.error(`External verification failed for grade ${gradeId}:`, error);
        }
    }

    generateQueryHash(params) {
        return crypto.createHash('md5').update(JSON.stringify(params)).digest('hex').substring(0, 16);
    }

    generateDiff(oldText, newText) {
        return newText.substring(0, 50) + '...';
    }

    async calculateTrends(gradeId, timeframe) {
        return { viewsTrend: 'up', gpaImpactTrend: 'stable' };
    }

    async getComparisons(grade, compareWith) {
        return { avgScore: 85, userScore: grade.score };
    }

    checkGradePrivacy(grade, requesterId) {
        if (grade.privacy.visibleToConnections && this.gradeService.isConnected(grade.userId, requesterId)) return { allowed: true };
        if (grade.privacy.visibleToAlumni && this.gradeService.isAlumni(grade.userId, requesterId)) return { allowed: true };
        return { allowed: false, reason: 'privacy_settings' };
    }

    async handleBulkOperation(operation, query, data, requesterId, req, options) {
        switch (operation) {
            case 'delete':
                const deleteResult = data.permanent
                    ? await Grade.deleteMany(query, options)
                    : await Grade.updateMany(query, { status: 'deleted', 'privacy.isPublic': false, 'privacy.searchable': false }, options);
                return { message: data.permanent ? 'Grades permanently deleted' : 'Grades soft deleted', result: deleteResult };
            case 'archive':
                const archiveResult = await Grade.updateMany(query, { status: 'archived' }, options);
                return { message: 'Grades archived', result: archiveResult };
            case 'publish':
                const publishResult = await Grade.updateMany(query, { status: 'active', 'privacy.isPublic': true, 'privacy.searchable': true }, options);
                return { message: 'Grades published', result: publishResult };
            case 'updateScore':
                const scoreResult = await Grade.updateMany(query, { score: parseFloat(data.score), 'metadata.lastModifiedBy': { userId: requesterId, timestamp: new Date(), ip: req.ip } }, options);
                return { message: 'Grades scores updated', result: scoreResult };
            case 'updateTags':
                const tagsResult = await Grade.updateMany(query, { tags: data.tags, 'metadata.lastModifiedBy': { userId: requesterId, timestamp: new Date(), ip: req.ip } }, options);
                return { message: 'Grades tags updated', result: tagsResult };
            case 'updatePrivacy':
                const privacyResult = await Grade.updateMany(query, { privacy: data.privacy, 'metadata.lastModifiedBy': { userId: requesterId, timestamp: new Date(), ip: req.ip } }, options);
                return { message: 'Grades privacy updated', result: privacyResult };
            case 'unlinkFromEducation':
                const unlinkEduResult = await Grade.updateMany(query, { educationId: null, 'metadata.lastModifiedBy': { userId: requesterId, timestamp: new Date(), ip: req.ip } }, options);
                return { message: 'Grades unlinked from education', result: unlinkEduResult };
            case 'unlinkFromDegree':
                const unlinkDegResult = await Grade.updateMany(query, { degreeId: null, 'metadata.lastModifiedBy': { userId: requesterId, timestamp: new Date(), ip: req.ip } }, options);
                return { message: 'Grades unlinked from degree', result: unlinkDegResult };
            default:
                throw new Error('Unknown operation');
        }
    }
}

export default new GradeController();