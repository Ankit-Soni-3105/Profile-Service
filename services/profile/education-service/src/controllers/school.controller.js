import School from '../models/School.js';
import SchoolService from '../services/SchoolService.js';
import VerificationService from '../services/VerificationService.js';
import MediaService from '../services/MediaService.js';
import NotificationService from '../services/NotificationService.js';
import { validateSchool, sanitizeInput } from '../validations/school.validation.js';
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
const createSchoolLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // 10 creates per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_school_${req.user.id} `,
    redisClient: cacheService.getRedisClient(),
});

const updateSchoolLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 20, // 20 updates per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_school_${req.user.id} `,
    redisClient: cacheService.getRedisClient(),
});

const verificationLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 5, // 5 verification requests per 30 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `verify_school_${req.user.id} `,
    redisClient: cacheService.getRedisClient(),
});

const bulkOperationsLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // 3 bulk operations per hour
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_school_${req.user.id} `,
    redisClient: cacheService.getRedisClient(),
});

const mediaUploadLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 10, // 10 media uploads per 10 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `media_school_${req.user.id} `,
    redisClient: cacheService.getRedisClient(),
});

class SchoolController {
    constructor() {
        this.schoolService = SchoolService;
        this.verificationService = VerificationService;
        this.mediaService = MediaService;
        this.notificationService = NotificationService;
    }

    /**
     * Create a new school
     * POST /api/v1/schools
     */
    createSchool = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const schoolData = req.body;
        const requestingUserId = req.user.id;

        // Validate admin permissions
        if (!req.user.isAdmin) {
            return next(new AppError('Access denied: Admin privileges required', 403));
        }

        // Apply rate limiting
        await createSchoolLimiter(req, res, () => { });

        // Validate input data
        const validation = validateSchool(schoolData);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        // Sanitize input
        const sanitizedData = sanitizeInput(schoolData);

        // Check school limits
        const schoolCount = await School.countDocuments({
            'status': { $ne: 'deleted' },
        }).cache({ ttl: 300, key: `school_count` });

        const limits = this.getSchoolLimits(req.user.accountType);
        if (schoolCount >= limits.maxSchools) {
            return next(new AppError(`School limit reached(${limits.maxSchools})`, 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            // Create school
            const school = await this.schoolService.createSchool({
                ...sanitizedData,
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

            // Start async processing
            this.processNewSchoolAsync(school._id, requestingUserId)
                .catch((err) => logger.error(`Async processing failed for school ${school._id}: `, err));

            // Log metrics
            metricsCollector.increment('school.created', {
                userId: requestingUserId,
                schoolName: school.name,
            });

            // Emit event
            eventEmitter.emit('school.created', {
                schoolId: school._id,
                userId: requestingUserId,
            });

            // Create backup
            if (school.settings?.autoBackup) {
                this.schoolService.createBackup(school._id, 'create', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for school ${school._id}: `, err));
            }

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`School created successfully: ${school._id} in ${responseTime} ms`);

            return ApiResponse.success(res, {
                message: 'School created successfully',
                data: {
                    id: school._id,
                    name: school.name,
                    status: school.status,
                    createdAt: school.createdAt,
                    processingStatus: 'started',
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`School creation failed: `, error);
            metricsCollector.increment('school.create_failed', { userId: requestingUserId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.code === 11000) {
                return next(new AppError('School with this name already exists', 409));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out', 504));
            }

            return next(new AppError('Failed to create school', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get schools with filtering and pagination
     * GET /api/v1/schools
     */
    getSchools = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const {
            page = 1,
            limit = 20,
            status,
            name,
            search,
            sortBy = 'recent',
            type,
            country,
            includeAnalytics = 'false',
        } = req.query;

        // Build query
        const query = this.buildSchoolQuery({
            status,
            name,
            search,
            type,
            country,
        });

        // Build sort option
        const sortOption = this.buildSortOption(sortBy);

        // Pagination
        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
        const skip = (pageNum - 1) * limitNum;

        // Cache key
        const cacheKey = `schools:${JSON.stringify({
            page: pageNum,
            limit: limitNum,
            status,
            name,
            search,
            sortBy,
            type,
            country,
        })
            } `;

        try {
            // Try cache first
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('school.cache_hit');
                return ApiResponse.success(res, cached);
            }

            // Query database
            const [schools, totalCount] = await Promise.all([
                School.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select(this.getSelectFields(includeAnalytics === 'true'))
                    .lean(),
                School.countDocuments(query).cache({ ttl: 300, key: `school_count_${JSON.stringify(query)} ` }),
            ]);

            // Process schools data
            const processedSchools = await Promise.all(
                schools.map((school) => this.processSchoolData(school, includeAnalytics === 'true')),
            );

            const totalPages = Math.ceil(totalCount / limitNum);
            const hasNext = pageNum < totalPages;
            const hasPrev = pageNum > 1;

            const result = {
                schools: processedSchools,
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
                    name: name || 'all',
                    sortBy,
                    search: search || null,
                },
            };

            await cacheService.set(cacheKey, result, 300);
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('school.fetched', { count: schools.length });
            logger.info(`Fetched ${schools.length} schools in ${responseTime} ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch schools: `, error);
            metricsCollector.increment('school.fetch_failed');
            if (error.name === 'CastError') {
                return next(new AppError('Invalid query parameters', 400));
            }
            return next(new AppError('Failed to fetch schools', 500));
        }
    });

    /**
     * Get single school by ID
     * GET /api/v1/schools/:id
     */
    getSchoolById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;
        const { includeAnalytics = 'false', includeVerification = 'false' } = req.query;

        try {
            const cacheKey = `school:${id} `;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('school.cache_hit');
                return ApiResponse.success(res, cached);
            }

            const school = await School.findById(id)
                .read('secondaryPreferred')
                .select(this.getSelectFields(includeAnalytics === 'true', includeVerification === 'true'))
                .cache({ ttl: 600, key: cacheKey });

            if (!school) {
                return next(new AppError('School not found', 404));
            }

            // Increment view count (async)
            school.incrementViews(true)
                .catch((err) => logger.error(`View increment failed for school ${id}: `, err));

            // Process response data
            const responseData = await this.processSchoolData(school.toObject(), includeAnalytics === 'true', includeVerification === 'true');

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('school.viewed', { schoolId: id, viewerId: requestingUserId });
            logger.info(`Fetched school ${id} in ${responseTime} ms`);

            return ApiResponse.success(res, { data: responseData });
        } catch (error) {
            logger.error(`Failed to fetch school ${id}: `, error);
            metricsCollector.increment('school.view_failed');
            if (error.name === 'CastError') {
                return next(new AppError('Invalid school ID', 400));
            }
            return next(new AppError('Failed to fetch school', 500));
        }
    });

    /**
     * Update school
     * PUT /api/v1/schools/:id
     */
    updateSchool = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;
        const updates = req.body;

        // Validate admin permissions
        if (!req.user.isAdmin) {
            return next(new AppError('Access denied: Admin privileges required', 403));
        }

        // Apply rate limiting
        await updateSchoolLimiter(req, res, () => { });

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const school = await School.findById(id).session(session);
            if (!school) {
                return next(new AppError('School not found', 404));
            }

            // Validate updates
            const allowedUpdates = this.getAllowedUpdateFields();
            const sanitizedUpdates = this.sanitizeUpdates(updates, allowedUpdates);

            if (Object.keys(sanitizedUpdates).length === 0) {
                return next(new AppError('No valid update fields provided', 400));
            }

            // Create version if content changed
            let versionCreated = false;
            if (sanitizedUpdates.description && sanitizedUpdates.description !== school.description) {
                await school.createVersion(sanitizedUpdates.description, sanitizedUpdates.name || school.name, 'edit', {
                    userId: requestingUserId,
                }, { session });
                versionCreated = true;
            }

            // Update school
            Object.assign(school, sanitizedUpdates);

            // Update audit trail
            school.metadata.lastModifiedBy = {
                userId: requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date(),
            };

            // Trigger re-verification if critical fields changed
            if (sanitizedUpdates.name || sanitizedUpdates.country || sanitizedUpdates.type) {
                school.verification.status = 'pending';
                this.processExternalVerification(school._id, requestingUserId)
                    .catch((err) => logger.error(`Re - verification failed for school ${id}: `, err));
            }

            await school.save({ session });

            // Recalculate quality score
            if (sanitizedUpdates.description) {
                await school.calculateQualityScore({ session });
            }

            // Create backup
            if (school.settings?.autoBackup) {
                this.schoolService.createBackup(school._id, 'update', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for school ${id}: `, err));
            }

            // Clear cache
            await cacheService.deletePattern(`school:${id}:* `);
            await cacheService.deletePattern(`schools:* `);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('school.updated', {
                userId: requestingUserId,
                versionCreated,
                fieldsUpdated: Object.keys(sanitizedUpdates).length,
            });

            // Emit event
            eventEmitter.emit('school.updated', {
                schoolId: school._id,
                userId: requestingUserId,
                changes: Object.keys(sanitizedUpdates),
                versionCreated,
            });

            logger.info(`School updated successfully: ${id} in ${responseTime} ms`);

            return ApiResponse.success(res, {
                message: 'School updated successfully',
                data: {
                    id: school._id,
                    name: school.name,
                    status: school.status,
                    updatedAt: school.updatedAt,
                    versionCreated,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`School update failed for ${id}: `, error);
            metricsCollector.increment('school.update_failed', { userId: requestingUserId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out', 504));
            }
            return next(new AppError('Failed to update school', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete school (soft or permanent)
     * DELETE /api/v1/schools/:id
     */
    deleteSchool = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;
        const { permanent = 'false' } = req.query;

        // Validate admin permissions
        if (!req.user.isAdmin) {
            return next(new AppError('Access denied: Admin privileges required', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const school = await School.findById(id).session(session);
            if (!school) {
                return next(new AppError('School not found', 404));
            }

            if (permanent === 'true') {
                // Permanent deletion
                await School.findByIdAndDelete(id, { session });
                await this.mediaService.deleteAllMedia(id, 'school', { session });
                this.schoolService.deleteAllBackups(id)
                    .catch((err) => logger.error(`Failed to delete backups for ${id}: `, err));
                metricsCollector.increment('school.permanently_deleted');
            } else {
                // Soft delete
                school.status = 'deleted';
                school.privacy.isPublic = false;
                school.metadata.lastModifiedBy = {
                    userId: requestingUserId,
                    ip: req.ip,
                    userAgent: req.get('User-Agent'),
                    timestamp: new Date(),
                };
                await school.save({ session });
                metricsCollector.increment('school.soft_deleted');
            }

            // Clear cache
            await cacheService.deletePattern(`school:${id}:* `);
            await cacheService.deletePattern(`schools:* `);

            // Emit event
            eventEmitter.emit('school.deleted', {
                schoolId: id,
                userId: requestingUserId,
                permanent: permanent === 'true',
            });

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`School ${id} deleted(permanent: ${permanent}) in ${responseTime} ms`);

            return ApiResponse.success(res, {
                message: permanent === 'true' ? 'School permanently deleted' : 'School moved to trash',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`School deletion failed for ${id}: `, error);
            metricsCollector.increment('school.delete_failed');
            return next(new AppError('Failed to delete school', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Bulk operations on schools
     * POST /api/v1/schools/bulk
     */
    bulkOperations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const requestingUserId = req.user.id;
        const { operation, schoolIds, data = {} } = req.body;

        // Validate admin permissions
        if (!req.user.isAdmin) {
            return next(new AppError('Access denied: Admin privileges required', 403));
        }

        // Apply rate limiting
        await bulkOperationsLimiter(req, res, () => { });

        // Validate input
        if (!Array.isArray(schoolIds) || schoolIds.length === 0) {
            return next(new AppError('School IDs array is required', 400));
        }
        if (schoolIds.length > 100) {
            return next(new AppError('Maximum 100 schools can be processed at once', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const query = { _id: { $in: schoolIds } };
            const { message } = await this.handleBulkOperation(operation, query, data, requestingUserId, req, { session });

            // Clear cache
            await Promise.all([
                cacheService.deletePattern(`schools:* `),
                ...schoolIds.map((id) => cacheService.deletePattern(`school:${id}:* `)),
            ]);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('school.bulk_operation', {
                operation,
                count: schoolIds.length,
            });
            logger.info(`Bulk operation ${operation} completed for ${schoolIds.length} schools in ${responseTime} ms`);

            return ApiResponse.success(res, {
                message,
                data: {
                    operation,
                    requested: schoolIds.length,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk operation failed: `, error);
            metricsCollector.increment('school.bulk_operation_failed', { operation });
            return next(new AppError('Bulk operation failed', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get school analytics
     * GET /api/v1/schools/:id/analytics
     */
    getAnalytics = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;
        const { timeframe = '30d', metrics = 'basic' } = req.query;

        // Validate admin permissions
        if (!req.user.isAdmin) {
            return next(new AppError('Access denied: Admin privileges required', 403));
        }

        try {
            const cacheKey = `analytics: school:${id}:${timeframe}:${metrics} `;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('school.analytics_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const school = await School.findById(id)
                .read('secondaryPreferred')
                .select('analytics verification metadata createdAt')
                .cache({ ttl: 900, key: cacheKey });

            if (!school) {
                return next(new AppError('School not found', 404));
            }

            const analytics = this.processAnalyticsData(school, timeframe, metrics);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('school.analytics_viewed');
            logger.info(`Fetched analytics for school ${id} in ${responseTime} ms`);

            return ApiResponse.success(res, { data: analytics });
        } catch (error) {
            logger.error(`Analytics fetch failed for ${id}: `, error);
            metricsCollector.increment('school.analytics_fetch_failed');
            return next(new AppError('Failed to fetch analytics', 500));
        }
    });

    /**
     * Verify school
     * POST /api/v1/schools/:id/verify
     */
    verifySchool = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;

        // Validate admin permissions
        if (!req.user.isAdmin) {
            return next(new AppError('Access denied: Admin privileges required', 403));
        }

        // Apply rate limiting
        await verificationLimiter(req, res, () => { });

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const school = await School.findById(id).session(session);
            if (!school) {
                return next(new AppError('School not found', 404));
            }

            // Trigger verification
            const verificationResult = await this.processExternalVerification(school._id, requestingUserId);
            if (!verificationResult.success) {
                return next(new AppError('Verification failed: ' + verificationResult.message, 424));
            }

            school.verification = {
                status: verificationResult.status,
                confidence: verificationResult.confidence,
                verifiedBy: verificationResult.verifiedBy,
                verifiedAt: new Date(),
                details: verificationResult.details,
            };

            await school.save({ session });

            // Notify admin
            this.notificationService.notifyUser(requestingUserId, {
                type: 'verification_completed',
                message: `School "${school.name}" verification ${verificationResult.status} `,
                data: { schoolId: id },
            }).catch((err) => logger.error(`Notification failed for school ${id}: `, err));

            // Clear cache
            await cacheService.deletePattern(`school:${id}:* `);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('school.verified', { status: verificationResult.status });
            logger.info(`School ${id} verified in ${responseTime} ms`);

            return ApiResponse.success(res, {
                message: 'School verification completed',
                data: school.verification,
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Verification failed for school ${id}: `, error);
            metricsCollector.increment('school.verify_failed');
            if (error.message.includes('timeout')) {
                return next(new AppError('External API timeout', 503));
            }
            return next(new AppError('Failed to verify school', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Upload media for school
     * POST /api/v1/schools/:id/media
     */
    uploadMedia = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;
        const files = req.files;

        // Validate admin permissions
        if (!req.user.isAdmin) {
            return next(new AppError('Access denied: Admin privileges required', 403));
        }

        // Apply rate limiting
        await mediaUploadLimiter(req, res, () => { });

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const school = await School.findById(id).session(session);
            if (!school) {
                return next(new AppError('School not found', 404));
            }

            // Validate media
            const validation = this.validateMediaUpload(files, school.media);
            if (!validation.valid) {
                return next(new AppError(validation.message, 422));
            }

            // Process media
            const mediaResults = await this.mediaService.uploadMedia({
                files,
                entityId: id,
                entityType: 'school',
                userId: requestingUserId,
            }, { session });

            // Virus scan
            const scanResults = await this.mediaService.scanMedia(mediaResults);
            if (scanResults.some((result) => result.infected)) {
                return next(new AppError('Media upload failed: Infected file detected', 422));
            }

            school.media.push(...mediaResults);
            await school.save({ session });

            // Clear cache
            await cacheService.deletePattern(`school:${id}:* `);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('school.media_uploaded', { count: mediaResults.length });
            logger.info(`Uploaded ${mediaResults.length} media files for school ${id} in ${responseTime} ms`);

            return ApiResponse.success(res, {
                message: 'Media uploaded successfully',
                data: { media: mediaResults },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Media upload failed for school ${id}: `, error);
            metricsCollector.increment('school.media_upload_failed');
            return next(new AppError('Failed to upload media', 422));
        } finally {
            session.endSession();
        }
    });

    /**
     * Share school
     * POST /api/v1/schools/:id/share
     */
    shareSchool = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;
        const { platform } = req.body;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const school = await School.findById(id).session(session);
            if (!school) {
                return next(new AppError('School not found', 404));
            }

            // Generate shareable link
            const shareLink = this.generateShareableLink(school, platform);

            // Track share
            school.analytics.shares.total += 1;
            school.analytics.shares.byPlatform = {
                ...school.analytics.shares.byPlatform,
                [platform]: (school.analytics.shares.byPlatform[platform] || 0) + 1,
            };
            await school.save({ session });

            // Clear cache
            await cacheService.deletePattern(`school:${id}:* `);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('school.shared', { platform });
            logger.info(`School ${id} shared on ${platform} in ${responseTime} ms`);

            return ApiResponse.success(res, {
                message: 'School shared successfully',
                data: { shareLink },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Share failed for school ${id}: `, error);
            metricsCollector.increment('school.share_failed');
            return next(new AppError('Failed to share school', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get verification status
     * GET /api/v1/schools/:id/verification
     */
    getVerificationStatus = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;

        // Validate admin permissions
        if (!req.user.isAdmin) {
            return next(new AppError('Access denied: Admin privileges required', 403));
        }

        try {
            const cacheKey = `verification: school:${id} `;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('school.verification_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const school = await School.findById(id)
                .read('secondaryPreferred')
                .select('verification')
                .cache({ ttl: 60, key: cacheKey });

            if (!school) {
                return next(new AppError('School not found', 404));
            }

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('school.verification_viewed');
            logger.info(`Fetched verification status for school ${id} in ${responseTime} ms`);

            return ApiResponse.success(res, {
                data: school.verification,
            });
        } catch (error) {
            logger.error(`Verification status fetch failed for ${id}: `, error);
            metricsCollector.increment('school.verification_fetch_failed');
            return next(new AppError('Failed to fetch verification status', 500));
        }
    });

    /**
     * Get trending schools
     * GET /api/v1/schools/trending
     */
    getTrendingSchools = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { timeframe = '7d', type, limit = 20 } = req.query;

        const cacheKey = `trending: schools:${timeframe}:${type || 'all'}:${limit} `;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('school.trending_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const schools = await this.schoolService.getTrendingSchools(timeframe, type, parseInt(limit));
            const processedSchools = await Promise.all(
                schools.map((school) => this.processSchoolData(school, false)),
            );

            const result = { schools: processedSchools };
            await cacheService.set(cacheKey, result, 3600);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('school.trending_viewed', { count: schools.length });
            logger.info(`Fetched ${schools.length} trending schools in ${responseTime} ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch trending schools: `, error);
            metricsCollector.increment('school.trending_fetch_failed');
            return next(new AppError('Failed to fetch trending schools', 500));
        }
    });

    /**
     * Search schools
     * GET /api/v1/schools/search
     */
    searchSchools = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { query, page = 1, limit = 20, filters = {} } = req.query;

        const cacheKey = `search: schools:${query}:${JSON.stringify(filters)}:${page}:${limit} `;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('school.search_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const searchResults = await this.schoolService.searchSchools(query, filters, {
                page: parseInt(page),
                limit: parseInt(limit),
            });

            const result = {
                schools: searchResults.hits,
                totalCount: searchResults.total,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    totalPages: Math.ceil(searchResults.total / parseInt(limit)),
                },
            };

            await cacheService.set(cacheKey, result, 300);
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('school.searched', { query, count: searchResults.hits.length });
            logger.info(`Search returned ${searchResults.hits.length} schools in ${responseTime} ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Search failed for query ${query}: `, error);
            metricsCollector.increment('school.search_failed');
            return next(new AppError('Failed to search schools', 500));
        }
    });

    /**
     * Export schools as CSV
     * GET /api/v1/schools/export
     */
    exportSchools = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const requestingUserId = req.user.id;
        const { format = 'csv', fields = 'name,type,country,description,status' } = req.query;

        // Validate admin permissions
        if (!req.user.isAdmin) {
            return next(new AppError('Access denied: Admin privileges required', 403));
        }

        try {
            const schools = await School.find({ status: { $ne: 'deleted' } })
                .read('secondaryPreferred')
                .select(fields.split(',').join(' '))
                .lean();

            const csvData = this.convertToCSV(schools, fields.split(','));
            const filename = `schools_${Date.now()}.csv`;

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('school.exported', { format });
            logger.info(`Exported ${schools.length} schools in ${responseTime} ms`);

            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename = "${filename}"`);
            return res.send(csvData);
        } catch (error) {
            logger.error(`Export failed: `, error);
            metricsCollector.increment('school.export_failed');
            return next(new AppError('Failed to export schools', 500));
        }
    });

    // Helper Methods

    /**
     * Process new school asynchronously
     */
    async processNewSchoolAsync(schoolId, userId) {
        try {
            const session = await mongoose.startSession();
            session.startTransaction();

            const school = await School.findById(schoolId).session(session);
            if (!school) {
                await session.abortTransaction();
                session.endSession();
                return;
            }

            // Extract attributes
            const attributes = await this.schoolService.extractAttributes(school.description);
            school.attributes = attributes.slice(0, 20);

            // Calculate quality score
            await school.calculateQualityScore({ session });

            // Auto-verify
            await this.processExternalVerification(schoolId, userId);

            // Index for search
            await this.schoolService.indexForSearch(school);

            await school.save({ session });
            await session.commitTransaction();
            logger.info(`Async processing completed for school ${schoolId}`);
        } catch (error) {
            logger.error(`Async processing failed for school ${schoolId}: `, error);
        } finally {
            session.endSession();
        }
    }

    /**
     * Get allowed update fields
     */
    getAllowedUpdateFields() {
        return [
            'name',
            'type',
            'description',
            'country',
            'attributes',
            'privacy',
            'status',
        ];
    }

    /**
     * Sanitize updates
     */
    sanitizeUpdates(updates, allowedFields) {
        const sanitized = {};
        allowedFields.forEach((field) => {
            if (updates[field] !== undefined) {
                sanitized[field] = field === 'description' ? sanitizeHtml(updates[field]) : sanitizeInput(updates[field]);
            }
        });
        return sanitized;
    }

    /**
     * Process analytics data
     */
    processAnalyticsData(school, timeframe, metrics) {
        const analytics = school.analytics || {};
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
            views: {
                total: analytics.views?.total || 0,
                unique: analytics.views?.unique || 0,
                byDate: (analytics.views?.byDate || []).filter((v) => new Date(v.date) >= timeframeDate),
            },
            shares: {
                total: analytics.shares?.total || 0,
                byPlatform: analytics.shares?.byPlatform || {},
            },
        };

        if (metrics === 'detailed') {
            filteredAnalytics.verification = school.verification;
        }

        return filteredAnalytics;
    }

    /**
     * Get school limits
     */
    getSchoolLimits(accountType) {
        const limits = {
            admin: { maxSchools: 1000000, maxMedia: 50, maxSizeMB: 500 },
        };
        return limits[accountType] || limits.admin;
    }

    /**
     * Build query for fetching schools
     */
    buildSchoolQuery({ status, name, search, type, country }) {
        const query = { status: { $ne: 'deleted' } };

        if (status && status !== 'all') {
            query.status = status;
        }
        if (name && name !== 'all') {
            query.name = name;
        }
        if (type) {
            query.type = type;
        }
        if (country) {
            query.country = country;
        }
        if (search) {
            query.$text = { $search: search };
        }

        return query;
    }

    /**
     * Build sort option
     */
    buildSortOption(sortBy) {
        const sortOptions = {
            recent: { updatedAt: -1 },
            oldest: { createdAt: 1 },
            name: { name: 1 },
            popular: { 'analytics.views.total': -1 },
            quality: { 'qualityScore': -1 },
            verified: { 'verification.confidence': -1 },
        };
        return sortOptions[sortBy] || sortOptions.recent;
    }

    /**
     * Get select fields
     */
    getSelectFields(includeAnalytics, includeVerification = false) {
        const baseFields = 'name type description status attributes country privacy createdAt updatedAt';
        let fields = baseFields;
        if (includeAnalytics) fields += ' analytics';
        if (includeVerification) fields += ' verification';
        return fields;
    }

    /**
     * Process school data
     */
    async processSchoolData(school, includeAnalytics = false, includeVerification = false) {
        const processed = { ...school };

        if (!includeAnalytics) {
            delete processed.analytics;
        }
        if (!includeVerification) {
            delete processed.verification;
        }

        return processed;
    }

    /**
     * Validate media upload
     */
    validateMediaUpload(files, existingMedia) {
        const limits = this.getSchoolLimits('admin');
        const totalSize = files.reduce((sum, file) => sum + file.size, 0);
        const totalMedia = existingMedia.length + files.length;

        if (totalMedia > limits.maxMedia) {
            return { valid: false, message: `Maximum ${limits.maxMedia} media files allowed` };
        }
        if (totalSize > limits.maxSizeMB * 1024 * 1024) {
            return { valid: false, message: `Total media size exceeds ${limits.maxSizeMB} MB` };
        }

        return { valid: true };
    }

    /**
     * Process external verification
     */
    async processExternalVerification(schoolId, userId) {
        try {
            const school = await School.findById(schoolId);
            const result = await this.verificationService.verifySchool({
                schoolId,
                userId,
                name: school.name,
                country: school.country,
                type: school.type,
            });

            return result;
        } catch (error) {
            logger.error(`External verification failed for school ${schoolId}: `, error);
            return { success: false, message: error.message };
        }
    }

    /**
     * Generate shareable link
     */
    generateShareableLink(school, platform) {
        const baseUrl = process.env.APP_URL || 'https://app.example.com';
        return `${baseUrl} /schools/${school._id}/share?platform=${platform}`;
    }

    /**
     * Handle bulk operation
     */
    async handleBulkOperation(operation, query, data, requestingUserId, req, options = {}) {
        let updateData = {};
        let message = '';

        switch (operation) {
            case 'delete':
                updateData = {
                    status: 'deleted',
                    privacy: { isPublic: false },
                    updatedAt: new Date(),
                    'metadata.lastModifiedBy': {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = 'Schools moved to trash';
                break;
            case 'archive':
                updateData = {
                    status: 'archived',
                    updatedAt: new Date(),
                    'metadata.lastModifiedBy': {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = 'Schools archived';
                break;
            case 'publish':
                updateData = {
                    status: 'active',
                    privacy: { isPublic: true },
                    updatedAt: new Date(),
                    'metadata.lastModifiedBy': {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = 'Schools published';
                break;
            case 'updateAttributes':
                if (!Array.isArray(data.attributes)) {
                    throw new AppError('Attributes array is required', 400);
                }
                updateData = {
                    $addToSet: {
                        attributes: { $each: data.attributes.map((attr) => attr.trim().toLowerCase()).slice(0, 15) },
                    },
                    updatedAt: new Date(),
                    'metadata.lastModifiedBy': {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = 'Attributes updated';
                break;
            case 'updatePrivacy':
                if (!data.privacy) {
                    throw new AppError('Privacy settings are required', 400);
                }
                updateData = {
                    privacy: data.privacy,
                    updatedAt: new Date(),
                    'metadata.lastModifiedBy': {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = 'Privacy updated';
                break;
        }

        const result = await School.updateMany(query, updateData, options);
        return { message, result };
    }

    /**
     * Convert data to CSV
     */
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

export default new SchoolController();
