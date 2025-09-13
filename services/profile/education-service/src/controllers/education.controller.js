// EducationController.js
import Education from '../models/Education.js';
import EducationService from '../services/EducationService.js';
import VerificationService from '../services/VerificationService.js';
import MediaService from '../services/MediaService.js';
import TemplateService from '../services/TemplateService.js';
import NotificationService from '../services/NotificationService.js';
import SchoolService from '../services/SchoolService.js';
import { validateEducation, sanitizeInput } from '../validations/education.validation.js';
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

// Rate limiters with enhanced configuration for scalability
const createEducationLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 15, // 15 creates per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_education_${req.user.id}`,
    redisClient: cacheService.getRedisClient(), // Use Redis client for distributed rate limiting
});

const updateEducationLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 25, // 25 updates per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_education_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const verificationLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 5, // 5 verification requests per 30 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `verify_education_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const bulkOperationsLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // 3 bulk operations per hour
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_education_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const mediaUploadLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 10, // 10 media uploads per 10 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `media_education_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

class EducationController {
    constructor() {
        this.educationService = EducationService;
        this.verificationService = VerificationService;
        this.mediaService = MediaService;
        this.templateService = TemplateService;
        this.notificationService = NotificationService;
        this.schoolService = SchoolService;
    }

    /**
     * Create a new education
     * POST /api/v1/education/:userId
     */
    createEducation = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const educationData = req.body;
        const requestingUserId = req.user.id;

        // Validate access permissions
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied: Cannot create education for another user', 403));
        }

        // Apply rate limiting
        await createEducationLimiter(req, res, () => { });

        // Validate input data
        const validation = validateEducation(educationData);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        // Sanitize input
        const sanitizedData = sanitizeInput(educationData);

        // Check user limits
        const userEducationCount = await Education.countDocuments({
            userId,
            'status': { $ne: 'deleted' },
        }).cache({ ttl: 300, key: `user_education_count_${userId}` });

        const limits = this.getUserLimits(req.user.accountType);
        if (userEducationCount >= limits.maxEducations) {
            return next(new AppError(`Education limit reached (${limits.maxEducations})`, 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            // Create education with service
            const education = await this.educationService.createEducation({
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

            // Start async processing
            this.processNewEducationAsync(education._id, requestingUserId)
                .catch((err) => logger.error(`Async processing failed for education ${education._id}:`, err));

            // Log metrics
            metricsCollector.increment('education.created', {
                userId,
                degree: education.degree,
                templateUsed: !!education.templateId,
            });

            // Emit event
            eventEmitter.emit('education.created', {
                educationId: education._id,
                userId,
                templateId: education.templateId,
            });

            // Create backup
            if (education.settings?.autoBackup) {
                this.educationService.createBackup(education._id, 'create', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for education ${education._id}:`, err));
            }

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`Education created successfully: ${education._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Education created successfully',
                data: {
                    id: education._id,
                    userId: education.userId,
                    degree: education.degree,
                    status: education.status,
                    createdAt: education.createdAt,
                    processingStatus: 'started',
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Education creation failed for user ${userId}:`, error);
            metricsCollector.increment('education.create_failed', { userId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.code === 11000) {
                return next(new AppError('Education with this degree already exists', 409));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out', 504));
            }

            return next(new AppError('Failed to create education', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get user's educations with filtering and pagination
     * GET /api/v1/education/:userId
     */
    getEducations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;

        // Validate access permissions
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const {
            page = 1,
            limit = 20,
            status,
            degree,
            search,
            sortBy = 'recent',
            templateId,
            tags,
            startDate,
            endDate,
            includeAnalytics = 'false',
        } = req.query;

        // Build query
        const query = this.buildEducationQuery({
            userId,
            status,
            degree,
            search,
            templateId,
            tags,
            startDate,
            endDate,
        });

        // Build sort option
        const sortOption = this.buildSortOption(sortBy);

        // Pagination
        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit))); // Max 100 items
        const skip = (pageNum - 1) * limitNum;

        // Cache key
        const cacheKey = `educations:${userId}:${JSON.stringify({
            page: pageNum,
            limit: limitNum,
            status,
            degree,
            search,
            sortBy,
            templateId,
            tags,
            startDate,
            endDate,
        })}`;

        try {
            // Try cache first
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('education.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            // Query database with optimized read preference
            const [educations, totalCount] = await Promise.all([
                Education.find(query)
                    .read('secondaryPreferred') // Optimize for read-heavy operations
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select(this.getSelectFields(includeAnalytics === 'true'))
                    .populate('templateId', 'name category')
                    .populate('schoolId', 'name type')
                    .lean(),
                Education.countDocuments(query).cache({ ttl: 300, key: `education_count_${userId}` }),
            ]);

            // Process educations data
            const processedEducations = await Promise.all(
                educations.map((edu) => this.processEducationData(edu, includeAnalytics === 'true')),
            );

            const totalPages = Math.ceil(totalCount / limitNum);
            const hasNext = pageNum < totalPages;
            const hasPrev = pageNum > 1;

            const result = {
                educations: processedEducations,
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
                    degree: degree || 'all',
                    sortBy,
                    search: search || null,
                },
            };

            // Cache result with distributed Redis
            await cacheService.set(cacheKey, result, 300); // 5 minutes

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('education.fetched', {
                userId,
                count: educations.length,
                cached: false,
            });
            logger.info(`Fetched ${educations.length} educations for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch educations for user ${userId}:`, error);
            metricsCollector.increment('education.fetch_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid query parameters', 400));
            }
            return next(new AppError('Failed to fetch educations', 500));
        }
    });

    /**
     * Get single education by ID
     * GET /api/v1/education/:userId/:id
     */
    getEducationById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { includeAnalytics = 'false', includeVerification = 'false' } = req.query;

        try {
            const cacheKey = `education:${id}:${userId}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('education.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const education = await Education.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .populate('templateId', 'name category')
                .populate('schoolId', 'name type')
                .cache({ ttl: 600, key: cacheKey });

            if (!education) {
                return next(new AppError('Education not found', 404));
            }

            // Check access permissions
            const hasAccess = this.checkEducationAccess(education, requestingUserId, req.user.isAdmin);
            if (!hasAccess) {
                return next(new AppError('Access denied', 403));
            }

            // Increment view count (async)
            if (requestingUserId !== userId) {
                education.incrementViews(true)
                    .catch((err) => logger.error(`View increment failed for education ${id}:`, err));
            }

            // Process response data
            const responseData = this.processEducationData(education.toObject(), includeAnalytics === 'true', includeVerification === 'true');

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('education.viewed', {
                userId,
                viewerId: requestingUserId,
                isOwner: userId === requestingUserId,
            });
            logger.info(`Fetched education ${id} for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: responseData });
        } catch (error) {
            logger.error(`Failed to fetch education ${id}:`, error);
            metricsCollector.increment('education.view_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid education ID', 400));
            }
            return next(new AppError('Failed to fetch education', 500));
        }
    });

    /**
     * Update education
     * PUT /api/v1/education/:userId/:id
     */
    updateEducation = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const updates = req.body;

        // Apply rate limiting
        await updateEducationLimiter(req, res, () => { });

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const education = await Education.findOne({ _id: id, userId }).session(session);
            if (!education) {
                return next(new AppError('Education not found', 404));
            }

            // Validate updates
            const allowedUpdates = this.getAllowedUpdateFields();
            const sanitizedUpdates = this.sanitizeUpdates(updates, allowedUpdates);

            if (Object.keys(sanitizedUpdates).length === 0) {
                return next(new AppError('No valid update fields provided', 400));
            }

            // Create version if content changed
            let versionCreated = false;
            if (sanitizedUpdates.description && sanitizedUpdates.description !== education.description) {
                await education.createVersion(sanitizedUpdates.description, sanitizedUpdates.degree || education.degree, 'edit', {
                    userId: requestingUserId,
                }, { session });
                versionCreated = true;
            }

            // Update education
            Object.assign(education, sanitizedUpdates);

            // Update audit trail
            education.metadata.lastModifiedBy = {
                userId: requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date(),
            };

            // Trigger re-verification if critical fields changed
            if (sanitizedUpdates.schoolId || sanitizedUpdates.duration || sanitizedUpdates.gpa) {
                education.verification.status = 'pending';
                this.processExternalVerification(education._id, requestingUserId)
                    .catch((err) => logger.error(`Re-verification failed for education ${id}:`, err));
            }

            await education.save({ session });

            // Recalculate quality score
            if (sanitizedUpdates.description) {
                await education.calculateQualityScore({ session });
            }

            // Create backup
            if (education.settings?.autoBackup) {
                this.educationService.createBackup(education._id, 'update', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for education ${id}:`, err));
            }

            // Clear cache
            await cacheService.deletePattern(`education:${id}:*`);
            await cacheService.deletePattern(`educations:${userId}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('education.updated', {
                userId,
                versionCreated,
                fieldsUpdated: Object.keys(sanitizedUpdates).length,
            });

            // Emit event
            eventEmitter.emit('education.updated', {
                educationId: education._id,
                userId,
                changes: Object.keys(sanitizedUpdates),
                versionCreated,
            });

            logger.info(`Education updated successfully: ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Education updated successfully',
                data: {
                    id: education._id,
                    degree: education.degree,
                    status: education.status,
                    updatedAt: education.updatedAt,
                    versionCreated,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Education update failed for ${id}:`, error);
            metricsCollector.increment('education.update_failed', { userId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out', 504));
            }
            return next(new AppError('Failed to update education', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete education (soft or permanent)
     * DELETE /api/v1/education/:userId/:id
     */
    deleteEducation = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { permanent = 'false' } = req.query;

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const education = await Education.findOne({ _id: id, userId }).session(session);
            if (!education) {
                return next(new AppError('Education not found', 404));
            }

            if (permanent === 'true') {
                // Permanent deletion
                await Education.findByIdAndDelete(id, { session });
                await this.mediaService.deleteAllMedia(id, 'education', { session });
                this.educationService.deleteAllBackups(id)
                    .catch((err) => logger.error(`Failed to delete backups for ${id}:`, err));
                metricsCollector.increment('education.permanently_deleted', { userId });
            } else {
                // Soft delete
                education.status = 'deleted';
                education.privacy.isPublic = false;
                education.metadata.lastModifiedBy = {
                    userId: requestingUserId,
                    ip: req.ip,
                    userAgent: req.get('User-Agent'),
                    timestamp: new Date(),
                };
                await education.save({ session });
                metricsCollector.increment('education.soft_deleted', { userId });
            }

            // Clear cache
            await cacheService.deletePattern(`education:${id}:*`);
            await cacheService.deletePattern(`educations:${userId}:*`);

            // Emit event
            eventEmitter.emit('education.deleted', {
                educationId: id,
                userId,
                permanent: permanent === 'true',
            });

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`Education ${id} deleted (permanent: ${permanent}) in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: permanent === 'true' ? 'Education permanently deleted' : 'Education moved to trash',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Education deletion failed for ${id}:`, error);
            metricsCollector.increment('education.delete_failed', { userId });
            return next(new AppError('Failed to delete education', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Bulk operations on educations
     * POST /api/v1/education/:userId/bulk
     */
    bulkOperations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { operation, educationIds, data = {} } = req.body;

        // Apply rate limiting
        await bulkOperationsLimiter(req, res, () => { });

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        // Validate input
        if (!Array.isArray(educationIds) || educationIds.length === 0) {
            return next(new AppError('Education IDs array is required', 400));
        }
        if (educationIds.length > 100) {
            return next(new AppError('Maximum 100 educations can be processed at once', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const query = { _id: { $in: educationIds }, userId };
            const { message } = await this.handleBulkOperation(operation, query, data, requestingUserId, req, { session });

            // Clear cache
            await Promise.all([
                cacheService.deletePattern(`educations:${userId}:*`),
                ...educationIds.map((id) => cacheService.deletePattern(`education:${id}:*`)),
            ]);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('education.bulk_operation', {
                userId,
                operation,
                count: educationIds.length,
            });
            logger.info(`Bulk operation ${operation} completed for ${educationIds.length} educations in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message,
                data: {
                    operation,
                    requested: educationIds.length,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk operation failed for user ${userId}:`, error);
            metricsCollector.increment('education.bulk_operation_failed', { userId, operation });
            return next(new AppError('Bulk operation failed', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get education analytics
     * GET /api/v1/education/:userId/:id/analytics
     */
    getAnalytics = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { timeframe = '30d', metrics = 'basic' } = req.query;

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        try {
            const cacheKey = `analytics:education:${id}:${timeframe}:${metrics}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('education.analytics_cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const education = await Education.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('analytics verification metadata createdAt')
                .cache({ ttl: 900, key: cacheKey });

            if (!education) {
                return next(new AppError('Education not found', 404));
            }

            const analytics = this.processAnalyticsData(education, timeframe, metrics);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('education.analytics_viewed', { userId });
            logger.info(`Fetched analytics for education ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: analytics });
        } catch (error) {
            logger.error(`Analytics fetch failed for ${id}:`, error);
            metricsCollector.increment('education.analytics_fetch_failed', { userId });
            return next(new AppError('Failed to fetch analytics', 500));
        }
    });

    /**
     * Duplicate education
     * POST /api/v1/education/:userId/:id/duplicate
     */
    duplicateEducation = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { degree, includeVersions = 'false' } = req.body;

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const originalEducation = await Education.findOne({ _id: id, userId }).session(session);
            if (!originalEducation) {
                return next(new AppError('Education not found', 404));
            }

            // Check user limits
            const userEducationCount = await Education.countDocuments({
                userId,
                'status': { $ne: 'deleted' },
            }).cache({ ttl: 300, key: `user_education_count_${userId}` });

            const limits = this.getUserLimits(req.user.accountType);
            if (userEducationCount >= limits.maxEducations) {
                return next(new AppError(`Education limit reached (${limits.maxEducations})`, 403));
            }

            // Create duplicate
            const duplicateData = originalEducation.toObject();
            delete duplicateData._id;
            delete duplicateData.createdAt;
            delete duplicateData.updatedAt;
            delete duplicateData.analytics;

            duplicateData.degree = degree || `${originalEducation.degree} (Copy)`;
            duplicateData.status = 'draft';
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
                    degree: duplicateData.degree,
                    changeType: 'create',
                    isActive: true,
                }];
            }

            const duplicate = new Education(duplicateData);
            await duplicate.save({ session });

            // Create backup
            if (duplicate.settings?.autoBackup) {
                this.educationService.createBackup(duplicate._id, 'duplicate', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for duplicate ${duplicate._id}:`, err));
            }

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('education.duplicated', { userId });
            logger.info(`Education ${id} duplicated as ${duplicate._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Education duplicated successfully',
                data: {
                    originalId: id,
                    duplicateId: duplicate._id,
                    degree: duplicate.degree,
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Education duplication failed for ${id}:`, error);
            metricsCollector.increment('education.duplicate_failed', { userId });
            return next(new AppError('Failed to duplicate education', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Verify education
     * POST /api/v1/education/:userId/:id/verify
     */
    verifyEducation = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        // Apply rate limiting
        await verificationLimiter(req, res, () => { });

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const education = await Education.findOne({ _id: id, userId }).session(session);
            if (!education) {
                return next(new AppError('Education not found', 404));
            }

            // Trigger verification with circuit breaker
            const verificationResult = await this.processExternalVerification(education._id, requestingUserId);
            if (!verificationResult.success) {
                return next(new AppError('Verification failed: ' + verificationResult.message, 424));
            }

            education.verification = {
                status: verificationResult.status,
                confidence: verificationResult.confidence,
                verifiedBy: verificationResult.verifiedBy,
                verifiedAt: new Date(),
                details: verificationResult.details,
            };

            await education.save({ session });

            // Notify user
            this.notificationService.notifyUser(userId, {
                type: 'verification_completed',
                message: `Education "${education.degree}" verification ${verificationResult.status}`,
                data: { educationId: id },
            }).catch((err) => logger.error(`Notification failed for education ${id}:`, err));

            // Clear cache
            await cacheService.deletePattern(`education:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('education.verified', {
                userId,
                status: verificationResult.status,
            });
            logger.info(`Education ${id} verified in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Education verification completed',
                data: education.verification,
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Verification failed for education ${id}:`, error);
            metricsCollector.increment('education.verify_failed', { userId });
            if (error.message.includes('timeout')) {
                return next(new AppError('External API timeout', 503));
            }
            return next(new AppError('Failed to verify education', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Upload media for education
     * POST /api/v1/education/:userId/:id/media
     */
    uploadMedia = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const files = req.files;

        // Apply rate limiting
        await mediaUploadLimiter(req, res, () => { });

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const education = await Education.findOne({ _id: id, userId }).session(session);
            if (!education) {
                return next(new AppError('Education not found', 404));
            }

            // Validate media
            const validation = this.validateMediaUpload(files, education.media);
            if (!validation.valid) {
                return next(new AppError(validation.message, 422));
            }

            // Process media
            const mediaResults = await this.mediaService.uploadMedia({
                files,
                entityId: id,
                entityType: 'education',
                userId,
            }, { session });

            // Virus scan
            const scanResults = await this.mediaService.scanMedia(mediaResults);
            if (scanResults.some((result) => result.infected)) {
                return next(new AppError('Media upload failed: Infected file detected', 422));
            }

            education.media.push(...mediaResults);
            await education.save({ session });

            // Clear cache
            await cacheService.deletePattern(`education:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('education.media_uploaded', {
                userId,
                count: mediaResults.length,
            });
            logger.info(`Uploaded ${mediaResults.length} media files for education ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Media uploaded successfully',
                data: { media: mediaResults },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Media upload failed for education ${id}:`, error);
            metricsCollector.increment('education.media_upload_failed', { userId });
            return next(new AppError('Failed to upload media', 422));
        } finally {
            session.endSession();
        }
    });

    /**
     * Share education
     * POST /api/v1/education/:userId/:id/share
     */
    shareEducation = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { platform } = req.body;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const education = await Education.findOne({ _id: id, userId }).session(session);
            if (!education) {
                return next(new AppError('Education not found', 404));
            }

            // Validate access
            const hasAccess = this.checkEducationAccess(education, requestingUserId, req.user.isAdmin);
            if (!hasAccess) {
                return next(new AppError('Access denied', 403));
            }

            // Generate shareable link
            const shareLink = this.generateShareableLink(education, platform);

            // Track share
            education.analytics.shares.total += 1;
            education.analytics.shares.byPlatform = {
                ...education.analytics.shares.byPlatform,
                [platform]: (education.analytics.shares.byPlatform[platform] || 0) + 1,
            };
            await education.save({ session });

            // Clear cache
            await cacheService.deletePattern(`education:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('education.shared', { userId, platform });
            logger.info(`Education ${id} shared on ${platform} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Education shared successfully',
                data: { shareLink },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Share failed for education ${id}:`, error);
            metricsCollector.increment('education.share_failed', { userId });
            return next(new AppError('Failed to share education', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Endorse education
     * POST /api/v1/education/:userId/:id/endorse
     */
    endorseEducation = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const education = await Education.findOne({ _id: id, userId }).session(session);
            if (!education) {
                return next(new AppError('Education not found', 404));
            }

            // Validate connection level
            const isConnected = await this.educationService.checkConnectionLevel(userId, requestingUserId);
            if (!isConnected) {
                return next(new AppError('Must be connected to endorse', 403));
            }

            // Check if already endorsed
            if (education.endorsements.some((e) => e.userId.toString() === requestingUserId)) {
                return next(new AppError('Education already endorsed by this user', 409));
            }

            // Add endorsement
            education.endorsements.push({
                userId: requestingUserId,
                endorsedAt: new Date(),
            });
            await education.save({ session });

            // Notify user
            this.notificationService.notifyUser(userId, {
                type: 'endorsement',
                message: `Your education "${education.degree}" was endorsed`,
                data: { educationId: id, endorserId: requestingUserId },
            }).catch((err) => logger.error(`Notification failed for endorsement ${id}:`, err));

            // Clear cache
            await cacheService.deletePattern(`education:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('education.endorsed', { userId, endorserId: requestingUserId });
            logger.info(`Education ${id} endorsed in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Education endorsed successfully',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Endorsement failed for education ${id}:`, error);
            metricsCollector.increment('education.endorse_failed', { userId });
            return next(new AppError('Failed to endorse education', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get verification status
     * GET /api/v1/education/:userId/:id/verification
     */
    getVerificationStatus = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        try {
            const cacheKey = `verification:education:${id}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('education.verification_cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const education = await Education.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('verification')
                .cache({ ttl: 60, key: cacheKey });

            if (!education) {
                return next(new AppError('Education not found', 404));
            }

            // Validate access
            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('education.verification_viewed', { userId });
            logger.info(`Fetched verification status for education ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                data: education.verification,
            });
        } catch (error) {
            logger.error(`Verification status fetch failed for ${id}:`, error);
            metricsCollector.increment('education.verification_fetch_failed', { userId });
            return next(new AppError('Failed to fetch verification status', 500));
        }
    });

    /**
     * Get trending educations
     * GET /api/v1/education/trending
     */
    getTrendingEducations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { timeframe = '7d', degree, limit = 20 } = req.query;

        const cacheKey = `trending:educations:${timeframe}:${degree || 'all'}:${limit}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('education.trending_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const educations = await this.educationService.getTrendingEducations(timeframe, degree, parseInt(limit));
            const processedEducations = await Promise.all(
                educations.map((edu) => this.processEducationData(edu, false)),
            );

            const result = { educations: processedEducations };
            await cacheService.set(cacheKey, result, 3600); // 1 hour

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('education.trending_viewed', { count: educations.length });
            logger.info(`Fetched ${educations.length} trending educations in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch trending educations:`, error);
            metricsCollector.increment('education.trending_fetch_failed');
            return next(new AppError('Failed to fetch trending educations', 500));
        }
    });

    /**
     * Get educations by degree
     * GET /api/v1/education/degrees/:degree
     */
    getEducationsByDegree = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { degree } = req.params;
        const { page = 1, limit = 20, sortBy = 'recent' } = req.query;

        const cacheKey = `educations:degree:${degree}:${page}:${limit}:${sortBy}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('education.degree_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const query = this.buildEducationQuery({ degree });
            const sortOption = this.buildSortOption(sortBy);
            const pageNum = Math.max(1, parseInt(page));
            const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
            const skip = (pageNum - 1) * limitNum;

            const [educations, totalCount] = await Promise.all([
                Education.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select(this.getSelectFields(false))
                    .lean(),
                Education.countDocuments(query).cache({ ttl: 300, key: `education_degree_count_${degree}` }),
            ]);

            const processedEducations = await Promise.all(
                educations.map((edu) => this.processEducationData(edu, false)),
            );

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                educations: processedEducations,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages,
                },
            };

            await cacheService.set(cacheKey, result, 1800); // 30 minutes

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('education.degree_viewed', { degree, count: educations.length });
            logger.info(`Fetched ${educations.length} educations for degree ${degree} in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch educations for degree ${degree}:`, error);
            metricsCollector.increment('education.degree_fetch_failed', { degree });
            return next(new AppError('Failed to fetch educations by degree', 500));
        }
    });

    /**
     * Search educations
     * GET /api/v1/education/search
     */
    searchEducations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { query, page = 1, limit = 20, filters = {} } = req.query;

        const cacheKey = `search:educations:${query}:${JSON.stringify(filters)}:${page}:${limit}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('education.search_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const searchResults = await this.educationService.searchEducations(query, filters, {
                page: parseInt(page),
                limit: parseInt(limit),
            });

            const result = {
                educations: searchResults.hits,
                totalCount: searchResults.total,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    totalPages: Math.ceil(searchResults.total / parseInt(limit)),
                },
            };

            await cacheService.set(cacheKey, result, 300); // 5 minutes

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('education.searched', { query, count: searchResults.hits.length });
            logger.info(`Search returned ${searchResults.hits.length} educations in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Search failed for query ${query}:`, error);
            metricsCollector.increment('education.search_failed');
            return next(new AppError('Failed to search educations', 500));
        }
    });

    // Helper Methods

    /**
     * Process new education asynchronously
     */
    async processNewEducationAsync(educationId, userId) {
        try {
            const session = await mongoose.startSession();
            session.startTransaction();

            const education = await Education.findById(educationId).session(session);
            if (!education) {
                await session.abortTransaction();
                session.endSession();
                return;
            }

            // Extract skills or courses
            const skills = await this.educationService.extractSkills(education.description);
            education.skills = skills.slice(0, 20);

            // Calculate quality score
            await education.calculateQualityScore({ session });

            // Auto-verify
            await this.processExternalVerification(educationId, userId);

            // Index for search
            await this.educationService.indexForSearch(education);

            // Update user stats
            await this.educationService.updateUserStats(userId, { session });

            await education.save({ session });
            await session.commitTransaction();
            logger.info(`Async processing completed for education ${educationId}`);
        } catch (error) {
            logger.error(`Async processing failed for education ${educationId}:`, error);
        } finally {
            session.endSession();
        }
    }

    /**
     * Check access permissions
     */
    checkEducationAccess(education, requestingUserId, isAdmin) {
        if (isAdmin) return true;
        if (education.userId.toString() === requestingUserId) return true;
        if (education.privacy.isPublic) return true;
        return false;
    }

    /**
     * Get allowed update fields
     */
    getAllowedUpdateFields() {
        return [
            'degree',
            'fieldOfStudy',
            'description',
            'tags',
            'skills',
            'schoolId',
            'duration',
            'privacy',
            'status',
            'templateId',
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
    processAnalyticsData(education, timeframe, metrics) {
        const analytics = education.analytics || {};
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
            endorsements: analytics.endorsements?.total || 0,
        };

        if (metrics === 'detailed') {
            filteredAnalytics.verification = education.verification;
        }

        return filteredAnalytics;
    }

    /**
     * Get user limits
     */
    getUserLimits(accountType) {
        const limits = {
            free: { maxEducations: 10, maxMedia: 5, maxSizeMB: 50 },
            premium: { maxEducations: 50, maxMedia: 20, maxSizeMB: 200 },
            enterprise: { maxEducations: 200, maxMedia: 50, maxSizeMB: 500 },
        };
        return limits[accountType] || limits.free;
    }

    /**
     * Build query for fetching educations
     */
    buildEducationQuery({ userId, status, degree, search, templateId, tags, startDate, endDate }) {
        const query = { userId, status: { $ne: 'deleted' } };

        if (status && status !== 'all') {
            query.status = status;
        }
        if (degree && degree !== 'all') {
            query.degree = degree;
        }
        if (templateId) {
            query.templateId = templateId;
        }
        if (tags) {
            const tagArray = tags.split(',').map((tag) => tag.trim().toLowerCase());
            query.tags = { $in: tagArray };
        }
        if (startDate || endDate) {
            query.duration = {};
            if (startDate) query.duration.startDate = { $gte: new Date(startDate) };
            if (endDate) query.duration.startDate = { $lte: new Date(endDate) };
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
            degree: { degree: 1 },
            popular: { 'analytics.views.total': -1 },
            quality: { 'qualityScore': -1 },
            verified: { 'verification.confidence': -1 },
        };
        return sortOptions[sortBy] || sortOptions.recent;
    }

    /**
     * Get select fields
     */
    getSelectFields(includeAnalytics) {
        const baseFields = 'degree fieldOfStudy description status tags skills schoolId duration privacy createdAt updatedAt templateId';
        return includeAnalytics ? baseFields + ' analytics' : baseFields;
    }

    /**
     * Process education data
     */
    async processEducationData(education, includeAnalytics = false, includeVerification = false) {
        const processed = {
            ...education,
            durationFormatted: this.educationService.calculateDurationFormatted(education.duration.startDate, education.duration.endDate),
        };

        if (!includeAnalytics) {
            delete processed.analytics;
        }
        if (!includeVerification) {
            delete processed.verification;
        }

        return processed;
    }

    /**
     * Calculate trending score
     */
    calculateTrendingScore(education) {
        const viewsWeight = 0.4;
        const sharesWeight = 0.3;
        const endorsementsWeight = 0.2;
        const recencyWeight = 0.1;

        const daysSinceCreated = (Date.now() - new Date(education.createdAt)) / (1000 * 60 * 60 * 24);
        const recencyScore = Math.max(0, 10 - daysSinceCreated);

        return (
            (education.analytics.views.total * viewsWeight) +
            (education.analytics.shares.total * sharesWeight) +
            (education.endorsements.length * endorsementsWeight) +
            (recencyScore * recencyWeight)
        );
    }

    /**
     * Validate media upload
     */
    validateMediaUpload(files, existingMedia) {
        const limits = this.getUserLimits('premium'); // Use premium for validation
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

    /**
     * Process external verification
     */
    async processExternalVerification(educationId, userId) {
        try {
            const education = await Education.findById(educationId);
            const result = await this.verificationService.verifyEducation({
                educationId,
                userId,
                schoolId: education.schoolId,
                degree: education.degree,
                duration: education.duration,
                gpa: education.gpa,
            });

            return result;
        } catch (error) {
            logger.error(`External verification failed for education ${educationId}:`, error);
            return { success: false, message: error.message };
        }
    }

    /**
     * Generate shareable link
     */
    generateShareableLink(education, platform) {
        const baseUrl = process.env.APP_URL || 'https://app.example.com';
        return `${baseUrl}/education/${education._id}/share?platform=${platform}`;
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
                message = 'Educations moved to trash';
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
                message = 'Educations archived';
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
                message = 'Educations published';
                break;
            case 'updateDegree':
                if (!data.degree) {
                    throw new AppError('Degree is required', 400);
                }
                updateData = {
                    degree: data.degree,
                    updatedAt: new Date(),
                    'metadata.lastModifiedBy': {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = `Degree updated to ${data.degree}`;
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

        const result = await Education.updateMany(query, updateData, options);
        return { message, result };
    }

    /**
     * Export educations as CSV
     * GET /api/v1/education/:userId/export
     */
    exportEducations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { format = 'csv', fields = 'degree,fieldOfStudy,description,status' } = req.query;

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        try {
            const educations = await Education.find({ userId, status: { $ne: 'deleted' } })
                .read('secondaryPreferred')
                .select(fields.split(',').join(' '))
                .lean();

            const csvData = this.convertToCSV(educations, fields.split(','));
            const filename = `educations_${userId}_${Date.now()}.csv`;

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('education.exported', { userId, format });
            logger.info(`Exported ${educations.length} educations for user ${userId} in ${responseTime}ms`);

            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            return res.send(csvData);
        } catch (error) {
            logger.error(`Export failed for user ${userId}:`, error);
            metricsCollector.increment('education.export_failed', { userId });
            return next(new AppError('Failed to export educations', 500));
        }
    });

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

export default new EducationController();