import Experience from '../models/Experience.js';
import ExperienceService from '../services/ExperienceService.js';
import VerificationService from '../services/VerificationService.js';
import MediaService from '../services/MediaService.js';
import TemplateService from '../services/TemplateService.js';
import NotificationService from '../services/NotificationService.js';
import { validateExperience, sanitizeInput } from '../validations/experience.validation.js';
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
const createExperienceLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 15, // 15 creates per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_experience_${req.user.id}`,
    redisClient: cacheService.getRedisClient(), // Use Redis client for distributed rate limiting
});

const updateExperienceLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 25, // 25 updates per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_experience_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const verificationLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 5, // 5 verification requests per 30 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `verify_experience_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const bulkOperationsLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // 3 bulk operations per hour
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_experience_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const mediaUploadLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 10, // 10 media uploads per 10 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `media_experience_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

class ExperienceController {
    constructor() {
        this.experienceService = ExperienceService;
        this.verificationService = VerificationService;
        this.mediaService = MediaService;
        this.templateService = TemplateService;
        this.notificationService = NotificationService;
    }

    /**
     * Create a new experience
     * POST /api/v1/experiences/:userId
     */
    createExperience = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const experienceData = req.body;
        const requestingUserId = req.user.id;

        // Validate access permissions
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied: Cannot create experience for another user', 403));
        }

        // Apply rate limiting
        await createExperienceLimiter(req, res, () => { });

        // Validate input data
        const validation = validateExperience(experienceData);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        // Sanitize input
        const sanitizedData = sanitizeInput(experienceData);

        // Check user limits
        const userExperienceCount = await Experience.countDocuments({
            userId,
            'status': { $ne: 'deleted' },
        }).cache({ ttl: 300, key: `user_experience_count_${userId}` });

        const limits = this.getUserLimits(req.user.accountType);
        if (userExperienceCount >= limits.maxExperiences) {
            return next(new AppError(`Experience limit reached (${limits.maxExperiences})`, 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            // Create experience with service
            const experience = await this.experienceService.createExperience({
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
            this.processNewExperienceAsync(experience._id, requestingUserId)
                .catch((err) => logger.error(`Async processing failed for experience ${experience._id}:`, err));

            // Log metrics
            metricsCollector.increment('experience.created', {
                userId,
                category: experience.category,
                templateUsed: !!experience.templateId,
            });

            // Emit event
            eventEmitter.emit('experience.created', {
                experienceId: experience._id,
                userId,
                templateId: experience.templateId,
            });

            // Create backup
            if (experience.settings?.autoBackup) {
                this.experienceService.createBackup(experience._id, 'create', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for experience ${experience._id}:`, err));
            }

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`Experience created successfully: ${experience._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Experience created successfully',
                data: {
                    id: experience._id,
                    userId: experience.userId,
                    title: experience.title,
                    status: experience.status,
                    createdAt: experience.createdAt,
                    processingStatus: 'started',
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Experience creation failed for user ${userId}:`, error);
            metricsCollector.increment('experience.create_failed', { userId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.code === 11000) {
                return next(new AppError('Experience with this title already exists', 409));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out', 504));
            }

            return next(new AppError('Failed to create experience', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get user's experiences with filtering and pagination
     * GET /api/v1/experiences/:userId
     */
    getExperiences = catchAsync(async (req, res, next) => {
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
            category,
            search,
            sortBy = 'recent',
            templateId,
            tags,
            startDate,
            endDate,
            includeAnalytics = 'false',
        } = req.query;

        // Build query
        const query = this.buildExperienceQuery({
            userId,
            status,
            category,
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
        const cacheKey = `experiences:${userId}:${JSON.stringify({
            page: pageNum,
            limit: limitNum,
            status,
            category,
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
                metricsCollector.increment('experience.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            // Query database with optimized read preference
            const [experiences, totalCount] = await Promise.all([
                Experience.find(query)
                    .read('secondaryPreferred') // Optimize for read-heavy operations
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select(this.getSelectFields(includeAnalytics === 'true'))
                    .populate('templateId', 'name category')
                    .populate('companyId', 'name industry')
                    .lean(),
                Experience.countDocuments(query).cache({ ttl: 300, key: `experience_count_${userId}` }),
            ]);

            // Process experiences data
            const processedExperiences = await Promise.all(
                experiences.map((exp) => this.processExperienceData(exp, includeAnalytics === 'true')),
            );

            const totalPages = Math.ceil(totalCount / limitNum);
            const hasNext = pageNum < totalPages;
            const hasPrev = pageNum > 1;

            const result = {
                experiences: processedExperiences,
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
                    category: category || 'all',
                    sortBy,
                    search: search || null,
                },
            };

            // Cache result with distributed Redis
            await cacheService.set(cacheKey, result, 300); // 5 minutes

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('experience.fetched', {
                userId,
                count: experiences.length,
                cached: false,
            });
            logger.info(`Fetched ${experiences.length} experiences for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch experiences for user ${userId}:`, error);
            metricsCollector.increment('experience.fetch_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid query parameters', 400));
            }
            return next(new AppError('Failed to fetch experiences', 500));
        }
    });

    /**
     * Get single experience by ID
     * GET /api/v1/experiences/:userId/:id
     */
    getExperienceById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { includeAnalytics = 'false', includeVerification = 'false' } = req.query;

        try {
            const cacheKey = `experience:${id}:${userId}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('experience.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const experience = await Experience.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .populate('templateId', 'name category')
                .populate('companyId', 'name industry')
                .cache({ ttl: 600, key: cacheKey });

            if (!experience) {
                return next(new AppError('Experience not found', 404));
            }

            // Check access permissions
            const hasAccess = this.checkExperienceAccess(experience, requestingUserId, req.user.isAdmin);
            if (!hasAccess) {
                return next(new AppError('Access denied', 403));
            }

            // Increment view count (async)
            if (requestingUserId !== userId) {
                experience.incrementViews(true)
                    .catch((err) => logger.error(`View increment failed for experience ${id}:`, err));
            }

            // Process response data
            const responseData = this.processExperienceData(experience.toObject(), includeAnalytics === 'true', includeVerification === 'true');

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('experience.viewed', {
                userId,
                viewerId: requestingUserId,
                isOwner: userId === requestingUserId,
            });
            logger.info(`Fetched experience ${id} for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: responseData });
        } catch (error) {
            logger.error(`Failed to fetch experience ${id}:`, error);
            metricsCollector.increment('experience.view_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid experience ID', 400));
            }
            return next(new AppError('Failed to fetch experience', 500));
        }
    });

    /**
     * Update experience
     * PUT /api/v1/experiences/:userId/:id
     */
    updateExperience = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const updates = req.body;

        // Apply rate limiting
        await updateExperienceLimiter(req, res, () => { });

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const experience = await Experience.findOne({ _id: id, userId }).session(session);
            if (!experience) {
                return next(new AppError('Experience not found', 404));
            }

            // Validate updates
            const allowedUpdates = this.getAllowedUpdateFields();
            const sanitizedUpdates = this.sanitizeUpdates(updates, allowedUpdates);

            if (Object.keys(sanitizedUpdates).length === 0) {
                return next(new AppError('No valid update fields provided', 400));
            }

            // Create version if content changed
            let versionCreated = false;
            if (sanitizedUpdates.description && sanitizedUpdates.description !== experience.description) {
                await experience.createVersion(sanitizedUpdates.description, sanitizedUpdates.title || experience.title, 'edit', {
                    userId: requestingUserId,
                }, { session });
                versionCreated = true;
            }

            // Update experience
            Object.assign(experience, sanitizedUpdates);

            // Update audit trail
            experience.metadata.lastModifiedBy = {
                userId: requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date(),
            };

            // Trigger re-verification if critical fields changed
            if (sanitizedUpdates.companyId || sanitizedUpdates.dateStart || sanitizedUpdates.dateEnd) {
                experience.verification.status = 'pending';
                this.processExternalVerification(experience._id, requestingUserId)
                    .catch((err) => logger.error(`Re-verification failed for experience ${id}:`, err));
            }

            await experience.save({ session });

            // Recalculate quality score
            if (sanitizedUpdates.description) {
                await experience.calculateQualityScore({ session });
            }

            // Create backup
            if (experience.settings?.autoBackup) {
                this.experienceService.createBackup(experience._id, 'update', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for experience ${id}:`, err));
            }

            // Clear cache
            await cacheService.deletePattern(`experience:${id}:*`);
            await cacheService.deletePattern(`experiences:${userId}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('experience.updated', {
                userId,
                versionCreated,
                fieldsUpdated: Object.keys(sanitizedUpdates).length,
            });

            // Emit event
            eventEmitter.emit('experience.updated', {
                experienceId: experience._id,
                userId,
                changes: Object.keys(sanitizedUpdates),
                versionCreated,
            });

            logger.info(`Experience updated successfully: ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Experience updated successfully',
                data: {
                    id: experience._id,
                    title: experience.title,
                    status: experience.status,
                    updatedAt: experience.updatedAt,
                    versionCreated,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Experience update failed for ${id}:`, error);
            metricsCollector.increment('experience.update_failed', { userId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out', 504));
            }
            return next(new AppError('Failed to update experience', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete experience (soft or permanent)
     * DELETE /api/v1/experiences/:userId/:id
     */
    deleteExperience = catchAsync(async (req, res, next) => {
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

            const experience = await Experience.findOne({ _id: id, userId }).session(session);
            if (!experience) {
                return next(new AppError('Experience not found', 404));
            }

            if (permanent === 'true') {
                // Permanent deletion
                await Experience.findByIdAndDelete(id, { session });
                await this.mediaService.deleteAllMedia(id, 'experience', { session });
                this.experienceService.deleteAllBackups(id)
                    .catch((err) => logger.error(`Failed to delete backups for ${id}:`, err));
                metricsCollector.increment('experience.permanently_deleted', { userId });
            } else {
                // Soft delete
                experience.status = 'deleted';
                experience.visibility = 'private';
                experience.metadata.lastModifiedBy = {
                    userId: requestingUserId,
                    ip: req.ip,
                    userAgent: req.get('User-Agent'),
                    timestamp: new Date(),
                };
                await experience.save({ session });
                metricsCollector.increment('experience.soft_deleted', { userId });
            }

            // Clear cache
            await cacheService.deletePattern(`experience:${id}:*`);
            await cacheService.deletePattern(`experiences:${userId}:*`);

            // Emit event
            eventEmitter.emit('experience.deleted', {
                experienceId: id,
                userId,
                permanent: permanent === 'true',
            });

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`Experience ${id} deleted (permanent: ${permanent}) in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: permanent === 'true' ? 'Experience permanently deleted' : 'Experience moved to trash',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Experience deletion failed for ${id}:`, error);
            metricsCollector.increment('experience.delete_failed', { userId });
            return next(new AppError('Failed to delete experience', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Bulk operations on experiences
     * POST /api/v1/experiences/:userId/bulk
     */
    bulkOperations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { operation, experienceIds, data = {} } = req.body;

        // Apply rate limiting
        await bulkOperationsLimiter(req, res, () => { });

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        // Validate input
        if (!Array.isArray(experienceIds) || experienceIds.length === 0) {
            return next(new AppError('Experience IDs array is required', 400));
        }
        if (experienceIds.length > 100) {
            return next(new AppError('Maximum 100 experiences can be processed at once', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const query = { _id: { $in: experienceIds }, userId };
            const { message } = await this.handleBulkOperation(operation, query, data, requestingUserId, req, { session });

            // Clear cache
            await Promise.all([
                cacheService.deletePattern(`experiences:${userId}:*`),
                ...experienceIds.map((id) => cacheService.deletePattern(`experience:${id}:*`)),
            ]);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('experience.bulk_operation', {
                userId,
                operation,
                count: experienceIds.length,
            });
            logger.info(`Bulk operation ${operation} completed for ${experienceIds.length} experiences in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message,
                data: {
                    operation,
                    requested: experienceIds.length,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk operation failed for user ${userId}:`, error);
            metricsCollector.increment('experience.bulk_operation_failed', { userId, operation });
            return next(new AppError('Bulk operation failed', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get experience analytics
     * GET /api/v1/experiences/:userId/:id/analytics
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
            const cacheKey = `analytics:experience:${id}:${timeframe}:${metrics}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('experience.analytics_cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const experience = await Experience.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('analytics verification metadata createdAt')
                .cache({ ttl: 900, key: cacheKey });

            if (!experience) {
                return next(new AppError('Experience not found', 404));
            }

            const analytics = this.processAnalyticsData(experience, timeframe, metrics);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('experience.analytics_viewed', { userId });
            logger.info(`Fetched analytics for experience ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: analytics });
        } catch (error) {
            logger.error(`Analytics fetch failed for ${id}:`, error);
            metricsCollector.increment('experience.analytics_fetch_failed', { userId });
            return next(new AppError('Failed to fetch analytics', 500));
        }
    });

    /**
     * Duplicate experience
     * POST /api/v1/experiences/:userId/:id/duplicate
     */
    duplicateExperience = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { title, includeVersions = 'false' } = req.body;

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const originalExperience = await Experience.findOne({ _id: id, userId }).session(session);
            if (!originalExperience) {
                return next(new AppError('Experience not found', 404));
            }

            // Check user limits
            const userExperienceCount = await Experience.countDocuments({
                userId,
                'status': { $ne: 'deleted' },
            }).cache({ ttl: 300, key: `user_experience_count_${userId}` });

            const limits = this.getUserLimits(req.user.accountType);
            if (userExperienceCount >= limits.maxExperiences) {
                return next(new AppError(`Experience limit reached (${limits.maxExperiences})`, 403));
            }

            // Create duplicate
            const duplicateData = originalExperience.toObject();
            delete duplicateData._id;
            delete duplicateData.createdAt;
            delete duplicateData.updatedAt;
            delete duplicateData.analytics;

            duplicateData.title = title || `${originalExperience.title} (Copy)`;
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
                    title: duplicateData.title,
                    changeType: 'create',
                    isActive: true,
                }];
            }

            const duplicate = new Experience(duplicateData);
            await duplicate.save({ session });

            // Create backup
            if (duplicate.settings?.autoBackup) {
                this.experienceService.createBackup(duplicate._id, 'duplicate', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for duplicate ${duplicate._id}:`, err));
            }

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('experience.duplicated', { userId });
            logger.info(`Experience ${id} duplicated as ${duplicate._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Experience duplicated successfully',
                data: {
                    originalId: id,
                    duplicateId: duplicate._id,
                    title: duplicate.title,
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Experience duplication failed for ${id}:`, error);
            metricsCollector.increment('experience.duplicate_failed', { userId });
            return next(new AppError('Failed to duplicate experience', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Verify experience
     * POST /api/v1/experiences/:userId/:id/verify
     */
    verifyExperience = catchAsync(async (req, res, next) => {
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

            const experience = await Experience.findOne({ _id: id, userId }).session(session);
            if (!experience) {
                return next(new AppError('Experience not found', 404));
            }

            // Trigger verification with circuit breaker
            const verificationResult = await this.processExternalVerification(experience._id, requestingUserId);
            if (!verificationResult.success) {
                return next(new AppError('Verification failed: ' + verificationResult.message, 424));
            }

            experience.verification = {
                status: verificationResult.status,
                confidence: verificationResult.confidence,
                verifiedBy: verificationResult.verifiedBy,
                verifiedAt: new Date(),
                details: verificationResult.details,
            };

            await experience.save({ session });

            // Notify user
            this.notificationService.notifyUser(userId, {
                type: 'verification_completed',
                message: `Experience "${experience.title}" verification ${verificationResult.status}`,
                data: { experienceId: id },
            }).catch((err) => logger.error(`Notification failed for experience ${id}:`, err));

            // Clear cache
            await cacheService.deletePattern(`experience:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('experience.verified', {
                userId,
                status: verificationResult.status,
            });
            logger.info(`Experience ${id} verified in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Experience verification completed',
                data: experience.verification,
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Verification failed for experience ${id}:`, error);
            metricsCollector.increment('experience.verify_failed', { userId });
            if (error.message.includes('timeout')) {
                return next(new AppError('External API timeout', 503));
            }
            return next(new AppError('Failed to verify experience', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Upload media for experience
     * POST /api/v1/experiences/:userId/:id/media
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

            const experience = await Experience.findOne({ _id: id, userId }).session(session);
            if (!experience) {
                return next(new AppError('Experience not found', 404));
            }

            // Validate media
            const validation = this.validateMediaUpload(files, experience.media);
            if (!validation.valid) {
                return next(new AppError(validation.message, 422));
            }

            // Process media
            const mediaResults = await this.mediaService.uploadMedia({
                files,
                entityId: id,
                entityType: 'experience',
                userId,
            }, { session });

            // Virus scan
            const scanResults = await this.mediaService.scanMedia(mediaResults);
            if (scanResults.some((result) => result.infected)) {
                return next(new AppError('Media upload failed: Infected file detected', 422));
            }

            experience.media.push(...mediaResults);
            await experience.save({ session });

            // Clear cache
            await cacheService.deletePattern(`experience:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('experience.media_uploaded', {
                userId,
                count: mediaResults.length,
            });
            logger.info(`Uploaded ${mediaResults.length} media files for experience ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Media uploaded successfully',
                data: { media: mediaResults },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Media upload failed for experience ${id}:`, error);
            metricsCollector.increment('experience.media_upload_failed', { userId });
            return next(new AppError('Failed to upload media', 422));
        } finally {
            session.endSession();
        }
    });

    /**
     * Share experience
     * POST /api/v1/experiences/:userId/:id/share
     */
    shareExperience = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { platform } = req.body;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const experience = await Experience.findOne({ _id: id, userId }).session(session);
            if (!experience) {
                return next(new AppError('Experience not found', 404));
            }

            // Validate access
            const hasAccess = this.checkExperienceAccess(experience, requestingUserId, req.user.isAdmin);
            if (!hasAccess) {
                return next(new AppError('Access denied', 403));
            }

            // Generate shareable link
            const shareLink = this.generateShareableLink(experience, platform);

            // Track share
            experience.analytics.shares.total += 1;
            experience.analytics.shares.byPlatform = {
                ...experience.analytics.shares.byPlatform,
                [platform]: (experience.analytics.shares.byPlatform[platform] || 0) + 1,
            };
            await experience.save({ session });

            // Clear cache
            await cacheService.deletePattern(`experience:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('experience.shared', { userId, platform });
            logger.info(`Experience ${id} shared on ${platform} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Experience shared successfully',
                data: { shareLink },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Share failed for experience ${id}:`, error);
            metricsCollector.increment('experience.share_failed', { userId });
            return next(new AppError('Failed to share experience', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Endorse experience
     * POST /api/v1/experiences/:userId/:id/endorse
     */
    endorseExperience = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const experience = await Experience.findOne({ _id: id, userId }).session(session);
            if (!experience) {
                return next(new AppError('Experience not found', 404));
            }

            // Validate connection level
            const isConnected = await this.experienceService.checkConnectionLevel(userId, requestingUserId);
            if (!isConnected) {
                return next(new AppError('Must be connected to endorse', 403));
            }

            // Check if already endorsed
            if (experience.endorsements.some((e) => e.userId.toString() === requestingUserId)) {
                return next(new AppError('Experience already endorsed by this user', 409));
            }

            // Add endorsement
            experience.endorsements.push({
                userId: requestingUserId,
                endorsedAt: new Date(),
            });
            await experience.save({ session });

            // Notify user
            this.notificationService.notifyUser(userId, {
                type: 'endorsement',
                message: `Your experience "${experience.title}" was endorsed`,
                data: { experienceId: id, endorserId: requestingUserId },
            }).catch((err) => logger.error(`Notification failed for endorsement ${id}:`, err));

            // Clear cache
            await cacheService.deletePattern(`experience:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('experience.endorsed', { userId, endorserId: requestingUserId });
            logger.info(`Experience ${id} endorsed in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Experience endorsed successfully',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Endorsement failed for experience ${id}:`, error);
            metricsCollector.increment('experience.endorse_failed', { userId });
            return next(new AppError('Failed to endorse experience', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get verification status
     * GET /api/v1/experiences/:userId/:id/verification
     */
    getVerificationStatus = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        try {
            const cacheKey = `verification:experience:${id}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('experience.verification_cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const experience = await Experience.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('verification')
                .cache({ ttl: 60, key: cacheKey });

            if (!experience) {
                return next(new AppError('Experience not found', 404));
            }

            // Validate access
            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('experience.verification_viewed', { userId });
            logger.info(`Fetched verification status for experience ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                data: experience.verification,
            });
        } catch (error) {
            logger.error(`Verification status fetch failed for ${id}:`, error);
            metricsCollector.increment('experience.verification_fetch_failed', { userId });
            return next(new AppError('Failed to fetch verification status', 500));
        }
    });

    /**
     * Get trending experiences
     * GET /api/v1/experiences/trending
     */
    getTrendingExperiences = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { timeframe = '7d', category, limit = 20 } = req.query;

        const cacheKey = `trending:experiences:${timeframe}:${category || 'all'}:${limit}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('experience.trending_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const experiences = await this.experienceService.getTrendingExperiences(timeframe, category, parseInt(limit));
            const processedExperiences = await Promise.all(
                experiences.map((exp) => this.processExperienceData(exp, false)),
            );

            const result = { experiences: processedExperiences };
            await cacheService.set(cacheKey, result, 3600); // 1 hour

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('experience.trending_viewed', { count: experiences.length });
            logger.info(`Fetched ${experiences.length} trending experiences in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch trending experiences:`, error);
            metricsCollector.increment('experience.trending_fetch_failed');
            return next(new AppError('Failed to fetch trending experiences', 500));
        }
    });

    /**
     * Get experiences by category
     * GET /api/v1/experiences/categories/:category
     */
    getExperiencesByCategory = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { category } = req.params;
        const { page = 1, limit = 20, sortBy = 'recent' } = req.query;

        const cacheKey = `experiences:category:${category}:${page}:${limit}:${sortBy}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('experience.category_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const query = this.buildExperienceQuery({ category });
            const sortOption = this.buildSortOption(sortBy);
            const pageNum = Math.max(1, parseInt(page));
            const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
            const skip = (pageNum - 1) * limitNum;

            const [experiences, totalCount] = await Promise.all([
                Experience.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select(this.getSelectFields(false))
                    .lean(),
                Experience.countDocuments(query).cache({ ttl: 300, key: `experience_category_count_${category}` }),
            ]);

            const processedExperiences = await Promise.all(
                experiences.map((exp) => this.processExperienceData(exp, false)),
            );

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                experiences: processedExperiences,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages,
                },
            };

            await cacheService.set(cacheKey, result, 1800); // 30 minutes

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('experience.category_viewed', { category, count: experiences.length });
            logger.info(`Fetched ${experiences.length} experiences for category ${category} in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch experiences for category ${category}:`, error);
            metricsCollector.increment('experience.category_fetch_failed', { category });
            return next(new AppError('Failed to fetch experiences by category', 500));
        }
    });

    /**
     * Search experiences
     * GET /api/v1/experiences/search
     */
    searchExperiences = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { query, page = 1, limit = 20, filters = {} } = req.query;

        const cacheKey = `search:experiences:${query}:${JSON.stringify(filters)}:${page}:${limit}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('experience.search_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const searchResults = await this.experienceService.searchExperiences(query, filters, {
                page: parseInt(page),
                limit: parseInt(limit),
            });

            const result = {
                experiences: searchResults.hits,
                totalCount: searchResults.total,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    totalPages: Math.ceil(searchResults.total / parseInt(limit)),
                },
            };

            await cacheService.set(cacheKey, result, 300); // 5 minutes

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('experience.searched', { query, count: searchResults.hits.length });
            logger.info(`Search returned ${searchResults.hits.length} experiences in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Search failed for query ${query}:`, error);
            metricsCollector.increment('experience.search_failed');
            return next(new AppError('Failed to search experiences', 500));
        }
    });

    // Helper Methods

    /**
     * Process new experience asynchronously
     */
    async processNewExperienceAsync(experienceId, userId) {
        try {
            const session = await mongoose.startSession();
            session.startTransaction();

            const experience = await Experience.findById(experienceId).session(session);
            if (!experience) {
                await session.abortTransaction();
                session.endSession();
                return;
            }

            // Extract skills
            const skills = await this.experienceService.extractSkills(experience.description);
            experience.skills = skills.slice(0, 20);

            // Calculate quality score
            await experience.calculateQualityScore({ session });

            // Auto-verify
            await this.processExternalVerification(experienceId, userId);

            // Index for search
            await this.experienceService.indexForSearch(experience);

            // Update user stats
            await this.experienceService.updateUserStats(userId, { session });

            await experience.save({ session });
            await session.commitTransaction();
            logger.info(`Async processing completed for experience ${experienceId}`);
        } catch (error) {
            logger.error(`Async processing failed for experience ${experienceId}:`, error);
        } finally {
            session.endSession();
        }
    }

    /**
     * Check access permissions
     */
    checkExperienceAccess(experience, requestingUserId, isAdmin) {
        if (isAdmin) return true;
        if (experience.userId.toString() === requestingUserId) return true;
        if (experience.visibility === 'public') return true;
        return false;
    }

    /**
     * Get allowed update fields
     */
    getAllowedUpdateFields() {
        return [
            'title',
            'description',
            'category',
            'tags',
            'skills',
            'companyId',
            'dateStart',
            'dateEnd',
            'visibility',
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
    processAnalyticsData(experience, timeframe, metrics) {
        const analytics = experience.analytics || {};
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
            filteredAnalytics.verification = experience.verification;
        }

        return filteredAnalytics;
    }

    /**
     * Get user limits
     */
    getUserLimits(accountType) {
        const limits = {
            free: { maxExperiences: 10, maxMedia: 5, maxSizeMB: 50 },
            premium: { maxExperiences: 50, maxMedia: 20, maxSizeMB: 200 },
            enterprise: { maxExperiences: 200, maxMedia: 50, maxSizeMB: 500 },
        };
        return limits[accountType] || limits.free;
    }

    /**
     * Build query for fetching experiences
     */
    buildExperienceQuery({ userId, status, category, search, templateId, tags, startDate, endDate }) {
        const query = { userId, status: { $ne: 'deleted' } };

        if (status && status !== 'all') {
            query.status = status;
        }
        if (category && category !== 'all') {
            query.category = category;
        }
        if (templateId) {
            query.templateId = templateId;
        }
        if (tags) {
            const tagArray = tags.split(',').map((tag) => tag.trim().toLowerCase());
            query.tags = { $in: tagArray };
        }
        if (startDate || endDate) {
            query.dateStart = {};
            if (startDate) query.dateStart.$gte = new Date(startDate);
            if (endDate) query.dateStart.$lte = new Date(endDate);
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
            title: { title: 1 },
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
        const baseFields = 'title description status category tags skills companyId dateStart dateEnd visibility createdAt updatedAt templateId';
        return includeAnalytics ? baseFields + ' analytics' : baseFields;
    }

    /**
     * Process experience data
     */
    async processExperienceData(experience, includeAnalytics = false, includeVerification = false) {
        const processed = {
            ...experience,
            duration: this.experienceService.calculateDuration(experience.dateStart, experience.dateEnd),
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
    calculateTrendingScore(experience) {
        const viewsWeight = 0.4;
        const sharesWeight = 0.3;
        const endorsementsWeight = 0.2;
        const recencyWeight = 0.1;

        const daysSinceCreated = (Date.now() - new Date(experience.createdAt)) / (1000 * 60 * 60 * 24);
        const recencyScore = Math.max(0, 10 - daysSinceCreated);

        return (
            (experience.analytics.views.total * viewsWeight) +
            (experience.analytics.shares.total * sharesWeight) +
            (experience.endorsements.length * endorsementsWeight) +
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
    async processExternalVerification(experienceId, userId) {
        try {
            const experience = await Experience.findById(experienceId);
            const result = await this.verificationService.verifyExperience({
                experienceId,
                userId,
                companyId: experience.companyId,
                title: experience.title,
                dateStart: experience.dateStart,
                dateEnd: experience.dateEnd,
            });

            return result;
        } catch (error) {
            logger.error(`External verification failed for experience ${experienceId}:`, error);
            return { success: false, message: error.message };
        }
    }

    /**
     * Generate shareable link
     */
    generateShareableLink(experience, platform) {
        const baseUrl = process.env.APP_URL || 'https://app.example.com';
        return `${baseUrl}/experiences/${experience._id}/share?platform=${platform}`;
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
                    visibility: 'private',
                    updatedAt: new Date(),
                    'metadata.lastModifiedBy': {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = 'Experiences moved to trash';
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
                message = 'Experiences archived';
                break;
            case 'publish':
                updateData = {
                    status: 'active',
                    visibility: 'public',
                    updatedAt: new Date(),
                    'metadata.lastModifiedBy': {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = 'Experiences published';
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

        const result = await Experience.updateMany(query, updateData, options);
        return { message, result };
    }

    /**
     * Export experiences as CSV
     * GET /api/v1/experiences/:userId/export
     */
    exportExperiences = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { format = 'csv', fields = 'title,description,category,status' } = req.query;

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        try {
            const experiences = await Experience.find({ userId, status: { $ne: 'deleted' } })
                .read('secondaryPreferred')
                .select(fields.split(',').join(' '))
                .lean();

            const csvData = this.convertToCSV(experiences, fields.split(','));
            const filename = `experiences_${userId}_${Date.now()}.csv`;

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('experience.exported', { userId, format });
            logger.info(`Exported ${experiences.length} experiences for user ${userId} in ${responseTime}ms`);

            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            return res.send(csvData);
        } catch (error) {
            logger.error(`Export failed for user ${userId}:`, error);
            metricsCollector.increment('experience.export_failed', { userId });
            return next(new AppError('Failed to export experiences', 500));
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

export default new ExperienceController();