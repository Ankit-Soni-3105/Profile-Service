import Certification from '../models/Certification.js';
import CertificationService from '../services/CertificationService.js';
import VerificationService from '../services/VerificationService.js';
import MediaService from '../services/MediaService.js';
import TemplateService from '../services/TemplateService.js';
import NotificationService from '../services/NotificationService.js';
import { validateCertification, sanitizeInput } from '../validations/certification.validation.js';
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
const createCertificationLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 15, // 15 creates per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_certification_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const updateCertificationLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 25, // 25 updates per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_certification_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const verificationLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 5, // 5 verification requests per 30 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `verify_certification_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const bulkOperationsLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // 3 bulk operations per hour
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_certification_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const mediaUploadLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 10, // 10 media uploads per 10 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `media_certification_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

class CertificationController {
    constructor() {
        this.certificationService = CertificationService;
        this.verificationService = VerificationService;
        this.mediaService = MediaService;
        this.templateService = TemplateService;
        this.notificationService = NotificationService;
    }

    /**
     * Create a new certification
     * POST /api/v1/certifications/:userId
     */
    createCertification = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const certificationData = req.body;
        const requestingUserId = req.user.id;

        // Validate access permissions
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied: Cannot create certification for another user', 403));
        }

        // Apply rate limiting
        await createCertificationLimiter(req, res, () => { });

        // Validate input data
        const validation = validateCertification(certificationData);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        // Sanitize input
        const sanitizedData = sanitizeInput(certificationData);

        // Check user limits
        const userCertificationCount = await Certification.countDocuments({
            userId,
            'status.isDeleted': false,
        }).cache({ ttl: 300, key: `user_certification_count_${userId}` });

        const limits = this.getUserLimits(req.user.accountType);
        if (userCertificationCount >= limits.maxCertifications) {
            return next(new AppError(`Certification limit reached (${limits.maxCertifications})`, 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            // Create certification with service
            const certification = await this.certificationService.createCertification({
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
            this.processNewCertificationAsync(certification._id, requestingUserId)
                .catch((err) => logger.error(`Async processing failed for certification ${certification._id}:`, err));

            // Log metrics
            metricsCollector.increment('certification.created', {
                userId,
                category: certification.badgeDetails.category,
                templateUsed: !!certification.templateId,
            });

            // Emit event
            eventEmitter.emit('certification.created', {
                certificationId: certification._id,
                userId,
                templateId: certification.templateId,
            });

            // Create backup
            if (certification.settings?.autoBackup) {
                this.certificationService.createBackup(certification._id, 'create', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for certification ${certification._id}:`, err));
            }

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`Certification created successfully: ${certification._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Certification created successfully',
                data: {
                    id: certification._id,
                    userId: certification.userId,
                    title: certification.badgeDetails.title,
                    status: certification.status.workflow,
                    createdAt: certification.createdAt,
                    processingStatus: 'started',
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Certification creation failed for user ${userId}:`, error);
            metricsCollector.increment('certification.create_failed', { userId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.code === 11000) {
                return next(new AppError('Certification with this title already exists', 409));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out', 504));
            }
            return next(new AppError('Failed to create certification', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get user's certifications with filtering and pagination
     * GET /api/v1/certifications/:userId
     */
    getCertifications = catchAsync(async (req, res, next) => {
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
        const query = this.buildCertificationQuery({
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
        const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
        const skip = (pageNum - 1) * limitNum;

        // Cache key
        const cacheKey = `certifications:${userId}:${JSON.stringify({
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
                metricsCollector.increment('certification.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            // Query database with optimized read preference
            const [certifications, totalCount] = await Promise.all([
                Certification.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select(this.getSelectFields(includeAnalytics === 'true'))
                    .populate('organization.organizationId', 'name logo industry verification.isVerified')
                    .lean(),
                Certification.countDocuments(query).cache({ ttl: 300, key: `certification_count_${userId}` }),
            ]);

            // Process certifications data
            const processedCertifications = await Promise.all(
                certifications.map((cert) => this.processCertificationData(cert, includeAnalytics === 'true')),
            );

            const totalPages = Math.ceil(totalCount / limitNum);
            const hasNext = pageNum < totalPages;
            const hasPrev = pageNum > 1;

            const result = {
                certifications: processedCertifications,
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

            // Cache result
            await cacheService.set(cacheKey, result, 300); // 5 minutes

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('certification.fetched', {
                userId,
                count: certifications.length,
                cached: false,
            });
            logger.info(`Fetched ${certifications.length} certifications for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch certifications for user ${userId}:`, error);
            metricsCollector.increment('certification.fetch_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid query parameters', 400));
            }
            return next(new AppError('Failed to fetch certifications', 500));
        }
    });

    /**
     * Get single certification by ID
     * GET /api/v1/certifications/:userId/:id
     */
    getCertificationById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { includeAnalytics = 'false', includeVerification = 'false' } = req.query;

        try {
            const cacheKey = `certification:${id}:${userId}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('certification.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const certification = await Certification.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .populate('organization.organizationId', 'name logo industry verification.isVerified')
                .cache({ ttl: 600, key: cacheKey });

            if (!certification) {
                return next(new AppError('Certification not found', 404));
            }

            // Check access permissions
            const hasAccess = this.checkCertificationAccess(certification, requestingUserId, req.user.isAdmin);
            if (!hasAccess) {
                return next(new AppError('Access denied', 403));
            }

            // Increment view count (async)
            if (requestingUserId !== userId) {
                certification.analytics.views += 1;
                certification.save()
                    .catch((err) => logger.error(`View increment failed for certification ${id}:`, err));
            }

            // Process response data
            const responseData = this.processCertificationData(certification.toObject(), includeAnalytics === 'true', includeVerification === 'true');

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('certification.viewed', {
                userId,
                viewerId: requestingUserId,
                isOwner: userId === requestingUserId,
            });
            logger.info(`Fetched certification ${id} for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: responseData });
        } catch (error) {
            logger.error(`Failed to fetch certification ${id}:`, error);
            metricsCollector.increment('certification.view_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid certification ID', 400));
            }
            return next(new AppError('Failed to fetch certification', 500));
        }
    });

    /**
     * Update certification
     * PUT /api/v1/certifications/:userId/:id
     */
    updateCertification = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const updates = req.body;

        // Apply rate limiting
        await updateCertificationLimiter(req, res, () => { });

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const certification = await Certification.findOne({ _id: id, userId }).session(session);
            if (!certification) {
                return next(new AppError('Certification not found', 404));
            }

            // Validate updates
            const allowedUpdates = this.getAllowedUpdateFields();
            const sanitizedUpdates = this.sanitizeUpdates(updates, allowedUpdates);

            if (Object.keys(sanitizedUpdates).length === 0) {
                return next(new AppError('No valid update fields provided', 400));
            }

            // Create version if content changed
            let versionCreated = false;
            if (sanitizedUpdates['badgeDetails.description'] && sanitizedUpdates['badgeDetails.description'] !== certification.badgeDetails.description) {
                await certification.createVersion(sanitizedUpdates['badgeDetails.description'], sanitizedUpdates['badgeDetails.title'] || certification.badgeDetails.title, 'edit', {
                    userId: requestingUserId,
                }, { session });
                versionCreated = true;
            }

            // Update certification
            Object.assign(certification, sanitizedUpdates);

            // Update audit trail
            certification.metadata.lastModifiedBy = {
                userId: requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date(),
            };

            // Trigger re-verification if critical fields changed
            if (sanitizedUpdates['organization.organizationId'] || sanitizedUpdates['duration.issueDate'] || sanitizedUpdates['duration.expirationDate']) {
                certification.verification.status = 'pending';
                this.processExternalVerification(certification._id, requestingUserId)
                    .catch((err) => logger.error(`Re-verification failed for certification ${id}:`, err));
            }

            await certification.save({ session });

            // Recalculate quality score
            if (sanitizedUpdates['badgeDetails.description']) {
                await certification.calculateQualityScore({ session });
            }

            // Create backup
            if (certification.settings?.autoBackup) {
                this.certificationService.createBackup(certification._id, 'update', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for certification ${id}:`, err));
            }

            // Clear cache
            await cacheService.deletePattern(`certification:${id}:*`);
            await cacheService.deletePattern(`certifications:${userId}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('certification.updated', {
                userId,
                versionCreated,
                fieldsUpdated: Object.keys(sanitizedUpdates).length,
            });

            // Emit event
            eventEmitter.emit('certification.updated', {
                certificationId: certification._id,
                userId,
                changes: Object.keys(sanitizedUpdates),
                versionCreated,
            });

            logger.info(`Certification updated successfully: ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Certification updated successfully',
                data: {
                    id: certification._id,
                    title: certification.badgeDetails.title,
                    status: certification.status.workflow,
                    updatedAt: certification.updatedAt,
                    versionCreated,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Certification update failed for ${id}:`, error);
            metricsCollector.increment('certification.update_failed', { userId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out', 504));
            }
            return next(new AppError('Failed to update certification', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete certification (soft or permanent)
     * DELETE /api/v1/certifications/:userId/:id
     */
    deleteCertification = catchAsync(async (req, res, next) => {
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

            const certification = await Certification.findOne({ _id: id, userId }).session(session);
            if (!certification) {
                return next(new AppError('Certification not found', 404));
            }

            if (permanent === 'true') {
                // Permanent deletion
                await Certification.findByIdAndDelete(id, { session });
                await this.mediaService.deleteAllMedia(id, 'certification', { session });
                this.certificationService.deleteAllBackups(id)
                    .catch((err) => logger.error(`Failed to delete backups for ${id}:`, err));
                metricsCollector.increment('certification.permanently_deleted', { userId });
            } else {
                // Soft delete
                certification.status.isDeleted = true;
                certification.status.isActive = false;
                certification.status.deletedAt = new Date();
                await certification.save({ session });
                metricsCollector.increment('certification.soft_deleted', { userId });
            }

            // Clear cache
            await cacheService.deletePattern(`certification:${id}:*`);
            await cacheService.deletePattern(`certifications:${userId}:*`);

            // Emit event
            eventEmitter.emit('certification.deleted', {
                certificationId: id,
                userId,
                permanent: permanent === 'true',
            });

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`Certification ${id} deleted (permanent: ${permanent}) in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: permanent === 'true' ? 'Certification permanently deleted' : 'Certification moved to trash',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Certification deletion failed for ${id}:`, error);
            metricsCollector.increment('certification.delete_failed', { userId });
            return next(new AppError('Failed to delete certification', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Bulk operations on certifications
     * POST /api/v1/certifications/:userId/bulk
     */
    bulkOperations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { operation, certificationIds, data = {} } = req.body;

        // Apply rate limiting
        await bulkOperationsLimiter(req, res, () => { });

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        // Validate input
        if (!Array.isArray(certificationIds) || certificationIds.length === 0) {
            return next(new AppError('Certification IDs array is required', 400));
        }
        if (certificationIds.length > 100) {
            return next(new AppError('Maximum 100 certifications can be processed at once', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const query = { _id: { $in: certificationIds }, userId };
            const { message } = await this.handleBulkOperation(operation, query, data, requestingUserId, req, { session });

            // Clear cache
            await Promise.all([
                cacheService.deletePattern(`certifications:${userId}:*`),
                ...certificationIds.map((id) => cacheService.deletePattern(`certification:${id}:*`)),
            ]);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('certification.bulk_operation', {
                userId,
                operation,
                count: certificationIds.length,
            });
            logger.info(`Bulk operation ${operation} completed for ${certificationIds.length} certifications in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message,
                data: {
                    operation,
                    requested: certificationIds.length,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk operation failed for user ${userId}:`, error);
            metricsCollector.increment('certification.bulk_operation_failed', { userId, operation });
            return next(new AppError('Bulk operation failed', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get certification analytics
     * GET /api/v1/certifications/:userId/:id/analytics
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
            const cacheKey = `analytics:certification:${id}:${timeframe}:${metrics}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('certification.analytics_cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const certification = await Certification.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('analytics verification metadata createdAt')
                .cache({ ttl: 900, key: cacheKey });

            if (!certification) {
                return next(new AppError('Certification not found', 404));
            }

            const analytics = this.processAnalyticsData(certification, timeframe, metrics);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('certification.analytics_viewed', { userId });
            logger.info(`Fetched analytics for certification ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: analytics });
        } catch (error) {
            logger.error(`Analytics fetch failed for ${id}:`, error);
            metricsCollector.increment('certification.analytics_fetch_failed', { userId });
            return next(new AppError('Failed to fetch analytics', 500));
        }
    });

    /**
     * Duplicate certification
     * POST /api/v1/certifications/:userId/:id/duplicate
     */
    duplicateCertification = catchAsync(async (req, res, next) => {
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

            const originalCertification = await Certification.findOne({ _id: id, userId }).session(session);
            if (!originalCertification) {
                return next(new AppError('Certification not found', 404));
            }

            // Check user limits
            const userCertificationCount = await Certification.countDocuments({
                userId,
                'status.isDeleted': false,
            }).cache({ ttl: 300, key: `user_certification_count_${userId}` });

            const limits = this.getUserLimits(req.user.accountType);
            if (userCertificationCount >= limits.maxCertifications) {
                return next(new AppError(`Certification limit reached (${limits.maxCertifications})`, 403));
            }

            // Create duplicate
            const duplicateData = originalCertification.toObject();
            delete duplicateData._id;
            delete duplicateData.createdAt;
            delete duplicateData.updatedAt;
            delete duplicateData.analytics;

            duplicateData.badgeDetails.title = title || `${originalCertification.badgeDetails.title} (Copy)`;
            duplicateData.status.workflow = 'draft';
            duplicateData.metadata.createdBy = {
                userId: requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date(),
            };

            if (includeVersions !== 'true') {
                duplicateData.versions = [{
                    versionNumber: 1,
                    description: duplicateData.badgeDetails.description,
                    title: duplicateData.badgeDetails.title,
                    changeType: 'create',
                    isActive: true,
                }];
            }

            const duplicate = new Certification(duplicateData);
            await duplicate.save({ session });

            // Create backup
            if (duplicate.settings?.autoBackup) {
                this.certificationService.createBackup(duplicate._id, 'duplicate', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for duplicate ${duplicate._id}:`, err));
            }

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('certification.duplicated', { userId });
            logger.info(`Certification ${id} duplicated as ${duplicate._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Certification duplicated successfully',
                data: {
                    originalId: id,
                    duplicateId: duplicate._id,
                    title: duplicate.badgeDetails.title,
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Certification duplication failed for ${id}:`, error);
            metricsCollector.increment('certification.duplicate_failed', { userId });
            return next(new AppError('Failed to duplicate certification', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Verify certification
     * POST /api/v1/certifications/:userId/:id/verify
     */
    verifyCertification = catchAsync(async (req, res, next) => {
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

            const certification = await Certification.findOne({ _id: id, userId }).session(session);
            if (!certification) {
                return next(new AppError('Certification not found', 404));
            }

            // Trigger verification
            const verificationResult = await this.processExternalVerification(certification._id, requestingUserId);
            if (!verificationResult.success) {
                return next(new AppError('Verification failed: ' + verificationResult.message, 424));
            }

            certification.verification = {
                status: verificationResult.status,
                verificationScore: verificationResult.confidence,
                verifiedBy: verificationResult.verifiedBy,
                verificationDate: new Date(),
                verificationMethod: verificationResult.method,
            };

            await certification.save({ session });

            // Notify user
            this.notificationService.notifyUser(userId, {
                type: 'verification_completed',
                message: `Certification "${certification.badgeDetails.title}" verification ${verificationResult.status}`,
                data: { certificationId: id },
            }).catch((err) => logger.error(`Notification failed for certification ${id}:`, err));

            // Clear cache
            await cacheService.deletePattern(`certification:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('certification.verified', {
                userId,
                status: verificationResult.status,
            });
            logger.info(`Certification ${id} verified in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Certification verification completed',
                data: certification.verification,
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Verification failed for certification ${id}:`, error);
            metricsCollector.increment('certification.verify_failed', { userId });
            if (error.message.includes('timeout')) {
                return next(new AppError('External API timeout', 503));
            }
            return next(new AppError('Failed to verify certification', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Upload media for certification
     * POST /api/v1/certifications/:userId/:id/media
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

            const certification = await Certification.findOne({ _id: id, userId }).session(session);
            if (!certification) {
                return next(new AppError('Certification not found', 404));
            }

            // Validate media
            const validation = this.validateMediaUpload(files, certification.verification.documents || []);
            if (!validation.valid) {
                return next(new AppError(validation.message, 422));
            }

            // Process media with CDN
            const mediaResults = await this.mediaService.uploadMedia({
                files,
                entityId: id,
                entityType: 'certification',
                userId,
            }, { session });

            // Virus scan
            const scanResults = await this.mediaService.scanMedia(mediaResults);
            if (scanResults.some((result) => result.infected)) {
                return next(new AppError('Media upload failed: Infected file detected', 422));
            }

            certification.verification.documents.push(...mediaResults);
            await certification.save({ session });

            // Clear cache
            await cacheService.deletePattern(`certification:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('certification.media_uploaded', {
                userId,
                count: mediaResults.length,
            });
            logger.info(`Uploaded ${mediaResults.length} media files for certification ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Media uploaded successfully',
                data: { media: mediaResults },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Media upload failed for certification ${id}:`, error);
            metricsCollector.increment('certification.media_upload_failed', { userId });
            return next(new AppError('Failed to upload media', 422));
        } finally {
            session.endSession();
        }
    });

    /**
     * Share certification
     * POST /api/v1/certifications/:userId/:id/share
     */
    shareCertification = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { platform } = req.body;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const certification = await Certification.findOne({ _id: id, userId }).session(session);
            if (!certification) {
                return next(new AppError('Certification not found', 404));
            }

            // Validate access
            const hasAccess = this.checkCertificationAccess(certification, requestingUserId, req.user.isAdmin);
            if (!hasAccess) {
                return next(new AppError('Access denied', 403));
            }

            // Generate shareable link
            const shareLink = this.generateShareableLink(certification, platform);

            // Track share
            certification.analytics.shareCount += 1;
            certification.social.shares.push({
                userId: requestingUserId,
                platform,
                sharedAt: new Date(),
                audience: 'public',
            });
            await certification.save({ session });

            // Clear cache
            await cacheService.deletePattern(`certification:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('certification.shared', { userId, platform });
            logger.info(`Certification ${id} shared on ${platform} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Certification shared successfully',
                data: { shareLink },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Share failed for certification ${id}:`, error);
            metricsCollector.increment('certification.share_failed', { userId });
            return next(new AppError('Failed to share certification', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Endorse certification
     * POST /api/v1/certifications/:userId/:id/endorse
     */
    endorseCertification = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const certification = await Certification.findOne({ _id: id, userId }).session(session);
            if (!certification) {
                return next(new AppError('Certification not found', 404));
            }

            // Validate connection level
            const isConnected = await this.certificationService.checkConnectionLevel(userId, requestingUserId);
            if (!isConnected) {
                return next(new AppError('Must be connected to endorse', 403));
            }

            // Check if already endorsed
            if (certification.social.endorsements.some((e) => e.userId.toString() === requestingUserId)) {
                return next(new AppError('Certification already endorsed by this user', 409));
            }

            // Add endorsement
            certification.social.endorsements.push({
                userId: requestingUserId,
                endorsedAt: new Date(),
            });
            certification.analytics.engagementMetrics.endorsements.push({
                userId: requestingUserId,
                endorsedAt: new Date(),
            });
            await certification.save({ session });

            // Notify user
            this.notificationService.notifyUser(userId, {
                type: 'endorsement',
                message: `Your certification "${certification.badgeDetails.title}" was endorsed`,
                data: { certificationId: id, endorserId: requestingUserId },
            }).catch((err) => logger.error(`Notification failed for endorsement ${id}:`, err));

            // Clear cache
            await cacheService.deletePattern(`certification:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('certification.endorsed', { userId, endorserId: requestingUserId });
            logger.info(`Certification ${id} endorsed in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Certification endorsed successfully',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Endorsement failed for certification ${id}:`, error);
            metricsCollector.increment('certification.endorse_failed', { userId });
            return next(new AppError('Failed to endorse certification', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get verification status
     * GET /api/v1/certifications/:userId/:id/verification
     */
    getVerificationStatus = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        try {
            const cacheKey = `verification:certification:${id}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('certification.verification_cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const certification = await Certification.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('verification')
                .cache({ ttl: 60, key: cacheKey });

            if (!certification) {
                return next(new AppError('Certification not found', 404));
            }

            // Validate access
            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('certification.verification_viewed', { userId });
            logger.info(`Fetched verification status for certification ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                data: certification.verification,
            });
        } catch (error) {
            logger.error(`Verification status fetch failed for ${id}:`, error);
            metricsCollector.increment('certification.verification_fetch_failed', { userId });
            return next(new AppError('Failed to fetch verification status', 500));
        }
    });

    /**
     * Get trending certifications
     * GET /api/v1/certifications/trending
     */
    getTrendingCertifications = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { timeframe = '7d', category, limit = 20 } = req.query;

        const cacheKey = `trending:certifications:${timeframe}:${category || 'all'}:${limit}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('certification.trending_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const certifications = await this.certificationService.getTrendingCertifications(timeframe, category, parseInt(limit));
            const processedCertifications = await Promise.all(
                certifications.map((cert) => this.processCertificationData(cert, false)),
            );

            const result = { certifications: processedCertifications };
            await cacheService.set(cacheKey, result, 3600); // 1 hour

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('certification.trending_viewed', { count: certifications.length });
            logger.info(`Fetched ${certifications.length} trending certifications in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch trending certifications:`, error);
            metricsCollector.increment('certification.trending_fetch_failed');
            return next(new AppError('Failed to fetch trending certifications', 500));
        }
    });

    /**
     * Get certifications by category
     * GET /api/v1/certifications/categories/:category
     */
    getCertificationsByCategory = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { category } = req.params;
        const { page = 1, limit = 20, sortBy = 'recent' } = req.query;

        const cacheKey = `certifications:category:${category}:${page}:${limit}:${sortBy}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('certification.category_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const query = this.buildCertificationQuery({ category });
            const sortOption = this.buildSortOption(sortBy);
            const pageNum = Math.max(1, parseInt(page));
            const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
            const skip = (pageNum - 1) * limitNum;

            const [certifications, totalCount] = await Promise.all([
                Certification.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select(this.getSelectFields(false))
                    .lean(),
                Certification.countDocuments(query).cache({ ttl: 300, key: `certification_category_count_${category}` }),
            ]);

            const processedCertifications = await Promise.all(
                certifications.map((cert) => this.processCertificationData(cert, false)),
            );

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                certifications: processedCertifications,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages,
                },
            };

            await cacheService.set(cacheKey, result, 1800); // 30 minutes

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('certification.category_viewed', { category, count: certifications.length });
            logger.info(`Fetched ${certifications.length} certifications for category ${category} in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch certifications for category ${category}:`, error);
            metricsCollector.increment('certification.category_fetch_failed', { category });
            return next(new AppError('Failed to fetch certifications by category', 500));
        }
    });

    /**
     * Search certifications
     * GET /api/v1/certifications/search
     */
    searchCertifications = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { query, page = 1, limit = 20, filters = {} } = req.query;

        const cacheKey = `search:certifications:${query}:${JSON.stringify(filters)}:${page}:${limit}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('certification.search_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const searchResults = await this.certificationService.searchCertifications(query, filters, {
                page: parseInt(page),
                limit: parseInt(limit),
            });

            const result = {
                certifications: searchResults.hits,
                totalCount: searchResults.total,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    totalPages: Math.ceil(searchResults.total / parseInt(limit)),
                },
            };

            await cacheService.set(cacheKey, result, 300); // 5 minutes

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('certification.searched', { query, count: searchResults.hits.length });
            logger.info(`Search returned ${searchResults.hits.length} certifications in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Search failed for query ${query}:`, error);
            metricsCollector.increment('certification.search_failed');
            return next(new AppError('Failed to search certifications', 500));
        }
    });

    // Helper Methods

    /**
     * Process new certification asynchronously
     */
    async processNewCertificationAsync(certificationId, userId) {
        try {
            const session = await mongoose.startSession();
            session.startTransaction();

            const certification = await Certification.findById(certificationId).session(session);
            if (!certification) {
                await session.abortTransaction();
                session.endSession();
                return;
            }

            // Extract skills
            const skills = await this.certificationService.extractSkills(certification.badgeDetails.description);
            certification.badgeDetails.skills = skills.slice(0, 20);

            // Calculate quality score
            await certification.calculateQualityScore({ session });

            // Auto-verify
            await this.processExternalVerification(certificationId, userId);

            // Index for search
            await this.certificationService.indexForSearch(certification);

            // Update user stats
            await this.certificationService.updateUserStats(userId, { session });

            await certification.save({ session });
            await session.commitTransaction();
            logger.info(`Async processing completed for certification ${certificationId}`);
        } catch (error) {
            logger.error(`Async processing failed for certification ${certificationId}:`, error);
        } finally {
            session.endSession();
        }
    }

    /**
     * Check access permissions
     */
    checkCertificationAccess(certification, requestingUserId, isAdmin) {
        if (isAdmin) return true;
        if (certification.userId.toString() === requestingUserId) return true;
        if (certification.status.isActive && !certification.status.isDeleted) return true;
        return false;
    }

    /**
     * Get allowed update fields
     */
    getAllowedUpdateFields() {
        return [
            'badgeDetails.title',
            'badgeDetails.description',
            'badgeDetails.category',
            'badgeDetails.tags',
            'badgeDetails.skills',
            'organization.organizationId',
            'duration.issueDate',
            'duration.expirationDate',
            'status.isActive',
            'status.workflow',
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
                sanitized[field] = field === 'badgeDetails.description' ? sanitizeHtml(updates[field]) : sanitizeInput(updates[field]);
            }
        });
        return sanitized;
    }

    /**
     * Process analytics data
     */
    processAnalyticsData(certification, timeframe, metrics) {
        const analytics = certification.analytics || {};
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
                total: analytics.views || 0,
                byDate: (analytics.viewHistory || []).filter((v) => new Date(v.viewedAt) >= timeframeDate),
            },
            shares: {
                total: analytics.shareCount || 0,
            },
            endorsements: analytics.engagementMetrics?.endorsements?.length || 0,
        };

        if (metrics === 'detailed') {
            filteredAnalytics.verification = certification.verification;
        }

        return filteredAnalytics;
    }

    /**
     * Get user limits
     */
    getUserLimits(accountType) {
        const limits = {
            free: { maxCertifications: 10, maxMedia: 5, maxSizeMB: 50 },
            premium: { maxCertifications: 50, maxMedia: 10, maxSizeMB: 100 },
            enterprise: { maxCertifications: 200, maxMedia: 20, maxSizeMB: 200 },
        };
        return limits[accountType] || limits.free;
    }

    /**
     * Build query for fetching certifications
     */
    buildCertificationQuery({ userId, status, category, search, templateId, tags, startDate, endDate }) {
        const query = { userId, 'status.isDeleted': false };

        if (status && status !== 'all') {
            query['status.workflow'] = status;
        }
        if (category && category !== 'all') {
            query['badgeDetails.category'] = category;
        }
        if (templateId) {
            query.templateId = templateId;
        }
        if (tags) {
            const tagArray = tags.split(',').map((tag) => tag.trim().toLowerCase());
            query['badgeDetails.tags'] = { $in: tagArray };
        }
        if (startDate || endDate) {
            query['duration.issueDate'] = {};
            if (startDate) query['duration.issueDate'].$gte = new Date(startDate);
            if (endDate) query['duration.issueDate'].$lte = new Date(endDate);
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
            recent: { 'duration.issueDate': -1 },
            oldest: { createdAt: 1 },
            title: { 'badgeDetails.title': 1 },
            popular: { 'cache.popularityScore': -1 },
            verified: { 'verification.verificationScore': -1 },
        };
        return sortOptions[sortBy] || sortOptions.recent;
    }

    /**
     * Get select fields
     */
    getSelectFields(includeAnalytics) {
        const baseFields = 'badgeDetails.title badgeDetails.description badgeDetails.category badgeDetails.tags badgeDetails.skills organization duration status createdAt updatedAt templateId';
        return includeAnalytics ? baseFields + ' analytics' : baseFields;
    }

    /**
     * Process certification data
     */
    async processCertificationData(certification, includeAnalytics = false, includeVerification = false) {
        const processed = {
            ...certification,
            duration: {
                issueDate: certification.duration.issueDate,
                expirationDate: certification.duration.expirationDate,
                isExpired: certification.isExpired,
            },
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
    calculateTrendingScore(certification) {
        const viewsWeight = 0.4;
        const sharesWeight = 0.3;
        const endorsementsWeight = 0.2;
        const recencyWeight = 0.1;

        const daysSinceCreated = (Date.now() - new Date(certification.createdAt)) / (1000 * 60 * 60 * 24);
        const recencyScore = Math.max(0, 10 - daysSinceCreated);

        return (
            (certification.analytics.views * viewsWeight) +
            (certification.analytics.shareCount * sharesWeight) +
            (certification.social.endorsements.length * endorsementsWeight) +
            (recencyScore * recencyWeight)
        );
    }

    /**
     * Validate media upload
     */
    validateMediaUpload(files, existingMedia) {
        const limits = this.getUserLimits('premium');
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
    async processExternalVerification(certificationId, userId) {
        try {
            const certification = await Certification.findById(certificationId);
            const result = await this.verificationService.verifyCertification({
                certificationId,
                userId,
                organizationId: certification.organization.organizationId,
                title: certification.badgeDetails.title,
                issueDate: certification.duration.issueDate,
                expirationDate: certification.duration.expirationDate,
            });

            return result;
        } catch (error) {
            logger.error(`External verification failed for certification ${certificationId}:`, error);
            return { success: false, message: error.message };
        }
    }

    /**
     * Generate shareable link
     */
    generateShareableLink(certification, platform) {
        const baseUrl = process.env.APP_URL || 'https://app.example.com';
        return `${baseUrl}/certifications/${certification._id}/share?platform=${platform}`;
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
                    'status.isDeleted': true,
                    'status.isActive': false,
                    'status.deletedAt': new Date(),
                    'metadata.lastModifiedBy': {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = 'Certifications moved to trash';
                break;
            case 'archive':
                updateData = {
                    'status.workflow': 'archived',
                    'status.archivedAt': new Date(),
                    'metadata.lastModifiedBy': {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = 'Certifications archived';
                break;
            case 'publish':
                updateData = {
                    'status.workflow': 'verified',
                    'status.isActive': true,
                    'metadata.lastModifiedBy': {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = 'Certifications published';
                break;
            case 'updateCategory':
                if (!data.category) {
                    throw new AppError('Category is required', 400);
                }
                updateData = {
                    'badgeDetails.category': data.category,
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
                        'badgeDetails.tags': { $each: data.tags.map((tag) => tag.trim().toLowerCase()).slice(0, 15) },
                    },
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
                    'status.isActive': data.visibility === 'public',
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

        const result = await Certification.updateMany(query, updateData, options);
        return { message, result };
    }

    /**
     * Export certifications as CSV
     * GET /api/v1/certifications/:userId/export
     */
    exportCertifications = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { format = 'csv', fields = 'badgeDetails.title,badgeDetails.description,badgeDetails.category,status.workflow' } = req.query;

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        try {
            const certifications = await Certification.find({ userId, 'status.isDeleted': false })
                .read('secondaryPreferred')
                .select(fields.split(',').join(' '))
                .lean();

            const csvData = this.convertToCSV(certifications, fields.split(','));
            const filename = `certifications_${userId}_${Date.now()}.csv`;

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('certification.exported', { userId, format });
            logger.info(`Exported ${certifications.length} certifications for user ${userId} in ${responseTime}ms`);

            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            return res.send(csvData);
        } catch (error) {
            logger.error(`Export failed for user ${userId}:`, error);
            metricsCollector.increment('certification.export_failed', { userId });
            return next(new AppError('Failed to export certifications', 500));
        }
    });

    /**
     * Convert data to CSV
     */
    convertToCSV(data, fields) {
        const headers = fields.join(',');
        const rows = data.map((item) => {
            return fields.map((field) => {
                const value = field.includes('.') ? field.split('.').reduce((obj, key) => obj?.[key] || '', item) : item[field] || '';
                return `"${value.toString().replace(/"/g, '""')}"`;
            }).join(',');
        });
        return `${headers}\n${rows.join('\n')}`;
    }
}

export default new CertificationController();