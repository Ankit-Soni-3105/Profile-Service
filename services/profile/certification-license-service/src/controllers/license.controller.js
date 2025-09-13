// LicenseController.js
import License from '../models/License.js';
import LicenseService from '../services/LicenseService.js';
import VerificationService from '../services/VerificationService.js';
import MediaService from '../services/MediaService.js';
import TemplateService from '../services/TemplateService.js';
import NotificationService from '../services/NotificationService.js';
import { validateLicense, sanitizeInput } from '../validations/license.validation.js';
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
const createLicenseLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 15, // 15 creates per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_license_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const updateLicenseLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 25, // 25 updates per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_license_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const verificationLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 5, // 5 verification requests per 30 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `verify_license_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const bulkOperationsLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // 3 bulk operations per hour
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_license_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const mediaUploadLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 10, // 10 media uploads per 10 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `media_license_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

class LicenseController {
    constructor() {
        this.licenseService = LicenseService;
        this.verificationService = VerificationService;
        this.mediaService = MediaService;
        this.templateService = TemplateService;
        this.notificationService = NotificationService;
    }

    /**
     * Create a new license
     * POST /api/v1/licenses/:userId
     */
    createLicense = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const licenseData = req.body;
        const requestingUserId = req.user.id;

        // Validate access permissions
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied: Cannot create license for another user', 403));
        }

        // Apply rate limiting
        await createLicenseLimiter(req, res, () => { });

        // Validate input data
        const validation = validateLicense(licenseData);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        // Sanitize input
        const sanitizedData = sanitizeInput(licenseData);

        // Check user limits
        const userLicenseCount = await License.countDocuments({
            userId,
            'status.isDeleted': false,
        }).cache({ ttl: 300, key: `user_license_count_${userId}` });

        const limits = this.getUserLimits(req.user.accountType);
        if (userLicenseCount >= limits.maxLicenses) {
            return next(new AppError(`License limit reached (${limits.maxLicenses})`, 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            // Create license with service
            const license = await this.licenseService.createLicense({
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
            this.processNewLicenseAsync(license._id, requestingUserId)
                .catch((err) => logger.error(`Async processing failed for license ${license._id}:`, err));

            // Log metrics
            metricsCollector.increment('license.created', {
                userId,
                category: license.licenseDetails.category,
                templateUsed: !!license.templateId,
            });

            // Emit event
            eventEmitter.emit('license.created', {
                licenseId: license._id,
                userId,
                templateId: license.templateId,
            });

            // Create backup
            if (license.settings?.autoBackup) {
                this.licenseService.createBackup(license._id, 'create', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for license ${license._id}:`, err));
            }

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`License created successfully: ${license._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'License created successfully',
                data: {
                    id: license._id,
                    userId: license.userId,
                    title: license.licenseDetails.title,
                    status: license.status.workflow,
                    createdAt: license.createdAt,
                    processingStatus: 'started',
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`License creation failed for user ${userId}:`, error);
            metricsCollector.increment('license.create_failed', { userId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.code === 11000) {
                return next(new AppError('License with this title already exists', 409));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out', 504));
            }
            return next(new AppError('Failed to create license', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get user's licenses with filtering and pagination
     * GET /api/v1/licenses/:userId
     */
    getLicenses = catchAsync(async (req, res, next) => {
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
        const query = this.buildLicenseQuery({
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
        const cacheKey = `licenses:${userId}:${JSON.stringify({
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
                metricsCollector.increment('license.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            // Query database with optimized read preference
            const [licenses, totalCount] = await Promise.all([
                License.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select(this.getSelectFields(includeAnalytics === 'true'))
                    .populate('organization.organizationId', 'name logo industry verification.isVerified')
                    .lean(),
                License.countDocuments(query).cache({ ttl: 300, key: `license_count_${userId}` }),
            ]);

            // Process licenses data
            const processedLicenses = await Promise.all(
                licenses.map((license) => this.processLicenseData(license, includeAnalytics === 'true')),
            );

            const totalPages = Math.ceil(totalCount / limitNum);
            const hasNext = pageNum < totalPages;
            const hasPrev = pageNum > 1;

            const result = {
                licenses: processedLicenses,
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
            metricsCollector.increment('license.fetched', {
                userId,
                count: licenses.length,
                cached: false,
            });
            logger.info(`Fetched ${licenses.length} licenses for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch licenses for user ${userId}:`, error);
            metricsCollector.increment('license.fetch_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid query parameters', 400));
            }
            return next(new AppError('Failed to fetch licenses', 500));
        }
    });

    /**
     * Get single license by ID
     * GET /api/v1/licenses/:userId/:id
     */
    getLicenseById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { includeAnalytics = 'false', includeVerification = 'false' } = req.query;

        try {
            const cacheKey = `license:${id}:${userId}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('license.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const license = await License.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .populate('organization.organizationId', 'name logo industry verification.isVerified')
                .cache({ ttl: 600, key: cacheKey });

            if (!license) {
                return next(new AppError('License not found', 404));
            }

            // Check access permissions
            const hasAccess = this.checkLicenseAccess(license, requestingUserId, req.user.isAdmin);
            if (!hasAccess) {
                return next(new AppError('Access denied', 403));
            }

            // Increment view count (async)
            if (requestingUserId !== userId) {
                license.analytics.views += 1;
                license.save()
                    .catch((err) => logger.error(`View increment failed for license ${id}:`, err));
            }

            // Process response data
            const responseData = this.processLicenseData(license.toObject(), includeAnalytics === 'true', includeVerification === 'true');

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('license.viewed', {
                userId,
                viewerId: requestingUserId,
                isOwner: userId === requestingUserId,
            });
            logger.info(`Fetched license ${id} for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: responseData });
        } catch (error) {
            logger.error(`Failed to fetch license ${id}:`, error);
            metricsCollector.increment('license.view_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid license ID', 400));
            }
            return next(new AppError('Failed to fetch license', 500));
        }
    });

    /**
     * Update license
     * PUT /api/v1/licenses/:userId/:id
     */
    updateLicense = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const updates = req.body;

        // Apply rate limiting
        await updateLicenseLimiter(req, res, () => { });

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const license = await License.findOne({ _id: id, userId }).session(session);
            if (!license) {
                return next(new AppError('License not found', 404));
            }

            // Validate updates
            const allowedUpdates = this.getAllowedUpdateFields();
            const sanitizedUpdates = this.sanitizeUpdates(updates, allowedUpdates);

            if (Object.keys(sanitizedUpdates).length === 0) {
                return next(new AppError('No valid update fields provided', 400));
            }

            // Update license
            Object.assign(license, sanitizedUpdates);

            // Update audit trail
            license.metadata.lastModifiedBy = {
                userId: requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date(),
            };

            // Trigger re-verification if critical fields changed
            if (sanitizedUpdates['organization.organizationId'] || sanitizedUpdates['duration.issueDate'] || sanitizedUpdates['duration.expirationDate']) {
                license.verification.status = 'pending';
                this.processExternalVerification(license._id, requestingUserId)
                    .catch((err) => logger.error(`Re-verification failed for license ${id}:`, err));
            }

            await license.save({ session });

            // Create backup
            if (license.settings?.autoBackup) {
                this.licenseService.createBackup(license._id, 'update', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for license ${id}:`, err));
            }

            // Clear cache
            await cacheService.deletePattern(`license:${id}:*`);
            await cacheService.deletePattern(`licenses:${userId}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('license.updated', {
                userId,
                fieldsUpdated: Object.keys(sanitizedUpdates).length,
            });

            // Emit event
            eventEmitter.emit('license.updated', {
                licenseId: license._id,
                userId,
                changes: Object.keys(sanitizedUpdates),
            });

            logger.info(`License updated successfully: ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'License updated successfully',
                data: {
                    id: license._id,
                    title: license.licenseDetails.title,
                    status: license.status.workflow,
                    updatedAt: license.updatedAt,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`License update failed for ${id}:`, error);
            metricsCollector.increment('license.update_failed', { userId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out', 504));
            }
            return next(new AppError('Failed to update license', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete license (soft or permanent)
     * DELETE /api/v1/licenses/:userId/:id
     */
    deleteLicense = catchAsync(async (req, res, next) => {
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

            const license = await License.findOne({ _id: id, userId }).session(session);
            if (!license) {
                return next(new AppError('License not found', 404));
            }

            if (permanent === 'true') {
                // Permanent deletion
                await License.findByIdAndDelete(id, { session });
                await this.mediaService.deleteAllMedia(id, 'license', { session });
                this.licenseService.deleteAllBackups(id)
                    .catch((err) => logger.error(`Failed to delete backups for ${id}:`, err));
                metricsCollector.increment('license.permanently_deleted', { userId });
            } else {
                // Soft delete
                license.status.isDeleted = true;
                license.status.isActive = false;
                license.status.deletedAt = new Date();
                await license.save({ session });
                metricsCollector.increment('license.soft_deleted', { userId });
            }

            // Clear cache
            await cacheService.deletePattern(`license:${id}:*`);
            await cacheService.deletePattern(`licenses:${userId}:*`);

            // Emit event
            eventEmitter.emit('license.deleted', {
                licenseId: id,
                userId,
                permanent: permanent === 'true',
            });

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`License ${id} deleted (permanent: ${permanent}) in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: permanent === 'true' ? 'License permanently deleted' : 'License moved to trash',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`License deletion failed for ${id}:`, error);
            metricsCollector.increment('license.delete_failed', { userId });
            return next(new AppError('Failed to delete license', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Bulk operations on licenses
     * POST /api/v1/licenses/:userId/bulk
     */
    bulkOperations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { operation, licenseIds, data = {} } = req.body;

        // Apply rate limiting
        await bulkOperationsLimiter(req, res, () => { });

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        // Validate input
        if (!Array.isArray(licenseIds) || licenseIds.length === 0) {
            return next(new AppError('License IDs array is required', 400));
        }
        if (licenseIds.length > 100) {
            return next(new AppError('Maximum 100 licenses can be processed at once', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const query = { _id: { $in: licenseIds }, userId };
            const { message } = await this.handleBulkOperation(operation, query, data, requestingUserId, req, { session });

            // Clear cache
            await Promise.all([
                cacheService.deletePattern(`licenses:${userId}:*`),
                ...licenseIds.map((id) => cacheService.deletePattern(`license:${id}:*`)),
            ]);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('license.bulk_operation', {
                userId,
                operation,
                count: licenseIds.length,
            });
            logger.info(`Bulk operation ${operation} completed for ${licenseIds.length} licenses in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message,
                data: {
                    operation,
                    requested: licenseIds.length,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk operation failed for user ${userId}:`, error);
            metricsCollector.increment('license.bulk_operation_failed', { userId, operation });
            return next(new AppError('Bulk operation failed', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get license analytics
     * GET /api/v1/licenses/:userId/:id/analytics
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
            const cacheKey = `analytics:license:${id}:${timeframe}:${metrics}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('license.analytics_cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const license = await License.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('analytics verification metadata createdAt')
                .cache({ ttl: 900, key: cacheKey });

            if (!license) {
                return next(new AppError('License not found', 404));
            }

            const analytics = this.processAnalyticsData(license, timeframe, metrics);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('license.analytics_viewed', { userId });
            logger.info(`Fetched analytics for license ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: analytics });
        } catch (error) {
            logger.error(`Analytics fetch failed for ${id}:`, error);
            metricsCollector.increment('license.analytics_fetch_failed', { userId });
            return next(new AppError('Failed to fetch analytics', 500));
        }
    });

    /**
     * Verify license
     * POST /api/v1/licenses/:userId/:id/verify
     */
    verifyLicense = catchAsync(async (req, res, next) => {
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

            const license = await License.findOne({ _id: id, userId }).session(session);
            if (!license) {
                return next(new AppError('License not found', 404));
            }

            // Trigger verification
            const verificationResult = await this.processExternalVerification(license._id, requestingUserId);
            if (!verificationResult.success) {
                return next(new AppError('Verification failed: ' + verificationResult.message, 424));
            }

            license.verification = {
                status: verificationResult.status,
                verificationScore: verificationResult.confidence,
                verifiedBy: verificationResult.verifiedBy,
                verificationDate: new Date(),
                verificationMethod: verificationResult.method,
            };

            await license.save({ session });

            // Notify user
            this.notificationService.notifyUser(userId, {
                type: 'verification_completed',
                message: `License "${license.licenseDetails.title}" verification ${verificationResult.status}`,
                data: { licenseId: id },
            }).catch((err) => logger.error(`Notification failed for license ${id}:`, err));

            // Clear cache
            await cacheService.deletePattern(`license:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('license.verified', {
                userId,
                status: verificationResult.status,
            });
            logger.info(`License ${id} verified in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'License verification completed',
                data: license.verification,
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Verification failed for license ${id}:`, error);
            metricsCollector.increment('license.verify_failed', { userId });
            if (error.message.includes('timeout')) {
                return next(new AppError('External API timeout', 503));
            }
            return next(new AppError('Failed to verify license', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Upload media for license
     * POST /api/v1/licenses/:userId/:id/media
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

            const license = await License.findOne({ _id: id, userId }).session(session);
            if (!license) {
                return next(new AppError('License not found', 404));
            }

            // Validate media
            const validation = this.validateMediaUpload(files, license.verification.documents || []);
            if (!validation.valid) {
                return next(new AppError(validation.message, 422));
            }

            // Process media with CDN
            const mediaResults = await this.mediaService.uploadMedia({
                files,
                entityId: id,
                entityType: 'license',
                userId,
            }, { session });

            // Virus scan
            const scanResults = await this.mediaService.scanMedia(mediaResults);
            if (scanResults.some((result) => result.infected)) {
                return next(new AppError('Media upload failed: Infected file detected', 422));
            }

            license.verification.documents.push(...mediaResults);
            await license.save({ session });

            // Clear cache
            await cacheService.deletePattern(`license:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('license.media_uploaded', {
                userId,
                count: mediaResults.length,
            });
            logger.info(`Uploaded ${mediaResults.length} media files for license ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Media uploaded successfully',
                data: { media: mediaResults },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Media upload failed for license ${id}:`, error);
            metricsCollector.increment('license.media_upload_failed', { userId });
            return next(new AppError('Failed to upload media', 422));
        } finally {
            session.endSession();
        }
    });

    /**
     * Share license
     * POST /api/v1/licenses/:userId/:id/share
     */
    shareLicense = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { platform } = req.body;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const license = await License.findOne({ _id: id, userId }).session(session);
            if (!license) {
                return next(new AppError('License not found', 404));
            }

            // Validate access
            const hasAccess = this.checkLicenseAccess(license, requestingUserId, req.user.isAdmin);
            if (!hasAccess) {
                return next(new AppError('Access denied', 403));
            }

            // Generate shareable link
            const shareLink = this.generateShareableLink(license, platform);

            // Track share
            license.analytics.shareCount += 1;
            license.social.shares.push({
                userId: requestingUserId,
                platform,
                sharedAt: new Date(),
                audience: 'public',
            });
            await license.save({ session });

            // Clear cache
            await cacheService.deletePattern(`license:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('license.shared', { userId, platform });
            logger.info(`License ${id} shared on ${platform} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'License shared successfully',
                data: { shareLink },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Share failed for license ${id}:`, error);
            metricsCollector.increment('license.share_failed', { userId });
            return next(new AppError('Failed to share license', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Endorse license
     * POST /api/v1/licenses/:userId/:id/endorse
     */
    endorseLicense = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const license = await License.findOne({ _id: id, userId }).session(session);
            if (!license) {
                return next(new AppError('License not found', 404));
            }

            // Validate connection level
            const isConnected = await this.licenseService.checkConnectionLevel(userId, requestingUserId);
            if (!isConnected) {
                return next(new AppError('Must be connected to endorse', 403));
            }

            // Check if already endorsed
            if (license.social.endorsements.some((e) => e.userId.toString() === requestingUserId)) {
                return next(new AppError('License already endorsed by this user', 409));
            }

            // Add endorsement
            license.social.endorsements.push({
                userId: requestingUserId,
                endorsedAt: new Date(),
            });
            license.analytics.engagementMetrics.endorsements.push({
                userId: requestingUserId,
                endorsedAt: new Date(),
            });
            await license.save({ session });

            // Notify user
            this.notificationService.notifyUser(userId, {
                type: 'endorsement',
                message: `Your license "${license.licenseDetails.title}" was endorsed`,
                data: { licenseId: id, endorserId: requestingUserId },
            }).catch((err) => logger.error(`Notification failed for endorsement ${id}:`, err));

            // Clear cache
            await cacheService.deletePattern(`license:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('license.endorsed', { userId, endorserId: requestingUserId });
            logger.info(`License ${id} endorsed in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'License endorsed successfully',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Endorsement failed for license ${id}:`, error);
            metricsCollector.increment('license.endorse_failed', { userId });
            return next(new AppError('Failed to endorse license', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get verification status
     * GET /api/v1/licenses/:userId/:id/verification
     */
    getVerificationStatus = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        try {
            const cacheKey = `verification:license:${id}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('license.verification_cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const license = await License.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('verification')
                .cache({ ttl: 60, key: cacheKey });

            if (!license) {
                return next(new AppError('License not found', 404));
            }

            // Validate access
            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('license.verification_viewed', { userId });
            logger.info(`Fetched verification status for license ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                data: license.verification,
            });
        } catch (error) {
            logger.error(`Verification status fetch failed for ${id}:`, error);
            metricsCollector.increment('license.verification_fetch_failed', { userId });
            return next(new AppError('Failed to fetch verification status', 500));
        }
    });

    /**
     * Get trending licenses
     * GET /api/v1/licenses/trending
     */
    getTrendingLicenses = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { timeframe = '7d', category, limit = 20 } = req.query;

        const cacheKey = `trending:licenses:${timeframe}:${category || 'all'}:${limit}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('license.trending_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const licenses = await this.licenseService.getTrendingLicenses(timeframe, category, parseInt(limit));
            const processedLicenses = await Promise.all(
                licenses.map((license) => this.processLicenseData(license, false)),
            );

            const result = { licenses: processedLicenses };
            await cacheService.set(cacheKey, result, 3600); // 1 hour

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('license.trending_viewed', { count: licenses.length });
            logger.info(`Fetched ${licenses.length} trending licenses in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch trending licenses:`, error);
            metricsCollector.increment('license.trending_fetch_failed');
            return next(new AppError('Failed to fetch trending licenses', 500));
        }
    });

    /**
     * Get licenses by category
     * GET /api/v1/licenses/categories/:category
     */
    getLicensesByCategory = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { category } = req.params;
        const { page = 1, limit = 20, sortBy = 'recent' } = req.query;

        const cacheKey = `licenses:category:${category}:${page}:${limit}:${sortBy}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('license.category_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const query = this.buildLicenseQuery({ category });
            const sortOption = this.buildSortOption(sortBy);
            const pageNum = Math.max(1, parseInt(page));
            const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
            const skip = (pageNum - 1) * limitNum;

            const [licenses, totalCount] = await Promise.all([
                License.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select(this.getSelectFields(false))
                    .lean(),
                License.countDocuments(query).cache({ ttl: 300, key: `license_category_count_${category}` }),
            ]);

            const processedLicenses = await Promise.all(
                licenses.map((license) => this.processLicenseData(license, false)),
            );

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                licenses: processedLicenses,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages,
                },
            };

            await cacheService.set(cacheKey, result, 1800); // 30 minutes

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('license.category_viewed', { category, count: licenses.length });
            logger.info(`Fetched ${licenses.length} licenses for category ${category} in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch licenses for category ${category}:`, error);
            metricsCollector.increment('license.category_fetch_failed', { category });
            return next(new AppError('Failed to fetch licenses by category', 500));
        }
    });

    /**
     * Search licenses
     * GET /api/v1/licenses/search
     */
    searchLicenses = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { query, page = 1, limit = 20, filters = {} } = req.query;

        const cacheKey = `search:licenses:${query}:${JSON.stringify(filters)}:${page}:${limit}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('license.search_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const searchResults = await this.licenseService.searchLicenses(query, filters, {
                page: parseInt(page),
                limit: parseInt(limit),
            });

            const result = {
                licenses: searchResults.hits,
                totalCount: searchResults.total,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    totalPages: Math.ceil(searchResults.total / parseInt(limit)),
                },
            };

            await cacheService.set(cacheKey, result, 300); // 5 minutes

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('license.searched', { query, count: searchResults.hits.length });
            logger.info(`Search returned ${searchResults.hits.length} licenses in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Search failed for query ${query}:`, error);
            metricsCollector.increment('license.search_failed');
            return next(new AppError('Failed to search licenses', 500));
        }
    });

    // Helper Methods

    /**
     * Process new license asynchronously
     */
    async processNewLicenseAsync(licenseId, userId) {
        try {
            const session = await mongoose.startSession();
            session.startTransaction();

            const license = await License.findById(licenseId).session(session);
            if (!license) {
                await session.abortTransaction();
                session.endSession();
                return;
            }

            // Calculate quality score
            await license.calculateQualityScore({ session });

            // Auto-verify
            await this.processExternalVerification(licenseId, userId);

            // Index for search
            await this.licenseService.indexForSearch(license);

            // Update user stats
            await this.licenseService.updateUserStats(userId, { session });

            await license.save({ session });
            await session.commitTransaction();
            logger.info(`Async processing completed for license ${licenseId}`);
        } catch (error) {
            logger.error(`Async processing failed for license ${licenseId}:`, error);
        } finally {
            session.endSession();
        }
    }

    /**
     * Check access permissions
     */
    checkLicenseAccess(license, requestingUserId, isAdmin) {
        if (isAdmin) return true;
        if (license.userId.toString() === requestingUserId) return true;
        if (license.status.isActive && !license.status.isDeleted) return true;
        return false;
    }

    /**
     * Get allowed update fields
     */
    getAllowedUpdateFields() {
        return [
            'licenseDetails.title',
            'licenseDetails.description',
            'licenseDetails.category',
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
                sanitized[field] = field === 'licenseDetails.description' ? sanitizeHtml(updates[field]) : sanitizeInput(updates[field]);
            }
        });
        return sanitized;
    }

    /**
     * Process analytics data
     */
    processAnalyticsData(license, timeframe, metrics) {
        const analytics = license.analytics || {};
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
            filteredAnalytics.verification = license.verification;
        }

        return filteredAnalytics;
    }

    /**
     * Get user limits
     */
    getUserLimits(accountType) {
        const limits = {
            free: { maxLicenses: 10, maxMedia: 5, maxSizeMB: 50 },
            premium: { maxLicenses: 50, maxMedia: 10, maxSizeMB: 100 },
            enterprise: { maxLicenses: 200, maxMedia: 20, maxSizeMB: 200 },
        };
        return limits[accountType] || limits.free;
    }

    /**
     * Build query for fetching licenses
     */
    buildLicenseQuery({ userId, status, category, search, templateId, tags, startDate, endDate }) {
        const query = { userId, 'status.isDeleted': false };

        if (status && status !== 'all') {
            query['status.workflow'] = status;
        }
        if (category && category !== 'all') {
            query['licenseDetails.category'] = category;
        }
        if (templateId) {
            query.templateId = templateId;
        }
        if (tags) {
            const tagArray = tags.split(',').map((tag) => tag.trim().toLowerCase());
            query['licenseDetails.tags'] = { $in: tagArray };
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
            title: { 'licenseDetails.title': 1 },
            popular: { 'cache.popularityScore': -1 },
            verified: { 'verification.verificationScore': -1 },
        };
        return sortOptions[sortBy] || sortOptions.recent;
    }

    /**
     * Get select fields
     */
    getSelectFields(includeAnalytics) {
        const baseFields = 'licenseDetails.title licenseDetails.description licenseDetails.category organization duration status createdAt updatedAt templateId';
        return includeAnalytics ? baseFields + ' analytics' : baseFields;
    }

    /**
     * Process license data
     */
    async processLicenseData(license, includeAnalytics = false, includeVerification = false) {
        const processed = {
            ...license,
            duration: {
                issueDate: license.duration.issueDate,
                expirationDate: license.duration.expirationDate,
                isExpired: license.isExpired,
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
    calculateTrendingScore(license) {
        const viewsWeight = 0.4;
        const sharesWeight = 0.3;
        const endorsementsWeight = 0.2;
        const recencyWeight = 0.1;

        const daysSinceCreated = (Date.now() - new Date(license.createdAt)) / (1000 * 60 * 60 * 24);
        const recencyScore = Math.max(0, 10 - daysSinceCreated);

        return (
            (license.analytics.views * viewsWeight) +
            (license.analytics.shareCount * sharesWeight) +
            (license.social.endorsements.length * endorsementsWeight) +
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
    async processExternalVerification(licenseId, userId) {
        try {
            const license = await License.findById(licenseId);
            const result = await this.verificationService.verifyLicense({
                licenseId,
                userId,
                organizationId: license.organization.organizationId,
                title: license.licenseDetails.title,
                issueDate: license.duration.issueDate,
                expirationDate: license.duration.expirationDate,
            });

            return result;
        } catch (error) {
            logger.error(`External verification failed for license ${licenseId}:`, error);
            return { success: false, message: error.message };
        }
    }

    /**
     * Generate shareable link
     */
    generateShareableLink(license, platform) {
        const baseUrl = process.env.APP_URL || 'https://app.example.com';
        return `${baseUrl}/licenses/${license._id}/share?platform=${platform}`;
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
                message = 'Licenses moved to trash';
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
                message = 'Licenses archived';
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
                message = 'Licenses published';
                break;
            case 'updateCategory':
                if (!data.category) {
                    throw new AppError('Category is required', 400);
                }
                updateData = {
                    'licenseDetails.category': data.category,
                    'metadata.lastModifiedBy': {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = `Category updated to ${data.category}`;
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

        const result = await License.updateMany(query, updateData, options);
        return { message, result };
    }
}

export default new LicenseController();