import Organization from '../models/Organization.js';
import VerificationService from '../services/VerificationService.js';
import MediaService from '../services/MediaService.js';
import NotificationService from '../services/NotificationService.js';
import { validateOrganization, sanitizeInput } from '../validations/organization.validation.js';
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
const createOrganizationLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15-minute window
    max: 5, // Allow 5 creates per user per IP (stricter due to organizational significance)
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_organization_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
    legacyHeaders: false,
});

const updateOrganizationLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5-minute window
    max: 15, // Allow 15 updates
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_organization_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const verificationLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30-minute window
    max: 3, // Strict limit for external API calls
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `verify_organization_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const bulkOperationsLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // Hourly limit
    max: 2, // Conservative limit for bulk operations
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_organization_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const mediaUploadLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000, // 10-minute window
    max: 10, // Limit uploads
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `media_organization_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const searchLimiter = createRateLimiter({
    windowMs: 1 * 60 * 1000, // 1-minute window
    max: 50, // Allow frequent searches
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `search_organization_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const analyticsLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5-minute window
    max: 20, // Moderate limit for analytics requests
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `analytics_organization_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

class OrganizationController {
    constructor() {
        this.verificationService = VerificationService;
        this.mediaService = MediaService;
        this.notificationService = NotificationService;
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
     * Create a new organization
     * POST /api/v1/organizations
     * Creates an organization record with validation, async processing, and transaction support.
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    createOrganization = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const requestingUserId = req.user.id;
        const organizationData = req.body;

        if (!req.user.isAdmin && !req.user.permissions.includes('create_organization')) {
            return next(new AppError('Access denied: Insufficient permissions', 403));
        }

        await createOrganizationLimiter(req, res, () => { });

        const validation = validateOrganization(organizationData);
        if (!validation.valid) {
            metricsCollector.increment('organization.validation_failed', { userId: requestingUserId, errors: validation.errors.length });
            return next(new AppError(`Validation failed: ${validation.message}`, 400));
        }

        const sanitizedData = sanitizeInput(organizationData);
        sanitizedData.name = sanitizedData.name?.trim();
        sanitizedData.description = sanitizedData.description ? sanitizeHtml(sanitizedData.description) : null;

        const existingOrg = await Organization.findOne({ name: sanitizedData.name, status: { $ne: 'deleted' } });
        if (existingOrg) {
            return next(new AppError('Organization with this name already exists', 409));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const organization = await Organization.create([{
                ...sanitizedData,
                createdBy: requestingUserId,
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
                status: 'pending',
                privacy: {
                    isPublic: false,
                    showDetails: true,
                    searchable: true,
                },
            }], { session });

            this.processNewOrganizationAsync(organization[0]._id, requestingUserId)
                .catch((err) => {
                    logger.error(`Async processing failed for organization ${organization[0]._id}:`, err);
                    metricsCollector.increment('organization.async_processing_failed', { organizationId: organization[0]._id });
                });

            metricsCollector.increment('organization.created', {
                userId: requestingUserId,
                name: organization[0].name,
                type: organization[0].type,
                accountType: req.user.accountType,
            });
            metricsCollector.timing('organization.create_time', Date.now() - startTime);

            eventEmitter.emit('organization.created', {
                organizationId: organization[0]._id,
                userId: requestingUserId,
                name: organization[0].name,
                type: organization[0].type,
            });

            if (organization[0].settings?.autoBackup) {
                await this.createBackup(organization[0]._id, 'create', requestingUserId, { session });
            }

            await session.commitTransaction();
            logger.info(`Organization created successfully: ${organization[0]._id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Organization created successfully',
                data: {
                    id: organization[0]._id,
                    name: organization[0].name,
                    status: organization[0].status,
                    createdAt: organization[0].createdAt,
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Organization creation failed for user ${requestingUserId}:`, { error: error.message });
            metricsCollector.increment('organization.create_failed', { userId: requestingUserId });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Get organizations with filtering and pagination
     * GET /api/v1/organizations
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    getOrganizations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const requestingUserId = req.user.id;
        const {
            page = 1,
            limit = 20,
            status,
            name,
            type,
            search,
            sortBy = 'recent',
            tags,
        } = req.query;

        await searchLimiter(req, res, () => { });

        const query = this.buildOrganizationQuery({ status, name, type, search, tags });
        const sortOption = this.buildSortOption(sortBy);
        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
        const skip = (pageNum - 1) * limitNum;

        const cacheKey = `organizations:${requestingUserId}:${JSON.stringify({ page, limit, status, name, type, sortBy, tags })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('organization.cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const [organizations, totalCount] = await Promise.all([
                Organization.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select('-__v')
                    .lean({ virtuals: true }),
                Organization.countDocuments(query).cache({ ttl: 300 }),
            ]);

            const result = {
                organizations,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages: Math.ceil(totalCount / limitNum),
                    hasNext: pageNum < Math.ceil(totalCount / limitNum),
                    hasPrev: pageNum > 1,
                },
            };

            await cacheService.set(cacheKey, result, 300, ['organizations:user:' + requestingUserId]);
            metricsCollector.increment('organization.fetched', { userId: requestingUserId, count: organizations.length });
            metricsCollector.timing('organization.get_list_time', Date.now() - startTime);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch organizations for user ${requestingUserId}:`, { error: error.message });
            metricsCollector.increment('organization.fetch_failed', { userId: requestingUserId });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        }
    });

    /**
     * Get single organization by ID
     * GET /api/v1/organizations/:id
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    getOrganizationById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;

        if (!req.user.isAdmin && !req.user.permissions.includes('view_organization')) {
            const hasAccess = await this.checkAccess(id, requestingUserId);
            if (!hasAccess) {
                return next(new AppError('Access denied', 403));
            }
        }

        const cacheKey = `organization:${id}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('organization.cache_hit', { id });
                return ApiResponse.success(res, cached);
            }

            const organization = await Organization.findOne({ _id: id, status: { $ne: 'deleted' } })
                .read('secondaryPreferred')
                .select('-__v')
                .lean({ virtuals: true });

            if (!organization) {
                return next(new AppError('Organization not found', 404));
            }

            await this.updateAnalytics(organization, requestingUserId);
            await cacheService.set(cacheKey, organization, 600, ['organizations:id:' + id]);
            metricsCollector.increment('organization.viewed', { id, userId: requestingUserId });
            metricsCollector.timing('organization.get_by_id_time', Date.now() - startTime);

            return ApiResponse.success(res, { data: organization });
        } catch (error) {
            logger.error(`Failed to fetch organization ${id}:`, { error: error.message });
            metricsCollector.increment('organization.view_failed', { id });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        }
    });

    /**
     * Update organization
     * PUT /api/v1/organizations/:id
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    updateOrganization = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;
        const updates = req.body;

        if (!req.user.isAdmin && !req.user.permissions.includes('update_organization')) {
            return next(new AppError('Access denied', 403));
        }

        await updateOrganizationLimiter(req, res, () => { });

        const sanitizedUpdates = this.sanitizeUpdates(updates, this.getAllowedUpdateFields());
        if (Object.keys(sanitizedUpdates).length === 0) {
            return next(new AppError('No valid update fields provided', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const organization = await Organization.findById(id).session(session);
            if (!organization || organization.status === 'deleted') {
                return next(new AppError('Organization not found', 404));
            }

            if (sanitizedUpdates.name || sanitizedUpdates.type) {
                organization.versions = organization.versions || [];
                organization.versions.push({
                    versionNumber: organization.metadata.version + 1,
                    name: sanitizedUpdates.name || organization.name,
                    type: sanitizedUpdates.type || organization.type,
                    changeType: 'edit',
                    timestamp: new Date(),
                });
            }

            Object.assign(organization, sanitizedUpdates);
            organization.metadata.version += 1;
            organization.metadata.updateCount += 1;
            organization.metadata.lastModifiedBy = {
                userId: requestingUserId,
                timestamp: new Date(),
                changes: Object.keys(sanitizedUpdates),
            };

            if (['name', 'type', 'website'].some(field => sanitizedUpdates[field])) {
                organization.verification.status = 'pending';
                this.processExternalVerification(organization._id, requestingUserId).catch((err) => {
                    logger.error(`Re-verification failed for organization ${organization._id}:`, err);
                });
            }

            await organization.save({ session });
            await this.indexForSearch(organization);
            await cacheService.deletePattern(`organization:${id}:*`);

            metricsCollector.increment('organization.updated', { id });
            metricsCollector.timing('organization.update_time', Date.now() - startTime);
            eventEmitter.emit('organization.updated', { organizationId: id, changes: Object.keys(sanitizedUpdates) });

            await session.commitTransaction();
            return ApiResponse.success(res, {
                message: 'Organization updated successfully',
                data: { id: organization._id, name: organization.name, status: organization.status },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Organization update failed for ${id}:`, { error: error.message });
            metricsCollector.increment('organization.update_failed', { id });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete organization
     * DELETE /api/v1/organizations/:id
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    deleteOrganization = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;
        const { permanent = 'false' } = req.query;

        if (!req.user.isAdmin && !req.user.permissions.includes('delete_organization')) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const organization = await Organization.findById(id).session(session);
            if (!organization || organization.status === 'deleted') {
                return next(new AppError('Organization not found', 404));
            }

            if (permanent === 'true') {
                await Organization.findByIdAndDelete(id, { session });
                await this.mediaService.deleteAllMedia(id, 'organization', { session });
            } else {
                organization.status = 'deleted';
                organization.privacy.isPublic = false;
                organization.privacy.searchable = false;
                await organization.save({ session });
            }

            await cacheService.deletePattern(`organization:${id}:*`);
            metricsCollector.increment(`organization.${permanent ? 'permanently_deleted' : 'soft_deleted'}`, { id });
            metricsCollector.timing('organization.delete_time', Date.now() - startTime);
            eventEmitter.emit('organization.deleted', { organizationId: id, permanent });

            await session.commitTransaction();
            return ApiResponse.success(res, {
                message: permanent === 'true' ? 'Organization permanently deleted' : 'Organization soft deleted',
                data: { id },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Organization deletion failed for ${id}:`, { error: error.message });
            metricsCollector.increment('organization.delete_failed', { id });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Verify organization
     * POST /api/v1/organizations/:id/verify
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    verifyOrganization = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;

        if (!req.user.isAdmin && !req.user.permissions.includes('verify_organization')) {
            return next(new AppError('Access denied for verification', 403));
        }

        await verificationLimiter(req, res, () => { });

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const organization = await Organization.findById(id).session(session);
            if (!organization || organization.status === 'deleted') {
                return next(new AppError('Organization not found', 404));
            }

            const verificationResult = await this.circuitBreaker.fire(async () => {
                return await retry(() => this.verificationService.verifyOrganization({
                    organizationId: organization._id,
                    name: organization.name,
                    type: organization.type,
                    website: organization.website,
                }), this.retryConfig);
            });

            organization.verification = {
                status: verificationResult.success ? 'verified' : 'failed',
                confidence: verificationResult.confidence || 0,
                verifiedBy: verificationResult.verifiedBy || 'external_api',
                verifiedAt: new Date(),
                details: verificationResult.details || [],
            };
            await organization.save({ session });

            await this.indexForSearch(organization);
            await cacheService.deletePattern(`organization:${id}:*`);

            eventEmitter.emit('organization.verified', {
                organizationId: id,
                userId: requestingUserId,
                verificationStatus: verificationResult.success ? 'verified' : 'failed',
            });

            await session.commitTransaction();
            metricsCollector.increment('organization.verified', { id, status: verificationResult.status });
            metricsCollector.timing('organization.verify_time', Date.now() - startTime);

            return ApiResponse.success(res, {
                message: `Organization ${verificationResult.success ? 'verified' : 'verification failed'}`,
                data: { id: organization._id, verificationStatus: organization.verification.status },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Verification failed for organization ${id}:`, { error: error.message });
            metricsCollector.increment('organization.verify_failed', { id });
            throw error instanceof AppError ? error : new AppError('Failed to verify organization', 424);
        } finally {
            session.endSession();
        }
    });

    /**
     * Upload organization media
     * POST /api/v1/organizations/:id/media
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    uploadOrganizationMedia = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;
        const files = req.files || [];

        if (!req.user.isAdmin && !req.user.permissions.includes('update_organization')) {
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

            const organization = await Organization.findById(id).session(session);
            if (!organization || organization.status === 'deleted') {
                return next(new AppError('Organization not found', 404));
            }

            const mediaResults = await this.mediaService.uploadMedia({
                files,
                entityId: organization._id,
                entityType: 'organization',
                userId: requestingUserId,
                category: 'organization_media',
            }, { session });

            const scanResults = await this.mediaService.scanMedia(mediaResults);
            const infected = scanResults.filter(r => r.infected);
            if (infected.length > 0) {
                await this.mediaService.deleteMedia(infected.map(m => m.id), { session });
                return next(new AppError(`Media upload failed: ${infected.length} infected files detected`, 422));
            }

            organization.media = [...(organization.media || []), ...mediaResults];
            await organization.save({ session });

            await cacheService.deletePattern(`organization:${id}:*`);
            metricsCollector.increment('organization.media_uploaded', { id, mediaCount: files.length });
            metricsCollector.timing('organization.media_upload_time', Date.now() - startTime);
            eventEmitter.emit('organization.media_uploaded', { organizationId: id, mediaCount: files.length });

            await session.commitTransaction();
            return ApiResponse.success(res, {
                message: 'Media uploaded successfully',
                data: { id: organization._id, mediaCount: mediaResults.length },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Media upload failed for organization ${id}:`, { error: error.message });
            metricsCollector.increment('organization.media_upload_failed', { id });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Bulk create organizations
     * POST /api/v1/organizations/bulk
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    bulkCreateOrganizations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const requestingUserId = req.user.id;
        const organizationsData = req.body.organizations || [];

        if (!req.user.isAdmin && !req.user.permissions.includes('create_organization')) {
            return next(new AppError('Access denied', 403));
        }

        await bulkOperationsLimiter(req, res, () => { });

        if (!Array.isArray(organizationsData) || organizationsData.length === 0) {
            return next(new AppError('No organizations data provided', 400));
        }

        if (organizationsData.length > 20) {
            return next(new AppError('Cannot process more than 20 organizations at once', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const validatedOrganizations = [];
            for (const orgData of organizationsData) {
                const validation = validateOrganization(orgData);
                if (!validation.valid) {
                    throw new AppError(`Validation failed for organization: ${validation.message}`, 400);
                }

                const sanitizedData = sanitizeInput(orgData);
                sanitizedData.name = sanitizedData.name?.trim();
                sanitizedData.description = sanitizedData.description ? sanitizeHtml(sanitizedData.description) : null;

                const existingOrg = await Organization.findOne({ name: sanitizedData.name, status: { $ne: 'deleted' } }).session(session);
                if (existingOrg) {
                    throw new AppError(`Organization with name ${sanitizedData.name} already exists`, 409);
                }

                validatedOrganizations.push({
                    ...sanitizedData,
                    createdBy: requestingUserId,
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
                    status: 'pending',
                    privacy: {
                        isPublic: false,
                        showDetails: true,
                        searchable: true,
                    },
                });
            }

            const organizations = await Organization.insertMany(validatedOrganizations, { session });

            for (const org of organizations) {
                this.processNewOrganizationAsync(org._id, requestingUserId).catch((err) => {
                    logger.error(`Async processing failed for organization ${org._id}:`, err);
                });
            }

            metricsCollector.increment('organization.bulk_created', { userId: requestingUserId, count: organizations.length });
            metricsCollector.timing('organization.bulk_create_time', Date.now() - startTime);
            eventEmitter.emit('organization.bulk_created', { userId: requestingUserId, count: organizations.length });

            await session.commitTransaction();
            return ApiResponse.success(res, {
                message: `Successfully created ${organizations.length} organizations`,
                data: { count: organizations.length, organizationIds: organizations.map(o => o._id) },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk organization creation failed for user ${requestingUserId}:`, { error: error.message });
            metricsCollector.increment('organization.bulk_create_failed', { userId: requestingUserId });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Get organization analytics
     * GET /api/v1/organizations/:id/analytics
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    getOrganizationAnalytics = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;

        if (!req.user.isAdmin && !req.user.permissions.includes('view_organization_analytics')) {
            return next(new AppError('Access denied', 403));
        }

        await analyticsLimiter(req, res, () => { });

        const cacheKey = `organization_analytics:${id}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('organization.analytics_cache_hit', { id });
                return ApiResponse.success(res, cached);
            }

            const organization = await Organization.findById(id)
                .select('analytics')
                .lean();

            if (!organization || organization.status === 'deleted') {
                return next(new AppError('Organization not found', 404));
            }

            const analytics = await this.computeAnalytics(organization.analytics);
            await cacheService.set(cacheKey, analytics, 300, ['organization_analytics:' + id]);

            metricsCollector.increment('organization.analytics_fetched', { id });
            metricsCollector.timing('organization.analytics_time', Date.now() - startTime);

            return ApiResponse.success(res, { data: analytics });
        } catch (error) {
            logger.error(`Failed to fetch analytics for organization ${id}:`, { error: error.message });
            metricsCollector.increment('organization.analytics_failed', { id });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        }
    });

    /**
     * Search organizations
     * GET /api/v1/organizations/search
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    searchOrganizations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const requestingUserId = req.user.id;
        const {
            query,
            page = 1,
            limit = 20,
            type,
            sortBy = 'relevance',
        } = req.query;

        await searchLimiter(req, res, () => { });

        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
        const from = (pageNum - 1) * limitNum;

        const cacheKey = `organization_search:${requestingUserId}:${JSON.stringify({ query, page, limit, type, sortBy })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('organization.search_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const esQuery = this.buildElasticsearchQuery({ query, type });
            const sortOption = this.buildSearchSortOption(sortBy);

            const esResponse = await elasticsearchClient.search({
                index: 'organizations',
                from,
                size: limitNum,
                body: {
                    query: esQuery,
                    sort: sortOption,
                },
            });

            const organizationIds = esResponse.hits.hits.map(hit => hit._id);
            const organizations = await Organization.find({ _id: { $in: organizationIds }, status: { $ne: 'deleted' } })
                .read('secondaryPreferred')
                .select('-__v')
                .lean({ virtuals: true });

            const totalCount = esResponse.hits.total.value;
            const result = {
                organizations,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages: Math.ceil(totalCount / limitNum),
                    hasNext: pageNum < Math.ceil(totalCount / limitNum),
                    hasPrev: pageNum > 1,
                },
            };

            await cacheService.set(cacheKey, result, 300, ['organization_search']);
            metricsCollector.increment('organization.search', { count: organizations.length });
            metricsCollector.timing('organization.search_time', Date.now() - startTime);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Organization search failed:`, { error: error.message });
            metricsCollector.increment('organization.search_failed');
            throw error instanceof AppError ? error : new AppError('Search failed', 500);
        }
    });

    /**
     * Export organization data
     * GET /api/v1/organizations/export
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    exportOrganizations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const requestingUserId = req.user.id;
        const { format = 'json' } = req.query;

        if (!req.user.isAdmin && !req.user.permissions.includes('export_organization')) {
            return next(new AppError('Access denied', 403));
        }

        try {
            const organizations = await Organization.find({ status: { $ne: 'deleted' } })
                .read('secondaryPreferred')
                .select('-__v')
                .lean();

            const exportData = this.formatExportData(organizations, format);
            const fileName = `organizations_${requestingUserId}_${Date.now()}.${format}`;
            const s3Key = `exports/organizations/${requestingUserId}/${fileName}`;

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

            metricsCollector.increment('organization.exported', { userId: requestingUserId, format });
            metricsCollector.timing('organization.export_time', Date.now() - startTime);
            eventEmitter.emit('organization.exported', { userId: requestingUserId, fileName, format });

            return ApiResponse.success(res, {
                message: 'Organizations exported successfully',
                data: { downloadUrl, fileName },
            });
        } catch (error) {
            logger.error(`Organization export failed for user ${requestingUserId}:`, { error: error.message });
            metricsCollector.increment('organization.export_failed', { userId: requestingUserId });
            throw error instanceof AppError ? error : new AppError('Export failed', 500);
        }
    });

    /**
     * Import organizations
     * POST /api/v1/organizations/import
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    importOrganizations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const requestingUserId = req.user.id;
        const { organizations, source } = req.body;

        if (!req.user.isAdmin && !req.user.permissions.includes('create_organization')) {
            return next(new AppError('Access denied', 403));
        }

        await bulkOperationsLimiter(req, res, () => { });

        if (!Array.isArray(organizations) || organizations.length === 0) {
            return next(new AppError('No organizations data provided', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const validatedOrganizations = [];
            for (const orgData of organizations) {
                const validation = validateOrganization(orgData);
                if (!validation.valid) {
                    throw new AppError(`Validation failed for organization: ${validation.message}`, 400);
                }

                const sanitizedData = sanitizeInput(orgData);
                sanitizedData.name = sanitizedData.name?.trim();
                sanitizedData.description = sanitizedData.description ? sanitizeHtml(sanitizedData.description) : null;

                const existingOrg = await Organization.findOne({ name: sanitizedData.name, status: { $ne: 'deleted' } }).session(session);
                if (existingOrg) {
                    throw new AppError(`Organization with name ${sanitizedData.name} already exists`, 409);
                }

                validatedOrganizations.push({
                    ...sanitizedData,
                    createdBy: requestingUserId,
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
                    status: 'pending',
                    privacy: {
                        isPublic: false,
                        showDetails: true,
                        searchable: true,
                    },
                });
            }

            const insertedOrganizations = await Organization.insertMany(validatedOrganizations, { session });

            for (const org of insertedOrganizations) {
                this.processNewOrganizationAsync(org._id, requestingUserId).catch((err) => {
                    logger.error(`Async processing failed for organization ${org._id}:`, err);
                });
            }

            metricsCollector.increment('organization.imported', { userId: requestingUserId, count: insertedOrganizations.length });
            metricsCollector.timing('organization.import_time', Date.now() - startTime);
            eventEmitter.emit('organization.imported', { userId: requestingUserId, count: insertedOrganizations.length });

            await session.commitTransaction();
            return ApiResponse.success(res, {
                message: `Successfully imported ${insertedOrganizations.length} organizations`,
                data: { count: insertedOrganizations.length, organizationIds: insertedOrganizations.map(o => o._id) },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Organization import failed for user ${requestingUserId}:`, { error: error.message });
            metricsCollector.increment('organization.import_failed', { userId: requestingUserId });
            throw error instanceof AppError ? error : new AppError('Import failed', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Get organization recommendations
     * GET /api/v1/organizations/recommendations
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    getOrganizationRecommendations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const requestingUserId = req.user.id;
        const { limit = 10, type } = req.query;

        if (!req.user.isAdmin && !req.user.permissions.includes('view_organization')) {
            return next(new AppError('Access denied', 403));
        }

        try {
            const recommendations = await this.generateRecommendations(type, parseInt(limit));
            metricsCollector.increment('organization.recommendations_fetched', { userId: requestingUserId, count: recommendations.length });
            metricsCollector.timing('organization.recommendations_time', Date.now() - startTime);

            return ApiResponse.success(res, {
                message: 'Recommendations generated successfully',
                data: recommendations,
            });
        } catch (error) {
            logger.error(`Failed to fetch recommendations for user ${requestingUserId}:`, { error: error.message });
            metricsCollector.increment('organization.recommendations_failed', { userId: requestingUserId });
            throw error instanceof AppError ? error : new AppError('Failed to generate recommendations', 500);
        }
    });

    // Helper methods
    getAllowedUpdateFields() {
        return [
            'name',
            'description',
            'type',
            'address',
            'website',
            'contacts',
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

    buildOrganizationQuery({ status, name, type, search, tags }) {
        const query = { status: { $ne: 'deleted' } };
        if (status) query.status = status;
        if (name) query.name = { $regex: name, $options: 'i' };
        if (type) query.type = { $regex: type, $options: 'i' };
        if (search) query.$text = { $search: search };
        if (tags) query.tags = { $all: tags.split(',').map(t => t.trim()) };
        return query;
    }

    buildSortOption(sortBy) {
        const sortOptions = {
            recent: { createdAt: -1 },
            name: { name: 1 },
        };
        return sortOptions[sortBy] || sortOptions.recent;
    }

    buildElasticsearchQuery({ query, type }) {
        const boolQuery = {
            must: [],
            filter: [{ term: { searchable: true } }],
        };
        if (query) {
            boolQuery.must.push({
                multi_match: {
                    query,
                    fields: ['name^2', 'type', 'description'],
                    fuzziness: 'AUTO',
                },
            });
        }
        if (type) boolQuery.filter.push({ match: { type } });
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

    async indexForSearch(organization) {
        try {
            await elasticsearchClient.index({
                index: 'organizations',
                id: organization._id.toString(),
                body: {
                    name: organization.name,
                    type: organization.type,
                    status: organization.status,
                    searchable: organization.privacy.searchable,
                    createdAt: organization.createdAt,
                },
            });
            metricsCollector.increment('organization.indexed', { organizationId: organization._id });
        } catch (error) {
            logger.error(`Failed to index organization ${organization._id}:`, { error: error.message });
        }
    }

    async createBackup(organizationId, action, userId, options = {}) {
        try {
            const organization = await Organization.findById(organizationId).session(options.session);
            if (!organization) return;

            const backupKey = `backups/organizations/${organizationId}/${Date.now()}.json`;
            await s3Client.upload({
                Bucket: 'user-backups',
                Key: backupKey,
                Body: Buffer.from(JSON.stringify(organization)),
                ContentType: 'application/json',
            }).promise();

            logger.info(`Backup created for organization ${organizationId} by ${userId} for action ${action}`);
            metricsCollector.increment('organization.backup_created', { organizationId, action });
        } catch (error) {
            logger.error(`Backup failed for organization ${organizationId}:`, { error: error.message });
        }
    }

    async checkAccess(organizationId, userId) {
        const organization = await Organization.findById(organizationId).select('createdBy privacy');
        if (!organization) return false;
        return organization.createdBy === userId || organization.privacy.isPublic || req.user.isAdmin;
    }

    async processNewOrganizationAsync(organizationId, userId) {
        try {
            const organization = await Organization.findById(organizationId);
            if (!organization) return;

            await this.circuitBreaker.fire(async () => {
                await retry(() => this.verificationService.verifyOrganization({
                    organizationId,
                    name: organization.name,
                    type: organization.type,
                    website: organization.website,
                }), this.retryConfig);
            });

            await this.indexForSearch(organization);
            metricsCollector.increment('organization.async_processed', { organizationId });
        } catch (error) {
            logger.error(`Async processing failed for organization ${organizationId}:`, { error: error.message });
        }
    }

    async processExternalVerification(organizationId, userId) {
        try {
            const organization = await Organization.findById(organizationId);
            if (!organization) return;

            await this.circuitBreaker.fire(async () => {
                await retry(() => this.verificationService.verifyOrganization({
                    organizationId,
                    name: organization.name,
                    type: organization.type,
                    website: organization.website,
                }), this.retryConfig);
            });
            metricsCollector.increment('organization.verification_processed', { organizationId });
        } catch (error) {
            logger.error(`External verification failed for organization ${organizationId}:`, { error: error.message });
        }
    }

    async updateAnalytics(organization, viewerId) {
        try {
            organization.analytics.views.total += 1;
            if (!organization.analytics.views.byDate) organization.analytics.views.byDate = [];
            const today = moment().startOf('day').toDate();
            const viewEntry = organization.analytics.views.byDate.find(v => v.date.toDateString() === today.toDateString());
            if (viewEntry) {
                viewEntry.count += 1;
            } else {
                organization.analytics.views.byDate.push({ date: today, count: 1 });
            }
            await organization.save();
        } catch (error) {
            logger.error(`Failed to update analytics for organization ${organization._id}:`, { error: error.message });
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

    async generateRecommendations(type, limit) {
        const query = { status: { $ne: 'deleted' }, 'privacy.searchable': true };
        if (type) query.type = type;

        const recommendedOrganizations = await Organization.find(query)
            .limit(limit)
            .select('name type')
            .lean();

        return recommendedOrganizations;
    }

    formatExportData(organizations, format) {
        if (format === 'csv') {
            const headers = ['id', 'name', 'type', 'website', 'status'];
            const csvRows = [headers.join(',')];
            for (const org of organizations) {
                const row = [
                    org._id,
                    `"${org.name}"`,
                    org.type || '',
                    org.website || '',
                    org.status,
                ];
                csvRows.push(row.join(','));
            }
            return csvRows.join('\n');
        }
        return organizations; // Default JSON
    }
}

export default new OrganizationController();