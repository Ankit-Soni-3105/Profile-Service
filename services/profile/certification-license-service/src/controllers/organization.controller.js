import Organization from '../models/Organization.js';
import OrganizationService from '../services/OrganizationService.js';
import VerificationService from '../services/VerificationService.js';
import NotificationService from '../services/NotificationService.js';
import MediaService from '../services/MediaService.js';
import AnalyticsService from '../services/AnalyticsService.js';
import { validateOrganization, validateBulkOrganizations, validateMerge, validateSearch, sanitizeInput } from '../validations/organization.validation.js';
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
import AWS from 'aws-sdk';
import { v4 as uuidv4 } from 'uuid';

// Initialize AWS S3 for media and backups
const s3 = new AWS.S3({
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    region: process.env.AWS_REGION,
});

// Rate limiters for various endpoints
const createOrgLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // 10 creates per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_org_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const updateOrgLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 20, // 20 updates per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_org_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const verificationLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 5, // 5 verification requests per 30 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `verify_org_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const mediaUploadLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 10, // 10 media uploads per 10 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `media_org_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const bulkOperationLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 5, // 5 bulk operations per 30 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_org_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const searchLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 50, // 50 searches per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `search_org_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

class OrganizationController {
    constructor() {
        this.organizationService = OrganizationService;
        this.verificationService = VerificationService;
        this.notificationService = NotificationService;
        this.mediaService = MediaService;
        this.analyticsService = AnalyticsService;
    }

    /**
     * Create a new organization
     * POST /api/v1/organizations
     */
    createOrganization = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const orgData = req.body;
        const requestingUserId = req.user.id;

        await createOrgLimiter(req, res, () => { });

        const validation = validateOrganization(orgData);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        const sanitizedData = this.sanitizeInput(orgData);
        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const organization = await this.organizationService.createOrganization({
                ...sanitizedData,
                metadata: {
                    ...sanitizedData.metadata,
                    createdBy: {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                },
            }, { session });

            // Async processing for search indexing and analytics
            this.processOrganizationAsync(organization._id, requestingUserId, 'create')
                .catch((err) => logger.error(`Async processing failed for organization ${organization._id}:`, err));

            // Create backup
            await this.createBackup(organization._id, 'create', requestingUserId, { session });

            // Emit event
            eventEmitter.emit('organization.created', {
                organizationId: organization._id,
                userId: requestingUserId,
                name: organization.name,
            });

            metricsCollector.increment('organization.created', { userId: requestingUserId });
            await session.commitTransaction();
            logger.info(`Organization created: ${organization._id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Organization created successfully',
                data: {
                    id: organization._id,
                    name: organization.name,
                    status: organization.status,
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Organization creation failed for user ${requestingUserId}:`, error);
            metricsCollector.increment('organization.create_failed', { userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get organization by ID
     * GET /api/v1/organizations/:id
     */
    getOrganizationById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;
        const cacheKey = `organization:${id}:${requestingUserId}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('organization.cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const organization = await this.organizationService.getOrganizationById(id, requestingUserId);
            if (!organization) {
                return next(new AppError('Organization not found', 404));
            }

            // Increment analytics
            await this.analyticsService.incrementView(id, 'organization', requestingUserId);

            await cacheService.set(cacheKey, organization, 600);
            metricsCollector.increment('organization.fetched', { id, userId: requestingUserId });
            logger.info(`Fetched organization ${id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, { data: organization });
        } catch (error) {
            logger.error(`Failed to fetch organization ${id}:`, error);
            metricsCollector.increment('organization.fetch_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        }
    });

    /**
     * Update organization
     * PUT /api/v1/organizations/:id
     */
    updateOrganization = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const updates = req.body;
        const requestingUserId = req.user.id;

        await updateOrgLimiter(req, res, () => { });

        const validation = validateOrganization(updates, true);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const sanitizedUpdates = this.sanitizeUpdates(updates);
            const organization = await this.organizationService.updateOrganization(id, requestingUserId, sanitizedUpdates, {
                session,
                requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
            });

            // Async processing
            this.processOrganizationAsync(id, requestingUserId, 'update')
                .catch((err) => logger.error(`Async processing failed for organization ${id}:`, err));

            // Create backup
            await this.createBackup(id, 'update', requestingUserId, { session });

            // Clear cache
            await cacheService.deletePattern(`organization:${id}:*`);

            eventEmitter.emit('organization.updated', {
                organizationId: id,
                userId: requestingUserId,
                changes: Object.keys(sanitizedUpdates),
            });

            metricsCollector.increment('organization.updated', { id, userId: requestingUserId });
            await session.commitTransaction();
            logger.info(`Organization updated: ${id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Organization updated successfully',
                data: {
                    id,
                    name: organization.name,
                    status: organization.status,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Organization update failed for ${id}:`, error);
            metricsCollector.increment('organization.update_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete organization (soft or permanent)
     * DELETE /api/v1/organizations/:id
     */
    deleteOrganization = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const { permanent = false } = req.query;
        const requestingUserId = req.user.id;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            await this.organizationService.deleteOrganization(id, requestingUserId, permanent, { session });

            // Clear cache
            await cacheService.deletePattern(`organization:${id}:*`);

            eventEmitter.emit('organization.deleted', {
                organizationId: id,
                userId: requestingUserId,
                permanent,
            });

            metricsCollector.increment(permanent ? 'organization.permanently_deleted' : 'organization.soft_deleted', {
                id,
                userId: requestingUserId,
            });
            await session.commitTransaction();
            logger.info(`Organization ${id} deleted (permanent: ${permanent}) in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: `Organization ${permanent ? 'permanently' : 'soft'} deleted successfully`,
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Organization deletion failed for ${id}:`, error);
            metricsCollector.increment('organization.delete_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Verify organization
     * POST /api/v1/organizations/:id/verify
     */
    verifyOrganization = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;

        await verificationLimiter(req, res, () => { });

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const organization = await Organization.findById(id).session(session);
            if (!organization) {
                return next(new AppError('Organization not found', 404));
            }

            const verificationResult = await this.verificationService.verifyOrganization({
                organizationId: id,
                name: organization.name,
                userId: requestingUserId,
            });

            organization.verification = {
                status: verificationResult.status,
                verificationScore: verificationResult.confidence,
                verifiedBy: verificationResult.verifiedBy,
                verificationDate: new Date(),
            };

            await organization.save({ session });
            await cacheService.deletePattern(`organization:${id}:*`);

            // Notify user
            await this.notificationService.notifyUser(requestingUserId, {
                type: 'organization_verified',
                message: `Organization ${id} verification ${verificationResult.status}`,
                data: { organizationId: id, verificationStatus: verificationResult.status },
            });

            eventEmitter.emit('organization.verified', {
                organizationId: id,
                userId: requestingUserId,
                status: verificationResult.status,
            });

            metricsCollector.increment('organization.verified', { id, status: verificationResult.status });
            await session.commitTransaction();
            logger.info(`Organization ${id} verified in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Organization verification completed',
                data: organization.verification,
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Verification failed for organization ${id}:`, error);
            metricsCollector.increment('organization.verify_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Upload media for organization
     * POST /api/v1/organizations/:id/media
     */
    uploadMedia = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const files = req.files;
        const requestingUserId = req.user.id;

        await mediaUploadLimiter(req, res, () => { });

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const organization = await Organization.findById(id).session(session);
            if (!organization) {
                return next(new AppError('Organization not found', 404));
            }

            const validation = this.organizationService.validateMediaUpload(files, organization.media || []);
            if (!validation.valid) {
                return next(new AppError(validation.message, 422));
            }

            const mediaResults = await this.mediaService.uploadMedia({
                files,
                entityId: id,
                entityType: 'organization',
                userId: requestingUserId,
            }, { session });

            organization.media = organization.media || [];
            organization.media.push(...mediaResults);
            await organization.save({ session });

            await cacheService.deletePattern(`organization:${id}:*`);

            eventEmitter.emit('organization.media_uploaded', {
                organizationId: id,
                userId: requestingUserId,
                mediaCount: mediaResults.length,
            });

            metricsCollector.increment('organization.media_uploaded', { id, count: mediaResults.length });
            await session.commitTransaction();
            logger.info(`Uploaded ${mediaResults.length} media for organization ${id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Media uploaded successfully',
                data: { media: mediaResults },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Media upload failed for organization ${id}:`, error);
            metricsCollector.increment('organization.media_upload_failed', { id });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get organizations with filtering and pagination
     * GET /api/v1/organizations
     */
    getOrganizations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { page = 1, limit = 20, status, industry, search, sortBy = 'recent' } = req.query;
        const requestingUserId = req.user.id;
        const cacheKey = `organizations:${requestingUserId}:${JSON.stringify({ page, limit, status, industry, search, sortBy })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('organization.cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const query = this.buildOrgQuery({ status, industry, search });
            const sortOption = this.buildSortOption(sortBy);
            const pageNum = Math.max(1, parseInt(page));
            const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
            const skip = (pageNum - 1) * limitNum;

            const [organizations, totalCount] = await Promise.all([
                Organization.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select('name logo industry verification status createdAt analytics')
                    .lean(),
                Organization.countDocuments(query).cache({ ttl: 300, key: `org_count_${requestingUserId}` }),
            ]);

            const processedOrganizations = organizations.map((org) => ({
                ...org,
                isVerified: org.verification?.status === 'verified',
            }));

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                organizations: processedOrganizations,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages,
                    hasNext: pageNum < totalPages,
                    hasPrev: pageNum > 1,
                },
                filters: { status, industry, search, sortBy },
            };

            await cacheService.set(cacheKey, result, 300);
            metricsCollector.increment('organization.fetched', { count: organizations.length, userId: requestingUserId });
            logger.info(`Fetched ${organizations.length} organizations in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch organizations:`, error);
            metricsCollector.increment('organization.fetch_failed', { userId: requestingUserId });
            return next(this.handleError(error));
        }
    });

    /**
     * Search organizations using Elasticsearch/Algolia
     * GET /api/v1/organizations/search
     */
    searchOrganizations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { query, filters = {}, page = 1, limit = 20 } = req.body;
        const requestingUserId = req.user.id;

        await searchLimiter(req, res, () => { });

        const validation = validateSearch({ query, filters });
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        const cacheKey = `org_search:${requestingUserId}:${JSON.stringify({ query, filters, page, limit })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('organization.search_cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const result = await this.organizationService.searchOrganizations(query, filters, { page, limit });
            await cacheService.set(cacheKey, result, 300);

            metricsCollector.increment('organization.searched', { count: result.hits.length, userId: requestingUserId });
            logger.info(`Search returned ${result.hits.length} organizations in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Search completed successfully',
                data: result,
            });
        } catch (error) {
            logger.error(`Search failed for query ${query}:`, error);
            metricsCollector.increment('organization.search_failed', { userId: requestingUserId });
            return next(new AppError('Failed to search organizations', 500));
        }
    });

    /**
     * Get trending organizations
     * GET /api/v1/organizations/trending
     */
    getTrendingOrganizations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { timeframe = '30d', industry, limit = 20 } = req.query;
        const requestingUserId = req.user.id;
        const cacheKey = `trending_orgs:${requestingUserId}:${timeframe}:${industry || 'all'}:${limit}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('organization.trending_cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const organizations = await this.organizationService.getTrendingOrganizations(timeframe, industry, parseInt(limit));
            await cacheService.set(cacheKey, organizations, 300);

            metricsCollector.increment('organization.trending_fetched', { count: organizations.length, userId: requestingUserId });
            logger.info(`Fetched ${organizations.length} trending organizations in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Trending organizations fetched successfully',
                data: organizations,
            });
        } catch (error) {
            logger.error(`Failed to fetch trending organizations:`, error);
            metricsCollector.increment('organization.trending_fetch_failed', { userId: requestingUserId });
            return next(new AppError('Failed to fetch trending organizations', 500));
        }
    });

    /**
     * Bulk create organizations
     * POST /api/v1/organizations/bulk
     */
    bulkCreateOrganizations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const organizationsData = req.body.organizations;
        const requestingUserId = req.user.id;

        await bulkOperationLimiter(req, res, () => { });

        const validation = validateBulkOrganizations(organizationsData);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const sanitizedData = organizationsData.map((org) => this.sanitizeInput(org));
            const createdOrganizations = await Promise.all(
                sanitizedData.map((org) =>
                    this.organizationService.createOrganization({
                        ...org,
                        metadata: {
                            ...org.metadata,
                            createdBy: {
                                userId: requestingUserId,
                                ip: req.ip,
                                userAgent: req.get('User-Agent'),
                                timestamp: new Date(),
                            },
                        },
                    }, { session })
                )
            );

            // Async processing for each organization
            createdOrganizations.forEach((org) => {
                this.processOrganizationAsync(org._id, requestingUserId, 'create')
                    .catch((err) => logger.error(`Async processing failed for organization ${org._id}:`, err));
            });

            // Create backups
            await Promise.all(
                createdOrganizations.map((org) =>
                    this.createBackup(org._id, 'create', requestingUserId, { session })
                )
            );

            eventEmitter.emit('organization.bulk_created', {
                organizationIds: createdOrganizations.map((org) => org._id),
                userId: requestingUserId,
            });

            metricsCollector.increment('organization.bulk_created', { count: createdOrganizations.length, userId: requestingUserId });
            await session.commitTransaction();
            logger.info(`Bulk created ${createdOrganizations.length} organizations in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Organizations created successfully',
                data: createdOrganizations.map((org) => ({
                    id: org._id,
                    name: org.name,
                    status: org.status,
                })),
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk organization creation failed:`, error);
            metricsCollector.increment('organization.bulk_create_failed', { userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Bulk update organizations
     * PUT /api/v1/organizations/bulk
     */
    bulkUpdateOrganizations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const updates = req.body.updates;
        const requestingUserId = req.user.id;

        await bulkOperationLimiter(req, res, () => { });

        const validation = validateBulkOrganizations(updates);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const sanitizedUpdates = updates.map((update) => ({
                id: update.id,
                data: this.sanitizeUpdates(update.data),
            }));

            const updatedOrganizations = await Promise.all(
                sanitizedUpdates.map(({ id, data }) =>
                    this.organizationService.updateOrganization(id, requestingUserId, data, {
                        session,
                        requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                    })
                )
            );

            // Async processing and backups
            await Promise.all(
                updatedOrganizations.map((org) => {
                    this.processOrganizationAsync(org._id, requestingUserId, 'update')
                        .catch((err) => logger.error(`Async processing failed for organization ${org._id}:`, err));
                    return this.createBackup(org._id, 'update', requestingUserId, { session });
                })
            );

            // Clear cache
            await Promise.all(
                updatedOrganizations.map((org) => cacheService.deletePattern(`organization:${org._id}:*`))
            );

            eventEmitter.emit('organization.bulk_updated', {
                organizationIds: updatedOrganizations.map((org) => org._id),
                userId: requestingUserId,
            });

            metricsCollector.increment('organization.bulk_updated', { count: updatedOrganizations.length, userId: requestingUserId });
            await session.commitTransaction();
            logger.info(`Bulk updated ${updatedOrganizations.length} organizations in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Organizations updated successfully',
                data: updatedOrganizations.map((org) => ({
                    id: org._id,
                    name: org.name,
                    status: org.status,
                })),
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk organization update failed:`, error);
            metricsCollector.increment('organization.bulk_update_failed', { userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Merge organizations
     * POST /api/v1/organizations/merge
     */
    mergeOrganizations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { sourceIds, targetId } = req.body;
        const requestingUserId = req.user.id;

        await bulkOperationLimiter(req, res, () => { });

        const validation = validateMerge({ sourceIds, targetId });
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const mergedOrganization = await this.organizationService.mergeOrganizations(sourceIds, targetId, requestingUserId, { session });

            // Async processing
            this.processOrganizationAsync(targetId, requestingUserId, 'merge')
                .catch((err) => logger.error(`Async processing failed for merged organization ${targetId}:`, err));

            // Create backup
            await this.createBackup(targetId, 'merge', requestingUserId, { session });

            // Clear cache
            await Promise.all([
                ...sourceIds.map((id) => cacheService.deletePattern(`organization:${id}:*`)),
                cacheService.deletePattern(`organization:${targetId}:*`),
            ]);

            eventEmitter.emit('organization.merged', {
                sourceIds,
                targetId,
                userId: requestingUserId,
            });

            metricsCollector.increment('organization.merged', { userId: requestingUserId });
            await session.commitTransaction();
            logger.info(`Merged organizations into ${targetId} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Organizations merged successfully',
                data: {
                    id: mergedOrganization._id,
                    name: mergedOrganization.name,
                    status: mergedOrganization.status,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Organization merge failed:`, error);
            metricsCollector.increment('organization.merge_failed', { userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get organization analytics
     * GET /api/v1/organizations/:id/analytics
     */
    getOrganizationAnalytics = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const { timeframe = '30d' } = req.query;
        const requestingUserId = req.user.id;
        const cacheKey = `org_analytics:${id}:${timeframe}:${requestingUserId}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('organization.analytics_cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const analytics = await this.analyticsService.getOrganizationAnalytics(id, timeframe);
            await cacheService.set(cacheKey, analytics, 300);

            metricsCollector.increment('organization.analytics_fetched', { id, userId: requestingUserId });
            logger.info(`Fetched analytics for organization ${id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Organization analytics fetched successfully',
                data: analytics,
            });
        } catch (error) {
            logger.error(`Failed to fetch analytics for organization ${id}:`, error);
            metricsCollector.increment('organization.analytics_fetch_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        }
    });

    /**
     * Assign roles to organization members
     * POST /api/v1/organizations/:id/roles
     */
    assignRoles = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const { userId, roles } = req.body;
        const requestingUserId = req.user.id;

        if (!req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const organization = await this.organizationService.assignRoles(id, userId, roles, requestingUserId, { session });

            await cacheService.deletePattern(`organization:${id}:*`);

            eventEmitter.emit('organization.roles_assigned', {
                organizationId: id,
                userId,
                roles,
                assignedBy: requestingUserId,
            });

            metricsCollector.increment('organization.roles_assigned', { id, userId });
            await session.commitTransaction();
            logger.info(`Assigned roles to user ${userId} in organization ${id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Roles assigned successfully',
                data: { organizationId: id, userId, roles },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Role assignment failed for organization ${id}:`, error);
            metricsCollector.increment('organization.roles_assign_failed', { id, userId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get organization members
     * GET /api/v1/organizations/:id/members
     */
    getMembers = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const { page = 1, limit = 20 } = req.query;
        const requestingUserId = req.user.id;
        const cacheKey = `org_members:${id}:${page}:${limit}:${requestingUserId}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('organization.members_cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const pageNum = Math.max(1, parseInt(page));
            const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
            const skip = (pageNum - 1) * limitNum;

            const result = await this.organizationService.getMembers(id, { page: pageNum, limit: limitNum });
            await cacheService.set(cacheKey, result, 300);

            metricsCollector.increment('organization.members_fetched', { count: result.members.length, userId: requestingUserId });
            logger.info(`Fetched ${result.members.length} members for organization ${id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Members fetched successfully',
                data: result,
            });
        } catch (error) {
            logger.error(`Failed to fetch members for organization ${id}:`, error);
            metricsCollector.increment('organization.members_fetch_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        }
    });

    /**
     * Export organization data
     * GET /api/v1/organizations/:id/export
     */
    exportOrganization = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const { format = 'json' } = req.query;
        const requestingUserId = req.user.id;

        try {
            const organization = await Organization.findById(id)
                .select('name logo industry verification status analytics metadata')
                .lean();

            if (!organization) {
                return next(new AppError('Organization not found', 404));
            }

            let exportData;
            let contentType;
            let extension;

            switch (format.toLowerCase()) {
                case 'json':
                    exportData = JSON.stringify(organization, null, 2);
                    contentType = 'application/json';
                    extension = 'json';
                    break;
                case 'csv':
                    exportData = this.convertToCSV(organization);
                    contentType = 'text/csv';
                    extension = 'csv';
                    break;
                default:
                    return next(new AppError('Unsupported export format', 400));
            }

            const exportKey = `org_export_${id}_${uuidv4()}.${extension}`;
            await s3.upload({
                Bucket: process.env.S3_EXPORT_BUCKET,
                Key: exportKey,
                Body: exportData,
                ContentType: contentType,
                ServerSideEncryption: 'AES256',
            }).promise();

            const signedUrl = await s3.getSignedUrlPromise('getObject', {
                Bucket: process.env.S3_EXPORT_BUCKET,
                Key: exportKey,
                Expires: 3600, // 1 hour
            });

            metricsCollector.increment('organization.exported', { id, format, userId: requestingUserId });
            logger.info(`Exported organization ${id} as ${format} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Organization exported successfully',
                data: { url: signedUrl },
            });
        } catch (error) {
            logger.error(`Export failed for organization ${id}:`, error);
            metricsCollector.increment('organization.export_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        }
    });

    /**
     * Get organization statistics
     * GET /api/v1/organizations/:id/stats
     */
    getOrganizationStats = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;
        const cacheKey = `org_stats:${id}:${requestingUserId}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('organization.stats_cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const stats = await this.organizationService.getOrganizationStats(id);
            await cacheService.set(cacheKey, stats, 3600);

            metricsCollector.increment('organization.stats_fetched', { id, userId: requestingUserId });
            logger.info(`Fetched stats for organization ${id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Organization stats fetched successfully',
                data: stats,
            });
        } catch (error) {
            logger.error(`Failed to fetch stats for organization ${id}:`, error);
            metricsCollector.increment('organization.stats_fetch_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        }
    });

    /**
     * Archive organization
     * POST /api/v1/organizations/:id/archive
     */
    archiveOrganization = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const organization = await Organization.findById(id).session(session);
            if (!organization) {
                return next(new AppError('Organization not found', 404));
            }

            organization.status.isActive = false;
            organization.status.isArchived = true;
            organization.status.archivedAt = new Date();
            await organization.save({ session });

            await cacheService.deletePattern(`organization:${id}:*`);

            eventEmitter.emit('organization.archived', {
                organizationId: id,
                userId: requestingUserId,
            });

            metricsCollector.increment('organization.archived', { id, userId: requestingUserId });
            await session.commitTransaction();
            logger.info(`Organization ${id} archived in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Organization archived successfully',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Archiving failed for organization ${id}:`, error);
            metricsCollector.increment('organization.archive_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Restore organization
     * POST /api/v1/organizations/:id/restore
     */
    restoreOrganization = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const organization = await Organization.findById(id).session(session);
            if (!organization) {
                return next(new AppError('Organization not found', 404));
            }

            organization.status.isActive = true;
            organization.status.isArchived = false;
            organization.status.restoredAt = new Date();
            await organization.save({ session });

            await cacheService.deletePattern(`organization:${id}:*`);

            eventEmitter.emit('organization.restored', {
                organizationId: id,
                userId: requestingUserId,
            });

            metricsCollector.increment('organization.restored', { id, userId: requestingUserId });
            await session.commitTransaction();
            logger.info(`Organization ${id} restored in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Organization restored successfully',
                data: {
                    id,
                    name: organization.name,
                    status: organization.status,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Restoring failed for organization ${id}:`, error);
            metricsCollector.increment('organization.restore_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get organization audit logs
     * GET /api/v1/organizations/:id/audit
     */
    getAuditLogs = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const { page = 1, limit = 20, action } = req.query;
        const requestingUserId = req.user.id;
        const cacheKey = `org_audit:${id}:${page}:${limit}:${action || 'all'}:${requestingUserId}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('organization.audit_cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const pageNum = Math.max(1, parseInt(page));
            const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
            const skip = (pageNum - 1) * limitNum;

            const query = { organizationId: id };
            if (action) query.action = action;

            const [logs, totalCount] = await Promise.all([
                this.organizationService.getAuditLogs(id, { page: pageNum, limit: limitNum, action }),
                this.organizationService.countAuditLogs(id, action),
            ]);

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                logs,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages,
                },
            };

            await cacheService.set(cacheKey, result, 300);
            metricsCollector.increment('organization.audit_fetched', { count: logs.length, userId: requestingUserId });
            logger.info(`Fetched ${logs.length} audit logs for organization ${id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Audit logs fetched successfully',
                data: result,
            });
        } catch (error) {
            logger.error(`Failed to fetch audit logs for organization ${id}:`, error);
            metricsCollector.increment('organization.audit_fetch_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        }
    });

    /**
     * Create backup of organization
     * @param {string} organizationId - Organization ID
     * @param {string} action - Action type
     * @param {string} userId - User ID
     * @param {Object} options - Additional options
     */
    async createBackup(organizationId, action, userId, options = {}) {
        const startTime = Date.now();
        try {
            const organization = await Organization.findById(organizationId).lean();
            if (!organization) {
                throw new AppError('Organization not found', 404);
            }

            const backupKey = `org_backup_${organizationId}_${Date.now()}_${uuidv4()}`;
            await s3.upload({
                Bucket: process.env.S3_BACKUP_BUCKET,
                Key: backupKey,
                Body: JSON.stringify({
                    organization,
                    action,
                    userId,
                    timestamp: new Date(),
                }),
                ContentType: 'application/json',
                ServerSideEncryption: 'AES256',
            }).promise();

            metricsCollector.increment('organization.backup_created', { userId, action });
            logger.info(`Backup created for organization ${organizationId} (${action}) in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to create backup for organization ${organizationId}:`, error);
            metricsCollector.increment('organization.backup_failed', { userId });
            throw error;
        }
    }

    /**
     * Process organization asynchronously
     * @param {string} organizationId - Organization ID
     * @param {string} userId - User ID
     * @param {string} action - Action type
     */
    async processOrganizationAsync(organizationId, userId, action) {
        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const organization = await Organization.findById(organizationId).session(session);
            if (!organization) {
                throw new AppError('Organization not found', 404);
            }

            // Index for search
            await this.organizationService.indexForSearch(organization);

            // Update analytics
            await this.analyticsService.updateOrganizationAnalytics(organizationId, { session });

            // Update user stats
            await this.organizationService.updateUserStats(userId, { session });

            await session.commitTransaction();
            logger.info(`Async processing completed for organization ${organizationId} (${action})`);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Async processing failed for organization ${organizationId}:`, error);
            metricsCollector.increment('organization.async_processing_failed', { organizationId });
        } finally {
            session.endSession();
        }
    }

    /**
     * Handle errors
     * @param {Error} error - Error object
     * @returns {AppError}
     */
    handleError(error) {
        if (error.name === 'ValidationError') {
            return new AppError('Validation failed: ' + error.message, 400);
        }
        if (error.code === 11000) {
            return new AppError('Organization already exists', 409);
        }
        if (error.name === 'CastError') {
            return new AppError('Invalid organization ID', 400);
        }
        if (error.message.includes('timeout')) {
            return new AppError('Operation timed out', 504);
        }
        return new AppError('Operation failed', 500);
    }

    /**
     * Sanitize input data
     * @param {Object} data - Input data
     * @returns {Object} - Sanitized data
     */
    sanitizeInput(data) {
        return {
            ...sanitizeInput(data),
            name: sanitizeHtml(data.name || ''),
            description: sanitizeHtml(data.description || ''),
            industry: sanitizeHtml(data.industry || ''),
            logo: data.logo ? sanitizeHtml(data.logo) : undefined,
        };
    }

    /**
     * Sanitize updates
     * @param {Object} updates - Update data
     * @returns {Object} - Sanitized updates
     */
    sanitizeUpdates(updates) {
        const allowedFields = ['name', 'logo', 'industry', 'description', 'status', 'settings'];
        const sanitized = {};
        allowedFields.forEach((field) => {
            if (updates[field] !== undefined) {
                sanitized[field] = ['name', 'description', 'industry'].includes(field)
                    ? sanitizeHtml(updates[field])
                    : sanitizeInput(updates[field]);
            }
        });
        return sanitized;
    }

    /**
     * Build MongoDB query
     * @param {Object} params - Query parameters
     * @returns {Object} - MongoDB query
     */
    buildOrgQuery({ status, industry, search }) {
        const query = { 'status.isDeleted': false };
        if (status) query['status.workflow'] = status;
        if (industry) query.industry = industry;
        if (search) query.$text = { $search: search };
        return query;
    }

    /**
     * Build sort option
     * @param {string} sortBy - Sort criteria
     * @returns {Object} - Sort option
     */
    buildSortOption(sortBy) {
        const sortOptions = {
            recent: { createdAt: -1 },
            name: { name: 1 },
            popularity: { 'analytics.views': -1 },
        };
        return sortOptions[sortBy] || sortOptions.recent;
    }

    /**
     * Convert organization to CSV
     * @param {Object} organization - Organization data
     * @returns {string} - CSV string
     */
    convertToCSV(organization) {
        const headers = ['id', 'name', 'industry', 'verification_status', 'created_at'];
        const row = [
            organization._id,
            `"${organization.name.replace(/"/g, '""')}"`,
            `"${organization.industry?.replace(/"/g, '""') || ''}"`,
            organization.verification?.status || 'pending',
            organization.createdAt,
        ];
        return [headers.join(','), row.join(',')].join('\n');
    }
}

export default new OrganizationController();