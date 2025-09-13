import Project from '../models/Project.js';
import VerificationService from '../services/VerificationService.js';
import MediaService from '../services/MediaService.js';
import NotificationService from '../services/NotificationService.js';
import OrganizationService from '../services/OrganizationService.js';
import { validateProject, sanitizeInput } from '../validations/project.validation.js';
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
const createProjectLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15-minute window
    max: 10, // Allow 10 creates per user per IP
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_project_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
    legacyHeaders: false,
});

const updateProjectLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5-minute window
    max: 20, // Allow 20 updates
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_project_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const verificationLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30-minute window
    max: 5, // Strict limit for external API calls
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `verify_project_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const bulkOperationsLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // Hourly limit
    max: 3, // Conservative limit for bulk operations
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_project_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const mediaUploadLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000, // 10-minute window
    max: 10, // Limit uploads
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `media_project_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const searchLimiter = createRateLimiter({
    windowMs: 1 * 60 * 1000, // 1-minute window
    max: 50, // Allow frequent searches
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `search_project_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const analyticsLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5-minute window
    max: 20, // Moderate limit for analytics requests
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `analytics_project_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

class ProjectController {
    constructor() {
        this.verificationService = VerificationService;
        this.mediaService = MediaService;
        this.notificationService = NotificationService;
        this.organizationService = OrganizationService;
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
     * Create a new project
     * POST /api/v1/projects/:userId
     * Creates a project record with validation, async processing, and transaction support.
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    createProject = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const projectData = req.body;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied: Cannot create project for another user', 403));
        }

        await createProjectLimiter(req, res, () => { });

        const validation = validateProject(projectData);
        if (!validation.valid) {
            metricsCollector.increment('project.validation_failed', { userId, errors: validation.errors.length });
            return next(new AppError(`Validation failed: ${validation.message}`, 400));
        }

        const sanitizedData = sanitizeInput(projectData);
        sanitizedData.title = sanitizedData.title?.trim();
        sanitizedData.startDate = new Date(sanitizedData.startDate) || null;
        sanitizedData.endDate = sanitizedData.endDate ? new Date(sanitizedData.endDate) : null;

        const userProjectCount = await Project.countDocuments({
            userId,
            'status': { $ne: 'deleted' },
        }).cache({ ttl: 300, key: `user_project_count_${userId}` });

        const limits = this.getUserLimits(req.user.accountType);
        if (userProjectCount >= limits.maxProjects) {
            metricsCollector.increment('project.limit_exceeded', { userId });
            return next(new AppError(`Project limit reached (${limits.maxProjects})`, 403));
        }

        if (sanitizedData.organizationId) {
            const organization = await this.organizationService.getOrganizationById(sanitizedData.organizationId);
            if (!organization || organization.status !== 'active') {
                return next(new AppError('Invalid or inactive organization association', 400));
            }
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const project = await Project.create([{
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

            this.processNewProjectAsync(project[0]._id, requestingUserId)
                .catch((err) => {
                    logger.error(`Async processing failed for project ${project[0]._id}:`, err);
                    metricsCollector.increment('project.async_processing_failed', { projectId: project[0]._id });
                });

            metricsCollector.increment('project.created', {
                userId,
                title: project[0].title,
                organizationAssociated: !!project[0].organizationId,
                accountType: req.user.accountType,
            });
            metricsCollector.timing('project.create_time', Date.now() - startTime);

            eventEmitter.emit('project.created', {
                projectId: project[0]._id,
                userId,
                organizationId: project[0].organizationId,
                title: project[0].title,
                category: project[0].category,
            });

            if (project[0].settings?.autoBackup) {
                await this.createBackup(project[0]._id, 'create', requestingUserId, { session });
            }

            await session.commitTransaction();
            logger.info(`Project created successfully: ${project[0]._id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Project created successfully',
                data: {
                    id: project[0]._id,
                    userId: project[0].userId,
                    title: project[0].title,
                    status: project[0].status,
                    createdAt: project[0].createdAt,
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Project creation failed for user ${userId}:`, { error: error.message });
            metricsCollector.increment('project.create_failed', { userId });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Get user's projects with filtering and pagination
     * GET /api/v1/projects/:userId
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    getProjects = catchAsync(async (req, res, next) => {
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
            organizationId,
            startDate,
            endDate,
            search,
            sortBy = 'recent',
            tags,
        } = req.query;

        await searchLimiter(req, res, () => { });

        const query = this.buildProjectQuery({ userId, status, title, category, organizationId, startDate, endDate, search, tags });
        const sortOption = this.buildSortOption(sortBy);
        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
        const skip = (pageNum - 1) * limitNum;

        const cacheKey = `projects:${userId}:${JSON.stringify({ page, limit, status, title, category, organizationId, sortBy, tags })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('project.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const [projects, totalCount] = await Promise.all([
                Project.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select('-__v')
                    .populate('organizationId', 'name type')
                    .lean({ virtuals: true }),
                Project.countDocuments(query).cache({ ttl: 300 }),
            ]);

            const result = {
                projects,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages: Math.ceil(totalCount / limitNum),
                    hasNext: pageNum < Math.ceil(totalCount / limitNum),
                    hasPrev: pageNum > 1,
                },
            };

            await cacheService.set(cacheKey, result, 300, ['projects:user:' + userId]);
            metricsCollector.increment('project.fetched', { userId, count: projects.length });
            metricsCollector.timing('project.get_list_time', Date.now() - startTime);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch projects for user ${userId}:`, { error: error.message });
            metricsCollector.increment('project.fetch_failed', { userId });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        }
    });

    /**
     * Get single project by ID
     * GET /api/v1/projects/:userId/:id
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    getProjectById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            const hasConnectionAccess = await this.checkConnectionAccess(userId, requestingUserId);
            if (!hasConnectionAccess) {
                return next(new AppError('Access denied', 403));
            }
        }

        const cacheKey = `project:${id}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('project.cache_hit', { id });
                return ApiResponse.success(res, cached);
            }

            const project = await Project.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('-__v')
                .populate('organizationId', 'name type')
                .lean({ virtuals: true });

            if (!project) {
                return next(new AppError('Project not found', 404));
            }

            await this.updateAnalytics(project, requestingUserId);
            await cacheService.set(cacheKey, project, 600, ['projects:id:' + id]);
            metricsCollector.increment('project.viewed', { id, userId });
            metricsCollector.timing('project.get_by_id_time', Date.now() - startTime);

            return ApiResponse.success(res, { data: project });
        } catch (error) {
            logger.error(`Failed to fetch project ${id}:`, { error: error.message });
            metricsCollector.increment('project.view_failed', { id });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        }
    });

    /**
     * Update project
     * PUT /api/v1/projects/:userId/:id
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    updateProject = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const updates = req.body;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        await updateProjectLimiter(req, res, () => { });

        const sanitizedUpdates = this.sanitizeUpdates(updates, this.getAllowedUpdateFields());
        if (Object.keys(sanitizedUpdates).length === 0) {
            return next(new AppError('No valid update fields provided', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const project = await Project.findOne({ _id: id, userId }).session(session);
            if (!project) {
                return next(new AppError('Project not found', 404));
            }

            if (sanitizedUpdates.title || sanitizedUpdates.category) {
                project.versions = project.versions || [];
                project.versions.push({
                    versionNumber: project.metadata.version + 1,
                    title: sanitizedUpdates.title || project.title,
                    category: sanitizedUpdates.category || project.category,
                    changeType: 'edit',
                    timestamp: new Date(),
                });
            }

            if (sanitizedUpdates.organizationId) {
                const organization = await this.organizationService.getOrganizationById(sanitizedUpdates.organizationId, { session });
                if (!organization || organization.status !== 'active') {
                    return next(new AppError('Invalid or inactive organization association', 400));
                }
            }

            Object.assign(project, sanitizedUpdates);
            project.metadata.version += 1;
            project.metadata.updateCount += 1;
            project.metadata.lastModifiedBy = {
                userId: requestingUserId,
                timestamp: new Date(),
                changes: Object.keys(sanitizedUpdates),
            };

            if (['title', 'category', 'organizationId'].some(field => sanitizedUpdates[field])) {
                project.verification.status = 'pending';
                this.processExternalVerification(project._id, userId).catch((err) => {
                    logger.error(`Re-verification failed for project ${project._id}:`, err);
                });
            }

            await project.save({ session });
            await this.indexForSearch(project);
            await cacheService.deletePattern(`project:${id}:*`);

            metricsCollector.increment('project.updated', { id });
            metricsCollector.timing('project.update_time', Date.now() - startTime);
            eventEmitter.emit('project.updated', { projectId: id, changes: Object.keys(sanitizedUpdates) });

            await session.commitTransaction();
            return ApiResponse.success(res, {
                message: 'Project updated successfully',
                data: { id: project._id, title: project.title, status: project.status },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Project update failed for ${id}:`, { error: error.message });
            metricsCollector.increment('project.update_failed', { id });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete project
     * DELETE /api/v1/projects/:userId/:id
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    deleteProject = catchAsync(async (req, res, next) => {
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

            const project = await Project.findOne({ _id: id, userId }).session(session);
            if (!project) {
                return next(new AppError('Project not found', 404));
            }

            if (permanent === 'true') {
                await Project.findByIdAndDelete(id, { session });
                await this.mediaService.deleteAllMedia(id, 'project', { session });
            } else {
                project.status = 'deleted';
                project.privacy.isPublic = false;
                project.privacy.searchable = false;
                await project.save({ session });
            }

            await cacheService.deletePattern(`project:${id}:*`);
            metricsCollector.increment(`project.${permanent ? 'permanently_deleted' : 'soft_deleted'}`, { id });
            metricsCollector.timing('project.delete_time', Date.now() - startTime);
            eventEmitter.emit('project.deleted', { projectId: id, permanent });

            await session.commitTransaction();
            return ApiResponse.success(res, {
                message: permanent === 'true' ? 'Project permanently deleted' : 'Project soft deleted',
                data: { id },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Project deletion failed for ${id}:`, { error: error.message });
            metricsCollector.increment('project.delete_failed', { id });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Verify project
     * POST /api/v1/projects/:userId/:id/verify
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    verifyProject = catchAsync(async (req, res, next) => {
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

            const project = await Project.findOne({ _id: id, userId }).session(session);
            if (!project) {
                return next(new AppError('Project not found', 404));
            }

            const verificationResult = await this.circuitBreaker.fire(async () => {
                return await retry(() => this.verificationService.verifyProject({
                    projectId: project._id,
                    userId,
                    title: project.title,
                    category: project.category,
                    organizationId: project.organizationId,
                }), this.retryConfig);
            });

            project.verification = {
                status: verificationResult.success ? 'verified' : 'failed',
                confidence: verificationResult.confidence || 0,
                verifiedBy: verificationResult.verifiedBy || 'external_api',
                verifiedAt: new Date(),
                details: verificationResult.details || [],
            };
            await project.save({ session });

            await this.indexForSearch(project);
            await cacheService.deletePattern(`project:${id}:*`);

            eventEmitter.emit('project.verified', {
                projectId: id,
                userId,
                verificationStatus: verificationResult.success ? 'verified' : 'failed',
            });

            await session.commitTransaction();
            metricsCollector.increment('project.verified', { id, status: verificationResult.status });
            metricsCollector.timing('project.verify_time', Date.now() - startTime);

            return ApiResponse.success(res, {
                message: `Project ${verificationResult.success ? 'verified' : 'verification failed'}`,
                data: { id: project._id, verificationStatus: project.verification.status },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Verification failed for project ${id}:`, { error: error.message });
            metricsCollector.increment('project.verify_failed', { id });
            throw error instanceof AppError ? error : new AppError('Failed to verify project', 424);
        } finally {
            session.endSession();
        }
    });

    /**
     * Upload project media
     * POST /api/v1/projects/:userId/:id/media
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    uploadProjectMedia = catchAsync(async (req, res, next) => {
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

            const project = await Project.findOne({ _id: id, userId }).session(session);
            if (!project) {
                return next(new AppError('Project not found', 404));
            }

            const mediaResults = await this.mediaService.uploadMedia({
                files,
                entityId: project._id,
                entityType: 'project',
                userId: requestingUserId,
                category: 'project_media',
            }, { session });

            const scanResults = await this.mediaService.scanMedia(mediaResults);
            const infected = scanResults.filter(r => r.infected);
            if (infected.length > 0) {
                await this.mediaService.deleteMedia(infected.map(m => m.id), { session });
                return next(new AppError(`Media upload failed: ${infected.length} infected files detected`, 422));
            }

            project.media = [...(project.media || []), ...mediaResults];
            await project.save({ session });

            await cacheService.deletePattern(`project:${id}:*`);
            metricsCollector.increment('project.media_uploaded', { id, mediaCount: files.length });
            metricsCollector.timing('project.media_upload_time', Date.now() - startTime);
            eventEmitter.emit('project.media_uploaded', { projectId: id, mediaCount: files.length });

            await session.commitTransaction();
            return ApiResponse.success(res, {
                message: 'Media uploaded successfully',
                data: { id: project._id, mediaCount: mediaResults.length },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Media upload failed for project ${id}:`, { error: error.message });
            metricsCollector.increment('project.media_upload_failed', { id });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Bulk create projects
     * POST /api/v1/projects/:userId/bulk
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    bulkCreateProjects = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const projectsData = req.body.projects || [];

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        await bulkOperationsLimiter(req, res, () => { });

        if (!Array.isArray(projectsData) || projectsData.length === 0) {
            return next(new AppError('No projects data provided', 400));
        }

        if (projectsData.length > 50) {
            return next(new AppError('Cannot process more than 50 projects at once', 400));
        }

        const userProjectCount = await Project.countDocuments({
            userId,
            'status': { $ne: 'deleted' },
        }).cache({ ttl: 300, key: `user_project_count_${userId}` });

        const limits = this.getUserLimits(req.user.accountType);
        if (userProjectCount + projectsData.length > limits.maxProjects) {
            return next(new AppError(`Project limit would be exceeded (${limits.maxProjects})`, 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const validatedProjects = [];
            for (const projectData of projectsData) {
                const validation = validateProject(projectData);
                if (!validation.valid) {
                    throw new AppError(`Validation failed for project: ${validation.message}`, 400);
                }

                const sanitizedData = sanitizeInput(projectData);
                sanitizedData.title = sanitizedData.title?.trim();
                sanitizedData.startDate = new Date(sanitizedData.startDate) || null;
                sanitizedData.endDate = sanitizedData.endDate ? new Date(sanitizedData.endDate) : null;

                if (sanitizedData.organizationId) {
                    const organization = await this.organizationService.getOrganizationById(sanitizedData.organizationId, { session });
                    if (!organization || organization.status !== 'active') {
                        throw new AppError(`Invalid organization association for project: ${sanitizedData.title}`, 400);
                    }
                }

                validatedProjects.push({
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

            const projects = await Project.insertMany(validatedProjects, { session });

            for (const project of projects) {
                this.processNewProjectAsync(project._id, userId).catch((err) => {
                    logger.error(`Async processing failed for project ${project._id}:`, err);
                });
            }

            metricsCollector.increment('project.bulk_created', { userId, count: projects.length });
            metricsCollector.timing('project.bulk_create_time', Date.now() - startTime);
            eventEmitter.emit('project.bulk_created', { userId, count: projects.length });

            await session.commitTransaction();
            return ApiResponse.success(res, {
                message: `Successfully created ${projects.length} projects`,
                data: { count: projects.length, projectIds: projects.map(p => p._id) },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk project creation failed for user ${userId}:`, { error: error.message });
            metricsCollector.increment('project.bulk_create_failed', { userId });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Get project analytics
     * GET /api/v1/projects/:userId/:id/analytics
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    getProjectAnalytics = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        await analyticsLimiter(req, res, () => { });

        const cacheKey = `project_analytics:${id}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('project.analytics_cache_hit', { id });
                return ApiResponse.success(res, cached);
            }

            const project = await Project.findOne({ _id: id, userId })
                .select('analytics')
                .lean();

            if (!project) {
                return next(new AppError('Project not found', 404));
            }

            const analytics = await this.computeAnalytics(project.analytics);
            await cacheService.set(cacheKey, analytics, 300, ['project_analytics:' + id]);

            metricsCollector.increment('project.analytics_fetched', { id });
            metricsCollector.timing('project.analytics_time', Date.now() - startTime);

            return ApiResponse.success(res, { data: analytics });
        } catch (error) {
            logger.error(`Failed to fetch analytics for project ${id}:`, { error: error.message });
            metricsCollector.increment('project.analytics_failed', { id });
            throw error instanceof AppError ? error : new AppError('Internal server error', 500);
        }
    });

    /**
     * Search projects
     * GET /api/v1/projects/search
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    searchProjects = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const requestingUserId = req.user.id;
        const {
            query,
            page = 1,
            limit = 20,
            category,
            organizationId,
            sortBy = 'relevance',
        } = req.query;

        await searchLimiter(req, res, () => { });

        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
        const from = (pageNum - 1) * limitNum;

        const cacheKey = `project_search:${requestingUserId}:${JSON.stringify({ query, page, limit, category, organizationId, sortBy })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('project.search_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const esQuery = this.buildElasticsearchQuery({ query, category, organizationId });
            const sortOption = this.buildSearchSortOption(sortBy);

            const esResponse = await elasticsearchClient.search({
                index: 'projects',
                from,
                size: limitNum,
                body: {
                    query: esQuery,
                    sort: sortOption,
                },
            });

            const projectIds = esResponse.hits.hits.map(hit => hit._id);
            const projects = await Project.find({ _id: { $in: projectIds } })
                .read('secondaryPreferred')
                .select('-__v')
                .populate('organizationId', 'name type')
                .lean({ virtuals: true });

            const totalCount = esResponse.hits.total.value;
            const result = {
                projects,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages: Math.ceil(totalCount / limitNum),
                    hasNext: pageNum < Math.ceil(totalCount / limitNum),
                    hasPrev: pageNum > 1,
                },
            };

            await cacheService.set(cacheKey, result, 300, ['project_search']);
            metricsCollector.increment('project.search', { count: projects.length });
            metricsCollector.timing('project.search_time', Date.now() - startTime);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Project search failed:`, { error: error.message });
            metricsCollector.increment('project.search_failed');
            throw error instanceof AppError ? error : new AppError('Search failed', 500);
        }
    });

    /**
     * Export project data
     * GET /api/v1/projects/:userId/export
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    exportProjects = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { format = 'json' } = req.query;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        try {
            const projects = await Project.find({ userId, status: { $ne: 'deleted' } })
                .read('secondaryPreferred')
                .select('-__v')
                .populate('organizationId', 'name type')
                .lean();

            const exportData = this.formatExportData(projects, format);
            const fileName = `projects_${userId}_${Date.now()}.${format}`;
            const s3Key = `exports/projects/${userId}/${fileName}`;

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

            metricsCollector.increment('project.exported', { userId, format });
            metricsCollector.timing('project.export_time', Date.now() - startTime);
            eventEmitter.emit('project.exported', { userId, fileName, format });

            return ApiResponse.success(res, {
                message: 'Projects exported successfully',
                data: { downloadUrl, fileName },
            });
        } catch (error) {
            logger.error(`Project export failed for user ${userId}:`, { error: error.message });
            metricsCollector.increment('project.export_failed', { userId });
            throw error instanceof AppError ? error : new AppError('Export failed', 500);
        }
    });

    /**
     * Import projects
     * POST /api/v1/projects/:userId/import
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    importProjects = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { projects, source } = req.body;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        await bulkOperationsLimiter(req, res, () => { });

        if (!Array.isArray(projects) || projects.length === 0) {
            return next(new AppError('No projects data provided', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const validatedProjects = [];
            for (const projectData of projects) {
                const validation = validateProject(projectData);
                if (!validation.valid) {
                    throw new AppError(`Validation failed for project: ${validation.message}`, 400);
                }

                const sanitizedData = sanitizeInput(projectData);
                validatedProjects.push({
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

            const insertedProjects = await Project.insertMany(validatedProjects, { session });

            for (const project of insertedProjects) {
                this.processNewProjectAsync(project._id, userId).catch((err) => {
                    logger.error(`Async processing failed for project ${project._id}:`, err);
                });
            }

            metricsCollector.increment('project.imported', { userId, count: insertedProjects.length });
            metricsCollector.timing('project.import_time', Date.now() - startTime);
            eventEmitter.emit('project.imported', { userId, count: insertedProjects.length });

            await session.commitTransaction();
            return ApiResponse.success(res, {
                message: `Successfully imported ${insertedProjects.length} projects`,
                data: { count: insertedProjects.length, projectIds: insertedProjects.map(p => p._id) },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Project import failed for user ${userId}:`, { error: error.message });
            metricsCollector.increment('project.import_failed', { userId });
            throw error instanceof AppError ? error : new AppError('Import failed', 500);
        } finally {
            session.endSession();
        }
    });

    /**
     * Get project recommendations
     * GET /api/v1/projects/:userId/recommendations
     * @param {Object} req - Request object
     * @param {Object} res - Response object
     * @param {Function} next - Next middleware function
     * @returns {Promise<void>}
     */
    getProjectRecommendations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { limit = 10 } = req.query;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        try {
            const userProjects = await Project.find({ userId, status: { $ne: 'deleted' } })
                .select('category organizationId')
                .lean();

            const recommendations = await this.generateRecommendations(userProjects, parseInt(limit));
            metricsCollector.increment('project.recommendations_fetched', { userId, count: recommendations.length });
            metricsCollector.timing('project.recommendations_time', Date.now() - startTime);

            return ApiResponse.success(res, {
                message: 'Recommendations generated successfully',
                data: recommendations,
            });
        } catch (error) {
            logger.error(`Failed to fetch recommendations for user ${userId}:`, { error: error.message });
            metricsCollector.increment('project.recommendations_failed', { userId });
            throw error instanceof AppError ? error : new AppError('Failed to generate recommendations', 500);
        }
    });

    // Helper methods
    getUserLimits(accountType) {
        const limits = {
            free: { maxProjects: 10, maxMedia: 5 },
            premium: { maxProjects: 50, maxMedia: 20 },
            enterprise: { maxProjects: 200, maxMedia: 100 },
        };
        return limits[accountType] || limits.free;
    }

    buildProjectQuery({ userId, status, title, category, organizationId, startDate, endDate, search, tags }) {
        const query = { userId, status: { $ne: 'deleted' } };
        if (status) query.status = status;
        if (title) query.title = { $regex: title, $options: 'i' };
        if (category) query.category = { $regex: category, $options: 'i' };
        if (organizationId) query.organizationId = mongoose.Types.ObjectId(organizationId);
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

    buildElasticsearchQuery({ query, category, organizationId }) {
        const boolQuery = {
            must: [],
            filter: [{ term: { searchable: true } }],
        };
        if (query) {
            boolQuery.must.push({
                multi_match: {
                    query,
                    fields: ['title^2', 'category', 'description'],
                    fuzziness: 'AUTO',
                },
            });
        }
        if (category) boolQuery.filter.push({ match: { category } });
        if (organizationId) boolQuery.filter.push({ term: { organizationId } });
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

    async indexForSearch(project) {
        try {
            await elasticsearchClient.index({
                index: 'projects',
                id: project._id.toString(),
                body: {
                    userId: project.userId,
                    title: project.title,
                    category: project.category,
                    organizationId: project.organizationId,
                    status: project.status,
                    searchable: project.privacy.searchable,
                    createdAt: project.createdAt,
                },
            });
            metricsCollector.increment('project.indexed', { projectId: project._id });
        } catch (error) {
            logger.error(`Failed to index project ${project._id}:`, { error: error.message });
        }
    }

    async createBackup(projectId, action, userId, options = {}) {
        try {
            const project = await Project.findById(projectId).session(options.session);
            if (!project) return;

            const backupKey = `backups/projects/${projectId}/${Date.now()}.json`;
            await s3Client.upload({
                Bucket: 'user-backups',
                Key: backupKey,
                Body: Buffer.from(JSON.stringify(project)),
                ContentType: 'application/json',
            }).promise();

            logger.info(`Backup created for project ${projectId} by ${userId} for action ${action}`);
            metricsCollector.increment('project.backup_created', { projectId, action });
        } catch (error) {
            logger.error(`Backup failed for project ${projectId}:`, { error: error.message });
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
            'startDate',
            'endDate',
            'organizationId',
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

    async processNewProjectAsync(projectId, userId) {
        try {
            const project = await Project.findById(projectId);
            if (!project) return;

            await this.circuitBreaker.fire(async () => {
                await retry(() => this.verificationService.verifyProject({
                    projectId,
                    userId,
                    title: project.title,
                    category: project.category,
                    organizationId: project.organizationId,
                }), this.retryConfig);
            });

            await this.indexForSearch(project);
            metricsCollector.increment('project.async_processed', { projectId });
        } catch (error) {
            logger.error(`Async processing failed for project ${projectId}:`, { error: error.message });
        }
    }

    async processExternalVerification(projectId, userId) {
        try {
            const project = await Project.findById(projectId);
            if (!project) return;

            await this.circuitBreaker.fire(async () => {
                await retry(() => this.verificationService.verifyProject({
                    projectId,
                    userId,
                    title: project.title,
                    category: project.category,
                    organizationId: project.organizationId,
                }), this.retryConfig);
            });
            metricsCollector.increment('project.verification_processed', { projectId });
        } catch (error) {
            logger.error(`External verification failed for project ${projectId}:`, { error: error.message });
        }
    }

    async updateAnalytics(project, viewerId) {
        try {
            project.analytics.views.total += 1;
            if (!project.analytics.views.byDate) project.analytics.views.byDate = [];
            const today = moment().startOf('day').toDate();
            const viewEntry = project.analytics.views.byDate.find(v => v.date.toDateString() === today.toDateString());
            if (viewEntry) {
                viewEntry.count += 1;
            } else {
                project.analytics.views.byDate.push({ date: today, count: 1 });
            }
            await project.save();
        } catch (error) {
            logger.error(`Failed to update analytics for project ${project._id}:`, { error: error.message });
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

    async generateRecommendations(userProjects, limit) {
        const organizationIds = userProjects.map(p => p.organizationId).filter(Boolean);
        const categories = userProjects.map(p => p.category).filter(Boolean);

        const recommendedProjects = await Project.find({
            $or: [
                { organizationId: { $in: organizationIds } },
                { category: { $in: categories } },
            ],
            status: { $ne: 'deleted' },
            'privacy.searchable': true,
        })
            .limit(limit)
            .select('title category organizationId')
            .lean();

        return recommendedProjects;
    }

    formatExportData(projects, format) {
        if (format === 'csv') {
            const headers = ['id', 'title', 'category', 'organizationId', 'startDate', 'endDate', 'status'];
            const csvRows = [headers.join(',')];
            for (const project of projects) {
                const row = [
                    project._id,
                    `"${project.title}"`,
                    project.category || '',
                    project.organizationId?._id || '',
                    project.startDate || '',
                    project.endDate || '',
                    project.status,
                ];
                csvRows.push(row.join(','));
            }
            return csvRows.join('\n');
        }
        return projects; // Default JSON
    }
}

export default new ProjectController();