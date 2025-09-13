import Project from '../models/Project.js';
import ProjectService from '../services/ProjectService.js';
import MediaService from '../services/MediaService.js';
import NotificationService from '../services/NotificationService.js';
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

// Rate limiters
const createProjectLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 15, // 15 creates per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_project_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const updateProjectLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 25, // 25 updates per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_project_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const bulkOperationsLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // 3 bulk operations per hour
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_project_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const mediaUploadLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 10, // 10 media uploads per 10 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `media_project_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

class ProjectController {
    constructor() {
        this.projectService = ProjectService;
        this.mediaService = MediaService;
        this.notificationService = NotificationService;
    }

    /**
     * Create a new project
     * POST /api/v1/projects/:userId
     */
    createProject = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const projectData = req.body;
        const requestingUserId = req.user.id;

        // Validate access permissions
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied: Cannot create project for another user', 403));
        }

        // Apply rate limiting
        await createProjectLimiter(req, res, () => { });

        // Validate input data
        const validation = validateProject(projectData);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        // Sanitize input
        const sanitizedData = sanitizeInput(projectData);

        // Check user limits
        const userProjectCount = await Project.countDocuments({
            userId,
            status: { $ne: 'deleted' },
        }).cache({ ttl: 300, key: `user_project_count_${userId}` });

        const limits = this.getUserLimits(req.user.accountType);
        if (userProjectCount >= limits.maxProjects) {
            return next(new AppError(`Project limit reached (${limits.maxProjects})`, 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            // Create project
            const project = await this.projectService.createProject({
                ...sanitizedData,
                userId,
                metadata: {
                    createdBy: {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        location: req.geoip,
                    },
                },
            }, { session });

            // Async processing
            this.processNewProjectAsync(project._id, userId)
                .catch((err) => logger.error(`Async processing failed for project ${project._id}:`, err));

            // Log metrics
            metricsCollector.increment('project.created', {
                userId,
                category: project.category,
            });

            // Emit event
            eventEmitter.emit('project.created', {
                projectId: project._id,
                userId,
            });

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`Project created successfully: ${project._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Project created successfully',
                data: {
                    id: project._id,
                    userId: project.userId,
                    title: project.title,
                    status: project.status,
                    createdAt: project.createdAt,
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Project creation failed for user ${userId}:`, error);
            metricsCollector.increment('project.create_failed', { userId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.code === 11000) {
                return next(new AppError('Project with this title already exists', 409));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out', 504));
            }
            return next(new AppError('Failed to create project', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get user's projects with filtering and pagination
     * GET /api/v1/projects/:userId
     */
    getProjects = catchAsync(async (req, res, next) => {
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
            startDate,
            endDate,
            includeAnalytics = 'false',
        } = req.query;

        // Build query
        const query = this.buildProjectQuery({
            userId,
            status,
            category,
            search,
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
        const cacheKey = `projects:${userId}:${JSON.stringify({
            page: pageNum,
            limit: limitNum,
            status,
            category,
            search,
            sortBy,
            startDate,
            endDate,
        })}`;

        try {
            // Try cache first
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('project.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            // Query database
            const [projects, totalCount] = await Promise.all([
                Project.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select(this.getSelectFields(includeAnalytics === 'true'))
                    .lean(),
                Project.countDocuments(query).cache({ ttl: 300, key: `project_count_${userId}` }),
            ]);

            const processedProjects = await Promise.all(
                projects.map((proj) => this.processProjectData(proj, includeAnalytics === 'true')),
            );

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                projects: processedProjects,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages,
                    hasNext: pageNum < totalPages,
                    hasPrev: pageNum > 1,
                    nextPage: pageNum < totalPages ? pageNum + 1 : null,
                    prevPage: pageNum > 1 ? pageNum - 1 : null,
                },
                filters: {
                    status: status || 'all',
                    category: category || 'all',
                    sortBy,
                    search: search || null,
                },
            };

            // Cache result
            await cacheService.set(cacheKey, result, 300);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('project.fetched', { userId, count: projects.length });
            logger.info(`Fetched ${projects.length} projects for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch projects for user ${userId}:`, error);
            metricsCollector.increment('project.fetch_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid query parameters', 400));
            }
            return next(new AppError('Failed to fetch projects', 500));
        }
    });

    /**
     * Get single project by ID
     * GET /api/v1/projects/:userId/:id
     */
    getProjectById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        try {
            const cacheKey = `project:${id}:${userId}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('project.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const project = await Project.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .cache({ ttl: 600, key: cacheKey });

            if (!project) {
                return next(new AppError('Project not found', 404));
            }

            // Check access permissions
            if (userId !== requestingUserId && !req.user.isAdmin && project.visibility !== 'public') {
                return next(new AppError('Access denied', 403));
            }

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('project.viewed', { userId });
            logger.info(`Fetched project ${id} for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: project });
        } catch (error) {
            logger.error(`Failed to fetch project ${id}:`, error);
            metricsCollector.increment('project.view_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid project ID', 400));
            }
            return next(new AppError('Failed to fetch project', 500));
        }
    });

    /**
     * Update project
     * PUT /api/v1/projects/:userId/:id
     */
    updateProject = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const updates = req.body;

        // Apply rate limiting
        await updateProjectLimiter(req, res, () => { });

        // Validate access
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

            // Validate updates
            const allowedUpdates = ['title', 'description', 'category', 'startDate', 'endDate', 'visibility', 'status'];
            const sanitizedUpdates = this.sanitizeUpdates(updates, allowedUpdates);

            if (Object.keys(sanitizedUpdates).length === 0) {
                return next(new AppError('No valid update fields provided', 400));
            }

            // Update project
            Object.assign(project, sanitizedUpdates);
            project.metadata.lastModifiedBy = {
                userId: requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date(),
            };

            await project.save({ session });

            // Clear cache
            await cacheService.deletePattern(`project:${id}:*`);
            await cacheService.deletePattern(`projects:${userId}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('project.updated', { userId });
            logger.info(`Project updated successfully: ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Project updated successfully',
                data: {
                    id: project._id,
                    title: project.title,
                    status: project.status,
                    updatedAt: project.updatedAt,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Project update failed for ${id}:`, error);
            metricsCollector.increment('project.update_failed', { userId });
            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            return next(new AppError('Failed to update project', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete project
     * DELETE /api/v1/projects/:userId/:id
     */
    deleteProject = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        // Validate access
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

            project.status = 'deleted';
            project.visibility = 'private';
            project.metadata.lastModifiedBy = {
                userId: requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date(),
            };
            await project.save({ session });

            // Clear cache
            await cacheService.deletePattern(`project:${id}:*`);
            await cacheService.deletePattern(`projects:${userId}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('project.deleted', { userId });
            logger.info(`Project ${id} deleted in ${responseTime}ms`);

            return ApiResponse.success(res, { message: 'Project deleted successfully' });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Project deletion failed for ${id}:`, error);
            metricsCollector.increment('project.delete_failed', { userId });
            return next(new AppError('Failed to delete project', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Bulk operations on projects
     * POST /api/v1/projects/:userId/bulk
     */
    bulkOperations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { operation, projectIds, data = {} } = req.body;

        // Apply rate limiting
        await bulkOperationsLimiter(req, res, () => { });

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        // Validate input
        if (!Array.isArray(projectIds) || projectIds.length === 0) {
            return next(new AppError('Project IDs array is required', 400));
        }
        if (projectIds.length > 100) {
            return next(new AppError('Maximum 100 projects can be processed at once', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const query = { _id: { $in: projectIds }, userId };
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
                    message = 'Projects moved to trash';
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
                default:
                    throw new AppError('Invalid operation', 400);
            }

            const result = await Project.updateMany(query, updateData, { session });
            await Promise.all([
                cacheService.deletePattern(`projects:${userId}:*`),
                ...projectIds.map((id) => cacheService.deletePattern(`project:${id}:*`)),
            ]);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('project.bulk_operation', { userId, operation, count: projectIds.length });
            logger.info(`Bulk operation ${operation} completed for ${projectIds.length} projects in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message,
                data: { operation, requested: projectIds.length },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk operation failed for user ${userId}:`, error);
            metricsCollector.increment('project.bulk_operation_failed', { userId });
            return next(new AppError('Bulk operation failed', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Upload media for project
     * POST /api/v1/projects/:userId/:id/media
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

            const project = await Project.findOne({ _id: id, userId }).session(session);
            if (!project) {
                return next(new AppError('Project not found', 404));
            }

            // Validate media
            const validation = this.validateMediaUpload(files, project.media);
            if (!validation.valid) {
                return next(new AppError(validation.message, 422));
            }

            // Process media
            const mediaResults = await this.mediaService.uploadMedia({
                files,
                entityId: id,
                entityType: 'project',
                userId,
            }, { session });

            // Virus scan
            const scanResults = await this.mediaService.scanMedia(mediaResults);
            if (scanResults.some((result) => result.infected)) {
                return next(new AppError('Media upload failed: Infected file detected', 422));
            }

            project.media.push(...mediaResults);
            await project.save({ session });

            // Clear cache
            await cacheService.deletePattern(`project:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('project.media_uploaded', { userId, count: mediaResults.length });
            logger.info(`Uploaded ${mediaResults.length} media files for project ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Media uploaded successfully',
                data: { media: mediaResults },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Media upload failed for project ${id}:`, error);
            metricsCollector.increment('project.media_upload_failed', { userId });
            return next(new AppError('Failed to upload media', 422));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get project analytics
     * GET /api/v1/projects/:userId/:id/analytics
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
            const cacheKey = `analytics:project:${id}:${timeframe}:${metrics}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('project.analytics_cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const project = await Project.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('analytics')
                .cache({ ttl: 900, key: cacheKey });

            if (!project) {
                return next(new AppError('Project not found', 404));
            }

            const analytics = this.processAnalyticsData(project, timeframe, metrics);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('project.analytics_viewed', { userId });
            logger.info(`Fetched analytics for project ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: analytics });
        } catch (error) {
            logger.error(`Analytics fetch failed for project ${id}:`, error);
            metricsCollector.increment('project.analytics_fetch_failed', { userId });
            return next(new AppError('Failed to fetch analytics', 500));
        }
    });

    // Helper Methods

    async processNewProjectAsync(projectId, userId) {
        try {
            const session = await mongoose.startSession();
            session.startTransaction();

            const project = await Project.findById(projectId).session(session);
            if (!project) {
                await session.abortTransaction();
                session.endSession();
                return;
            }

            // Extract keywords
            const keywords = await this.projectService.extractKeywords(project.description);
            project.keywords = keywords.slice(0, 20);

            // Index for search
            await this.projectService.indexForSearch(project);

            await project.save({ session });
            await session.commitTransaction();
            logger.info(`Async processing completed for project ${projectId}`);
        } catch (error) {
            logger.error(`Async processing failed for project ${projectId}:`, error);
        } finally {
            session.endSession();
        }
    }

    getUserLimits(accountType) {
        const limits = {
            free: { maxProjects: 5, maxMedia: 5, maxSizeMB: 50 },
            premium: { maxProjects: 25, maxMedia: 20, maxSizeMB: 200 },
            enterprise: { maxProjects: 100, maxMedia: 50, maxSizeMB: 500 },
        };
        return limits[accountType] || limits.free;
    }

    buildProjectQuery({ userId, status, category, search, startDate, endDate }) {
        const query = { userId, status: { $ne: 'deleted' } };
        if (status && status !== 'all') query.status = status;
        if (category && category !== 'all') query.category = category;
        if (search) query.$text = { $search: search };
        if (startDate || endDate) {
            query.startDate = {};
            if (startDate) query.startDate.$gte = new Date(startDate);
            if (endDate) query.startDate.$lte = new Date(endDate);
        }
        return query;
    }

    buildSortOption(sortBy) {
        const sortOptions = {
            recent: { updatedAt: -1 },
            oldest: { createdAt: 1 },
            title: { title: 1 },
            startDate: { startDate: -1 },
        };
        return sortOptions[sortBy] || sortOptions.recent;
    }

    getSelectFields(includeAnalytics) {
        const baseFields = 'title description category startDate endDate status visibility createdAt updatedAt';
        return includeAnalytics ? baseFields + ' analytics' : baseFields;
    }

    async processProjectData(project, includeAnalytics) {
        const processed = { ...project };
        if (!includeAnalytics) delete processed.analytics;
        return processed;
    }

    processAnalyticsData(project, timeframe, metrics) {
        const analytics = project.analytics || {};
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
        };

        if (metrics === 'detailed') {
            filteredAnalytics.shares = {
                total: analytics.shares?.total || 0,
                byPlatform: analytics.shares?.byPlatform || {},
            };
        }

        return filteredAnalytics;
    }

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

    sanitizeUpdates(updates, allowedFields) {
        const sanitized = {};
        allowedFields.forEach((field) => {
            if (updates[field] !== undefined) {
                sanitized[field] = field === 'description' ? sanitizeHtml(updates[field]) : sanitizeInput(updates[field]);
            }
        });
        return sanitized;
    }
}

export default new ProjectController();