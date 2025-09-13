import JobTitle from '../models/JobTitle.js';
import JobTitleService from '../services/JobTitleService.js';
import { validateJobTitle, sanitizeInput } from '../validations/jobTitle.validation.js';
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
const createJobTitleLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 20, // 20 creates per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_jobtitle_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const updateJobTitleLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 30, // 30 updates per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_jobtitle_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const bulkOperationsLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5, // 5 bulk operations per hour
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_jobtitle_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

class JobTitleController {
    constructor() {
        this.jobTitleService = JobTitleService;
    }

    /**
     * Create a new job title
     * POST /api/v1/jobtitles/:userId
     */
    createJobTitle = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const jobTitleData = req.body;
        const requestingUserId = req.user.id;

        // Validate access permissions
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied: Cannot create job title for another user', 403));
        }

        // Apply rate limiting
        await createJobTitleLimiter(req, res, () => { });

        // Validate input data
        const validation = validateJobTitle(jobTitleData);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        // Sanitize input
        const sanitizedData = sanitizeInput(jobTitleData);

        // Check user limits
        const userJobTitleCount = await JobTitle.countDocuments({
            userId,
            status: { $ne: 'deleted' },
        }).cache({ ttl: 300, key: `user_jobtitle_count_${userId}` });

        const limits = this.getUserLimits(req.user.accountType);
        if (userJobTitleCount >= limits.maxJobTitles) {
            return next(new AppError(`Job title limit reached (${limits.maxJobTitles})`, 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            // Create job title
            const jobTitle = await this.jobTitleService.createJobTitle({
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

            // Log metrics
            metricsCollector.increment('jobtitle.created', { userId, category: jobTitle.category });

            // Emit event
            eventEmitter.emit('jobtitle.created', { jobTitleId: jobTitle._id, userId });

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`Job title created successfully: ${jobTitle._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Job title created successfully',
                data: {
                    id: jobTitle._id,
                    userId: jobTitle.userId,
                    name: jobTitle.name,
                    status: jobTitle.status,
                    createdAt: jobTitle.createdAt,
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Job title creation failed for user ${userId}:`, error);
            metricsCollector.increment('jobtitle.create_failed', { userId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.code === 11000) {
                return next(new AppError('Job title with this name already exists', 409));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out', 504));
            }
            return next(new AppError('Failed to create job title', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get user's job titles with filtering and pagination
     * GET /api/v1/jobtitles/:userId
     */
    getJobTitles = catchAsync(async (req, res, next) => {
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
        } = req.query;

        // Build query
        const query = this.buildJobTitleQuery({ userId, status, category, search });

        // Build sort option
        const sortOption = this.buildSortOption(sortBy);

        // Pagination
        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
        const skip = (pageNum - 1) * limitNum;

        // Cache key
        const cacheKey = `jobtitles:${userId}:${JSON.stringify({ page: pageNum, limit: limitNum, status, category, search, sortBy })}`;

        try {
            // Try cache first
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('jobtitle.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            // Query database
            const [jobTitles, totalCount] = await Promise.all([
                JobTitle.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select('name status category createdAt updatedAt')
                    .lean(),
                JobTitle.countDocuments(query).cache({ ttl: 300, key: `jobtitle_count_${userId}` }),
            ]);

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                jobTitles,
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
                filters: { status: status || 'all', category: category || 'all', sortBy, search: search || null },
            };

            // Cache result
            await cacheService.set(cacheKey, result, 300);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('jobtitle.fetched', { userId, count: jobTitles.length });
            logger.info(`Fetched ${jobTitles.length} job titles for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch job titles for user ${userId}:`, error);
            metricsCollector.increment('jobtitle.fetch_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid query parameters', 400));
            }
            return next(new AppError('Failed to fetch job titles', 500));
        }
    });

    /**
     * Get single job title by ID
     * GET /api/v1/jobtitles/:userId/:id
     */
    getJobTitleById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        try {
            const cacheKey = `jobtitle:${id}:${userId}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('jobtitle.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const jobTitle = await JobTitle.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .cache({ ttl: 600, key: cacheKey });

            if (!jobTitle) {
                return next(new AppError('Job title not found', 404));
            }

            // Check access permissions
            if (userId !== requestingUserId && !req.user.isAdmin && jobTitle.visibility !== 'public') {
                return next(new AppError('Access denied', 403));
            }

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('jobtitle.viewed', { userId });
            logger.info(`Fetched job title ${id} for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: jobTitle });
        } catch (error) {
            logger.error(`Failed to fetch job title ${id}:`, error);
            metricsCollector.increment('jobtitle.view_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid job title ID', 400));
            }
            return next(new AppError('Failed to fetch job title', 500));
        }
    });

    /**
     * Update job title
     * PUT /api/v1/jobtitles/:userId/:id
     */
    updateJobTitle = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const updates = req.body;

        // Apply rate limiting
        await updateJobTitleLimiter(req, res, () => { });

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const jobTitle = await JobTitle.findOne({ _id: id, userId }).session(session);
            if (!jobTitle) {
                return next(new AppError('Job title not found', 404));
            }

            // Validate updates
            const allowedUpdates = ['name', 'description', 'category', 'visibility', 'status'];
            const sanitizedUpdates = this.sanitizeUpdates(updates, allowedUpdates);

            if (Object.keys(sanitizedUpdates).length === 0) {
                return next(new AppError('No valid update fields provided', 400));
            }

            // Update job title
            Object.assign(jobTitle, sanitizedUpdates);
            jobTitle.metadata.lastModifiedBy = {
                userId: requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date(),
            };

            await jobTitle.save({ session });

            // Clear cache
            await cacheService.deletePattern(`jobtitle:${id}:*`);
            await cacheService.deletePattern(`jobtitles:${userId}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('jobtitle.updated', { userId });
            logger.info(`Job title updated successfully: ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Job title updated successfully',
                data: {
                    id: jobTitle._id,
                    name: jobTitle.name,
                    status: jobTitle.status,
                    updatedAt: jobTitle.updatedAt,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Job title update failed for ${id}:`, error);
            metricsCollector.increment('jobtitle.update_failed', { userId });
            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            return next(new AppError('Failed to update job title', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete job title
     * DELETE /api/v1/jobtitles/:userId/:id
     */
    deleteJobTitle = catchAsync(async (req, res, next) => {
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

            const jobTitle = await JobTitle.findOne({ _id: id, userId }).session(session);
            if (!jobTitle) {
                return next(new AppError('Job title not found', 404));
            }

            jobTitle.status = 'deleted';
            jobTitle.visibility = 'private';
            jobTitle.metadata.lastModifiedBy = {
                userId: requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date(),
            };
            await jobTitle.save({ session });

            // Clear cache
            await cacheService.deletePattern(`jobtitle:${id}:*`);
            await cacheService.deletePattern(`jobtitles:${userId}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('jobtitle.deleted', { userId });
            logger.info(`Job title ${id} deleted in ${responseTime}ms`);

            return ApiResponse.success(res, { message: 'Job title deleted successfully' });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Job title deletion failed for ${id}:`, error);
            metricsCollector.increment('jobtitle.delete_failed', { userId });
            return next(new AppError('Failed to delete job title', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Bulk operations on job titles
     * POST /api/v1/jobtitles/:userId/bulk
     */
    bulkOperations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { operation, jobTitleIds, data = {} } = req.body;

        // Apply rate limiting
        await bulkOperationsLimiter(req, res, () => { });

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        // Validate input
        if (!Array.isArray(jobTitleIds) || jobTitleIds.length === 0) {
            return next(new AppError('Job title IDs array is required', 400));
        }
        if (jobTitleIds.length > 100) {
            return next(new AppError('Maximum 100 job titles can be processed at once', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const query = { _id: { $in: jobTitleIds }, userId };
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
                    message = 'Job titles moved to trash';
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

            const result = await JobTitle.updateMany(query, updateData, { session });
            await Promise.all([
                cacheService.deletePattern(`jobtitles:${userId}:*`),
                ...jobTitleIds.map((id) => cacheService.deletePattern(`jobtitle:${id}:*`)),
            ]);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('jobtitle.bulk_operation', { userId, operation, count: jobTitleIds.length });
            logger.info(`Bulk operation ${operation} completed for ${jobTitleIds.length} job titles in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message,
                data: { operation, requested: jobTitleIds.length },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk operation failed for user ${userId}:`, error);
            metricsCollector.increment('jobtitle.bulk_operation_failed', { userId });
            return next(new AppError('Bulk operation failed', 500));
        } finally {
            session.endSession();
        }
    });

    // Helper Methods

    getUserLimits(accountType) {
        const limits = {
            free: { maxJobTitles: 10 },
            premium: { maxJobTitles: 50 },
            enterprise: { maxJobTitles: 200 },
        };
        return limits[accountType] || limits.free;
    }

    buildJobTitleQuery({ userId, status, category, search }) {
        const query = { userId, status: { $ne: 'deleted' } };
        if (status && status !== 'all') query.status = status;
        if (category && category !== 'all') query.category = category;
        if (search) query.$text = { $search: search };
        return query;
    }

    buildSortOption(sortBy) {
        const sortOptions = {
            recent: { updatedAt: -1 },
            oldest: { createdAt: 1 },
            name: { name: 1 },
        };
        return sortOptions[sortBy] || sortOptions.recent;
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

export default new JobTitleController();