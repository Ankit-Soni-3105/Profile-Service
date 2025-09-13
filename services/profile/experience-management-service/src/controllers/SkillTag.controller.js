import SkillTag from '../models/SkillTag.js';
import SkillTagService from '../services/SkillTagService.js';
import { validateSkillTag, sanitizeInput } from '../validations/skillTag.validation.js';
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
const createSkillTagLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 50, // 50 creates per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_skilltag_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const updateSkillTagLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 50, // 50 updates per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_skilltag_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const bulkOperationsLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5, // 5 bulk operations per hour
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_skilltag_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

class SkillTagController {
    constructor() {
        this.skillTagService = SkillTagService;
    }

    /**
     * Create a new skill tag
     * POST /api/v1/skilltags/:userId
     */
    createSkillTag = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const skillTagData = req.body;
        const requestingUserId = req.user.id;

        // Validate access permissions
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied: Cannot create skill tag for another user', 403));
        }

        // Apply rate limiting
        await createSkillTagLimiter(req, res, () => { });

        // Validate input data
        const validation = validateSkillTag(skillTagData);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        // Sanitize input
        const sanitizedData = sanitizeInput(skillTagData);

        // Check user limits
        const userSkillTagCount = await SkillTag.countDocuments({
            userId,
            status: { $ne: 'deleted' },
        }).cache({ ttl: 300, key: `user_skilltag_count_${userId}` });

        const limits = this.getUserLimits(req.user.accountType);
        if (userSkillTagCount >= limits.maxSkillTags) {
            return next(new AppError(`Skill tag limit reached (${limits.maxSkillTags})`, 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            // Create skill tag
            const skillTag = await this.skillTagService.createSkillTag({
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
            metricsCollector.increment('skilltag.created', { userId, category: skillTag.category });

            // Emit event
            eventEmitter.emit('skilltag.created', { skillTagId: skillTag._id, userId });

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`Skill tag created successfully: ${skillTag._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Skill tag created successfully',
                data: {
                    id: skillTag._id,
                    userId: skillTag.userId,
                    name: skillTag.name,
                    status: skillTag.status,
                    createdAt: skillTag.createdAt,
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Skill tag creation failed for user ${userId}:`, error);
            metricsCollector.increment('skilltag.create_failed', { userId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.code === 11000) {
                return next(new AppError('Skill tag with this name already exists', 409));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out', 504));
            }
            return next(new AppError('Failed to create skill tag', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get user's skill tags with filtering and pagination
     * GET /api/v1/skilltags/:userId
     */
    getSkillTags = catchAsync(async (req, res, next) => {
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
        const query = this.buildSkillTagQuery({ userId, status, category, search });

        // Build sort option
        const sortOption = this.buildSortOption(sortBy);

        // Pagination
        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
        const skip = (pageNum - 1) * limitNum;

        // Cache key
        const cacheKey = `skilltags:${userId}:${JSON.stringify({ page: pageNum, limit: limitNum, status, category, search, sortBy })}`;

        try {
            // Try cache first
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('skilltag.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            // Query database
            const [skillTags, totalCount] = await Promise.all([
                SkillTag.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select('name category status createdAt updatedAt')
                    .lean(),
                SkillTag.countDocuments(query).cache({ ttl: 300, key: `skilltag_count_${userId}` }),
            ]);

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                skillTags,
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
            metricsCollector.increment('skilltag.fetched', { userId, count: skillTags.length });
            logger.info(`Fetched ${skillTags.length} skill tags for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch skill tags for user ${userId}:`, error);
            metricsCollector.increment('skilltag.fetch_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid query parameters', 400));
            }
            return next(new AppError('Failed to fetch skill tags', 500));
        }
    });

    /**
     * Get single skill tag by ID
     * GET /api/v1/skilltags/:userId/:id
     */
    getSkillTagById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        try {
            const cacheKey = `skilltag:${id}:${userId}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('skilltag.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const skillTag = await SkillTag.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .cache({ ttl: 600, key: cacheKey });

            if (!skillTag) {
                return next(new AppError('Skill tag not found', 404));
            }

            // Check access permissions
            if (userId !== requestingUserId && !req.user.isAdmin && skillTag.visibility !== 'public') {
                return next(new AppError('Access denied', 403));
            }

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('skilltag.viewed', { userId });
            logger.info(`Fetched skill tag ${id} for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: skillTag });
        } catch (error) {
            logger.error(`Failed to fetch skill tag ${id}:`, error);
            metricsCollector.increment('skilltag.view_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid skill tag ID', 400));
            }
            return next(new AppError('Failed to fetch skill tag', 500));
        }
    });

    /**
     * Update skill tag
     * PUT /api/v1/skilltags/:userId/:id
     */
    updateSkillTag = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const updates = req.body;

        // Apply rate limiting
        await updateSkillTagLimiter(req, res, () => { });

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const skillTag = await SkillTag.findOne({ _id: id, userId }).session(session);
            if (!skillTag) {
                return next(new AppError('Skill tag not found', 404));
            }

            // Validate updates
            const allowedUpdates = ['name', 'category', 'visibility', 'status'];
            const sanitizedUpdates = this.sanitizeUpdates(updates, allowedUpdates);

            if (Object.keys(sanitizedUpdates).length === 0) {
                return next(new AppError('No valid update fields provided', 400));
            }

            // Update skill tag
            Object.assign(skillTag, sanitizedUpdates);
            skillTag.metadata.lastModifiedBy = {
                userId: requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date(),
            };

            await skillTag.save({ session });

            // Clear cache
            await cacheService.deletePattern(`skilltag:${id}:*`);
            await cacheService.deletePattern(`skilltags:${userId}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('skilltag.updated', { userId });
            logger.info(`Skill tag updated successfully: ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Skill tag updated successfully',
                data: {
                    id: skillTag._id,
                    name: skillTag.name,
                    status: skillTag.status,
                    updatedAt: skillTag.updatedAt,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Skill tag update failed for ${id}:`, error);
            metricsCollector.increment('skilltag.update_failed', { userId });
            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            return next(new AppError('Failed to update skill tag', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete skill tag
     * DELETE /api/v1/skilltags/:userId/:id
     */
    deleteSkillTag = catchAsync(async (req, res, next) => {
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

            const skillTag = await SkillTag.findOne({ _id: id, userId }).session(session);
            if (!skillTag) {
                return next(new AppError('Skill tag not found', 404));
            }

            skillTag.status = 'deleted';
            skillTag.visibility = 'private';
            skillTag.metadata.lastModifiedBy = {
                userId: requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date(),
            };
            await skillTag.save({ session });

            // Clear cache
            await cacheService.deletePattern(`skilltag:${id}:*`);
            await cacheService.deletePattern(`skilltags:${userId}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('skilltag.deleted', { userId });
            logger.info(`Skill tag ${id} deleted in ${responseTime}ms`);

            return ApiResponse.success(res, { message: 'Skill tag deleted successfully' });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Skill tag deletion failed for ${id}:`, error);
            metricsCollector.increment('skilltag.delete_failed', { userId });
            return next(new AppError('Failed to delete skill tag', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Bulk operations on skill tags
     * POST /api/v1/skilltags/:userId/bulk
     */
    bulkOperations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { operation, skillTagIds, data = {} } = req.body;

        // Apply rate limiting
        await bulkOperationsLimiter(req, res, () => { });

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        // Validate input
        if (!Array.isArray(skillTagIds) || skillTagIds.length === 0) {
            return next(new AppError('Skill tag IDs array is required', 400));
        }
        if (skillTagIds.length > 100) {
            return next(new AppError('Maximum 100 skill tags can be processed at once', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const query = { _id: { $in: skillTagIds }, userId };
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
                    message = 'Skill tags moved to trash';
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

            const result = await SkillTag.updateMany(query, updateData, { session });
            await Promise.all([
                cacheService.deletePattern(`skilltags:${userId}:*`),
                ...skillTagIds.map((id) => cacheService.deletePattern(`skilltag:${id}:*`)),
            ]);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('skilltag.bulk_operation', { userId, operation, count: skillTagIds.length });
            logger.info(`Bulk operation ${operation} completed for ${skillTagIds.length} skill tags in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message,
                data: { operation, requested: skillTagIds.length },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk operation failed for user ${userId}:`, error);
            metricsCollector.increment('skilltag.bulk_operation_failed', { userId });
            return next(new AppError('Bulk operation failed', 500));
        } finally {
            session.endSession();
        }
    });

    // Helper Methods

    getUserLimits(accountType) {
        const limits = {
            free: { maxSkillTags: 50 },
            premium: { maxSkillTags: 200 },
            enterprise: { maxSkillTags: 500 },
        };
        return limits[accountType] || limits.free;
    }

    buildSkillTagQuery({ userId, status, category, search }) {
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
                sanitized[field] = sanitizeInput(updates[field]);
            }
        });
        return sanitized;
    }
}

export default new SkillTagController();