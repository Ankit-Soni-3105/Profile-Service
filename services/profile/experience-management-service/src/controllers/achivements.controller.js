import mongoose from 'mongoose';
import sanitizeHtml from 'sanitize-html';
import Achievement from '../models/achivements.model.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { catchAsync } from '../handler/catchAsync.js';
import { ApiResponse } from '../services/apiresponse.service.js';
import { createRateLimiter } from '../utils/rateLimiter.js';
import { cacheService } from '../services/redis.service.js';
import { eventEmitter } from '../events/events.js';
import { metricsCollector } from '../utils/matrics.js';
// import NotificationService from '../services/NotificationService.js';
// import AchievementService from '../services/AchievementService.js';
// import { validateAchievement, sanitizeInput } from '../validations/achievement.validation.js';

// Rate limiters for scalability
const createAchievementLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 20, // 20 creates per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_achievement_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const updateAchievementLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 30, // 30 updates per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_achievement_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const bulkOperationsLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5, // 5 bulk operations per hour
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_achievement_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

class AchievementController {
    constructor() {
        this.achievementService = AchievementService;
        this.notificationService = NotificationService;
    }

    /**
     * Create a new achievement
     * POST /api/v1/achievements/:userId
     */
    createAchievement = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const achievementData = req.body;
        const requestingUserId = req.user.id;

        // Validate access permissions
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied: Cannot create achievement for another user', 403));
        }

        // Apply rate limiting
        await createAchievementLimiter(req, res, () => { });

        // Validate input data
        const validation = validateAchievement(achievementData);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        // Sanitize input
        const sanitizedData = sanitizeInput(achievementData);

        // Check user limits
        const userAchievementCount = await Achievement.countDocuments({
            userId,
            status: { $ne: 'deleted' },
        }).cache({ ttl: 300, key: `user_achievement_count_${userId}` });

        const limits = this.getUserLimits(req.user.accountType);
        if (userAchievementCount >= limits.maxAchievements) {
            return next(new AppError(`Achievement limit reached (${limits.maxAchievements})`, 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            // Create achievement
            const achievement = await this.achievementService.createAchievement({
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
            this.processNewAchievementAsync(achievement._id, userId)
                .catch((err) => logger.error(`Async processing failed for achievement ${achievement._id}:`, err));

            // Log metrics
            metricsCollector.increment('achievement.created', {
                userId,
                category: achievement.category,
            });

            // Emit event
            eventEmitter.emit('achievement.created', {
                achievementId: achievement._id,
                userId,
            });

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`Achievement created successfully: ${achievement._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Achievement created successfully',
                data: {
                    id: achievement._id,
                    userId: achievement.userId,
                    title: achievement.title,
                    status: achievement.status,
                    createdAt: achievement.createdAt,
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Achievement creation failed for user ${userId}:`, error);
            metricsCollector.increment('achievement.create_failed', { userId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.code === 11000) {
                return next(new AppError('Achievement with this title already exists', 409));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out', 504));
            }
            return next(new AppError('Failed to create achievement', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get user's achievements with filtering and pagination
     * GET /api/v1/achievements/:userId
     */
    getAchievements = catchAsync(async (req, res, next) => {
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
            dateAchievedStart,
            dateAchievedEnd,
            includeAnalytics = 'false',
        } = req.query;

        // Build query
        const query = this.buildAchievementQuery({
            userId,
            status,
            category,
            search,
            dateAchievedStart,
            dateAchievedEnd,
        });

        // Build sort option
        const sortOption = this.buildSortOption(sortBy);

        // Pagination
        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
        const skip = (pageNum - 1) * limitNum;

        // Cache key
        const cacheKey = `achievements:${userId}:${JSON.stringify({
            page: pageNum,
            limit: limitNum,
            status,
            category,
            search,
            sortBy,
            dateAchievedStart,
            dateAchievedEnd,
        })}`;

        try {
            // Try cache first
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('achievement.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            // Query database
            const [achievements, totalCount] = await Promise.all([
                Achievement.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select(this.getSelectFields(includeAnalytics === 'true'))
                    .lean(),
                Achievement.countDocuments(query).cache({ ttl: 300, key: `achievement_count_${userId}` }),
            ]);

            const processedAchievements = await Promise.all(
                achievements.map((ach) => this.processAchievementData(ach, includeAnalytics === 'true')),
            );

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                achievements: processedAchievements,
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
            metricsCollector.increment('achievement.fetched', { userId, count: achievements.length });
            logger.info(`Fetched ${achievements.length} achievements for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch achievements for user ${userId}:`, error);
            metricsCollector.increment('achievement.fetch_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid query parameters', 400));
            }
            return next(new AppError('Failed to fetch achievements', 500));
        }
    });

    /**
     * Get single achievement by ID
     * GET /api/v1/achievements/:userId/:id
     */
    getAchievementById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        try {
            const cacheKey = `achievement:${id}:${userId}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('achievement.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const achievement = await Achievement.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .cache({ ttl: 600, key: cacheKey });

            if (!achievement) {
                return next(new AppError('Achievement not found', 404));
            }

            // Check access permissions
            if (userId !== requestingUserId && !req.user.isAdmin && achievement.visibility !== 'public') {
                return next(new AppError('Access denied', 403));
            }

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('achievement.viewed', { userId });
            logger.info(`Fetched achievement ${id} for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: achievement });
        } catch (error) {
            logger.error(`Failed to fetch achievement ${id}:`, error);
            metricsCollector.increment('achievement.view_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid achievement ID', 400));
            }
            return next(new AppError('Failed to fetch achievement', 500));
        }
    });

    /**
     * Update achievement
     * PUT /api/v1/achievements/:userId/:id
     */
    updateAchievement = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const updates = req.body;

        // Apply rate limiting
        await updateAchievementLimiter(req, res, () => { });

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const achievement = await Achievement.findOne({ _id: id, userId }).session(session);
            if (!achievement) {
                return next(new AppError('Achievement not found', 404));
            }

            // Validate updates
            const allowedUpdates = ['title', 'description', 'category', 'dateAchieved', 'visibility', 'status'];
            const sanitizedUpdates = this.sanitizeUpdates(updates, allowedUpdates);

            if (Object.keys(sanitizedUpdates).length === 0) {
                return next(new AppError('No valid update fields provided', 400));
            }

            // Update achievement
            Object.assign(achievement, sanitizedUpdates);
            achievement.metadata.lastModifiedBy = {
                userId: requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date(),
            };

            await achievement.save({ session });

            // Clear cache
            await cacheService.deletePattern(`achievement:${id}:*`);
            await cacheService.deletePattern(`achievements:${userId}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('achievement.updated', { userId });
            logger.info(`Achievement updated successfully: ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Achievement updated successfully',
                data: {
                    id: achievement._id,
                    title: achievement.title,
                    status: achievement.status,
                    updatedAt: achievement.updatedAt,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Achievement update failed for ${id}:`, error);
            metricsCollector.increment('achievement.update_failed', { userId });
            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            return next(new AppError('Failed to update achievement', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete achievement
     * DELETE /api/v1/achievements/:userId/:id
     */
    deleteAchievement = catchAsync(async (req, res, next) => {
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

            const achievement = await Achievement.findOne({ _id: id, userId }).session(session);
            if (!achievement) {
                return next(new AppError('Achievement not found', 404));
            }

            achievement.status = 'deleted';
            achievement.visibility = 'private';
            achievement.metadata.lastModifiedBy = {
                userId: requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date(),
            };
            await achievement.save({ session });

            // Clear cache
            await cacheService.deletePattern(`achievement:${id}:*`);
            await cacheService.deletePattern(`achievements:${userId}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('achievement.deleted', { userId });
            logger.info(`Achievement ${id} deleted in ${responseTime}ms`);

            return ApiResponse.success(res, { message: 'Achievement deleted successfully' });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Achievement deletion failed for ${id}:`, error);
            metricsCollector.increment('achievement.delete_failed', { userId });
            return next(new AppError('Failed to delete achievement', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Bulk operations on achievements
     * POST /api/v1/achievements/:userId/bulk
     */
    bulkOperations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { operation, achievementIds, data = {} } = req.body;

        // Apply rate limiting
        await bulkOperationsLimiter(req, res, () => { });

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        // Validate input
        if (!Array.isArray(achievementIds) || achievementIds.length === 0) {
            return next(new AppError('Achievement IDs array is required', 400));
        }
        if (achievementIds.length > 100) {
            return next(new AppError('Maximum 100 achievements can be processed at once', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const query = { _id: { $in: achievementIds }, userId };
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
                    message = 'Achievements moved to trash';
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

            const result = await Achievement.updateMany(query, updateData, { session });
            await Promise.all([
                cacheService.deletePattern(`achievements:${userId}:*`),
                ...achievementIds.map((id) => cacheService.deletePattern(`achievement:${id}:*`)),
            ]);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('achievement.bulk_operation', { userId, operation, count: achievementIds.length });
            logger.info(`Bulk operation ${operation} completed for ${achievementIds.length} achievements in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message,
                data: { operation, requested: achievementIds.length },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk operation failed for user ${userId}:`, error);
            metricsCollector.increment('achievement.bulk_operation_failed', { userId });
            return next(new AppError('Bulk operation failed', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get achievement analytics
     * GET /api/v1/achievements/:userId/:id/analytics
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
            const cacheKey = `analytics:achievement:${id}:${timeframe}:${metrics}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('achievement.analytics_cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const achievement = await Achievement.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('analytics')
                .cache({ ttl: 900, key: cacheKey });

            if (!achievement) {
                return next(new AppError('Achievement not found', 404));
            }

            const analytics = this.processAnalyticsData(achievement, timeframe, metrics);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('achievement.analytics_viewed', { userId });
            logger.info(`Fetched analytics for achievement ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: analytics });
        } catch (error) {
            logger.error(`Analytics fetch failed for achievement ${id}:`, error);
            metricsCollector.increment('achievement.analytics_fetch_failed', { userId });
            return next(new AppError('Failed to fetch analytics', 500));
        }
    });

    // Helper Methods

    async processNewAchievementAsync(achievementId, userId) {
        try {
            const session = await mongoose.startSession();
            session.startTransaction();

            const achievement = await Achievement.findById(achievementId).session(session);
            if (!achievement) {
                await session.abortTransaction();
                session.endSession();
                return;
            }

            // Extract keywords
            const keywords = await this.achievementService.extractKeywords(achievement.description);
            achievement.keywords = keywords.slice(0, 20);

            // Index for search
            await this.achievementService.indexForSearch(achievement);

            await achievement.save({ session });
            await session.commitTransaction();
            logger.info(`Async processing completed for achievement ${achievementId}`);
        } catch (error) {
            logger.error(`Async processing failed for achievement ${achievementId}:`, error);
        } finally {
            session.endSession();
        }
    }

    getUserLimits(accountType) {
        const limits = {
            free: { maxAchievements: 10 },
            premium: { maxAchievements: 50 },
            enterprise: { maxAchievements: 200 },
        };
        return limits[accountType] || limits.free;
    }

    buildAchievementQuery({ userId, status, category, search, dateAchievedStart, dateAchievedEnd }) {
        const query = { userId, status: { $ne: 'deleted' } };
        if (status && status !== 'all') query.status = status;
        if (category && category !== 'all') query.category = category;
        if (search) query.$text = { $search: search };
        if (dateAchievedStart || dateAchievedEnd) {
            query.dateAchieved = {};
            if (dateAchievedStart) query.dateAchieved.$gte = new Date(dateAchievedStart);
            if (dateAchievedEnd) query.dateAchieved.$lte = new Date(dateAchievedEnd);
        }
        return query;
    }

    buildSortOption(sortBy) {
        const sortOptions = {
            recent: { updatedAt: -1 },
            oldest: { createdAt: 1 },
            title: { title: 1 },
            dateAchieved: { dateAchieved: -1 },
        };
        return sortOptions[sortBy] || sortOptions.recent;
    }

    getSelectFields(includeAnalytics) {
        const baseFields = 'title description category dateAchieved status visibility createdAt updatedAt';
        return includeAnalytics ? baseFields + ' analytics' : baseFields;
    }

    async processAchievementData(achievement, includeAnalytics) {
        const processed = { ...achievement };
        if (!includeAnalytics) delete processed.analytics;
        return processed;
    }

    processAnalyticsData(achievement, timeframe, metrics) {
        const analytics = achievement.analytics || {};
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

export default new AchievementController();