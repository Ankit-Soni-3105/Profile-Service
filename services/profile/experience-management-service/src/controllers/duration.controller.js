import Duration from '../models/Duration.js';
import DurationService from '../services/DurationService.js';
import NotificationService from '../services/NotificationService.js';
import { validateDuration, sanitizeInput } from '../validations/duration.validation.js';
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
const createDurationLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 20, // 20 creates per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_duration_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const updateDurationLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 30, // 30 updates per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_duration_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const bulkOperationsLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5, // 5 bulk operations per hour
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_duration_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const shareDurationLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 10, // 10 shares per 10 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `share_duration_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

class DurationController {
    constructor() {
        this.durationService = DurationService;
        this.notificationService = NotificationService;
    }

    /**
     * Create a new duration
     * POST /api/v1/durations/:userId
     */
    createDuration = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const durationData = req.body;
        const requestingUserId = req.user.id;

        // Validate access permissions
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied: Cannot create duration for another user', 403));
        }

        // Apply rate limiting
        await createDurationLimiter(req, res, () => { });

        // Validate input data
        const validation = validateDuration(durationData);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        // Sanitize input
        const sanitizedData = sanitizeInput(durationData);

        // Check user limits
        const userDurationCount = await Duration.countDocuments({
            userId,
            status: { $ne: 'deleted' },
        }).cache({ ttl: 300, key: `user_duration_count_${userId}` });

        const limits = this.getUserLimits(req.user.accountType);
        if (userDurationCount >= limits.maxDurations) {
            return next(new AppError(`Duration limit reached (${limits.maxDurations})`, 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            // Create duration
            const duration = await this.durationService.createDuration({
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

            // Start async processing
            this.processNewDurationAsync(duration._id, userId)
                .catch((err) => logger.error(`Async processing failed for duration ${duration._id}:`, err));

            // Log metrics
            metricsCollector.increment('duration.created', { userId });

            // Emit event
            eventEmitter.emit('duration.created', { durationId: duration._id, userId });

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`Duration created successfully: ${duration._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Duration created successfully',
                data: {
                    id: duration._id,
                    userId: duration.userId,
                    startDate: duration.startDate,
                    endDate: duration.endDate,
                    status: duration.status,
                    createdAt: duration.createdAt,
                    processingStatus: 'started',
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Duration creation failed for user ${userId}:`, error);
            metricsCollector.increment('duration.create_failed', { userId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.code === 11000) {
                return next(new AppError('Duration with this data already exists', 409));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out', 504));
            }
            return next(new AppError('Failed to create duration', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get user's durations with filtering and pagination
     * GET /api/v1/durations/:userId
     */
    getDurations = catchAsync(async (req, res, next) => {
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
            startDate,
            endDate,
            search,
            sortBy = 'recent',
            tags,
            includeAnalytics = 'false',
        } = req.query;

        // Build query
        const query = this.buildDurationQuery({ userId, status, startDate, endDate, search, tags });

        // Build sort option
        const sortOption = this.buildSortOption(sortBy);

        // Pagination
        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
        const skip = (pageNum - 1) * limitNum;

        // Cache key
        const cacheKey = `durations:${userId}:${JSON.stringify({
            page: pageNum,
            limit: limitNum,
            status,
            startDate,
            endDate,
            search,
            sortBy,
            tags,
        })}`;

        try {
            // Try cache first
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('duration.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            // Query database
            const [durations, totalCount] = await Promise.all([
                Duration.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select(this.getSelectFields(includeAnalytics === 'true'))
                    .lean(),
                Duration.countDocuments(query).cache({ ttl: 300, key: `duration_count_${userId}` }),
            ]);

            // Process durations
            const processedDurations = await Promise.all(
                durations.map((dur) => this.processDurationData(dur, includeAnalytics === 'true')),
            );

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                durations: processedDurations,
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
                filters: { status: status || 'all', sortBy, search: search || null },
            };

            // Cache result
            await cacheService.set(cacheKey, result, 300);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('duration.fetched', { userId, count: durations.length });
            logger.info(`Fetched ${durations.length} durations for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch durations for user ${userId}:`, error);
            metricsCollector.increment('duration.fetch_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid query parameters', 400));
            }
            return next(new AppError('Failed to fetch durations', 500));
        }
    });

    /**
     * Get single duration by ID
     * GET /api/v1/durations/:userId/:id
     */
    getDurationById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { includeAnalytics = 'false' } = req.query;

        try {
            const cacheKey = `duration:${id}:${userId}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('duration.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const duration = await Duration.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .cache({ ttl: 600, key: cacheKey });

            if (!duration) {
                return next(new AppError('Duration not found', 404));
            }

            // Check access permissions
            if (!this.checkDurationAccess(duration, requestingUserId, req.user.isAdmin)) {
                return next(new AppError('Access denied', 403));
            }

            // Increment view count (async)
            if (requestingUserId !== userId) {
                duration.incrementViews(true)
                    .catch((err) => logger.error(`View increment failed for duration ${id}:`, err));
            }

            const responseData = await this.processDurationData(duration.toObject(), includeAnalytics === 'true');

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('duration.viewed', { userId });
            logger.info(`Fetched duration ${id} for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: responseData });
        } catch (error) {
            logger.error(`Failed to fetch duration ${id}:`, error);
            metricsCollector.increment('duration.view_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid duration ID', 400));
            }
            return next(new AppError('Failed to fetch duration', 500));
        }
    });

    /**
     * Update duration
     * PUT /api/v1/durations/:userId/:id
     */
    updateDuration = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const updates = req.body;

        // Apply rate limiting
        await updateDurationLimiter(req, res, () => { });

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const duration = await Duration.findOne({ _id: id, userId }).session(session);
            if (!duration) {
                return next(new AppError('Duration not found', 404));
            }

            // Validate updates
            const allowedUpdates = ['startDate', 'endDate', 'description', 'visibility', 'status', 'tags'];
            const sanitizedUpdates = this.sanitizeUpdates(updates, allowedUpdates);

            if (Object.keys(sanitizedUpdates).length === 0) {
                return next(new AppError('No valid update fields provided', 400));
            }

            // Update duration
            Object.assign(duration, sanitizedUpdates);
            duration.metadata.lastModifiedBy = {
                userId: requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date(),
            };

            await duration.save({ session });

            // Clear cache
            await cacheService.deletePattern(`duration:${id}:*`);
            await cacheService.deletePattern(`durations:${userId}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('duration.updated', { userId });
            logger.info(`Duration updated successfully: ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Duration updated successfully',
                data: {
                    id: duration._id,
                    startDate: duration.startDate,
                    endDate: duration.endDate,
                    status: duration.status,
                    updatedAt: duration.updatedAt,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Duration update failed for ${id}:`, error);
            metricsCollector.increment('duration.update_failed', { userId });
            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            return next(new AppError('Failed to update duration', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete duration (soft or permanent)
     * DELETE /api/v1/durations/:userId/:id
     */
    deleteDuration = catchAsync(async (req, res, next) => {
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

            const duration = await Duration.findOne({ _id: id, userId }).session(session);
            if (!duration) {
                return next(new AppError('Duration not found', 404));
            }

            if (permanent === 'true') {
                // Permanent deletion
                await Duration.findByIdAndDelete(id, { session });
                metricsCollector.increment('duration.permanently_deleted', { userId });
            } else {
                // Soft delete
                duration.status = 'deleted';
                duration.visibility = 'private';
                duration.metadata.lastModifiedBy = {
                    userId: requestingUserId,
                    ip: req.ip,
                    userAgent: req.get('User-Agent'),
                    timestamp: new Date(),
                };
                await duration.save({ session });
                metricsCollector.increment('duration.soft_deleted', { userId });
            }

            // Clear cache
            await cacheService.deletePattern(`duration:${id}:*`);
            await cacheService.deletePattern(`durations:${userId}:*`);

            // Emit event
            eventEmitter.emit('duration.deleted', {
                durationId: id,
                userId,
                permanent: permanent === 'true',
            });

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`Duration ${id} deleted (permanent: ${permanent}) in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: permanent === 'true' ? 'Duration permanently deleted' : 'Duration moved to trash',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Duration deletion failed for ${id}:`, error);
            metricsCollector.increment('duration.delete_failed', { userId });
            return next(new AppError('Failed to delete duration', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Bulk operations on durations
     * POST /api/v1/durations/:userId/bulk
     */
    bulkOperations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { operation, durationIds, data = {} } = req.body;

        // Apply rate limiting
        await bulkOperationsLimiter(req, res, () => { });

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        // Validate input
        if (!Array.isArray(durationIds) || durationIds.length === 0) {
            return next(new AppError('Duration IDs array is required', 400));
        }
        if (durationIds.length > 100) {
            return next(new AppError('Maximum 100 durations can be processed at once', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const query = { _id: { $in: durationIds }, userId };
            const { message } = await this.handleBulkOperation(operation, query, data, requestingUserId, req, { session });

            // Clear cache
            await Promise.all([
                cacheService.deletePattern(`durations:${userId}:*`),
                ...durationIds.map((id) => cacheService.deletePattern(`duration:${id}:*`)),
            ]);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('duration.bulk_operation', { userId, operation, count: durationIds.length });
            logger.info(`Bulk operation ${operation} completed for ${durationIds.length} durations in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message,
                data: { operation, requested: durationIds.length },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk operation failed for user ${userId}:`, error);
            metricsCollector.increment('duration.bulk_operation_failed', { userId });
            return next(new AppError('Bulk operation failed', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get duration analytics
     * GET /api/v1/durations/:userId/:id/analytics
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
            const cacheKey = `analytics:duration:${id}:${timeframe}:${metrics}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('duration.analytics_cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const duration = await Duration.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('analytics metadata createdAt')
                .cache({ ttl: 900, key: cacheKey });

            if (!duration) {
                return next(new AppError('Duration not found', 404));
            }

            const analytics = this.processAnalyticsData(duration, timeframe, metrics);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('duration.analytics_viewed', { userId });
            logger.info(`Fetched analytics for duration ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: analytics });
        } catch (error) {
            logger.error(`Analytics fetch failed for ${id}:`, error);
            metricsCollector.increment('duration.analytics_fetch_failed', { userId });
            return next(new AppError('Failed to fetch analytics', 500));
        }
    });

    /**
     * Share duration
     * POST /api/v1/durations/:userId/:id/share
     */
    shareDuration = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { platform } = req.body;

        // Apply rate limiting
        await shareDurationLimiter(req, res, () => { });

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const duration = await Duration.findOne({ _id: id, userId }).session(session);
            if (!duration) {
                return next(new AppError('Duration not found', 404));
            }

            // Validate access
            if (!this.checkDurationAccess(duration, requestingUserId, req.user.isAdmin)) {
                return next(new AppError('Access denied', 403));
            }

            // Generate shareable link
            const shareLink = this.generateShareableLink(duration, platform);

            // Track share
            duration.analytics.shares.total += 1;
            duration.analytics.shares.byPlatform = {
                ...duration.analytics.shares.byPlatform,
                [platform]: (duration.analytics.shares.byPlatform[platform] || 0) + 1,
            };
            await duration.save({ session });

            // Clear cache
            await cacheService.deletePattern(`duration:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('duration.shared', { userId, platform });
            logger.info(`Duration ${id} shared on ${platform} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Duration shared successfully',
                data: { shareLink },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Share failed for duration ${id}:`, error);
            metricsCollector.increment('duration.share_failed', { userId });
            return next(new AppError('Failed to share duration', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Endorse duration
     * POST /api/v1/durations/:userId/:id/endorse
     */
    endorseDuration = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const duration = await Duration.findOne({ _id: id, userId }).session(session);
            if (!duration) {
                return next(new AppError('Duration not found', 404));
            }

            // Validate connection level
            const isConnected = await this.durationService.checkConnectionLevel(userId, requestingUserId);
            if (!isConnected) {
                return next(new AppError('Must be connected to endorse', 403));
            }

            // Check if already endorsed
            if (duration.endorsements.some((e) => e.userId.toString() === requestingUserId)) {
                return next(new AppError('Duration already endorsed by this user', 409));
            }

            // Add endorsement
            duration.endorsements.push({
                userId: requestingUserId,
                endorsedAt: new Date(),
            });
            await duration.save({ session });

            // Notify user
            this.notificationService.notifyUser(userId, {
                type: 'endorsement',
                message: `Your duration was endorsed`,
                data: { durationId: id, endorserId: requestingUserId },
            }).catch((err) => logger.error(`Notification failed for endorsement ${id}:`, err));

            // Clear cache
            await cacheService.deletePattern(`duration:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('duration.endorsed', { userId, endorserId: requestingUserId });
            logger.info(`Duration ${id} endorsed in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Duration endorsed successfully',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Endorsement failed for duration ${id}:`, error);
            metricsCollector.increment('duration.endorse_failed', { userId });
            return next(new AppError('Failed to endorse duration', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Search durations
     * GET /api/v1/durations/search
     */
    searchDurations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { query, page = 1, limit = 20, filters = {} } = req.query;

        const cacheKey = `search:durations:${query}:${JSON.stringify(filters)}:${page}:${limit}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('duration.search_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const searchResults = await this.durationService.searchDurations(query, filters, {
                page: parseInt(page),
                limit: parseInt(limit),
            });

            const result = {
                durations: searchResults.hits,
                totalCount: searchResults.total,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    totalPages: Math.ceil(searchResults.total / parseInt(limit)),
                },
            };

            await cacheService.set(cacheKey, result, 300);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('duration.searched', { query, count: searchResults.hits.length });
            logger.info(`Search returned ${searchResults.hits.length} durations in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Search failed for query ${query}:`, error);
            metricsCollector.increment('duration.search_failed');
            return next(new AppError('Failed to search durations', 500));
        }
    });

    /**
     * Export durations as CSV
     * GET /api/v1/durations/:userId/export
     */
    exportDurations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { format = 'csv', fields = 'startDate,endDate,description,status' } = req.query;

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        try {
            const durations = await Duration.find({ userId, status: { $ne: 'deleted' } })
                .read('secondaryPreferred')
                .select(fields.split(',').join(' '))
                .lean();

            const csvData = this.convertToCSV(durations, fields.split(','));
            const filename = `durations_${userId}_${Date.now()}.csv`;

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('duration.exported', { userId, format });
            logger.info(`Exported ${durations.length} durations for user ${userId} in ${responseTime}ms`);

            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            return res.send(csvData);
        } catch (error) {
            logger.error(`Export failed for user ${userId}:`, error);
            metricsCollector.increment('duration.export_failed', { userId });
            return next(new AppError('Failed to export durations', 500));
        }
    });

    // Helper Methods

    /**
     * Process new duration asynchronously
     */
    async processNewDurationAsync(durationId, userId) {
        try {
            const session = await mongoose.startSession();
            session.startTransaction();

            const duration = await Duration.findById(durationId).session(session);
            if (!duration) {
                await session.abortTransaction();
                session.endSession();
                return;
            }

            // Extract keywords
            const keywords = await this.durationService.extractKeywords(duration.description);
            duration.keywords = keywords.slice(0, 20);

            // Index for search
            await this.durationService.indexForSearch(duration);

            // Update user stats
            await this.durationService.updateUserStats(userId, { session });

            await duration.save({ session });
            await session.commitTransaction();
            logger.info(`Async processing completed for duration ${durationId}`);
        } catch (error) {
            logger.error(`Async processing failed for duration ${durationId}:`, error);
        } finally {
            session.endSession();
        }
    }

    /**
     * Check access permissions
     */
    checkDurationAccess(duration, requestingUserId, isAdmin) {
        if (isAdmin) return true;
        if (duration.userId.toString() === requestingUserId) return true;
        if (duration.visibility === 'public') return true;
        return false;
    }

    /**
     * Get allowed update fields
     */
    getAllowedUpdateFields() {
        return ['startDate', 'endDate', 'description', 'visibility', 'status', 'tags'];
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
    processAnalyticsData(duration, timeframe, metrics) {
        const analytics = duration.analytics || {};
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
            filteredAnalytics.metadata = duration.metadata;
        }

        return filteredAnalytics;
    }

    /**
     * Get user limits
     */
    getUserLimits(accountType) {
        const limits = {
            free: { maxDurations: 10 },
            premium: { maxDurations: 50 },
            enterprise: { maxDurations: 200 },
        };
        return limits[accountType] || limits.free;
    }

    /**
     * Build query for fetching durations
     */
    buildDurationQuery({ userId, status, startDate, endDate, search, tags }) {
        const query = { userId, status: { $ne: 'deleted' } };
        if (status && status !== 'all') query.status = status;
        if (startDate || endDate) {
            query.startDate = {};
            if (startDate) query.startDate.$gte = new Date(startDate);
            if (endDate) query.startDate.$lte = new Date(endDate);
        }
        if (search) query.$text = { $search: search };
        if (tags) {
            const tagArray = tags.split(',').map((tag) => tag.trim().toLowerCase());
            query.tags = { $in: tagArray };
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
            startDate: { startDate: 1 },
            durationLength: { $subtract: ['$endDate', '$startDate'] },
        };
        return sortOptions[sortBy] || sortOptions.recent;
    }

    /**
     * Get select fields
     */
    getSelectFields(includeAnalytics) {
        const baseFields = 'startDate endDate description status tags visibility createdAt updatedAt';
        return includeAnalytics ? baseFields + ' analytics' : baseFields;
    }

    /**
     * Process duration data
     */
    async processDurationData(duration, includeAnalytics = false) {
        const processed = { ...duration };
        if (!includeAnalytics) delete processed.analytics;
        return processed;
    }

    /**
     * Generate shareable link
     */
    generateShareableLink(duration, platform) {
        const baseUrl = process.env.APP_URL || 'https://app.example.com';
        return `${baseUrl}/durations/${duration._id}/share?platform=${platform}`;
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
                message = 'Durations moved to trash';
                break;
            case 'updateStatus':
                if (!data.status) {
                    throw new AppError('Status is required', 400);
                }
                updateData = {
                    status: data.status,
                    updatedAt: new Date(),
                    'metadata.lastModifiedBy': {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = `Status updated to ${data.status}`;
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
            default:
                throw new AppError('Invalid operation', 400);
        }

        const result = await Duration.updateMany(query, updateData, options);
        return { message, result };
    }

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

export default new DurationController();