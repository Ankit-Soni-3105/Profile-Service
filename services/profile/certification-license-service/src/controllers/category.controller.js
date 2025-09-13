import Category from '../models/Category.js';
import CategoryService from '../services/CategoryService.js';
import VerificationService from '../services/VerificationService.js';
import NotificationService from '../services/NotificationService.js';
import MediaService from '../services/MediaService.js';
import AnalyticsService from '../services/AnalyticsService.js';
import { validateCategory, validateBulkCategories, validateSearch, sanitizeInput } from '../validations/category.validation.js';
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
const createCategoryLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // 10 creates per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_category_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const updateCategoryLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 20, // 20 updates per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_category_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const mediaUploadLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 10, // 10 media uploads per 10 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `media_category_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const bulkOperationLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 5, // 5 bulk operations per 30 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_category_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const searchLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 50, // 50 searches per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `search_category_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

class CategoryController {
    constructor() {
        this.categoryService = CategoryService;
        this.verificationService = VerificationService;
        this.notificationService = NotificationService;
        this.mediaService = MediaService;
        this.analyticsService = AnalyticsService;
    }

    /**
     * Create a new category
     * POST /api/v1/categories
     */
    createCategory = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const categoryData = req.body;
        const requestingUserId = req.user.id;

        await createCategoryLimiter(req, res, () => { });

        const validation = validateCategory(categoryData);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        const sanitizedData = this.sanitizeInput(categoryData);
        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const category = await this.categoryService.createCategory({
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
            this.processCategoryAsync(category._id, requestingUserId, 'create')
                .catch((err) => logger.error(`Async processing failed for category ${category._id}:`, err));

            // Create backup
            await this.createBackup(category._id, 'create', requestingUserId, { session });

            eventEmitter.emit('category.created', {
                categoryId: category._id,
                userId: requestingUserId,
                name: category.name,
            });

            metricsCollector.increment('category.created', { userId: requestingUserId });
            await session.commitTransaction();
            logger.info(`Category created: ${category._id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Category created successfully',
                data: {
                    id: category._id,
                    name: category.name,
                    status: category.status,
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Category creation failed for user ${requestingUserId}:`, error);
            metricsCollector.increment('category.create_failed', { userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get category by ID
     * GET /api/v1/categories/:id
     */
    getCategoryById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;
        const cacheKey = `category:${id}:${requestingUserId}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('category.cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const category = await this.categoryService.getCategoryById(id, requestingUserId);
            if (!category) {
                return next(new AppError('Category not found', 404));
            }

            await this.analyticsService.incrementView(id, 'category', requestingUserId);
            await cacheService.set(cacheKey, category, 600);
            metricsCollector.increment('category.fetched', { id, userId: requestingUserId });
            logger.info(`Fetched category ${id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, { data: category });
        } catch (error) {
            logger.error(`Failed to fetch category ${id}:`, error);
            metricsCollector.increment('category.fetch_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        }
    });

    /**
     * Update category
     * PUT /api/v1/categories/:id
     */
    updateCategory = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const updates = req.body;
        const requestingUserId = req.user.id;

        await updateCategoryLimiter(req, res, () => { });

        const validation = validateCategory(updates, true);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const sanitizedUpdates = this.sanitizeUpdates(updates);
            const category = await this.categoryService.updateCategory(id, requestingUserId, sanitizedUpdates, {
                session,
                requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
            });

            this.processCategoryAsync(id, requestingUserId, 'update')
                .catch((err) => logger.error(`Async processing failed for category ${id}:`, err));

            await this.createBackup(id, 'update', requestingUserId, { session });
            await cacheService.deletePattern(`category:${id}:*`);

            eventEmitter.emit('category.updated', {
                categoryId: id,
                userId: requestingUserId,
                changes: Object.keys(sanitizedUpdates),
            });

            metricsCollector.increment('category.updated', { id, userId: requestingUserId });
            await session.commitTransaction();
            logger.info(`Category updated: ${id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Category updated successfully',
                data: {
                    id,
                    name: category.name,
                    status: category.status,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Category update failed for ${id}:`, error);
            metricsCollector.increment('category.update_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete category
     * DELETE /api/v1/categories/:id
     */
    deleteCategory = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const { permanent = false } = req.query;
        const requestingUserId = req.user.id;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            await this.categoryService.deleteCategory(id, requestingUserId, permanent, { session });
            await cacheService.deletePattern(`category:${id}:*`);

            eventEmitter.emit('category.deleted', {
                categoryId: id,
                userId: requestingUserId,
                permanent,
            });

            metricsCollector.increment(permanent ? 'category.permanently_deleted' : 'category.soft_deleted', {
                id,
                userId: requestingUserId,
            });
            await session.commitTransaction();
            logger.info(`Category ${id} deleted (permanent: ${permanent}) in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: `Category ${permanent ? 'permanently' : 'soft'} deleted successfully`,
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Category deletion failed for ${id}:`, error);
            metricsCollector.increment('category.delete_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Upload media for category
     * POST /api/v1/categories/:id/media
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

            const category = await Category.findById(id).session(session);
            if (!category) {
                return next(new AppError('Category not found', 404));
            }

            const validation = this.categoryService.validateMediaUpload(files, category.media || []);
            if (!validation.valid) {
                return next(new AppError(validation.message, 422));
            }

            const mediaResults = await this.mediaService.uploadMedia({
                files,
                entityId: id,
                entityType: 'category',
                userId: requestingUserId,
            }, { session });

            category.media = category.media || [];
            category.media.push(...mediaResults);
            await category.save({ session });

            await cacheService.deletePattern(`category:${id}:*`);

            eventEmitter.emit('category.media_uploaded', {
                categoryId: id,
                userId: requestingUserId,
                mediaCount: mediaResults.length,
            });

            metricsCollector.increment('category.media_uploaded', { id, count: mediaResults.length });
            await session.commitTransaction();
            logger.info(`Uploaded ${mediaResults.length} media for category ${id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Media uploaded successfully',
                data: { media: mediaResults },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Media upload failed for category ${id}:`, error);
            metricsCollector.increment('category.media_upload_failed', { id });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get categories with filtering and pagination
     * GET /api/v1/categories
     */
    getCategories = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { page = 1, limit = 20, status, parentId, search, sortBy = 'recent' } = req.query;
        const requestingUserId = req.user.id;
        const cacheKey = `categories:${requestingUserId}:${JSON.stringify({ page, limit, status, parentId, search, sortBy })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('category.cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const query = this.buildCategoryQuery({ status, parentId, search });
            const sortOption = this.buildSortOption(sortBy);
            const pageNum = Math.max(1, parseInt(page));
            const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
            const skip = (pageNum - 1) * limitNum;

            const [categories, totalCount] = await Promise.all([
                Category.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select('name icon description parentId verification status createdAt analytics')
                    .lean(),
                Category.countDocuments(query).cache({ ttl: 300, key: `category_count_${requestingUserId}` }),
            ]);

            const processedCategories = categories.map((category) => ({
                ...category,
                isVerified: category.verification?.status === 'verified',
            }));

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                categories: processedCategories,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages,
                    hasNext: pageNum < totalPages,
                    hasPrev: pageNum > 1,
                },
                filters: { status, parentId, search, sortBy },
            };

            await cacheService.set(cacheKey, result, 300);
            metricsCollector.increment('category.fetched', { count: categories.length, userId: requestingUserId });
            logger.info(`Fetched ${categories.length} categories in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch categories:`, error);
            metricsCollector.increment('category.fetch_failed', { userId: requestingUserId });
            return next(this.handleError(error));
        }
    });

    /**
     * Search categories
     * GET /api/v1/categories/search
     */
    searchCategories = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { query, filters = {}, page = 1, limit = 20 } = req.body;
        const requestingUserId = req.user.id;

        await searchLimiter(req, res, () => { });

        const validation = validateSearch({ query, filters });
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        const cacheKey = `category_search:${requestingUserId}:${JSON.stringify({ query, filters, page, limit })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('category.search_cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const result = await this.categoryService.searchCategories(query, filters, { page, limit });
            await cacheService.set(cacheKey, result, 300);

            metricsCollector.increment('category.searched', { count: result.hits.length, userId: requestingUserId });
            logger.info(`Search returned ${result.hits.length} categories in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Search completed successfully',
                data: result,
            });
        } catch (error) {
            logger.error(`Search failed for query ${query}:`, error);
            metricsCollector.increment('category.search_failed', { userId: requestingUserId });
            return next(new AppError('Failed to search categories', 500));
        }
    });

    /**
     * Get trending categories
     * GET /api/v1/categories/trending
     */
    getTrendingCategories = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { timeframe = '30d', parentId, limit = 20 } = req.query;
        const requestingUserId = req.user.id;
        const cacheKey = `trending_categories:${requestingUserId}:${timeframe}:${parentId || 'all'}:${limit}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('category.trending_cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const categories = await this.categoryService.getTrendingCategories(timeframe, parentId, parseInt(limit));
            await cacheService.set(cacheKey, categories, 300);

            metricsCollector.increment('category.trending_fetched', { count: categories.length, userId: requestingUserId });
            logger.info(`Fetched ${categories.length} trending categories in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Trending categories fetched successfully',
                data: categories,
            });
        } catch (error) {
            logger.error(`Failed to fetch trending categories:`, error);
            metricsCollector.increment('category.trending_fetch_failed', { userId: requestingUserId });
            return next(new AppError('Failed to fetch trending categories', 500));
        }
    });

    /**
     * Bulk create categories
     * POST /api/v1/categories/bulk
     */
    bulkCreateCategories = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const categoriesData = req.body.categories;
        const requestingUserId = req.user.id;

        await bulkOperationLimiter(req, res, () => { });

        const validation = validateBulkCategories(categoriesData);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const sanitizedData = categoriesData.map((category) => this.sanitizeInput(category));
            const createdCategories = await Promise.all(
                sanitizedData.map((category) =>
                    this.categoryService.createCategory({
                        ...category,
                        metadata: {
                            ...category.metadata,
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

            createdCategories.forEach((category) => {
                this.processCategoryAsync(category._id, requestingUserId, 'create')
                    .catch((err) => logger.error(`Async processing failed for category ${category._id}:`, err));
            });

            await Promise.all(
                createdCategories.map((category) =>
                    this.createBackup(category._id, 'create', requestingUserId, { session })
                )
            );

            eventEmitter.emit('category.bulk_created', {
                categoryIds: createdCategories.map((category) => category._id),
                userId: requestingUserId,
            });

            metricsCollector.increment('category.bulk_created', { count: createdCategories.length, userId: requestingUserId });
            await session.commitTransaction();
            logger.info(`Bulk created ${createdCategories.length} categories in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Categories created successfully',
                data: createdCategories.map((category) => ({
                    id: category._id,
                    name: category.name,
                    status: category.status,
                })),
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk category creation failed:`, error);
            metricsCollector.increment('category.bulk_create_failed', { userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Bulk update categories
     * PUT /api/v1/categories/bulk
     */
    bulkUpdateCategories = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const updates = req.body.updates;
        const requestingUserId = req.user.id;

        await bulkOperationLimiter(req, res, () => { });

        const validation = validateBulkCategories(updates);
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

            const updatedCategories = await Promise.all(
                sanitizedUpdates.map(({ id, data }) =>
                    this.categoryService.updateCategory(id, requestingUserId, data, {
                        session,
                        requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                    })
                )
            );

            await Promise.all(
                updatedCategories.map((category) => {
                    this.processCategoryAsync(category._id, requestingUserId, 'update')
                        .catch((err) => logger.error(`Async processing failed for category ${category._id}:`, err));
                    return this.createBackup(category._id, 'update', requestingUserId, { session });
                })
            );

            await Promise.all(
                updatedCategories.map((category) => cacheService.deletePattern(`category:${category._id}:*`))
            );

            eventEmitter.emit('category.bulk_updated', {
                categoryIds: updatedCategories.map((category) => category._id),
                userId: requestingUserId,
            });

            metricsCollector.increment('category.bulk_updated', { count: updatedCategories.length, userId: requestingUserId });
            await session.commitTransaction();
            logger.info(`Bulk updated ${updatedCategories.length} categories in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Categories updated successfully',
                data: updatedCategories.map((category) => ({
                    id: category._id,
                    name: category.name,
                    status: category.status,
                })),
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk category update failed:`, error);
            metricsCollector.increment('category.bulk_update_failed', { userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get category analytics
     * GET /api/v1/categories/:id/analytics
     */
    getCategoryAnalytics = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const { timeframe = '30d' } = req.query;
        const requestingUserId = req.user.id;
        const cacheKey = `category_analytics:${id}:${timeframe}:${requestingUserId}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('category.analytics_cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const analytics = await this.analyticsService.getCategoryAnalytics(id, timeframe);
            await cacheService.set(cacheKey, analytics, 300);

            metricsCollector.increment('category.analytics_fetched', { id, userId: requestingUserId });
            logger.info(`Fetched analytics for category ${id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Category analytics fetched successfully',
                data: analytics,
            });
        } catch (error) {
            logger.error(`Failed to fetch analytics for category ${id}:`, error);
            metricsCollector.increment('category.analytics_fetch_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        }
    });

    /**
     * Export category data
     * GET /api/v1/categories/:id/export
     */
    exportCategory = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const { format = 'json' } = req.query;
        const requestingUserId = req.user.id;

        try {
            const category = await Category.findById(id)
                .select('name icon description parentId verification status analytics metadata')
                .lean();

            if (!category) {
                return next(new AppError('Category not found', 404));
            }

            let exportData;
            let contentType;
            let extension;

            switch (format.toLowerCase()) {
                case 'json':
                    exportData = JSON.stringify(category, null, 2);
                    contentType = 'application/json';
                    extension = 'json';
                    break;
                case 'csv':
                    exportData = this.convertToCSV(category);
                    contentType = 'text/csv';
                    extension = 'csv';
                    break;
                default:
                    return next(new AppError('Unsupported export format', 400));
            }

            const exportKey = `category_export_${id}_${uuidv4()}.${extension}`;
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

            metricsCollector.increment('category.exported', { id, format, userId: requestingUserId });
            logger.info(`Exported category ${id} as ${format} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Category exported successfully',
                data: { url: signedUrl },
            });
        } catch (error) {
            logger.error(`Export failed for category ${id}:`, error);
            metricsCollector.increment('category.export_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        }
    });

    /**
     * Get category statistics
     * GET /api/v1/categories/:id/stats
     */
    getCategoryStats = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;
        const cacheKey = `category_stats:${id}:${requestingUserId}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('category.stats_cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const stats = await this.categoryService.getCategoryStats(id);
            await cacheService.set(cacheKey, stats, 3600);

            metricsCollector.increment('category.stats_fetched', { id, userId: requestingUserId });
            logger.info(`Fetched stats for category ${id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Category stats fetched successfully',
                data: stats,
            });
        } catch (error) {
            logger.error(`Failed to fetch stats for category ${id}:`, error);
            metricsCollector.increment('category.stats_fetch_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        }
    });

    /**
     * Archive category
     * POST /api/v1/categories/:id/archive
     */
    archiveCategory = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const category = await Category.findById(id).session(session);
            if (!category) {
                return next(new AppError('Category not found', 404));
            }

            category.status.isActive = false;
            category.status.isArchived = true;
            category.status.archivedAt = new Date();
            await category.save({ session });

            await cacheService.deletePattern(`category:${id}:*`);

            eventEmitter.emit('category.archived', {
                categoryId: id,
                userId: requestingUserId,
            });

            metricsCollector.increment('category.archived', { id, userId: requestingUserId });
            await session.commitTransaction();
            logger.info(`Category ${id} archived in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Category archived successfully',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Archiving failed for category ${id}:`, error);
            metricsCollector.increment('category.archive_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Restore category
     * POST /api/v1/categories/:id/restore
     */
    restoreCategory = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const requestingUserId = req.user.id;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const category = await Category.findById(id).session(session);
            if (!category) {
                return next(new AppError('Category not found', 404));
            }

            category.status.isActive = true;
            category.status.isArchived = false;
            category.status.restoredAt = new Date();
            await category.save({ session });

            await cacheService.deletePattern(`category:${id}:*`);

            eventEmitter.emit('category.restored', {
                categoryId: id,
                userId: requestingUserId,
            });

            metricsCollector.increment('category.restored', { id, userId: requestingUserId });
            await session.commitTransaction();
            logger.info(`Category ${id} restored in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Category restored successfully',
                data: {
                    id,
                    name: category.name,
                    status: category.status,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Restoring failed for category ${id}:`, error);
            metricsCollector.increment('category.restore_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get category audit logs
     * GET /api/v1/categories/:id/audit
     */
    getAuditLogs = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { id } = req.params;
        const { page = 1, limit = 20, action } = req.query;
        const requestingUserId = req.user.id;
        const cacheKey = `category_audit:${id}:${page}:${limit}:${action || 'all'}:${requestingUserId}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('category.audit_cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            const pageNum = Math.max(1, parseInt(page));
            const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
            const skip = (pageNum - 1) * limitNum;

            const query = { categoryId: id };
            if (action) query.action = action;

            const [logs, totalCount] = await Promise.all([
                this.categoryService.getAuditLogs(id, { page: pageNum, limit: limitNum, action }),
                this.categoryService.countAuditLogs(id, action),
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
            metricsCollector.increment('category.audit_fetched', { count: logs.length, userId: requestingUserId });
            logger.info(`Fetched ${logs.length} audit logs for category ${id} in ${Date.now() - startTime}ms`);

            return ApiResponse.success(res, {
                message: 'Audit logs fetched successfully',
                data: result,
            });
        } catch (error) {
            logger.error(`Failed to fetch audit logs for category ${id}:`, error);
            metricsCollector.increment('category.audit_fetch_failed', { id, userId: requestingUserId });
            return next(this.handleError(error));
        }
    });

    /**
     * Create backup of category
     * @param {string} categoryId - Category ID
     * @param {string} action - Action type
     * @param {string} userId - User ID
     * @param {Object} options - Additional options
     */
    async createBackup(categoryId, action, userId, options = {}) {
        const startTime = Date.now();
        try {
            const category = await Category.findById(categoryId).lean();
            if (!category) {
                throw new AppError('Category not found', 404);
            }

            const backupKey = `category_backup_${categoryId}_${Date.now()}_${uuidv4()}`;
            await s3.upload({
                Bucket: process.env.S3_BACKUP_BUCKET,
                Key: backupKey,
                Body: JSON.stringify({
                    category,
                    action,
                    userId,
                    timestamp: new Date(),
                }),
                ContentType: 'application/json',
                ServerSideEncryption: 'AES256',
            }).promise();

            metricsCollector.increment('category.backup_created', { userId, action });
            logger.info(`Backup created for category ${categoryId} (${action}) in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to create backup for category ${categoryId}:`, error);
            metricsCollector.increment('category.backup_failed', { userId });
            throw error;
        }
    }

    /**
     * Process category asynchronously
     * @param {string} categoryId - Category ID
     * @param {string} userId - User ID
     * @param {string} action - Action type
     */
    async processCategoryAsync(categoryId, userId, action) {
        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const category = await Category.findById(categoryId).session(session);
            if (!category) {
                throw new AppError('Category not found', 404);
            }

            await this.categoryService.indexForSearch(category);
            await this.analyticsService.updateCategoryAnalytics(categoryId, { session });

            await session.commitTransaction();
            logger.info(`Async processing completed for category ${categoryId} (${action})`);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Async processing failed for category ${categoryId}:`, error);
            metricsCollector.increment('category.async_processing_failed', { categoryId });
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
            return new AppError('Category already exists', 409);
        }
        if (error.name === 'CastError') {
            return new AppError('Invalid category ID', 400);
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
            icon: data.icon ? sanitizeHtml(data.icon) : undefined,
        };
    }

    /**
     * Sanitize updates
     * @param {Object} updates - Update data
     * @returns {Object} - Sanitized updates
     */
    sanitizeUpdates(updates) {
        const allowedFields = ['name', 'icon', 'description', 'status', 'parentId'];
        const sanitized = {};
        allowedFields.forEach((field) => {
            if (updates[field] !== undefined) {
                sanitized[field] = ['name', 'description'].includes(field)
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
    buildCategoryQuery({ status, parentId, search }) {
        const query = { 'status.isDeleted': false };
        if (status) query['status.workflow'] = status;
        if (parentId) query.parentId = parentId;
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
     * Convert category to CSV
     * @param {Object} category - Category data
     * @returns {string} - CSV string
     */
    convertToCSV(category) {
        const headers = ['id', 'name', 'parentId', 'verification_status', 'created_at'];
        const row = [
            category._id,
            `"${category.name.replace(/"/g, '""')}"`,
            category.parentId || '',
            category.verification?.status || 'pending',
            category.createdAt,
        ];
        return [headers.join(','), row.join(',')].join('\n');
    }
}

export default new CategoryController();