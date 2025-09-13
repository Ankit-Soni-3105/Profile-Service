import SkillCategory from '../models/SkillCategory.js';
import Skill from '../models/Skill.js';
import SkillTrend from '../models/SkillTrend.js';
import SkillDemand from '../models/SkillDemand.js';
import CategoryService from '../services/CategoryService.js';
import VerificationService from '../services/VerificationService.js';
import MediaService from '../services/MediaService.js';
import NotificationService from '../services/NotificationService.js';
import { validateCategory, sanitizeInput } from '../validations/category.validation.js';
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
const createCategoryLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 15, // 15 creates per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_category_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const updateCategoryLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 25, // 25 updates per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_category_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const verificationLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 5, // 5 verification requests per 30 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `verify_category_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const bulkOperationsLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // 3 bulk operations per hour
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_category_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const mediaUploadLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 10, // 10 media uploads per 10 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `media_category_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

class CategoryController {
    constructor() {
        this.categoryService = new CategoryService();
        this.verificationService = new VerificationService();
        this.mediaService = new MediaService();
        this.notificationService = new NotificationService();
    }

    /**
     * Create a new category
     * POST /api/v1/categories/:userId
     */
    createCategory = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const categoryData = req.body;
        const requestingUserId = req.user.id;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied: Cannot create category for another user', 403));
        }

        await createCategoryLimiter(req, res, () => { });

        const validation = validateCategory(categoryData);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        const sanitizedData = sanitizeInput(categoryData);

        const userCategoryCount = await SkillCategory.countDocuments({
            userId,
            'status.isDeleted': false,
        }).cache({ ttl: 300, key: `user_category_count_${userId}` });

        const limits = this.getUserLimits(req.user.accountType);
        if (userCategoryCount >= limits.maxCategories) {
            return next(new AppError(`Category limit reached (${limits.maxCategories})`, 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const category = await this.categoryService.createCategory({
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

            this.processNewCategoryAsync(category._id, requestingUserId)
                .catch((err) => logger.error(`Async processing failed for category ${category._id}:`, err));

            metricsCollector.increment('category.created', {
                userId,
                type: category.type,
            });

            eventEmitter.emit('category.created', {
                categoryId: category._id,
                userId,
                type: category.type,
            });

            if (category.settings?.autoBackup) {
                this.categoryService.createBackup(category._id, 'create', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for category ${category._id}:`, err));
            }

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`Category created successfully: ${category._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Category created successfully',
                data: {
                    id: category._id,
                    userId: category.userId,
                    name: category.name,
                    status: category.status,
                    createdAt: category.createdAt,
                    processingStatus: 'started',
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Category creation failed for user ${userId}:`, error);
            metricsCollector.increment('category.create_failed', { userId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.code === 11000) {
                return next(new AppError('Category with this name already exists', 409));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out', 504));
            }
            return next(new AppError('Failed to create category', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get user's categories with filtering and pagination
     * GET /api/v1/categories/:userId
     */
    getCategories = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const {
            page = 1,
            limit = 20,
            status,
            type,
            search,
            sortBy = 'recent',
            tags,
            includeAnalytics = 'false',
        } = req.query;

        const query = this.buildCategoryQuery({
            userId,
            status,
            type,
            search,
            tags,
        });

        const sortOption = this.buildSortOption(sortBy);
        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
        const skip = (pageNum - 1) * limitNum;

        const cacheKey = `categories:${userId}:${JSON.stringify({
            page: pageNum,
            limit: limitNum,
            status,
            type,
            search,
            sortBy,
            tags,
        })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('category.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const [categories, totalCount] = await Promise.all([
                SkillCategory.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select(this.getSelectFields(includeAnalytics === 'true'))
                    .lean(),
                SkillCategory.countDocuments(query).cache({ ttl: 300, key: `category_count_${userId}` }),
            ]);

            const processedCategories = await Promise.all(
                categories.map((category) => this.processCategoryData(category, includeAnalytics === 'true')),
            );

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
                    nextPage: pageNum < totalPages ? pageNum + 1 : null,
                    prevPage: pageNum > 1 ? pageNum - 1 : null,
                },
                filters: {
                    status: status || 'all',
                    type: type || 'all',
                    sortBy,
                    search: search || null,
                },
            };

            await cacheService.set(cacheKey, result, 300);
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('category.fetched', {
                userId,
                count: categories.length,
                cached: false,
            });
            logger.info(`Fetched ${categories.length} categories for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch categories for user ${userId}:`, error);
            metricsCollector.increment('category.fetch_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid query parameters', 400));
            }
            return next(new AppError('Failed to fetch categories', 500));
        }
    });

    /**
     * Get single category by ID
     * GET /api/v1/categories/:userId/:id
     */
    getCategoryById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { includeAnalytics = 'false', includeVerification = 'false' } = req.query;

        try {
            const cacheKey = `category:${id}:${userId}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('category.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const category = await SkillCategory.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .cache({ ttl: 600, key: cacheKey });

            if (!category) {
                return next(new AppError('Category not found', 404));
            }

            const hasAccess = this.checkCategoryAccess(category, requestingUserId, req.user.isAdmin);
            if (!hasAccess) {
                return next(new AppError('Access denied', 403));
            }

            if (requestingUserId !== userId) {
                category.analytics.viewCount += 1;
                category.analytics.lastViewed = new Date();
                await category.save();
            }

            const responseData = this.processCategoryData(category.toObject(), includeAnalytics === 'true', includeVerification === 'true');

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('category.viewed', {
                userId,
                viewerId: requestingUserId,
                isOwner: userId === requestingUserId,
            });
            logger.info(`Fetched category ${id} for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: responseData });
        } catch (error) {
            logger.error(`Failed to fetch category ${id}:`, error);
            metricsCollector.increment('category.view_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid category ID', 400));
            }
            return next(new AppError('Failed to fetch category', 500));
        }
    });

    /**
     * Update category
     * PUT /api/v1/categories/:userId/:id
     */
    updateCategory = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const updates = req.body;

        await updateCategoryLimiter(req, res, () => { });

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const category = await SkillCategory.findOne({ _id: id, userId }).session(session);
            if (!category) {
                return next(new AppError('Category not found', 404));
            }

            const allowedUpdates = this.getAllowedUpdateFields();
            const sanitizedUpdates = this.sanitizeUpdates(updates, allowedUpdates);

            if (Object.keys(sanitizedUpdates).length === 0) {
                return next(new AppError('No valid update fields provided', 400));
            }

            let versionCreated = false;
            if (sanitizedUpdates.description && sanitizedUpdates.description !== category.description) {
                await category.createVersion(sanitizedUpdates.description, sanitizedUpdates.name || category.name, 'edit', {
                    userId: requestingUserId,
                }, { session });
                versionCreated = true;
            }

            Object.assign(category, sanitizedUpdates);

            category.metadata.lastModifiedBy = {
                userId: requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date(),
            };

            if (sanitizedUpdates.type || sanitizedUpdates.name) {
                category.verification.status = 'pending';
                this.processExternalVerification(category._id, requestingUserId)
                    .catch((err) => logger.error(`Re-verification failed for category ${id}:`, err));
            }

            await category.save({ session });

            if (sanitizedUpdates.description) {
                await category.calculateQualityScore({ session });
            }

            if (category.settings?.autoBackup) {
                this.categoryService.createBackup(category._id, 'update', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for category ${id}:`, err));
            }

            await cacheService.deletePattern(`category:${id}:*`);
            await cacheService.deletePattern(`categories:${userId}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('category.updated', {
                userId,
                versionCreated,
                fieldsUpdated: Object.keys(sanitizedUpdates).length,
            });

            eventEmitter.emit('category.updated', {
                categoryId: category._id,
                userId,
                changes: Object.keys(sanitizedUpdates),
                versionCreated,
            });

            logger.info(`Category updated successfully: ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Category updated successfully',
                data: {
                    id: category._id,
                    name: category.name,
                    status: category.status,
                    updatedAt: category.updatedAt,
                    versionCreated,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Category update failed for ${id}:`, error);
            metricsCollector.increment('category.update_failed', { userId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out', 504));
            }
            return next(new AppError('Failed to update category', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete category (soft or permanent)
     * DELETE /api/v1/categories/:userId/:id
     */
    deleteCategory = catchAsync(async (req, res, next) => {
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

            const category = await SkillCategory.findOne({ _id: id, userId }).session(session);
            if (!category) {
                return next(new AppError('Category not found', 404));
            }

            if (permanent === 'true') {
                await SkillCategory.findByIdAndDelete(id, { session });
                await this.mediaService.deleteAllMedia(id, 'category', { session });
                this.categoryService.deleteAllBackups(id)
                    .catch((err) => logger.error(`Failed to delete backups for ${id}:`, err));
                metricsCollector.increment('category.permanently_deleted', { userId });
            } else {
                category.status.isDeleted = true;
                category.status.deletedAt = new Date();
                category.metadata.lastModifiedBy = {
                    userId: requestingUserId,
                    ip: req.ip,
                    userAgent: req.get('User-Agent'),
                    timestamp: new Date(),
                };
                await category.save({ session });
                metricsCollector.increment('category.soft_deleted', { userId });
            }

            await cacheService.deletePattern(`category:${id}:*`);
            await cacheService.deletePattern(`categories:${userId}:*`);

            eventEmitter.emit('category.deleted', {
                categoryId: id,
                userId,
                permanent: permanent === 'true',
            });

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`Category ${id} deleted (permanent: ${permanent}) in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: permanent === 'true' ? 'Category permanently deleted' : 'Category moved to trash',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Category deletion failed for ${id}:`, error);
            metricsCollector.increment('category.delete_failed', { userId });
            return next(new AppError('Failed to delete category', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Bulk operations on categories
     * POST /api/v1/categories/:userId/bulk
     */
    bulkOperations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { operation, categoryIds, data = {} } = req.body;

        await bulkOperationsLimiter(req, res, () => { });

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        if (!Array.isArray(categoryIds) || categoryIds.length === 0) {
            return next(new AppError('Category IDs array is required', 400));
        }
        if (categoryIds.length > 100) {
            return next(new AppError('Maximum 100 categories can be processed at once', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const query = { _id: { $in: categoryIds }, userId };
            const { message } = await this.handleBulkOperation(operation, query, data, requestingUserId, req, { session });

            await Promise.all([
                cacheService.deletePattern(`categories:${userId}:*`),
                ...categoryIds.map((id) => cacheService.deletePattern(`category:${id}:*`)),
            ]);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('category.bulk_operation', {
                userId,
                operation,
                count: categoryIds.length,
            });
            logger.info(`Bulk operation ${operation} completed for ${categoryIds.length} categories in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message,
                data: {
                    operation,
                    requested: categoryIds.length,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk operation failed for user ${userId}:`, error);
            metricsCollector.increment('category.bulk_operation_failed', { userId, operation });
            return next(new AppError('Bulk operation failed', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get category analytics
     * GET /api/v1/categories/:userId/:id/analytics
     */
    getAnalytics = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { timeframe = '30d', metrics = 'basic' } = req.query;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        try {
            const cacheKey = `analytics:category:${id}:${timeframe}:${metrics}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('category.analytics_cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const category = await SkillCategory.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('analytics verification metadata createdAt')
                .cache({ ttl: 900, key: cacheKey });

            if (!category) {
                return next(new AppError('Category not found', 404));
            }

            const analytics = this.processAnalyticsData(category, timeframe, metrics);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('category.analytics_viewed', { userId });
            logger.info(`Fetched analytics for category ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: analytics });
        } catch (error) {
            logger.error(`Analytics fetch failed for ${id}:`, error);
            metricsCollector.increment('category.analytics_fetch_failed', { userId });
            return next(new AppError('Failed to fetch analytics', 500));
        }
    });

    /**
     * Duplicate category
     * POST /api/v1/categories/:userId/:id/duplicate
     */
    duplicateCategory = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { name, includeVersions = 'false' } = req.body;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const originalCategory = await SkillCategory.findOne({ _id: id, userId }).session(session);
            if (!originalCategory) {
                return next(new AppError('Category not found', 404));
            }

            const userCategoryCount = await SkillCategory.countDocuments({
                userId,
                'status.isDeleted': false,
            }).cache({ ttl: 300, key: `user_category_count_${userId}` });

            const limits = this.getUserLimits(req.user.accountType);
            if (userCategoryCount >= limits.maxCategories) {
                return next(new AppError(`Category limit reached (${limits.maxCategories})`, 403));
            }

            const duplicateData = originalCategory.toObject();
            delete duplicateData._id;
            delete duplicateData.createdAt;
            delete duplicateData.updatedAt;
            delete duplicateData.analytics;

            duplicateData.name = name || `${originalCategory.name} (Copy)`;
            duplicateData.status.isActive = true;
            duplicateData.status.isDeleted = false;
            duplicateData.metadata.createdBy = {
                userId: requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date(),
            };

            if (includeVersions !== 'true') {
                duplicateData.versions = [{
                    versionNumber: 1,
                    description: duplicateData.description,
                    name: duplicateData.name,
                    changeType: 'create',
                    isActive: true,
                }];
            }

            const duplicate = new SkillCategory(duplicateData);
            await duplicate.save({ session });

            if (duplicate.settings?.autoBackup) {
                this.categoryService.createBackup(duplicate._id, 'duplicate', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for duplicate ${duplicate._id}:`, err));
            }

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('category.duplicated', { userId });
            logger.info(`Category ${id} duplicated as ${duplicate._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Category duplicated successfully',
                data: {
                    originalId: id,
                    duplicateId: duplicate._id,
                    name: duplicate.name,
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Category duplication failed for ${id}:`, error);
            metricsCollector.increment('category.duplicate_failed', { userId });
            return next(new AppError('Failed to duplicate category', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Verify category
     * POST /api/v1/categories/:userId/:id/verify
     */
    verifyCategory = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        await verificationLimiter(req, res, () => { });

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const category = await SkillCategory.findOne({ _id: id, userId }).session(session);
            if (!category) {
                return next(new AppError('Category not found', 404));
            }

            const verificationResult = await this.processExternalVerification(category._id, requestingUserId);
            if (!verificationResult.success) {
                return next(new AppError('Verification failed: ' + verificationResult.message, 424));
            }

            category.verification = {
                status: verificationResult.status,
                confidence: verificationResult.confidence,
                verifiedBy: verificationResult.verifiedBy,
                verifiedAt: new Date(),
                details: verificationResult.details,
            };

            await category.save({ session });

            this.notificationService.notifyUser(userId, {
                type: 'verification_completed',
                message: `Category "${category.name}" verification ${verificationResult.status}`,
                data: { categoryId: id },
            }).catch((err) => logger.error(`Notification failed for category ${id}:`, err));

            await cacheService.deletePattern(`category:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('category.verified', {
                userId,
                status: verificationResult.status,
            });
            logger.info(`Category ${id} verified in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Category verification completed',
                data: category.verification,
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Verification failed for category ${id}:`, error);
            metricsCollector.increment('category.verify_failed', { userId });
            if (error.message.includes('timeout')) {
                return next(new AppError('External API timeout', 503));
            }
            return next(new AppError('Failed to verify category', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Upload media for category
     * POST /api/v1/categories/:userId/:id/media
     */
    uploadMedia = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const files = req.files;

        await mediaUploadLimiter(req, res, () => { });

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const category = await SkillCategory.findOne({ _id: id, userId }).session(session);
            if (!category) {
                return next(new AppError('Category not found', 404));
            }

            const validation = this.validateMediaUpload(files, category.media);
            if (!validation.valid) {
                return next(new AppError(validation.message, 422));
            }

            const mediaResults = await this.mediaService.uploadMedia({
                files,
                entityId: id,
                entityType: 'category',
                userId,
            }, { session });

            const scanResults = await this.mediaService.scanMedia(mediaResults);
            if (scanResults.some((result) => result.infected)) {
                return next(new AppError('Media upload failed: Infected file detected', 422));
            }

            category.media.push(...mediaResults);
            await category.save({ session });

            await cacheService.deletePattern(`category:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('category.media_uploaded', {
                userId,
                count: mediaResults.length,
            });
            logger.info(`Uploaded ${mediaResults.length} media files for category ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Media uploaded successfully',
                data: { media: mediaResults },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Media upload failed for category ${id}:`, error);
            metricsCollector.increment('category.media_upload_failed', { userId });
            return next(new AppError('Failed to upload media', 422));
        } finally {
            session.endSession();
        }
    });

    /**
     * Share category
     * POST /api/v1/categories/:userId/:id/share
     */
    shareCategory = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { platform } = req.body;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const category = await SkillCategory.findOne({ _id: id, userId }).session(session);
            if (!category) {
                return next(new AppError('Category not found', 404));
            }

            const hasAccess = this.checkCategoryAccess(category, requestingUserId, req.user.isAdmin);
            if (!hasAccess) {
                return next(new AppError('Access denied', 403));
            }

            const shareLink = this.generateShareableLink(category, platform);

            category.analytics.shares = category.analytics.shares || { total: 0, byPlatform: {} };
            category.analytics.shares.total += 1;
            category.analytics.shares.byPlatform[platform] = (category.analytics.shares.byPlatform[platform] || 0) + 1;
            await category.save({ session });

            await cacheService.deletePattern(`category:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('category.shared', { userId, platform });
            logger.info(`Category ${id} shared on ${platform} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Category shared successfully',
                data: { shareLink },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Share failed for category ${id}:`, error);
            metricsCollector.increment('category.share_failed', { userId });
            return next(new AppError('Failed to share category', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Endorse category
     * POST /api/v1/categories/:userId/:id/endorse
     */
    endorseCategory = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const category = await SkillCategory.findOne({ _id: id, userId }).session(session);
            if (!category) {
                return next(new AppError('Category not found', 404));
            }

            const isConnected = await this.categoryService.checkConnectionLevel(userId, requestingUserId);
            if (!isConnected) {
                return next(new AppError('Must be connected to endorse', 403));
            }

            if (category.endorsements.some((e) => e.userId.toString() === requestingUserId)) {
                return next(new AppError('Category already endorsed by this user', 409));
            }

            category.endorsements.push({
                userId: requestingUserId,
                endorsedAt: new Date(),
            });
            await category.save({ session });

            this.notificationService.notifyUser(userId, {
                type: 'endorsement',
                message: `Your category "${category.name}" was endorsed`,
                data: { categoryId: id, endorserId: requestingUserId },
            }).catch((err) => logger.error(`Notification failed for endorsement ${id}:`, err));

            await cacheService.deletePattern(`category:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('category.endorsed', { userId, endorserId: requestingUserId });
            logger.info(`Category ${id} endorsed in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Category endorsed successfully',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Endorsement failed for category ${id}:`, error);
            metricsCollector.increment('category.endorse_failed', { userId });
            return next(new AppError('Failed to endorse category', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get verification status
     * GET /api/v1/categories/:userId/:id/verification
     */
    getVerificationStatus = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        try {
            const cacheKey = `verification:category:${id}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('category.verification_cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const category = await SkillCategory.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('verification')
                .cache({ ttl: 60, key: cacheKey });

            if (!category) {
                return next(new AppError('Category not found', 404));
            }

            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('category.verification_viewed', { userId });
            logger.info(`Fetched verification status for category ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                data: category.verification,
            });
        } catch (error) {
            logger.error(`Verification status fetch failed for ${id}:`, error);
            metricsCollector.increment('category.verification_fetch_failed', { userId });
            return next(new AppError('Failed to fetch verification status', 500));
        }
    });

    /**
     * Get trending categories
     * GET /api/v1/categories/trending
     */
    getTrendingCategories = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { timeframe = '7d', type, limit = 20 } = req.query;

        const cacheKey = `trending:categories:${timeframe}:${type || 'all'}:${limit}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('category.trending_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const categories = await this.categoryService.getTrendingCategories(timeframe, type, parseInt(limit));
            const processedCategories = await Promise.all(
                categories.map((category) => this.processCategoryData(category, false)),
            );

            const result = { categories: processedCategories };
            await cacheService.set(cacheKey, result, 3600);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('category.trending_viewed', { count: categories.length });
            logger.info(`Fetched ${categories.length} trending categories in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch trending categories:`, error);
            metricsCollector.increment('category.trending_fetch_failed');
            return next(new AppError('Failed to fetch trending categories', 500));
        }
    });

    /**
     * Get categories by type
     * GET /api/v1/categories/types/:type
     */
    getCategoriesByType = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { type } = req.params;
        const { page = 1, limit = 20, sortBy = 'recent' } = req.query;

        const cacheKey = `categories:type:${type}:${page}:${limit}:${sortBy}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('category.type_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const query = this.buildCategoryQuery({ type });
            const sortOption = this.buildSortOption(sortBy);
            const pageNum = Math.max(1, parseInt(page));
            const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
            const skip = (pageNum - 1) * limitNum;

            const [categories, totalCount] = await Promise.all([
                SkillCategory.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select(this.getSelectFields(false))
                    .lean(),
                SkillCategory.countDocuments(query).cache({ ttl: 300, key: `category_type_count_${type}` }),
            ]);

            const processedCategories = await Promise.all(
                categories.map((category) => this.processCategoryData(category, false)),
            );

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                categories: processedCategories,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages,
                },
            };

            await cacheService.set(cacheKey, result, 1800);
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('category.type_viewed', { type, count: categories.length });
            logger.info(`Fetched ${categories.length} categories for type ${type} in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch categories for type ${type}:`, error);
            metricsCollector.increment('category.type_fetch_failed', { type });
            return next(new AppError('Failed to fetch categories by type', 500));
        }
    });

    /**
     * Search categories
     * GET /api/v1/categories/search
     */
    searchCategories = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { query, page = 1, limit = 20, filters = {} } = req.query;

        const cacheKey = `search:categories:${query}:${JSON.stringify(filters)}:${page}:${limit}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('category.search_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const searchResults = await this.categoryService.searchCategories(query, filters, {
                page: parseInt(page),
                limit: parseInt(limit),
            });

            const result = {
                categories: searchResults.hits,
                totalCount: searchResults.total,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    totalPages: Math.ceil(searchResults.total / parseInt(limit)),
                },
            };

            await cacheService.set(cacheKey, result, 300);
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('category.searched', { query, count: searchResults.hits.length });
            logger.info(`Search returned ${searchResults.hits.length} categories in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Search failed for query ${query}:`, error);
            metricsCollector.increment('category.search_failed');
            return next(new AppError('Failed to search categories', 500));
        }
    });

    /**
     * Export categories as CSV
     * GET /api/v1/categories/:userId/export
     */
    exportCategories = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { format = 'csv', fields = 'name,description,type,status' } = req.query;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        try {
            const categories = await SkillCategory.find({ userId, 'status.isDeleted': false })
                .read('secondaryPreferred')
                .select(fields.split(',').join(' '))
                .lean();

            const csvData = this.convertToCSV(categories, fields.split(','));
            const filename = `categories_${userId}_${Date.now()}.csv`;

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('category.exported', { userId, format });
            logger.info(`Exported ${categories.length} categories for user ${userId} in ${responseTime}ms`);

            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            return res.send(csvData);
        } catch (error) {
            logger.error(`Export failed for user ${userId}:`, error);
            metricsCollector.increment('category.export_failed', { userId });
            return next(new AppError('Failed to export categories', 500));
        }
    });

    // Helper Methods

    async processNewCategoryAsync(categoryId, userId) {
        try {
            const session = await mongoose.startSession();
            session.startTransaction();

            const category = await SkillCategory.findById(categoryId).session(session);
            if (!category) {
                await session.abortTransaction();
                session.endSession();
                return;
            }

            const skillsExtracted = await this.categoryService.extractSkills(category.description);
            category.skills = skillsExtracted.slice(0, 20);

            await category.calculateQualityScore({ session });

            await this.processExternalVerification(categoryId, userId);

            await this.categoryService.indexForSearch(category);

            await this.categoryService.updateUserStats(userId, { session });

            await category.save({ session });
            await session.commitTransaction();
            logger.info(`Async processing completed for category ${categoryId}`);
        } catch (error) {
            logger.error(`Async processing failed for category ${categoryId}:`, error);
        } finally {
            session.endSession();
        }
    }

    checkCategoryAccess(category, requestingUserId, isAdmin) {
        if (isAdmin) return true;
        if (category.userId.toString() === requestingUserId) return true;
        if (category.visibility === 'public') return true;
        return false;
    }

    getAllowedUpdateFields() {
        return [
            'name',
            'description',
            'type',
            'tags',
            'skills',
            'visibility',
            'status',
        ];
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

    processAnalyticsData(category, timeframe, metrics) {
        const analytics = category.analytics || {};
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
            viewCount: analytics.viewCount || 0,
            searchAppearances: analytics.searchAppearances || 0,
            engagementScore: analytics.engagementScore || 0,
            lastViewed: analytics.lastViewed || null,
            clickThroughRate: analytics.clickThroughRate || 0,
            userInteractions: analytics.userInteractions || 0,
            shares: {
                total: analytics.shares?.total || 0,
                byPlatform: analytics.shares?.byPlatform || {},
            },
            endorsements: category.endorsements?.length || 0,
        };

        if (metrics === 'detailed') {
            filteredAnalytics.verification = category.verification;
        }

        return filteredAnalytics;
    }

    getUserLimits(accountType) {
        const limits = {
            free: { maxCategories: 10, maxMedia: 5, maxSizeMB: 50 },
            premium: { maxCategories: 50, maxMedia: 20, maxSizeMB: 200 },
            enterprise: { maxCategories: 200, maxMedia: 50, maxSizeMB: 500 },
        };
        return limits[accountType] || limits.free;
    }

    buildCategoryQuery({ userId, status, type, search, tags }) {
        const query = { userId, 'status.isDeleted': false };

        if (status && status !== 'all') {
            query['status.isActive'] = status === 'active';
        }
        if (type && type !== 'all') {
            query.type = type;
        }
        if (tags) {
            const tagArray = tags.split(',').map((tag) => tag.trim().toLowerCase());
            query.tags = { $in: tagArray };
        }
        if (search) {
            query.$text = { $search: search };
        }

        return query;
    }

    buildSortOption(sortBy) {
        const sortOptions = {
            recent: { updatedAt: -1 },
            oldest: { createdAt: 1 },
            name: { name: 1 },
            popular: { 'analytics.viewCount': -1 },
            quality: { 'metadata.qualityScore': -1 },
            verified: { 'verification.confidence': -1 },
        };
        return sortOptions[sortBy] || sortOptions.recent;
    }

    getSelectFields(includeAnalytics) {
        const baseFields = 'name description type tags skills visibility status createdAt updatedAt';
        return includeAnalytics ? baseFields + ' analytics' : baseFields;
    }

    async processCategoryData(category, includeAnalytics = false, includeVerification = false) {
        const processed = {
            ...category,
            type: category.type,
        };

        if (!includeAnalytics) {
            delete processed.analytics;
        }
        if (!includeVerification) {
            delete processed.verification;
        }

        return processed;
    }

    calculateTrendingScore(category) {
        const viewsWeight = 0.4;
        const sharesWeight = 0.3;
        const endorsementsWeight = 0.2;
        const recencyWeight = 0.1;

        const daysSinceCreated = (Date.now() - new Date(category.createdAt)) / (1000 * 60 * 60 * 24);
        const recencyScore = Math.max(0, 10 - daysSinceCreated);

        return (
            (category.analytics.viewCount * viewsWeight) +
            ((category.analytics.shares?.total || 0) * sharesWeight) +
            (category.endorsements.length * endorsementsWeight) +
            (recencyScore * recencyWeight)
        );
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

    async processExternalVerification(categoryId, userId) {
        try {
            const category = await SkillCategory.findById(categoryId);
            const result = await this.verificationService.verifyCategory({
                categoryId,
                userId,
                name: category.name,
                type: category.type,
            });

            return result;
        } catch (error) {
            logger.error(`External verification failed for category ${categoryId}:`, error);
            return { success: false, message: error.message };
        }
    }

    generateShareableLink(category, platform) {
        const baseUrl = process.env.APP_URL || 'https://app.example.com';
        return `${baseUrl}/categories/${category._id}/share?platform=${platform}`;
    }

    async handleBulkOperation(operation, query, data, requestingUserId, req, options = {}) {
        let updateData = {};
        let message = '';

        switch (operation) {
            case 'delete':
                updateData = {
                    'status.isDeleted': true,
                    'status.deletedAt': new Date(),
                    updatedAt: new Date(),
                    'metadata.lastModifiedBy': {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = 'Categories moved to trash';
                break;
            case 'archive':
                updateData = {
                    'status.isActive': false,
                    updatedAt: new Date(),
                    'metadata.lastModifiedBy': {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = 'Categories archived';
                break;
            case 'publish':
                updateData = {
                    'status.isActive': true,
                    visibility: 'public',
                    updatedAt: new Date(),
                    'metadata.lastModifiedBy': {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = 'Categories published';
                break;
            case 'updateType':
                if (!data.type) {
                    throw new AppError('Type is required', 400);
                }
                updateData = {
                    type: data.type,
                    updatedAt: new Date(),
                    'metadata.lastModifiedBy': {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = `Type updated to ${data.type}`;
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
            case 'updateVisibility':
                if (!data.visibility) {
                    throw new AppError('Visibility is required', 400);
                }
                updateData = {
                    visibility: data.visibility,
                    updatedAt: new Date(),
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

        const result = await SkillCategory.updateMany(query, updateData, options);
        return { message, result };
    }

    convertToCSV(data, fields) {
        const headers = fields.join(',');
        const rows = data.map((item) => {
            return fields.map((field) => {
                const value = field.includes('.') ? field.split('.').reduce((obj, key) => obj?.[key] || '', item) : item[field] || '';
                return `"${value.toString().replace(/"/g, '""')}"`;
            }).join(',');
        });
        return `${headers}\n${rows.join('\n')}`;
    }
}

export default new CategoryController();