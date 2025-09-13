import Template from '../models/Template.js';
import TemplateService from '../services/TemplateService.js';
import NotificationService from '../services/NotificationService.js';
import { validateTemplate, sanitizeInput } from '../validations/template.validation.js';
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
const createTemplateLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // 10 creates per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_template_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const updateTemplateLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 20, // 20 updates per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_template_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const bulkOperationsLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5, // 5 bulk operations per hour
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_template_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const shareTemplateLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 10, // 10 shares per 10 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `share_template_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

class TemplateController {
    constructor() {
        this.templateService = TemplateService;
        this.notificationService = NotificationService;
    }

    /**
     * Create a new template
     * POST /api/v1/templates/:userId
     */
    createTemplate = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const templateData = req.body;
        const requestingUserId = req.user.id;

        // Validate access permissions
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied: Cannot create template for another user', 403));
        }

        // Apply rate limiting
        await createTemplateLimiter(req, res, () => { });

        // Validate input data
        const validation = validateTemplate(templateData);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        // Sanitize input
        const sanitizedData = sanitizeInput(templateData);

        // Check user limits
        const userTemplateCount = await Template.countDocuments({
            userId,
            status: { $ne: 'deleted' },
        }).cache({ ttl: 300, key: `user_template_count_${userId}` });

        const limits = this.getUserLimits(req.user.accountType);
        if (userTemplateCount >= limits.maxTemplates) {
            return next(new AppError(`Template limit reached (${limits.maxTemplates})`, 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            // Create template
            const template = await this.templateService.createTemplate({
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
            this.processNewTemplateAsync(template._id, userId)
                .catch((err) => logger.error(`Async processing failed for template ${template._id}:`, err));

            // Log metrics
            metricsCollector.increment('template.created', { userId, category: template.category });

            // Emit event
            eventEmitter.emit('template.created', { templateId: template._id, userId });

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`Template created successfully: ${template._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Template created successfully',
                data: {
                    id: template._id,
                    userId: template.userId,
                    name: template.name,
                    status: template.status,
                    createdAt: template.createdAt,
                    processingStatus: 'started',
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Template creation failed for user ${userId}:`, error);
            metricsCollector.increment('template.create_failed', { userId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.code === 11000) {
                return next(new AppError('Template with this name already exists', 409));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out', 504));
            }
            return next(new AppError('Failed to create template', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get user's templates with filtering and pagination
     * GET /api/v1/templates/:userId
     */
    getTemplates = catchAsync(async (req, res, next) => {
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
            tags,
            includeAnalytics = 'false',
        } = req.query;

        // Build query
        const query = this.buildTemplateQuery({ userId, status, category, search, tags });

        // Build sort option
        const sortOption = this.buildSortOption(sortBy);

        // Pagination
        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
        const skip = (pageNum - 1) * limitNum;

        // Cache key
        const cacheKey = `templates:${userId}:${JSON.stringify({
            page: pageNum,
            limit: limitNum,
            status,
            category,
            search,
            sortBy,
            tags,
        })}`;

        try {
            // Try cache first
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('template.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            // Query database
            const [templates, totalCount] = await Promise.all([
                Template.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select(this.getSelectFields(includeAnalytics === 'true'))
                    .lean(),
                Template.countDocuments(query).cache({ ttl: 300, key: `template_count_${userId}` }),
            ]);

            // Process templates
            const processedTemplates = await Promise.all(
                templates.map((temp) => this.processTemplateData(temp, includeAnalytics === 'true')),
            );

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                templates: processedTemplates,
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
            metricsCollector.increment('template.fetched', { userId, count: templates.length });
            logger.info(`Fetched ${templates.length} templates for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch templates for user ${userId}:`, error);
            metricsCollector.increment('template.fetch_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid query parameters', 400));
            }
            return next(new AppError('Failed to fetch templates', 500));
        }
    });

    /**
     * Get single template by ID
     * GET /api/v1/templates/:userId/:id
     */
    getTemplateById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { includeAnalytics = 'false' } = req.query;

        try {
            const cacheKey = `template:${id}:${userId}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('template.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const template = await Template.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .cache({ ttl: 600, key: cacheKey });

            if (!template) {
                return next(new AppError('Template not found', 404));
            }

            // Check access permissions
            if (!this.checkTemplateAccess(template, requestingUserId, req.user.isAdmin)) {
                return next(new AppError('Access denied', 403));
            }

            // Increment view count (async)
            if (requestingUserId !== userId) {
                template.incrementViews(true)
                    .catch((err) => logger.error(`View increment failed for template ${id}:`, err));
            }

            const responseData = await this.processTemplateData(template.toObject(), includeAnalytics === 'true');

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('template.viewed', { userId });
            logger.info(`Fetched template ${id} for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: responseData });
        } catch (error) {
            logger.error(`Failed to fetch template ${id}:`, error);
            metricsCollector.increment('template.view_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid template ID', 400));
            }
            return next(new AppError('Failed to fetch template', 500));
        }
    });

    /**
     * Update template
     * PUT /api/v1/templates/:userId/:id
     */
    updateTemplate = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const updates = req.body;

        // Apply rate limiting
        await updateTemplateLimiter(req, res, () => { });

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const template = await Template.findOne({ _id: id, userId }).session(session);
            if (!template) {
                return next(new AppError('Template not found', 404));
            }

            // Validate updates
            const allowedUpdates = ['name', 'content', 'category', 'visibility', 'status', 'tags'];
            const sanitizedUpdates = this.sanitizeUpdates(updates, allowedUpdates);

            if (Object.keys(sanitizedUpdates).length === 0) {
                return next(new AppError('No valid update fields provided', 400));
            }

            // Update template
            Object.assign(template, sanitizedUpdates);
            template.metadata.lastModifiedBy = {
                userId: requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date(),
            };

            await template.save({ session });

            // Clear cache
            await cacheService.deletePattern(`template:${id}:*`);
            await cacheService.deletePattern(`templates:${userId}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('template.updated', { userId });
            logger.info(`Template updated successfully: ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Template updated successfully',
                data: {
                    id: template._id,
                    name: template.name,
                    status: template.status,
                    updatedAt: template.updatedAt,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Template update failed for ${id}:`, error);
            metricsCollector.increment('template.update_failed', { userId });
            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            return next(new AppError('Failed to update template', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete template (soft or permanent)
     * DELETE /api/v1/templates/:userId/:id
     */
    deleteTemplate = catchAsync(async (req, res, next) => {
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

            const template = await Template.findOne({ _id: id, userId }).session(session);
            if (!template) {
                return next(new AppError('Template not found', 404));
            }

            if (permanent === 'true') {
                await Template.findByIdAndDelete(id, { session });
                metricsCollector.increment('template.permanently_deleted', { userId });
            } else {
                template.status = 'deleted';
                template.visibility = 'private';
                template.metadata.lastModifiedBy = {
                    userId: requestingUserId,
                    ip: req.ip,
                    userAgent: req.get('User-Agent'),
                    timestamp: new Date(),
                };
                await template.save({ session });
                metricsCollector.increment('template.soft_deleted', { userId });
            }

            // Clear cache
            await cacheService.deletePattern(`template:${id}:*`);
            await cacheService.deletePattern(`templates:${userId}:*`);

            // Emit event
            eventEmitter.emit('template.deleted', {
                templateId: id,
                userId,
                permanent: permanent === 'true',
            });

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`Template ${id} deleted (permanent: ${permanent}) in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: permanent === 'true' ? 'Template permanently deleted' : 'Template moved to trash',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Template deletion failed for ${id}:`, error);
            metricsCollector.increment('template.delete_failed', { userId });
            return next(new AppError('Failed to delete template', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Bulk operations on templates
     * POST /api/v1/templates/:userId/bulk
     */
    bulkOperations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { operation, templateIds, data = {} } = req.body;

        // Apply rate limiting
        await bulkOperationsLimiter(req, res, () => { });

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        // Validate input
        if (!Array.isArray(templateIds) || templateIds.length === 0) {
            return next(new AppError('Template IDs array is required', 400));
        }
        if (templateIds.length > 100) {
            return next(new AppError('Maximum 100 templates can be processed at once', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const query = { _id: { $in: templateIds }, userId };
            const { message } = await this.handleBulkOperation(operation, query, data, requestingUserId, req, { session });

            // Clear cache
            await Promise.all([
                cacheService.deletePattern(`templates:${userId}:*`),
                ...templateIds.map((id) => cacheService.deletePattern(`template:${id}:*`)),
            ]);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('template.bulk_operation', { userId, operation, count: templateIds.length });
            logger.info(`Bulk operation ${operation} completed for ${templateIds.length} templates in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message,
                data: { operation, requested: templateIds.length },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk operation failed for user ${userId}:`, error);
            metricsCollector.increment('template.bulk_operation_failed', { userId });
            return next(new AppError('Bulk operation failed', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get template analytics
     * GET /api/v1/templates/:userId/:id/analytics
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
            const cacheKey = `analytics:template:${id}:${timeframe}:${metrics}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('template.analytics_cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const template = await Template.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('analytics metadata createdAt')
                .cache({ ttl: 900, key: cacheKey });

            if (!template) {
                return next(new AppError('Template not found', 404));
            }

            const analytics = this.processAnalyticsData(template, timeframe, metrics);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('template.analytics_viewed', { userId });
            logger.info(`Fetched analytics for template ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: analytics });
        } catch (error) {
            logger.error(`Analytics fetch failed for ${id}:`, error);
            metricsCollector.increment('template.analytics_fetch_failed', { userId });
            return next(new AppError('Failed to fetch analytics', 500));
        }
    });

    /**
     * Share template
     * POST /api/v1/templates/:userId/:id/share
     */
    shareTemplate = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { platform } = req.body;

        // Apply rate limiting
        await shareTemplateLimiter(req, res, () => { });

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const template = await Template.findOne({ _id: id, userId }).session(session);
            if (!template) {
                return next(new AppError('Template not found', 404));
            }

            // Validate access
            if (!this.checkTemplateAccess(template, requestingUserId, req.user.isAdmin)) {
                return next(new AppError('Access denied', 403));
            }

            // Generate shareable link
            const shareLink = this.generateShareableLink(template, platform);

            // Track share
            template.analytics.shares.total += 1;
            template.analytics.shares.byPlatform = {
                ...template.analytics.shares.byPlatform,
                [platform]: (template.analytics.shares.byPlatform[platform] || 0) + 1,
            };
            await template.save({ session });

            // Clear cache
            await cacheService.deletePattern(`template:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('template.shared', { userId, platform });
            logger.info(`Template ${id} shared on ${platform} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Template shared successfully',
                data: { shareLink },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Share failed for template ${id}:`, error);
            metricsCollector.increment('template.share_failed', { userId });
            return next(new AppError('Failed to share template', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Search templates
     * GET /api/v1/templates/search
     */
    searchTemplates = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { query, page = 1, limit = 20, filters = {} } = req.query;

        const cacheKey = `search:templates:${query}:${JSON.stringify(filters)}:${page}:${limit}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('template.search_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const searchResults = await this.templateService.searchTemplates(query, filters, {
                page: parseInt(page),
                limit: parseInt(limit),
            });

            const result = {
                templates: searchResults.hits,
                totalCount: searchResults.total,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    totalPages: Math.ceil(searchResults.total / parseInt(limit)),
                },
            };

            await cacheService.set(cacheKey, result, 300);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('template.searched', { query, count: searchResults.hits.length });
            logger.info(`Search returned ${searchResults.hits.length} templates in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Search failed for query ${query}:`, error);
            metricsCollector.increment('template.search_failed');
            return next(new AppError('Failed to search templates', 500));
        }
    });

    /**
     * Export templates as CSV
     * GET /api/v1/templates/:userId/export
     */
    exportTemplates = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { format = 'csv', fields = 'name,category,description,status' } = req.query;

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        try {
            const templates = await Template.find({ userId, status: { $ne: 'deleted' } })
                .read('secondaryPreferred')
                .select(fields.split(',').join(' '))
                .lean();

            const csvData = this.convertToCSV(templates, fields.split(','));
            const filename = `templates_${userId}_${Date.now()}.csv`;

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('template.exported', { userId, format });
            logger.info(`Exported ${templates.length} templates for user ${userId} in ${responseTime}ms`);

            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            return res.send(csvData);
        } catch (error) {
            logger.error(`Export failed for user ${userId}:`, error);
            metricsCollector.increment('template.export_failed', { userId });
            return next(new AppError('Failed to export templates', 500));
        }
    });

    // Helper Methods

    /**
     * Process new template asynchronously
     */
    async processNewTemplateAsync(templateId, userId) {
        try {
            const session = await mongoose.startSession();
            session.startTransaction();

            const template = await Template.findById(templateId).session(session);
            if (!template) {
                await session.abortTransaction();
                session.endSession();
                return;
            }

            // Extract keywords
            const keywords = await this.templateService.extractKeywords(template.content);
            template.keywords = keywords.slice(0, 20);

            // Index for search
            await this.templateService.indexForSearch(template);

            // Update user stats
            await this.templateService.updateUserStats(userId, { session });

            await template.save({ session });
            await session.commitTransaction();
            logger.info(`Async processing completed for template ${templateId}`);
        } catch (error) {
            logger.error(`Async processing failed for template ${templateId}:`, error);
        } finally {
            session.endSession();
        }
    }

    /**
     * Check access permissions
     */
    checkTemplateAccess(template, requestingUserId, isAdmin) {
        if (isAdmin) return true;
        if (template.userId.toString() === requestingUserId) return true;
        if (template.visibility === 'public') return true;
        return false;
    }

    /**
     * Get allowed update fields
     */
    getAllowedUpdateFields() {
        return ['name', 'content', 'category', 'visibility', 'status', 'tags'];
    }

    /**
     * Sanitize updates
     */
    sanitizeUpdates(updates, allowedFields) {
        const sanitized = {};
        allowedFields.forEach((field) => {
            if (updates[field] !== undefined) {
                sanitized[field] = field === 'content' ? sanitizeHtml(updates[field]) : sanitizeInput(updates[field]);
            }
        });
        return sanitized;
    }

    /**
     * Process analytics data
     */
    processAnalyticsData(template, timeframe, metrics) {
        const analytics = template.analytics || {};
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
        };

        if (metrics === 'detailed') {
            filteredAnalytics.metadata = template.metadata;
        }

        return filteredAnalytics;
    }

    /**
     * Get user limits
     */
    getUserLimits(accountType) {
        const limits = {
            free: { maxTemplates: 5 },
            premium: { maxTemplates: 20 },
            enterprise: { maxTemplates: 100 },
        };
        return limits[accountType] || limits.free;
    }

    /**
     * Build query for fetching templates
     */
    buildTemplateQuery({ userId, status, category, search, tags }) {
        const query = { userId, status: { $ne: 'deleted' } };
        if (status && status !== 'all') query.status = status;
        if (category && category !== 'all') query.category = category;
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
            name: { name: 1 },
        };
        return sortOptions[sortBy] || sortOptions.recent;
    }

    /**
     * Get select fields
     */
    getSelectFields(includeAnalytics) {
        const baseFields = 'name content category status tags visibility createdAt updatedAt';
        return includeAnalytics ? baseFields + ' analytics' : baseFields;
    }

    /**
     * Process template data
     */
    async processTemplateData(template, includeAnalytics = false) {
        const processed = { ...template };
        if (!includeAnalytics) delete processed.analytics;
        return processed;
    }

    /**
     * Generate shareable link
     */
    generateShareableLink(template, platform) {
        const baseUrl = process.env.APP_URL || 'https://app.example.com';
        return `${baseUrl}/templates/${template._id}/share?platform=${platform}`;
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
                message = 'Templates moved to trash';
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

        const result = await Template.updateMany(query, updateData, options);
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

export default new TemplateController();