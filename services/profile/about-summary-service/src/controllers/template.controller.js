import TemplateService from '../services/TemplateService.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { catchAsync } from '../handler/catchAsync.js';
import { ApiResponse } from '../utils/response.js';
import { createRateLimiter } from '../utils/rateLimiter.js';
import { cacheService } from '../services/cache.service.js';
import { metricsCollector } from '../utils/metrics.js';
import { eventEmitter } from '../events/events.js';
import { validateTemplate } from '../validations/template.validation.js';
import { sanitizeInput } from '../utils/sanitizer.js';

// Rate limiters for template operations
const createTemplateLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // 10 creates per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_template_${req.user.id}`,
});

const updateTemplateLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 20, // 20 updates per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_template_${req.user.id}`,
});

const bulkTemplateLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5, // 5 bulk operations per hour
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_template_${req.user.id}`,
});

class TemplateController {
    constructor() {
        this.templateService = TemplateService;
    }

    /**
     * Create a new template
     * POST /api/v1/summary/templates
     */
    createTemplate = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const requestingUserId = req.user.id;
        const templateData = req.body;

        // Apply rate limiting
        await createTemplateLimiter(req, res, () => { });

        // Validate input
        const validation = validateTemplate(templateData);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        // Sanitize input
        const sanitizedData = sanitizeInput(templateData);

        try {
            // Check user limits
            const userTemplateCount = await this.templateService.countTemplates({ userId: requestingUserId });
            const limits = this.getUserLimits(req.user.accountType);
            if (userTemplateCount >= limits.maxTemplates) {
                return next(new AppError(`Template limit reached (${limits.maxTemplates})`, 403));
            }

            // Create template
            const template = await this.templateService.createTemplate({
                ...sanitizedData,
                userId: requestingUserId,
                metadata: {
                    ...sanitizedData.metadata,
                    createdBy: {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        location: req.geoip,
                    },
                },
            });

            // Clear cache
            await cacheService.deletePattern('templates:*');

            // Emit event
            eventEmitter.emit('template.created', {
                templateId: template._id,
                userId: requestingUserId,
                category: template.category,
            });

            // Log metrics
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('template.created', {
                userId: requestingUserId,
                category: template.category,
            });
            logger.info(`Template created: ${template._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Template created successfully',
                data: {
                    id: template._id,
                    name: template.name,
                    category: template.category,
                    createdAt: template.createdAt,
                },
            }, 201);
        } catch (error) {
            logger.error(`Template creation failed for user ${requestingUserId}:`, error);
            metricsCollector.increment('template.create_failed', { userId: requestingUserId });
            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.code === 11000) {
                return next(new AppError('Template with this name already exists', 409));
            }
            return next(new AppError('Failed to create template', 500));
        }
    });

    /**
     * Get all templates with filtering and pagination
     * GET /api/v1/summary/templates
     */
    getTemplates = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const requestingUserId = req.user.id;
        const {
            page = 1,
            limit = 20,
            category,
            search,
            sortBy = 'recent',
            visibility = 'public',
            tags,
            startDate,
            endDate,
        } = req.query;

        // Build query
        const query = this.buildTemplateQuery({
            userId: requestingUserId,
            category,
            search,
            visibility,
            tags,
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
        const cacheKey = `templates:${requestingUserId}:${JSON.stringify({
            page: pageNum,
            limit: limitNum,
            category,
            search,
            sortBy,
            visibility,
            tags,
            startDate,
            endDate,
        })}`;

        try {
            // Try cache first
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('template.cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, cached);
            }

            // Query database
            const [templates, totalCount] = await Promise.all([
                this.templateService.getTemplates(query)
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select(this.getSelectFields())
                    .lean(),
                this.templateService.countTemplates(query),
            ]);

            // Process templates data
            const processedTemplates = templates.map(template => this.processTemplateData(template));

            const totalPages = Math.ceil(totalCount / limitNum);
            const hasNext = pageNum < totalPages;
            const hasPrev = pageNum > 1;

            const result = {
                templates: processedTemplates,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages,
                    hasNext,
                    hasPrev,
                    nextPage: hasNext ? pageNum + 1 : null,
                    prevPage: hasPrev ? pageNum - 1 : null,
                },
                filters: {
                    category: category || 'all',
                    visibility: visibility || 'public',
                    sortBy,
                    search: search || null,
                },
            };

            // Cache result
            await cacheService.set(cacheKey, result, 300); // 5 minutes

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('template.fetched', {
                userId: requestingUserId,
                count: templates.length,
                cached: false,
            });
            logger.info(`Fetched ${templates.length} templates for user ${requestingUserId} in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch templates for user ${requestingUserId}:`, error);
            metricsCollector.increment('template.fetch_failed', { userId: requestingUserId });
            return next(new AppError('Failed to fetch templates', 500));
        }
    });

    /**
     * Get a single template by ID
     * GET /api/v1/summary/templates/:templateId
     */
    getTemplateById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { templateId } = req.params;
        const requestingUserId = req.user.id;

        try {
            const template = await this.templateService.getTemplateById(templateId, requestingUserId);
            if (!template) {
                return next(new AppError('Template not found', 404));
            }

            // Check access permissions
            const hasAccess = this.checkTemplateAccess(template, requestingUserId, req.user.isAdmin);
            if (!hasAccess) {
                return next(new AppError('Access denied', 403));
            }

            // Increment view count (async)
            if (requestingUserId !== template.userId) {
                this.templateService.incrementViews(templateId).catch(err =>
                    logger.error(`View increment failed for template ${templateId}:`, err)
                );
            }

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('template.viewed', {
                userId: template.userId,
                viewerId: requestingUserId,
                isOwner: template.userId === requestingUserId,
            });
            logger.info(`Fetched template ${templateId} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                data: this.processTemplateData(template),
            });
        } catch (error) {
            logger.error(`Failed to fetch template ${templateId}:`, error);
            metricsCollector.increment('template.view_failed', { userId: requestingUserId });
            return next(new AppError('Failed to fetch template', 500));
        }
    });

    /**
     * Update a template
     * PUT /api/v1/summary/templates/:templateId
     */
    updateTemplate = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { templateId } = req.params;
        const requestingUserId = req.user.id;
        const updates = req.body;

        // Apply rate limiting
        await updateTemplateLimiter(req, res, () => { });

        // Validate input
        const validation = validateTemplate(updates);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        try {
            const template = await this.templateService.getTemplateById(templateId, requestingUserId);
            if (!template) {
                return next(new AppError('Template not found', 404));
            }

            // Check access
            if (template.userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            // Sanitize updates
            const allowedUpdates = this.getAllowedUpdateFields();
            const sanitizedUpdates = sanitizeInput(updates, allowedUpdates);

            if (Object.keys(sanitizedUpdates).length === 0) {
                return next(new AppError('No valid update fields provided', 400));
            }

            // Update template
            const updatedTemplate = await this.templateService.updateTemplate(templateId, sanitizedUpdates, requestingUserId);

            // Clear cache
            await cacheService.deletePattern(`template:${templateId}:*`);
            await cacheService.deletePattern('templates:*');

            // Emit event
            eventEmitter.emit('template.updated', {
                templateId,
                userId: requestingUserId,
                changes: Object.keys(sanitizedUpdates),
            });

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('template.updated', {
                userId: requestingUserId,
                fieldsUpdated: Object.keys(sanitizedUpdates).length,
            });
            logger.info(`Template updated: ${templateId} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Template updated successfully',
                data: {
                    id: updatedTemplate._id,
                    name: updatedTemplate.name,
                    category: updatedTemplate.category,
                    updatedAt: updatedTemplate.updatedAt,
                },
            });
        } catch (error) {
            logger.error(`Template update failed for ${templateId}:`, error);
            metricsCollector.increment('template.update_failed', { userId: requestingUserId });
            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            return next(new AppError('Failed to update template', 500));
        }
    });

    /**
     * Delete a template (soft delete)
     * DELETE /api/v1/summary/templates/:templateId
     */
    deleteTemplate = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { templateId } = req.params;
        const requestingUserId = req.user.id;
        const { permanent = 'false' } = req.query;

        try {
            const template = await this.templateService.getTemplateById(templateId, requestingUserId);
            if (!template) {
                return next(new AppError('Template not found', 404));
            }

            // Check access
            if (template.userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            // Delete template
            await this.templateService.deleteTemplate(templateId, requestingUserId, permanent === 'true');

            // Clear cache
            await cacheService.deletePattern(`template:${templateId}:*`);
            await cacheService.deletePattern('templates:*');

            // Emit event
            eventEmitter.emit('template.deleted', {
                templateId,
                userId: requestingUserId,
                permanent: permanent === 'true',
            });

            const responseTime = Date.now() - startTime;
            metricsCollector.increment(permanent === 'true' ? 'template.permanently_deleted' : 'template.soft_deleted', {
                userId: requestingUserId,
            });
            logger.info(`Template ${templateId} ${permanent === 'true' ? 'permanently' : 'soft'} deleted in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: permanent === 'true' ? 'Template permanently deleted' : 'Template moved to trash',
            });
        } catch (error) {
            logger.error(`Template deletion failed for ${templateId}:`, error);
            metricsCollector.increment('template.delete_failed', { userId: requestingUserId });
            return next(new AppError('Failed to delete template', 500));
        }
    });

    /**
     * Bulk operations on templates
     * POST /api/v1/summary/templates/bulk
     */
    bulkOperations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const requestingUserId = req.user.id;
        const { operation, templateIds, data = {} } = req.body;

        // Apply rate limiting
        await bulkTemplateLimiter(req, res, () => { });

        // Validate input
        if (!Array.isArray(templateIds) || templateIds.length === 0) {
            return next(new AppError('Template IDs array is required', 400));
        }

        if (templateIds.length > 100) {
            return next(new AppError('Maximum 100 templates can be processed at once', 400));
        }

        const allowedOperations = ['delete', 'updateCategory', 'updateVisibility', 'updateTags'];
        if (!allowedOperations.includes(operation)) {
            return next(new AppError('Invalid operation', 400));
        }

        try {
            const result = await this.templateService.bulkUpdate(
                templateIds,
                operation,
                data,
                requestingUserId
            );

            // Clear cache
            await Promise.all([
                cacheService.deletePattern('templates:*'),
                ...templateIds.map(id => cacheService.deletePattern(`template:${id}:*`)),
            ]);

            // Emit event
            eventEmitter.emit('template.bulk_updated', {
                userId: requestingUserId,
                operation,
                templateIds,
                modifiedCount: result.modified,
            });

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('template.bulk_operation', {
                userId: requestingUserId,
                operation,
                count: result.modified,
            });
            logger.info(`Bulk operation ${operation} completed for ${result.modified} templates in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: `Bulk ${operation} completed`,
                data: {
                    operation,
                    requested: templateIds.length,
                    matched: result.matched,
                    modified: result.modified,
                },
            });
        } catch (error) {
            logger.error(`Bulk operation failed for user ${requestingUserId}:`, error);
            metricsCollector.increment('template.bulk_operation_failed', { userId: requestingUserId, operation });
            return next(new AppError('Bulk operation failed', 500));
        }
    });

    /**
     * Get template analytics
     * GET /api/v1/summary/templates/:templateId/analytics
     */
    getAnalytics = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { templateId } = req.params;
        const requestingUserId = req.user.id;
        const { timeframe = '30d', metrics = 'basic' } = req.query;

        try {
            const template = await this.templateService.getTemplateById(templateId, requestingUserId);
            if (!template) {
                return next(new AppError('Template not found', 404));
            }

            // Check access
            if (template.userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            const analytics = await this.templateService.getAnalytics(templateId, timeframe, metrics);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('template.analytics_viewed', { userId: requestingUserId });
            logger.info(`Fetched analytics for template ${templateId} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                data: analytics,
            });
        } catch (error) {
            logger.error(`Analytics fetch failed for template ${templateId}:`, error);
            metricsCollector.increment('template.analytics_fetch_failed', { userId: requestingUserId });
            return next(new AppError('Failed to fetch analytics', 500));
        }
    });

    /**
     * Duplicate a template
     * POST /api/v1/summary/templates/:templateId/duplicate
     */
    duplicateTemplate = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { templateId } = req.params;
        const requestingUserId = req.user.id;
        const { name } = req.body;

        try {
            // Check user limits
            const userTemplateCount = await this.templateService.countTemplates({ userId: requestingUserId });
            const limits = this.getUserLimits(req.user.accountType);
            if (userTemplateCount >= limits.maxTemplates) {
                return next(new AppError(`Template limit reached (${limits.maxTemplates})`, 403));
            }

            const template = await this.templateService.getTemplateById(templateId, requestingUserId);
            if (!template) {
                return next(new AppError('Template not found', 404));
            }

            // Check access
            const hasAccess = this.checkTemplateAccess(template, requestingUserId, req.user.isAdmin);
            if (!hasAccess) {
                return next(new AppError('Access denied', 403));
            }

            // Duplicate template
            const duplicate = await this.templateService.duplicateTemplate(templateId, requestingUserId, { name });

            // Clear cache
            await cacheService.deletePattern('templates:*');

            // Emit event
            eventEmitter.emit('template.duplicated', {
                originalId: templateId,
                duplicateId: duplicate._id,
                userId: requestingUserId,
            });

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('template.duplicated', { userId: requestingUserId });
            logger.info(`Template ${templateId} duplicated as ${duplicate._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Template duplicated successfully',
                data: {
                    originalId: templateId,
                    duplicateId: duplicate._id,
                    name: duplicate.name,
                },
            }, 201);
        } catch (error) {
            logger.error(`Template duplication failed for ${templateId}:`, error);
            metricsCollector.increment('template.duplicate_failed', { userId: requestingUserId });
            return next(new AppError('Failed to duplicate template', 500));
        }
    });

    // Helper Methods

    /**
     * Get user limits based on account type
     */
    getUserLimits(accountType) {
        const limits = {
            free: { maxTemplates: 5 },
            premium: { maxTemplates: 50 },
            enterprise: { maxTemplates: 500 },
        };
        return limits[accountType] || limits.free;
    }

    /**
     * Build query for fetching templates
     */
    buildTemplateQuery({ userId, category, search, visibility, tags, startDate, endDate }) {
        const query = {};

        // Visibility filter
        if (visibility === 'own') {
            query.userId = userId;
        } else if (visibility === 'public') {
            query.visibility = 'public';
        } else if (visibility === 'all' && req.user.isAdmin) {
            // Admin can see all templates
        } else {
            query.$or = [{ visibility: 'public' }, { userId }];
        }

        // Category filter
        if (category && category !== 'all') {
            query.category = category;
        }

        // Tags filter
        if (tags) {
            const tagArray = tags.split(',').map(tag => tag.trim().toLowerCase());
            query.tags = { $in: tagArray };
        }

        // Date range filter
        if (startDate || endDate) {
            query.createdAt = {};
            if (startDate) query.createdAt.$gte = new Date(startDate);
            if (endDate) query.createdAt.$lte = new Date(endDate);
        }

        // Search filter
        if (search) {
            query.$text = { $search: search };
        }

        return query;
    }

    /**
     * Build sort option for queries
     */
    buildSortOption(sortBy) {
        const sortOptions = {
            recent: { updatedAt: -1 },
            oldest: { createdAt: 1 },
            name: { name: 1 },
            popular: { 'analytics.usage.total': -1 },
        };
        return sortOptions[sortBy] || sortOptions.recent;
    }

    /**
     * Get fields to select in queries
     */
    getSelectFields() {
        return 'name content category tags visibility createdAt updatedAt analytics';
    }

    /**
     * Process template data for response
     */
    processTemplateData(template) {
        const processed = {
            ...template,
            variableCount: (template.content.match(/\{\{[^}]+\}\}/g) || []).length,
        };
        return processed;
    }

    /**
     * Check access permissions for a template
     */
    checkTemplateAccess(template, requestingUserId, isAdmin) {
        if (isAdmin) return true;
        if (template.userId === requestingUserId) return true;
        if (template.visibility === 'public') return true;
        return false;
    }

    /**
     * Get allowed fields for update
     */
    getAllowedUpdateFields() {
        return [
            'name',
            'content',
            'category',
            'tags',
            'visibility',
            'settings',
        ];
    }
}

export default new TemplateController();