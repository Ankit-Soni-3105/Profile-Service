import retry from 'async-retry';
import Template from '../models/Template.model.js';
import { TemplateService } from '../services/template.service.js';
import { generatePreview, validateTemplate } from '../services/template.service.js';
import { AppError } from '../errors/app.error.js';
import { catchAsync } from '../handler/catchAsync.js';
import { logger } from '../utils/logger.js';

class TemplateController {
    // Get all templates with filtering and pagination
    getTemplates = catchAsync(async (req, res, next) => {
        const {
            page = 1,
            limit = 20,
            category = 'profile-cover',
            pricing = 'all',
            difficulty = 'all',
            minRating = 0,
            sortBy = 'popularity',
            featured = false
        } = req.query;
        const userId = req.user?.id;
        const allowedGroups = req.user?.groups || [];

        const options = {
            page: parseInt(page),
            limit: parseInt(limit),
            pricing,
            difficulty,
            minRating: parseFloat(minRating),
            sortBy,
            userId,
            allowedGroups
        };

        let templates, totalCount;

        if (featured === 'true') {
            templates = await Template.getFeaturedTemplates(options.limit, category, userId, allowedGroups);
            totalCount = templates.length;
        } else {
            const result = await Template.findByCategory(category, options);
            templates = result.templates;
            totalCount = result.total;
        }

        res.json({
            success: true,
            data: {
                templates,
                pagination: {
                    page: options.page,
                    limit: options.limit,
                    totalCount,
                    totalPages: Math.ceil(totalCount / options.limit),
                    hasNext: options.page < Math.ceil(totalCount / options.limit),
                    hasPrev: options.page > 1
                }
            }
        });
    });

    // Search templates
    searchTemplates = catchAsync(async (req, res, next) => {
        const { q: searchQuery } = req.query;
        const {
            categories = [],
            industries = [],
            targetAudience = [],
            priceRange = 'all',
            difficulty = 'all',
            aspectRatios = [],
            colors = [],
            page = 1,
            limit = 20
        } = req.body;
        const userId = req.user?.id;
        const allowedGroups = req.user?.groups || [];

        if (!searchQuery && !categories.length && !industries.length && !targetAudience.length) {
            return next(new AppError('Search query or filters are required', 400));
        }

        const filters = {
            categories,
            industries,
            targetAudience,
            priceRange,
            difficulty,
            aspectRatios,
            colors,
            page: parseInt(page),
            limit: parseInt(limit),
            userId,
            allowedGroups
        };

        const templates = await Template.searchTemplates(searchQuery || '', filters);
        const totalCount = templates.length;

        res.json({
            success: true,
            data: {
                templates,
                query: searchQuery || '',
                filters,
                pagination: {
                    page: filters.page,
                    limit: filters.limit,
                    totalCount,
                    totalPages: Math.ceil(totalCount / filters.limit),
                    hasNext: filters.page < Math.ceil(totalCount / filters.limit),
                    hasPrev: filters.page > 1
                }
            }
        });
    });

    // Get single template by ID
    getTemplateById = catchAsync(async (req, res, next) => {
        const { templateId } = req.params;
        const userId = req.user?.id;

        const template = await Template.findOne({ templateId }).lean();
        if (!template) {
            return next(new AppError('Template not found', 404));
        }

        // Check access permissions
        const hasAccess = template.accessControl.visibility === 'public' ||
            template.accessControl.visibility === 'featured' ||
            template.createdBy === userId ||
            template.accessControl.allowedUsers.includes(userId) ||
            template.accessControl.allowedGroups.some(group => req.user?.groups?.includes(group));

        if (!hasAccess) {
            return next(new AppError('Access denied', 403));
        }

        // Increment view count (async)
        if (userId && userId !== template.createdBy) {
            Template.findOneAndUpdate(
                { templateId },
                { $inc: { 'analytics.views': 1 } },
                { new: true }
            ).catch(err => logger.error('Template view increment failed', { error: err.message, templateId }));
        }

        res.json({
            success: true,
            data: template.getPublicData ? template.getPublicData() : template
        });
    });

    // Create new template
    createTemplate = catchAsync(async (req, res, next) => {
        const {
            name,
            description,
            category = 'profile-cover',
            canvas,
            layers,
            tags = [],
            pricing = { type: 'free', price: 0 },
            customization = {}
        } = req.body;
        const userId = req.user.id;

        // Check user template creation limits
        const userTemplateCount = await Template.countDocuments({ createdBy: userId, status: { $ne: 'deleted' } });
        const creationLimit = req.user.accountType === 'free' ? 5 :
            req.user.accountType === 'premium' ? 50 : 500;

        if (userTemplateCount >= creationLimit) {
            return next(new AppError(`Template creation limit reached (${creationLimit} templates)`, 403));
        }

        // Validate required fields
        if (!name || !category || !canvas || !Array.isArray(layers)) {
            return next(new AppError('Name, category, canvas, and layers are required', 400));
        }

        // Validate template structure
        const validation = validateTemplate({ canvas, layers });
        if (!validation.valid) {
            return next(new AppError(`Template validation failed: ${validation.errors.join(', ')}`, 400));
        }

        try {
            const templateData = {
                createdBy: userId,
                name: name.trim(),
                description: description?.trim() || '',
                category,
                canvas: {
                    ...canvas,
                    aspectRatio: canvas.width / canvas.height
                },
                layers: layers.map((layer, index) => ({
                    ...layer,
                    id: layer.id || require('crypto').randomUUID(),
                    order: layer.order || index
                })),
                tags: Array.isArray(tags) ? tags.map(tag => tag.trim().toLowerCase()) : [],
                pricing,
                customization: {
                    difficulty: customization.difficulty || 'beginner',
                    customizableElements: customization.customizableElements || []
                },
                status: 'draft',
                accessControl: { visibility: 'private' }
            };

            const template = new Template(templateData);
            await template.save();

            // Generate preview asynchronously
            this.generatePreviewAsync(template.templateId).catch(err =>
                logger.error('Preview generation failed', { error: err.message, templateId })
            );

            res.status(201).json({
                success: true,
                message: 'Template created successfully',
                data: {
                    templateId: template.templateId,
                    status: template.status,
                    previewGenerating: true
                }
            });
        } catch (error) {
            logger.error('Template creation error', { error: error.message });
            if (error.name === 'ValidationError') {
                const errors = Object.values(error.errors).map(err => err.message);
                return next(new AppError(`Validation error: ${errors.join(', ')}`, 400));
            }
            return next(new AppError('Template creation failed', 500));
        }
    });

    // Generate preview asynchronously
    generatePreviewAsync = async (templateId) => {
        await retry(
            async () => {
                const template = await Template.findOne({ templateId });
                if (!template) {
                    throw new AppError('Template not found', 404);
                }

                const previews = await generatePreview(template.canvas, template.layers, {
                    generateThumbnail: true,
                    generatePreview: true,
                    generateMockups: false
                });

                await Template.generatePreviews(template);
                template.status = 'active';
                await template.save();

                logger.info('Template preview generated', { templateId });
            },
            {
                retries: 3,
                factor: 2,
                minTimeout: 1000,
                maxTimeout: 5000,
                onRetry: (err) => {
                    logger.warn('Retrying preview generation', { error: err.message, templateId });
                }
            }
        );
    };

    // Update template
    updateTemplate = catchAsync(async (req, res, next) => {
        const { templateId } = req.params;
        const userId = req.user.id;
        const updates = req.body;

        const template = await Template.findOne({
            templateId,
            $or: [
                { createdBy: userId },
                { 'accessControl.allowedUsers': userId },
                { 'accessControl.allowedGroups': { $in: req.user?.groups || [] } }
            ]
        });

        if (!template) {
            return next(new AppError('Template not found or access denied', 404));
        }

        const allowedUpdates = ['name', 'description', 'tags', 'layers', 'canvas', 'customization', 'pricing', 'status', 'accessControl'];
        const updateData = {};
        Object.keys(updates).forEach(key => {
            if (allowedUpdates.includes(key)) {
                updateData[key] = updates[key];
            }
        });

        if (Object.keys(updateData).length === 0) {
            return next(new AppError('No valid update fields provided', 400));
        }

        if (updateData.layers || updateData.canvas) {
            const validation = validateTemplate({
                canvas: updateData.canvas || template.canvas,
                layers: updateData.layers || template.layers
            });
            if (!validation.valid) {
                return next(new AppError(`Validation failed: ${validation.errors.join(', ')}`, 400));
            }
        }

        if (updateData.layers || updateData.canvas) {
            const changes = [];
            if (updateData.layers) changes.push('layers modified');
            if (updateData.canvas) changes.push('canvas updated');
            await template.createVersion(changes.join(', '), userId);
        }

        Object.assign(template, updateData);
        await template.save();

        res.json({
            success: true,
            message: 'Template updated successfully',
            data: template.getPublicData()
        });
    });

    // Delete template
    deleteTemplate = catchAsync(async (req, res, next) => {
        const { templateId } = req.params;
        const userId = req.user.id;
        const { permanent = false } = req.query;

        const template = await Template.findOne({ templateId, createdBy: userId });
        if (!template) {
            return next(new AppError('Template not found or access denied', 404));
        }

        if (permanent) {
            if (template.analytics.uses > 0 && req.user.accountType !== 'enterprise') {
                return next(new AppError('Cannot permanently delete template with usage history', 403));
            }
            await Template.findByIdAndDelete(template._id);
            res.json({ success: true, message: 'Template permanently deleted' });
        } else {
            template.status = 'deleted';
            await template.save();
            res.json({ success: true, message: 'Template moved to trash' });
        }
    });

    // Use template
    useTemplate = catchAsync(async (req, res, next) => {
        const { templateId } = req.params;
        const userId = req.user.id;

        const template = await Template.findOne({
            templateId,
            status: 'active',
            $or: [
                { 'accessControl.visibility': { $in: ['public', 'featured'] } },
                { createdBy: userId },
                { 'accessControl.allowedUsers': userId },
                { 'accessControl.allowedGroups': { $in: req.user?.groups || [] } }
            ]
        });

        if (!template) {
            return next(new AppError('Template not found or not available', 404));
        }

        if (template.pricing.type !== 'free') {
            const hasAccess = await this.checkTemplateAccess(userId, template);
            if (!hasAccess) {
                return next(new AppError('Premium template access required', 402));
            }
        }

        await template.incrementUsage(userId, 'use');

        res.json({
            success: true,
            message: 'Template ready for customization',
            data: template.getPublicData()
        });
    });

    // Get template categories
    getCategories = catchAsync(async (req, res, next) => {
        const categories = await Template.aggregate([
            {
                $match: {
                    status: 'active',
                    $or: [
                        { 'accessControl.visibility': { $in: ['public', 'featured'] } },
                        { createdBy: req.user?.id },
                        { 'accessControl.allowedUsers': req.user?.id },
                        { 'accessControl.allowedGroups': { $in: req.user?.groups || [] } }
                    ]
                }
            },
            {
                $group: {
                    _id: '$category',
                    count: { $sum: 1 },
                    avgRating: { $avg: '$analytics.avgRating' },
                    popularTemplates: {
                        $push: {
                            $cond: [
                                { $gte: ['$analytics.popularityScore', 70] },
                                {
                                    templateId: '$templateId',
                                    name: '$name',
                                    popularityScore: '$analytics.popularityScore'
                                },
                                '$REMOVE'
                            ]
                        }
                    }
                }
            },
            {
                $project: {
                    _id: 0,
                    category: '$_id',
                    count: 1,
                    avgRating: { $round: ['$avgRating', 1] },
                    popularTemplates: { $slice: ['$popularTemplates', 3] }
                }
            },
            { $sort: { count: -1 } }
        ]);

        res.json({ success: true, data: categories });
    });

    // Get trending templates
    getTrendingTemplates = catchAsync(async (req, res, next) => {
        const { timeframe = 7, limit = 20, category } = req.query;
        const userId = req.user?.id;
        const allowedGroups = req.user?.groups || [];

        const templates = await Template.getTrendingTemplates(parseInt(timeframe), parseInt(limit), category, userId, allowedGroups);

        res.json({ success: true, data: templates });
    });

    // Rate template
    rateTemplate = catchAsync(async (req, res, next) => {
        const { templateId } = req.params;
        const { rating } = req.body;
        const userId = req.user.id;

        if (!rating || rating < 1 || rating > 5) {
            return next(new AppError('Rating must be between 1 and 5', 400));
        }

        const template = await Template.findOne({ templateId });
        if (!template) {
            return next(new AppError('Template not found', 404));
        }

        const hasUsed = template.analytics.recentActivity.some(
            activity => activity.userId === userId && activity.action === 'use'
        );

        if (!hasUsed) {
            return next(new AppError('You must use the template before rating it', 403));
        }

        const currentAvg = template.analytics.avgRating || 0;
        const currentCount = template.analytics.ratings.count || 0;
        const newAvg = ((currentAvg * currentCount) + rating) / (currentCount + 1);

        template.analytics.avgRating = Math.round(newAvg * 10) / 10;
        template.analytics.ratings.count += 1;
        template.analytics.ratings.distribution[rating] += 1;
        template.cacheVersion += 1;

        await template.save();

        res.json({
            success: true,
            message: 'Rating submitted successfully',
            data: {
                newAverage: template.analytics.avgRating,
                totalRatings: template.analytics.ratings.count
            }
        });
    });

    // Get template analytics
    getTemplateAnalytics = catchAsync(async (req, res, next) => {
        const { templateId } = req.params;
        const userId = req.user.id;

        const template = await Template.findOne({ templateId, createdBy: userId });
        if (!template) {
            return next(new AppError('Template not found or access denied', 404));
        }

        const analytics = {
            overview: {
                totalUses: template.analytics.uses,
                totalViews: template.analytics.views,
                totalDownloads: template.analytics.downloads,
                likes: template.analytics.likes,
                popularityScore: template.analytics.popularityScore,
                avgRating: template.analytics.avgRating,
                totalRatings: template.analytics.ratings.count
            },
            quality: {
                designScore: template.quality.designScore,
                overallQuality: template.quality.overallQuality,
                reviewStatus: template.quality.reviewStatus
            }
        };

        res.json({ success: true, data: analytics });
    });

    // Duplicate template
    duplicateTemplate = catchAsync(async (req, res, next) => {
        const { templateId } = req.params;
        const { name, makePrivate = true } = req.body;
        const userId = req.user.id;

        const originalTemplate = await Template.findOne({
            templateId,
            $or: [
                { 'accessControl.visibility': { $in: ['public', 'featured'] } },
                { createdBy: userId },
                { 'accessControl.allowedUsers': userId },
                { 'accessControl.allowedGroups': { $in: req.user?.groups || [] } }
            ]
        });

        if (!originalTemplate) {
            return next(new AppError('Template not found or access denied', 404));
        }

        const duplicateData = originalTemplate.toObject();
        delete duplicateData._id;
        delete duplicateData.templateId;
        delete duplicateData.analytics;
        delete duplicateData.versions;

        duplicateData.createdBy = userId;
        duplicateData.name = name || `${originalTemplate.name} (Copy)`;
        duplicateData.status = 'draft';
        duplicateData.accessControl.visibility = makePrivate ? 'private' : 'public';
        duplicateData.createdAt = new Date();
        duplicateData.updatedAt = new Date();

        const duplicateTemplate = new Template(duplicateData);
        await duplicateTemplate.save();

        res.status(201).json({
            success: true,
            message: 'Template duplicated successfully',
            data: {
                templateId: duplicateTemplate.templateId,
                name: duplicateTemplate.name
            }
        });
    });

    // Get user's created templates
    getUserTemplates = catchAsync(async (req, res, next) => {
        const userId = req.user.id;
        const { page = 1, limit = 20, status = 'all', sortBy = 'recent' } = req.query;

        const query = { createdBy: userId };
        if (status !== 'all') {
            query.status = status;
        } else {
            query.status = { $ne: 'deleted' };
        }

        let sortOption = {};
        switch (sortBy) {
            case 'recent': sortOption = { updatedAt: -1 }; break;
            case 'popular': sortOption = { 'analytics.popularityScore': -1 }; break;
            case 'name': sortOption = { name: 1 }; break;
            case 'uses': sortOption = { 'analytics.uses': -1 }; break;
            default: sortOption = { updatedAt: -1 };
        }

        const skip = (page - 1) * limit;
        const templates = await Template.find(query)
            .sort(sortOption)
            .skip(skip)
            .limit(parseInt(limit))
            .select('-versions -analytics.recentActivity')
            .lean();

        const totalCount = await Template.countDocuments(query);

        res.json({
            success: true,
            data: {
                templates,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    totalCount,
                    totalPages: Math.ceil(totalCount / limit),
                    hasNext: page < Math.ceil(totalCount / limit),
                    hasPrev: page > 1
                }
            }
        });
    });

    // Bulk operations for admin
    bulkUpdateTemplates = catchAsync(async (req, res, next) => {
        const { templateIds, operation, data } = req.body;
        const userId = req.user.id;

        if (!req.user.isAdmin && req.user.accountType !== 'enterprise') {
            return next(new AppError('Admin access required', 403));
        }

        if (!Array.isArray(templateIds) || templateIds.length === 0) {
            return next(new AppError('Template IDs array is required', 400));
        }

        const query = { templateId: { $in: templateIds } };
        if (!req.user.isAdmin) {
            query.createdBy = userId;
        }

        let updateData = {}, message = '';
        switch (operation) {
            case 'approve':
                updateData = { 'quality.reviewStatus': 'approved', 'quality.reviewedBy': userId, 'quality.reviewedAt': new Date() };
                message = 'Templates approved';
                break;
            case 'reject':
                updateData = { 'quality.reviewStatus': 'rejected', 'quality.reviewedBy': userId, 'quality.reviewedAt': new Date(), 'quality.reviewNotes': data.reason || '' };
                message = 'Templates rejected';
                break;
            case 'feature':
                updateData = { 'accessControl.visibility': 'featured', 'quality.reviewedBy': userId, 'quality.reviewedAt': new Date() };
                message = 'Templates featured';
                break;
            case 'unfeature':
                updateData = { 'accessControl.visibility': 'public' };
                message = 'Templates unfeatured';
                break;
            default:
                return next(new AppError('Invalid operation', 400));
        }

        const result = await Template.updateMany(query, updateData);

        res.json({
            success: true,
            message,
            data: {
                matched: result.matchedCount,
                modified: result.modifiedCount
            }
        });
    });

    // Helper method to check template access
    async checkTemplateAccess(userId, template) {
        // Placeholder: Integrate with billing/subscription system
        return true;
    }
}

export default new TemplateController();