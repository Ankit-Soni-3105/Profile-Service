import { logger } from '../utils/logger.js';
import Design from '../models/Design.model.js';
import Template from '../models/Template.model.js';
import { DesignService } from '../services/design.service.js';
import { AppError } from '../errors/app.error.js';
import { catchAsync } from '../handler/catchAsync.js';

class DesignController {
    // Create new design from template
    createFromTemplate = catchAsync(async (req, res, next) => {
        const { templateId } = req.params;
        const { name, customizations = [], category } = req.body;
        const userId = req.user.id;

        // Find template with caching
        const template = await Template.findOne({
            templateId,
            status: 'active',
            $or: [
                { accessControl: { visibility: { $in: ['public', 'featured'] } } },
                { createdBy: userId }
            ]
        }).cache({ key: `template:${templateId}:${userId}` });

        if (!template) {
            return next(new AppError('Template not found or not accessible', 404));
        }

        // Check user design limits
        const designLimit = req.user.accountType === 'free' ? 10 :
            req.user.accountType === 'premium' ? 100 : 1000;
        const userDesignCount = await Design.countDocuments({
            userId,
            category: 'profile-cover',
            status: { $ne: 'deleted' }
        }).hint('userId_status_category');

        if (userDesignCount >= designLimit) {
            return next(new AppError(`Design limit reached (${designLimit} designs)`, 403));
        }

        try {
            const designData = {
                designId: `des_${Date.now().toString(36)}${Math.random().toString(36).substring(2, 8)}`,
                userId,
                templateId: template.templateId,
                name: name?.trim() || `${template.name} - Custom`,
                description: `Design based on ${template.name} template`,
                category: category || template.category || 'profile-cover',
                status: 'draft',
                accessControl: {
                    visibility: 'private',
                    allowedUsers: [],
                    allowedGroups: [],
                    allowDownload: false,
                    allowShare: false
                },
                dimensions: {
                    width: template.canvas.width,
                    height: template.canvas.height,
                    aspectRatio: template.canvas.aspectRatio
                },
                customizations: customizations.slice(0, 50).map(c => ({
                    elementId: c.elementId,
                    elementType: c.elementType,
                    originalValue: c.originalValue,
                    customValue: c.customValue,
                    source: 'user',
                    appliedAt: new Date()
                })),
                analytics: { views: 0, likes: 0, shares: 0, downloads: 0, comments: 0, collaborators: 0, editTime: 0 },
                quality: { design: 0, branding: 0, accessibility: 0, overall: 0 }
            };

            const design = new Design(designData);
            await design.save();

            // Async increment template usage
            template.incrementUsage(userId, 'use').catch(err =>
                logger.error(`Template usage increment failed for templateId ${templateId}:`, err)
            );

            res.status(201).json({
                success: true,
                message: 'Design created successfully',
                data: {
                    designId: design.designId,
                    name: design.name,
                    status: design.status,
                    templateId
                }
            });
        } catch (error) {
            logger.error(`Design creation error for templateId ${templateId}:`, error);
            return next(new AppError('Design creation failed', 500));
        }
    });

    // Create blank design
    createBlankDesign = catchAsync(async (req, res, next) => {
        const { name, category, dimensions, description } = req.body;
        const userId = req.user.id;

        if (!name || !category || !dimensions || !dimensions.width || !dimensions.height) {
            return next(new AppError('Name, category, and dimensions (width, height) are required', 400));
        }

        // Validate dimensions
        if (dimensions.width < 100 || dimensions.height < 100 ||
            dimensions.width > 8192 || dimensions.height > 8192) {
            return next(new AppError('Invalid dimensions (100-8192px)', 400));
        }

        try {
            const designData = {
                designId: `des_${Date.now().toString(36)}${Math.random().toString(36).substring(2, 8)}`,
                userId,
                name: name.trim().slice(0, 100),
                description: description?.trim().slice(0, 500) || '',
                category: category || 'profile-cover',
                status: 'draft',
                accessControl: {
                    visibility: 'private',
                    allowedUsers: [],
                    allowedGroups: [],
                    allowDownload: false,
                    allowShare: false
                },
                dimensions: {
                    width: dimensions.width,
                    height: dimensions.height,
                    aspectRatio: Math.round((dimensions.width / dimensions.height) * 100) / 100
                },
                analytics: { views: 0, likes: 0, shares: 0, downloads: 0, comments: 0, collaborators: 0, editTime: 0 },
                quality: { design: 0, branding: 0, accessibility: 0, overall: 0 }
            };

            const design = new Design(designData);
            await design.save();

            res.status(201).json({
                success: true,
                message: 'Blank design created successfully',
                data: {
                    designId: design.designId,
                    name: design.name,
                    status: design.status,
                    dimensions: design.dimensions
                }
            });
        } catch (error) {
            logger.error(`Blank design creation error for userId ${userId}:`, error);
            return next(new AppError('Design creation failed', 500));
        }
    });

    // Get user designs
    getUserDesigns = catchAsync(async (req, res, next) => {
        const userId = req.user.id;
        const {
            status = 'all',
            category = 'profile-cover',
            page = 1,
            limit = 20,
            sortBy = 'updated',
            search
        } = req.query;

        const query = {
            userId,
            ...(category !== 'all' ? { category } : { category: 'profile-cover' }),
            ...(status !== 'all' ? { status } : { status: { $ne: 'deleted' } }),
            ...(search ? { $text: { $search: search } } : {})
        };

        let sortOption;
        switch (sortBy) {
            case 'updated': sortOption = { updatedAt: -1 }; break;
            case 'created': sortOption = { createdAt: 1 }; break;
            case 'name': sortOption = { name: 1 }; break;
            case 'popularity': sortOption = { 'analytics.popularityScore': -1 }; break;
            default: sortOption = { updatedAt: -1 };
        }

        const skip = (page - 1) * limit;
        const designs = await Design.find(query)
            .select('designId name description category status accessControl dimensions quality analytics createdAt updatedAt')
            .sort(sortOption)
            .skip(skip)
            .limit(parseInt(limit))
            .hint('userId_status_category')
            .cache({ key: `designs:user:${userId}:${page}:${limit}:${sortBy}:${status}:${category}:${search || ''}` })
            .lean();

        const totalCount = await Design.countDocuments(query).hint('userId_status_category');
        const totalPages = Math.ceil(totalCount / limit);

        res.json({
            success: true,
            data: {
                designs,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    totalCount,
                    totalPages,
                    hasNext: page < totalPages,
                    hasPrev: page > 1
                }
            }
        });
    });

    // Get single design
    getDesignById = catchAsync(async (req, res, next) => {
        const { designId } = req.params;
        const userId = req.user?.id;

        const design = await Design.findOne({ designId })
            .cache({ key: `design:${designId}:${userId || 'public'}` });

        if (!design) {
            return next(new AppError('Design not found', 404));
        }

        // Check access permissions
        const hasAccess = design.userId === userId ||
            design.accessControl.visibility === 'public' ||
            design.accessControl.allowedUsers.includes(userId) ||
            design.collaboration.collaborators.some(c => c.userId === userId && c.status === 'accepted');

        if (!hasAccess) {
            return next(new AppError('Access denied', 403));
        }

        // Increment view count (async)
        if (userId && userId !== design.userId) {
            design.incrementViews(userId).catch(err =>
                logger.error(`View increment failed for designId ${designId}:`, err)
            );
        }

        // Filter data based on access level
        const responseData = design.userId === userId ? design.toObject() : design.getPublicData();

        res.json({
            success: true,
            data: responseData
        });
    });

    // Update design
    updateDesign = catchAsync(async (req, res, next) => {
        const { designId } = req.params;
        const userId = req.user.id;
        const updates = req.body;

        const design = await Design.findOne({
            designId,
            $or: [
                { userId },
                { 'collaboration.collaborators': { $elemMatch: { userId, role: { $in: ['editor', 'admin'] }, status: 'accepted' } } }
            ]
        });

        if (!design) {
            return next(new AppError('Design not found or access denied', 404));
        }

        // Allowed update fields
        const allowedUpdates = [
            'name', 'description', 'status', 'accessControl.visibility', 'accessControl.allowDownload',
            'accessControl.allowShare', 'tags', 'customizations', 'branding', 'format'
        ];

        const updateData = {};
        Object.keys(updates).forEach(key => {
            if (allowedUpdates.includes(key)) {
                if (key === 'tags') {
                    updateData[key] = updates[key].map(tag => tag.trim().toLowerCase()).slice(0, 10);
                } else if (key === 'customizations') {
                    updateData[key] = updates[key].slice(0, 50).map(c => ({
                        ...c,
                        appliedAt: new Date(),
                        source: 'user'
                    }));
                } else if (key.startsWith('accessControl.')) {
                    updateData[key] = updates[key];
                } else {
                    updateData[key] = updates[key];
                }
            }
        });

        if (Object.keys(updateData).length === 0) {
            return next(new AppError('No valid update fields provided', 400));
        }

        // Create version for significant changes
        const significantChanges = ['customizations', 'branding'];
        if (Object.keys(updateData).some(key => significantChanges.includes(key))) {
            design.createVersion(`Modifications by user ${userId}`, userId);
        }

        const updatedDesign = await Design.findOneAndUpdate(
            { designId },
            { $set: updateData, $inc: { cacheVersion: 1 } },
            { new: true, runValidators: true }
        );

        res.json({
            success: true,
            message: 'Design updated successfully',
            data: updatedDesign.getPublicData()
        });
    });

    // Add customization to design
    addCustomization = catchAsync(async (req, res, next) => {
        const { designId } = req.params;
        const { elementId, elementType, originalValue, customValue } = req.body;
        const userId = req.user.id;

        if (!elementId || !elementType || customValue === undefined) {
            return next(new AppError('elementId, elementType, and customValue are required', 400));
        }

        const design = await Design.findOne({
            designId,
            $or: [
                { userId },
                { 'collaboration.collaborators': { $elemMatch: { userId, role: { $in: ['editor', 'admin'] }, status: 'accepted' } } }
            ]
        });

        if (!design) {
            return next(new AppError('Design not found or access denied', 404));
        }

        design.addCustomization(elementId, elementType, originalValue, customValue, 'user');
        await design.save();

        res.json({
            success: true,
            message: 'Customization added successfully',
            data: {
                designId,
                totalCustomizations: design.customizations.length,
                latestCustomization: design.customizations[design.customizations.length - 1]
            }
        });
    });

    // Apply branding to design
    applyBranding = catchAsync(async (req, res, next) => {
        const { designId } = req.params;
        const { brandProfile, autoApply = false } = req.body;
        const userId = req.user.id;

        const design = await Design.findOne({
            designId,
            $or: [
                { userId },
                { 'collaboration.collaborators': { $elemMatch: { userId, role: { $in: ['editor', 'admin'] }, status: 'accepted' } } }
            ]
        });

        if (!design) {
            return next(new AppError('Design not found or access denied', 404));
        }

        if (!brandProfile || typeof brandProfile !== 'object') {
            return next(new AppError('Valid brand profile is required', 400));
        }

        // Apply branding
        design.branding.enabled = true;
        design.branding.brandProfile = {
            companyName: brandProfile.companyName?.slice(0, 100),
            colors: brandProfile.colors || {},
            fonts: brandProfile.fonts || {},
            logo: brandProfile.logo || {}
        };
        design.branding.autoApply = autoApply;

        // Calculate brand consistency score
        let consistencyScore = 0;
        if (brandProfile.companyName) consistencyScore += 20;
        if (brandProfile.colors?.primary) consistencyScore += 30;
        if (brandProfile.fonts?.primary) consistencyScore += 25;
        if (brandProfile.logo?.url) consistencyScore += 25;
        design.branding.consistency = Math.min(consistencyScore, 100);

        // Auto-apply branding
        if (autoApply) {
            design.customizations.push({
                elementId: `auto-brand-${Date.now()}`,
                elementType: 'style',
                originalValue: null,
                customValue: design.branding.brandProfile,
                source: 'branding',
                appliedAt: new Date()
            });
        }

        design.createVersion(`Branding applied by user ${userId}`, userId);
        await design.save();

        res.json({
            success: true,
            message: 'Branding applied successfully',
            data: {
                designId,
                brandingEnabled: design.branding.enabled,
                consistencyScore: design.branding.consistency
            }
        });
    });

    // Export design
    exportDesign = catchAsync(async (req, res, next) => {
        const { designId } = req.params;
        const { format = 'png', quality = 'web', dimensions, includeBleed = false } = req.body;
        const userId = req.user.id;

        const design = await Design.findOne({
            designId,
            $or: [
                { userId },
                { 'collaboration.collaborators': { $elemMatch: { userId, status: 'accepted' } } }
            ]
        });

        if (!design) {
            return next(new AppError('Design not found or access denied', 404));
        }

        if (!['jpeg', 'png', 'webp', 'svg', 'pdf'].includes(format)) {
            return next(new AppError('Invalid export format (jpeg, png, webp, svg, pdf)', 400));
        }

        try {
            const exportResult = await DesignService.exportDesign(design, {
                format,
                quality,
                dimensions: dimensions || design.dimensions,
                includeBleed
            });

            const exportRecord = {
                exportId: `exp_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
                format,
                quality,
                dimensions: exportResult.dimensions,
                fileSize: exportResult.fileSize,
                downloadUrl: exportResult.downloadUrl,
                expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
                settings: {
                    includeBleed,
                    dpi: quality === 'print' ? 300 : 72,
                    colorSpace: format === 'pdf' ? 'CMYK' : 'RGB'
                }
            };

            design.exportHistory.push(exportRecord);
            design.analytics.downloads += 1;
            design.cacheVersion += 1;

            if (design.exportHistory.length > 20) {
                design.exportHistory = design.exportHistory.slice(-20);
            }

            await design.save();

            res.json({
                success: true,
                message: 'Design exported successfully',
                data: {
                    exportId: exportRecord.exportId,
                    downloadUrl: exportResult.downloadUrl,
                    format,
                    fileSize: exportResult.fileSize,
                    expiresAt: exportRecord.expiresAt
                }
            });
        } catch (error) {
            logger.error(`Design export error for designId ${designId}:`, error);
            return next(new AppError('Export failed', 500));
        }
    });

    // Duplicate design
    duplicateDesign = catchAsync(async (req, res, next) => {
        const { designId } = req.params;
        const { name } = req.body;
        const userId = req.user.id;

        const originalDesign = await Design.findOne({
            designId,
            $or: [
                { userId },
                { accessControl: { visibility: 'public' } },
                { 'collaboration.collaborators': { $elemMatch: { userId, status: 'accepted' } } }
            ]
        }).cache({ key: `design:${designId}:${userId}` });

        if (!originalDesign) {
            return next(new AppError('Design not found or access denied', 404));
        }

        try {
            const duplicateData = originalDesign.toObject();
            delete duplicateData._id;
            delete duplicateData.designId;
            delete duplicateData.analytics;
            delete duplicateData.exportHistory;
            delete duplicateData.collaboration;
            delete duplicateData.versionHistory;
            delete duplicateData.performanceMetrics;

            duplicateData.designId = `des_${Date.now().toString(36)}${Math.random().toString(36).substring(2, 8)}`;
            duplicateData.userId = userId;
            duplicateData.name = name?.trim().slice(0, 100) || `${originalDesign.name} (Copy)`;
            duplicateData.accessControl = {
                visibility: 'private',
                allowedUsers: [],
                allowedGroups: [],
                allowDownload: false,
                allowShare: false
            };
            duplicateData.status = 'draft';
            duplicateData.createdAt = new Date();
            duplicateData.updatedAt = new Date();
            duplicateData.cacheVersion = 0;

            const duplicateDesign = new Design(duplicateData);
            await duplicateDesign.save();

            res.status(201).json({
                success: true,
                message: 'Design duplicated successfully',
                data: {
                    designId: duplicateDesign.designId,
                    name: duplicateDesign.name
                }
            });
        } catch (error) {
            logger.error(`Design duplication error for designId ${designId}:`, error);
            return next(new AppError('Duplication failed', 500));
        }
    });

    // Delete design (soft or permanent)
    deleteDesign = catchAsync(async (req, res, next) => {
        const { designId } = req.params;
        const userId = req.user.id;
        const { permanent = false } = req.query;

        const design = await Design.findOne({
            designId,
            $or: [
                { userId },
                { 'collaboration.collaborators': { $elemMatch: { userId, role: 'admin', status: 'accepted' } } }
            ]
        });

        if (!design) {
            return next(new AppError('Design not found or access denied', 404));
        }

        try {
            if (permanent) {
                // Delete associated assets (e.g., Cloudinary images)
                if (design.processing?.original?.cloudinaryId) {
                    await DesignService.deleteAssets(design.processing.original.cloudinaryId);
                }
                await Design.findByIdAndDelete(design._id);
                res.json({
                    success: true,
                    message: 'Design permanently deleted'
                });
            } else {
                design.status = 'deleted';
                design.cacheVersion += 1;
                await design.save();
                res.json({
                    success: true,
                    message: 'Design moved to trash'
                });
            }
        } catch (error) {
            logger.error(`Design deletion error for designId ${designId}:`, error);
            return next(new AppError('Deletion failed', 500));
        }
    });
}

export default new DesignController();