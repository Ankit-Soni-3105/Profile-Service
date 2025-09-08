import Design from '../models/Design.model.js';
import { processImage, analyzeWithAI } from '../services/cover.service.js';
import { uploadToCloudinary } from '../utils/cloudinary.js';
import { validateImageFile, sanitizeFileName } from "../validations/file.validation.js"
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { catchAsync } from '../handler/catchAsync.js';

class CoverUploadController {
    // Upload new cover photo
    uploadCover = catchAsync(async (req, res, next) => {
        const { file } = req;
        const { title, description, category, tags, visibility = 'private', templateId } = req.body;
        const userId = req.user.id;

        // Validate file
        if (!file) {
            return next(new AppError('No file uploaded', 400));
        }

        const validation = validateImageFile(file);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        // Check user upload limits
        const userCoverCount = await Design.countDocuments({
            userId,
            category: 'profile-cover',
            status: { $ne: 'deleted' }
        });

        const uploadLimit = req.user.accountType === 'free' ? 50 :
            req.user.accountType === 'premium' ? 500 : 1000;

        if (userCoverCount >= uploadLimit) {
            return next(new AppError(`Upload limit reached (${uploadLimit} covers)`, 403));
        }

        try {
            // Create initial design document
            const designData = {
                designId: `des_${Date.now().toString(36)}${Math.random().toString(36).substring(2, 8)}`,
                userId,
                templateId: templateId || null,
                name: title || sanitizeFileName(file.originalname),
                description: description || '',
                category: category || 'profile-cover',
                tags: tags ? tags.split(',').map(tag => tag.trim().toLowerCase()).slice(0, 10) : [],
                status: 'draft',
                accessControl: {
                    visibility,
                    allowedUsers: [],
                    allowedGroups: [],
                    allowDownload: visibility === 'public',
                    allowShare: visibility === 'public'
                },
                dimensions: { width: 0, height: 0, aspectRatio: 0 },
                format: file.mimetype.split('/')[1].toLowerCase(),
                quality: { design: 0, branding: 0, accessibility: 0, overall: 0 },
                analytics: { views: 0, likes: 0, shares: 0, downloads: 0, comments: 0, collaborators: 0, editTime: 0 },
                processing: {
                    status: 'pending',
                    original: { url: '', size: file.size, cloudinaryId: '' },
                    optimized: {},
                    thumbnails: [],
                    variants: []
                }
            };

            const design = new Design(designData);
            await design.save();

            // Start async processing
            this.processUploadAsync(design, file, userId);

            res.status(201).json({
                success: true,
                message: 'Cover upload started',
                data: {
                    designId: design.designId,
                    status: 'processing',
                    estimatedTime: '30-60 seconds'
                }
            });

        } catch (error) {
            logger.error(`Cover upload error for designId ${designData.designId}:`, error);
            return next(new AppError('Upload failed', 500));
        }
    });

    // Async processing pipeline
    processUploadAsync = async (design, file, userId) => {
        try {
            design.processing.status = 'processing';
            design.processing.processingStartedAt = new Date();
            await design.save();

            // 1. Upload to cloud storage
            const uploadResult = await uploadToCloudinary(file.buffer, {
                folder: `covers/${userId}`,
                public_id: design.designId,
                resource_type: 'image',
                quality: 'auto:eco',
                fetch_format: 'auto'
            });

            // 2. Extract metadata and process variants
            const processedResult = await processImage(uploadResult.secure_url, {
                generateThumbnails: true,
                generateVariants: true,
                optimize: true
            });

            // 3. AI analysis
            const aiAnalysis = await analyzeWithAI(uploadResult.secure_url, {
                analyzeColors: true,
                detectObjects: true,
                assessQuality: true,
                generateTags: true
            });

            // 4. Update design with processed data
            design.dimensions.width = processedResult.width;
            design.dimensions.height = processedResult.height;
            design.dimensions.aspectRatio = Math.round((processedResult.width / processedResult.height) * 100) / 100;

            design.processing.original.url = uploadResult.secure_url;
            design.processing.original.cloudinaryId = uploadResult.public_id;
            design.processing.optimized = processedResult.optimized || {};
            design.processing.thumbnails = processedResult.thumbnails || [];
            design.processing.variants = processedResult.variants || [];
            design.processing.status = 'completed';
            design.processing.processingCompletedAt = new Date();
            design.processing.processingDuration = Date.now() - design.processing.processingStartedAt.getTime();

            design.aiAssistance.suggestions = aiAnalysis.suggestions || [];
            design.quality = {
                design: aiAnalysis.qualityScore?.design || 0,
                branding: aiAnalysis.qualityScore?.branding || 0,
                accessibility: aiAnalysis.qualityScore?.accessibility || 0,
                overall: aiAnalysis.qualityScore?.overall || 0
            };
            design.status = 'active';
            design.tags = [...new Set([...design.tags, ...(aiAnalysis.tags || []).map(tag => tag.toLowerCase())])].slice(0, 10);

            await design.save();
            design.calculateQualityScores(); // Recalculate quality scores
            await design.save();

            logger.info(`Cover processed successfully: ${design.designId}`);

        } catch (error) {
            logger.error(`Cover processing failed for designId ${design.designId}:`, error);

            design.processing.status = 'failed';
            design.processing.errorMessage = error.message;
            design.processing.retryCount = (design.processing.retryCount || 0) + 1;
            design.status = 'processing';

            await design.save();
        }
    };

    // Get upload status
    getUploadStatus = catchAsync(async (req, res, next) => {
        const { designId } = req.params;
        const userId = req.user.id;

        const design = await Design.findOne({ designId, userId })
            .select('processing.status processing.processingDuration processing.errorMessage status')
            .cache({ key: `design:status:${designId}:${userId}` });

        if (!design) {
            return next(new AppError('Cover not found', 404));
        }

        res.json({
            success: true,
            data: {
                designId,
                status: design.processing.status,
                overallStatus: design.status,
                processingDuration: design.processing.processingDuration,
                error: design.processing.errorMessage
            }
        });
    });

    // Get user's covers with filtering and pagination
    getUserCovers = catchAsync(async (req, res, next) => {
        const userId = req.user.id;
        const {
            page = 1,
            limit = 20,
            category = 'profile-cover',
            status,
            sortBy = 'recent',
            search
        } = req.query;

        const query = { userId, category };

        if (status && status !== 'all') {
            query.status = status;
        } else {
            query.status = { $ne: 'deleted' };
        }

        if (search) {
            query.$text = { $search: search };
        }

        let sortOption = {};
        switch (sortBy) {
            case 'recent': sortOption = { updatedAt: -1 }; break;
            case 'oldest': sortOption = { createdAt: 1 }; break;
            case 'popular': sortOption = { 'analytics.popularityScore': -1, 'analytics.views': -1 }; break;
            case 'name': sortOption = { name: 1 }; break;
            case 'quality': sortOption = { 'quality.overall': -1 }; break;
            default: sortOption = { updatedAt: -1 };
        }

        const skip = (page - 1) * limit;

        const designs = await Design.find(query)
            .sort(sortOption)
            .skip(skip)
            .limit(parseInt(limit))
            .select('designId name description category status accessControl dimensions quality analytics createdAt updatedAt')
            .cache({ key: `user:designs:${userId}:${page}:${limit}:${sortBy}:${status}:${category}:${search || ''}` })
            .lean();

        const totalCount = await Design.countDocuments(query);
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

    // Get single cover details
    getCoverById = catchAsync(async (req, res, next) => {
        const { designId } = req.params;
        const userId = req.user?.id;

        const design = await Design.findOne({ designId })
            .cache({ key: `design:${designId}:${userId || 'public'}` });

        if (!design) {
            return next(new AppError('Cover not found', 404));
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

        // Return appropriate data based on access level
        const responseData = design.userId === userId ? design.toObject() : design.getPublicData();

        res.json({
            success: true,
            data: responseData
        });
    });

    // Update cover metadata
    updateCover = catchAsync(async (req, res, next) => {
        const { designId } = req.params;
        const userId = req.user.id;
        const updates = req.body;

        const design = await Design.findOne({ designId, userId });

        if (!design) {
            return next(new AppError('Cover not found', 404));
        }

        // Allowed update fields
        const allowedUpdates = [
            'name', 'description', 'category', 'tags',
            'accessControl.visibility', 'accessControl.allowDownload',
            'accessControl.allowShare', 'accessControl.allowedUsers',
            'accessControl.allowedGroups'
        ];

        const updateData = {};
        Object.keys(updates).forEach(key => {
            if (allowedUpdates.includes(key)) {
                if (key === 'tags' && Array.isArray(updates[key])) {
                    updateData[key] = updates[key].map(tag => tag.trim().toLowerCase()).slice(0, 10);
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

        const updatedDesign = await Design.findOneAndUpdate(
            { designId, userId },
            { $set: updateData, $inc: { cacheVersion: 1 } },
            { new: true, runValidators: true }
        );

        res.json({
            success: true,
            message: 'Cover updated successfully',
            data: updatedDesign.getPublicData()
        });
    });

    // Delete cover (soft or permanent)
    deleteCover = catchAsync(async (req, res, next) => {
        const { designId } = req.params;
        const userId = req.user.id;
        const { permanent = false } = req.query;

        const design = await Design.findOne({ designId, userId });

        if (!design) {
            return next(new AppError('Cover not found', 404));
        }

        if (permanent) {
            // Permanent deletion - remove from cloud storage
            if (design.processing.original.cloudinaryId) {
                try {
                    await uploadToCloudinary.destroy(design.processing.original.cloudinaryId);
                } catch (error) {
                    logger.error(`Failed to delete from Cloudinary for designId ${designId}:`, error);
                }
            }

            await Design.findByIdAndDelete(design._id);

            res.json({
                success: true,
                message: 'Cover permanently deleted'
            });
        } else {
            // Soft delete
            design.status = 'deleted';
            design.cacheVersion += 1;
            await design.save();

            res.json({
                success: true,
                message: 'Cover moved to trash'
            });
        }
    });

    // Bulk operations
    bulkUpdateCovers = catchAsync(async (req, res, next) => {
        const { designIds, operation, data } = req.body;
        const userId = req.user.id;

        if (!Array.isArray(designIds) || designIds.length === 0) {
            return next(new AppError('Design IDs array is required', 400));
        }

        if (designIds.length > 50) {
            return next(new AppError('Maximum 50 designs can be updated at once', 400));
        }

        const query = { designId: { $in: designIds }, userId };

        let updateData = {};
        let message = '';

        switch (operation) {
            case 'delete':
                updateData = { status: 'deleted', cacheVersion: { $inc: 1 } };
                message = 'Covers moved to trash';
                break;
            case 'category':
                if (!data.category) {
                    return next(new AppError('Category is required', 400));
                }
                updateData = { category: data.category, cacheVersion: { $inc: 1 } };
                message = 'Category updated for covers';
                break;
            case 'visibility':
                if (!data.visibility) {
                    return next(new AppError('Visibility is required', 400));
                }
                updateData = { 'accessControl.visibility': data.visibility, cacheVersion: { $inc: 1 } };
                message = 'Visibility updated for covers';
                break;
            case 'addTags':
                if (!Array.isArray(data.tags)) {
                    return next(new AppError('Tags array is required', 400));
                }
                updateData = {
                    $addToSet: {
                        tags: { $each: data.tags.map(tag => tag.trim().toLowerCase()).slice(0, 10) }
                    },
                    $inc: { cacheVersion: 1 }
                };
                message = 'Tags added to covers';
                break;
            default:
                return next(new AppError('Invalid operation', 400));
        }

        const result = await Design.updateMany(query, updateData);

        res.json({
            success: true,
            message,
            data: {
                matched: result.matchedCount,
                modified: result.modifiedCount
            }
        });
    });

    // Generate cover variations using AI
    generateVariations = catchAsync(async (req, res, next) => {
        const { designId } = req.params;
        const { count = 3, style, mood } = req.body;
        const userId = req.user.id;

        const design = await Design.findOne({ designId, userId });

        if (!design) {
            return next(new AppError('Cover not found', 404));
        }

        if (count > 5) {
            return next(new AppError('Maximum 5 variations allowed', 400));
        }

        try {
            // Generate variations using AI service
            const variations = await processImage(design.processing.original.url, {
                count,
                style: style || design.aiAssistance.suggestions.find(s => s.type === 'style')?.suggestedValue || 'professional',
                mood: mood || design.aiAssistance.suggestions.find(s => s.type === 'mood')?.suggestedValue || 'neutral',
                preserveAspectRatio: true
            });

            // Save variations as customizations
            variations.forEach((variation, index) => {
                design.addCustomization(
                    `${design.designId}_var_${index + 1}`,
                    'image',
                    design.processing.original.url,
                    variation.url,
                    'ai-suggestion'
                );
            });

            await design.save();

            res.json({
                success: true,
                message: 'Variations generated successfully',
                data: {
                    original: design.designId,
                    variations: variations.map((variation, index) => ({
                        variationId: `${design.designId}_var_${index + 1}`,
                        url: variation.url,
                        style: variation.style,
                        mood: variation.mood,
                        processingTime: variation.processingTime
                    }))
                }
            });

        } catch (error) {
            logger.error(`Variation generation failed for designId ${designId}:`, error);
            return next(new AppError('Failed to generate variations', 500));
        }
    });

    // Get cover analytics
    getCoverAnalytics = catchAsync(async (req, res, next) => {
        const { designId } = req.params;
        const userId = req.user.id;
        const { timeframe = '30d' } = req.query;

        const design = await Design.findOne({ designId, userId })
            .cache({ key: `analytics:design:${designId}:${userId}:${timeframe}` });

        if (!design) {
            return next(new AppError('Cover not found', 404));
        }

        // Calculate timeframe
        let daysAgo = 30;
        switch (timeframe) {
            case '7d': daysAgo = 7; break;
            case '30d': daysAgo = 30; break;
            case '90d': daysAgo = 90; break;
            case '1y': daysAgo = 365; break;
        }

        const startDate = new Date();
        startDate.setDate(startDate.getDate() - daysAgo);

        // Get analytics data
        const analytics = {
            summary: {
                totalViews: design.analytics.views,
                likes: design.analytics.likes,
                shares: design.analytics.shares,
                downloads: design.analytics.downloads,
                comments: design.analytics.comments,
                popularityScore: design.analytics.popularityScore
            },
            qualityMetrics: {
                overall: design.quality.overall,
                design: design.quality.design,
                branding: design.quality.branding,
                accessibility: design.quality.accessibility
            }
        };

        res.json({
            success: true,
            data: analytics
        });
    });
}

export default new CoverUploadController();