import { AppError } from '../errors/app.error.js';
import { logger } from '../utils/logger.js';
import { catchAsync } from '../handler/catchAsync.js';
import { BrandingService } from '../services/BrandingService.js';
import { TemplateService } from '../services/TemplateService.js';
import CoverPhoto from '../models/CoverPhoto.js';
import Design from '../models/Design.model.js';
import { validate as uuidValidate } from 'uuid';
import { body, param, query, validationResult } from 'express-validator';
import { validateImageFile, sanitizeFileName } from '../validations/file.validation.js';
import { uploadToCloudinary } from '../utils/cloudinary.js';

class BrandingController {
    // Validation middleware
    static validateBranding = [
        body('branding').isObject().withMessage('Branding must be an object'),
        body('branding.companyName').optional().isString().trim().isLength({ max: 100 }).withMessage('Company name must be a string, max 100 chars'),
        body('branding.logo.url').optional().isURL().withMessage('Logo URL must be valid'),
        body('branding.colors.primary').optional().matches(/^#[0-9A-F]{6}$/i).withMessage('Primary color must be a valid hex code'),
        body('branding.fonts.primary').optional().isString().isLength({ max: 50 }).withMessage('Primary font must be a string, max 50 chars'),
    ];

    static validateBulkBranding = [
        body('ids').isArray().withMessage('IDs must be an array'),
        body('ids.*').custom(uuidValidate).withMessage('Invalid ID'),
        body('type').isIn(['cover', 'design']).withMessage('Type must be "cover" or "design"'),
    ];

    // Apply branding to a cover photo
    applyCoverBranding = catchAsync(async (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return next(new AppError(errors.array().map(e => e.msg).join(', '), 400));
        }

        const { coverId } = req.params;
        const { branding } = req.body;
        const userId = req.user.id;

        const coverCount = await CoverPhoto.countDocuments({ userId, status: { $ne: 'deleted' } });
        const uploadLimit = req.user.accountType === 'free' ? 50 : req.user.accountType === 'premium' ? 500 : 1000;
        if (coverCount >= uploadLimit) {
            return next(new AppError(`Cover limit reached (${uploadLimit})`, 403));
        }

        const cover = await BrandingService.applyCoverBranding(coverId, branding, userId, req.user.groups || []);
        logger.info(`Branding applied to cover ${coverId} by user ${userId}`);

        res.status(200).json({
            success: true,
            data: cover.getPublicData()
        });
    });

    // Apply branding to a design
    applyDesignBranding = catchAsync(async (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return next(new AppError(errors.array().map(e => e.msg).join(', '), 400));
        }

        const { designId } = req.params;
        const { branding } = req.body;
        const userId = req.user.id;

        const designCount = await Design.countDocuments({ userId, status: { $ne: 'deleted' } });
        const uploadLimit = req.user.accountType === 'free' ? 50 : req.user.accountType === 'premium' ? 500 : 1000;
        if (designCount >= uploadLimit) {
            return next(new AppError(`Design limit reached (${uploadLimit})`, 403));
        }

        const design = await BrandingService.applyDesignBranding(designId, branding, userId, req.user.groups || []);
        logger.info(`Branding applied to design ${designId} by user ${userId}`);

        res.status(200).json({
            success: true,
            data: design.getPublicData()
        });
    });

    // Check branding compliance
    checkBrandingCompliance = catchAsync(async (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return next(new AppError(errors.array().map(e => e.msg).join(', '), 400));
        }

        const { designId } = req.params;
        const userId = req.user.id;

        const compliance = await BrandingService.checkBrandingCompliance(designId, userId, req.user.groups || []);
        logger.info(`Branding compliance checked for design ${designId} by user ${userId}`);

        res.status(200).json({
            success: true,
            data: { designId, compliance }
        });
    });

    // Bulk apply branding
    bulkApplyBranding = catchAsync(async (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return next(new AppError(errors.array().map(e => e.msg).join(', '), 400));
        }

        const { ids, type, branding } = req.body;
        const userId = req.user.id;

        if (!ids || ids.length === 0) {
            return next(new AppError('At least one ID is required', 400));
        }

        if (ids.length > 50) {
            return next(new AppError('Maximum 50 items can be updated at once', 400));
        }

        const results = await BrandingService.bulkApplyBranding(ids, type, branding, userId, req.user.groups || []);
        logger.info(`Bulk branding applied to ${ids.length} ${type}s by user ${userId}`);

        res.status(200).json({
            success: true,
            data: {
                total: ids.length,
                updated: results.updated.length,
                failed: results.failed
            }
        });
    });

    // Upload branding logo
    uploadBrandingLogo = catchAsync(async (req, res, next) => {
        const { file } = req;
        const { designId } = req.params;
        const userId = req.user.id;

        if (!file) {
            return next(new AppError('No file uploaded', 400));
        }

        const validation = validateImageFile(file);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        const design = await Design.findOne({ designId, userId });
        if (!design) {
            return next(new AppError('Design not found', 404));
        }

        const uploadResult = await uploadToCloudinary(file.buffer, {
            folder: `branding/${userId}`,
            public_id: `logo_${designId}_${Date.now()}`,
            resource_type: 'image',
            quality: 'auto:eco'
        });

        design.branding.brandProfile.logo.url = uploadResult.secure_url;
        design.branding.brandProfile.logo.cloudinaryId = uploadResult.public_id;
        design.cacheVersion += 1;
        await design.save();

        logger.info(`Branding logo uploaded for design ${designId} by user ${userId}`);

        res.status(200).json({
            success: true,
            data: {
                designId,
                logoUrl: uploadResult.secure_url
            }
        });
    });

    // Generate AI branding suggestions
    generateBrandingSuggestions = catchAsync(async (req, res, next) => {
        const { designId } = req.params;
        const { style, mood } = req.body;
        const userId = req.user.id;

        const design = await Design.findOne({ designId, userId });
        if (!design) {
            return next(new AppError('Design not found', 404));
        }

        const suggestions = await BrandingService.generateBrandingSuggestions(design, { style, mood });
        design.aiAssistance.suggestions.push(...suggestions.map(s => ({
            suggestionId: `sug_${Date.now().toString(36)}${Math.random().toString(36).substring(2, 8)}`,
            type: 'branding',
            suggestedValue: s,
            confidence: 0.9,
            createdAt: new Date()
        })));
        await design.save();

        logger.info(`Branding suggestions generated for design ${designId} by user ${userId}`);

        res.status(200).json({
            success: true,
            data: suggestions
        });
    });

    // Get branding audit trail
    getBrandingAuditTrail = catchAsync(async (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return next(new AppError(errors.array().map(e => e.msg).join(', '), 400));
        }

        const { designId } = req.params;
        const { limit = 50 } = req.query;
        const userId = req.user.id;

        const auditTrail = await BrandingService.getBrandingAuditTrail(designId, userId, req.user.groups || [], limit);
        logger.info(`Branding audit trail retrieved for design ${designId} by user ${userId}`);

        res.status(200).json({
            success: true,
            data: { designId, auditTrail }
        });
    });

    // Revert branding changes
    revertBranding = catchAsync(async (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return next(new AppError(errors.array().map(e => e.msg).join(', '), 400));
        }

        const { designId, versionId } = req.params;
        const userId = req.user.id;

        const design = await BrandingService.revertBranding(designId, versionId, userId, req.user.groups || []);
        logger.info(`Branding reverted for design ${designId} to version ${versionId} by user ${userId}`);

        res.status(200).json({
            success: true,
            data: design.getPublicData()
        });
    });

    // Preview branding application
    previewBranding = catchAsync(async (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return next(new AppError(errors.array().map(e => e.msg).join(', '), 400));
        }

        const { id, type } = req.params;
        const { branding } = req.body;
        const userId = req.user.id;

        const previewUrl = await BrandingService.previewBranding(id, type, branding, userId, req.user.groups || []);
        logger.info(`Branding preview generated for ${type} ${id} by user ${userId}`);

        res.status(200).json({
            success: true,
            data: { previewUrl }
        });
    });
}

export default new BrandingController();