import { AppError } from '../errors/app.error.js';
import { logger } from '../utils/logger.js';
import CoverPhoto from '../models/CoverPhoto.js';
import Design from '../models/Design.model.js';
import { TemplateService } from './TemplateService.js';
import { processImage, analyzeWithAI } from './cover.service.js';
import { uploadToCloudinary } from '../utils/cloudinary.js';
import { v4 as uuidv4 } from 'uuid';

export class BrandingService {
    static async applyCoverBranding(coverId, branding, userId, groups = []) {
        const cover = await CoverPhoto.findOne({
            coverId,
            $or: [
                { userId },
                { 'accessControl.allowedUsers': userId },
                { 'accessControl.allowedGroups': { $in: groups } }
            ]
        });

        if (!cover) {
            throw new AppError('Cover photo not found or access denied', 404);
        }

        if (!cover.accessControl.allowModification) {
            throw new AppError('Modification not allowed for this cover photo', 403);
        }

        cover.brandingElements = {
            logo: {
                enabled: !!branding.logo?.url,
                url: branding.logo?.url || '',
                position: branding.logo?.position || 'bottom-right',
                size: branding.logo?.size || 0.2,
                opacity: branding.logo?.opacity || 1
            },
            companyName: {
                enabled: !!branding.companyName,
                text: branding.companyName || '',
                font: branding.fonts?.primary || 'Arial',
                color: branding.colors?.primary || '#FFFFFF',
                position: branding.companyName?.position || 'bottom-left',
                size: branding.companyName?.size || 24
            },
            colorOverlay: {
                enabled: !!branding.colors?.primary,
                color: branding.colors?.primary || '#000000',
                opacity: branding.colorOverlay?.opacity || 0.3,
                blendMode: branding.colorOverlay?.blendMode || 'normal'
            }
        };

        if (cover.templateId) {
            const templateValidation = await TemplateService.validateTemplate(cover.templateId);
            if (!templateValidation.valid) {
                throw new AppError(`Template validation failed: ${templateValidation.errors.join(', ')}`, 400);
            }
        }

        cover.cacheVersion += 1;
        return await cover.save();
    }

    static async applyDesignBranding(designId, branding, userId, groups = []) {
        const design = await Design.findOne({
            designId,
            $or: [
                { userId },
                { 'accessControl.allowedUsers': userId },
                { 'accessControl.allowedGroups': { $in: groups } },
                { 'collaboration.collaborators': { $elemMatch: { userId, status: 'accepted', role: { $in: ['editor', 'admin'] } } } }
            ]
        });

        if (!design) {
            throw new AppError('Design not found or access denied', 404);
        }

        design.branding = {
            enabled: true,
            brandProfile: {
                companyName: branding.companyName || '',
                logo: {
                    url: branding.logo?.url || '',
                    position: branding.logo?.position || 'bottom-right',
                    size: branding.logo?.size || 0.2,
                    opacity: branding.logo?.opacity || 1
                },
                colors: {
                    primary: branding.colors?.primary || '#000000',
                    secondary: branding.colors?.secondary || '#000000',
                    accent: branding.colors?.accent || '#000000',
                    text: branding.colors?.text || '#000000',
                    background: branding.colors?.background || '#FFFFFF'
                },
                fonts: {
                    primary: branding.fonts?.primary || 'Arial',
                    secondary: branding.fonts?.secondary || 'Arial',
                    accent: branding.fonts?.accent || 'Arial'
                },
                style: branding.style || 'professional'
            },
            appliedElements: [],
            autoApply: branding.autoApply || false,
            consistency: branding.consistency || 0
        };

        const compliance = design.validateBrandingCompliance();
        design.compliance.brandGuidelines = {
            compliant: compliance.compliant,
            violations: compliance.violations,
            lastChecked: new Date()
        };

        design.createVersion('Applied branding', userId);
        return await design.save();
    }

    static async checkBrandingCompliance(designId, userId, groups = []) {
        const design = await Design.findOne({
            designId,
            $or: [
                { userId },
                { 'accessControl.allowedUsers': userId },
                { 'accessControl.allowedGroups': { $in: groups } },
                { 'collaboration.collaborators': { $elemMatch: { userId, status: 'accepted' } } }
            ]
        });

        if (!design) {
            throw new AppError('Design not found or access denied', 404);
        }

        const compliance = design.validateBrandingCompliance();
        design.compliance.brandGuidelines = {
            compliant: compliance.compliant,
            violations: compliance.violations,
            lastChecked: new Date()
        };

        await design.save();
        return design.compliance.brandGuidelines;
    }

    static async bulkApplyBranding(ids, type, branding, userId, groups = []) {
        const Model = type === 'cover' ? CoverPhoto : Design;
        const field = type === 'cover' ? 'coverId' : 'designId';

        const resources = await Model.find({
            [field]: { $in: ids },
            $or: [
                { userId },
                { 'accessControl.allowedUsers': userId },
                { 'accessControl.allowedGroups': { $in: groups } },
                type === 'design' ? { 'collaboration.collaborators': { $elemMatch: { userId, status: 'accepted', role: { $in: ['editor', 'admin'] } } } } : {}
            ]
        });

        const updated = [];
        const failed = [];

        for (const resource of resources) {
            try {
                if (type === 'cover') {
                    resource.brandingElements = {
                        logo: {
                            enabled: !!branding.logo?.url,
                            url: branding.logo?.url || '',
                            position: branding.logo?.position || 'bottom-right',
                            size: branding.logo?.size || 0.2,
                            opacity: branding.logo?.opacity || 1
                        },
                        companyName: {
                            enabled: !!branding.companyName,
                            text: branding.companyName || '',
                            font: branding.fonts?.primary || 'Arial',
                            color: branding.colors?.primary || '#FFFFFF',
                            position: branding.companyName?.position || 'bottom-left',
                            size: branding.companyName?.size || 24
                        },
                        colorOverlay: {
                            enabled: !!branding.colors?.primary,
                            color: branding.colors?.primary || '#000000',
                            opacity: branding.colorOverlay?.opacity || 0.3,
                            blendMode: branding.colorOverlay?.blendMode || 'normal'
                        }
                    };
                } else {
                    resource.branding = {
                        enabled: true,
                        brandProfile: {
                            companyName: branding.companyName || '',
                            logo: {
                                url: branding.logo?.url || '',
                                position: branding.logo?.position || 'bottom-right',
                                size: branding.logo?.size || 0.2,
                                opacity: branding.logo?.opacity || 1
                            },
                            colors: {
                                primary: branding.colors?.primary || '#000000',
                                secondary: branding.colors?.secondary || '#000000',
                                accent: branding.colors?.accent || '#000000',
                                text: branding.colors?.text || '#000000',
                                background: branding.colors?.background || '#FFFFFF'
                            },
                            fonts: {
                                primary: branding.fonts?.primary || 'Arial',
                                secondary: branding.fonts?.secondary || 'Arial',
                                accent: branding.fonts?.accent || 'Arial'
                            },
                            style: branding.style || 'professional'
                        },
                        appliedElements: [],
                        autoApply: branding.autoApply || false,
                        consistency: branding.consistency || 0
                    };
                    resource.createVersion('Bulk applied branding', userId);
                }

                if (resource.templateId) {
                    const templateValidation = await TemplateService.validateTemplate(resource.templateId);
                    if (!templateValidation.valid) {
                        failed.push({ [field]: resource[field], error: templateValidation.errors.join(', ') });
                        continue;
                    }
                }

                resource.cacheVersion += 1;
                updated.push(await resource.save());
            } catch (error) {
                failed.push({ [field]: resource[field], error: error.message });
            }
        }

        return { updated, failed };
    }

    static async generateBrandingSuggestions(design, options = {}) {
        const analysis = await analyzeWithAI(design.processing.original.url, {
            analyzeColors: true,
            detectObjects: true,
            generateTags: true
        });

        const suggestions = [
            { type: 'color', value: analysis.colors?.primary || '#000000', confidence: 0.9 },
            { type: 'font', value: options.style === 'modern' ? 'Roboto' : 'Arial', confidence: 0.85 },
            { type: 'style', value: options.style || 'professional', confidence: 0.9 }
        ];

        return suggestions;
    }

    static async getBrandingAuditTrail(designId, userId, groups = [], limit = 50) {
        const design = await Design.findOne({
            designId,
            $or: [
                { userId },
                { 'accessControl.allowedUsers': userId },
                { 'accessControl.allowedGroups': { $in: groups } },
                { 'collaboration.collaborators': { $elemMatch: { userId, status: 'accepted' } } }
            ]
        }).select('versionHistory collaboration.activityLog');

        if (!design) {
            throw new AppError('Design not found or access denied', 404);
        }

        const auditTrail = [
            ...design.versionHistory
                .filter(v => v.changes.some(c => c.type.includes('branding')))
                .map(v => ({
                    versionId: v.versionId,
                    type: 'version',
                    changes: v.changes,
                    createdBy: v.createdBy,
                    createdAt: v.createdAt
                })),
            ...design.collaboration.activityLog
                .filter(a => a.action === 'branding-applied')
                .map(a => ({
                    actionId: uuidv4(),
                    type: 'activity',
                    action: a.action,
                    details: a.details,
                    userId: a.userId,
                    timestamp: a.timestamp
                }))
        ].sort((a, b) => b.createdAt - a.createdAt).slice(0, limit);

        return auditTrail;
    }

    static async previewBranding(id, type, branding, userId, groups = []) {
        const Model = type === 'cover' ? CoverPhoto : Design;
        const field = type === 'cover' ? 'coverId' : 'designId';

        const resource = await Model.findOne({
            [field]: id,
            $or: [
                { userId },
                { 'accessControl.allowedUsers': userId },
                { 'accessControl.allowedGroups': { $in: groups } },
                type === 'design' ? { 'collaboration.collaborators': { $elemMatch: { userId, status: 'accepted' } } } : {}
            ]
        });

        if (!resource) {
            throw new AppError(`${type} not found or access denied`, 404);
        }

        const preview = await processImage(resource.processing.original.url, {
            applyBranding: branding,
            generatePreview: true
        });

        return preview.url;
    }

    static async revertBranding(designId, versionId, userId, groups = []) {
        const design = await Design.findOne({
            designId,
            $or: [
                { userId },
                { 'accessControl.allowedUsers': userId },
                { 'accessControl.allowedGroups': { $in: groups } },
                { 'collaboration.collaborators': { $elemMatch: { userId, status: 'accepted', role: { $in: ['editor', 'admin'] } } } }
            ]
        });

        if (!design) {
            throw new AppError('Design not found or access denied', 404);
        }

        const version = design.versionHistory.find(v => v.versionId === versionId);
        if (!version) {
            throw new AppError('Version not found', 404);
        }

        design.branding = version.changes.find(c => c.type === 'branding')?.value || design.branding;
        design.createVersion('Reverted branding', userId);
        return await design.save();
    }
}