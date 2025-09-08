import { validate as uuidValidate } from 'uuid';
import { AppError } from '../errors/app.error.js';
import { logger } from '../utils/logger.js';
import { uploadToCloudinary, generatePreviewUrl } from '../utils/cloudinary.js';
import Template from '../models/Template.model.js';

// Utility function to validate template structure
export const validateTemplate = ({ canvas, layers }) => {
    const errors = [];

    // Validate canvas
    if (!canvas || typeof canvas !== 'object') {
        errors.push('Canvas is required and must be an object');
    } else {
        if (!Number.isFinite(canvas.width) || canvas.width < 100 || canvas.width > 8192) {
            errors.push('Canvas width must be between 100 and 8192 pixels');
        }
        if (!Number.isFinite(canvas.height) || canvas.height < 100 || canvas.height > 8192) {
            errors.push('Canvas height must be between 100 and 8192 pixels');
        }
        if (canvas.backgroundColor && !/^#[0-9A-F]{6}$|^transparent$/i.test(canvas.backgroundColor)) {
            errors.push('Canvas background color must be a valid hex code or transparent');
        }
    }

    // Validate layers
    if (!Array.isArray(layers) || layers.length === 0) {
        errors.push('Layers must be a non-empty array');
    } else {
        const validLayerTypes = ['background', 'image', 'text', 'shape', 'logo', 'overlay', 'gradient'];
        layers.forEach((layer, index) => {
            if (!layer.id || !uuidValidate(layer.id)) {
                errors.push(`Layer ${index}: Invalid or missing UUID`);
            }
            if (!validLayerTypes.includes(layer.type)) {
                errors.push(`Layer ${index}: Invalid type, must be one of ${validLayerTypes.join(', ')}`);
            }
            if (!layer.name || typeof layer.name !== 'string' || layer.name.length > 100) {
                errors.push(`Layer ${index}: Name is required and must be a string (max 100 chars)`);
            }
            if (!Number.isFinite(layer.order) || layer.order < 0) {
                errors.push(`Layer ${index}: Order must be a non-negative number`);
            }
            if (!layer.position || !Number.isFinite(layer.position.x) || !Number.isFinite(layer.position.y)) {
                errors.push(`Layer ${index}: Position must include valid x and y coordinates`);
            }
            if (!layer.size || !Number.isFinite(layer.size.width) || layer.size.width < 0 || !Number.isFinite(layer.size.height) || layer.size.height < 0) {
                errors.push(`Layer ${index}: Size must include valid width and height`);
            }
            if (layer.type === 'text' && (!layer.content.text || typeof layer.content.text !== 'string')) {
                errors.push(`Layer ${index}: Text content is required for text layers`);
            }
            if (layer.type === 'image' && (!layer.content.imageUrl || !/^https?:\/\/.+\.(jpg|jpeg|png|webp)$/.test(layer.content.imageUrl))) {
                errors.push(`Layer ${index}: Valid image URL is required for image layers`);
            }
            if (layer.styling?.color && !/^#[0-9A-F]{6}$/i.test(layer.styling.color)) {
                errors.push(`Layer ${index}: Styling color must be a valid hex code`);
            }
        });

        // Check for duplicate layer IDs
        const layerIds = layers.map(layer => layer.id);
        if (new Set(layerIds).size !== layerIds.length) {
            errors.push('Duplicate layer IDs detected');
        }
    }

    return {
        valid: errors.length === 0,
        errors
    };
};

// Utility function to generate previews
export const generatePreview = async (canvas, layers, options = {}) => {
    const { generateThumbnail = true, generatePreview = true, generateMockups = false } = options;

    try {
        const previews = {};

        // Generate thumbnail (300x200)
        if (generateThumbnail) {
            const thumbnailUrl = await generatePreviewUrl({
                canvas,
                layers,
                width: 300,
                height: 200,
                format: 'jpg',
                quality: 'auto:low'
            });
            const thumbnailData = await uploadToCloudinary(thumbnailUrl, {
                folder: 'templates/thumbnails',
                transformation: [{ width: 300, height: 200, crop: 'fill' }]
            });

            previews.thumbnail = {
                url: thumbnailData.secure_url,
                width: 300,
                height: 200,
                size: thumbnailData.bytes,
                generatedAt: new Date()
            };
        }

        // Generate preview (800x600)
        if (generatePreview) {
            const previewUrl = await generatePreviewUrl({
                canvas,
                layers,
                width: 800,
                height: 600,
                format: 'jpg',
                quality: 'auto:good'
            });
            const previewData = await uploadToCloudinary(previewUrl, {
                folder: 'templates/previews',
                transformation: [{ width: 800, height: 600, crop: 'fill' }]
            });

            previews.preview = {
                url: previewData.secure_url,
                width: 800,
                height: 600,
                size: previewData.bytes,
                generatedAt: new Date()
            };
        }

        // Generate mockups (placeholder for social platforms)
        if (generateMockups) {
            previews.mockups = [];
            const mockupTypes = ['linkedin', 'twitter', 'instagram'];
            for (const type of mockupTypes) {
                const mockupUrl = await generatePreviewUrl({
                    canvas,
                    layers,
                    width: type === 'instagram' ? 1080 : 1200,
                    height: type === 'instagram' ? 1080 : 630,
                    format: 'jpg',
                    quality: 'auto:good'
                });
                const mockupData = await uploadToCloudinary(mockupUrl, {
                    folder: `templates/mockups/${type}`,
                    transformation: [{ width: type === 'instagram' ? 1080 : 1200, height: type === 'instagram' ? 1080 : 630, crop: 'fill' }]
                });

                previews.mockups.push({
                    type,
                    url: mockupData.secure_url,
                    generatedAt: new Date()
                });
            }
        }

        return previews;
    } catch (error) {
        logger.error('Preview generation failed', { error: error.message });
        throw new AppError('Failed to generate previews', 500);
    }
};

// TemplateService class
export class TemplateService {
    // Generate previews and update template
    static async generatePreviews(template) {
        const previews = await generatePreview(template.canvas, template.layers, {
            generateThumbnail: true,
            generatePreview: true,
            generateMockups: false
        });

        template.previews = previews;
        await template.save();
        return previews;
    }

    // Validate and update template metadata
    static async updateTemplateMetadata(templateId, metadata) {
        const template = await Template.findOne({ templateId });
        if (!template) {
            throw new AppError('Template not found', 404);
        }

        if (metadata.industry && !['technology', 'finance', 'healthcare', 'education', 'retail', 'real-estate', 'consulting', 'marketing', 'non-profit', 'government', 'entertainment', 'food-beverage'].includes(metadata.industry)) {
            throw new AppError('Invalid industry', 400);
        }

        if (metadata.targetAudience && !['business-professionals', 'entrepreneurs', 'creatives', 'students', 'marketers', 'developers', 'designers', 'small-business', 'enterprise', 'personal'].includes(metadata.targetAudience)) {
            throw new AppError('Invalid target audience', 400);
        }

        template.metadata = { ...template.metadata, ...metadata };
        await template.save();
        return template;
    }

    // Check template compatibility
    static async checkCompatibility(templateId, platform, outputFormat) {
        const template = await Template.findOne({ templateId });
        if (!template) {
            throw new AppError('Template not found', 404);
        }

        const isCompatible = template.compatibility.platforms.includes(platform) &&
            template.compatibility.outputFormats.some(f => f.format === outputFormat && f.supported);

        return {
            compatible: isCompatible,
            platform,
            outputFormat,
            recommendations: template.compatibility.socialPlatforms.find(p => p.platform === platform)?.recommendations || []
        };
    }
}