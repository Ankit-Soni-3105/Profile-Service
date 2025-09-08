import cloudinary from 'cloudinary';
import sharp from 'sharp';
import axios from 'axios';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';



// Process image with Sharp
export const processImage = async (url, options) => {
    try {
        const { generateThumbnails, generateVariants, optimize } = options;

        // Fetch image
        const response = await axios.get(url, { responseType: 'arraybuffer' });
        const buffer = Buffer.from(response.data);

        // Get metadata
        const metadata = await sharp(buffer).metadata();

        const result = {
            width: metadata.width,
            height: metadata.height,
            orientation: metadata.width > metadata.height ? 'landscape' : 'portrait',
            optimized: null,
            thumbnails: [],
            variants: []
        };

        // Optimize image
        if (optimize) {
            const optimizedBuffer = await sharp(buffer)
                .resize({ width: Math.min(metadata.width, 1920), withoutEnlargement: true })
                .webp({ quality: 80 })
                .toBuffer();

            const optimizedUpload = await uploadToCloudinary(optimizedBuffer, {
                folder: options.folder,
                public_id: `${options.public_id}_optimized`,
                resource_type: 'image'
            });

            result.optimized = {
                url: optimizedUpload.secure_url,
                size: optimizedUpload.bytes,
                format: optimizedUpload.format
            };
        }

        // Generate thumbnails
        if (generateThumbnails) {
            const thumbnailSizes = [100, 300, 500];
            for (const size of thumbnailSizes) {
                const thumbnailBuffer = await sharp(buffer)
                    .resize({ width: size, height: size, fit: 'cover' })
                    .webp({ quality: 60 })
                    .toBuffer();

                const thumbnailUpload = await uploadToCloudinary(thumbnailBuffer, {
                    folder: options.folder,
                    public_id: `${options.public_id}_thumb_${size}`,
                    resource_type: 'image'
                });

                result.thumbnails.push({
                    size,
                    url: thumbnailUpload.secure_url,
                    format: thumbnailUpload.format,
                    bytes: thumbnailUpload.bytes
                });
            }
        }

        // Generate variants
        if (generateVariants) {
            const variantStyles = ['grayscale', 'sepia', 'brighten'];
            for (const style of variantStyles) {
                let variantBuffer;
                if (style === 'grayscale') {
                    variantBuffer = await sharp(buffer).grayscale().toBuffer();
                } else if (style === 'sepia') {
                    variantBuffer = await sharp(buffer).tint({ r: 112, g: 66, b: 20 }).toBuffer();
                } else {
                    variantBuffer = await sharp(buffer).modulate({ brightness: 1.2 }).toBuffer();
                }

                const variantUpload = await uploadToCloudinary(variantBuffer, {
                    folder: options.folder,
                    public_id: `${options.public_id}_variant_${style}`,
                    resource_type: 'image'
                });

                result.variants.push({
                    style,
                    url: variantUpload.secure_url,
                    format: variantUpload.format,
                    bytes: variantUpload.bytes
                });
            }
        }

        return result;
    } catch (error) {
        logger.error(`Image processing error: ${error.message}`);
        throw new AppError(`Image processing failed: ${error.message}`, 500);
    }
};

// AI analysis (mock implementation)
export const analyzeWithAI = async (url, options) => {
    try {
        const { analyzeColors, detectObjects, assessQuality, generateTags } = options;

        const result = {
            colors: [],
            objects: [],
            qualityScore: { design: 0, branding: 0, accessibility: 0, overall: 0 },
            tags: [],
            suggestions: []
        };

        if (analyzeColors) {
            result.colors = ['#FF0000', '#00FF00', '#0000FF']; // Mock colors
        }

        if (detectObjects) {
            result.objects = ['background', 'text', 'logo']; // Mock objects
        }

        if (assessQuality) {
            result.qualityScore = {
                design: 7.5,
                branding: 6.0,
                accessibility: 8.0,
                overall: 7.0
            };
        }

        if (generateTags) {
            result.tags = ['cover', 'profile', 'design'];
        }

        result.suggestions = [
            {
                suggestionId: `sug_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`,
                type: 'color-palette',
                title: 'Adjust Color Contrast',
                description: 'Increase contrast for better accessibility',
                confidence: 0.9,
                category: 'accessibility',
                status: 'pending'
            }
        ];

        return result;
    } catch (error) {
        logger.error(`AI analysis error: ${error.message}`);
        throw new AppError(`AI analysis failed: ${error.message}`, 500);
    }
};