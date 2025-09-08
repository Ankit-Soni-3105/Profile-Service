import cloudinary from 'cloudinary';
import sharp from 'sharp';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';

// Configure Cloudinary
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

export class DesignService {
    static async exportDesign(design, options) {
        const { format, quality, dimensions, includeBleed } = options;

        try {
            let imageUrl = design.processing?.original?.url;
            if (!imageUrl) {
                throw new AppError('No source image available for export', 400);
            }

            // Fetch image
            const response = await fetch(imageUrl);
            const buffer = Buffer.from(await response.arrayBuffer());

            // Process image with Sharp
            let sharpImage = sharp(buffer);
            if (dimensions && (dimensions.width !== design.dimensions.width || dimensions.height !== design.dimensions.height)) {
                sharpImage = sharpImage.resize({
                    width: dimensions.width,
                    height: dimensions.height,
                    fit: 'contain',
                    withoutEnlargement: true
                });
            }

            if (includeBleed) {
                sharpImage = sharpImage.extend({
                    top: 20,
                    bottom: 20,
                    left: 20,
                    right: 20,
                    background: { r: 255, g: 255, b: 255 }
                });
            }

            let outputBuffer;
            switch (format) {
                case 'jpeg':
                    outputBuffer = await sharpImage.jpeg({ quality: quality === 'print' ? 90 : 80 }).toBuffer();
                    break;
                case 'png':
                    outputBuffer = await sharpImage.png({ compressionLevel: quality === 'print' ? 8 : 6 }).toBuffer();
                    break;
                case 'webp':
                    outputBuffer = await sharpImage.webp({ quality: quality === 'print' ? 90 : 80 }).toBuffer();
                    break;
                case 'pdf':
                    outputBuffer = await sharpImage.png({ compressionLevel: 8 }).toBuffer(); // Mock PDF
                    break;
                case 'svg':
                    outputBuffer = buffer; // Mock SVG
                    break;
                default:
                    throw new AppError('Unsupported format', 400);
            }

            // Upload to Cloudinary
            const uploadResult = await cloudinary.v2.uploader.upload_stream({
                folder: `exports/${design.userId}`,
                public_id: `export_${design.designId}_${Date.now()}`,
                resource_type: 'image',
                format,
                timeout: 60000
            }, (error, result) => {
                if (error) throw new AppError('Cloudinary upload failed', 500);
                return result;
            }).end(outputBuffer);

            return {
                downloadUrl: uploadResult.secure_url,
                fileSize: uploadResult.bytes,
                dimensions: {
                    width: dimensions?.width || design.dimensions.width,
                    height: dimensions?.height || design.dimensions.height
                }
            };
        } catch (error) {
            logger.error(`Export failed for designId ${design.designId}:`, error);
            throw new AppError(`Export failed: ${error.message}`, 500);
        }
    }

    static async deleteAssets(cloudinaryId) {
        try {
            if (cloudinaryId) {
                await cloudinary.v2.uploader.destroy(cloudinaryId, { resource_type: 'image' });
            }
        } catch (error) {
            logger.error(`Asset deletion failed for cloudinaryId ${cloudinaryId}:`, error);
            throw new AppError('Asset deletion failed', 500);
        }
    }
}