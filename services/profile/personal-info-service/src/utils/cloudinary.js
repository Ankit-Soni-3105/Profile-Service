import { v2 as cloudinary } from 'cloudinary';
import { logger } from '../config/logger.js';
import ApiError from '../utils/apiError.js';

// Cloudinary configuration
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
    secure: true,
});

// Retry logic for uploads
const retryUpload = async (operation, retries = 3, delay = 1000) => {
    for (let attempt = 1; attempt <= retries; attempt++) {
        try {
            return await operation();
        } catch (error) {
            logger.error(`Cloudinary upload attempt ${attempt} failed`, {
                error: error.message,
                stack: error.stack,
            });
            if (attempt === retries) {
                throw new ApiError(500, 'Failed to upload to Cloudinary after retries');
            }
            await new Promise((resolve) => setTimeout(resolve, delay * attempt));
        }
    }
};

// Upload file to Cloudinary
export const uploadToCloudinary = async (file, options = {}) => {
    try {
        const result = await retryUpload(() =>
            cloudinary.uploader.upload(file.path, {
                folder: options.folder || 'profile_media',
                resource_type: options.resource_type || 'auto',
                public_id: options.public_id,
                transformation: options.transformation || [
                    { width: 1200, height: 1200, crop: 'limit' },
                    { quality: 'auto', fetch_format: 'auto' },
                ],
                ...options,
            })
        );
        logger.info('File uploaded to Cloudinary', {
            public_id: result.public_id,
            url: result.secure_url,
        });
        return result;
    } catch (error) {
        logger.error('Cloudinary upload failed', {
            error: error.message,
            stack: error.stack,
        });
        throw new ApiError(500, 'Failed to upload file to Cloudinary');
    }
};

// Delete file from Cloudinary
export const deleteFromCloudinary = async (publicId, resourceType = 'image') => {
    try {
        const result = await retryUpload(() =>
            cloudinary.uploader.destroy(publicId, { resource_type: resourceType })
        );
        logger.info('File deleted from Cloudinary', { public_id: publicId });
        return result;
    } catch (error) {
        logger.error('Cloudinary deletion failed', {
            error: error.message,
            stack: error.stack,
        });
        throw new ApiError(500, 'Failed to delete file from Cloudinary');
    }
};

export default cloudinary;