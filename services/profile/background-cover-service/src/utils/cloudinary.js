import retry from 'async-retry';
import { v2 as cloudinary } from 'cloudinary';
import dotenv from 'dotenv';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';

dotenv.config();

// Configure Cloudinary
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
    secure: true
});

// Validate upload options
const validateOptions = (options) => {
    const allowedResourceTypes = ['image', 'video', 'raw', 'auto'];
    const allowedFormats = ['jpg', 'png', 'webp', 'svg', 'pdf', 'gif', 'mp4', 'mov'];

    if (options.resource_type && !allowedResourceTypes.includes(options.resource_type)) {
        throw new AppError(`Invalid resource_type: ${options.resource_type}`, 400);
    }
    if (options.format && !allowedFormats.includes(options.format)) {
        throw new AppError(`Invalid format: ${options.format}`, 400);
    }
    if (options.folder && !/^[a-zA-Z0-9-_/]{1,100}$/.test(options.folder)) {
        throw new AppError('Invalid folder name', 400);
    }
    return {
        ...options,
        resource_type: options.resource_type || 'image',
        timeout: options.timeout || 60000
    };
};

// Upload to Cloudinary with retry
export const uploadToCloudinary = async (buffer, options = {}) => {
    const validatedOptions = validateOptions(options);

    try {
        const result = await retry(
            async () => {
                return await new Promise((resolve, reject) => {
                    const stream = cloudinary.uploader.upload_stream(
                        validatedOptions,
                        (error, result) => {
                            if (error) reject(error);
                            else resolve(result);
                        }
                    );
                    stream.end(buffer);
                });
            },
            {
                retries: 3,
                factor: 2,
                minTimeout: 1000,
                maxTimeout: 5000,
                onRetry: (err) => {
                    logger.warn('Retrying Cloudinary upload', {
                        error: err.message,
                        attempt: err.attemptNumber
                    });
                }
            }
        );

        logger.info('File uploaded to Cloudinary', {
            public_id: result.public_id,
            url: result.secure_url,
            format: result.format,
            resource_type: result.resource_type
        });

        return {
            publicId: result.public_id,
            url: result.secure_url,
            format: result.format,
            width: result.width,
            height: result.height,
            bytes: result.bytes,
            createdAt: result.created_at
        };
    } catch (error) {
        logger.error('Cloudinary upload failed', {
            message: error.message,
            options: validatedOptions
        });
        throw new AppError(`Cloudinary upload failed: ${error.message}`, 500);
    }
};

// Delete from Cloudinary with retry
export const deleteFromCloudinary = async (publicId, options = {}) => {
    if (!publicId || typeof publicId !== 'string') {
        throw new AppError('Invalid publicId', 400);
    }

    const validatedOptions = {
        resource_type: options.resource_type || 'image',
        invalidate: options.invalidate || true
    };

    try {
        const result = await retry(
            async () => {
                return await cloudinary.uploader.destroy(publicId, validatedOptions);
            },
            {
                retries: 3,
                factor: 2,
                minTimeout: 1000,
                maxTimeout: 5000,
                onRetry: (err) => {
                    logger.warn('Retrying Cloudinary delete', {
                        publicId,
                        error: err.message,
                        attempt: err.attemptNumber
                    });
                }
            }
        );

        logger.info('File deleted from Cloudinary', {
            public_id: publicId,
            result: result.result
        });

        return result;
    } catch (error) {
        logger.error('Cloudinary delete failed', {
            public_id: publicId,
            message: error.message
        });
        throw new AppError(`Cloudinary delete failed: ${error.message}`, 500);
    }
};

// Generate preview URL
export const generatePreviewUrl = (publicId, options = {}) => {
    try {
        const transformations = {
            width: options.width || 300,
            height: options.height || 200,
            crop: 'fit',
            quality: options.quality || 'auto',
            fetch_format: options.format || 'auto'
        };

        const url = cloudinary.url(publicId, {
            resource_type: options.resource_type || 'image',
            transformation: [transformations],
            secure: true
        });

        logger.info('Generated Cloudinary preview URL', {
            public_id: publicId,
            url
        });

        return url;
    } catch (error) {
        logger.error('Cloudinary preview URL generation failed', {
            public_id: publicId,
            message: error.message
        });
        throw new AppError(`Preview URL generation failed: ${error.message}`, 500);
    }
};

export default cloudinary;