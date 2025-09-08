import cloudinary from 'cloudinary';
import { logger } from '../utils/logger.js';
import dotenv from 'dotenv';
import { promises as fs } from 'fs';

dotenv.config();

cloudinary.v2.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
});

export const uploadToCloudinary = async (buffer, options = {}) => {
    try {
        const result = await cloudinary.v2.uploader.upload_stream(options, (error, result) => {
            if (error) throw error;
            return result;
        }).end(buffer);

        logger.info('File uploaded to Cloudinary', { public_id: result.public_id, url: result.secure_url });
        return result;
    } catch (error) {
        logger.error('Cloudinary upload error', { message: error.message });
        throw error;
    }
};

export const deleteFromCloudinary = async (publicId) => {
    try {
        const result = await cloudinary.v2.uploader.destroy(publicId);
        logger.info('File deleted from Cloudinary', { public_id: publicId, result });
        return result;
    } catch (error) {
        logger.error('Cloudinary delete error', { message: error.message, public_id: publicId });
        throw error;
    }
};

export default cloudinary.v2;