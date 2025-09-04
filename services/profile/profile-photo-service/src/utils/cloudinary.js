import cloudinary from 'cloudinary';
import dotenv from 'dotenv';
import { promises as fs } from 'fs';

dotenv.config();

cloudinary.v2.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
});

export const uploadToCloudinary = async (filePath) => {
    try {
        const result = await cloudinary.v2.uploader.upload(filePath, {
            folder: 'profile-photos',
            resource_type: 'image',
        });
        await fs.unlink(filePath); // Clean up temporary file
        return result;
    } catch (error) {
        console.error('Cloudinary upload error:', error.message);
        throw error;
    }
};

export default cloudinary.v2;