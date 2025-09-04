import { uploadToCloudinary } from '../utils/cloudinary.js';
import Photo from '../models/photo.model.js';
import PhotoHistory from '../models/photo.history.model.js';
import { getCache, setCache } from '../services/redis.service.js';
import { promises as fs } from 'fs';

export const cropPhoto = async (req, res) => {
    try {
        const userId = req.user.userId;
        const { photoId, cropRatio } = req.body;
        if (!photoId || !cropRatio) {
            return res.status(400).json({ error: 'Photo ID and crop ratio are required' });
        }

        // Fetch photo from cache or DB
        const cacheKey = `photo:${userId}:${photoId}`;
        let photo = await getCache(cacheKey);
        if (!photo) {
            photo = await Photo.findOne({ userId, photoId });
            if (!photo) return res.status(404).json({ error: 'Photo not found' });
            await setCache(cacheKey, photo, 3600);
        }

        // Download original image (temporary for cropping)
        const tempFilePath = `/tmp/${photoId}-crop.jpg`;
        const response = await fetch(photo.url);
        const buffer = await response.arrayBuffer();
        await fs.writeFile(tempFilePath, Buffer.from(buffer));

        // Crop using Cloudinary
        const result = await uploadToCloudinary(tempFilePath, {
            transformation: [{ width: 300, height: 300, crop: 'fill', gravity: 'center' }],
        });
        await fs.unlink(tempFilePath); // Clean up

        // Update photo
        photo.url = result.secure_url;
        photo.status = 'processed';
        await photo.save();

        // Log history
        await PhotoHistory.create({
            userId,
            photoId,
            action: 'crop',
            details: { cropRatio },
        });

        // Update cache
        await setCache(cacheKey, photo, 3600);

        res.status(200).json({ 
            photoId, 
            url: result.secure_url, 
            message: 'Photo cropped successfully' 
        });
    } catch (error) {
        console.error('Error cropping photo:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
};
