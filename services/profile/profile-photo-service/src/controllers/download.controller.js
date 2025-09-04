import Photo from '../models/photo.model.js';
import { getCache, setCache } from '../services/redis.service.js';

export const downloadPhoto = async (req, res) => {
    try {
        const userId = req.user.userId;
        const { photoId } = req.params;
        if (!photoId) {
            return res.status(400).json({ error: 'Photo ID is required' });
        }

        const cacheKey = `photo:${userId}:${photoId}`;
        let photo = await getCache(cacheKey);
        if (!photo) {
            photo = await Photo.findOne({ userId, photoId });
            if (!photo) return res.status(404).json({ error: 'Photo not found' });
            await setCache(cacheKey, photo, 3600);
        }

        res.redirect(photo.url); // Redirect to Cloudinary URL
    } catch (error) {
        console.error('Error downloading photo:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
};
