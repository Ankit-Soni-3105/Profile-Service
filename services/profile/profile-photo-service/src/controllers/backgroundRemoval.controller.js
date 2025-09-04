import { uploadToCloudinary } from '../utils/cloudinary.js';
import Photo from '../models/photo.model.js';
import PhotoHistory from '../models/photo.history.model.js';
import { getCache, setCache } from '../services/redis.service.js';
import { promises as fs } from 'fs';

export const removeBackground = async (req, res) => {
  try {
    const userId = req.user.userId;
    const { photoId } = req.body;
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

    const tempFilePath = `/tmp/${photoId}-bg.jpg`;
    const response = await fetch(photo.url);
    const buffer = await response.arrayBuffer();
    await fs.writeFile(tempFilePath, Buffer.from(buffer));

    const result = await uploadToCloudinary(tempFilePath, {
      transformation: [{ background_removal: 'cloudinary_ai' }],
    });
    await fs.unlink(tempFilePath);

    photo.url = result.secure_url;
    photo.status = 'processed';
    await photo.save();

    await PhotoHistory.create({
      userId,
      photoId,
      action: 'remove',
      details: { method: 'cloudinary_ai' },
    });

    await setCache(cacheKey, photo, 3600);

    res.status(200).json({ 
        photoId, 
        url: result.secure_url, 
        message: 'Background removed successfully' 
    });
  } catch (error) {
    console.error('Error removing background:', error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
};