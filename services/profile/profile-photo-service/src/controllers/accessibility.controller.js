import PhotoSettings from '../models/photo.settings.model.js';
import { getCache, setCache } from '../services/redis.service.js';

export const setAccessibility = async (req, res) => {
  try {
    const userId = req.user.userId;
    const { photoId, tags } = req.body;
    if (!photoId || !Array.isArray(tags)) {
      return res.status(400).json({ error: 'Photo ID and tags array are required' });
    }

    const cacheKey = `photosettings:${userId}:${photoId}`;
    let settings = await getCache(cacheKey);
    if (!settings) {
      settings = await PhotoSettings.findOne({ userId });
      if (!settings) {
        settings = new PhotoSettings({ userId });
      }
      await setCache(cacheKey, settings, 3600);
    }

    settings.accessibilityTags = tags;
    await settings.save();

    await setCache(cacheKey, settings, 3600);

    res.status(200).json({ 
        photoId, 
        tags, 
        message: 'Accessibility tags updated' 
    });
  } catch (error) {
    console.error('Error setting accessibility:', error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
};