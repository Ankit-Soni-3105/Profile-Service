import PhotoSettings from '../models/photo.settings.model.js';
import { getCache, setCache } from '../services/redis.service.js';

export const setVisibility = async (req, res) => {
  try {
    const userId = req.user.userId;
    const { photoId, visibility } = req.body;
    if (!photoId || !['public', 'private', 'connections'].includes(visibility)) {
      return res.status(400).json({ error: 'Photo ID and valid visibility are required' });
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

    settings.visibility = visibility;
    await settings.save();

    await setCache(cacheKey, settings, 3600);

    res.status(200).json({ photoId, visibility, message: 'Visibility updated successfully' });
  } catch (error) {
    console.error('Error setting visibility:', error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
};
