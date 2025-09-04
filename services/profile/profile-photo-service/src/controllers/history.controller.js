import PhotoHistory from '../models/photo.history.model.js';
import { getCache, setCache } from '../services/redis.service.js';

export const getHistory = async (req, res) => {
  try {
    const userId = req.user.userId;
    const { photoId } = req.params;

    const cacheKey = `history:${userId}:${photoId}`;
    const cachedData = await getCache(cacheKey);
    if (cachedData) {
      return res.status(200).json(cachedData);
    }

    const history = await PhotoHistory.find({ userId, photoId }).sort({ timestamp: -1 });
    if (!history.length) {
      return res.status(404).json({ error: 'No history found' });
    }

    await setCache(cacheKey, history, 3600);
    res.status(200).json(history);
  } catch (error) {
    console.error('Error fetching history:', error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
};
