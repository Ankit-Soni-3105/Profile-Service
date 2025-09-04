import { getCache, setCache } from "../services/redis.service.js";


export const getUpdateHistory = async (req, res) => {
    try {
        const userId = req.user.userId;
        const cacheKey = `updatehistory:${userId}`;

        const cachedData = await getCache(cacheKey);
        if (cachedData) {
            return res.status(200).json(cachedData);
        }

        const updateHistory = { userId, updates: [{ field: 'email', date: new Date() }] }; // Replace with DB model
        await setCache(cacheKey, updateHistory, 3600);
        res.status(200).json({
            message: 'Update history fetched successfully',
            data: updateHistory
        });
    } catch (error) {
        console.error('Error fetching update history:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
};
