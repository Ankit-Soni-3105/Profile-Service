import { getCache, setCache } from "../services/redis.service.js";


export const getTimezone = async (req, res) => {
    try {
        const userId = req.user.userId;
        const cacheKey = `timezone:${userId}`;

        const cachedData = await getCache(cacheKey);
        if (cachedData) {
            return res.status(200).json(cachedData);
        }

        const timezone = { userId, timezone: 'UTC+5:30' }; // Replace with DB model
        await setCache(cacheKey, timezone, 3600);
        res.status(200).json({
            message: 'Timezone fetched successfully',
            data: timezone
        });
    } catch (error) {
        console.error('Error fetching timezone:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
};
