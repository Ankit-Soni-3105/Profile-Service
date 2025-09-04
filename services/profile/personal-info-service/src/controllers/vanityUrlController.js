import { getCache, setCache } from "../services/redis.service.js";

export const getVanityUrl = async (req, res) => {
    try {
        const userId = req.user.userId;
        const cacheKey = `vanityurl:${userId}`;

        const cachedData = await getCache(cacheKey);
        if (cachedData) {
            return res.status(200).json(cachedData);
        }

        const vanityUrl = { userId, vanity: 'user123' }; // Replace with DB model
        await setCache(cacheKey, vanityUrl, 3600);
        res.status(200).json({
            message: 'Vanity URL fetched successfully',
            data: vanityUrl
        });
    } catch (error) {
        console.error('Error fetching vanity URL:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
};
