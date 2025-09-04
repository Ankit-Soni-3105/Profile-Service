import { getCache, setCache } from "../services/redis.service.js";

export const getWebsite = async (req, res) => {
    try {
        const userId = req.user.userId;
        const cacheKey = `website:${userId}`;

        const cachedData = await getCache(cacheKey);
        if (cachedData) {
            return res.status(200).json(cachedData);
        }

        const website = { userId, website: 'https://example.com' }; // Replace with DB model
        await setCache(cacheKey, website, 3600);
        res.status(200).json({
            message: 'Website fetched successfully',
            data: website
        });
    } catch (error) {
        console.error('Error fetching website:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
};