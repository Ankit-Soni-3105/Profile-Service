import { getCache, setCache } from "../services/redis.service.js";

export const getProfileUrl = async (req, res) => {
    try {
        const userId = req.user.userId;
        const cacheKey = `profileurl:${userId}`;

        const cachedData = await getCache(cacheKey);
        if (cachedData) {
            return res.status(200).json(cachedData);
        }

        const profileUrl = { userId, url: 'linkedin.com/in/user123' }; // Replace with DB model
        await setCache(cacheKey, profileUrl, 3600);
        res.status(200).json({
            message: 'Profile URL fetched successfully',
            data: profileUrl
        });
    } catch (error) {
        console.error('Error fetching profile URL:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
};
