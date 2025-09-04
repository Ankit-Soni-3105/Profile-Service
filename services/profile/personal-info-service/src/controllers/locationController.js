import { getCache, setCache } from "../services/redis.service.js";

export const getLocation = async (req, res) => {
    try {
        const userId = req.user.userId;
        const cacheKey = `location:${userId}`;

        const cachedData = await getCache(cacheKey);
        if (cachedData) {
            return res.status(200).json(cachedData);
        }

        const location = { userId, city: 'New York', country: 'USA' }; // Replace with DB model
        await setCache(cacheKey, location, 3600);
        res.status(200).json({
            message: 'Location fetched successfully',
            data: location
        });
    } catch (error) {
        console.error('Error fetching location:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
};

export default { getLocation };