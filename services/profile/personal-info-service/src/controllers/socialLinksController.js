import socialLinksModel from "../models/socialLinks.model.js";
import { getCache, setCache } from "../services/redis.service.js";


export const getSocialLinks = async (req, res) => {
    try {
        const userId = req.user.userId;
        const cacheKey = `social:${userId}`;

        const cachedData = await getCache(cacheKey);
        if (cachedData) {
            return res.status(200).json(cachedData);
        }

        const socialLinks = await socialLinksModel.findOne({ userId });
        if (!socialLinks) {
            return res.status(404).json({ error: 'Social links not found' });
        }

        await setCache(cacheKey, socialLinks, 3600);
        res.status(200).json({
            message: 'Social links fetched successfully',
            data: socialLinks
        });
    } catch (error) {
        console.error('Error fetching social links:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
};
