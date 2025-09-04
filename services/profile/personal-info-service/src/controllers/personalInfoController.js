
import profileModel from '../models/profile.model.js';
import { getCache, setCache } from '../services/redis.service.js';

export const getPersonalInfo = async (req, res) => {
    try {
        const userId = req.user.userId;
        const cacheKey = `personal:${userId}`;

        const cachedData = await getCache(cacheKey);
        if (cachedData) {
            return res.status(200).json(cachedData);
        }

        const personalInfo = await profileModel.findOne({ userId });
        if (!personalInfo) {
            return res.status(404).json({ error: 'Personal info not found' });
        }

        await setCache(cacheKey, personalInfo, 3600);
        res.status(200).json({
            message: 'Personal info fetched successfully',
            data: personalInfo
        });
    } catch (error) {
        console.error('Error fetching personal info:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
};

export const updatePersonalInfo = async (req, res) => {
    try {
        const userId = req.user.userId;
        const { firstName, middleName, lastName, pronouns, tagline } = req.body;

        const updatedInfo = await profileModel.findOneAndUpdate(
            { userId },
            { firstName, middleName, lastName, pronouns, tagline },
            { new: true, runValidators: true }
        );
        if (!updatedInfo) {
            return res.status(404).json({ error: 'Personal info not found' });
        }

        const cacheKey = `personal:${userId}`;
        await setCache(cacheKey, updatedInfo, 3600);
        res.status(200).json({
            message: 'Personal info updated successfully',
            data: updatedInfo
        });
    } catch (error) {
        console.error('Error updating personal info:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
};
