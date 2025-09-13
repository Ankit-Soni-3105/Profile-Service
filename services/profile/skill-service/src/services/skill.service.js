import Skill from '../models/Skill.js';
import SkillCategory from '../models/SkillCategory.js';
import SkillTrend from '../models/SkillTrend.js';
import SkillDemand from '../models/SkillDemand.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { cacheService } from './cache.service.js';
import { metricsCollector } from '../utils/metrics.js';
import mongoose from 'mongoose';
import algoliasearch from 'algoliasearch';
import { v4 as uuidv4 } from 'uuid';

// Initialize Algolia client
const algoliaClient = process.env.ALGOLIA_APP_ID && process.env.ALGOLIA_ADMIN_KEY
    ? algoliasearch(process.env.ALGOLIA_APP_ID, process.env.ALGOLIA_ADMIN_KEY)
    : null;
const algoliaIndex = algoliaClient ? algoliaClient.initIndex('skills') : null;

class SkillService {
    async createSkill(skillData, options = {}) {
        try {
            const skill = new Skill(skillData);
            await skill.save(options);
            await this.indexForSearch(skill);
            return skill;
        } catch (error) {
            logger.error('Skill creation failed:', error);
            throw new AppError('Failed to create skill', 500);
        }
    }

    async createBackup(skillId, reason, userId, options = {}) {
        try {
            const skill = await Skill.findById(skillId);
            if (!skill) throw new AppError('Skill not found', 404);

            const ArchiveSkill = mongoose.model('ArchiveSkill', Skill.schema, 'archive_skills');
            const backup = new ArchiveSkill({
                ...skill.toObject(),
                originalId: skill._id,
                backupReason: reason,
                backedUpBy: userId,
                backedUpAt: new Date(),
            });
            await backup.save(options);
            logger.info(`Backup created for skill ${skillId} with reason: ${reason}`);
            return backup;
        } catch (error) {
            logger.error(`Backup creation failed for skill ${skillId}:`, error);
            throw new AppError('Failed to create backup', 500);
        }
    }

    async deleteAllBackups(skillId) {
        try {
            const ArchiveSkill = mongoose.model('ArchiveSkill', Skill.schema, 'archive_skills');
            const result = await ArchiveSkill.deleteMany({ originalId: skillId });
            logger.info(`Deleted ${result.deletedCount} backups for skill ${skillId}`);
            return result;
        } catch (error) {
            logger.error(`Backup deletion failed for skill ${skillId}:`, error);
            throw new AppError('Failed to delete backups', 500);
        }
    }

    async extractSkills(description) {
        try {
            // Placeholder for NLP-based skill extraction (e.g., using external NLP service)
            const skills = ['JavaScript', 'Python', 'React']; // Mock implementation
            return skills.map(skill => ({ name: skill, confidence: 0.9 }));
        } catch (error) {
            logger.error('Skill extraction failed:', error);
            return [];
        }
    }

    async indexForSearch(skill) {
        if (!algoliaIndex) {
            logger.warn('Algolia not configured, skipping search indexing');
            return;
        }
        try {
            await algoliaIndex.saveObject({
                objectID: skill._id.toString(),
                name: skill.name,
                description: skill.description,
                categoryId: skill.categoryId,
                proficiencyLevel: skill.proficiency?.level,
                tags: skill.tags,
                userId: skill.userId,
                visibility: skill.visibility,
                createdAt: skill.createdAt,
            });
            logger.info(`Skill ${skill._id} indexed for search`);
        } catch (error) {
            logger.error(`Search indexing failed for skill ${skill._id}:`, error);
        }
    }

    async updateUserStats(userId, options = {}) {
        try {
            const skillCount = await Skill.countDocuments({ userId, 'status.isDeleted': false });
            // Update user profile with skill stats (mock implementation)
            logger.info(`Updated stats for user ${userId}: ${skillCount} skills`);
            // Example: await User.updateOne({ _id: userId }, { 'stats.skillCount': skillCount }, options);
        } catch (error) {
            logger.error(`User stats update failed for user ${userId}:`, error);
        }
    }

    async checkConnectionLevel(userId, requestingUserId) {
        // Mock implementation for checking connection level
        return userId !== requestingUserId; // Assume connected if different users
    }

    async searchSkills(query, filters = {}, options = {}) {
        if (!algoliaIndex) {
            throw new AppError('Search service not configured', 503);
        }
        try {
            const { page = 1, limit = 20 } = options;
            const searchParams = {
                query,
                filters: this.buildSearchFilters(filters),
                page: page - 1,
                hitsPerPage: limit,
                attributesToRetrieve: ['objectID', 'name', 'description', 'categoryId', 'proficiencyLevel', 'tags'],
            };
            const { hits, nbHits } = await algoliaIndex.search(query, searchParams);
            return {
                hits: hits.map(hit => ({
                    id: hit.objectID,
                    name: hit.name,
                    description: hit.description,
                    categoryId: hit.categoryId,
                    proficiencyLevel: hit.proficiencyLevel,
                    tags: hit.tags,
                })),
                total: nbHits,
            };
        } catch (error) {
            logger.error(`Search failed for query ${query}:`, error);
            throw new AppError('Search failed', 500);
        }
    }

    async getTrendingSkills(timeframe, categoryId, limit) {
        try {
            const startDate = new Date();
            switch (timeframe) {
                case '7d':
                    startDate.setDate(startDate.getDate() - 7);
                    break;
                case '30d':
                    startDate.setDate(startDate.getDate() - 30);
                    break;
                case '90d':
                    startDate.setDate(startDate.getDate() - 90);
                    break;
                default:
                    startDate.setDate(startDate.getDate() - 7);
            }

            const query = {
                'status.isActive': true,
                'status.isDeleted': false,
                createdAt: { $gte: startDate },
                ...(categoryId && { categoryId }),
            };

            const skills = await Skill.find(query)
                .sort({ 'analytics.viewCount': -1 })
                .limit(limit)
                .select('name description categoryId proficiency analytics endorsements createdAt')
                .lean();

            return skills.map(skill => ({
                ...skill,
                trendingScore: this.calculateTrendingScore(skill),
            })).sort((a, b) => b.trendingScore - a.trendingScore);
        } catch (error) {
            logger.error(`Failed to fetch trending skills:`, error);
            throw new AppError('Failed to fetch trending skills', 500);
        }
    }

    calculateTrendingScore(skill) {
        const viewsWeight = 0.4;
        const sharesWeight = 0.3;
        const endorsementsWeight = 0.2;
        const recencyWeight = 0.1;

        const daysSinceCreated = (Date.now() - new Date(skill.createdAt)) / (1000 * 60 * 60 * 24);
        const recencyScore = Math.max(0, 10 - daysSinceCreated);

        return (
            (skill.analytics.viewCount * viewsWeight) +
            ((skill.analytics.shares?.total || 0) * sharesWeight) +
            (skill.endorsements.length * endorsementsWeight) +
            (recencyScore * recencyWeight)
        );
    }

    buildSearchFilters(filters) {
        const filterArray = [];
        if (filters.categoryId) filterArray.push(`categoryId:${filters.categoryId}`);
        if (filters.proficiencyLevel) filterArray.push(`proficiencyLevel:${filters.proficiencyLevel}`);
        if (filters.tags) filterArray.push(`tags:${filters.tags.join(' OR tags:')}`);
        return filterArray.join(' AND ');
    }
}

export default SkillService;