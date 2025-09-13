import SkillCategory from '../models/SkillCategory.js';
import Skill from '../models/Skill.js';
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
const algoliaIndex = algoliaClient ? algoliaClient.initIndex('categories') : null;

class CategoryService {
    async createCategory(categoryData, options = {}) {
        try {
            const category = new SkillCategory(categoryData);
            await category.save(options);
            await this.indexForSearch(category);
            return category;
        } catch (error) {
            logger.error('Category creation failed:', error);
            throw new AppError('Failed to create category', 500);
        }
    }

    async createBackup(categoryId, reason, userId, options = {}) {
        try {
            const category = await SkillCategory.findById(categoryId);
            if (!category) throw new AppError('Category not found', 404);

            const ArchiveCategory = mongoose.model('ArchiveCategory', SkillCategory.schema, 'archive_categories');
            const backup = new ArchiveCategory({
                ...category.toObject(),
                originalId: category._id,
                backupReason: reason,
                backedUpBy: userId,
                backedUpAt: new Date(),
            });
            await backup.save(options);
            logger.info(`Backup created for category ${categoryId} with reason: ${reason}`);
            return backup;
        } catch (error) {
            logger.error(`Backup creation failed for category ${categoryId}:`, error);
            throw new AppError('Failed to create backup', 500);
        }
    }

    async deleteAllBackups(categoryId) {
        try {
            const ArchiveCategory = mongoose.model('ArchiveCategory', SkillCategory.schema, 'archive_categories');
            const result = await ArchiveCategory.deleteMany({ originalId: categoryId });
            logger.info(`Deleted ${result.deletedCount} backups for category ${categoryId}`);
            return result;
        } catch (error) {
            logger.error(`Backup deletion failed for category ${categoryId}:`, error);
            throw new AppError('Failed to delete backups', 500);
        }
    }

    async extractSkills(description) {
        try {
            const skills = ['Programming', 'Leadership', 'Communication']; // Mock implementation
            return skills.map(skill => ({ name: skill, confidence: 0.9 }));
        } catch (error) {
            logger.error('Skill extraction failed:', error);
            return [];
        }
    }

    async indexForSearch(category) {
        if (!algoliaIndex) {
            logger.warn('Algolia not configured, skipping search indexing');
            return;
        }
        try {
            await algoliaIndex.saveObject({
                objectID: category._id.toString(),
                name: category.name,
                description: category.description,
                type: category.type,
                tags: category.tags,
                userId: category.userId,
                visibility: category.visibility,
                createdAt: category.createdAt,
            });
            logger.info(`Category ${category._id} indexed for search`);
        } catch (error) {
            logger.error(`Search indexing failed for category ${category._id}:`, error);
        }
    }

    async updateUserStats(userId, options = {}) {
        try {
            const categoryCount = await SkillCategory.countDocuments({ userId, 'status.isDeleted': false });
            logger.info(`Updated stats for user ${userId}: ${categoryCount} categories`);
        } catch (error) {
            logger.error(`User stats update failed for user ${userId}:`, error);
        }
    }

    async checkConnectionLevel(userId, requestingUserId) {
        return userId !== requestingUserId; // Mock implementation
    }

    async searchCategories(query, filters = {}, options = {}) {
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
                attributesToRetrieve: ['objectID', 'name', 'description', 'type', 'tags'],
            };
            const { hits, nbHits } = await algoliaIndex.search(query, searchParams);
            return {
                hits: hits.map(hit => ({
                    id: hit.objectID,
                    name: hit.name,
                    description: hit.description,
                    type: hit.type,
                    tags: hit.tags,
                })),
                total: nbHits,
            };
        } catch (error) {
            logger.error(`Search failed for query ${query}:`, error);
            throw new AppError('Search failed', 500);
        }
    }

    async getTrendingCategories(timeframe, type, limit) {
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
                ...(type && { type }),
            };

            const categories = await SkillCategory.find(query)
                .sort({ 'analytics.viewCount': -1 })
                .limit(limit)
                .select('name description type analytics endorsements createdAt')
                .lean();

            return categories.map(category => ({
                ...category,
                trendingScore: this.calculateTrendingScore(category),
            })).sort((a, b) => b.trendingScore - a.trendingScore);
        } catch (error) {
            logger.error(`Failed to fetch trending categories:`, error);
            throw new AppError('Failed to fetch trending categories', 500);
        }
    }

    calculateTrendingScore(category) {
        const viewsWeight = 0.4;
        const sharesWeight = 0.3;
        const endorsementsWeight = 0.2;
        const recencyWeight = 0.1;

        const daysSinceCreated = (Date.now() - new Date(category.createdAt)) / (1000 * 60 * 60 * 24);
        const recencyScore = Math.max(0, 10 - daysSinceCreated);

        return (
            (category.analytics.viewCount * viewsWeight) +
            ((category.analytics.shares?.total || 0) * sharesWeight) +
            (category.endorsements.length * endorsementsWeight) +
            (recencyScore * recencyWeight)
        );
    }

    buildSearchFilters(filters) {
        const filterArray = [];
        if (filters.type) filterArray.push(`type:${filters.type}`);
        if (filters.tags) filterArray.push(`tags:${filters.tags.join(' OR tags:')}`);
        return filterArray.join(' AND ');
    }
}

export default CategoryService;