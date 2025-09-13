import Proficiency from '../models/Proficiency.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { cacheService } from '../services/cache.service.js';
import { metricsCollector } from '../utils/metrics.js';
import mongoose from 'mongoose';
import { eventEmitter } from '../events/events.js';
import { searchClient } from '../config/elasticsearch.config.js';
import { backupService } from './backup.service.js';
import { verificationService } from './verification.service.js';

class ProficiencyService {
    /**
     * Create a new proficiency record
     * @param {Object} data - Proficiency data
     * @param {Object} options - Additional options (e.g., session)
     * @returns {Promise<Object>} - Created proficiency document
     */
    async createProficiency(data, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;

        try {
            const proficiency = new Proficiency({
                ...data,
                status: {
                    isActive: true,
                    isDeleted: false,
                    createdAt: new Date(),
                    updatedAt: new Date(),
                },
                metadata: {
                    ...data.metadata,
                    qualityScore: 0,
                    lastModifiedBy: data.metadata?.createdBy || null,
                },
            });

            const savedProficiency = await proficiency.save({ session });

            // Index for search
            await this.indexForSearch(savedProficiency);

            metricsCollector.increment('proficiency.created', {
                userId: data.userId,
                category: data.category,
            });

            eventEmitter.emit('proficiency.created', {
                proficiencyId: savedProficiency._id,
                userId: data.userId,
                category: data.category,
            });

            logger.info(`Proficiency created: ${savedProficiency._id} in ${Date.now() - startTime}ms`);
            return savedProficiency;
        } catch (error) {
            logger.error(`Failed to create proficiency for user ${data.userId}:`, error);
            metricsCollector.increment('proficiency.create_failed', { userId: data.userId });
            throw new AppError('Failed to create proficiency', 500);
        }
    }

    /**
     * Get proficiency by ID
     * @param {string} id - Proficiency ID
     * @param {string} userId - User ID
     * @param {Object} options - Additional options
     * @returns {Promise<Object>} - Proficiency document
     */
    async getProficiencyById(id, userId, options = {}) {
        const startTime = Date.now();
        const cacheKey = `proficiency:${id}:${userId}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('proficiency.cache_hit', { userId });
                return cached;
            }

            const proficiency = await Proficiency.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .cache({ ttl: 600, key: cacheKey });

            if (!proficiency) {
                throw new AppError('Proficiency not found', 404);
            }

            metricsCollector.increment('proficiency.fetched', { userId });
            logger.info(`Fetched proficiency ${id} in ${Date.now() - startTime}ms`);
            return proficiency;
        } catch (error) {
            logger.error(`Failed to fetch proficiency ${id}:`, error);
            metricsCollector.increment('proficiency.fetch_failed', { userId });
            throw error.name === 'CastError' ? new AppError('Invalid proficiency ID', 400) : error;
        }
    }

    /**
     * Update proficiency
     * @param {string} id - Proficiency ID
     * @param {string} userId - User ID
     * @param {Object} updates - Fields to update
     * @param {Object} options - Additional options
     * @returns {Promise<Object>} - Updated proficiency document
     */
    async updateProficiency(id, userId, updates, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;

        try {
            const proficiency = await Proficiency.findOne({ _id: id, userId }).session(session);
            if (!proficiency) {
                throw new AppError('Proficiency not found', 404);
            }

            Object.assign(proficiency, updates);
            proficiency.updatedAt = new Date();

            if (updates.level || updates.skillId) {
                proficiency.verification.status = 'pending';
            }

            await proficiency.save({ session });

            // Update search index
            await this.indexForSearch(proficiency);

            // Clear cache
            await cacheService.deletePattern(`proficiency:${id}:*`);
            await cacheService.deletePattern(`proficiencies:${userId}:*`);

            metricsCollector.increment('proficiency.updated', {
                userId,
                fieldsUpdated: Object.keys(updates).length,
            });

            eventEmitter.emit('proficiency.updated', {
                proficiencyId: id,
                userId,
                changes: Object.keys(updates),
            });

            logger.info(`Proficiency updated: ${id} in ${Date.now() - startTime}ms`);
            return proficiency;
        } catch (error) {
            logger.error(`Failed to update proficiency ${id}:`, error);
            metricsCollector.increment('proficiency.update_failed', { userId });
            throw error.name === 'ValidationError' ? new AppError('Validation failed: ' + error.message, 400) : error;
        }
    }

    /**
     * Delete proficiency (soft or permanent)
     * @param {string} id - Proficiency ID
     * @param {string} userId - User ID
     * @param {boolean} permanent - Permanent deletion flag
     * @param {Object} options - Additional options
     * @returns {Promise<void>}
     */
    async deleteProficiency(id, userId, permanent = false, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;

        try {
            if (permanent) {
                await Proficiency.findOneAndDelete({ _id: id, userId }, { session });
                await this.deleteAllBackups(id);
                await searchClient.delete({ index: 'proficiencies', id });
                metricsCollector.increment('proficiency.permanently_deleted', { userId });
            } else {
                const proficiency = await Proficiency.findOne({ _id: id, userId }).session(session);
                if (!proficiency) {
                    throw new AppError('Proficiency not found', 404);
                }
                proficiency.status.isDeleted = true;
                proficiency.status.deletedAt = new Date();
                await proficiency.save({ session });
                metricsCollector.increment('proficiency.soft_deleted', { userId });
            }

            await cacheService.deletePattern(`proficiency:${id}:*`);
            await cacheService.deletePattern(`proficiencies:${userId}:*`);

            eventEmitter.emit('proficiency.deleted', { proficiencyId: id, userId, permanent });

            logger.info(`Proficiency ${id} deleted (permanent: ${permanent}) in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to delete proficiency ${id}:`, error);
            metricsCollector.increment('proficiency.delete_failed', { userId });
            throw error;
        }
    }

    /**
     * Get proficiencies with filtering and pagination
     * @param {Object} query - Query parameters
     * @param {Object} options - Additional options
     * @returns {Promise<Object>} - Proficiencies and pagination info
     */
    async getProficiencies(query, options = {}) {
        const startTime = Date.now();
        const { userId, page = 1, limit = 20, status, category, search, tags, sortBy = 'recent' } = query;
        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
        const skip = (pageNum - 1) * limitNum;

        const cacheKey = `proficiencies:${userId}:${JSON.stringify({ pageNum, limitNum, status, category, search, tags, sortBy })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('proficiencies.cache_hit', { userId });
                return cached;
            }

            const mongoQuery = this.buildMongoQuery({ userId, status, category, search, tags });
            const sortOption = this.buildSortOption(sortBy);

            const [proficiencies, totalCount] = await Promise.all([
                Proficiency.find(mongoQuery)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select('userId skillId level category tags status createdAt updatedAt')
                    .lean(),
                Proficiency.countDocuments(mongoQuery).cache({ ttl: 300, key: `proficiency_count_${userId}` }),
            ]);

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                proficiencies,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages,
                    hasNext: pageNum < totalPages,
                    hasPrev: pageNum > 1,
                },
            };

            await cacheService.set(cacheKey, result, 300);
            metricsCollector.increment('proficiencies.fetched', { userId, count: proficiencies.length });
            logger.info(`Fetched ${proficiencies.length} proficiencies for user ${userId} in ${Date.now() - startTime}ms`);
            return result;
        } catch (error) {
            logger.error(`Failed to fetch proficiencies for user ${userId}:`, error);
            metricsCollector.increment('proficiencies.fetch_failed', { userId });
            throw new AppError('Failed to fetch proficiencies', 500);
        }
    }

    /**
     * Search proficiencies using Elasticsearch
     * @param {string} query - Search query
     * @param {Object} filters - Additional filters
     * @param {Object} options - Pagination options
     * @returns {Promise<Object>} - Search results
     */
    async searchProficiencies(query, filters = {}, options = {}) {
        const startTime = Date.now();
        const { page = 1, limit = 20 } = options;
        const from = (page - 1) * limit;

        try {
            const esQuery = {
                index: 'proficiencies',
                body: {
                    query: {
                        bool: {
                            must: query ? { multi_match: { query, fields: ['skillId', 'category', 'tags'] } } : { match_all: {} },
                            filter: this.buildEsFilters(filters),
                        },
                    },
                    from,
                    size: limit,
                    sort: [{ updatedAt: 'desc' }],
                },
            };

            const result = await searchClient.search(esQuery);
            const hits = result.hits.hits.map((hit) => hit._source);
            const total = result.hits.total.value;

            metricsCollector.increment('proficiency.searched', { query, count: hits.length });
            logger.info(`Search returned ${hits.length} proficiencies in ${Date.now() - startTime}ms`);
            return { hits, total };
        } catch (error) {
            logger.error(`Search failed for query ${query}:`, error);
            metricsCollector.increment('proficiency.search_failed');
            throw new AppError('Failed to search proficiencies', 500);
        }
    }

    /**
     * Get trending proficiencies
     * @param {string} timeframe - Timeframe (e.g., '7d', '30d')
     * @param {string} category - Optional category filter
     * @param {number} limit - Number of results
     * @returns {Promise<Array>} - Trending proficiencies
     */
    async getTrendingProficiencies(timeframe, category, limit) {
        const startTime = Date.now();
        const timeframeDate = new Date();

        switch (timeframe) {
            case '7d':
                timeframeDate.setDate(timeframeDate.getDate() - 7);
                break;
            case '30d':
                timeframeDate.setDate(timeframeDate.getDate() - 30);
                break;
            case '90d':
                timeframeDate.setDate(timeframeDate.getDate() - 90);
                break;
            default:
                timeframeDate.setDate(timeframeDate.getDate() - 30);
        }

        try {
            const query = {
                'status.isDeleted': false,
                createdAt: { $gte: timeframeDate },
            };
            if (category) {
                query.category = category;
            }

            const proficiencies = await Proficiency.find(query)
                .read('secondaryPreferred')
                .select('userId skillId level category analytics createdAt')
                .limit(limit)
                .lean();

            const trending = proficiencies
                .map((prof) => ({
                    ...prof,
                    trendingScore: this.calculateTrendingScore(prof),
                }))
                .sort((a, b) => b.trendingScore - a.trendingScore)
                .slice(0, limit);

            metricsCollector.increment('proficiency.trending_fetched', { count: trending.length });
            logger.info(`Fetched ${trending.length} trending proficiencies in ${Date.now() - startTime}ms`);
            return trending;
        } catch (error) {
            logger.error(`Failed to fetch trending proficiencies:`, error);
            metricsCollector.increment('proficiency.trending_fetch_failed');
            throw new AppError('Failed to fetch trending proficiencies', 500);
        }
    }

    /**
     * Create backup of proficiency
     * @param {string} proficiencyId - Proficiency ID
     * @param {string} action - Action type (create, update, duplicate)
     * @param {string} userId - User ID
     * @param {Object} options - Additional options
     * @returns {Promise<void>}
     */
    async createBackup(proficiencyId, action, userId, options = {}) {
        const startTime = Date.now();
        try {
            const proficiency = await Proficiency.findById(proficiencyId);
            if (!proficiency) {
                throw new AppError('Proficiency not found', 404);
            }

            await backupService.createBackup({
                entityType: 'proficiency',
                entityId: proficiencyId,
                data: proficiency.toObject(),
                action,
                userId,
            }, options);

            logger.info(`Backup created for proficiency ${proficiencyId} (${action}) in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to create backup for proficiency ${proficiencyId}:`, error);
            throw error;
        }
    }

    /**
     * Delete all backups for a proficiency
     * @param {string} proficiencyId - Proficiency ID
     * @returns {Promise<void>}
     */
    async deleteAllBackups(proficiencyId) {
        const startTime = Date.now();
        try {
            await backupService.deleteBackups('proficiency', proficiencyId);
            logger.info(`Deleted all backups for proficiency ${proficiencyId} in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to delete backups for proficiency ${proficiencyId}:`, error);
            throw error;
        }
    }

    /**
     * Index proficiency for Elasticsearch
     * @param {Object} proficiency - Proficiency document
     * @returns {Promise<void>}
     */
    async indexForSearch(proficiency) {
        const startTime = Date.now();
        try {
            await searchClient.index({
                index: 'proficiencies',
                id: proficiency._id.toString(),
                body: {
                    userId: proficiency.userId,
                    skillId: proficiency.skillId,
                    level: proficiency.level,
                    category: proficiency.category,
                    tags: proficiency.tags,
                    status: proficiency.status,
                    createdAt: proficiency.createdAt,
                    updatedAt: proficiency.updatedAt,
                },
            });
            logger.info(`Indexed proficiency ${proficiency._id} for search in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to index proficiency ${proficiency._id}:`, error);
            throw error;
        }
    }

    /**
     * Update user stats
     * @param {string} userId - User ID
     * @param {Object} options - Additional options
     * @returns {Promise<void>}
     */
    async updateUserStats(userId, options = {}) {
        const startTime = Date.now();
        try {
            const stats = await Proficiency.aggregate([
                { $match: { userId: new mongoose.Types.ObjectId(userId), 'status.isDeleted': false } },
                {
                    $group: {
                        _id: null,
                        totalProficiencies: { $sum: 1 },
                        averageLevel: { $avg: '$level' },
                        categories: { $addToSet: '$category' },
                    },
                },
            ]).cache({ ttl: 3600, key: `user_stats_${userId}` });

            eventEmitter.emit('user.stats_updated', { userId, stats: stats[0] || {} });
            logger.info(`Updated stats for user ${userId} in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to update stats for user ${userId}:`, error);
            throw error;
        }
    }

    /**
     * Verify proficiency with external service
     * @param {Object} data - Verification data
     * @returns {Promise<Object>} - Verification result
     */
    async verifyProficiency(data) {
        const startTime = Date.now();
        try {
            const result = await verificationService.verify({
                entityType: 'proficiency',
                entityId: data.proficiencyId,
                data: {
                    skillId: data.skillId,
                    level: data.level,
                    category: data.category,
                },
                userId: data.userId,
            });

            metricsCollector.increment('proficiency.verified', { userId: data.userId, status: result.status });
            logger.info(`Verified proficiency ${data.proficiencyId} in ${Date.now() - startTime}ms`);
            return result;
        } catch (error) {
            logger.error(`Verification failed for proficiency ${data.proficiencyId}:`, error);
            metricsCollector.increment('proficiency.verify_failed', { userId: data.userId });
            throw new AppError('Verification failed', 424);
        }
    }

    /**
     * Check connection level between users
     * @param {string} userId - Target user ID
     * @param {string} requestingUserId - Requesting user ID
     * @returns {Promise<boolean>} - Connection status
     */
    async checkConnectionLevel(userId, requestingUserId) {
        const startTime = Date.now();
        try {
            // Placeholder: Assume a UserService or connection model exists
            const isConnected = true; // Replace with actual logic
            logger.info(`Checked connection for ${userId} and ${requestingUserId} in ${Date.now() - startTime}ms`);
            return isConnected;
        } catch (error) {
            logger.error(`Failed to check connection for ${userId}:`, error);
            throw new AppError('Failed to check connection', 500);
        }
    }

    /**
     * Extract skills from description (for compatibility with DemandService)
     * @param {string} description - Description text
     * @returns {Promise<Array>} - Extracted skills
     */
    async extractSkills(description) {
        const startTime = Date.now();
        try {
            // Placeholder: Assume NLP or external API for skill extraction
            const skills = description
                .toLowerCase()
                .match(/\b(python|javascript|java|sql|leadership|communication|teamwork)\b/gi) || [];
            logger.info(`Extracted ${skills.length} skills in ${Date.now() - startTime}ms`);
            return skills;
        } catch (error) {
            logger.error(`Failed to extract skills:`, error);
            return [];
        }
    }

    /**
     * Calculate trending score
     * @param {Object} proficiency - Proficiency document
     * @returns {number} - Trending score
     */
    calculateTrendingScore(proficiency) {
        const viewsWeight = 0.4;
        const endorsementsWeight = 0.3;
        const recencyWeight = 0.2;
        const levelWeight = 0.1;

        const daysSinceCreated = (Date.now() - new Date(proficiency.createdAt)) / (1000 * 60 * 60 * 24);
        const recencyScore = Math.max(0, 10 - daysSinceCreated);
        const levelScore = proficiency.level || 1;

        return (
            ((proficiency.analytics?.viewCount || 0) * viewsWeight) +
            ((proficiency.endorsements?.length || 0) * endorsementsWeight) +
            (recencyScore * recencyWeight) +
            (levelScore * levelWeight)
        );
    }

    /**
     * Build MongoDB query
     * @param {Object} params - Query parameters
     * @returns {Object} - MongoDB query
     */
    buildMongoQuery({ userId, status, category, search, tags }) {
        const query = { userId, 'status.isDeleted': false };

        if (status && status !== 'all') {
            query['status.isActive'] = status === 'active';
        }
        if (category && category !== 'all') {
            query.category = category;
        }
        if (tags) {
            query.tags = { $in: tags.split(',').map((tag) => tag.trim().toLowerCase()) };
        }
        if (search) {
            query.$text = { $search: search };
        }

        return query;
    }

    /**
     * Build Elasticsearch filters
     * @param {Object} filters - Filters object
     * @returns {Array} - Elasticsearch filters
     */
    buildEsFilters(filters) {
        const esFilters = [];
        if (filters.category) {
            esFilters.push({ term: { category: filters.category } });
        }
        if (filters.tags) {
            esFilters.push({ terms: { tags: filters.tags } });
        }
        if (filters.status) {
            esFilters.push({ term: { 'status.isActive': filters.status === 'active' } });
        }
        return esFilters;
    }

    /**
     * Build sort option
     * @param {string} sortBy - Sort criteria
     * @returns {Object} - Sort option
     */
    buildSortOption(sortBy) {
        const sortOptions = {
            recent: { updatedAt: -1 },
            oldest: { createdAt: 1 },
            level: { level: -1 },
            popular: { 'analytics.viewCount': -1 },
            quality: { 'metadata.qualityScore': -1 },
        };
        return sortOptions[sortBy] || sortOptions.recent;
    }
}

export default new ProficiencyService();