import Demand from '../models/Demand.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { cacheService } from '../services/cache.service.js';
import { metricsCollector } from '../utils/metrics.js';
import mongoose from 'mongoose';
import { eventEmitter } from '../events/events.js';
import { searchClient } from '../config/elasticsearch.config.js';
import { backupService } from './backup.service.js';
import { verificationService } from './verification.service.js';

class DemandService {
    /**
     * Create a new demand record
     * @param {Object} data - Demand data
     * @param {Object} options - Additional options (e.g., session)
     * @returns {Promise<Object>} - Created demand document
     */
    async createDemand(data, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;

        try {
            const demand = new Demand({
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

            const savedDemand = await demand.save({ session });
            await this.indexForSearch(savedDemand);

            metricsCollector.increment('demand.created', {
                userId: data.userId,
                category: data.category,
            });

            eventEmitter.emit('demand.created', {
                demandId: savedDemand._id,
                userId: data.userId,
                category: data.category,
            });

            logger.info(`Demand created: ${savedDemand._id} in ${Date.now() - startTime}ms`);
            return savedDemand;
        } catch (error) {
            logger.error(`Failed to create demand for user ${data.userId}:`, error);
            metricsCollector.increment('demand.create_failed', { userId: data.userId });
            throw new AppError('Failed to create demand', 500);
        }
    }

    /**
     * Get demand by ID
     * @param {string} id - Demand ID
     * @param {string} userId - User ID
     * @param {Object} options - Additional options
     * @returns {Promise<Object>} - Demand document
     */
    async getDemandById(id, userId, options = {}) {
        const startTime = Date.now();
        const cacheKey = `demand:${id}:${userId}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('demand.cache_hit', { userId });
                return cached;
            }

            const demand = await Demand.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .cache({ ttl: 600, key: cacheKey });

            if (!demand) {
                throw new AppError('Demand not found', 404);
            }

            metricsCollector.increment('demand.fetched', { userId });
            logger.info(`Fetched demand ${id} in ${Date.now() - startTime}ms`);
            return demand;
        } catch (error) {
            logger.error(`Failed to fetch demand ${id}:`, error);
            metricsCollector.increment('demand.fetch_failed', { userId });
            throw error.name === 'CastError' ? new AppError('Invalid demand ID', 400) : error;
        }
    }

    /**
     * Update demand
     * @param {string} id - Demand ID
     * @param {string} userId - User ID
     * @param {Object} updates - Fields to update
     * @param {Object} options - Additional options
     * @returns {Promise<Object>} - Updated demand document
     */
    async updateDemand(id, userId, updates, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;

        try {
            const demand = await Demand.findOne({ _id: id, userId }).session(session);
            if (!demand) {
                throw new AppError('Demand not found', 404);
            }

            Object.assign(demand, updates);
            demand.updatedAt = new Date();

            if (updates.title || updates.metrics) {
                demand.verification.status = 'pending';
            }

            await demand.save({ session });
            await this.indexForSearch(demand);

            await cacheService.deletePattern(`demand:${id}:*`);
            await cacheService.deletePattern(`demands:${userId}:*`);

            metricsCollector.increment('demand.updated', {
                userId,
                fieldsUpdated: Object.keys(updates).length,
            });

            eventEmitter.emit('demand.updated', {
                demandId: id,
                userId,
                changes: Object.keys(updates),
            });

            logger.info(`Demand updated: ${id} in ${Date.now() - startTime}ms`);
            return demand;
        } catch (error) {
            logger.error(`Failed to update demand ${id}:`, error);
            metricsCollector.increment('demand.update_failed', { userId });
            throw error.name === 'ValidationError' ? new AppError('Validation failed: ' + error.message, 400) : error;
        }
    }

    /**
     * Delete demand (soft or permanent)
     * @param {string} id - Demand ID
     * @param {string} userId - User ID
     * @param {boolean} permanent - Permanent deletion flag
     * @param {Object} options - Additional options
     * @returns {Promise<void>}
     */
    async deleteDemand(id, userId, permanent = false, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;

        try {
            if (permanent) {
                await Demand.findOneAndDelete({ _id: id, userId }, { session });
                await this.deleteAllBackups(id);
                await searchClient.delete({ index: 'demands', id });
                metricsCollector.increment('demand.permanently_deleted', { userId });
            } else {
                const demand = await Demand.findOne({ _id: id, userId }).session(session);
                if (!demand) {
                    throw new AppError('Demand not found', 404);
                }
                demand.status.isDeleted = true;
                demand.status.deletedAt = new Date();
                await demand.save({ session });
                metricsCollector.increment('demand.soft_deleted', { userId });
            }

            await cacheService.deletePattern(`demand:${id}:*`);
            await cacheService.deletePattern(`demands:${userId}:*`);

            eventEmitter.emit('demand.deleted', { demandId: id, userId, permanent });

            logger.info(`Demand ${id} deleted (permanent: ${permanent}) in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to delete demand ${id}:`, error);
            metricsCollector.increment('demand.delete_failed', { userId });
            throw error;
        }
    }

    /**
     * Get demands with filtering and pagination
     * @param {Object} query - Query parameters
     * @param {Object} options - Additional options
     * @returns {Promise<Object>} - Demands and pagination info
     */
    async getDemands(query, options = {}) {
        const startTime = Date.now();
        const { userId, page = 1, limit = 20, status, category, search, tags, sortBy = 'recent' } = query;
        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
        const skip = (pageNum - 1) * limitNum;

        const cacheKey = `demands:${userId}:${JSON.stringify({ pageNum, limitNum, status, category, search, tags, sortBy })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('demands.cache_hit', { userId });
                return cached;
            }

            const mongoQuery = this.buildMongoQuery({ userId, status, category, search, tags });
            const sortOption = this.buildSortOption(sortBy);

            const [demands, totalCount] = await Promise.all([
                Demand.find(mongoQuery)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select('userId title description category metrics tags status createdAt updatedAt')
                    .lean(),
                Demand.countDocuments(mongoQuery).cache({ ttl: 300, key: `demand_count_${userId}` }),
            ]);

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                demands,
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
            metricsCollector.increment('demands.fetched', { userId, count: demands.length });
            logger.info(`Fetched ${demands.length} demands for user ${userId} in ${Date.now() - startTime}ms`);
            return result;
        } catch (error) {
            logger.error(`Failed to fetch demands for user ${userId}:`, error);
            metricsCollector.increment('demands.fetch_failed', { userId });
            throw new AppError('Failed to fetch demands', 500);
        }
    }

    /**
     * Search demands using Elasticsearch
     * @param {string} query - Search query
     * @param {Object} filters - Additional filters
     * @param {Object} options - Pagination options
     * @returns {Promise<Object>} - Search results
     */
    async searchDemands(query, filters = {}, options = {}) {
        const startTime = Date.now();
        const { page = 1, limit = 20 } = options;
        const from = (page - 1) * limit;

        try {
            const esQuery = {
                index: 'demands',
                body: {
                    query: {
                        bool: {
                            must: query ? { multi_match: { query, fields: ['title', 'description', 'category', 'tags'] } } : { match_all: {} },
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

            metricsCollector.increment('demand.searched', { query, count: hits.length });
            logger.info(`Search returned ${hits.length} demands in ${Date.now() - startTime}ms`);
            return { hits, total };
        } catch (error) {
            logger.error(`Search failed for query ${query}:`, error);
            metricsCollector.increment('demand.search_failed');
            throw new AppError('Failed to search demands', 500);
        }
    }

    /**
     * Get trending demands
     * @param {string} timeframe - Timeframe (e.g., '7d', '30d')
     * @param {string} category - Optional category filter
     * @param {number} limit - Number of results
     * @returns {Promise<Array>} - Trending demands
     */
    async getTrendingDemands(timeframe, category, limit) {
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

            const demands = await Demand.find(query)
                .read('secondaryPreferred')
                .select('userId title description category metrics analytics createdAt')
                .limit(limit)
                .lean();

            const trending = demands
                .map((dem) => ({
                    ...dem,
                    trendingScore: this.calculateTrendingScore(dem),
                }))
                .sort((a, b) => b.trendingScore - a.trendingScore)
                .slice(0, limit);

            metricsCollector.increment('demand.trending_fetched', { count: trending.length });
            logger.info(`Fetched ${trending.length} trending demands in ${Date.now() - startTime}ms`);
            return trending;
        } catch (error) {
            logger.error(`Failed to fetch trending demands:`, error);
            metricsCollector.increment('demand.trending_fetch_failed');
            throw new AppError('Failed to fetch trending demands', 500);
        }
    }

    /**
     * Create backup of demand
     * @param {string} demandId - Demand ID
     * @param {string} action - Action type (create, update, duplicate)
     * @param {string} userId - User ID
     * @param {Object} options - Additional options
     * @returns {Promise<void>}
     */
    async createBackup(demandId, action, userId, options = {}) {
        const startTime = Date.now();
        try {
            const demand = await Demand.findById(demandId);
            if (!demand) {
                throw new AppError('Demand not found', 404);
            }

            await backupService.createBackup({
                entityType: 'demand',
                entityId: demandId,
                data: demand.toObject(),
                action,
                userId,
            }, options);

            logger.info(`Backup created for demand ${demandId} (${action}) in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to create backup for demand ${demandId}:`, error);
            throw error;
        }
    }

    /**
     * Delete all backups for a demand
     * @param {string} demandId - Demand ID
     * @returns {Promise<void>}
     */
    async deleteAllBackups(demandId) {
        const startTime = Date.now();
        try {
            await backupService.deleteBackups('demand', demandId);
            logger.info(`Deleted all backups for demand ${demandId} in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to delete backups for demand ${demandId}:`, error);
            throw error;
        }
    }

    /**
     * Index demand for Elasticsearch
     * @param {Object} demand - Demand document
     * @returns {Promise<void>}
     */
    async indexForSearch(demand) {
        const startTime = Date.now();
        try {
            await searchClient.index({
                index: 'demands',
                id: demand._id.toString(),
                body: {
                    userId: demand.userId,
                    title: demand.title,
                    description: demand.description,
                    category: demand.category,
                    metrics: demand.metrics,
                    tags: demand.tags,
                    status: demand.status,
                    createdAt: demand.createdAt,
                    updatedAt: demand.updatedAt,
                },
            });
            logger.info(`Indexed demand ${demand._id} for search in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to index demand ${demand._id}:`, error);
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
            const stats = await Demand.aggregate([
                { $match: { userId: new mongoose.Types.ObjectId(userId), 'status.isDeleted': false } },
                {
                    $group: {
                        _id: null,
                        totalDemands: { $sum: 1 },
                        categories: { $addToSet: '$category' },
                        averageGrowthRate: { $avg: '$metrics.growthRate' },
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
     * Verify demand with external service
     * @param {Object} data - Verification data
     * @returns {Promise<Object>} - Verification result
     */
    async verifyDemand(data) {
        const startTime = Date.now();
        try {
            const result = await verificationService.verify({
                entityType: 'demand',
                entityId: data.demandId,
                data: {
                    title: data.title,
                    metrics: data.metrics,
                    category: data.category,
                },
                userId: data.userId,
            });

            metricsCollector.increment('demand.verified', { userId: data.userId, status: result.status });
            logger.info(`Verified demand ${data.demandId} in ${Date.now() - startTime}ms`);
            return result;
        } catch (error) {
            logger.error(`Verification failed for demand ${data.demandId}:`, error);
            metricsCollector.increment('demand.verify_failed', { userId: data.userId });
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
     * Extract skills from description
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
     * @param {Object} demand - Demand document
     * @returns {number} - Trending score
     */
    calculateTrendingScore(demand) {
        const viewsWeight = 0.3;
        const sharesWeight = 0.2;
        const endorsementsWeight = 0.2;
        const recencyWeight = 0.1;
        const growthWeight = 0.2;

        const daysSinceCreated = (Date.now() - new Date(demand.createdAt)) / (1000 * 60 * 60 * 24);
        const recencyScore = Math.max(0, 10 - daysSinceCreated);
        const growthScore = demand.metrics?.growthRate || 0;

        return (
            ((demand.analytics?.viewCount || 0) * viewsWeight) +
            ((demand.analytics?.shares?.total || 0) * sharesWeight) +
            ((demand.endorsements?.length || 0) * endorsementsWeight) +
            (recencyScore * recencyWeight) +
            (growthScore * growthWeight)
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
            title: { title: 1 },
            popular: { 'analytics.viewCount': -1 },
            quality: { 'metadata.qualityScore': -1 },
            verified: { 'verification.confidence': -1 },
            growth: { 'metrics.growthRate': -1 },
        };
        return sortOptions[sortBy] || sortOptions.recent;
    }
}

export default new DemandService();