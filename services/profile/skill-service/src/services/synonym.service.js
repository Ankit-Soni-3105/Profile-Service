import Synonym from '../models/Synonym.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { cacheService } from '../services/cache.service.js';
import { metricsCollector } from '../utils/metrics.js';
import mongoose from 'mongoose';
import { eventEmitter } from '../events/events.js';
import { searchClient } from '../config/elasticsearch.config.js';
import { backupService } from './backup.service.js';
import { verificationService } from './verification.service.js';

class SynonymService {
    async createSynonym(data, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;

        try {
            const synonym = new Synonym({
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

            const savedSynonym = await synonym.save({ session });
            await this.indexForSearch(savedSynonym);

            metricsCollector.increment('synonym.created', {
                userId: data.userId,
                category: data.category,
            });

            eventEmitter.emit('synonym.created', {
                synonymId: savedSynonym._id,
                userId: data.userId,
                category: data.category,
            });

            logger.info(`Synonym created: ${savedSynonym._id} in ${Date.now() - startTime}ms`);
            return savedSynonym;
        } catch (error) {
            logger.error(`Failed to create synonym for user ${data.userId}:`, error);
            metricsCollector.increment('synonym.create_failed', { userId: data.userId });
            throw new AppError('Failed to create synonym', 500);
        }
    }

    async getSynonymById(id, userId, options = {}) {
        const startTime = Date.now();
        const cacheKey = `synonym:${id}:${userId}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('synonym.cache_hit', { userId });
                return cached;
            }

            const synonym = await Synonym.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .cache({ ttl: 600, key: cacheKey });

            if (!synonym) {
                throw new AppError('Synonym not found', 404);
            }

            metricsCollector.increment('synonym.fetched', { userId });
            logger.info(`Fetched synonym ${id} in ${Date.now() - startTime}ms`);
            return synonym;
        } catch (error) {
            logger.error(`Failed to fetch synonym ${id}:`, error);
            metricsCollector.increment('synonym.fetch_failed', { userId });
            throw error.name === 'CastError' ? new AppError('Invalid synonym ID', 400) : error;
        }
    }

    async updateSynonym(id, userId, updates, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;

        try {
            const synonym = await Synonym.findOne({ _id: id, userId }).session(session);
            if (!synonym) {
                throw new AppError('Synonym not found', 404);
            }

            Object.assign(synonym, updates);
            synonym.updatedAt = new Date();

            if (updates.term || updates.synonyms) {
                synonym.verification.status = 'pending';
            }

            await synonym.save({ session });
            await this.indexForSearch(synonym);

            await cacheService.deletePattern(`synonym:${id}:*`);
            await cacheService.deletePattern(`synonyms:${userId}:*`);

            metricsCollector.increment('synonym.updated', {
                userId,
                fieldsUpdated: Object.keys(updates).length,
            });

            eventEmitter.emit('synonym.updated', {
                synonymId: id,
                userId,
                changes: Object.keys(updates),
            });

            logger.info(`Synonym updated: ${id} in ${Date.now() - startTime}ms`);
            return synonym;
        } catch (error) {
            logger.error(`Failed to update synonym ${id}:`, error);
            metricsCollector.increment('synonym.update_failed', { userId });
            throw error.name === 'ValidationError' ? new AppError('Validation failed: ' + error.message, 400) : error;
        }
    }

    async deleteSynonym(id, userId, permanent = false, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;

        try {
            if (permanent) {
                await Synonym.findOneAndDelete({ _id: id, userId }, { session });
                await this.deleteAllBackups(id);
                await searchClient.delete({ index: 'synonyms', id });
                metricsCollector.increment('synonym.permanently_deleted', { userId });
            } else {
                const synonym = await Synonym.findOne({ _id: id, userId }).session(session);
                if (!synonym) {
                    throw new AppError('Synonym not found', 404);
                }
                synonym.status.isDeleted = true;
                synonym.status.deletedAt = new Date();
                await synonym.save({ session });
                metricsCollector.increment('synonym.soft_deleted', { userId });
            }

            await cacheService.deletePattern(`synonym:${id}:*`);
            await cacheService.deletePattern(`synonyms:${userId}:*`);

            eventEmitter.emit('synonym.deleted', { synonymId: id, userId, permanent });

            logger.info(`Synonym ${id} deleted (permanent: ${permanent}) in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to delete synonym ${id}:`, error);
            metricsCollector.increment('synonym.delete_failed', { userId });
            throw error;
        }
    }

    async getSynonyms(query, options = {}) {
        const startTime = Date.now();
        const { userId, page = 1, limit = 20, status, category, search, tags, sortBy = 'recent' } = query;
        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
        const skip = (pageNum - 1) * limitNum;

        const cacheKey = `synonyms:${userId}:${JSON.stringify({ pageNum, limitNum, status, category, search, tags, sortBy })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('synonyms.cache_hit', { userId });
                return cached;
            }

            const mongoQuery = this.buildMongoQuery({ userId, status, category, search, tags });
            const sortOption = this.buildSortOption(sortBy);

            const [synonyms, totalCount] = await Promise.all([
                Synonym.find(mongoQuery)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select('userId term synonyms category tags status createdAt updatedAt')
                    .lean(),
                Synonym.countDocuments(mongoQuery).cache({ ttl: 300, key: `synonym_count_${userId}` }),
            ]);

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                synonyms,
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
            metricsCollector.increment('synonyms.fetched', { userId, count: synonyms.length });
            logger.info(`Fetched ${synonyms.length} synonyms for user ${userId} in ${Date.now() - startTime}ms`);
            return result;
        } catch (error) {
            logger.error(`Failed to fetch synonyms for user ${userId}:`, error);
            metricsCollector.increment('synonyms.fetch_failed', { userId });
            throw new AppError('Failed to fetch synonyms', 500);
        }
    }

    async searchSynonyms(query, filters = {}, options = {}) {
        const startTime = Date.now();
        const { page = 1, limit = 20 } = options;
        const from = (page - 1) * limit;

        try {
            const esQuery = {
                index: 'synonyms',
                body: {
                    query: {
                        bool: {
                            must: query ? { multi_match: { query, fields: ['term', 'synonyms', 'category', 'tags'] } } : { match_all: {} },
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

            metricsCollector.increment('synonym.searched', { query, count: hits.length });
            logger.info(`Search returned ${hits.length} synonyms in ${Date.now() - startTime}ms`);
            return { hits, total };
        } catch (error) {
            logger.error(`Search failed for query ${query}:`, error);
            metricsCollector.increment('synonym.search_failed');
            throw new AppError('Failed to search synonyms', 500);
        }
    }

    async getTrendingSynonyms(timeframe, category, limit) {
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

            const synonyms = await Synonym.find(query)
                .read('secondaryPreferred')
                .select('userId term synonyms category analytics createdAt')
                .limit(limit)
                .lean();

            const trending = synonyms
                .map((syn) => ({
                    ...syn,
                    trendingScore: this.calculateTrendingScore(syn),
                }))
                .sort((a, b) => b.trendingScore - a.trendingScore)
                .slice(0, limit);

            metricsCollector.increment('synonym.trending_fetched', { count: trending.length });
            logger.info(`Fetched ${trending.length} trending synonyms in ${Date.now() - startTime}ms`);
            return trending;
        } catch (error) {
            logger.error(`Failed to fetch trending synonyms:`, error);
            metricsCollector.increment('synonym.trending_fetch_failed');
            throw new AppError('Failed to fetch trending synonyms', 500);
        }
    }

    async createBackup(synonymId, action, userId, options = {}) {
        const startTime = Date.now();
        try {
            const synonym = await Synonym.findById(synonymId);
            if (!synonym) {
                throw new AppError('Synonym not found', 404);
            }

            await backupService.createBackup({
                entityType: 'synonym',
                entityId: synonymId,
                data: synonym.toObject(),
                action,
                userId,
            }, options);

            logger.info(`Backup created for synonym ${synonymId} (${action}) in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to create backup for synonym ${synonymId}:`, error);
            throw error;
        }
    }

    async deleteAllBackups(synonymId) {
        const startTime = Date.now();
        try {
            await backupService.deleteBackups('synonym', synonymId);
            logger.info(`Deleted all backups for synonym ${synonymId} in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to delete backups for synonym ${synonymId}:`, error);
            throw error;
        }
    }

    async indexForSearch(synonym) {
        const startTime = Date.now();
        try {
            await searchClient.index({
                index: 'synonyms',
                id: synonym._id.toString(),
                body: {
                    userId: synonym.userId,
                    term: synonym.term,
                    synonyms: synonym.synonyms,
                    category: synonym.category,
                    tags: synonym.tags,
                    status: synonym.status,
                    createdAt: synonym.createdAt,
                    updatedAt: synonym.updatedAt,
                },
            });
            logger.info(`Indexed synonym ${synonym._id} for search in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to index synonym ${synonym._id}:`, error);
            throw error;
        }
    }

    async updateUserStats(userId, options = {}) {
        const startTime = Date.now();
        try {
            const stats = await Synonym.aggregate([
                { $match: { userId: new mongoose.Types.ObjectId(userId), 'status.isDeleted': false } },
                {
                    $group: {
                        _id: null,
                        totalSynonyms: { $sum: 1 },
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

    async verifySynonym(data) {
        const startTime = Date.now();
        try {
            const result = await verificationService.verify({
                entityType: 'synonym',
                entityId: data.synonymId,
                data: {
                    term: data.term,
                    synonyms: data.synonyms,
                    category: data.category,
                },
                userId: data.userId,
            });

            metricsCollector.increment('synonym.verified', { userId: data.userId, status: result.status });
            logger.info(`Verified synonym ${data.synonymId} in ${Date.now() - startTime}ms`);
            return result;
        } catch (error) {
            logger.error(`Verification failed for synonym ${data.synonymId}:`, error);
            metricsCollector.increment('synonym.verify_failed', { userId: data.userId });
            throw new AppError('Verification failed', 424);
        }
    }

    async checkConnectionLevel(userId, requestingUserId) {
        const startTime = Date.now();
        try {
            const isConnected = true; // Replace with actual logic
            logger.info(`Checked connection for ${userId} and ${requestingUserId} in ${Date.now() - startTime}ms`);
            return isConnected;
        } catch (error) {
            logger.error(`Failed to check connection for ${userId}:`, error);
            throw new AppError('Failed to check connection', 500);
        }
    }

    calculateTrendingScore(synonym) {
        const viewsWeight = 0.4;
        const endorsementsWeight = 0.3;
        const recencyWeight = 0.3;

        const daysSinceCreated = (Date.now() - new Date(synonym.createdAt)) / (1000 * 60 * 60 * 24);
        const recencyScore = Math.max(0, 10 - daysSinceCreated);

        return (
            ((synonym.analytics?.viewCount || 0) * viewsWeight) +
            ((synonym.endorsements?.length || 0) * endorsementsWeight) +
            (recencyScore * recencyWeight)
        );
    }

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

    buildSortOption(sortBy) {
        const sortOptions = {
            recent: { updatedAt: -1 },
            oldest: { createdAt: 1 },
            term: { term: 1 },
            popular: { 'analytics.viewCount': -1 },
            quality: { 'metadata.qualityScore': -1 },
        };
        return sortOptions[sortBy] || sortOptions.recent;
    }
}

export default new SynonymService();