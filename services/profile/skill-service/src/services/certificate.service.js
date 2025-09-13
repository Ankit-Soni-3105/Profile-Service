import Certification from '../models/Certification.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { cacheService } from '../services/cache.service.js';
import { metricsCollector } from '../utils/metrics.js';
import mongoose from 'mongoose';
import { eventEmitter } from '../events/events.js';
import { searchClient } from '../config/elasticsearch.config.js';
import { backupService } from './backup.service.js';
import { verificationService } from './verification.service.js';

class CertificationService {
    async createCertification(data, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;

        try {
            const certification = new Certification({
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

            const savedCertification = await certification.save({ session });
            await this.indexForSearch(savedCertification);

            metricsCollector.increment('certification.created', {
                userId: data.userId,
                category: data.category,
            });

            eventEmitter.emit('certification.created', {
                certificationId: savedCertification._id,
                userId: data.userId,
                category: data.category,
            });

            logger.info(`Certification created: ${savedCertification._id} in ${Date.now() - startTime}ms`);
            return savedCertification;
        } catch (error) {
            logger.error(`Failed to create certification for user ${data.userId}:`, error);
            metricsCollector.increment('certification.create_failed', { userId: data.userId });
            throw new AppError('Failed to create certification', 500);
        }
    }

    async getCertificationById(id, userId, options = {}) {
        const startTime = Date.now();
        const cacheKey = `certification:${id}:${userId}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('certification.cache_hit', { userId });
                return cached;
            }

            const certification = await Certification.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .cache({ ttl: 600, key: cacheKey });

            if (!certification) {
                throw new AppError('Certification not found', 404);
            }

            metricsCollector.increment('certification.fetched', { userId });
            logger.info(`Fetched certification ${id} in ${Date.now() - startTime}ms`);
            return certification;
        } catch (error) {
            logger.error(`Failed to fetch certification ${id}:`, error);
            metricsCollector.increment('certification.fetch_failed', { userId });
            throw error.name === 'CastError' ? new AppError('Invalid certification ID', 400) : error;
        }
    }

    async updateCertification(id, userId, updates, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;

        try {
            const certification = await Certification.findOne({ _id: id, userId }).session(session);
            if (!certification) {
                throw new AppError('Certification not found', 404);
            }

            Object.assign(certification, updates);
            certification.updatedAt = new Date();

            if (updates.title || updates.issuer) {
                certification.verification.status = 'pending';
            }

            await certification.save({ session });
            await this.indexForSearch(certification);

            await cacheService.deletePattern(`certification:${id}:*`);
            await cacheService.deletePattern(`certifications:${userId}:*`);

            metricsCollector.increment('certification.updated', {
                userId,
                fieldsUpdated: Object.keys(updates).length,
            });

            eventEmitter.emit('certification.updated', {
                certificationId: id,
                userId,
                changes: Object.keys(updates),
            });

            logger.info(`Certification updated: ${id} in ${Date.now() - startTime}ms`);
            return certification;
        } catch (error) {
            logger.error(`Failed to update certification ${id}:`, error);
            metricsCollector.increment('certification.update_failed', { userId });
            throw error.name === 'ValidationError' ? new AppError('Validation failed: ' + error.message, 400) : error;
        }
    }

    async deleteCertification(id, userId, permanent = false, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;

        try {
            if (permanent) {
                await Certification.findOneAndDelete({ _id: id, userId }, { session });
                await this.deleteAllBackups(id);
                await searchClient.delete({ index: 'certifications', id });
                metricsCollector.increment('certification.permanently_deleted', { userId });
            } else {
                const certification = await Certification.findOne({ _id: id, userId }).session(session);
                if (!certification) {
                    throw new AppError('Certification not found', 404);
                }
                certification.status.isDeleted = true;
                certification.status.deletedAt = new Date();
                await certification.save({ session });
                metricsCollector.increment('certification.soft_deleted', { userId });
            }

            await cacheService.deletePattern(`certification:${id}:*`);
            await cacheService.deletePattern(`certifications:${userId}:*`);

            eventEmitter.emit('certification.deleted', { certificationId: id, userId, permanent });

            logger.info(`Certification ${id} deleted (permanent: ${permanent}) in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to delete certification ${id}:`, error);
            metricsCollector.increment('certification.delete_failed', { userId });
            throw error;
        }
    }

    async getCertifications(query, options = {}) {
        const startTime = Date.now();
        const { userId, page = 1, limit = 20, status, category, search, tags, sortBy = 'recent' } = query;
        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
        const skip = (pageNum - 1) * limitNum;

        const cacheKey = `certifications:${userId}:${JSON.stringify({ pageNum, limitNum, status, category, search, tags, sortBy })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('certifications.cache_hit', { userId });
                return cached;
            }

            const mongoQuery = this.buildMongoQuery({ userId, status, category, search, tags });
            const sortOption = this.buildSortOption(sortBy);

            const [certifications, totalCount] = await Promise.all([
                Certification.find(mongoQuery)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select('userId title issuer category tags status createdAt updatedAt')
                    .lean(),
                Certification.countDocuments(mongoQuery).cache({ ttl: 300, key: `certification_count_${userId}` }),
            ]);

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                certifications,
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
            metricsCollector.increment('certifications.fetched', { userId, count: certifications.length });
            logger.info(`Fetched ${certifications.length} certifications for user ${userId} in ${Date.now() - startTime}ms`);
            return result;
        } catch (error) {
            logger.error(`Failed to fetch certifications for user ${userId}:`, error);
            metricsCollector.increment('certifications.fetch_failed', { userId });
            throw new AppError('Failed to fetch certifications', 500);
        }
    }

    async searchCertifications(query, filters = {}, options = {}) {
        const startTime = Date.now();
        const { page = 1, limit = 20 } = options;
        const from = (page - 1) * limit;

        try {
            const esQuery = {
                index: 'certifications',
                body: {
                    query: {
                        bool: {
                            must: query ? { multi_match: { query, fields: ['title', 'issuer', 'category', 'tags'] } } : { match_all: {} },
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

            metricsCollector.increment('certification.searched', { query, count: hits.length });
            logger.info(`Search returned ${hits.length} certifications in ${Date.now() - startTime}ms`);
            return { hits, total };
        } catch (error) {
            logger.error(`Search failed for query ${query}:`, error);
            metricsCollector.increment('certification.search_failed');
            throw new AppError('Failed to search certifications', 500);
        }
    }

    async getTrendingCertifications(timeframe, category, limit) {
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

            const certifications = await Certification.find(query)
                .read('secondaryPreferred')
                .select('userId title issuer category analytics createdAt')
                .limit(limit)
                .lean();

            const trending = certifications
                .map((cert) => ({
                    ...cert,
                    trendingScore: this.calculateTrendingScore(cert),
                }))
                .sort((a, b) => b.trendingScore - a.trendingScore)
                .slice(0, limit);

            metricsCollector.increment('certification.trending_fetched', { count: trending.length });
            logger.info(`Fetched ${trending.length} trending certifications in ${Date.now() - startTime}ms`);
            return trending;
        } catch (error) {
            logger.error(`Failed to fetch trending certifications:`, error);
            metricsCollector.increment('certification.trending_fetch_failed');
            throw new AppError('Failed to fetch trending certifications', 500);
        }
    }

    async createBackup(certificationId, action, userId, options = {}) {
        const startTime = Date.now();
        try {
            const certification = await Certification.findById(certificationId);
            if (!certification) {
                throw new AppError('Certification not found', 404);
            }

            await backupService.createBackup({
                entityType: 'certification',
                entityId: certificationId,
                data: certification.toObject(),
                action,
                userId,
            }, options);

            logger.info(`Backup created for certification ${certificationId} (${action}) in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to create backup for certification ${certificationId}:`, error);
            throw error;
        }
    }

    async deleteAllBackups(certificationId) {
        const startTime = Date.now();
        try {
            await backupService.deleteBackups('certification', certificationId);
            logger.info(`Deleted all backups for certification ${certificationId} in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to delete backups for certification ${certificationId}:`, error);
            throw error;
        }
    }

    async indexForSearch(certification) {
        const startTime = Date.now();
        try {
            await searchClient.index({
                index: 'certifications',
                id: certification._id.toString(),
                body: {
                    userId: certification.userId,
                    title: certification.title,
                    issuer: certification.issuer,
                    category: certification.category,
                    tags: certification.tags,
                    status: certification.status,
                    createdAt: certification.createdAt,
                    updatedAt: certification.updatedAt,
                },
            });
            logger.info(`Indexed certification ${certification._id} for search in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to index certification ${certification._id}:`, error);
            throw error;
        }
    }

    async updateUserStats(userId, options = {}) {
        const startTime = Date.now();
        try {
            const stats = await Certification.aggregate([
                { $match: { userId: new mongoose.Types.ObjectId(userId), 'status.isDeleted': false } },
                {
                    $group: {
                        _id: null,
                        totalCertifications: { $sum: 1 },
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

    async verifyCertification(data) {
        const startTime = Date.now();
        try {
            const result = await verificationService.verify({
                entityType: 'certification',
                entityId: data.certificationId,
                data: {
                    title: data.title,
                    issuer: data.issuer,
                    category: data.category,
                },
                userId: data.userId,
            });

            metricsCollector.increment('certification.verified', { userId: data.userId, status: result.status });
            logger.info(`Verified certification ${data.certificationId} in ${Date.now() - startTime}ms`);
            return result;
        } catch (error) {
            logger.error(`Verification failed for certification ${data.certificationId}:`, error);
            metricsCollector.increment('certification.verify_failed', { userId: data.userId });
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

    calculateTrendingScore(certification) {
        const viewsWeight = 0.4;
        const endorsementsWeight = 0.3;
        const recencyWeight = 0.3;

        const daysSinceCreated = (Date.now() - new Date(certification.createdAt)) / (1000 * 60 * 60 * 24);
        const recencyScore = Math.max(0, 10 - daysSinceCreated);

        return (
            ((certification.analytics?.viewCount || 0) * viewsWeight) +
            ((certification.endorsements?.length || 0) * endorsementsWeight) +
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
            title: { title: 1 },
            popular: { 'analytics.viewCount': -1 },
            quality: { 'metadata.qualityScore': -1 },
        };
        return sortOptions[sortBy] || sortOptions.recent;
    }
}

export default new CertificationService();