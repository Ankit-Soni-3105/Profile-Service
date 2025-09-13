import School from '../models/School.js';
import { logger } from '../utils/logger.js';
import { cacheService } from './cache.service.js';
import { eventEmitter } from '../events/events.js';
import { metricsCollector } from '../utils/metrics.js';
import mongoose from 'mongoose';
import sanitizeHtml from 'sanitize-html';
import { AppError } from '../errors/app.error.js';
import { CircuitBreaker } from '../utils/circuitBreaker.js';
import { retry } from '../utils/retry.js';
import { elasticsearchClient } from '../config/elasticsearch.js';
import { s3Client } from '../config/s3.js';

class SchoolService {
    constructor() {
        this.model = School;
        this.circuitBreaker = new CircuitBreaker({
            timeout: 10000, // 10s timeout for external calls
            errorThresholdPercentage: 50,
            resetTimeout: 30000, // 30s reset
        });
        this.retryConfig = {
            retries: 3,
            delay: 100,
            backoff: 'exponential',
        };
    }

    /**
     * Create school with distributed transaction
     */
    async createSchool(data, options = {}) {
        const startTime = Date.now();
        const session = options.session || await mongoose.startSession();
        const { userId, name, type, country } = data;

        try {
            await session.withTransaction(async () => {
                const school = new this.model({
                    ...data,
                    description: sanitizeHtml(data.description || '', { allowedTags: [] }),
                    status: 'draft',
                    privacy: { isPublic: false },
                    analytics: { views: { total: 0, unique: 0, byDate: [] }, shares: { total: 0, byPlatform: {} } },
                    verification: { status: 'pending' },
                    attributes: [],
                });

                await school.save({ session });
                metricsCollector.increment('school.created', { userId, schoolName: name });
                logger.info(`School created: ${school._id} `);

                // Emit event for async processing
                eventEmitter.emit('school.created', { schoolId: school._id, userId });

                return school;
            });

            const responseTime = Date.now() - startTime;
            metricsCollector.timing('school.create_time', responseTime);
            return school;
        } catch (error) {
            logger.error(`School creation failed for user ${userId}: `, error);
            metricsCollector.increment('school.create_failed', { userId, error: error.name });
            throw error.name === 'MongoServerError' && error.message.includes('timeout')
                ? new AppError('Database operation timed out', 504)
                : error;
        } finally {
            if (!options.session) session.endSession();
        }
    }

    /**
     * Get trending schools with optimized aggregation
     */
    async getTrendingSchools(timeframe, type, limit) {
        const startTime = Date.now();
        const cacheKey = `trending_schools_${timeframe}_${type || 'all'}_${limit} `;
        const cached = await cacheService.get(cacheKey);
        if (cached) {
            metricsCollector.increment('school.trending_cache_hit');
            return cached;
        }

        try {
            const startDate = new Date();
            startDate.setDate(startDate.getDate() - parseInt(timeframe.replace('d', '')));

            const pipeline = [
                {
                    $match: {
                        status: 'active',
                        'privacy.isPublic': true,
                        createdAt: { $gte: startDate },
                        ...(type && { type }),
                    },
                },
                {
                    $addFields: {
                        trendingScore: {
                            $add: [
                                { $multiply: [{ $ifNull: ['$analytics.views.total', 0] }, 0.4] },
                                { $multiply: [{ $ifNull: ['$analytics.shares.total', 0] }, 0.3] },
                                { $multiply: [{ $size: { $ifNull: ['$attributes', []] } }, 0.2] },
                                {
                                    $multiply: [
                                        { $divide: [{ $subtract: [new Date(), '$createdAt'] }, 1000 * 60 * 60 * 24] },
                                        -0.1,
                                    ],
                                },
                            ],
                        },
                    },
                },
                { $sort: { trendingScore: -1 } },
                { $limit: parseInt(limit) },
                {
                    $project: {
                        trendingScore: 0,
                        verification: 0,
                        analytics: { $cond: [{ $eq: ['$privacy.isPublic', false] }, {}, '$analytics'] },
                    },
                },
            ];

            const results = await retry(
                () => this.model.aggregate(pipeline).read('secondaryPreferred').exec(),
                this.retryConfig
            );

            await cacheService.set(cacheKey, results, 3600); // 1 hour TTL
            const responseTime = Date.now() - startTime;
            metricsCollector.timing('school.trending_time', responseTime);
            metricsCollector.increment('school.trending_fetched', { count: results.length });
            logger.info(`Fetched ${results.length} trending schools in ${responseTime} ms`);

            return results;
        } catch (error) {
            logger.error(`Failed to fetch trending schools: `, error);
            metricsCollector.increment('school.trending_fetch_failed');
            throw new AppError('Failed to fetch trending schools', 500);
        }
    }

    /**
     * Search schools with Elasticsearch integration
     */
    async searchSchools(query, filters, pagination) {
        const startTime = Date.now();
        const cacheKey = `search_schools_${query}_${JSON.stringify(filters)}_page${pagination.page}_limit${pagination.limit} `;
        const cached = await cacheService.get(cacheKey);
        if (cached) {
            metricsCollector.increment('school.search_cache_hit');
            return cached;
        }

        try {
            const esQuery = {
                bool: {
                    must: [
                        { match: { status: 'active' } },
                        { match: { 'privacy.isPublic': true } },
                        query ? { multi_match: { query, fields: ['name^2', 'description', 'type', 'attributes'] } } : {},
                    ],
                    filter: this.buildSearchFilters(filters),
                },
            };

            const result = await retry(
                () =>
                    elasticsearchClient.search({
                        index: 'schools',
                        body: {
                            query: esQuery,
                            from: (pagination.page - 1) * pagination.limit,
                            size: pagination.limit,
                            sort: query ? [{ _score: 'desc' }] : [{ updatedAt: 'desc' }],
                        },
                    }),
                this.retryConfig
            );

            const hits = result.hits.hits.map((hit) => ({
                ...hit._source,
                _id: hit._id,
                score: hit._score,
            }));
            const total = result.hits.total.value;

            const response = { hits, total, pagination: { ...pagination, totalPages: Math.ceil(total / pagination.limit) } };
            await cacheService.set(cacheKey, response, 300); // 5 min TTL

            const responseTime = Date.now() - startTime;
            metricsCollector.timing('school.search_time', responseTime);
            metricsCollector.increment('school.searched', { query, count: hits.length });
            logger.info(`Search returned ${hits.length} schools in ${responseTime} ms`);

            return response;
        } catch (error) {
            logger.error(`Search failed for query ${query}: `, error);
            metricsCollector.increment('school.search_failed');
            throw new AppError('Failed to search schools', 500);
        }
    }

    /**
     * Extract attributes from description using NLP
     */
    async extractAttributes(description) {
        const startTime = Date.now();
        try {
            const attributes = await this.circuitBreaker.fire(async () => {
                // Simulated NLP call (e.g., AWS Comprehend)
                const rawAttributes = description.match(/\b(accredited|public|private|research|liberal arts)\b/gi) || [];
                return [...new Set(rawAttributes.map((a) => a.toLowerCase()))].slice(0, 20);
            });

            const responseTime = Date.now() - startTime;
            metricsCollector.timing('school.attribute_extraction_time', responseTime);
            logger.info(`Extracted ${attributes.length} attributes in ${responseTime} ms`);
            return attributes;
        } catch (error) {
            logger.error(`Attribute extraction failed: `, error);
            metricsCollector.increment('school.attribute_extraction_failed');
            return [];
        }
    }

    /**
     * Calculate quality score based on completeness and verification
     */
    async calculateQualityScore(school, options = {}) {
        const startTime = Date.now();
        try {
            let score = 0;
            if (school.name) score += 20;
            if (school.description && school.description.length > 50) score += 30;
            if (school.attributes?.length) score += school.attributes.length * 5;
            if (school.verification?.status === 'verified') score += 30;
            if (school.country) score += 10;
            score = Math.min(score, 100);

            school.qualityScore = score;
            await school.save(options);

            const responseTime = Date.now() - startTime;
            metricsCollector.timing('school.quality_score_time', responseTime);
            logger.info(`Calculated quality score ${score} for school ${school._id}`);
            return score;
        } catch (error) {
            logger.error(`Quality score calculation failed for school ${school._id}: `, error);
            metricsCollector.increment('school.quality_score_failed');
            throw new AppError('Failed to calculate quality score', 500);
        }
    }

    /**
     * Index school for Elasticsearch
     */
    async indexForSearch(school) {
        const startTime = Date.now();
        try {
            await retry(
                () =>
                    elasticsearchClient.index({
                        index: 'schools',
                        id: school._id.toString(),
                        body: {
                            name: school.name,
                            type: school.type,
                            description: school.description,
                            country: school.country,
                            attributes: school.attributes,
                            status: school.status,
                            privacy: school.privacy,
                            createdAt: school.createdAt,
                            updatedAt: school.updatedAt,
                        },
                    }),
                this.retryConfig
            );

            const responseTime = Date.now() - startTime;
            metricsCollector.timing('school.index_time', responseTime);
            logger.info(`Indexed school ${school._id} for search in ${responseTime} ms`);
        } catch (error) {
            logger.error(`Search indexing failed for school ${school._id}: `, error);
            metricsCollector.increment('school.index_failed');
            throw new AppError('Failed to index school for search', 500);
        }
    }

    /**
     * Update user stats
     */
    async updateUserStats(userId, options = {}) {
        const startTime = Date.now();
        try {
            const schoolCount = await this.model.countDocuments({ 'metadata.createdBy.userId': userId, status: { $ne: 'deleted' } });
            // Update user profile stats (hypothetical User model)
            // await User.updateOne({ _id: userId }, { $set: { schoolCount } }, options);

            const responseTime = Date.now() - startTime;
            metricsCollector.timing('school.user_stats_time', responseTime);
            logger.info(`Updated stats for user ${userId}: ${schoolCount} schools`);
        } catch (error) {
            logger.error(`User stats update failed for ${userId}: `, error);
            metricsCollector.increment('school.user_stats_failed');
            throw new AppError('Failed to update user stats', 500);
        }
    }

    /**
     * Check connection level for endorsements
     */
    async checkConnectionLevel(userId1, userId2) {
        const startTime = Date.now();
        try {
            // Placeholder: Assume connected for demo
            const isConnected = true;
            const responseTime = Date.now() - startTime;
            metricsCollector.timing('school.connection_check_time', responseTime);
            return isConnected;
        } catch (error) {
            logger.error(`Connection check failed for ${userId1} and ${userId2}: `, error);
            metricsCollector.increment('school.connection_check_failed');
            throw new AppError('Failed to check connection level', 500);
        }
    }

    /**
     * Build search filters for Elasticsearch
     */
    buildSearchFilters(filters) {
        const filterQuery = [];
        if (filters.type) filterQuery.push({ match: { type: filters.type } });
        if (filters.status) filterQuery.push({ match: { status: filters.status } });
        if (filters.country) filterQuery.push({ match: { country: filters.country } });
        if (filters.attributes) filterQuery.push({ terms: { attributes: filters.attributes.split(',').map((a) => a.trim()) } });
        return filterQuery;
    }

    /**
     * Create backup to S3
     */
    async createBackup(schoolId, action, userId, options = {}) {
        const startTime = Date.now();
        try {
            const school = await this.model.findById(schoolId).session(options.session);
            if (!school) throw new AppError('School not found for backup', 404);

            const backupData = {
                schoolId,
                action,
                userId,
                data: school.toObject(),
                timestamp: new Date(),
            };

            await retry(
                () =>
                    s3Client.upload({
                        Bucket: process.env.S3_BACKUP_BUCKET,
                        Key: `backups / school / ${schoolId}/${Date.now()}.json`,
                        Body: JSON.stringify(backupData),
                        Metadata: { userId: userId.toString(), action },
                    }),
                this.retryConfig
            );

            const responseTime = Date.now() - startTime;
            metricsCollector.timing('school.backup_time', responseTime);
            logger.info(`Backup created for school ${schoolId} after ${action}`);
        } catch (error) {
            logger.error(`Backup failed for school ${schoolId}:`, error);
            metricsCollector.increment('school.backup_failed');
            throw new AppError('Failed to create backup', 500);
        }
    }

    /**
     * Delete all backups from S3
     */
    async deleteAllBackups(schoolId) {
        const startTime = Date.now();
        try {
            const objects = await s3Client.listObjectsV2({
                Bucket: process.env.S3_BACKUP_BUCKET,
                Prefix: `backups/school/${schoolId}/`,
            }).promise();

            if (objects.Contents.length) {
                await retry(
                    () =>
                        s3Client.deleteObjects({
                            Bucket: process.env.S3_BACKUP_BUCKET,
                            Delete: { Objects: objects.Contents.map(({ Key }) => ({ Key })) },
                        }),
                    this.retryConfig
                );
            }

            const responseTime = Date.now() - startTime;
            metricsCollector.timing('school.delete_backups_time', responseTime);
            logger.info(`All backups deleted for school ${schoolId}`);
        } catch (error) {
            logger.error(`Backup deletion failed for school ${schoolId}:`, error);
            metricsCollector.increment('school.delete_backups_failed');
            throw new AppError('Failed to delete backups', 500);
        }
    }

    /**
     * Verify school with external API
     */
    async verifySchool({ schoolId, userId, name, country, type }) {
        const startTime = Date.now();
        try {
            const verificationResult = await this.circuitBreaker.fire(async () => {
                // Placeholder for external verification API (e.g., university registry)
                return {
                    success: true,
                    status: 'verified',
                    confidence: 0.95,
                    verifiedBy: 'external_api',
                    details: { name, country, type },
                };
            });

            const responseTime = Date.now() - startTime;
            metricsCollector.timing('school.verify_time', responseTime);
            metricsCollector.increment('school.verified', { userId, status: verificationResult.status });
            logger.info(`School ${schoolId} verified in ${responseTime}ms`);
            return verificationResult;
        } catch (error) {
            logger.error(`Verification failed for school ${schoolId}:`, error);
            metricsCollector.increment('school.verify_failed', { userId });
            throw error.message.includes('timeout')
                ? new AppError('External API timeout', 503)
                : new AppError('Failed to verify school', 424);
        }
    }

    /**
     * Get school by ID with optimized query
     */
    async getSchoolById(schoolId) {
        const startTime = Date.now();
        const cacheKey = `school:${schoolId}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('school.cache_hit');
                return cached;
            }

            const school = await retry(
                () =>
                    this.model
                        .findById(schoolId)
                        .read('secondaryPreferred')
                        .lean(),
                this.retryConfig
            );

            if (!school) throw new AppError('School not found', 404);

            await cacheService.set(cacheKey, school, 600); // 10 min TTL
            const responseTime = Date.now() - startTime;
            metricsCollector.timing('school.get_by_id_time', responseTime);
            return school;
        } catch (error) {
            logger.error(`Failed to fetch school ${schoolId}:`, error);
            metricsCollector.increment('school.get_by_id_failed');
            throw error;
        }
    }
}

export default new SchoolService();
