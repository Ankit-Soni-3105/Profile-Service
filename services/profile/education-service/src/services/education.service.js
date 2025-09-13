// EducationService.js
import Education from '../models/Education.js';
import School from '../models/School.js';
import { logger } from '../utils/logger.js';
import { cacheService } from './cache.service.js';
import { eventEmitter } from '../events/events.js';
import { metricsCollector } from '../utils/metrics.js';
import mongoose from 'mongoose';
import sanitizeHtml from 'sanitize-html';
import { AppError } from '../errors/app.error.js';
import { CircuitBreaker } from '../utils/circuitBreaker.js'; // Hypothetical circuit breaker utility
import { retry } from '../utils/retry.js'; // Hypothetical retry utility
import { elasticsearchClient } from '../config/elasticsearch.js'; // Elasticsearch client
import { s3Client } from '../config/s3.js'; // S3 client for media storage

class EducationService {
    constructor() {
        this.model = Education;
        this.schoolModel = School;
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
     * Create education with distributed transaction and async processing
     */
    async createEducation(data, options = {}) {
        const startTime = Date.now();
        const session = options.session || await mongoose.startSession();
        const { userId, degree, schoolId, duration } = data;

        try {
            await session.withTransaction(async () => {
                // Validate school existence
                const schoolExists = await this.schoolModel.findById(schoolId).session(session);
                if (!schoolExists) {
                    throw new AppError('School not found', 404);
                }

                const education = new this.model({
                    ...data,
                    description: sanitizeHtml(data.description || '', { allowedTags: [] }),
                    status: 'draft',
                    privacy: { isPublic: false },
                    analytics: { views: { total: 0, unique: 0, byDate: [] }, shares: { total: 0, byPlatform: {} } },
                    endorsements: [],
                    verification: { status: 'pending' },
                });

                await education.save({ session });
                metricsCollector.increment('education.created', { userId, degree });
                logger.info(`Education created: ${education._id}`);

                // Emit event for async processing
                eventEmitter.emit('education.created', { educationId: education._id, userId });

                return education;
            });

            const responseTime = Date.now() - startTime;
            metricsCollector.timing('education.create_time', responseTime);
            return education;
        } catch (error) {
            logger.error(`Education creation failed for user ${userId}:`, error);
            metricsCollector.increment('education.create_failed', { userId, error: error.name });
            throw error.name === 'MongoServerError' && error.message.includes('timeout')
                ? new AppError('Database operation timed out', 504)
                : error;
        } finally {
            if (!options.session) session.endSession();
        }
    }

    /**
     * Get trending educations with optimized aggregation
     */
    async getTrendingEducations(timeframe, degree, limit) {
        const startTime = Date.now();
        const cacheKey = `trending_educations_${timeframe}_${degree || 'all'}_${limit}`;
        const cached = await cacheService.get(cacheKey);
        if (cached) {
            metricsCollector.increment('education.trending_cache_hit');
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
                        ...(degree && { degree }),
                    },
                },
                {
                    $lookup: {
                        from: 'schools',
                        localField: 'schoolId',
                        foreignField: '_id',
                        as: 'school',
                    },
                },
                { $unwind: { path: '$school', preserveNullAndEmptyArrays: true } },
                {
                    $addFields: {
                        trendingScore: {
                            $add: [
                                { $multiply: [{ $ifNull: ['$analytics.views.total', 0] }, 0.4] },
                                { $multiply: [{ $ifNull: ['$analytics.shares.total', 0] }, 0.3] },
                                { $multiply: [{ $size: { $ifNull: ['$endorsements', []] } }, 0.2] },
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
            metricsCollector.timing('education.trending_time', responseTime);
            metricsCollector.increment('education.trending_fetched', { count: results.length });
            logger.info(`Fetched ${results.length} trending educations in ${responseTime}ms`);

            return results;
        } catch (error) {
            logger.error(`Failed to fetch trending educations:`, error);
            metricsCollector.increment('education.trending_fetch_failed');
            throw new AppError('Failed to fetch trending educations', 500);
        }
    }

    /**
     * Search educations with Elasticsearch integration
     */
    async searchEducations(query, filters, pagination) {
        const startTime = Date.now();
        const cacheKey = `search_educations_${query}_${JSON.stringify(filters)}_page${pagination.page}_limit${pagination.limit}`;
        const cached = await cacheService.get(cacheKey);
        if (cached) {
            metricsCollector.increment('education.search_cache_hit');
            return cached;
        }

        try {
            const esQuery = {
                bool: {
                    must: [
                        { match: { status: 'active' } },
                        { match: { 'privacy.isPublic': true } },
                        query ? { multi_match: { query, fields: ['degree^2', 'description', 'fieldOfStudy', 'tags'] } } : {},
                    ],
                    filter: this.buildSearchFilters(filters),
                },
            };

            const result = await retry(
                () =>
                    elasticsearchClient.search({
                        index: 'educations',
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
            metricsCollector.timing('education.search_time', responseTime);
            metricsCollector.increment('education.searched', { query, count: hits.length });
            logger.info(`Search returned ${hits.length} educations in ${responseTime}ms`);

            return response;
        } catch (error) {
            logger.error(`Search failed for query ${query}:`, error);
            metricsCollector.increment('education.search_failed');
            throw new AppError('Failed to search educations', 500);
        }
    }

    /**
     * Extract skills from description using NLP
     */
    async extractSkills(description) {
        const startTime = Date.now();
        try {
            // Implement NLP-based skill extraction (e.g., using AWS Comprehend or similar)
            // Placeholder: Mock skill extraction
            const skills = await this.circuitBreaker.fire(async () => {
                // Simulated NLP call
                const rawSkills = description.match(/\b(programming|leadership|research|analysis)\b/gi) || [];
                return [...new Set(rawSkills.map((s) => s.toLowerCase()))].slice(0, 20);
            });

            const responseTime = Date.now() - startTime;
            metricsCollector.timing('education.skill_extraction_time', responseTime);
            logger.info(`Extracted ${skills.length} skills in ${responseTime}ms`);
            return skills;
        } catch (error) {
            logger.error(`Skill extraction failed:`, error);
            metricsCollector.increment('education.skill_extraction_failed');
            return [];
        }
    }

    /**
     * Calculate quality score based on completeness and verification
     */
    async calculateQualityScore(education, options = {}) {
        const startTime = Date.now();
        try {
            let score = 0;
            // Completeness scoring
            if (education.degree) score += 20;
            if (education.description && education.description.length > 50) score += 30;
            if (education.skills?.length) score += education.skills.length * 5;
            if (education.verification?.status === 'verified') score += 30;
            if (education.gpa) score += 10;
            score = Math.min(score, 100);

            education.qualityScore = score;
            await education.save(options);

            const responseTime = Date.now() - startTime;
            metricsCollector.timing('education.quality_score_time', responseTime);
            logger.info(`Calculated quality score ${score} for education ${education._id}`);
            return score;
        } catch (error) {
            logger.error(`Quality score calculation failed for education ${education._id}:`, error);
            metricsCollector.increment('education.quality_score_failed');
            throw new AppError('Failed to calculate quality score', 500);
        }
    }

    /**
     * Index education for Elasticsearch
     */
    async indexForSearch(education) {
        const startTime = Date.now();
        try {
            await retry(
                () =>
                    elasticsearchClient.index({
                        index: 'educations',
                        id: education._id.toString(),
                        body: {
                            degree: education.degree,
                            fieldOfStudy: education.fieldOfStudy,
                            description: education.description,
                            tags: education.tags,
                            skills: education.skills,
                            schoolId: education.schoolId,
                            status: education.status,
                            privacy: education.privacy,
                            createdAt: education.createdAt,
                            updatedAt: education.updatedAt,
                        },
                    }),
                this.retryConfig
            );

            const responseTime = Date.now() - startTime;
            metricsCollector.timing('education.index_time', responseTime);
            logger.info(`Indexed education ${education._id} for search in ${responseTime}ms`);
        } catch (error) {
            logger.error(`Search indexing failed for education ${education._id}:`, error);
            metricsCollector.increment('education.index_failed');
            throw new AppError('Failed to index education for search', 500);
        }
    }

    /**
     * Update user stats
     */
    async updateUserStats(userId, options = {}) {
        const startTime = Date.now();
        try {
            const educationCount = await this.model.countDocuments({ userId, status: { $ne: 'deleted' } });
            // Update user profile stats (hypothetical User model)
            // await User.updateOne({ _id: userId }, { $set: { educationCount } }, options);

            const responseTime = Date.now() - startTime;
            metricsCollector.timing('education.user_stats_time', responseTime);
            logger.info(`Updated stats for user ${userId}: ${educationCount} educations`);
        } catch (error) {
            logger.error(`User stats update failed for ${userId}:`, error);
            metricsCollector.increment('education.user_stats_failed');
            throw new AppError('Failed to update user stats', 500);
        }
    }

    /**
     * Check connection level for endorsements
     */
    async checkConnectionLevel(userId1, userId2) {
        const startTime = Date.now();
        try {
            // Implement connection check logic (e.g., check mutual connections in a User model)
            // Placeholder: Assume connected for demo
            const isConnected = true; // Replace with actual logic
            const responseTime = Date.now() - startTime;
            metricsCollector.timing('education.connection_check_time', responseTime);
            return isConnected;
        } catch (error) {
            logger.error(`Connection check failed for ${userId1} and ${userId2}:`, error);
            metricsCollector.increment('education.connection_check_failed');
            throw new AppError('Failed to check connection level', 500);
        }
    }

    /**
     * Build search filters for Elasticsearch
     */
    buildSearchFilters(filters) {
        const filterQuery = [];
        if (filters.degree) filterQuery.push({ match: { degree: filters.degree } });
        if (filters.status) filterQuery.push({ match: { status: filters.status } });
        if (filters.fieldOfStudy) filterQuery.push({ match: { fieldOfStudy: filters.fieldOfStudy } });
        if (filters.tags) filterQuery.push({ terms: { tags: filters.tags.split(',').map((t) => t.trim()) } });
        if (filters.startDate || filters.endDate) {
            filterQuery.push({
                range: {
                    'duration.startDate': {
                        ...(filters.startDate && { gte: filters.startDate }),
                        ...(filters.endDate && { lte: filters.endDate }),
                    },
                },
            });
        }
        return filterQuery;
    }

    /**
     * Calculate duration formatted
     */
    calculateDurationFormatted(startDate, endDate) {
        try {
            if (!startDate) return 'N/A';
            const end = endDate || new Date();
            const months = Math.round((new Date(end) - new Date(startDate)) / (1000 * 60 * 60 * 24 * 30));
            const years = Math.floor(months / 12);
            const remainingMonths = months % 12;
            return `${years > 0 ? `${years} year${years > 1 ? 's' : ''} ` : ''}${remainingMonths} month${remainingMonths !== 1 ? 's' : ''}`;
        } catch (error) {
            logger.error(`Duration formatting failed:`, error);
            return 'N/A';
        }
    }

    /**
     * Create backup to S3
     */
    async createBackup(educationId, action, userId, options = {}) {
        const startTime = Date.now();
        try {
            const education = await this.model.findById(educationId).session(options.session);
            if (!education) throw new AppError('Education not found for backup', 404);

            const backupData = {
                educationId,
                action,
                userId,
                data: education.toObject(),
                timestamp: new Date(),
            };

            await retry(
                () =>
                    s3Client.upload({
                        Bucket: process.env.S3_BACKUP_BUCKET,
                        Key: `backups/education/${educationId}/${Date.now()}.json`,
                        Body: JSON.stringify(backupData),
                        Metadata: { userId: userId.toString(), action },
                    }),
                this.retryConfig
            );

            const responseTime = Date.now() - startTime;
            metricsCollector.timing('education.backup_time', responseTime);
            logger.info(`Backup created for education ${educationId} after ${action}`);
        } catch (error) {
            logger.error(`Backup failed for education ${educationId}:`, error);
            metricsCollector.increment('education.backup_failed');
            throw new AppError('Failed to create backup', 500);
        }
    }

    /**
     * Delete all backups from S3
     */
    async deleteAllBackups(educationId) {
        const startTime = Date.now();
        try {
            const objects = await s3Client.listObjectsV2({
                Bucket: process.env.S3_BACKUP_BUCKET,
                Prefix: `backups/education/${educationId}/`,
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
            metricsCollector.timing('education.delete_backups_time', responseTime);
            logger.info(`All backups deleted for education ${educationId}`);
        } catch (error) {
            logger.error(`Backup deletion failed for education ${educationId}:`, error);
            metricsCollector.increment('education.delete_backups_failed');
            throw new AppError('Failed to delete backups', 500);
        }
    }

    /**
     * Verify education with external API
     */
    async verifyEducation({ educationId, userId, schoolId, degree, duration, gpa }) {
        const startTime = Date.now();
        try {
            const school = await this.schoolModel.findById(schoolId);
            if (!school) throw new AppError('School not found', 404);

            const verificationResult = await this.circuitBreaker.fire(async () => {
                // Placeholder for external verification API (e.g., university API)
                // Simulated response
                return {
                    success: true,
                    status: 'verified',
                    confidence: 0.95,
                    verifiedBy: 'external_api',
                    details: { degree, school: school.name, duration, gpa },
                };
            });

            const responseTime = Date.now() - startTime;
            metricsCollector.timing('education.verify_time', responseTime);
            metricsCollector.increment('education.verified', { userId, status: verificationResult.status });
            logger.info(`Education ${educationId} verified in ${responseTime}ms`);
            return verificationResult;
        } catch (error) {
            logger.error(`Verification failed for education ${educationId}:`, error);
            metricsCollector.increment('education.verify_failed', { userId });
            throw error.message.includes('timeout')
                ? new AppError('External API timeout', 503)
                : new AppError('Failed to verify education', 424);
        }
    }

    /**
     * Get education by ID with optimized query
     */
    async getEducationById(educationId) {
        const startTime = Date.now();
        const cacheKey = `education:${educationId}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('education.cache_hit');
                return cached;
            }

            const education = await retry(
                () =>
                    this.model
                        .findById(educationId)
                        .read('secondaryPreferred')
                        .populate('schoolId', 'name type')
                        .lean(),
                this.retryConfig
            );

            if (!education) throw new AppError('Education not found', 404);

            await cacheService.set(cacheKey, education, 600); // 10 min TTL
            const responseTime = Date.now() - startTime;
            metricsCollector.timing('education.get_by_id_time', responseTime);
            return education;
        } catch (error) {
            logger.error(`Failed to fetch education ${educationId}:`, error);
            metricsCollector.increment('education.get_by_id_failed');
            throw error;
        }
    }
}

export default new EducationService();