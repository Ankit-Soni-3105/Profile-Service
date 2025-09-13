import Certification from '../models/Certification.js';
import User from '../models/User.js';
import Organization from '../models/Organization.js';
import { cacheService } from './cache.service.js';
import { logger } from '../utils/logger.js';
import { metricsCollector } from '../utils/metrics.js';
import { AppError } from '../errors/app.error.js';
import mongoose from 'mongoose';
import { eventEmitter } from '../events/events.js';
import { searchClient } from '../config/elasticsearch.config.js';
import AWS from 'aws-sdk';
import { v4 as uuidv4 } from 'uuid';

// Initialize AWS S3 for backups
const s3 = new AWS.S3({
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    region: process.env.AWS_REGION,
});

class CertificationService {
    /**
     * Create a new certification
     * @param {Object} data - Certification data
     * @param {Object} options - Additional options (e.g., session)
     * @returns {Promise<Object>} - Created certification document
     */
    async createCertification(data, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;

        try {
            const certification = new Certification({
                ...data,
                status: {
                    isActive: true,
                    isDeleted: false,
                    workflow: 'draft',
                    createdAt: new Date(),
                    updatedAt: new Date(),
                },
                metadata: {
                    ...data.metadata,
                    qualityScore: 0,
                    lastModifiedBy: data.metadata?.createdBy || null,
                },
                analytics: {
                    views: 0,
                    shareCount: 0,
                    engagementMetrics: { endorsements: [] },
                    viewHistory: [],
                },
                verification: {
                    status: 'pending',
                    verificationScore: 0,
                    documents: [],
                },
            });

            const savedCertification = await certification.save({ session });

            // Index for search
            await this.indexForSearch(savedCertification);

            // Emit event
            eventEmitter.emit('certification.created', {
                certificationId: savedCertification._id,
                userId: data.userId,
                category: data.badgeDetails?.category,
            });

            // Log metrics
            metricsCollector.increment('certification.created', {
                userId: data.userId,
                category: data.badgeDetails?.category,
                templateUsed: !!data.templateId,
            });

            logger.info(`Certification created: ${savedCertification._id} in ${Date.now() - startTime}ms`);
            return savedCertification;
        } catch (error) {
            logger.error(`Failed to create certification for user ${data.userId}:`, error);
            metricsCollector.increment('certification.create_failed', { userId: data.userId });
            if (error.name === 'ValidationError') {
                throw new AppError('Validation failed: ' + error.message, 400);
            }
            if (error.code === 11000) {
                throw new AppError('Certification with this title already exists', 409);
            }
            throw new AppError('Failed to create certification', 500);
        }
    }

    /**
     * Get certification by ID
     * @param {string} id - Certification ID
     * @param {string} userId - User ID
     * @param {Object} options - Additional options
     * @returns {Promise<Object>} - Certification document
     */
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
                .populate('organization.organizationId', 'name logo industry verification.isVerified')
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
            if (error.name === 'CastError') {
                throw new AppError('Invalid certification ID', 400);
            }
            throw error;
        }
    }

    /**
     * Update certification
     * @param {string} id - Certification ID
     * @param {string} userId - User ID
     * @param {Object} updates - Fields to update
     * @param {Object} options - Additional options
     * @returns {Promise<Object>} - Updated certification document
     */
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

            if (updates.badgeDetails || updates.organization || updates.duration) {
                certification.verification.status = 'pending';
            }

            await certification.save({ session });

            // Update search index
            await this.indexForSearch(certification);

            // Clear cache
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
            if (error.name === 'ValidationError') {
                throw new AppError('Validation failed: ' + error.message, 400);
            }
            throw error;
        }
    }

    /**
     * Delete certification (soft or permanent)
     * @param {string} id - Certification ID
     * @param {string} userId - User ID
     * @param {boolean} permanent - Permanent deletion flag
     * @param {Object} options - Additional options
     * @returns {Promise<void>}
     */
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
                certification.status.isActive = false;
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

    /**
     * Get certifications with filtering and pagination
     * @param {Object} query - Query parameters
     * @param {Object} options - Additional options
     * @returns {Promise<Object>} - Certifications and pagination info
     */
    async getCertifications(query, options = {}) {
        const startTime = Date.now();
        const { userId, page = 1, limit = 20, status, category, search, tags, templateId, sortBy = 'recent' } = query;
        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
        const skip = (pageNum - 1) * limitNum;

        const cacheKey = `certifications:${userId}:${JSON.stringify({ pageNum, limitNum, status, category, search, tags, templateId, sortBy })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('certifications.cache_hit', { userId });
                return cached;
            }

            const mongoQuery = this.buildMongoQuery({ userId, status, category, search, tags, templateId });
            const sortOption = this.buildSortOption(sortBy);

            const [certifications, totalCount] = await Promise.all([
                Certification.find(mongoQuery)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select('badgeDetails organization duration status templateId createdAt updatedAt')
                    .populate('organization.organizationId', 'name logo industry verification.isVerified')
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

    /**
     * Search certifications using Elasticsearch
     * @param {string} query - Search query
     * @param {Object} filters - Additional filters
     * @param {Object} options - Pagination options
     * @returns {Promise<Object>} - Search results
     */
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
                            must: query ? { multi_match: { query, fields: ['badgeDetails.title', 'badgeDetails.description', 'badgeDetails.category', 'badgeDetails.tags', 'badgeDetails.skills'] } } : { match_all: {} },
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

    /**
     * Get trending certifications
     * @param {string} timeframe - Timeframe (e.g., '7d', '30d')
     * @param {string} category - Optional category filter
     * @param {number} limit - Number of results
     * @returns {Promise<Array>} - Trending certifications
     */
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
                'status.isActive': true,
                'status.isDeleted': false,
                'status.workflow': 'verified',
                'analytics.lastViewed': { $gte: timeframeDate },
            };
            if (category && category !== 'all') {
                query['badgeDetails.category'] = category;
            }

            const certifications = await Certification.find(query)
                .read('secondaryPreferred')
                .select('badgeDetails organization duration verification analytics createdAt')
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

    /**
     * Create backup of certification
     * @param {string} certificationId - Certification ID
     * @param {string} action - Action type (create, update, duplicate)
     * @param {string} userId - User ID
     * @param {Object} options - Additional options
     * @returns {Promise<void>}
     */
    async createBackup(certificationId, action, userId, options = {}) {
        const startTime = Date.now();
        try {
            const certification = await Certification.findById(certificationId).lean();
            if (!certification) {
                throw new AppError('Certification not found', 404);
            }

            const backupKey = `certification_backup_${certificationId}_${Date.now()}`;
            await s3.upload({
                Bucket: process.env.S3_BACKUP_BUCKET,
                Key: backupKey,
                Body: JSON.stringify({
                    certification,
                    action,
                    userId,
                    timestamp: new Date(),
                }),
                ContentType: 'application/json',
                ServerSideEncryption: 'AES256',
            }).promise();

            logger.info(`Backup created for certification ${certificationId} (${action}) in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to create backup for certification ${certificationId}:`, error);
            throw error;
        }
    }

    /**
     * Delete all backups for a certification
     * @param {string} certificationId - Certification ID
     * @returns {Promise<void>}
     */
    async deleteAllBackups(certificationId) {
        const startTime = Date.now();
        try {
            const objects = await s3.listObjectsV2({
                Bucket: process.env.S3_BACKUP_BUCKET,
                Prefix: `certification_backup_${certificationId}_`,
            }).promise();

            if (objects.Contents.length > 0) {
                await s3.deleteObjects({
                    Bucket: process.env.S3_BACKUP_BUCKET,
                    Delete: {
                        Objects: objects.Contents.map(({ Key }) => ({ Key })),
                    },
                }).promise();
            }

            logger.info(`Deleted all backups for certification ${certificationId} in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to delete backups for certification ${certificationId}:`, error);
            throw error;
        }
    }

    /**
     * Index certification for Elasticsearch
     * @param {Object} certification - Certification document
     * @returns {Promise<void>}
     */
    async indexForSearch(certification) {
        const startTime = Date.now();
        try {
            await searchClient.index({
                index: 'certifications',
                id: certification._id.toString(),
                body: {
                    userId: certification.userId,
                    title: certification.badgeDetails.title,
                    description: certification.badgeDetails.description,
                    category: certification.badgeDetails.category,
                    tags: certification.badgeDetails.tags,
                    skills: certification.badgeDetails.skills,
                    organization: certification.organization,
                    status: certification.status,
                    verificationStatus: certification.verification.status,
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

    /**
     * Update user stats
     * @param {string} userId - User ID
     * @param {Object} options - Additional options
     * @returns {Promise<void>}
     */
    async updateUserStats(userId, options = {}) {
        const startTime = Date.now();
        try {
            const stats = await Certification.aggregate([
                { $match: { userId: new mongoose.Types.ObjectId(userId), 'status.isDeleted': false } },
                {
                    $group: {
                        _id: null,
                        totalCertifications: { $sum: 1 },
                        categories: { $addToSet: '$badgeDetails.category' },
                        verifiedCount: {
                            $sum: { $cond: [{ $eq: ['$status.workflow', 'verified'] }, 1, 0] },
                        },
                    },
                },
            ]).cache({ ttl: 3600, key: `user_stats_${userId}` });

            await User.updateOne(
                { _id: userId },
                {
                    $set: {
                        'profile.certificationCount': stats[0]?.totalCertifications || 0,
                        'profile.categories': stats[0]?.categories || [],
                        'profile.lastUpdated': new Date(),
                    },
                    $inc: { 'analytics.profileUpdates': 1 },
                },
                options
            );

            await cacheService.deletePattern(`user:${userId}:*`);
            eventEmitter.emit('user.stats_updated', { userId, stats: stats[0] || {} });
            logger.info(`Updated stats for user ${userId} in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to update stats for user ${userId}:`, error);
            throw error;
        }
    }

    /**
     * Verify certification with external service
     * @param {Object} data - Verification data
     * @returns {Promise<Object>} - Verification result
     */
    async verifyCertification(data) {
        const startTime = Date.now();
        try {
            // Mock external verification (replace with actual service like LinkedIn/Credly)
            const result = {
                success: true,
                status: 'verified',
                confidence: Math.random() * 100,
                verifiedBy: 'external_service',
                method: 'api',
            };

            metricsCollector.increment('certification.verified', { userId: data.userId, status: result.status });
            logger.info(`Verified certification ${data.certificationId} in ${Date.now() - startTime}ms`);
            return result;
        } catch (error) {
            logger.error(`Verification failed for certification ${data.certificationId}:`, error);
            metricsCollector.increment('certification.verify_failed', { userId: data.userId });
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
            const user = await User.findById(userId).select('connections').lean();
            const isConnected = user?.connections?.some((conn) => conn.userId.toString() === requestingUserId) || false;
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
            const skills = description
                .toLowerCase()
                .match(/\b(javascript|python|java|sql|aws|react|node|mongodb|leadership|communication|teamwork)\b/gi) || [];
            logger.info(`Extracted ${skills.length} skills in ${Date.now() - startTime}ms`);
            return skills.slice(0, 20);
        } catch (error) {
            logger.error(`Failed to extract skills:`, error);
            return [];
        }
    }

    /**
     * Calculate trending score
     * @param {Object} certification - Certification document
     * @returns {number} - Trending score
     */
    calculateTrendingScore(certification) {
        const viewsWeight = 0.4;
        const sharesWeight = 0.3;
        const endorsementsWeight = 0.2;
        const recencyWeight = 0.1;

        const daysSinceCreated = (Date.now() - new Date(certification.createdAt)) / (1000 * 60 * 60 * 24);
        const recencyScore = Math.max(0, 10 - daysSinceCreated);

        return (
            ((certification.analytics?.views || 0) * viewsWeight) +
            ((certification.analytics?.shareCount || 0) * sharesWeight) +
            ((certification.social?.endorsements?.length || 0) * endorsementsWeight) +
            (recencyScore * recencyWeight)
        );
    }

    /**
     * Build MongoDB query
     * @param {Object} params - Query parameters
     * @returns {Object} - MongoDB query
     */
    buildMongoQuery({ userId, status, category, search, tags, templateId }) {
        const query = { userId, 'status.isDeleted': false };

        if (status && status !== 'all') {
            query['status.workflow'] = status;
        }
        if (category && category !== 'all') {
            query['badgeDetails.category'] = category;
        }
        if (templateId) {
            query.templateId = templateId;
        }
        if (tags) {
            query['badgeDetails.tags'] = { $in: tags.split(',').map((tag) => tag.trim().toLowerCase()) };
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
        if (filters.verificationStatus) {
            esFilters.push({ term: { verificationStatus: filters.verificationStatus } });
        }
        if (filters.organizationId) {
            esFilters.push({ term: { 'organization.organizationId': filters.organizationId } });
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
            recent: { 'duration.issueDate': -1 },
            oldest: { createdAt: 1 },
            title: { 'badgeDetails.title': 1 },
            popular: { 'analytics.views': -1 },
            verified: { 'verification.verificationScore': -1 },
        };
        return sortOptions[sortBy] || sortOptions.recent;
    }
}

export default new CertificationService();