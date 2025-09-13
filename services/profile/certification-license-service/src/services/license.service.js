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
import sanitizeHtml from 'sanitize-html';

// Initialize AWS S3 for backups
const s3 = new AWS.S3({
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    region: process.env.AWS_REGION,
});

class CertificationService {
    /**
     * Create a new certification with transaction support
     * @param {Object} data - Certification data
     * @param {Object} options - Additional options (e.g., session)
     * @returns {Promise<Object>} - Created certification document
     */
    async createCertification(data, options = {}) {
        const startTime = Date.now();
        const session = options.session || await mongoose.startSession();
        if (!options.session) session.startTransaction();

        try {
            // Sanitize input
            const sanitizedData = {
                ...data,
                badgeDetails: {
                    ...data.badgeDetails,
                    title: sanitizeHtml(data.badgeDetails?.title || ''),
                    description: sanitizeHtml(data.badgeDetails?.description || ''),
                    category: sanitizeHtml(data.badgeDetails?.category || ''),
                    tags: (data.badgeDetails?.tags || []).map((tag) => sanitizeHtml(tag)),
                    skills: (data.badgeDetails?.skills || []).map((skill) => sanitizeHtml(skill)),
                },
                metadata: {
                    ...data.metadata,
                    createdBy: {
                        userId: data.metadata?.createdBy?.userId || null,
                        ip: data.metadata?.createdBy?.ip || null,
                        userAgent: data.metadata?.createdBy?.userAgent || null,
                        location: data.metadata?.createdBy?.location || null,
                    },
                },
            };

            // Validate organization exists
            if (sanitizedData.organization?.organizationId) {
                const orgExists = await Organization.exists({ _id: sanitizedData.organization.organizationId }).session(session);
                if (!orgExists) {
                    throw new AppError('Invalid organization ID', 400);
                }
            }

            const certification = new Certification({
                ...sanitizedData,
                status: {
                    isActive: true,
                    isDeleted: false,
                    workflow: 'draft',
                    createdAt: new Date(),
                    updatedAt: new Date(),
                },
                metadata: {
                    ...sanitizedData.metadata,
                    qualityScore: 0,
                    lastModifiedBy: sanitizedData.metadata?.createdBy || null,
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
                cache: {
                    trendingScore: 0,
                    popularityScore: 0,
                    lastCached: new Date(),
                },
            });

            const savedCertification = await certification.save({ session });

            // Async processing
            this.processNewCertificationAsync(savedCertification._id, sanitizedData.userId)
                .catch((err) => logger.error(`Async processing failed for certification ${savedCertification._id}:`, err));

            // Create backup
            if (sanitizedData.settings?.autoBackup) {
                await this.createBackup(savedCertification._id, 'create', sanitizedData.userId, { session });
            }

            // Emit event
            eventEmitter.emit('certification.created', {
                certificationId: savedCertification._id,
                userId: sanitizedData.userId,
                category: sanitizedData.badgeDetails?.category,
                templateId: sanitizedData.templateId,
            });

            // Log metrics
            metricsCollector.increment('certification.created', {
                userId: sanitizedData.userId,
                category: sanitizedData.badgeDetails?.category,
                templateUsed: !!sanitizedData.templateId,
            });

            if (!options.session) await session.commitTransaction();
            logger.info(`Certification created: ${savedCertification._id} in ${Date.now() - startTime}ms`);
            return savedCertification;
        } catch (error) {
            if (!options.session) await session.abortTransaction();
            logger.error(`Failed to create certification for user ${data.userId}:`, error);
            metricsCollector.increment('certification.create_failed', { userId: data.userId });
            if (error.name === 'ValidationError') {
                throw new AppError('Validation failed: ' + error.message, 400);
            }
            if (error.code === 11000) {
                throw new AppError('Certification with this title already exists', 409);
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                throw new AppError('Database operation timed out', 504);
            }
            throw new AppError('Failed to create certification', 500);
        } finally {
            if (!options.session) session.endSession();
        }
    }

    /**
     * Get certification by ID with caching
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
                .lean();

            if (!certification) {
                throw new AppError('Certification not found', 404);
            }

            // Cache result
            await cacheService.set(cacheKey, certification, 600); // 10 minutes

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
     * Update certification with transaction support
     * @param {string} id - Certification ID
     * @param {string} userId - User ID
     * @param {Object} updates - Fields to update
     * @param {Object} options - Additional options
     * @returns {Promise<Object>} - Updated certification document
     */
    async updateCertification(id, userId, updates, options = {}) {
        const startTime = Date.now();
        const session = options.session || await mongoose.startSession();
        if (!options.session) session.startTransaction();

        try {
            const certification = await Certification.findOne({ _id: id, userId }).session(session);
            if (!certification) {
                throw new AppError('Certification not found', 404);
            }

            // Sanitize updates
            const sanitizedUpdates = this.sanitizeUpdates(updates);

            // Apply updates
            Object.assign(certification, sanitizedUpdates);
            certification.updatedAt = new Date();
            certification.metadata.lastModifiedBy = {
                userId: options.requestingUserId || userId,
                ip: options.ip || null,
                userAgent: options.userAgent || null,
                timestamp: new Date(),
            };

            // Trigger re-verification if critical fields changed
            if (
                sanitizedUpdates.badgeDetails ||
                sanitizedUpdates.organization ||
                sanitizedUpdates.duration
            ) {
                certification.verification.status = 'pending';
                this.verifyCertification({
                    certificationId: id,
                    userId,
                    organizationId: certification.organization?.organizationId,
                    title: certification.badgeDetails.title,
                    issueDate: certification.duration?.issueDate,
                    expirationDate: certification.duration?.expirationDate,
                }).catch((err) => logger.error(`Re-verification failed for certification ${id}:`, err));
            }

            await certification.save({ session });

            // Update search index
            await this.indexForSearch(certification);

            // Create backup
            if (certification.settings?.autoBackup) {
                await this.createBackup(id, 'update', userId, { session });
            }

            // Clear cache
            await Promise.all([
                cacheService.deletePattern(`certification:${id}:*`),
                cacheService.deletePattern(`certifications:${userId}:*`),
            ]);

            // Emit event
            eventEmitter.emit('certification.updated', {
                certificationId: id,
                userId,
                changes: Object.keys(sanitizedUpdates),
            });

            metricsCollector.increment('certification.updated', {
                userId,
                fieldsUpdated: Object.keys(sanitizedUpdates).length,
            });

            if (!options.session) await session.commitTransaction();
            logger.info(`Certification updated: ${id} in ${Date.now() - startTime}ms`);
            return certification;
        } catch (error) {
            if (!options.session) await session.abortTransaction();
            logger.error(`Failed to update certification ${id}:`, error);
            metricsCollector.increment('certification.update_failed', { userId });
            if (error.name === 'ValidationError') {
                throw new AppError('Validation failed: ' + error.message, 400);
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                throw new AppError('Database operation timed out', 504);
            }
            throw error;
        } finally {
            if (!options.session) session.endSession();
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
        const session = options.session || await mongoose.startSession();
        if (!options.session) session.startTransaction();

        try {
            const certification = await Certification.findOne({ _id: id, userId }).session(session);
            if (!certification) {
                throw new AppError('Certification not found', 404);
            }

            if (permanent) {
                await Certification.findOneAndDelete({ _id: id, userId }, { session });
                await this.deleteAllBackups(id);
                await searchClient.delete({ index: 'certifications', id });
                metricsCollector.increment('certification.permanently_deleted', { userId });
            } else {
                certification.status.isDeleted = true;
                certification.status.isActive = false;
                certification.status.deletedAt = new Date();
                await certification.save({ session });
                metricsCollector.increment('certification.soft_deleted', { userId });
            }

            // Clear cache
            await Promise.all([
                cacheService.deletePattern(`certification:${id}:*`),
                cacheService.deletePattern(`certifications:${userId}:*`),
            ]);

            // Emit event
            eventEmitter.emit('certification.deleted', { certificationId: id, userId, permanent });

            if (!options.session) await session.commitTransaction();
            logger.info(`Certification ${id} deleted (permanent: ${permanent}) in ${Date.now() - startTime}ms`);
        } catch (error) {
            if (!options.session) await session.abortTransaction();
            logger.error(`Failed to delete certification ${id}:`, error);
            metricsCollector.increment('certification.delete_failed', { userId });
            throw error;
        } finally {
            if (!options.session) session.endSession();
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
        const { userId, page = 1, limit = 20, status, category, search, tags, templateId, startDate, endDate, sortBy = 'recent' } = query;
        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
        const skip = (pageNum - 1) * limitNum;

        const cacheKey = `certifications:${userId}:${JSON.stringify({
            page: pageNum,
            limit: limitNum,
            status,
            category,
            search,
            tags,
            templateId,
            startDate,
            endDate,
            sortBy,
        })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('certifications.cache_hit', { userId });
                return cached;
            }

            const mongoQuery = this.buildMongoQuery({ userId, status, category, search, tags, templateId, startDate, endDate });
            const sortOption = this.buildSortOption(sortBy);

            const [certifications, totalCount] = await Promise.all([
                Certification.find(mongoQuery)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select('badgeDetails organization duration status templateId createdAt updatedAt analytics')
                    .populate('organization.organizationId', 'name logo industry verification.isVerified')
                    .lean(),
                Certification.countDocuments(mongoQuery).cache({ ttl: 300, key: `certification_count_${userId}` }),
            ]);

            const processedCertifications = certifications.map((cert) => ({
                ...cert,
                isExpired: cert.duration?.expirationDate ? new Date(cert.duration.expirationDate) < new Date() : false,
            }));

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                certifications: processedCertifications,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages,
                    hasNext: pageNum < totalPages,
                    hasPrev: pageNum > 1,
                    nextPage: pageNum < totalPages ? pageNum + 1 : null,
                    prevPage: pageNum > 1 ? pageNum - 1 : null,
                },
                filters: {
                    status: status || 'all',
                    category: category || 'all',
                    search: search || null,
                    sortBy,
                },
            };

            await cacheService.set(cacheKey, result, 300); // 5 minutes
            metricsCollector.increment('certifications.fetched', { userId, count: certifications.length });
            logger.info(`Fetched ${certifications.length} certifications for user ${userId} in ${Date.now() - startTime}ms`);
            return result;
        } catch (error) {
            logger.error(`Failed to fetch certifications for user ${userId}:`, error);
            metricsCollector.increment('certifications.fetch_failed', { userId });
            if (error.name === 'CastError') {
                throw new AppError('Invalid query parameters', 400);
            }
            throw new AppError('Failed to fetch certifications', 500);
        }
    }

    /**
     * Search certifications using Elasticsearch with MongoDB fallback
     * @param {string} query - Search query
     * @param {Object} filters - Additional filters
     * @param {Object} options - Pagination options
     * @returns {Promise<Object>} - Search results
     */
    async searchCertifications(query, filters = {}, options = {}) {
        const startTime = Date.now();
        const { page = 1, limit = 20 } = options;
        const from = (page - 1) * limit;

        const cacheKey = `search:certifications:${query}:${JSON.stringify(filters)}:${page}:${limit}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('certification.search_cache_hit');
                return cached;
            }

            let result;
            if (process.env.ALGOLIA_APP_ID && process.env.ALGOLIA_ADMIN_KEY) {
                // Algolia integration (for consistency with LicenseService)
                const searchParams = {
                    query,
                    filters: Object.entries(filters)
                        .map(([key, value]) => `${key}:${value}`)
                        .join(' AND '),
                    page: page - 1,
                    hitsPerPage: limit,
                };
                result = await searchClient.searchSingleIndex('certifications', searchParams);
            } else {
                // Fallback to Elasticsearch
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
                result = await searchClient.search(esQuery);
            }

            const hits = result.hits.hits ? result.hits.hits.map((hit) => hit._source) : result.hits;
            const total = result.hits.total?.value || result.nbHits;

            const processedResult = {
                hits,
                total,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    totalPages: Math.ceil(total / limit),
                },
            };

            await cacheService.set(cacheKey, processedResult, 300); // 5 minutes
            metricsCollector.increment('certification.searched', { query, count: hits.length });
            logger.info(`Search returned ${hits.length} certifications in ${Date.now() - startTime}ms`);
            return processedResult;
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
                createdAt: { $gte: timeframeDate },
            };
            if (category && category !== 'all') {
                query['badgeDetails.category'] = category;
            }

            const certifications = await Certification.find(query)
                .read('secondaryPreferred')
                .select('badgeDetails organization duration verification analytics createdAt cache')
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
     * Create backup of certification to S3
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

            const backupKey = `certification_backup_${certificationId}_${Date.now()}_${uuidv4()}`;
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

            metricsCollector.increment('certification.backup_created', { userId, action });
            logger.info(`Backup created for certification ${certificationId} (${action}) in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to create backup for certification ${certificationId}:`, error);
            metricsCollector.increment('certification.backup_failed', { userId });
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

            metricsCollector.increment('certification.backups_deleted', { certificationId });
            logger.info(`Deleted all backups for certification ${certificationId} in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to delete backups for certification ${certificationId}:`, error);
            metricsCollector.increment('certification.backups_delete_failed', { certificationId });
            throw error;
        }
    }

    /**
     * Index certification for search (Elasticsearch or Algolia)
     * @param {Object} certification - Certification document
     * @returns {Promise<void>}
     */
    async indexForSearch(certification) {
        const startTime = Date.now();
        try {
            if (process.env.ALGOLIA_APP_ID && process.env.ALGOLIA_ADMIN_KEY) {
                await searchClient.saveObject({
                    indexName: 'certifications',
                    objectID: certification._id.toString(),
                    userId: certification.userId.toString(),
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
                });
            } else {
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
            }
            logger.info(`Indexed certification ${certification._id} for search in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to index certification ${certification._id}:`, error);
            metricsCollector.increment('certification.index_failed', { certificationId: certification._id });
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
        const session = options.session || null;

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
                { session }
            );

            await cacheService.deletePattern(`user:${userId}:*`);
            eventEmitter.emit('user.stats_updated', { userId, stats: stats[0] || {} });
            metricsCollector.increment('certification.user_stats_updated', { userId });
            logger.info(`Updated stats for user ${userId} in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to update stats for user ${userId}:`, error);
            metricsCollector.increment('certification.user_stats_failed', { userId });
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
            if (error.message.includes('timeout')) {
                throw new AppError('External API timeout', 503);
            }
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
            metricsCollector.increment('certification.connection_checked', { userId, requestingUserId });
            logger.info(`Checked connection for ${userId} and ${requestingUserId} in ${Date.now() - startTime}ms`);
            return isConnected;
        } catch (error) {
            logger.error(`Failed to check connection for ${userId}:`, error);
            metricsCollector.increment('certification.connection_check_failed', { userId });
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
            const sanitizedDescription = sanitizeHtml(description);
            const skills = sanitizedDescription
                .toLowerCase()
                .match(/\b(javascript|python|java|sql|aws|react|node|mongodb|leadership|communication|teamwork)\b/gi) || [];
            metricsCollector.increment('certification.skills_extracted', { count: skills.length });
            logger.info(`Extracted ${skills.length} skills in ${Date.now() - startTime}ms`);
            return skills.slice(0, 20);
        } catch (error) {
            logger.error(`Failed to extract skills:`, error);
            metricsCollector.increment('certification.skills_extract_failed');
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

        const score = (
            ((certification.analytics?.views || 0) * viewsWeight) +
            ((certification.analytics?.shareCount || 0) * sharesWeight) +
            ((certification.social?.endorsements?.length || 0) * endorsementsWeight) +
            (recencyScore * recencyWeight)
        );

        // Update cache
        certification.cache = certification.cache || {};
        certification.cache.trendingScore = score;
        certification.cache.lastCached = new Date();
        return score;
    }

    /**
     * Validate media upload
     * @param {Array} files - Uploaded files
     * @param {Array} existingMedia - Existing media documents
     * @returns {Object} - Validation result
     */
    validateMediaUpload(files, existingMedia) {
        const limits = {
            maxMedia: 10,
            maxSizeMB: 100,
        };
        const totalSize = files.reduce((sum, file) => sum + file.size, 0);
        const totalMedia = existingMedia.length + files.length;

        if (totalMedia > limits.maxMedia) {
            return { valid: false, message: `Maximum ${limits.maxMedia} media files allowed` };
        }
        if (totalSize > limits.maxSizeMB * 1024 * 1024) {
            return { valid: false, message: `Total media size exceeds ${limits.maxSizeMB}MB` };
        }

        return { valid: true };
    }

    /**
     * Process new certification asynchronously
     * @param {string} certificationId - Certification ID
     * @param {string} userId - User ID
     * @returns {Promise<void>}
     */
    async processNewCertificationAsync(certificationId, userId) {
        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const certification = await Certification.findById(certificationId).session(session);
            if (!certification) {
                throw new AppError('Certification not found', 404);
            }

            // Calculate quality score
            await certification.calculateQualityScore({ session });

            // Auto-verify
            await this.verifyCertification({
                certificationId,
                userId,
                organizationId: certification.organization?.organizationId,
                title: certification.badgeDetails.title,
                issueDate: certification.duration?.issueDate,
                expirationDate: certification.duration?.expirationDate,
            });

            // Index for search
            await this.indexForSearch(certification);

            // Update user stats
            await this.updateUserStats(userId, { session });

            await certification.save({ session });
            await session.commitTransaction();
            logger.info(`Async processing completed for certification ${certificationId}`);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Async processing failed for certification ${certificationId}:`, error);
            metricsCollector.increment('certification.async_processing_failed', { certificationId });
        } finally {
            session.endSession();
        }
    }

    /**
     * Sanitize updates
     * @param {Object} updates - Update data
     * @returns {Object} - Sanitized updates
     */
    sanitizeUpdates(updates) {
        const allowedFields = [
            'badgeDetails.title',
            'badgeDetails.description',
            'badgeDetails.category',
            'badgeDetails.tags',
            'badgeDetails.skills',
            'organization.organizationId',
            'duration.issueDate',
            'duration.expirationDate',
            'status.isActive',
            'status.workflow',
            'templateId',
        ];

        const sanitized = {};
        allowedFields.forEach((field) => {
            if (updates[field] !== undefined) {
                if (field === 'badgeDetails.description' || field === 'badgeDetails.title') {
                    sanitized[field] = sanitizeHtml(updates[field]);
                } else if (field === 'badgeDetails.tags' || field === 'badgeDetails.skills') {
                    sanitized[field] = updates[field].map((item) => sanitizeHtml(item));
                } else {
                    sanitized[field] = updates[field];
                }
            }
        });
        return sanitized;
    }

    /**
     * Build MongoDB query
     * @param {Object} params - Query parameters
     * @returns {Object} - MongoDB query
     */
    buildMongoQuery({ userId, status, category, search, tags, templateId, startDate, endDate }) {
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
        if (startDate || endDate) {
            query['duration.issueDate'] = {};
            if (startDate) query['duration.issueDate'].$gte = new Date(startDate);
            if (endDate) query['duration.issueDate'].$lte = new Date(endDate);
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
            popular: { 'cache.popularityScore': -1 },
            verified: { 'verification.verificationScore': -1 },
        };
        return sortOptions[sortBy] || sortOptions.recent;
    }
}

export default new CertificationService();