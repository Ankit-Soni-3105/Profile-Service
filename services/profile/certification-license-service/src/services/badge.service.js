import Badge from '../models/Badge.js';
import User from '../models/User.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { cacheService } from '../services/cache.service.js';
import { metricsCollector } from '../utils/metrics.js';
import { eventEmitter } from '../events/events.js';
import mongoose from 'mongoose';
import AWS from 'aws-sdk';
import { v4 as uuidv4 } from 'uuid';
import { searchClient } from '../config/search.config.js';
import sanitizeHtml from 'sanitize-html';

// Initialize AWS S3 for backups and media
const s3 = new AWS.S3({
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    region: process.env.AWS_REGION,
});

// Search engine configuration
const SEARCH_ENGINE = process.env.SEARCH_ENGINE || 'elasticsearch';
const INDEX_NAME = 'badges';

// Validation schemas (assumed to be defined in badge.validation.js)
import { validateBadge, validateMediaUpload, validateIssueBadge } from '../validations/badge.validation.js';

class BadgeService {
    /**
     * Create a new badge
     * @param {Object} badgeData - Badge data
     * @param {Object} options - Options including session
     * @returns {Promise<Object>} - Created badge
     */
    async createBadge(badgeData, options = {}) {
        const startTime = Date.now();
        try {
            const sanitizedData = this.sanitizeData(badgeData);
            const badge = new Badge({
                ...sanitizedData,
                status: {
                    workflow: 'pending',
                    isActive: true,
                    isDeleted: false,
                    isArchived: false,
                },
                analytics: { views: 0, shares: 0, endorsements: 0 },
                verification: { status: 'pending', verificationScore: 0 },
                recipients: [],
                media: [],
            });

            await badge.save(options);
            metricsCollector.increment('badge_service.created');
            logger.info(`Badge created: ${badge._id} in ${Date.now() - startTime}ms`);

            return badge;
        } catch (error) {
            logger.error(`Failed to create badge:`, error);
            metricsCollector.increment('badge_service.create_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Get badge by ID
     * @param {string} id - Badge ID
     * @param {string} userId - Requesting user ID
     * @returns {Promise<Object>} - Badge document
     */
    async getBadgeById(id, userId) {
        const startTime = Date.now();
        try {
            const cacheKey = `badge:${id}:${userId}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('badge_service.cache_hit');
                return cached;
            }

            const badge = await Badge.findOne({
                _id: id,
                'status.isDeleted': false,
            })
                .read('secondaryPreferred')
                .select('name image type verification status analytics metadata recipients media')
                .lean();

            if (!badge) {
                throw new AppError('Badge not found', 404);
            }

            await cacheService.set(cacheKey, badge, 600);
            metricsCollector.increment('badge_service.fetched');
            logger.info(`Fetched badge ${id} in ${Date.now() - startTime}ms`);

            return badge;
        } catch (error) {
            logger.error(`Failed to fetch badge ${id}:`, error);
            metricsCollector.increment('badge_service.fetch_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Update badge
     * @param {string} id - Badge ID
     * @param {string} userId - Requesting user ID
     * @param {Object} updates - Update data
     * @param {Object} options - Options including session and metadata
     * @returns {Promise<Object>} - Updated badge
     */
    async updateBadge(id, userId, updates, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;
        try {
            const badge = await Badge.findOne({
                _id: id,
                'status.isDeleted': false,
            }).session(session);

            if (!badge) {
                throw new AppError('Badge not found', 404);
            }

            if (!this.hasPermission(userId, badge, 'update')) {
                throw new AppError('Access denied', 403);
            }

            Object.assign(badge, this.sanitizeData(updates));
            badge.metadata.lastModifiedBy = {
                userId: options.requestingUserId || userId,
                ip: options.ip,
                userAgent: options.userAgent,
                timestamp: new Date(),
            };

            await badge.save({ session });
            metricsCollector.increment('badge_service.updated');
            logger.info(`Badge updated: ${id} in ${Date.now() - startTime}ms`);

            return badge;
        } catch (error) {
            logger.error(`Failed to update badge ${id}:`, error);
            metricsCollector.increment('badge_service.update_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Delete badge
     * @param {string} id - Badge ID
     * @param {string} userId - Requesting user ID
     * @param {boolean} permanent - Permanent deletion flag
     * @param {Object} options - Options including session
     */
    async deleteBadge(id, userId, permanent = false, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;
        try {
            const badge = await Badge.findOne({
                _id: id,
                'status.isDeleted': false,
            }).session(session);

            if (!badge) {
                throw new AppError('Badge not found', 404);
            }

            if (!this.hasPermission(userId, badge, 'delete')) {
                throw new AppError('Access denied', 403);
            }

            if (permanent) {
                await badge.deleteOne({ session });
            } else {
                badge.status.isDeleted = true;
                badge.status.deletedAt = new Date();
                await badge.save({ session });
            }

            metricsCollector.increment(permanent ? 'badge_service.permanently_deleted' : 'badge_service.soft_deleted');
            logger.info(`Badge ${id} deleted (permanent: ${permanent}) in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to delete badge ${id}:`, error);
            metricsCollector.increment('badge_service.delete_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Issue badge to a user
     * @param {string} badgeId - Badge ID
     * @param {string} recipientId - Recipient user ID
     * @param {string} userId - Requesting user ID
     * @param {Object} options - Options including session
     * @returns {Promise<Object>} - Updated badge
     */
    async issueBadge(badgeId, recipientId, userId, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;
        try {
            const badge = await Badge.findOne({
                _id: badgeId,
                'status.isDeleted': false,
            }).session(session);

            if (!badge) {
                throw new AppError('Badge not found', 404);
            }

            if (!this.hasPermission(userId, badge, 'issue')) {
                throw new AppError('Access denied', 403);
            }

            const recipient = await User.findById(recipientId).session(session);
            if (!recipient) {
                throw new AppError('Recipient not found', 404);
            }

            const validation = validateIssueBadge({ recipientId });
            if (!validation.valid) {
                throw new AppError(validation.message, 400);
            }

            badge.recipients = badge.recipients || [];
            if (badge.recipients.some((r) => r.userId.toString() === recipientId)) {
                throw new AppError('Badge already issued to this user', 409);
            }

            badge.recipients.push({
                userId: recipientId,
                issuedAt: new Date(),
                issuedBy: userId,
                status: 'active',
            });

            badge.analytics = badge.analytics || { views: 0, shares: 0, endorsements: 0 };
            badge.analytics.endorsements += 1;

            await badge.save({ session });
            metricsCollector.increment('badge_service.issued');
            logger.info(`Badge ${badgeId} issued to ${recipientId} in ${Date.now() - startTime}ms`);

            return badge;
        } catch (error) {
            logger.error(`Failed to issue badge ${badgeId} to ${recipientId}:`, error);
            metricsCollector.increment('badge_service.issue_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Revoke badge from a user
     * @param {string} badgeId - Badge ID
     * @param {string} recipientId - Recipient user ID
     * @param {string} userId - Requesting user ID
     * @param {Object} options - Options including session
     */
    async revokeBadge(badgeId, recipientId, userId, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;
        try {
            const badge = await Badge.findOne({
                _id: badgeId,
                'status.isDeleted': false,
            }).session(session);

            if (!badge) {
                throw new AppError('Badge not found', 404);
            }

            if (!this.hasPermission(userId, badge, 'revoke')) {
                throw new AppError('Access denied', 403);
            }

            badge.recipients = badge.recipients || [];
            const recipientIndex = badge.recipients.findIndex((r) => r.userId.toString() === recipientId);
            if (recipientIndex === -1) {
                throw new AppError('Badge not issued to this user', 404);
            }

            badge.recipients[recipientIndex].status = 'revoked';
            badge.recipients[recipientIndex].revokedAt = new Date();
            badge.recipients[recipientIndex].revokedBy = userId;

            badge.analytics = badge.analytics || { views: 0, shares: 0, endorsements: 0 };
            badge.analytics.endorsements = Math.max(0, badge.analytics.endorsements - 1);

            await badge.save({ session });
            metricsCollector.increment('badge_service.revoked');
            logger.info(`Badge ${badgeId} revoked from ${recipientId} in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to revoke badge ${badgeId} from ${recipientId}:`, error);
            metricsCollector.increment('badge_service.revoke_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Search badges
     * @param {string} query - Search query
     * @param {Object} filters - Additional filters
     * @param {Object} options - Pagination options
     * @returns {Promise<Object>} - Search results
     */
    async searchBadges(query, filters = {}, options = { page: 1, limit: 20 }) {
        const startTime = Date.now();
        try {
            const searchQuery = this.buildSearchQuery(query, filters);
            let results;

            if (SEARCH_ENGINE === 'algolia') {
                results = await searchClient.search({
                    indexName: INDEX_NAME,
                    query,
                    filters: this.formatAlgoliaFilters(filters),
                    page: options.page - 1,
                    hitsPerPage: options.limit,
                });
            } else {
                results = await searchClient.search({
                    index: INDEX_NAME,
                    body: {
                        query: searchQuery,
                        from: (options.page - 1) * options.limit,
                        size: options.limit,
                    },
                });
            }

            const hits = SEARCH_ENGINE === 'algolia' ? results.hits : results.hits.hits.map((hit) => hit._source);
            const totalHits = SEARCH_ENGINE === 'algolia' ? results.nbHits : results.hits.total.value;

            metricsCollector.increment('badge_service.searched', { count: hits.length });
            logger.info(`Search returned ${hits.length} badges in ${Date.now() - startTime}ms`);

            return {
                hits,
                totalHits,
                page: options.page,
                limit: options.limit,
                totalPages: Math.ceil(totalHits / options.limit),
            };
        } catch (error) {
            logger.error(`Search failed for query ${query}:`, error);
            metricsCollector.increment('badge_service.search_failed');
            throw new AppError('Failed to search badges', 500);
        }
    }

    /**
     * Get trending badges
     * @param {string} timeframe - Timeframe (e.g., '30d')
     * @param {string} type - Badge type filter
     * @param {number} limit - Number of results
     * @returns {Promise<Array>} - Trending badges
     */
    async getTrendingBadges(timeframe, type, limit) {
        const startTime = Date.now();
        try {
            const cacheKey = `trending_badges:${timeframe}:${type || 'all'}:${limit}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('badge_service.trending_cache_hit');
                return cached;
            }

            const query = {
                'status.isDeleted': false,
                'analytics.views': { $gt: 0 },
            };
            if (type) query.type = type;

            const badges = await Badge.find(query)
                .read('secondaryPreferred')
                .sort({ 'analytics.views': -1 })
                .limit(limit)
                .select('name image type verification status analytics')
                .lean();

            await cacheService.set(cacheKey, badges, 300);
            metricsCollector.increment('badge_service.trending_fetched', { count: badges.length });
            logger.info(`Fetched ${badges.length} trending badges in ${Date.now() - startTime}ms`);

            return badges;
        } catch (error) {
            logger.error(`Failed to fetch trending badges:`, error);
            metricsCollector.increment('badge_service.trending_fetch_failed');
            throw new AppError('Failed to fetch trending badges', 500);
        }
    }

    /**
     * Validate media upload
     * @param {Array} files - Uploaded files
     * @param {Array} existingMedia - Existing media
     * @returns {Object} - Validation result
     */
    validateMediaUpload(files, existingMedia) {
        const startTime = Date.now();
        try {
            const validation = validateMediaUpload(files, existingMedia);
            logger.info(`Media validation completed in ${Date.now() - startTime}ms`);
            return validation;
        } catch (error) {
            logger.error(`Media validation failed:`, error);
            metricsCollector.increment('badge_service.media_validation_failed');
            throw new AppError('Media validation failed', 422);
        }
    }

    /**
     * Index badge for search
     * @param {Object} badge - Badge document
     */
    async indexForSearch(badge) {
        const startTime = Date.now();
        try {
            const indexData = {
                objectID: badge._id.toString(),
                name: badge.name,
                type: badge.type,
                description: badge.description,
                status: badge.status.workflow,
                createdAt: badge.createdAt,
            };

            if (SEARCH_ENGINE === 'algolia') {
                await searchClient.saveObject({
                    indexName: INDEX_NAME,
                    body: indexData,
                });
            } else {
                await searchClient.index({
                    index: INDEX_NAME,
                    id: badge._id.toString(),
                    body: indexData,
                });
            }

            metricsCollector.increment('badge_service.indexed');
            logger.info(`Indexed badge ${badge._id} for search in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to index badge ${badge._id}:`, error);
            metricsCollector.increment('badge_service.index_failed');
            throw new AppError('Failed to index badge', 500);
        }
    }

    /**
     * Get badge analytics
     * @param {string} id - Badge ID
     * @param {string} timeframe - Timeframe (e.g., '30d')
     * @returns {Promise<Object>} - Analytics data
     */
    async getBadgeAnalytics(id, timeframe) {
        const startTime = Date.now();
        try {
            const cacheKey = `badge_analytics:${id}:${timeframe}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('badge_service.analytics_cache_hit');
                return cached;
            }

            const badge = await Badge.findById(id)
                .select('analytics metadata recipients')
                .lean();

            if (!badge) {
                throw new AppError('Badge not found', 404);
            }

            const analytics = {
                views: badge.analytics.views || 0,
                shares: badge.analytics.shares || 0,
                endorsements: badge.analytics.endorsements || 0,
                recipients: badge.recipients?.length || 0,
                timeframe,
                lastUpdated: badge.metadata.lastModifiedBy?.timestamp || badge.createdAt,
            };

            await cacheService.set(cacheKey, analytics, 300);
            metricsCollector.increment('badge_service.analytics_fetched');
            logger.info(`Fetched analytics for badge ${id} in ${Date.now() - startTime}ms`);

            return analytics;
        } catch (error) {
            logger.error(`Failed to fetch analytics for badge ${id}:`, error);
            metricsCollector.increment('badge_service.analytics_fetch_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Get badge statistics
     * @param {string} id - Badge ID
     * @returns {Promise<Object>} - Statistics
     */
    async getBadgeStats(id) {
        const startTime = Date.now();
        try {
            const cacheKey = `badge_stats:${id}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('badge_service.stats_cache_hit');
                return cached;
            }

            const badge = await Badge.findById(id)
                .select('analytics recipients status createdAt')
                .lean();

            if (!badge) {
                throw new AppError('Badge not found', 404);
            }

            const stats = {
                totalViews: badge.analytics.views || 0,
                totalShares: badge.analytics.shares || 0,
                totalEndorsements: badge.analytics.endorsements || 0,
                recipientCount: badge.recipients?.length || 0,
                status: badge.status.workflow,
                ageInDays: Math.floor((Date.now() - new Date(badge.createdAt)) / (1000 * 60 * 60 * 24)),
            };

            await cacheService.set(cacheKey, stats, 3600);
            metricsCollector.increment('badge_service.stats_fetched');
            logger.info(`Fetched stats for badge ${id} in ${Date.now() - startTime}ms`);

            return stats;
        } catch (error) {
            logger.error(`Failed to fetch stats for badge ${id}:`, error);
            metricsCollector.increment('badge_service.stats_fetch_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Get audit logs
     * @param {string} badgeId - Badge ID
     * @param {Object} options - Options including page, limit, action
     * @returns {Promise<Array>} - Audit logs
     */
    async getAuditLogs(badgeId, options = { page: 1, limit: 20, action: null }) {
        const startTime = Date.now();
        try {
            const page = Math.max(1, options.page);
            const limit = Math.min(100, Math.max(1, options.limit));
            const skip = (page - 1) * limit;

            const query = { badgeId };
            if (options.action) query.action = options.action;

            const logs = await BadgeAuditLog.find(query) // Assumed model for audit logs
                .skip(skip)
                .limit(limit)
                .lean();

            metricsCollector.increment('badge_service.audit_fetched', { count: logs.length });
            logger.info(`Fetched ${logs.length} audit logs for badge ${badgeId} in ${Date.now() - startTime}ms`);

            return logs;
        } catch (error) {
            logger.error(`Failed to fetch audit logs for badge ${badgeId}:`, error);
            metricsCollector.increment('badge_service.audit_fetch_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Count audit logs
     * @param {string} badgeId - Badge ID
     * @param {string} action - Action filter
     * @returns {Promise<number>} - Total count
     */
    async countAuditLogs(badgeId, action) {
        const startTime = Date.now();
        try {
            const query = { badgeId };
            if (action) query.action = action;

            const count = await BadgeAuditLog.countDocuments(query);
            logger.info(`Counted ${count} audit logs for badge ${badgeId} in ${Date.now() - startTime}ms`);

            return count;
        } catch (error) {
            logger.error(`Failed to count audit logs for badge ${badgeId}:`, error);
            throw this.handleError(error);
        }
    }

    /**
     * Update user stats
     * @param {string} userId - User ID
     * @param {Object} options - Options including session
     */
    async updateUserStats(userId, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;
        try {
            const user = await User.findById(userId).session(session);
            if (!user) {
                throw new AppError('User not found', 404);
            }

            user.stats = user.stats || {};
            user.stats.badges = await Badge.countDocuments({
                'recipients.userId': userId,
                'status.isDeleted': false,
            });

            await user.save({ session });
            logger.info(`Updated stats for user ${userId} in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to update stats for user ${userId}:`, error);
            metricsCollector.increment('badge_service.user_stats_update_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Update badge analytics
     * @param {string} badgeId - Badge ID
     * @param {Object} options - Options including session
     */
    async updateBadgeAnalytics(badgeId, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;
        try {
            const badge = await Badge.findById(badgeId).session(session);
            if (!badge) {
                throw new AppError('Badge not found', 404);
            }

            badge.analytics = badge.analytics || { views: 0, shares: 0, endorsements: 0 };
            badge.analytics.views += 1; // Example increment
            await badge.save({ session });

            logger.info(`Updated analytics for badge ${badgeId} in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to update analytics for badge ${badgeId}:`, error);
            metricsCollector.increment('badge_service.analytics_update_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Process new badge asynchronously
     * @param {string} badgeId - Badge ID
     * @param {string} userId - User ID
     * @param {string} action - Action type
     */
    async processNewBadgeAsync(badgeId, userId, action) {
        const startTime = Date.now();
        try {
            const badge = await Badge.findById(badgeId).lean();
            if (!badge) {
                throw new AppError('Badge not found', 404);
            }

            // Index for search
            await this.indexForSearch(badge);

            // Update user stats
            await this.updateUserStats(userId);

            // Create backup
            await this.createBackup(badgeId, action, userId);

            metricsCollector.increment('badge_service.async_processed');
            logger.info(`Async processing completed for badge ${badgeId} in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Async processing failed for badge ${badgeId}:`, error);
            metricsCollector.increment('badge_service.async_process_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Create backup
     * @param {string} badgeId - Badge ID
     * @param {string} action - Action type
     * @param {string} userId - User ID
     */
    async createBackup(badgeId, action, userId) {
        const startTime = Date.now();
        try {
            const badge = await Badge.findById(badgeId).lean();
            if (!badge) {
                throw new AppError('Badge not found', 404);
            }

            const backupKey = `badge_backup_${badgeId}_${Date.now()}_${uuidv4()}`;
            await s3.upload({
                Bucket: process.env.S3_BACKUP_BUCKET,
                Key: backupKey,
                Body: JSON.stringify({
                    badge,
                    action,
                    userId,
                    timestamp: new Date(),
                }),
                ContentType: 'application/json',
                ServerSideEncryption: 'AES256',
            }).promise();

            metricsCollector.increment('badge_service.backup_created', { action });
            logger.info(`Backup created for badge ${badgeId} (${action}) in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to create backup for badge ${badgeId}:`, error);
            metricsCollector.increment('badge_service.backup_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Sanitize data
     * @param {Object} data - Input data
     * @returns {Object} - Sanitized data
     */
    sanitizeData(data) {
        return {
            ...data,
            name: sanitizeHtml(data.name || ''),
            description: sanitizeHtml(data.description || ''),
            type: sanitizeHtml(data.type || ''),
            image: data.image ? sanitizeHtml(data.image) : undefined,
        };
    }

    /**
     * Build search query
     * @param {string} query - Search query
     * @param {Object} filters - Filters
     * @returns {Object} - Search query
     */
    buildSearchQuery(query, filters) {
        if (SEARCH_ENGINE === 'algolia') {
            return query;
        }

        return {
            bool: {
                must: query ? { match: { name: query } } : { match_all: {} },
                filter: Object.entries(filters).map(([key, value]) => ({ term: { [key]: value } })),
            },
        };
    }

    /**
     * Format Algolia filters
     * @param {Object} filters - Filters
     * @returns {string} - Algolia filter string
     */
    formatAlgoliaFilters(filters) {
        return Object.entries(filters)
            .map(([key, value]) => `${key}:${value}`)
            .join(' AND ');
    }

    /**
     * Check permissions
     * @param {string} userId - User ID
     * @param {Object} badge - Badge document
     * @param {string} action - Action type
     * @returns {boolean} - Permission granted
     */
    hasPermission(userId, badge, action) {
        const creatorId = badge.metadata?.createdBy?.userId?.toString();
        const permissions = {
            update: creatorId === userId || badge.recipients?.some((r) => r.userId.toString() === userId && r.roles?.includes('admin')),
            delete: creatorId === userId,
            issue: creatorId === userId || badge.recipients?.some((r) => r.userId.toString() === userId && r.roles?.includes('issuer')),
            revoke: creatorId === userId || badge.recipients?.some((r) => r.userId.toString() === userId && r.roles?.includes('admin')),
        };

        return permissions[action] || false;
    }

    /**
     * Handle errors
     * @param {Error} error - Error object
     * @returns {AppError}
     */
    handleError(error) {
        if (error.name === 'ValidationError') {
            return new AppError('Validation failed: ' + error.message, 400);
        }
        if (error.code === 11000) {
            return new AppError('Badge already exists', 409);
        }
        if (error.name === 'CastError') {
            return new AppError('Invalid badge ID', 400);
        }
        if (error.message.includes('timeout')) {
            return new AppError('Operation timed out', 504);
        }
        return new AppError('Operation failed', 500);
    }
}

export default new BadgeService();