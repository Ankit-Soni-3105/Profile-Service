import Expiration from '../models/Expiration.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { cacheService } from '../services/cache.service.js';
import { metricsCollector } from '../utils/metrics.js';
import { eventEmitter } from '../events/events.js';
import { queueService } from '../services/queue.service.js';
import mongoose from 'mongoose';
import AWS from 'aws-sdk';
import { v4 as uuidv4 } from 'uuid';
import { searchClient } from '../config/search.config.js';
import sanitizeHtml from 'sanitize-html';

// Initialize AWS S3 for backups
const s3 = new AWS.S3({
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    region: process.env.AWS_REGION,
});

// Search engine configuration
const SEARCH_ENGINE = process.env.SEARCH_ENGINE || 'elasticsearch';
const INDEX_NAME = 'expirations';

// Validation schemas (assumed to be defined in expiration.validation.js)
import { validateExpiration, validateMediaUpload } from '../validations/expiration.validation.js';

class ExpirationService {
    /**
     * Create a new expiration record
     * @param {Object} expirationData - Expiration data
     * @param {Object} options - Options including session
     * @returns {Promise<Object>} - Created expiration record
     */
    async createExpiration(expirationData, options = {}) {
        const startTime = Date.now();
        try {
            const sanitizedData = this.sanitizeData(expirationData);
            const expiration = new Expiration({
                ...sanitizedData,
                status: {
                    workflow: 'active',
                    isActive: true,
                    isDeleted: false,
                    isArchived: false,
                },
                analytics: { views: 0, associatedItems: 0 },
                media: [],
            });

            await expiration.save(options);
            metricsCollector.increment('expiration_service.created');
            logger.info(`Expiration created: ${expiration._id} in ${Date.now() - startTime}ms`);

            return expiration;
        } catch (error) {
            logger.error(`Failed to create expiration:`, error);
            metricsCollector.increment('expiration_service.create_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Get expiration record by ID
     * @param {string} id - Expiration ID
     * @param {string} userId - Requesting user ID
     * @returns {Promise<Object>} - Expiration document
     */
    async getExpirationById(id, userId) {
        const startTime = Date.now();
        try {
            const cacheKey = `expiration:${id}:${userId}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('expiration_service.cache_hit');
                return cached;
            }

            const expiration = await Expiration.findOne({
                _id: id,
                'status.isDeleted': false,
            })
                .read('secondaryPreferred')
                .select('entityType entityId expirationDate description status analytics metadata media')
                .lean();

            if (!expiration) {
                throw new AppError('Expiration record not found', 404);
            }

            await cacheService.set(cacheKey, expiration, 300); // Short TTL for high-traffic
            metricsCollector.increment('expiration_service.fetched');
            logger.info(`Fetched expiration ${id} in ${Date.now() - startTime}ms`);

            return expiration;
        } catch (error) {
            logger.error(`Failed to fetch expiration ${id}:`, error);
            metricsCollector.increment('expiration_service.fetch_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Update expiration record
     * @param {string} id - Expiration ID
     * @param {string} userId - Requesting user ID
     * @param {Object} updates - Update data
     * @param {Object} options - Options including session and metadata
     * @returns {Promise<Object>} - Updated expiration record
     */
    async updateExpiration(id, userId, updates, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;
        try {
            const expiration = await Expiration.findOne({
                _id: id,
                'status.isDeleted': false,
            }).session(session);

            if (!expiration) {
                throw new AppError('Expiration record not found', 404);
            }

            if (!this.hasPermission(userId, expiration, 'update')) {
                throw new AppError('Access denied', 403);
            }

            Object.assign(expiration, this.sanitizeData(updates));
            expiration.metadata.lastModifiedBy = {
                userId: options.requestingUserId || userId,
                ip: options.ip,
                userAgent: options.userAgent,
                timestamp: new Date(),
            };

            await expiration.save({ session });
            metricsCollector.increment('expiration_service.updated');
            logger.info(`Expiration updated: ${id} in ${Date.now() - startTime}ms`);

            return expiration;
        } catch (error) {
            logger.error(`Failed to update expiration ${id}:`, error);
            metricsCollector.increment('expiration_service.update_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Delete expiration record
     * @param {string} id - Expiration ID
     * @param {string} userId - Requesting user ID
     * @param {boolean} permanent - Permanent deletion flag
     * @param {Object} options - Options including session
     */
    async deleteExpiration(id, userId, permanent = false, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;
        try {
            const expiration = await Expiration.findOne({
                _id: id,
                'status.isDeleted': false,
            }).session(session);

            if (!expiration) {
                throw new AppError('Expiration record not found', 404);
            }

            if (!this.hasPermission(userId, expiration, 'delete')) {
                throw new AppError('Access denied', 403);
            }

            if (permanent) {
                await expiration.deleteOne({ session });
            } else {
                expiration.status.isDeleted = true;
                expiration.status.deletedAt = new Date();
                await expiration.save({ session });
            }

            metricsCollector.increment(permanent ? 'expiration_service.permanently_deleted' : 'expiration_service.soft_deleted');
            logger.info(`Expiration ${id} deleted (permanent: ${permanent}) in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to delete expiration ${id}:`, error);
            metricsCollector.increment('expiration_service.delete_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Search expiration records
     * @param {string} query - Search query
     * @param {Object} filters - Additional filters
     * @param {Object} options - Pagination options
     * @returns {Promise<Object>} - Search results
     */
    async searchExpirations(query, filters = {}, options = { page: 1, limit: 20 }) {
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

            metricsCollector.increment('expiration_service.searched', { count: hits.length });
            logger.info(`Search returned ${hits.length} expiration records in ${Date.now() - startTime}ms`);

            return {
                hits,
                totalHits,
                page: options.page,
                limit: options.limit,
                totalPages: Math.ceil(totalHits / options.limit),
            };
        } catch (error) {
            logger.error(`Search failed for query ${query}:`, error);
            metricsCollector.increment('expiration_service.search_failed');
            throw new AppError('Failed to search expiration records', 500);
        }
    }

    /**
     * Get upcoming expirations
     * @param {number} days - Number of days to look ahead
     * @param {string} entityType - Entity type filter
     * @param {number} limit - Number of results
     * @returns {Promise<Array>} - Upcoming expiration records
     */
    async getUpcomingExpirations(days, entityType, limit) {
        const startTime = Date.now();
        try {
            const cacheKey = `upcoming_expirations:${days}:${entityType || 'all'}:${limit}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('expiration_service.upcoming_cache_hit');
                return cached;
            }

            const cutoffDate = new Date();
            cutoffDate.setDate(cutoffDate.getDate() + parseInt(days));

            const query = {
                'status.isDeleted': false,
                expirationDate: { $gte: new Date(), $lte: cutoffDate },
            };
            if (entityType) query.entityType = entityType;

            const expirations = await Expiration.find(query)
                .read('secondaryPreferred')
                .sort({ expirationDate: 1 })
                .limit(parseInt(limit))
                .select('entityType entityId expirationDate status')
                .lean();

            await cacheService.set(cacheKey, expirations, 300);
            metricsCollector.increment('expiration_service.upcoming_fetched', { count: expirations.length });
            logger.info(`Fetched ${expirations.length} upcoming expiration records in ${Date.now() - startTime}ms`);

            return expirations;
        } catch (error) {
            logger.error(`Failed to fetch upcoming expirations:`, error);
            metricsCollector.increment('expiration_service.upcoming_fetch_failed');
            throw new AppError('Failed to fetch upcoming expirations', 500);
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
            metricsCollector.increment('expiration_service.media_validation_failed');
            throw new AppError('Media validation failed', 422);
        }
    }

    /**
     * Index expiration record for search
     * @param {Object} expiration - Expiration document
     */
    async indexForSearch(expiration) {
        const startTime = Date.now();
        try {
            const indexData = {
                objectID: expiration._id.toString(),
                entityType: expiration.entityType,
                entityId: expiration.entityId,
                description: expiration.description,
                expirationDate: expiration.expirationDate,
                status: expiration.status.workflow,
                createdAt: expiration.createdAt,
            };

            if (SEARCH_ENGINE === 'algolia') {
                await searchClient.saveObject({
                    indexName: INDEX_NAME,
                    body: indexData,
                });
            } else {
                await searchClient.index({
                    index: INDEX_NAME,
                    id: expiration._id.toString(),
                    body: indexData,
                });
            }

            metricsCollector.increment('expiration_service.indexed');
            logger.info(`Indexed expiration ${expiration._id} for search in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to index expiration ${expiration._id}:`, error);
            metricsCollector.increment('expiration_service.index_failed');
            throw new AppError('Failed to index expiration record', 500);
        }
    }

    /**
     * Get expiration analytics
     * @param {string} id - Expiration ID
     * @param {string} timeframe - Timeframe (e.g., '30d')
     * @returns {Promise<Object>} - Analytics data
     */
    async getExpirationAnalytics(id, timeframe) {
        const startTime = Date.now();
        try {
            const cacheKey = `expiration_analytics:${id}:${timeframe}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('expiration_service.analytics_cache_hit');
                return cached;
            }

            const expiration = await Expiration.findById(id)
                .select('analytics metadata')
                .lean();

            if (!expiration) {
                throw new AppError('Expiration record not found', 404);
            }

            const analytics = {
                views: expiration.analytics.views || 0,
                associatedItems: expiration.analytics.associatedItems || 0,
                timeframe,
                lastUpdated: expiration.metadata.lastModifiedBy?.timestamp || expiration.createdAt,
            };

            await cacheService.set(cacheKey, analytics, 300);
            metricsCollector.increment('expiration_service.analytics_fetched');
            logger.info(`Fetched analytics for expiration ${id} in ${Date.now() - startTime}ms`);

            return analytics;
        } catch (error) {
            logger.error(`Failed to fetch analytics for expiration ${id}:`, error);
            metricsCollector.increment('expiration_service.analytics_fetch_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Get expiration statistics
     * @param {string} id - Expiration ID
     * @returns {Promise<Object>} - Statistics
     */
    async getExpirationStats(id) {
        const startTime = Date.now();
        try {
            const cacheKey = `expiration_stats:${id}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('expiration_service.stats_cache_hit');
                return cached;
            }

            const expiration = await Expiration.findById(id)
                .select('analytics status expirationDate createdAt')
                .lean();

            if (!expiration) {
                throw new AppError('Expiration record not found', 404);
            }

            const stats = {
                totalViews: expiration.analytics.views || 0,
                associatedItems: expiration.analytics.associatedItems || 0,
                status: expiration.status.workflow,
                ageInDays: Math.floor((Date.now() - new Date(expiration.createdAt)) / (1000 * 60 * 60 * 24)),
                daysUntilExpiration: Math.floor((new Date(expiration.expirationDate) - Date.now()) / (1000 * 60 * 60 * 24)),
                isExpired: new Date(expiration.expirationDate) < new Date(),
            };

            await cacheService.set(cacheKey, stats, 3600);
            metricsCollector.increment('expiration_service.stats_fetched');
            logger.info(`Fetched stats for expiration ${id} in ${Date.now() - startTime}ms`);

            return stats;
        } catch (error) {
            logger.error(`Failed to fetch stats for expiration ${id}:`, error);
            metricsCollector.increment('expiration_service.stats_fetch_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Get audit logs
     * @param {string} expirationId - Expiration ID
     * @param {Object} options - Options including page, limit, action
     * @returns {Promise<Array>} - Audit logs
     */
    async getAuditLogs(expirationId, options = { page: 1, limit: 20, action: null }) {
        const startTime = Date.now();
        try {
            const page = Math.max(1, options.page);
            const limit = Math.min(100, Math.max(1, options.limit));
            const skip = (page - 1) * limit;

            const query = { expirationId };
            if (options.action) query.action = options.action;

            const logs = await ExpirationAuditLog.find(query) // Assumed model for audit logs
                .skip(skip)
                .limit(limit)
                .lean();

            metricsCollector.increment('expiration_service.audit_fetched', { count: logs.length });
            logger.info(`Fetched ${logs.length} audit logs for expiration ${expirationId} in ${Date.now() - startTime}ms`);

            return logs;
        } catch (error) {
            logger.error(`Failed to fetch audit logs for expiration ${expirationId}:`, error);
            metricsCollector.increment('expiration_service.audit_fetch_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Count audit logs
     * @param {string} expirationId - Expiration ID
     * @param {string} action - Action filter
     * @returns {Promise<number>} - Total count
     */
    async countAuditLogs(expirationId, action) {
        const startTime = Date.now();
        try {
            const query = { expirationId };
            if (action) query.action = action;

            const count = await ExpirationAuditLog.countDocuments(query);
            logger.info(`Counted ${count} audit logs for expiration ${expirationId} in ${Date.now() - startTime}ms`);

            return count;
        } catch (error) {
            logger.error(`Failed to count audit logs for expiration ${expirationId}:`, error);
            throw this.handleError(error);
        }
    }

    /**
     * Update expiration analytics
     * @param {string} expirationId - Expiration ID
     * @param {Object} options - Options including session
     */
    async updateExpirationAnalytics(expirationId, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;
        try {
            const expiration = await Expiration.findById(expirationId).session(session);
            if (!expiration) {
                throw new AppError('Expiration record not found', 404);
            }

            expiration.analytics = expiration.analytics || { views: 0, associatedItems: 0 };
            expiration.analytics.views += 1;
            await expiration.save({ session });

            logger.info(`Updated analytics for expiration ${expirationId} in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to update analytics for expiration ${expirationId}:`, error);
            metricsCollector.increment('expiration_service.analytics_update_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Process expiration record asynchronously
     * @param {string} expirationId - Expiration ID
     * @param {string} userId - User ID
     * @param {string} action - Action type
     */
    async processExpirationAsync(expirationId, userId, action) {
        const startTime = Date.now();
        try {
            const expiration = await Expiration.findById(expirationId).lean();
            if (!expiration) {
                throw new AppError('Expiration record not found', 404);
            }

            // Index for search
            await this.indexForSearch(expiration);

            // Create backup
            await this.createBackup(expirationId, action, userId);

            // Queue reminder if nearing expiration
            const daysUntilExpiration = Math.floor((new Date(expiration.expirationDate) - Date.now()) / (1000 * 60 * 60 * 24));
            if (daysUntilExpiration <= 30 && daysUntilExpiration >= 0) {
                await queueService.addJob('sendExpirationReminder', {
                    expirationId,
                    userId,
                    entityType: expiration.entityType,
                    entityId: expiration.entityId,
                    expirationDate: expiration.expirationDate,
                });
            }

            metricsCollector.increment('expiration_service.async_processed');
            logger.info(`Async processing completed for expiration ${expirationId} in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Async processing failed for expiration ${expirationId}:`, error);
            metricsCollector.increment('expiration_service.async_process_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Create backup
     * @param {string} expirationId - Expiration ID
     * @param {string} action - Action type
     * @param {string} userId - User ID
     */
    async createBackup(expirationId, action, userId) {
        const startTime = Date.now();
        try {
            const expiration = await Expiration.findById(expirationId).lean();
            if (!expiration) {
                throw new AppError('Expiration record not found', 404);
            }

            const backupKey = `expiration_backup_${expirationId}_${Date.now()}_${uuidv4()}`;
            await s3.upload({
                Bucket: process.env.S3_BACKUP_BUCKET,
                Key: backupKey,
                Body: JSON.stringify({
                    expiration,
                    action,
                    userId,
                    timestamp: new Date(),
                }),
                ContentType: 'application/json',
                ServerSideEncryption: 'AES256',
            }).promise();

            metricsCollector.increment('expiration_service.backup_created', { action });
            logger.info(`Backup created for expiration ${expirationId} (${action}) in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to create backup for expiration ${expirationId}:`, error);
            metricsCollector.increment('expiration_service.backup_failed');
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
            entityType: sanitizeHtml(data.entityType || ''),
            entityId: sanitizeHtml(data.entityId || ''),
            description: sanitizeHtml(data.description || ''),
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
                must: query ? { multi_match: { query, fields: ['entityType', 'entityId', 'description'] } } : { match_all: {} },
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
     * @param {Object} expiration - Expiration document
     * @param {string} action - Action type
     * @returns {boolean} - Permission granted
     */
    hasPermission(userId, expiration, action) {
        const creatorId = expiration.metadata?.createdBy?.userId?.toString();
        const permissions = {
            update: creatorId === userId,
            delete: creatorId === userId,
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
            return new AppError('Expiration record already exists', 409);
        }
        if (error.name === 'CastError') {
            return new AppError('Invalid expiration ID', 400);
        }
        if (error.message.includes('timeout')) {
            return new AppError('Operation timed out', 504);
        }
        return new AppError('Operation failed', 500);
    }
}

export default new ExpirationService();