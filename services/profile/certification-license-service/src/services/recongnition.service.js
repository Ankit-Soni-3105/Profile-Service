import Recognition from '../models/Recognition.js';
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
const INDEX_NAME = 'recognitions';

// Validation schemas (assumed to be defined in recognition.validation.js)
import { validateRecognition, validateMediaUpload, validateSearch } from '../validations/recognition.validation.js';

class RecognitionService {
    /**
     * Create a new recognition record
     * @param {Object} recognitionData - Recognition data
     * @param {Object} options - Options including session
     * @returns {Promise<Object>} - Created recognition record
     */
    async createRecognition(recognitionData, options = {}) {
        const startTime = Date.now();
        try {
            const sanitizedData = this.sanitizeData(recognitionData);
            const recognition = new Recognition({
                ...sanitizedData,
                status: {
                    workflow: 'pending',
                    isActive: true,
                    isDeleted: false,
                    isArchived: false,
                },
                analytics: { views: 0, shares: 0, associatedItems: 0 },
                media: [],
                verification: { status: 'pending', details: {} },
            });

            await recognition.save(options);
            metricsCollector.increment('recognition_service.created');
            logger.info(`Recognition created: ${recognition._id} in ${Date.now() - startTime}ms`);

            return recognition;
        } catch (error) {
            logger.error(`Failed to create recognition:`, error);
            metricsCollector.increment('recognition_service.create_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Get recognition record by ID
     * @param {string} id - Recognition ID
     * @param {string} userId - Requesting user ID
     * @returns {Promise<Object>} - Recognition document
     */
    async getRecognitionById(id, userId) {
        const startTime = Date.now();
        try {
            const cacheKey = `recognition:${id}:${userId}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('recognition_service.cache_hit');
                return cached;
            }

            const recognition = await Recognition.findOne({
                _id: id,
                'status.isDeleted': false,
            })
                .read('secondaryPreferred')
                .select('title issuer recipientId issueDate categoryId description verification status analytics metadata media')
                .lean();

            if (!recognition) {
                throw new AppError('Recognition record not found', 404);
            }

            await cacheService.set(cacheKey, recognition, 300); // Short TTL for high-traffic
            metricsCollector.increment('recognition_service.fetched');
            logger.info(`Fetched recognition ${id} in ${Date.now() - startTime}ms`);

            return recognition;
        } catch (error) {
            logger.error(`Failed to fetch recognition ${id}:`, error);
            metricsCollector.increment('recognition_service.fetch_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Update recognition record
     * @param {string} id - Recognition ID
     * @param {string} userId - Requesting user ID
     * @param {Object} updates - Update data
     * @param {Object} options - Options including session and metadata
     * @returns {Promise<Object>} - Updated recognition record
     */
    async updateRecognition(id, userId, updates, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;
        try {
            const recognition = await Recognition.findOne({
                _id: id,
                'status.isDeleted': false,
            }).session(session);

            if (!recognition) {
                throw new AppError('Recognition record not found', 404);
            }

            if (!this.hasPermission(userId, recognition, 'update')) {
                throw new AppError('Access denied', 403);
            }

            Object.assign(recognition, this.sanitizeData(updates));
            recognition.metadata.lastModifiedBy = {
                userId: options.requestingUserId || userId,
                ip: options.ip,
                userAgent: options.userAgent,
                timestamp: new Date(),
            };

            await recognition.save({ session });
            metricsCollector.increment('recognition_service.updated');
            logger.info(`Recognition updated: ${id} in ${Date.now() - startTime}ms`);

            return recognition;
        } catch (error) {
            logger.error(`Failed to update recognition ${id}:`, error);
            metricsCollector.increment('recognition_service.update_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Delete recognition record
     * @param {string} id - Recognition ID
     * @param {string} userId - Requesting user ID
     * @param {boolean} permanent - Permanent deletion flag
     * @param {Object} options - Options including session
     */
    async deleteRecognition(id, userId, permanent = false, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;
        try {
            const recognition = await Recognition.findOne({
                _id: id,
                'status.isDeleted': false,
            }).session(session);

            if (!recognition) {
                throw new AppError('Recognition record not found', 404);
            }

            if (!this.hasPermission(userId, recognition, 'delete')) {
                throw new AppError('Access denied', 403);
            }

            if (permanent) {
                await recognition.deleteOne({ session });
            } else {
                recognition.status.isDeleted = true;
                recognition.status.deletedAt = new Date();
                await recognition.save({ session });
            }

            metricsCollector.increment(permanent ? 'recognition_service.permanently_deleted' : 'recognition_service.soft_deleted');
            logger.info(`Recognition ${id} deleted (permanent: ${permanent}) in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to delete recognition ${id}:`, error);
            metricsCollector.increment('recognition_service.delete_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Search recognition records
     * @param {string} query - Search query
     * @param {Object} filters - Additional filters
     * @param {Object} options - Pagination options
     * @returns {Promise<Object>} - Search results
     */
    async searchRecognitions(query, filters = {}, options = { page: 1, limit: 20 }) {
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

            metricsCollector.increment('recognition_service.searched', { count: hits.length });
            logger.info(`Search returned ${hits.length} recognition records in ${Date.now() - startTime}ms`);

            return {
                hits,
                totalHits,
                page: options.page,
                limit: options.limit,
                totalPages: Math.ceil(totalHits / options.limit),
            };
        } catch (error) {
            logger.error(`Search failed for query ${query}:`, error);
            metricsCollector.increment('recognition_service.search_failed');
            throw new AppError('Failed to search recognition records', 500);
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
            metricsCollector.increment('recognition_service.media_validation_failed');
            throw new AppError('Media validation failed', 422);
        }
    }

    /**
     * Index recognition record for search
     * @param {Object} recognition - Recognition document
     */
    async indexForSearch(recognition) {
        const startTime = Date.now();
        try {
            const indexData = {
                objectID: recognition._id.toString(),
                title: recognition.title,
                issuer: recognition.issuer,
                recipientId: recognition.recipientId,
                issueDate: recognition.issueDate,
                description: recognition.description,
                categoryId: recognition.categoryId,
                status: recognition.status.workflow,
                verificationStatus: recognition.verification.status,
                createdAt: recognition.createdAt,
            };

            if (SEARCH_ENGINE === 'algolia') {
                await searchClient.saveObject({
                    indexName: INDEX_NAME,
                    body: indexData,
                });
            } else {
                await searchClient.index({
                    index: INDEX_NAME,
                    id: recognition._id.toString(),
                    body: indexData,
                });
            }

            metricsCollector.increment('recognition_service.indexed');
            logger.info(`Indexed recognition ${recognition._id} for search in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to index recognition ${recognition._id}:`, error);
            metricsCollector.increment('recognition_service.index_failed');
            throw new AppError('Failed to index recognition record', 500);
        }
    }

    /**
     * Get recognition analytics
     * @param {string} id - Recognition ID
     * @param {string} timeframe - Timeframe (e.g., '30d')
     * @returns {Promise<Object>} - Analytics data
     */
    async getRecognitionAnalytics(id, timeframe) {
        const startTime = Date.now();
        try {
            const cacheKey = `recognition_analytics:${id}:${timeframe}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('recognition_service.analytics_cache_hit');
                return cached;
            }

            const recognition = await Recognition.findById(id)
                .select('analytics metadata')
                .lean();

            if (!recognition) {
                throw new AppError('Recognition record not found', 404);
            }

            const analytics = {
                views: recognition.analytics.views || 0,
                shares: recognition.analytics.shares || 0,
                associatedItems: recognition.analytics.associatedItems || 0,
                timeframe,
                lastUpdated: recognition.metadata.lastModifiedBy?.timestamp || recognition.createdAt,
            };

            await cacheService.set(cacheKey, analytics, 300);
            metricsCollector.increment('recognition_service.analytics_fetched');
            logger.info(`Fetched analytics for recognition ${id} in ${Date.now() - startTime}ms`);

            return analytics;
        } catch (error) {
            logger.error(`Failed to fetch analytics for recognition ${id}:`, error);
            metricsCollector.increment('recognition_service.analytics_fetch_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Get recognition statistics
     * @param {string} id - Recognition ID
     * @returns {Promise<Object>} - Statistics
     */
    async getRecognitionStats(id) {
        const startTime = Date.now();
        try {
            const cacheKey = `recognition_stats:${id}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('recognition_service.stats_cache_hit');
                return cached;
            }

            const recognition = await Recognition.findById(id)
                .select('analytics status verification issueDate createdAt')
                .lean();

            if (!recognition) {
                throw new AppError('Recognition record not found', 404);
            }

            const stats = {
                totalViews: recognition.analytics.views || 0,
                totalShares: recognition.analytics.shares || 0,
                associatedItems: recognition.analytics.associatedItems || 0,
                status: recognition.status.workflow,
                verificationStatus: recognition.verification.status,
                ageInDays: Math.floor((Date.now() - new Date(recognition.createdAt)) / (1000 * 60 * 60 * 24)),
            };

            await cacheService.set(cacheKey, stats, 3600);
            metricsCollector.increment('recognition_service.stats_fetched');
            logger.info(`Fetched stats for recognition ${id} in ${Date.now() - startTime}ms`);

            return stats;
        } catch (error) {
            logger.error(`Failed to fetch stats for recognition ${id}:`, error);
            metricsCollector.increment('recognition_service.stats_fetch_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Get audit logs
     * @param {string} recognitionId - Recognition ID
     * @param {Object} options - Options including page, limit, action
     * @returns {Promise<Array>} - Audit logs
     */
    async getAuditLogs(recognitionId, options = { page: 1, limit: 20, action: null }) {
        const startTime = Date.now();
        try {
            const page = Math.max(1, options.page);
            const limit = Math.min(100, Math.max(1, options.limit));
            const skip = (page - 1) * limit;

            const query = { recognitionId };
            if (options.action) query.action = options.action;

            const logs = await RecognitionAuditLog.find(query) // Assumed model for audit logs
                .skip(skip)
                .limit(limit)
                .lean();

            metricsCollector.increment('recognition_service.audit_fetched', { count: logs.length });
            logger.info(`Fetched ${logs.length} audit logs for recognition ${recognitionId} in ${Date.now() - startTime}ms`);

            return logs;
        } catch (error) {
            logger.error(`Failed to fetch audit logs for recognition ${recognitionId}:`, error);
            metricsCollector.increment('recognition_service.audit_fetch_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Count audit logs
     * @param {string} recognitionId - Recognition ID
     * @param {string} action - Action filter
     * @returns {Promise<number>} - Total count
     */
    async countAuditLogs(recognitionId, action) {
        const startTime = Date.now();
        try {
            const query = { recognitionId };
            if (action) query.action = action;

            const count = await RecognitionAuditLog.countDocuments(query);
            logger.info(`Counted ${count} audit logs for recognition ${recognitionId} in ${Date.now() - startTime}ms`);

            return count;
        } catch (error) {
            logger.error(`Failed to count audit logs for recognition ${recognitionId}:`, error);
            throw this.handleError(error);
        }
    }

    /**
     * Update recognition analytics
     * @param {string} recognitionId - Recognition ID
     * @param {Object} options - Options including session
     */
    async updateRecognitionAnalytics(recognitionId, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;
        try {
            const recognition = await Recognition.findById(recognitionId).session(session);
            if (!recognition) {
                throw new AppError('Recognition record not found', 404);
            }

            recognition.analytics = recognition.analytics || { views: 0, shares: 0, associatedItems: 0 };
            recognition.analytics.views += 1;
            await recognition.save({ session });

            logger.info(`Updated analytics for recognition ${recognitionId} in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to update analytics for recognition ${recognitionId}:`, error);
            metricsCollector.increment('recognition_service.analytics_update_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Increment recognition shares
     * @param {string} recognitionId - Recognition ID
     * @param {Object} options - Options including session
     */
    async incrementShares(recognitionId, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;
        try {
            const recognition = await Recognition.findById(recognitionId).session(session);
            if (!recognition) {
                throw new AppError('Recognition record not found', 404);
            }

            recognition.analytics = recognition.analytics || { views: 0, shares: 0, associatedItems: 0 };
            recognition.analytics.shares += 1;
            await recognition.save({ session });

            metricsCollector.increment('recognition_service.shares_incremented');
            logger.info(`Incremented shares for recognition ${recognitionId} in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to increment shares for recognition ${recognitionId}:`, error);
            metricsCollector.increment('recognition_service.shares_increment_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Process recognition record asynchronously
     * @param {string} recognitionId - Recognition ID
     * @param {string} userId - User ID
     * @param {string} action - Action type
     */
    async processRecognitionAsync(recognitionId, userId, action) {
        const startTime = Date.now();
        try {
            const recognition = await Recognition.findById(recognitionId).lean();
            if (!recognition) {
                throw new AppError('Recognition record not found', 404);
            }

            // Index for search
            await this.indexForSearch(recognition);

            // Create backup
            await this.createBackup(recognitionId, action, userId);

            // Queue notification if verified
            if (action === 'verify' && recognition.verification.status === 'verified') {
                await queueService.addJob('sendVerificationNotification', {
                    recognitionId,
                    userId,
                    recipientId: recognition.recipientId,
                    title: recognition.title,
                });
            }

            metricsCollector.increment('recognition_service.async_processed');
            logger.info(`Async processing completed for recognition ${recognitionId} in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Async processing failed for recognition ${recognitionId}:`, error);
            metricsCollector.increment('recognition_service.async_process_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Create backup
     * @param {string} recognitionId - Recognition ID
     * @param {string} action - Action type
     * @param {string} userId - User ID
     */
    async createBackup(recognitionId, action, userId) {
        const startTime = Date.now();
        try {
            const recognition = await Recognition.findById(recognitionId).lean();
            if (!recognition) {
                throw new AppError('Recognition record not found', 404);
            }

            const backupKey = `recognition_backup_${recognitionId}_${Date.now()}_${uuidv4()}`;
            await s3.upload({
                Bucket: process.env.S3_BACKUP_BUCKET,
                Key: backupKey,
                Body: JSON.stringify({
                    recognition,
                    action,
                    userId,
                    timestamp: new Date(),
                }),
                ContentType: 'application/json',
                ServerSideEncryption: 'AES256',
            }).promise();

            metricsCollector.increment('recognition_service.backup_created', { action });
            logger.info(`Backup created for recognition ${recognitionId} (${action}) in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to create backup for recognition ${recognitionId}:`, error);
            metricsCollector.increment('recognition_service.backup_failed');
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
            title: sanitizeHtml(data.title || ''),
            issuer: sanitizeHtml(data.issuer || ''),
            description: sanitizeHtml(data.description || ''),
            categoryId: sanitizeHtml(data.categoryId || ''),
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
                must: query ? { multi_match: { query, fields: ['title', 'issuer', 'description', 'categoryId'] } } : { match_all: {} },
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
     * @param {Object} recognition - Recognition document
     * @param {string} action - Action type
     * @returns {boolean} - Permission granted
     */
    hasPermission(userId, recognition, action) {
        const creatorId = recognition.metadata?.createdBy?.userId?.toString();
        const recipientId = recognition.recipientId?.toString();
        const permissions = {
            update: creatorId === userId || recipientId === userId,
            delete: creatorId === userId,
            share: creatorId === userId || recipientId === userId,
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
            return new AppError('Recognition record already exists', 409);
        }
        if (error.name === 'CastError') {
            return new AppError('Invalid recognition ID', 400);
        }
        if (error.message.includes('timeout')) {
            return new AppError('Operation timed out', 504);
        }
        return new AppError('Operation failed', 500);
    }
}

export default new RecognitionService();    