import Education from '../models/Education.js';
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
const INDEX_NAME = 'educations';

// Validation schemas (assumed to be defined in education.validation.js)
import { validateEducation, validateMediaUpload } from '../validations/education.validation.js';

class EducationService {
    /**
     * Create a new education record
     * @param {Object} educationData - Education data
     * @param {Object} options - Options including session
     * @returns {Promise<Object>} - Created education record
     */
    async createEducation(educationData, options = {}) {
        const startTime = Date.now();
        try {
            const sanitizedData = this.sanitizeData(educationData);
            const education = new Education({
                ...sanitizedData,
                status: {
                    workflow: 'active',
                    isActive: true,
                    isDeleted: false,
                    isArchived: false,
                },
                analytics: { views: 0, associatedItems: 0 },
                verification: { status: 'pending', verificationScore: 0 },
                media: [],
            });

            await education.save(options);
            metricsCollector.increment('education_service.created');
            logger.info(`Education created: ${education._id} in ${Date.now() - startTime}ms`);

            return education;
        } catch (error) {
            logger.error(`Failed to create education:`, error);
            metricsCollector.increment('education_service.create_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Get education record by ID
     * @param {string} id - Education ID
     * @param {string} userId - Requesting user ID
     * @returns {Promise<Object>} - Education document
     */
    async getEducationById(id, userId) {
        const startTime = Date.now();
        try {
            const cacheKey = `education:${id}:${userId}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('education_service.cache_hit');
                return cached;
            }

            const education = await Education.findOne({
                _id: id,
                'status.isDeleted': false,
            })
                .read('secondaryPreferred')
                .select('title institution description categoryId startDate endDate verification status analytics metadata media')
                .lean();

            if (!education) {
                throw new AppError('Education record not found', 404);
            }

            await cacheService.set(cacheKey, education, 600);
            metricsCollector.increment('education_service.fetched');
            logger.info(`Fetched education ${id} in ${Date.now() - startTime}ms`);

            return education;
        } catch (error) {
            logger.error(`Failed to fetch education ${id}:`, error);
            metricsCollector.increment('education_service.fetch_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Update education record
     * @param {string} id - Education ID
     * @param {string} userId - Requesting user ID
     * @param {Object} updates - Update data
     * @param {Object} options - Options including session and metadata
     * @returns {Promise<Object>} - Updated education record
     */
    async updateEducation(id, userId, updates, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;
        try {
            const education = await Education.findOne({
                _id: id,
                'status.isDeleted': false,
            }).session(session);

            if (!education) {
                throw new AppError('Education record not found', 404);
            }

            if (!this.hasPermission(userId, education, 'update')) {
                throw new AppError('Access denied', 403);
            }

            Object.assign(education, this.sanitizeData(updates));
            education.metadata.lastModifiedBy = {
                userId: options.requestingUserId || userId,
                ip: options.ip,
                userAgent: options.userAgent,
                timestamp: new Date(),
            };

            await education.save({ session });
            metricsCollector.increment('education_service.updated');
            logger.info(`Education updated: ${id} in ${Date.now() - startTime}ms`);

            return education;
        } catch (error) {
            logger.error(`Failed to update education ${id}:`, error);
            metricsCollector.increment('education_service.update_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Delete education record
     * @param {string} id - Education ID
     * @param {string} userId - Requesting user ID
     * @param {boolean} permanent - Permanent deletion flag
     * @param {Object} options - Options including session
     */
    async deleteEducation(id, userId, permanent = false, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;
        try {
            const education = await Education.findOne({
                _id: id,
                'status.isDeleted': false,
            }).session(session);

            if (!education) {
                throw new AppError('Education record not found', 404);
            }

            if (!this.hasPermission(userId, education, 'delete')) {
                throw new AppError('Access denied', 403);
            }

            if (permanent) {
                await education.deleteOne({ session });
            } else {
                education.status.isDeleted = true;
                education.status.deletedAt = new Date();
                await education.save({ session });
            }

            metricsCollector.increment(permanent ? 'education_service.permanently_deleted' : 'education_service.soft_deleted');
            logger.info(`Education ${id} deleted (permanent: ${permanent}) in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to delete education ${id}:`, error);
            metricsCollector.increment('education_service.delete_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Search education records
     * @param {string} query - Search query
     * @param {Object} filters - Additional filters
     * @param {Object} options - Pagination options
     * @returns {Promise<Object>} - Search results
     */
    async searchEducations(query, filters = {}, options = { page: 1, limit: 20 }) {
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

            metricsCollector.increment('education_service.searched', { count: hits.length });
            logger.info(`Search returned ${hits.length} education records in ${Date.now() - startTime}ms`);

            return {
                hits,
                totalHits,
                page: options.page,
                limit: options.limit,
                totalPages: Math.ceil(totalHits / options.limit),
            };
        } catch (error) {
            logger.error(`Search failed for query ${query}:`, error);
            metricsCollector.increment('education_service.search_failed');
            throw new AppError('Failed to search education records', 500);
        }
    }

    /**
     * Get trending education records
     * @param {string} timeframe - Timeframe (e.g., '30d')
     * @param {string} categoryId - Category ID
     * @param {number} limit - Number of results
     * @returns {Promise<Array>} - Trending education records
     */
    async getTrendingEducations(timeframe, categoryId, limit) {
        const startTime = Date.now();
        try {
            const cacheKey = `trending_educations:${timeframe}:${categoryId || 'all'}:${limit}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('education_service.trending_cache_hit');
                return cached;
            }

            const query = {
                'status.isDeleted': false,
                'analytics.views': { $gt: 0 },
            };
            if (categoryId) query.categoryId = categoryId;

            const educations = await Education.find(query)
                .read('secondaryPreferred')
                .sort({ 'analytics.views': -1 })
                .limit(limit)
                .select('title institution description categoryId startDate endDate verification status analytics')
                .lean();

            await cacheService.set(cacheKey, educations, 300);
            metricsCollector.increment('education_service.trending_fetched', { count: educations.length });
            logger.info(`Fetched ${educations.length} trending education records in ${Date.now() - startTime}ms`);

            return educations;
        } catch (error) {
            logger.error(`Failed to fetch trending education records:`, error);
            metricsCollector.increment('education_service.trending_fetch_failed');
            throw new AppError('Failed to fetch trending education records', 500);
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
            metricsCollector.increment('education_service.media_validation_failed');
            throw new AppError('Media validation failed', 422);
        }
    }

    /**
     * Index education record for search
     * @param {Object} education - Education document
     */
    async indexForSearch(education) {
        const startTime = Date.now();
        try {
            const indexData = {
                objectID: education._id.toString(),
                title: education.title,
                institution: education.institution,
                description: education.description,
                categoryId: education.categoryId?.toString(),
                status: education.status.workflow,
                createdAt: education.createdAt,
                startDate: education.startDate,
                endDate: education.endDate,
            };

            if (SEARCH_ENGINE === 'algolia') {
                await searchClient.saveObject({
                    indexName: INDEX_NAME,
                    body: indexData,
                });
            } else {
                await searchClient.index({
                    index: INDEX_NAME,
                    id: education._id.toString(),
                    body: indexData,
                });
            }

            metricsCollector.increment('education_service.indexed');
            logger.info(`Indexed education ${education._id} for search in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to index education ${education._id}:`, error);
            metricsCollector.increment('education_service.index_failed');
            throw new AppError('Failed to index education record', 500);
        }
    }

    /**
     * Get education analytics
     * @param {string} id - Education ID
     * @param {string} timeframe - Timeframe (e.g., '30d')
     * @returns {Promise<Object>} - Analytics data
     */
    async getEducationAnalytics(id, timeframe) {
        const startTime = Date.now();
        try {
            const cacheKey = `education_analytics:${id}:${timeframe}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('education_service.analytics_cache_hit');
                return cached;
            }

            const education = await Education.findById(id)
                .select('analytics metadata')
                .lean();

            if (!education) {
                throw new AppError('Education record not found', 404);
            }

            const analytics = {
                views: education.analytics.views || 0,
                associatedItems: education.analytics.associatedItems || 0,
                timeframe,
                lastUpdated: education.metadata.lastModifiedBy?.timestamp || education.createdAt,
            };

            await cacheService.set(cacheKey, analytics, 300);
            metricsCollector.increment('education_service.analytics_fetched');
            logger.info(`Fetched analytics for education ${id} in ${Date.now() - startTime}ms`);

            return analytics;
        } catch (error) {
            logger.error(`Failed to fetch analytics for education ${id}:`, error);
            metricsCollector.increment('education_service.analytics_fetch_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Get education statistics
     * @param {string} id - Education ID
     * @returns {Promise<Object>} - Statistics
     */
    async getEducationStats(id) {
        const startTime = Date.now();
        try {
            const cacheKey = `education_stats:${id}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('education_service.stats_cache_hit');
                return cached;
            }

            const education = await Education.findById(id)
                .select('analytics status createdAt')
                .lean();

            if (!education) {
                throw new AppError('Education record not found', 404);
            }

            const stats = {
                totalViews: education.analytics.views || 0,
                associatedItems: education.analytics.associatedItems || 0,
                status: education.status.workflow,
                ageInDays: Math.floor((Date.now() - new Date(education.createdAt)) / (1000 * 60 * 60 * 24)),
                duration: education.startDate && education.endDate
                    ? Math.floor((new Date(education.endDate) - new Date(education.startDate)) / (1000 * 60 * 60 * 24))
                    : null,
            };

            await cacheService.set(cacheKey, stats, 3600);
            metricsCollector.increment('education_service.stats_fetched');
            logger.info(`Fetched stats for education ${id} in ${Date.now() - startTime}ms`);

            return stats;
        } catch (error) {
            logger.error(`Failed to fetch stats for education ${id}:`, error);
            metricsCollector.increment('education_service.stats_fetch_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Get audit logs
     * @param {string} educationId - Education ID
     * @param {Object} options - Options including page, limit, action
     * @returns {Promise<Array>} - Audit logs
     */
    async getAuditLogs(educationId, options = { page: 1, limit: 20, action: null }) {
        const startTime = Date.now();
        try {
            const page = Math.max(1, options.page);
            const limit = Math.min(100, Math.max(1, options.limit));
            const skip = (page - 1) * limit;

            const query = { educationId };
            if (options.action) query.action = options.action;

            const logs = await EducationAuditLog.find(query) // Assumed model for audit logs
                .skip(skip)
                .limit(limit)
                .lean();

            metricsCollector.increment('education_service.audit_fetched', { count: logs.length });
            logger.info(`Fetched ${logs.length} audit logs for education ${educationId} in ${Date.now() - startTime}ms`);

            return logs;
        } catch (error) {
            logger.error(`Failed to fetch audit logs for education ${educationId}:`, error);
            metricsCollector.increment('education_service.audit_fetch_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Count audit logs
     * @param {string} educationId - Education ID
     * @param {string} action - Action filter
     * @returns {Promise<number>} - Total count
     */
    async countAuditLogs(educationId, action) {
        const startTime = Date.now();
        try {
            const query = { educationId };
            if (action) query.action = action;

            const count = await EducationAuditLog.countDocuments(query);
            logger.info(`Counted ${count} audit logs for education ${educationId} in ${Date.now() - startTime}ms`);

            return count;
        } catch (error) {
            logger.error(`Failed to count audit logs for education ${educationId}:`, error);
            throw this.handleError(error);
        }
    }

    /**
     * Update education analytics
     * @param {string} educationId - Education ID
     * @param {Object} options - Options including session
     */
    async updateEducationAnalytics(educationId, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;
        try {
            const education = await Education.findById(educationId).session(session);
            if (!education) {
                throw new AppError('Education record not found', 404);
            }

            education.analytics = education.analytics || { views: 0, associatedItems: 0 };
            education.analytics.views += 1; // Example increment
            await education.save({ session });

            logger.info(`Updated analytics for education ${educationId} in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to update analytics for education ${educationId}:`, error);
            metricsCollector.increment('education_service.analytics_update_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Process new education record asynchronously
     * @param {string} educationId - Education ID
     * @param {string} userId - User ID
     * @param {string} action - Action type
     */
    async processNewEducationAsync(educationId, userId, action) {
        const startTime = Date.now();
        try {
            const education = await Education.findById(educationId).lean();
            if (!education) {
                throw new AppError('Education record not found', 404);
            }

            // Index for search
            await this.indexForSearch(education);

            // Create backup
            await this.createBackup(educationId, action, userId);

            metricsCollector.increment('education_service.async_processed');
            logger.info(`Async processing completed for education ${educationId} in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Async processing failed for education ${educationId}:`, error);
            metricsCollector.increment('education_service.async_process_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Create backup
     * @param {string} educationId - Education ID
     * @param {string} action - Action type
     * @param {string} userId - User ID
     */
    async createBackup(educationId, action, userId) {
        const startTime = Date.now();
        try {
            const education = await Education.findById(educationId).lean();
            if (!education) {
                throw new AppError('Education record not found', 404);
            }

            const backupKey = `education_backup_${educationId}_${Date.now()}_${uuidv4()}`;
            await s3.upload({
                Bucket: process.env.S3_BACKUP_BUCKET,
                Key: backupKey,
                Body: JSON.stringify({
                    education,
                    action,
                    userId,
                    timestamp: new Date(),
                }),
                ContentType: 'application/json',
                ServerSideEncryption: 'AES256',
            }).promise();

            metricsCollector.increment('education_service.backup_created', { action });
            logger.info(`Backup created for education ${educationId} (${action}) in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to create backup for education ${educationId}:`, error);
            metricsCollector.increment('education_service.backup_failed');
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
            institution: sanitizeHtml(data.institution || ''),
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
                must: query ? { multi_match: { query, fields: ['title', 'institution', 'description'] } } : { match_all: {} },
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
     * @param {Object} education - Education document
     * @param {string} action - Action type
     * @returns {boolean} - Permission granted
     */
    hasPermission(userId, education, action) {
        const creatorId = education.metadata?.createdBy?.userId?.toString();
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
            return new AppError('Education record already exists', 409);
        }
        if (error.name === 'CastError') {
            return new AppError('Invalid education ID', 400);
        }
        if (error.message.includes('timeout')) {
            return new AppError('Operation timed out', 504);
        }
        return new AppError('Operation failed', 500);
    }
}

export default new EducationService();