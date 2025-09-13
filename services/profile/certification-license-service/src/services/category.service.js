import Category from '../models/Category.js';
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
const INDEX_NAME = 'categories';

// Validation schemas (assumed to be defined in category.validation.js)
import { validateCategory, validateMediaUpload } from '../validations/category.validation.js';

class CategoryService {
    /**
     * Create a new category
     * @param {Object} categoryData - Category data
     * @param {Object} options - Options including session
     * @returns {Promise<Object>} - Created category
     */
    async createCategory(categoryData, options = {}) {
        const startTime = Date.now();
        try {
            const sanitizedData = this.sanitizeData(categoryData);
            const category = new Category({
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

            await category.save(options);
            metricsCollector.increment('category_service.created');
            logger.info(`Category created: ${category._id} in ${Date.now() - startTime}ms`);

            return category;
        } catch (error) {
            logger.error(`Failed to create category:`, error);
            metricsCollector.increment('category_service.create_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Get category by ID
     * @param {string} id - Category ID
     * @param {string} userId - Requesting user ID
     * @returns {Promise<Object>} - Category document
     */
    async getCategoryById(id, userId) {
        const startTime = Date.now();
        try {
            const cacheKey = `category:${id}:${userId}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('category_service.cache_hit');
                return cached;
            }

            const category = await Category.findOne({
                _id: id,
                'status.isDeleted': false,
            })
                .read('secondaryPreferred')
                .select('name icon description parentId verification status analytics metadata media')
                .lean();

            if (!category) {
                throw new AppError('Category not found', 404);
            }

            await cacheService.set(cacheKey, category, 600);
            metricsCollector.increment('category_service.fetched');
            logger.info(`Fetched category ${id} in ${Date.now() - startTime}ms`);

            return category;
        } catch (error) {
            logger.error(`Failed to fetch category ${id}:`, error);
            metricsCollector.increment('category_service.fetch_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Update category
     * @param {string} id - Category ID
     * @param {string} userId - Requesting user ID
     * @param {Object} updates - Update data
     * @param {Object} options - Options including session and metadata
     * @returns {Promise<Object>} - Updated category
     */
    async updateCategory(id, userId, updates, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;
        try {
            const category = await Category.findOne({
                _id: id,
                'status.isDeleted': false,
            }).session(session);

            if (!category) {
                throw new AppError('Category not found', 404);
            }

            if (!this.hasPermission(userId, category, 'update')) {
                throw new AppError('Access denied', 403);
            }

            Object.assign(category, this.sanitizeData(updates));
            category.metadata.lastModifiedBy = {
                userId: options.requestingUserId || userId,
                ip: options.ip,
                userAgent: options.userAgent,
                timestamp: new Date(),
            };

            await category.save({ session });
            metricsCollector.increment('category_service.updated');
            logger.info(`Category updated: ${id} in ${Date.now() - startTime}ms`);

            return category;
        } catch (error) {
            logger.error(`Failed to update category ${id}:`, error);
            metricsCollector.increment('category_service.update_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Delete category
     * @param {string} id - Category ID
     * @param {string} userId - Requesting user ID
     * @param {boolean} permanent - Permanent deletion flag
     * @param {Object} options - Options including session
     */
    async deleteCategory(id, userId, permanent = false, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;
        try {
            const category = await Category.findOne({
                _id: id,
                'status.isDeleted': false,
            }).session(session);

            if (!category) {
                throw new AppError('Category not found', 404);
            }

            if (!this.hasPermission(userId, category, 'delete')) {
                throw new AppError('Access denied', 403);
            }

            // Check for subcategories
            const subCategories = await Category.countDocuments({
                parentId: id,
                'status.isDeleted': false,
            }).session(session);

            if (subCategories > 0 && permanent) {
                throw new AppError('Cannot permanently delete category with subcategories', 400);
            }

            if (permanent) {
                await category.deleteOne({ session });
            } else {
                category.status.isDeleted = true;
                category.status.deletedAt = new Date();
                await category.save({ session });
            }

            metricsCollector.increment(permanent ? 'category_service.permanently_deleted' : 'category_service.soft_deleted');
            logger.info(`Category ${id} deleted (permanent: ${permanent}) in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to delete category ${id}:`, error);
            metricsCollector.increment('category_service.delete_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Search categories
     * @param {string} query - Search query
     * @param {Object} filters - Additional filters
     * @param {Object} options - Pagination options
     * @returns {Promise<Object>} - Search results
     */
    async searchCategories(query, filters = {}, options = { page: 1, limit: 20 }) {
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

            metricsCollector.increment('category_service.searched', { count: hits.length });
            logger.info(`Search returned ${hits.length} categories in ${Date.now() - startTime}ms`);

            return {
                hits,
                totalHits,
                page: options.page,
                limit: options.limit,
                totalPages: Math.ceil(totalHits / options.limit),
            };
        } catch (error) {
            logger.error(`Search failed for query ${query}:`, error);
            metricsCollector.increment('category_service.search_failed');
            throw new AppError('Failed to search categories', 500);
        }
    }

    /**
     * Get trending categories
     * @param {string} timeframe - Timeframe (e.g., '30d')
     * @param {string} parentId - Parent category ID
     * @param {number} limit - Number of results
     * @returns {Promise<Array>} - Trending categories
     */
    async getTrendingCategories(timeframe, parentId, limit) {
        const startTime = Date.now();
        try {
            const cacheKey = `trending_categories:${timeframe}:${parentId || 'all'}:${limit}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('category_service.trending_cache_hit');
                return cached;
            }

            const query = {
                'status.isDeleted': false,
                'analytics.views': { $gt: 0 },
            };
            if (parentId) query.parentId = parentId;

            const categories = await Category.find(query)
                .read('secondaryPreferred')
                .sort({ 'analytics.views': -1 })
                .limit(limit)
                .select('name icon description parentId verification status analytics')
                .lean();

            await cacheService.set(cacheKey, categories, 300);
            metricsCollector.increment('category_service.trending_fetched', { count: categories.length });
            logger.info(`Fetched ${categories.length} trending categories in ${Date.now() - startTime}ms`);

            return categories;
        } catch (error) {
            logger.error(`Failed to fetch trending categories:`, error);
            metricsCollector.increment('category_service.trending_fetch_failed');
            throw new AppError('Failed to fetch trending categories', 500);
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
            metricsCollector.increment('category_service.media_validation_failed');
            throw new AppError('Media validation failed', 422);
        }
    }

    /**
     * Index category for search
     * @param {Object} category - Category document
     */
    async indexForSearch(category) {
        const startTime = Date.now();
        try {
            const indexData = {
                objectID: category._id.toString(),
                name: category.name,
                description: category.description,
                parentId: category.parentId?.toString(),
                status: category.status.workflow,
                createdAt: category.createdAt,
            };

            if (SEARCH_ENGINE === 'algolia') {
                await searchClient.saveObject({
                    indexName: INDEX_NAME,
                    body: indexData,
                });
            } else {
                await searchClient.index({
                    index: INDEX_NAME,
                    id: category._id.toString(),
                    body: indexData,
                });
            }

            metricsCollector.increment('category_service.indexed');
            logger.info(`Indexed category ${category._id} for search in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to index category ${category._id}:`, error);
            metricsCollector.increment('category_service.index_failed');
            throw new AppError('Failed to index category', 500);
        }
    }

    /**
     * Get category analytics
     * @param {string} id - Category ID
     * @param {string} timeframe - Timeframe (e.g., '30d')
     * @returns {Promise<Object>} - Analytics data
     */
    async getCategoryAnalytics(id, timeframe) {
        const startTime = Date.now();
        try {
            const cacheKey = `category_analytics:${id}:${timeframe}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('category_service.analytics_cache_hit');
                return cached;
            }

            const category = await Category.findById(id)
                .select('analytics metadata')
                .lean();

            if (!category) {
                throw new AppError('Category not found', 404);
            }

            const analytics = {
                views: category.analytics.views || 0,
                associatedItems: category.analytics.associatedItems || 0,
                timeframe,
                lastUpdated: category.metadata.lastModifiedBy?.timestamp || category.createdAt,
            };

            await cacheService.set(cacheKey, analytics, 300);
            metricsCollector.increment('category_service.analytics_fetched');
            logger.info(`Fetched analytics for category ${id} in ${Date.now() - startTime}ms`);

            return analytics;
        } catch (error) {
            logger.error(`Failed to fetch analytics for category ${id}:`, error);
            metricsCollector.increment('category_service.analytics_fetch_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Get category statistics
     * @param {string} id - Category ID
     * @returns {Promise<Object>} - Statistics
     */
    async getCategoryStats(id) {
        const startTime = Date.now();
        try {
            const cacheKey = `category_stats:${id}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('category_service.stats_cache_hit');
                return cached;
            }

            const category = await Category.findById(id)
                .select('analytics status createdAt')
                .lean();

            if (!category) {
                throw new AppError('Category not found', 404);
            }

            const subCategoryCount = await Category.countDocuments({
                parentId: id,
                'status.isDeleted': false,
            });

            const stats = {
                totalViews: category.analytics.views || 0,
                associatedItems: category.analytics.associatedItems || 0,
                subCategoryCount,
                status: category.status.workflow,
                ageInDays: Math.floor((Date.now() - new Date(category.createdAt)) / (1000 * 60 * 60 * 24)),
            };

            await cacheService.set(cacheKey, stats, 3600);
            metricsCollector.increment('category_service.stats_fetched');
            logger.info(`Fetched stats for category ${id} in ${Date.now() - startTime}ms`);

            return stats;
        } catch (error) {
            logger.error(`Failed to fetch stats for category ${id}:`, error);
            metricsCollector.increment('category_service.stats_fetch_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Get audit logs
     * @param {string} categoryId - Category ID
     * @param {Object} options - Options including page, limit, action
     * @returns {Promise<Array>} - Audit logs
     */
    async getAuditLogs(categoryId, options = { page: 1, limit: 20, action: null }) {
        const startTime = Date.now();
        try {
            const page = Math.max(1, options.page);
            const limit = Math.min(100, Math.max(1, options.limit));
            const skip = (page - 1) * limit;

            const query = { categoryId };
            if (options.action) query.action = options.action;

            const logs = await CategoryAuditLog.find(query) // Assumed model for audit logs
                .skip(skip)
                .limit(limit)
                .lean();

            metricsCollector.increment('category_service.audit_fetched', { count: logs.length });
            logger.info(`Fetched ${logs.length} audit logs for category ${categoryId} in ${Date.now() - startTime}ms`);

            return logs;
        } catch (error) {
            logger.error(`Failed to fetch audit logs for category ${categoryId}:`, error);
            metricsCollector.increment('category_service.audit_fetch_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Count audit logs
     * @param {string} categoryId - Category ID
     * @param {string} action - Action filter
     * @returns {Promise<number>} - Total count
     */
    async countAuditLogs(categoryId, action) {
        const startTime = Date.now();
        try {
            const query = { categoryId };
            if (action) query.action = action;

            const count = await CategoryAuditLog.countDocuments(query);
            logger.info(`Counted ${count} audit logs for category ${categoryId} in ${Date.now() - startTime}ms`);

            return count;
        } catch (error) {
            logger.error(`Failed to count audit logs for category ${categoryId}:`, error);
            throw this.handleError(error);
        }
    }

    /**
     * Update category analytics
     * @param {string} categoryId - Category ID
     * @param {Object} options - Options including session
     */
    async updateCategoryAnalytics(categoryId, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;
        try {
            const category = await Category.findById(categoryId).session(session);
            if (!category) {
                throw new AppError('Category not found', 404);
            }

            category.analytics = category.analytics || { views: 0, associatedItems: 0 };
            category.analytics.views += 1; // Example increment
            await category.save({ session });

            logger.info(`Updated analytics for category ${categoryId} in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to update analytics for category ${categoryId}:`, error);
            metricsCollector.increment('category_service.analytics_update_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Process new category asynchronously
     * @param {string} categoryId - Category ID
     * @param {string} userId - User ID
     * @param {string} action - Action type
     */
    async processNewCategoryAsync(categoryId, userId, action) {
        const startTime = Date.now();
        try {
            const category = await Category.findById(categoryId).lean();
            if (!category) {
                throw new AppError('Category not found', 404);
            }

            // Index for search
            await this.indexForSearch(category);

            // Create backup
            await this.createBackup(categoryId, action, userId);

            metricsCollector.increment('category_service.async_processed');
            logger.info(`Async processing completed for category ${categoryId} in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Async processing failed for category ${categoryId}:`, error);
            metricsCollector.increment('category_service.async_process_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Create backup
     * @param {string} categoryId - Category ID
     * @param {string} action - Action type
     * @param {string} userId - User ID
     */
    async createBackup(categoryId, action, userId) {
        const startTime = Date.now();
        try {
            const category = await Category.findById(categoryId).lean();
            if (!category) {
                throw new AppError('Category not found', 404);
            }

            const backupKey = `category_backup_${categoryId}_${Date.now()}_${uuidv4()}`;
            await s3.upload({
                Bucket: process.env.S3_BACKUP_BUCKET,
                Key: backupKey,
                Body: JSON.stringify({
                    category,
                    action,
                    userId,
                    timestamp: new Date(),
                }),
                ContentType: 'application/json',
                ServerSideEncryption: 'AES256',
            }).promise();

            metricsCollector.increment('category_service.backup_created', { action });
            logger.info(`Backup created for category ${categoryId} (${action}) in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to create backup for category ${categoryId}:`, error);
            metricsCollector.increment('category_service.backup_failed');
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
            icon: data.icon ? sanitizeHtml(data.icon) : undefined,
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
     * @param {Object} category - Category document
     * @param {string} action - Action type
     * @returns {boolean} - Permission granted
     */
    hasPermission(userId, category, action) {
        const creatorId = category.metadata?.createdBy?.userId?.toString();
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
            return new AppError('Category already exists', 409);
        }
        if (error.name === 'CastError') {
            return new AppError('Invalid category ID', 400);
        }
        if (error.message.includes('timeout')) {
            return new AppError('Operation timed out', 504);
        }
        return new AppError('Operation failed', 500);
    }
}

export default new CategoryService();