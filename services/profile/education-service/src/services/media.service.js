import AWS from 'aws-sdk';
import { s3Client } from '../config/s3.js';
import { elasticsearchClient } from '../config/elasticsearch.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { metricsCollector } from '../utils/metrics.js';
import { cacheService } from '../services/cache.service.js';
import { createRateLimiter } from '../utils/rateLimiter.js';
import { CircuitBreaker } from '../utils/circuitBreaker.js';
import { retry } from '../utils/retry.js';
import mongoose from 'mongoose';
import Media from '../models/Media.js';
import { NotificationService } from './NotificationService.js';
import sanitizeHtml from 'sanitize-html';
import { v4 as uuidv4 } from 'uuid';
import moment from 'moment';
import axios from 'axios';

// Rate limiters for high concurrency
const uploadLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000, // 10-minute window
    max: 15, // Allow 15 uploads per user
    skipSuccessfulRequests: true,
    keyGenerator: (data) => `media_upload_${data.userId}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const scanLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30-minute window
    max: 5, // Strict limit for external scan API
    skipSuccessfulRequests: true,
    keyGenerator: (data) => `media_scan_${data.userId}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const deleteLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5-minute window
    max: 20, // Allow 20 deletions
    skipSuccessfulRequests: true,
    keyGenerator: (data) => `media_delete_${data.userId}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

class MediaService {
    constructor() {
        this.notificationService = new NotificationService();
        this.circuitBreaker = new CircuitBreaker({
            timeout: 10000,
            errorThresholdPercentage: 50,
            resetTimeout: 30000,
        });
        this.retryConfig = {
            retries: 3,
            delay: 100,
            backoff: 'exponential',
        };
        this.allowedFileTypes = ['image/jpeg', 'image/png', 'application/pdf'];
        this.maxFileSize = 5 * 1024 * 1024; // 5MB
    }

    /**
     * Upload media to S3 and store metadata
     * @param {Object} data - Upload data (files, entityId, entityType, userId, category)
     * @param {Object} options - Mongoose session options
     * @returns {Promise<Array>} - Array of uploaded media metadata
     */
    async uploadMedia(data, options = {}) {
        const startTime = Date.now();
        const { files, entityId, entityType, userId, category } = data;

        await uploadLimiter({ userId }, null, () => { });

        if (!files || files.length === 0) {
            throw new AppError('No files provided', Proj 400);
        }

        if (!this.validateEntityType(entityType)) {
            throw new AppError(`Invalid entity type: ${entityType}`, 400);
        }

        const session = options.session || await mongoose.startSession();
        try {
            if (!options.session) session.startTransaction();

            const uploadPromises = files.map(async (file) => {
                if (!this.validateFile(file)) {
                    throw new AppError(`Invalid file: ${file.originalname}`, 422);
                }

                const fileKey = `media/${entityType}/${entityId}/${uuidv4()}_${file.originalname}`;
                const uploadParams = {
                    Bucket: 'app-media-bucket',
                    Key: fileKey,
                    Body: file.buffer,
                    ContentType: file.mimetype,
                    Metadata: {
                        userId,
                        entityType,
                        entityId,
                        category: category || 'general',
                    },
                };

                const uploadResult = await this.circuitBreaker.fire(async () => {
                    return await retry(() => s3Client.upload(uploadParams).promise(), this.retryConfig);
                });

                const mediaRecord = {
                    entityId,
                    entityType,
                    userId,
                    fileName: file.originalname,
                    fileType: file.mimetype,
                    fileSize: file.size,
                    url: uploadResult.Location,
                    category: category || 'general',
                    status: 'pending',
                    metadata: {
                        createdBy: { userId },
                        version: 1,
                        uploadSource: 'direct',
                    },
                    analytics: {
                        views: { total: 0, unique: 0, byDate: [] },
                        downloads: { total: 0, byDate: [] },
                    },
                };

                const media = await Media.create([mediaRecord], { session });
                return media[0];
            });

            const uploadedMedia = await Promise.all(uploadPromises);

            for (const media of uploadedMedia) {
                this.indexForSearch(media).catch((err) => {
                    logger.error(`Failed to index media ${media._id}:`, err);
                });
            }

            metricsCollector.increment('media.uploaded', { entityId, entityType, count: uploadedMedia.length });
            metricsCollector.timing('media.upload_time', Date.now() - startTime);

            if (!options.session) await session.commitTransaction();
            return uploadedMedia.map(m => ({
                id: m._id,
                fileName: m.fileName,
                fileType: m.fileType,
                fileSize: m.fileSize,
                url: m.url,
                category: m.category,
            }));
        } catch (error) {
            if (!options.session) await session.abortTransaction();
            logger.error(`Media upload failed for user ${userId}:`, { error: error.message });
            metricsCollector.increment('media.upload_failed', { entityId, entityType });
            throw error instanceof AppError ? error : new AppError('Failed to upload media', 500);
        } finally {
            if (!options.session) session.endSession();
        }
    }

    /**
     * Scan media for security issues
     * @param {Array} mediaItems - Array of media items to scan (id, url)
     * @returns {Promise<Array>} - Array of scan results
     */
    async scanMedia(mediaItems) {
        const startTime = Date.now();
        if (!mediaItems || mediaItems.length === 0) {
            throw new AppError('No media items provided for scanning', 400);
        }

        await scanLimiter({ userId: mediaItems[0].userId }, null, () => { });

        try {
            const scanPromises = mediaItems.map(async (item) => {
                const scanResult = await this.circuitBreaker.fire(async () => {
                    return await retry(async () => {
                        const response = await axios.post('https://virus-scanner-api.example.com/scan', { url: item.url });
                        return {
                            id: item.id,
                            infected: response.data.infected,
                            details: response.data.details || [],
                        };
                    }, this.retryConfig);
                });

                if (scanResult.infected) {
                    await this.notificationService.notifyUser({
                        userId: item.userId,
                        message: `Media ${item.id} is potentially infected and has been quarantined`,
                        type: 'security_alert',
                    });
                }

                return scanResult;
            });

            const results = await Promise.all(scanPromises);
            metricsCollector.increment('media.scanned', { count: results.length, infected: results.filter(r => r.infected).length });
            metricsCollector.timing('media.scan_time', Date.now() - startTime);
            return results;
        } catch (error) {
            logger.error(`Media scan failed:`, { error: error.message });
            metricsCollector.increment('media.scan_failed', { count: mediaItems.length });
            throw error instanceof AppError ? error : new AppError('Failed to scan media', 424);
        }
    }

    /**
     * Delete media from S3 and database
     * @param {Array} mediaIds - Array of media IDs to delete
     * @param {Object} options - Mongoose session options
     * @returns {Promise<void>}
     */
    async deleteMedia(mediaIds, options = {}) {
        const startTime = Date.now();
        if (!mediaIds || mediaIds.length === 0) {
            throw new AppError('No media IDs provided', 400);
        }

        const session = options.session || await mongoose.startSession();
        try {
            if (!options.session) session.startTransaction();

            const mediaItems = await Media.find({ _id: { $in: mediaIds } }).session(session);
            if (mediaItems.length === 0) {
                throw new AppError('No media found for provided IDs', 404);
            }

            const deletePromises = mediaItems.map(async (media) => {
                await deleteLimiter({ userId: media.userId }, null, () => { });
                const fileKey = media.url.split('app-media-bucket/')[1];
                await this.circuitBreaker.fire(async () => {
                    await retry(() => s3Client.deleteObject({
                        Bucket: 'app-media-bucket',
                        Key: fileKey,
                    }).promise(), this.retryConfig);
                });
            });

            await Promise.all(deletePromises);
            await Media.deleteMany({ _id: { $in: mediaIds } }, { session });

            for (const media of mediaItems) {
                await cacheService.deletePattern(`media:${media._id}:*`);
                await this.removeFromSearch(media._id);
            }

            metricsCollector.increment('media.deleted', { count: mediaItems.length });
            metricsCollector.timing('media.delete_time', Date.now() - startTime);

            if (!options.session) await session.commitTransaction();
        } catch (error) {
            if (!options.session) await session.abortTransaction();
            logger.error(`Media deletion failed:`, { error: error.message });
            metricsCollector.increment('media.delete_failed', { count: mediaIds.length });
            throw error instanceof AppError ? error : new AppError('Failed to delete media', 500);
        } finally {
            if (!options.session) session.endSession();
        }
    }

    /**
     * Get signed URL for media access
     * @param {String} mediaId - Media ID
     * @param {Number} expires - Expiry time in seconds
     * @returns {Promise<String>} - Signed URL
     */
    async getSignedUrl(mediaId, expires = 3600) {
        const startTime = Date.now();
        const media = await Media.findById(mediaId).lean();
        if (!media || media.status === 'deleted') {
            throw new AppError('Media not found', 404);
        }

        try {
            const fileKey = media.url.split('app-media-bucket/')[1];
            const signedUrl = await this.circuitBreaker.fire(async () => {
                return await retry(() => s3Client.getSignedUrlPromise('getObject', {
                    Bucket: 'app-media-bucket',
                    Key: fileKey,
                    Expires: expires,
                }), this.retryConfig);
            });

            metricsCollector.increment('media.signed_url_generated', { mediaId });
            metricsCollector.timing('media.signed_url_time', Date.now() - startTime);
            return signedUrl;
        } catch (error) {
            logger.error(`Failed to generate signed URL for media ${mediaId}:`, { error: error.message });
            metricsCollector.increment('media.signed_url_failed', { mediaId });
            throw error instanceof AppError ? error : new AppError('Failed to generate signed URL', 500);
        }
    }

    /**
     * Update media metadata
     * @param {String} mediaId - Media ID
     * @param {Object} updates - Metadata updates
     * @param {Object} options - Mongoose session options
     * @returns {Promise<Object>} - Updated media record
     */
    async updateMediaMetadata(mediaId, updates, options = {}) {
        const startTime = Date.now();
        const sanitizedUpdates = this.sanitizeUpdates(updates);
        if (Object.keys(sanitizedUpdates).length === 0) {
            throw new AppError('No valid update fields provided', 400);
        }

        const session = options.session || await mongoose.startSession();
        try {
            if (!options.session) session.startTransaction();

            const media = await Media.findById(mediaId).session(session);
            if (!media || media.status === 'deleted') {
                throw new AppError('Media not found', 404);
            }

            Object.assign(media, sanitizedUpdates);
            media.metadata.version += 1;
            media.metadata.updateCount += 1;
            media.metadata.lastModifiedBy = {
                userId: updates.userId,
                timestamp: new Date(),
                changes: Object.keys(sanitizedUpdates),
            };

            await media.save({ session });
            await cacheService.deletePattern(`media:${mediaId}:*`);
            await this.indexForSearch(media);

            metricsCollector.increment('media.metadata_updated', { mediaId });
            metricsCollector.timing('media.metadata_update_time', Date.now() - startTime);

            if (!options.session) await session.commitTransaction();
            return media;
        } catch (error) {
            if (!options.session) await session.abortTransaction();
            logger.error(`Media metadata update failed for ${mediaId}:`, { error: error.message });
            metricsCollector.increment('media.metadata_update_failed', { mediaId });
            throw error instanceof AppError ? error : new AppError('Failed to update media metadata', 500);
        } finally {
            if (!options.session) session.endSession();
        }
    }

    /**
     * Get media analytics
     * @param {String} mediaId - Media ID
     * @returns {Promise<Object>} - Analytics data
     */
    async getMediaAnalytics(mediaId) {
        const startTime = Date.now();
        const cacheKey = `media_analytics:${mediaId}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('media.analytics_cache_hit', { mediaId });
                return cached;
            }

            const media = await Media.findById(mediaId).select('analytics').lean();
            if (!media || media.status === 'deleted') {
                throw new AppError('Media not found', 404);
            }

            const analytics = this.computeAnalytics(media.analytics);
            await cacheService.set(cacheKey, analytics, 300, [`media_analytics:${mediaId}`]);

            metricsCollector.increment('media.analytics_fetched', { mediaId });
            metricsCollector.timing('media.analytics_time', Date.now() - startTime);
            return analytics;
        } catch (error) {
            logger.error(`Failed to fetch analytics for media ${mediaId}:`, { error: error.message });
            metricsCollector.increment('media.analytics_failed', { mediaId });
            throw error instanceof AppError ? error : new AppError('Failed to fetch media analytics', 500);
        }
    }

    /**
     * Bulk delete media
     * @param {Array} mediaIds - Array of media IDs
     * @param {Object} options - Mongoose session options
     * @returns {Promise<void>}
     */
    async bulkDeleteMedia(mediaIds, options = {}) {
        const startTime = Date.now();
        if (!mediaIds || mediaIds.length === 0 || mediaIds.length > 50) {
            throw new AppError('Invalid media IDs or too many IDs (max 50)', 400);
        }

        const session = options.session || await mongoose.startSession();
        try {
            if (!options.session) session.startTransaction();

            const mediaItems = await Media.find({ _id: { $in: mediaIds } }).session(session);
            if (mediaItems.length === 0) {
                throw new AppError('No media found for provided IDs', 404);
            }

            const deletePromises = mediaItems.map(async (media) => {
                await deleteLimiter({ userId: media.userId }, null, () => { });
                const fileKey = media.url.split('app-media-bucket/')[1];
                await this.circuitBreaker.fire(async () => {
                    await retry(() => s3Client.deleteObject({
                        Bucket: 'app-media-bucket',
                        Key: fileKey,
                    }).promise(), this.retryConfig);
                });
            });

            await Promise.all(deletePromises);
            await Media.deleteMany({ _id: { $in: mediaIds } }, { session });

            for (const media of mediaItems) {
                await cacheService.deletePattern(`media:${media._id}:*`);
                await this.removeFromSearch(media._id);
            }

            metricsCollector.increment('media.bulk_deleted', { count: mediaItems.length });
            metricsCollector.timing('media.bulk_delete_time', Date.now() - startTime);

            if (!options.session) await session.commitTransaction();
        } catch (error) {
            if (!options.session) await session.abortTransaction();
            logger.error(`Bulk media deletion failed:`, { error: error.message });
            metricsCollector.increment('media.bulk_delete_failed', { count: mediaIds.length });
            throw error instanceof AppError ? error : new AppError('Failed to bulk delete media', 500);
        } finally {
            if (!options.session) session.endSession();
        }
    }

    /**
     * Validate file type and size
     * @param {Object} file - File object
     * @returns {Boolean} - Validation result
     */
    validateFile(file) {
        if (!this.allowedFileTypes.includes(file.mimetype)) {
            return false;
        }
        if (file.size > this.maxFileSize) {
            return false;
        }
        return true;
    }

    /**
     * Validate entity type
     * @param {String} entityType - Entity type
     * @returns {Boolean} - Validation result
     */
    validateEntityType(entityType) {
        const validTypes = ['course', 'organization', 'project'];
        return validTypes.includes(entityType.toLowerCase());
    }

    /**
     * Sanitize metadata updates
     * @param {Object} updates - Metadata updates
     * @returns {Object} - Sanitized updates
     */
    sanitizeUpdates(updates) {
        const allowedFields = ['category', 'status'];
        const sanitized = {};
        for (const [key, value] of Object.entries(updates)) {
            if (allowedFields.includes(key)) {
                sanitized[key] = key === 'category' ? sanitizeHtml(value) : value;
            }
        }
        return sanitized;
    }

    /**
     * Index media for search
     * @param {Object} media - Media document
     * @returns {Promise<void>}
     */
    async indexForSearch(media) {
        try {
            await elasticsearchClient.index({
                index: 'media',
                id: media._id.toString(),
                body: {
                    entityId: media.entityId,
                    entityType: media.entityType,
                    userId: media.userId,
                    fileName: media.fileName,
                    category: media.category,
                    status: media.status,
                    createdAt: media.createdAt,
                },
            });
            metricsCollector.increment('media.indexed', { mediaId: media._id });
        } catch (error) {
            logger.error(`Failed to index media ${media._id}:`, { error: error.message });
            metricsCollector.increment('media.index_failed', { mediaId: media._id });
        }
    }

    /**
     * Remove media from search index
     * @param {String} mediaId - Media ID
     * @returns {Promise<void>}
     */
    async removeFromSearch(mediaId) {
        try {
            await elasticsearchClient.delete({
                index: 'media',
                id: mediaId,
            });
            metricsCollector.increment('media.removed_from_search', { mediaId });
        } catch (error) {
            logger.error(`Failed to remove media ${mediaId} from search:`, { error: error.message });
        }
    }

    /**
     * Create backup of media metadata
     * @param {String} mediaId - Media ID
     * @param {String} action - Action type
     * @param {String} userId - User ID
     * @param {Object} options - Mongoose session options
     * @returns {Promise<void>}
     */
    async createBackup(mediaId, action, userId, options = {}) {
        try {
            const media = await Media.findById(mediaId).session(options.session);
            if (!media) return;

            const backupKey = `backups/media/${mediaId}/${Date.now()}.json`;
            await s3Client.upload({
                Bucket: 'user-backups',
                Key: backupKey,
                Body: Buffer.from(JSON.stringify(media)),
                ContentType: 'application/json',
            }).promise();

            logger.info(`Backup created for media ${mediaId} by ${userId} for action ${action}`);
            metricsCollector.increment('media.backup_created', { mediaId, action });
        } catch (error) {
            logger.error(`Backup failed for media ${mediaId}:`, { error: error.message });
            metricsCollector.increment('media.backup_failed', { mediaId });
        }
    }

    /**
     * Compute analytics data
     * @param {Object} analytics - Analytics data
     * @returns {Object} - Computed analytics
     */
    computeAnalytics(analytics) {
        const viewsByMonth = analytics.views.byDate.reduce((acc, entry) => {
            const month = moment(entry.date).format('YYYY-MM');
            acc[month] = (acc[month] || 0) + entry.count;
            return acc;
        }, {});

        const downloadsByMonth = analytics.downloads.byDate.reduce((acc, entry) => {
            const month = moment(entry.date).format('YYYY-MM');
            acc[month] = (acc[month] || 0) + entry.count;
            return acc;
        }, {});

        return {
            totalViews: analytics.views.total || 0,
            uniqueViews: analytics.views.unique || 0,
            viewsByMonth,
            totalDownloads: analytics.downloads.total || 0,
            downloadsByMonth,
        };
    }

    /**
     * Update media analytics
     * @param {String} mediaId - Media ID
     * @param {String} type - Analytics type (view/download)
     * @param {String} userId - User ID
     * @returns {Promise<void>}
     */
    async updateAnalytics(mediaId, type, userId) {
        const startTime = Date.now();
        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const media = await Media.findById(mediaId).session(session);
            if (!media || media.status === 'deleted') {
                throw new AppError('Media not found', 404);
            }

            const today = moment().startOf('day').toDate();
            if (type === 'view') {
                media.analytics.views.total += 1;
                if (!media.analytics.views.byDate) media.analytics.views.byDate = [];
                const viewEntry = media.analytics.views.byDate.find(v => v.date.toDateString() === today.toDateString());
                if (viewEntry) {
                    viewEntry.count += 1;
                } else {
                    media.analytics.views.byDate.push({ date: today, count: 1 });
                }
            } else if (type === 'download') {
                media.analytics.downloads.total += 1;
                if (!media.analytics.downloads.byDate) media.analytics.downloads.byDate = [];
                const downloadEntry = media.analytics.downloads.byDate.find(d => d.date.toDateString() === today.toDateString());
                if (downloadEntry) {
                    downloadEntry.count += 1;
                } else {
                    media.analytics.downloads.byDate.push({ date: today, count: 1 });
                }
            }

            await media.save({ session });
            await cacheService.deletePattern(`media_analytics:${mediaId}:*`);

            metricsCollector.increment(`media.${type}_recorded`, { mediaId });
            metricsCollector.timing(`media.${type}_update_time`, Date.now() - startTime);

            await session.commitTransaction();
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Failed to update ${type} analytics for media ${mediaId}:`, { error: error.message });
            metricsCollector.increment(`media.${type}_update_failed`, { mediaId });
            throw error instanceof AppError ? error : new AppError(`Failed to update ${type} analytics`, 500);
        } finally {
            session.endSession();
        }
    }
}

export default new MediaService();