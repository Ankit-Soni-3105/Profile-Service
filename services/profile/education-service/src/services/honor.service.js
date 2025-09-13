import mongoose from 'mongoose';
import Honor from '../models/Honor.js';
import VerificationService from './VerificationService.js';
import MediaService from './MediaService.js';
import NotificationService from './NotificationService.js';
import SchoolService from './SchoolService.js';
import EducationService from './EducationService.js';
import DegreeService from './DegreeService.js';
import { validateHonor } from '../validations/honor.validation.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { catchAsync } from '../handler/catchAsync.js';
import { cacheService } from '../services/cache.service.js';
import { eventEmitter } from '../events/events.js';
import { metricsCollector } from '../utils/metrics.js';
import { createRateLimiter } from '../utils/rateLimiter.js';
import { CircuitBreaker } from '../utils/circuitBreaker.js';
import { retry } from '../utils/retry.js';
import { elasticsearchClient } from '../config/elasticsearch.js';
import { s3Client } from '../config/s3.js';
import crypto from 'crypto';
import sanitizeHtml from 'sanitize-html';

// Rate limiters for honor operations
const createHonorLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15-minute window
    max: 10, // Allow 10 honor creations
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_honor_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const updateHonorLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5-minute window
    max: 20, // Allow 20 updates
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_honor_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const bulkHonorLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // Hourly limit
    max: 5, // Conservative limit for bulk operations
    keyGenerator: (req) => `bulk_honor_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

class HonorService {
    constructor() {
        this.verificationService = VerificationService;
        this.mediaService = MediaService;
        this.notificationService = NotificationService;
        this.schoolService = SchoolService;
        this.educationService = EducationService;
        this.degreeService = DegreeService;
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
    }

    /**
     * Create a new honor
     * Creates an honor record with validation, caching, and async processing.
     * @param {Object} honorData - Honor data
     * @param {Object} options - Mongoose session and other options
     * @returns {Promise<Object>} Created honor
     */
    async createHonor(honorData, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;
        const validation = validateHonor(honorData);
        if (!validation.valid) {
            metricsCollector.increment('honor.validation_failed', { errors: validation.errors.length });
            throw new AppError(`Validation failed: ${validation.message}`, 400);
        }

        const sanitizedData = this.sanitizeInput(honorData);
        sanitizedData.title = sanitizedData.title?.trim();
        sanitizedData.awardDate = new Date(sanitizedData.awardDate) || null;

        if (sanitizedData.schoolId) {
            const school = await this.schoolService.getSchoolById(sanitizedData.schoolId, { session });
            if (!school || school.status !== 'active') {
                throw new AppError('Invalid or inactive school association', 400);
            }
        }

        const sessionOptions = session ? { session } : {};
        try {
            const honor = await Honor.create([{
                ...sanitizedData,
                metadata: {
                    ...sanitizedData.metadata,
                    createdBy: sanitizedData.metadata?.createdBy || { userId: sanitizedData.userId },
                    importSource: sanitizedData.metadata?.importSource || 'manual',
                    version: 1,
                },
                analytics: {
                    views: { total: 0, unique: 0, byDate: [] },
                    endorsements: { total: 0, byUser: [] },
                },
                verification: {
                    status: 'pending',
                    confidence: 0,
                    verifiedBy: null,
                    verifiedAt: null,
                    details: [],
                },
                status: 'draft',
                privacy: {
                    isPublic: false,
                    showDetails: true,
                    searchable: true,
                    visibleToConnections: true,
                    visibleToAlumni: true,
                },
            }], sessionOptions);

            this.processNewHonorAsync(honor[0]._id, honor[0].userId).catch((err) => {
                logger.error(`Async processing failed for honor ${honor[0]._id}:`, err);
                metricsCollector.increment('honor.async_processing_failed', { honorId: honor[0]._id });
            });

            metricsCollector.increment('honor.created', {
                userId: honor[0].userId,
                title: honor[0].title,
                schoolId: honor[0].schoolId,
            });
            metricsCollector.timing('honor.create_time', Date.now() - startTime);

            eventEmitter.emit('honor.created', {
                honorId: honor[0]._id,
                userId: honor[0].userId,
                schoolId: honor[0].schoolId,
                title: honor[0].title,
            });

            return honor[0];
        } catch (error) {
            logger.error(`Honor creation failed:`, { error: error.message, stack: error.stack });
            metricsCollector.increment('honor.create_failed', { userId: honorData.userId });
            throw error;
        }
    }

    /**
     * Get honor by ID
     * Retrieves an honor with optional population and caching.
     * @param {String} honorId - Honor ID
     * @param {Object} options - Query options
     * @returns {Promise<Object>} Honor document
     */
    async getHonorById(honorId, options = {}) {
        const startTime = Date.now();
        const cacheKey = `honor:${honorId}:${JSON.stringify(options)}`;
        const cached = await cacheService.get(cacheKey);
        if (cached) {
            metricsCollector.increment('honor.cache_hit', { honorId });
            return cached;
        }

        try {
            const query = Honor.findById(honorId)
                .read('secondaryPreferred')
                .select(options.select || '-__v')
                .populate(options.populate || ['schoolId']);
            if (options.session) query.session(options.session);

            const honor = await query.lean({ virtuals: true });
            if (!honor) {
                throw new AppError('Honor not found', 404);
            }

            await cacheService.set(cacheKey, honor, 600, ['honors:id:' + honorId]);
            metricsCollector.increment('honor.fetched', { honorId });
            metricsCollector.timing('honor.get_time', Date.now() - startTime);
            return honor;
        } catch (error) {
            logger.error(`Failed to fetch honor ${honorId}:`, { error: error.message });
            metricsCollector.increment('honor.fetch_failed', { honorId });
            throw error;
        }
    }

    /**
     * Update honor
     * Updates an honor with versioning and re-verification.
     * @param {String} honorId - Honor ID
     * @param {Object} updates - Update data
     * @param {Object} options - Mongoose session and other options
     * @returns {Promise<Object>} Updated honor
     */
    async updateHonor(honorId, updates, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;
        const sanitizedUpdates = this.sanitizeUpdates(updates, this.getAllowedUpdateFields());

        const sessionOptions = session ? { session } : {};
        try {
            const honor = await Honor.findById(honorId).session(session);
            if (!honor) {
                throw new AppError('Honor not found', 404);
            }

            if (sanitizedUpdates.title) {
                honor.versions = honor.versions || [];
                honor.versions.push({
                    versionNumber: honor.metadata.version + 1,
                    title: sanitizedUpdates.title || honor.title,
                    changeType: 'edit',
                    timestamp: new Date(),
                });
            }

            Object.assign(honor, sanitizedUpdates);
            honor.metadata.version += 1;
            honor.metadata.updateCount += 1;
            honor.metadata.lastModifiedBy = {
                userId: options.userId,
                timestamp: new Date(),
                changes: Object.keys(sanitizedUpdates),
            };

            if (['title', 'schoolId'].some(field => sanitizedUpdates[field])) {
                honor.verification.status = 'pending';
                this.processExternalVerification(honor._id, honor.userId).catch((err) => {
                    logger.error(`Re-verification failed for honor ${honor._id}:`, err);
                });
            }

            await honor.save(sessionOptions);
            await Promise.all([
                cacheService.deletePattern(`honor:${honorId}:*`),
                cacheService.deleteByTag(['honors:id:' + honorId]),
            ]);

            metricsCollector.increment('honor.updated', { honorId });
            metricsCollector.timing('honor.update_time', Date.now() - startTime);
            eventEmitter.emit('honor.updated', { honorId, changes: Object.keys(sanitizedUpdates) });

            return honor;
        } catch (error) {
            logger.error(`Honor update failed for ${honorId}:`, { error: error.message });
            metricsCollector.increment('honor.update_failed', { honorId });
            throw error;
        }
    }

    /**
     * Delete honor
     * Supports soft and permanent deletion.
     * @param {String} honorId - Honor ID
     * @param {Object} options - Deletion options
     * @returns {Promise<void>}
     */
    async deleteHonor(honorId, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;
        const permanent = options.permanent || false;

        const sessionOptions = session ? { session } : {};
        try {
            const honor = await Honor.findById(honorId).session(session);
            if (!honor) {
                throw new AppError('Honor not found', 404);
            }

            if (permanent) {
                await Honor.findByIdAndDelete(honorId, sessionOptions);
                await this.mediaService.deleteAllMedia(honorId, 'honor', sessionOptions);
            } else {
                honor.status = 'deleted';
                honor.privacy.isPublic = false;
                honor.privacy.searchable = false;
                await honor.save(sessionOptions);
            }

            await Promise.all([
                cacheService.deletePattern(`honor:${honorId}:*`),
                cacheService.deleteByTag(['honors:id:' + honorId]),
            ]);

            metricsCollector.increment(`honor.${permanent ? 'permanently_deleted' : 'soft_deleted'}`, { honorId });
            metricsCollector.timing('honor.delete_time', Date.now() - startTime);
            eventEmitter.emit('honor.deleted', { honorId, permanent });
        } catch (error) {
            logger.error(`Honor deletion failed for ${honorId}:`, { error: error.message });
            metricsCollector.increment('honor.delete_failed', { honorId });
            throw error;
        }
    }

    /**
     * Index honor for search
     * Indexes honor data in Elasticsearch for search capabilities.
     * @param {Object} honor - Honor document
     * @returns {Promise<void>}
     */
    async indexForSearch(honor) {
        try {
            await elasticsearchClient.index({
                index: 'honors',
                id: honor._id.toString(),
                body: {
                    userId: honor.userId,
                    title: honor.title,
                    schoolId: honor.schoolId,
                    status: honor.status,
                    createdAt: honor.createdAt,
                    searchable: honor.privacy.searchable,
                },
            });
            metricsCollector.increment('honor.indexed', { honorId: honor._id });
        } catch (error) {
            logger.error(`Failed to index honor ${honor._id}:`, { error: error.message });
            throw error;
        }
    }

    /**
     * Async processing for new honor
     * Handles verification and indexing.
     * @param {String} honorId - Honor ID
     * @param {String} userId - User ID
     * @returns {Promise<void>}
     */
    async processNewHonorAsync(honorId, userId) {
        try {
            const honor = await Honor.findById(honorId);
            if (!honor) return;

            await this.verificationService.verifyHonor({
                honorId,
                userId,
                title: honor.title,
                schoolId: honor.schoolId,
            });

            await this.indexForSearch(honor);
            metricsCollector.increment('honor.async_processed', { honorId });
        } catch (error) {
            logger.error(`Async processing failed for honor ${honorId}:`, { error: error.message });
        }
    }

    /**
     * Sanitize input data
     * Sanitizes honor input to prevent XSS and normalize data.
     * @param {Object} data - Input data
     * @returns {Object} Sanitized data
     */
    sanitizeInput(data) {
        const sanitized = { ...data };
        if (sanitized.description) {
            sanitized.description = sanitizeHtml(sanitized.description);
        }
        return sanitized;
    }

    /**
     * Get allowed update fields
     * Defines fields that can be updated.
     * @returns {Array} Allowed fields
     */
    getAllowedUpdateFields() {
        return [
            'title',
            'description',
            'awardDate',
            'schoolId',
            'tags',
            'privacy',
            'settings',
        ];
    }

    /**
     * Sanitize updates
     * Filters and sanitizes update fields.
     * @param {Object} updates - Update data
     * @param {Array} allowedFields - Allowed fields
     * @returns {Object} Sanitized updates
     */
    sanitizeUpdates(updates, allowedFields) {
        const sanitized = {};
        for (const [key, value] of Object.entries(updates)) {
            if (allowedFields.includes(key)) {
                sanitized[key] = key === 'description' ? sanitizeHtml(value) : value;
            }
        }
        return sanitized;
    }

    /**
     * Process external verification
     * Initiates external verification for an honor.
     * @param {String} honorId - Honor ID
     * @param {String} userId - User ID
     * @returns {Promise<void>}
     */
    async processExternalVerification(honorId, userId) {
        try {
            const honor = await Honor.findById(honorId);
            if (!honor) return;

            await this.circuitBreaker.fire(async () => {
                await this.verificationService.verifyHonor({
                    honorId,
                    userId,
                    title: honor.title,
                    schoolId: honor.schoolId,
                });
            });
            metricsCollector.increment('honor.verification_processed', { honorId });
        } catch (error) {
            logger.error(`External verification failed for honor ${honorId}:`, { error: error.message });
        }
    }
}

export default new HonorService();