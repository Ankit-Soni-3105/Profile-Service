import mongoose from 'mongoose';
import Thesis from '../models/Thesis.js';
import VerificationService from './VerificationService.js';
import MediaService from './MediaService.js';
import NotificationService from './NotificationService.js';
import SchoolService from './SchoolService.js';
import EducationService from './EducationService.js';
import DegreeService from './DegreeService.js';
import { validateThesis } from '../validations/thesis.validation.js';
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

// Rate limiters for thesis operations
const createThesisLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15-minute window
    max: 5, // Allow 5 thesis creations
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_thesis_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const updateThesisLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5-minute window
    max: 15, // Allow 15 updates
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_thesis_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const bulkThesisLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // Hourly limit
    max: 3, // Conservative limit for bulk operations
    keyGenerator: (req) => `bulk_thesis_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

class ThesisService {
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
     * Create a new thesis
     * Creates a thesis record with validation, caching, and async processing.
     * @param {Object} thesisData - Thesis data
     * @param {Object} options - Mongoose session and other options
     * @returns {Promise<Object>} Created thesis
     */
    async createThesis(thesisData, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;
        const validation = validateThesis(thesisData);
        if (!validation.valid) {
            metricsCollector.increment('thesis.validation_failed', { errors: validation.errors.length });
            throw new AppError(`Validation failed: ${validation.message}`, 400);
        }

        const sanitizedData = this.sanitizeInput(thesisData);
        sanitizedData.title = sanitizedData.title?.trim();
        sanitizedData.submissionDate = new Date(sanitizedData.submissionDate) || null;

        if (sanitizedData.schoolId) {
            const school = await this.schoolService.getSchoolById(sanitizedData.schoolId, { session });
            if (!school || school.status !== 'active') {
                throw new AppError('Invalid or inactive school association', 400);
            }
        }

        if (sanitizedData.degreeId) {
            const degree = await this.degreeService.getDegreeById(sanitizedData.degreeId, { session });
            if (!degree || degree.userId.toString() !== sanitizedData.userId) {
                throw new AppError('Invalid degree association', 400);
            }
        }

        const sessionOptions = session ? { session } : {};
        try {
            const thesis = await Thesis.create([{
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

            if (sanitizedData.degreeId) {
                await this.degreeService.linkThesisToDegree(sanitizedData.degreeId, thesis[0]._id, sessionOptions);
            }

            this.processNewThesisAsync(thesis[0]._id, thesis[0].userId).catch((err) => {
                logger.error(`Async processing failed for thesis ${thesis[0]._id}:`, err);
                metricsCollector.increment('thesis.async_processing_failed', { thesisId: thesis[0]._id });
            });

            metricsCollector.increment('thesis.created', {
                userId: thesis[0].userId,
                title: thesis[0].title,
                schoolId: thesis[0].schoolId,
                degreeId: thesis[0].degreeId,
            });
            metricsCollector.timing('thesis.create_time', Date.now() - startTime);

            eventEmitter.emit('thesis.created', {
                thesisId: thesis[0]._id,
                userId: thesis[0].userId,
                schoolId: thesis[0].schoolId,
                degreeId: thesis[0].degreeId,
                title: thesis[0].title,
            });

            return thesis[0];
        } catch (error) {
            logger.error(`Thesis creation failed:`, { error: error.message, stack: error.stack });
            metricsCollector.increment('thesis.create_failed', { userId: thesisData.userId });
            throw error;
        }
    }

    /**
     * Get thesis by ID
     * Retrieves a thesis with optional population and caching.
     * @param {String} thesisId - Thesis ID
     * @param {Object} options - Query options
     * @returns {Promise<Object>} Thesis document
     */
    async getThesisById(thesisId, options = {}) {
        const startTime = Date.now();
        const cacheKey = `thesis:${thesisId}:${JSON.stringify(options)}`;
        const cached = await cacheService.get(cacheKey);
        if (cached) {
            metricsCollector.increment('thesis.cache_hit', { thesisId });
            return cached;
        }

        try {
            const query = Thesis.findById(thesisId)
                .read('secondaryPreferred')
                .select(options.select || '-__v')
                .populate(options.populate || ['schoolId', 'degreeId']);
            if (options.session) query.session(options.session);

            const thesis = await query.lean({ virtuals: true });
            if (!thesis) {
                throw new AppError('Thesis not found', 404);
            }

            await cacheService.set(cacheKey, thesis, 600, ['theses:id:' + thesisId]);
            metricsCollector.increment('thesis.fetched', { thesisId });
            metricsCollector.timing('thesis.get_time', Date.now() - startTime);
            return thesis;
        } catch (error) {
            logger.error(`Failed to fetch thesis ${thesisId}:`, { error: error.message });
            metricsCollector.increment('thesis.fetch_failed', { thesisId });
            throw error;
        }
    }

    /**
     * Update thesis
     * Updates a thesis with versioning and re-verification.
     * @param {String} thesisId - Thesis ID
     * @param {Object} updates - Update data
     * @param {Object} options - Mongoose session and other options
     * @returns {Promise<Object>} Updated thesis
     */
    async updateThesis(thesisId, updates, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;
        const sanitizedUpdates = this.sanitizeUpdates(updates, this.getAllowedUpdateFields());

        const sessionOptions = session ? { session } : {};
        try {
            const thesis = await Thesis.findById(thesisId).session(session);
            if (!thesis) {
                throw new AppError('Thesis not found', 404);
            }

            if (sanitizedUpdates.title || sanitizedUpdates.abstract) {
                thesis.versions = thesis.versions || [];
                thesis.versions.push({
                    versionNumber: thesis.metadata.version + 1,
                    title: sanitizedUpdates.title || thesis.title,
                    abstract: sanitizedUpdates.abstract || thesis.abstract,
                    changeType: 'edit',
                    timestamp: new Date(),
                });
            }

            Object.assign(thesis, sanitizedUpdates);
            thesis.metadata.version += 1;
            thesis.metadata.updateCount += 1;
            thesis.metadata.lastModifiedBy = {
                userId: options.userId,
                timestamp: new Date(),
                changes: Object.keys(sanitizedUpdates),
            };

            if (['title', 'abstract', 'schoolId', 'degreeId'].some(field => sanitizedUpdates[field])) {
                thesis.verification.status = 'pending';
                this.processExternalVerification(thesis._id, thesis.userId).catch((err) => {
                    logger.error(`Re-verification failed for thesis ${thesis._id}:`, err);
                });
            }

            await thesis.save(sessionOptions);
            await Promise.all([
                cacheService.deletePattern(`thesis:${thesisId}:*`),
                cacheService.deleteByTag(['theses:id:' + thesisId]),
            ]);

            metricsCollector.increment('thesis.updated', { thesisId });
            metricsCollector.timing('thesis.update_time', Date.now() - startTime);
            eventEmitter.emit('thesis.updated', { thesisId, changes: Object.keys(sanitizedUpdates) });

            return thesis;
        } catch (error) {
            logger.error(`Thesis update failed for ${thesisId}:`, { error: error.message });
            metricsCollector.increment('thesis.update_failed', { thesisId });
            throw error;
        }
    }

    /**
     * Delete thesis
     * Supports soft and permanent deletion.
     * @param {String} thesisId - Thesis ID
     * @param {Object} options - Deletion options
     * @returns {Promise<void>}
     */
    async deleteThesis(thesisId, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;
        const permanent = options.permanent || false;
        const unlinkDegree = options.unlinkDegree || true;

        const sessionOptions = session ? { session } : {};
        try {
            const thesis = await Thesis.findById(thesisId).session(session);
            if (!thesis) {
                throw new AppError('Thesis not found', 404);
            }

            if (permanent) {
                await Thesis.findByIdAndDelete(thesisId, sessionOptions);
                await this.mediaService.deleteAllMedia(thesisId, 'thesis', sessionOptions);
                if (unlinkDegree && thesis.degreeId) {
                    await this.degreeService.unlinkThesisFromDegree(thesis.degreeId, thesisId, sessionOptions);
                }
            } else {
                thesis.status = 'deleted';
                thesis.privacy.isPublic = false;
                thesis.privacy.searchable = false;
                await thesis.save(sessionOptions);
            }

            await Promise.all([
                cacheService.deletePattern(`thesis:${thesisId}:*`),
                cacheService.deleteByTag(['theses:id:' + thesisId]),
            ]);

            metricsCollector.increment(`thesis.${permanent ? 'permanently_deleted' : 'soft_deleted'}`, { thesisId });
            metricsCollector.timing('thesis.delete_time', Date.now() - startTime);
            eventEmitter.emit('thesis.deleted', { thesisId, permanent, degreeUnlinked: unlinkDegree });
        } catch (error) {
            logger.error(`Thesis deletion failed for ${thesisId}:`, { error: error.message });
            metricsCollector.increment('thesis.delete_failed', { thesisId });
            throw error;
        }
    }

    /**
     * Link thesis to degree
     * Associates a thesis with a degree.
     * @param {String} degreeId - Degree ID
     * @param {String} thesisId - Thesis ID
     * @param {Object} options - Mongoose session
     * @returns {Promise<void>}
     */
    async linkThesisToDegree(degreeId, thesisId, options = {}) {
        const session = options.session || null;
        try {
            const degree = await Degree.findById(degreeId).session(session);
            if (!degree) {
                throw new AppError('Degree not found', 404);
            }

            degree.theses = degree.theses || [];
            if (!degree.theses.includes(thesisId)) {
                degree.theses.push(thesisId);
                await degree.save(options.session ? { session } : {});
            }

            metricsCollector.increment('thesis.degree_linked', { degreeId, thesisId });
            eventEmitter.emit('thesis.degree_linked', { degreeId, thesisId });
        } catch (error) {
            logger.error(`Failed to link thesis ${thesisId} to degree ${degreeId}:`, { error: error.message });
            throw error;
        }
    }

    /**
     * Unlink thesis from degree
     * Removes a thesis association from a degree.
     * @param {String} degreeId - Degree ID
     * @param {String} thesisId - Thesis ID
     * @param {Object} options - Mongoose session
     * @returns {Promise<void>}
     */
    async unlinkThesisFromDegree(degreeId, thesisId, options = {}) {
        const session = options.session || null;
        try {
            const degree = await Degree.findById(degreeId).session(session);
            if (!degree) {
                throw new AppError('Degree not found', 404);
            }

            degree.theses = degree.theses.filter(t => t.toString() !== thesisId.toString());
            await degree.save(options.session ? { session } : {});

            metricsCollector.increment('thesis.degree_unlinked', { degreeId, thesisId });
            eventEmitter.emit('thesis.degree_unlinked', { degreeId, thesisId });
        } catch (error) {
            logger.error(`Failed to unlink thesis ${thesisId} from degree ${degreeId}:`, { error: error.message });
            throw error;
        }
    }

    /**
     * Index thesis for search
     * Indexes thesis data in Elasticsearch for search capabilities.
     * @param {Object} thesis - Thesis document
     * @returns {Promise<void>}
     */
    async indexForSearch(thesis) {
        try {
            await elasticsearchClient.index({
                index: 'theses',
                id: thesis._id.toString(),
                body: {
                    userId: thesis.userId,
                    title: thesis.title,
                    abstract: thesis.abstract,
                    schoolId: thesis.schoolId,
                    degreeId: thesis.degreeId,
                    status: thesis.status,
                    createdAt: thesis.createdAt,
                    searchable: thesis.privacy.searchable,
                },
            });
            metricsCollector.increment('thesis.indexed', { thesisId: thesis._id });
        } catch (error) {
            logger.error(`Failed to index thesis ${thesis._id}:`, { error: error.message });
            throw error;
        }
    }

    /**
     * Async processing for new thesis
     * Handles verification and indexing.
     * @param {String} thesisId - Thesis ID
     * @param {String} userId - User ID
     * @returns {Promise<void>}
     */
    async processNewThesisAsync(thesisId, userId) {
        try {
            const thesis = await Thesis.findById(thesisId);
            if (!thesis) return;

            await this.verificationService.verifyThesis({
                thesisId,
                userId,
                title: thesis.title,
                abstract: thesis.abstract,
                schoolId: thesis.schoolId,
                degreeId: thesis.degreeId,
            });

            await this.indexForSearch(thesis);
            metricsCollector.increment('thesis.async_processed', { thesisId });
        } catch (error) {
            logger.error(`Async processing failed for thesis ${thesisId}:`, { error: error.message });
        }
    }

    /**
     * Sanitize input data
     * Sanitizes thesis input to prevent XSS and normalize data.
     * @param {Object} data - Input data
     * @returns {Object} Sanitized data
     */
    sanitizeInput(data) {
        const sanitized = { ...data };
        if (sanitized.abstract) {
            sanitized.abstract = sanitizeHtml(sanitized.abstract);
        }
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
            'abstract',
            'submissionDate',
            'schoolId',
            'degreeId',
            'tags',
            'privacy',
            'settings',
            'description',
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
                sanitized[key] = ['abstract', 'description'].includes(key) ? sanitizeHtml(value) : value;
            }
        }
        return sanitized;
    }

    /**
     * Process external verification
     * Initiates external verification for a thesis.
     * @param {String} thesisId - Thesis ID
     * @param {String} userId - User ID
     * @returns {Promise<void>}
     */
    async processExternalVerification(thesisId, userId) {
        try {
            const thesis = await Thesis.findById(thesisId);
            if (!thesis) return;

            await this.circuitBreaker.fire(async () => {
                await this.verificationService.verifyThesis({
                    thesisId,
                    userId,
                    title: thesis.title,
                    abstract: thesis.abstract,
                    schoolId: thesis.schoolId,
                    degreeId: thesis.degreeId,
                });
            });
            metricsCollector.increment('thesis.verification_processed', { thesisId });
        } catch (error) {
            logger.error(`External verification failed for thesis ${thesisId}:`, { error: error.message });
        }
    }
}

export default new ThesisService();