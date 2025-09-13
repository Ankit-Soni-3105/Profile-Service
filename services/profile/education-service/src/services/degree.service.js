import mongoose from 'mongoose';
import Degree from '../models/Degree.js';
import VerificationService from './VerificationService.js';
import MediaService from './MediaService.js';
import NotificationService from './NotificationService.js';
import SchoolService from './SchoolService.js';
import EducationService from './EducationService.js';
import { validateDegree } from '../validations/degree.validation.js';
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

// Rate limiters for degree operations
const createDegreeLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15-minute window
    max: 10, // Allow 10 degree creations
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_degree_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const updateDegreeLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5-minute window
    max: 20, // Allow 20 updates
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_degree_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const bulkDegreeLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // Hourly limit
    max: 5, // Conservative limit for bulk operations
    keyGenerator: (req) => `bulk_degree_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

class DegreeService {
    constructor() {
        this.verificationService = VerificationService;
        this.mediaService = MediaService;
        this.notificationService = NotificationService;
        this.schoolService = SchoolService;
        this.educationService = EducationService;
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
     * Create a new degree
     * Creates a degree record with validation, caching, and async processing.
     * @param {Object} degreeData - Degree data
     * @param {Object} options - Mongoose session and other options
     * @returns {Promise<Object>} Created degree
     */
    async createDegree(degreeData, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;
        const validation = validateDegree(degreeData);
        if (!validation.valid) {
            metricsCollector.increment('degree.validation_failed', { errors: validation.errors.length });
            throw new AppError(`Validation failed: ${validation.message}`, 400);
        }

        const sanitizedData = this.sanitizeInput(degreeData);
        sanitizedData.fieldOfStudy = sanitizedData.fieldOfStudy?.toLowerCase().trim();
        sanitizedData.degreeLevel = sanitizedData.degreeLevel?.toUpperCase().trim();

        if (sanitizedData.schoolId) {
            const school = await this.schoolService.getSchoolById(sanitizedData.schoolId, { session });
            if (!school || school.status !== 'active') {
                throw new AppError('Invalid or inactive school association', 400);
            }
        }

        const sessionOptions = session ? { session } : {};
        try {
            const degree = await Degree.create([{
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

            this.processNewDegreeAsync(degree[0]._id, degree[0].userId).catch((err) => {
                logger.error(`Async processing failed for degree ${degree[0]._id}:`, err);
                metricsCollector.increment('degree.async_processing_failed', { degreeId: degree[0]._id });
            });

            metricsCollector.increment('degree.created', {
                userId: degree[0].userId,
                degreeLevel: degree[0].degreeLevel,
                fieldOfStudy: degree[0].fieldOfStudy,
            });
            metricsCollector.timing('degree.create_time', Date.now() - startTime);

            eventEmitter.emit('degree.created', {
                degreeId: degree[0]._id,
                userId: degree[0].userId,
                schoolId: degree[0].schoolId,
                fieldOfStudy: degree[0].fieldOfStudy,
            });

            return degree[0];
        } catch (error) {
            logger.error(`Degree creation failed:`, { error: error.message, stack: error.stack });
            metricsCollector.increment('degree.create_failed', { userId: degreeData.userId });
            throw error;
        }
    }

    /**
     * Get degree by ID
     * Retrieves a degree with optional population and caching.
     * @param {String} degreeId - Degree ID
     * @param {Object} options - Query options
     * @returns {Promise<Object>} Degree document
     */
    async getDegreeById(degreeId, options = {}) {
        const startTime = Date.now();
        const cacheKey = `degree:${degreeId}:${JSON.stringify(options)}`;
        const cached = await cacheService.get(cacheKey);
        if (cached) {
            metricsCollector.increment('degree.cache_hit', { degreeId });
            return cached;
        }

        try {
            const query = Degree.findById(degreeId)
                .read('secondaryPreferred')
                .select(options.select || '-__v')
                .populate(options.populate || ['schoolId']);
            if (options.session) query.session(options.session);

            const degree = await query.lean({ virtuals: true });
            if (!degree) {
                throw new AppError('Degree not found', 404);
            }

            await cacheService.set(cacheKey, degree, 600, ['degrees:id:' + degreeId]);
            metricsCollector.increment('degree.fetched', { degreeId });
            metricsCollector.timing('degree.get_time', Date.now() - startTime);
            return degree;
        } catch (error) {
            logger.error(`Failed to fetch degree ${degreeId}:`, { error: error.message });
            metricsCollector.increment('degree.fetch_failed', { degreeId });
            throw error;
        }
    }

    /**
     * Update degree
     * Updates a degree with versioning and re-verification.
     * @param {String} degreeId - Degree ID
     * @param {Object} updates - Update data
     * @param {Object} options - Mongoose session and other options
     * @returns {Promise<Object>} Updated degree
     */
    async updateDegree(degreeId, updates, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;
        const sanitizedUpdates = this.sanitizeUpdates(updates, this.getAllowedUpdateFields());

        const sessionOptions = session ? { session } : {};
        try {
            const degree = await Degree.findById(degreeId).session(session);
            if (!degree) {
                throw new AppError('Degree not found', 404);
            }

            if (sanitizedUpdates.fieldOfStudy || sanitizedUpdates.degreeLevel) {
                degree.versions = degree.versions || [];
                degree.versions.push({
                    versionNumber: degree.metadata.version + 1,
                    fieldOfStudy: sanitizedUpdates.fieldOfStudy || degree.fieldOfStudy,
                    degreeLevel: sanitizedUpdates.degreeLevel || degree.degreeLevel,
                    changeType: 'edit',
                    timestamp: new Date(),
                });
            }

            Object.assign(degree, sanitizedUpdates);
            degree.metadata.version += 1;
            degree.metadata.updateCount += 1;
            degree.metadata.lastModifiedBy = {
                userId: options.userId,
                timestamp: new Date(),
                changes: Object.keys(sanitizedUpdates),
            };

            if (['fieldOfStudy', 'degreeLevel', 'schoolId'].some(field => sanitizedUpdates[field])) {
                degree.verification.status = 'pending';
                this.processExternalVerification(degree._id, degree.userId).catch((err) => {
                    logger.error(`Re-verification failed for degree ${degree._id}:`, err);
                });
            }

            await degree.save(sessionOptions);
            await Promise.all([
                cacheService.deletePattern(`degree:${degreeId}:*`),
                cacheService.deleteByTag(['degrees:id:' + degreeId]),
            ]);

            metricsCollector.increment('degree.updated', { degreeId });
            metricsCollector.timing('degree.update_time', Date.now() - startTime);
            eventEmitter.emit('degree.updated', { degreeId, changes: Object.keys(sanitizedUpdates) });

            return degree;
        } catch (error) {
            logger.error(`Degree update failed for ${degreeId}:`, { error: error.message });
            metricsCollector.increment('degree.update_failed', { degreeId });
            throw error;
        }
    }

    /**
     * Delete degree
     * Supports soft and permanent deletion.
     * @param {String} degreeId - Degree ID
     * @param {Object} options - Deletion options
     * @returns {Promise<void>}
     */
    async deleteDegree(degreeId, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;
        const permanent = options.permanent || false;

        const sessionOptions = session ? { session } : {};
        try {
            const degree = await Degree.findById(degreeId).session(session);
            if (!degree) {
                throw new AppError('Degree not found', 404);
            }

            if (permanent) {
                await Degree.findByIdAndDelete(degreeId, sessionOptions);
                await this.mediaService.deleteAllMedia(degreeId, 'degree', sessionOptions);
            } else {
                degree.status = 'deleted';
                degree.privacy.isPublic = false;
                degree.privacy.searchable = false;
                await degree.save(sessionOptions);
            }

            await Promise.all([
                cacheService.deletePattern(`degree:${degreeId}:*`),
                cacheService.deleteByTag(['degrees:id:' + degreeId]),
            ]);

            metricsCollector.increment(`degree.${permanent ? 'permanently_deleted' : 'soft_deleted'}`, { degreeId });
            metricsCollector.timing('degree.delete_time', Date.now() - startTime);
            eventEmitter.emit('degree.deleted', { degreeId, permanent });
        } catch (error) {
            logger.error(`Degree deletion failed for ${degreeId}:`, { error: error.message });
            metricsCollector.increment('degree.delete_failed', { degreeId });
            throw error;
        }
    }

    /**
     * Link grade to degree
     * Associates a grade with a degree.
     * @param {String} degreeId - Degree ID
     * @param {String} gradeId - Grade ID
     * @param {Object} options - Mongoose session
     * @returns {Promise<void>}
     */
    async linkGradeToDegree(degreeId, gradeId, options = {}) {
        const session = options.session || null;
        try {
            const degree = await Degree.findById(degreeId).session(session);
            if (!degree) {
                throw new AppError('Degree not found', 404);
            }

            degree.grades = degree.grades || [];
            if (!degree.grades.includes(gradeId)) {
                degree.grades.push(gradeId);
                await degree.save(options.session ? { session } : {});
            }

            metricsCollector.increment('degree.grade_linked', { degreeId, gradeId });
            eventEmitter.emit('degree.grade_linked', { degreeId, gradeId });
        } catch (error) {
            logger.error(`Failed to link grade ${gradeId} to degree ${degreeId}:`, { error: error.message });
            throw error;
        }
    }

    /**
     * Unlink grade from degree
     * Removes a grade association from a degree.
     * @param {String} degreeId - Degree ID
     * @param {String} gradeId - Grade ID
     * @param {Object} options - Mongoose session
     * @returns {Promise<void>}
     */
    async unlinkGradeFromDegree(degreeId, gradeId, options = {}) {
        const session = options.session || null;
        try {
            const degree = await Degree.findById(degreeId).session(session);
            if (!degree) {
                throw new AppError('Degree not found', 404);
            }

            degree.grades = degree.grades.filter(g => g.toString() !== gradeId.toString());
            await degree.save(options.session ? { session } : {});

            metricsCollector.increment('degree.grade_unlinked', { degreeId, gradeId });
            eventEmitter.emit('degree.grade_unlinked', { degreeId, gradeId });
        } catch (error) {
            logger.error(`Failed to unlink grade ${gradeId} from degree ${degreeId}:`, { error: error.message });
            throw error;
        }
    }

    /**
     * Index degree for search
     * Indexes degree data in Elasticsearch for search capabilities.
     * @param {Object} degree - Degree document
     * @returns {Promise<void>}
     */
    async indexForSearch(degree) {
        try {
            await elasticsearchClient.index({
                index: 'degrees',
                id: degree._id.toString(),
                body: {
                    userId: degree.userId,
                    fieldOfStudy: degree.fieldOfStudy,
                    degreeLevel: degree.degreeLevel,
                    schoolId: degree.schoolId,
                    status: degree.status,
                    createdAt: degree.createdAt,
                    searchable: degree.privacy.searchable,
                },
            });
            metricsCollector.increment('degree.indexed', { degreeId: degree._id });
        } catch (error) {
            logger.error(`Failed to index degree ${degree._id}:`, { error: error.message });
            throw error;
        }
    }

    /**
     * Async processing for new degree
     * Handles verification and indexing.
     * @param {String} degreeId - Degree ID
     * @param {String} userId - User ID
     * @returns {Promise<void>}
     */
    async processNewDegreeAsync(degreeId, userId) {
        try {
            const degree = await Degree.findById(degreeId);
            if (!degree) return;

            await this.verificationService.verifyDegree({
                degreeId,
                userId,
                fieldOfStudy: degree.fieldOfStudy,
                degreeLevel: degree.degreeLevel,
                schoolId: degree.schoolId,
            });

            await this.indexForSearch(degree);
            metricsCollector.increment('degree.async_processed', { degreeId });
        } catch (error) {
            logger.error(`Async processing failed for degree ${degreeId}:`, { error: error.message });
        }
    }

    /**
     * Sanitize input data
     * Sanitizes degree input to prevent XSS and normalize data.
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
            'fieldOfStudy',
            'degreeLevel',
            'schoolId',
            'startDate',
            'endDate',
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
                sanitized[key] = key === 'description' ? sanitizeHtml(value) : value;
            }
        }
        return sanitized;
    }
}

export default new DegreeService();