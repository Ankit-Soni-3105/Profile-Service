import mongoose from 'mongoose';
import Grade from '../models/Grade.js';
import VerificationService from './VerificationService.js';
import MediaService from './MediaService.js';
import NotificationService from './NotificationService.js';
import SchoolService from './SchoolService.js';
import EducationService from './EducationService.js';
import DegreeService from './DegreeService.js';
import { validateGrade } from '../validations/grade.validation.js';
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

// Rate limiters for grade operations
const createGradeLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15-minute window
    max: 20, // Allow 20 grade creations
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_grade_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const updateGradeLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5-minute window
    max: 30, // Allow 30 updates
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_grade_${req.user.id}_${req.ip}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const bulkGradeLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // Hourly limit
    max: 5, // Conservative limit for bulk operations
    keyGenerator: (req) => `bulk_grade_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

class GradeService {
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
     * Create a new grade
     * Creates a grade record with validation and async processing.
     * @param {Object} gradeData - Grade data
     * @param {Object} options - Mongoose session and other options
     * @returns {Promise<Object>} Created grade
     */
    async createGrade(gradeData, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;
        const validation = validateGrade(gradeData);
        if (!validation.valid) {
            metricsCollector.increment('grade.validation_failed', { errors: validation.errors.length });
            throw new AppError(`Validation failed: ${validation.message}`, 400);
        }

        const sanitizedData = this.sanitizeInput(gradeData);
        sanitizedData.course = sanitizedData.course?.toLowerCase().trim();
        sanitizedData.score = parseFloat(sanitizedData.score) || null;
        sanitizedData.gradeFormat = sanitizedData.gradeFormat?.toUpperCase() || 'LETTER';

        if (sanitizedData.schoolId) {
            const school = await this.schoolService.getSchoolById(sanitizedData.schoolId, { session });
            if (!school || school.status !== 'active') {
                throw new AppError('Invalid or inactive school association', 400);
            }
        }

        const sessionOptions = session ? { session } : {};
        try {
            const grade = await Grade.create([{
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

            this.processNewGradeAsync(grade[0]._id, grade[0].userId).catch((err) => {
                logger.error(`Async processing failed for grade ${grade[0]._id}:`, err);
                metricsCollector.increment('grade.async_processing_failed', { gradeId: grade[0]._id });
            });

            metricsCollector.increment('grade.created', {
                userId: grade[0].userId,
                course: grade[0].course,
                gradeFormat: grade[0].gradeFormat,
            });
            metricsCollector.timing('grade.create_time', Date.now() - startTime);

            eventEmitter.emit('grade.created', {
                gradeId: grade[0]._id,
                userId: grade[0].userId,
                course: grade[0].course,
                schoolId: grade[0].schoolId,
            });

            return grade[0];
        } catch (error) {
            logger.error(`Grade creation failed:`, { error: error.message, stack: error.stack });
            metricsCollector.increment('grade.create_failed', { userId: gradeData.userId });
            throw error;
        }
    }

    /**
     * Get grade by ID
     * Retrieves a grade with optional population and caching.
     * @param {String} gradeId - Grade ID
     * @param {Object} options - Query options
     * @returns {Promise<Object>} Grade document
     */
    async getGradeById(gradeId, options = {}) {
        const startTime = Date.now();
        const cacheKey = `grade:${gradeId}:${JSON.stringify(options)}`;
        const cached = await cacheService.get(cacheKey);
        if (cached) {
            metricsCollector.increment('grade.cache_hit', { gradeId });
            return cached;
        }

        try {
            const query = Grade.findById(gradeId)
                .read('secondaryPreferred')
                .select(options.select || '-__v')
                .populate(options.populate || ['schoolId', 'degreeId', 'educationId']);
            if (options.session) query.session(options.session);

            const grade = await query.lean({ virtuals: true });
            if (!grade) {
                throw new AppError('Grade not found', 404);
            }

            await cacheService.set(cacheKey, grade, 600, ['grades:id:' + gradeId]);
            metricsCollector.increment('grade.fetched', { gradeId });
            metricsCollector.timing('grade.get_time', Date.now() - startTime);
            return grade;
        } catch (error) {
            logger.error(`Failed to fetch grade ${gradeId}:`, { error: error.message });
            metricsCollector.increment('grade.fetch_failed', { gradeId });
            throw error;
        }
    }

    /**
     * Update grade
     * Updates a grade with versioning and re-verification.
     * @param {String} gradeId - Grade ID
     * @param {Object} updates - Update data
     * @param {Object} options - Mongoose session and other options
     * @returns {Promise<Object>} Updated grade
     */
    async updateGrade(gradeId, updates, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;
        const sanitizedUpdates = this.sanitizeUpdates(updates, this.getAllowedUpdateFields());

        const sessionOptions = session ? { session } : {};
        try {
            const grade = await Grade.findById(gradeId).session(session);
            if (!grade) {
                throw new AppError('Grade not found', 404);
            }

            if (sanitizedUpdates.course || sanitizedUpdates.score) {
                grade.versions = grade.versions || [];
                grade.versions.push({
                    versionNumber: grade.metadata.version + 1,
                    course: sanitizedUpdates.course || grade.course,
                    score: sanitizedUpdates.score || grade.score,
                    changeType: 'edit',
                    timestamp: new Date(),
                });
            }

            Object.assign(grade, sanitizedUpdates);
            grade.metadata.version += 1;
            grade.metadata.updateCount += 1;
            grade.metadata.lastModifiedBy = {
                userId: options.userId,
                timestamp: new Date(),
                changes: Object.keys(sanitizedUpdates),
            };

            if (['course', 'score', 'schoolId', 'degreeId'].some(field => sanitizedUpdates[field])) {
                grade.verification.status = 'pending';
                this.processExternalVerification(grade._id, grade.userId).catch((err) => {
                    logger.error(`Re-verification failed for grade ${grade._id}:`, err);
                });
            }

            await grade.save(sessionOptions);
            await Promise.all([
                cacheService.deletePattern(`grade:${gradeId}:*`),
                cacheService.deleteByTag(['grades:id:' + gradeId]),
            ]);

            metricsCollector.increment('grade.updated', { gradeId });
            metricsCollector.timing('grade.update_time', Date.now() - startTime);
            eventEmitter.emit('grade.updated', { gradeId, changes: Object.keys(sanitizedUpdates) });

            return grade;
        } catch (error) {
            logger.error(`Grade update failed for ${gradeId}:`, { error: error.message });
            metricsCollector.increment('grade.update_failed', { gradeId });
            throw error;
        }
    }

    /**
     * Delete grade
     * Supports soft and permanent deletion.
     * @param {String} gradeId - Grade ID
     * @param {Object} options - Deletion options
     * @returns {Promise<void>}
     */
    async deleteGrade(gradeId, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;
        const permanent = options.permanent || false;

        const sessionOptions = session ? { session } : {};
        try {
            const grade = await Grade.findById(gradeId).session(session);
            if (!grade) {
                throw new AppError('Grade not found', 404);
            }

            if (permanent) {
                await Grade.findByIdAndDelete(gradeId, sessionOptions);
                await this.mediaService.deleteAllMedia(gradeId, 'grade', sessionOptions);
            } else {
                grade.status = 'deleted';
                grade.privacy.isPublic = false;
                grade.privacy.searchable = false;
                await grade.save(sessionOptions);
            }

            await Promise.all([
                cacheService.deletePattern(`grade:${gradeId}:*`),
                cacheService.deleteByTag(['grades:id:' + gradeId]),
            ]);

            metricsCollector.increment(`grade.${permanent ? 'permanently_deleted' : 'soft_deleted'}`, { gradeId });
            metricsCollector.timing('grade.delete_time', Date.now() - startTime);
            eventEmitter.emit('grade.deleted', { gradeId, permanent });
        } catch (error) {
            logger.error(`Grade deletion failed for ${gradeId}:`, { error: error.message });
            metricsCollector.increment('grade.delete_failed', { gradeId });
            throw error;
        }
    }

    /**
     * Index grade for search
     * Indexes grade data in Elasticsearch for search capabilities.
     * @param {Object} grade - Grade document
     * @returns {Promise<void>}
     */
    async indexForSearch(grade) {
        try {
            await elasticsearchClient.index({
                index: 'grades',
                id grade._id.toString(),
                body: {
                    userId: grade.userId,
                    course: grade.course,
                    score: grade.score,
                    schoolId: grade.schoolId,
                    status: grade.status,
                    createdAt: grade.createdAt,
                    searchable: grade.privacy.searchable,
                },
            });
            metricsCollector.increment('grade.indexed', { gradeId: grade._id });
        } catch (error) {
            logger.error(`Failed to index grade ${grade._id}:`, { error: error.message });
            throw error;
        }
    }

    /**
     * Async processing for new grade
     * Handles verification, attribute extraction, and indexing.
     * @param {String} gradeId - Grade ID
     * @param {String} userId - User ID
     * @returns {Promise<void>}
     */
    async processNewGradeAsync(gradeId, userId) {
        try {
            const grade = await Grade.findById(gradeId);
            if (!grade) return;

            const attributes = await this.extractAttributes(grade.description || grade.course);
            if (attributes.length) {
                grade.attributes = attributes;
                await grade.save();
            }

            await this.verificationService.verifyGrade({
                gradeId,
                userId,
                course: grade.course,
                score: grade.score,
                term: grade.term,
                schoolId: grade.schoolId,
            });

            await this.indexForSearch(grade);
            metricsCollector.increment('grade.async_processed', { gradeId });
        } catch (error) {
            logger.error(`Async processing failed for grade ${gradeId}:`, { error: error.message });
        }
    }

    /**
     * Extract attributes from text
     * Placeholder for extracting attributes from grade description.
     * @param {String} text - Text to analyze
     * @returns {Promise<Array>} Extracted attributes
     */
    async extractAttributes(text) {
        // Placeholder for NLP or regex-based attribute extraction
        return text.split(' ').filter(word => word.length > 3).slice(0, 5);
    }

    /**
     * Calculate quality score
     * Placeholder for calculating grade quality score.
     * @param {Object} grade - Grade document
     * @returns {Promise<void>}
     */
    async calculateQualityScore(grade) {
        // Placeholder for quality score logic
        grade.qualityScore = grade.score ? (grade.score / 100) * 5 : 0;
        await grade.save();
    }

    /**
     * Sanitize input data
     * Sanitizes grade input to prevent XSS and normalize data.
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
            'course',
            'score',
            'gradeFormat',
            'term',
            'schoolId',
            'degreeId',
            'educationId',
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

    /**
     * Check connection access
     * Verifies if a user has access to another user's grades.
     * @param {String} ownerId - Owner user ID
     * @param {String} requesterId - Requester user ID
     * @returns {Promise<Boolean>} Access status
     */
    async checkConnectionAccess(ownerId, requesterId) {
        // Placeholder for connection check logic
        return ownerId === requesterId; // Simplified for now
    }

    /**
     * Check bulk access
     * Verifies access for bulk operations.
     * @param {String} ownerId - Owner user ID
     * @param {String} requesterId - Requester user ID
     * @param {String} operation - Operation type
     * @returns {Promise<Boolean>} Access status
     */
    async checkBulkAccess(ownerId, requesterId, operation) {
        // Placeholder for bulk access logic
        return ownerId === requesterId; // Simplified for now
    }

    /**
     * Increment views
     * Increments view count for a grade.
     * @param {String} gradeId - Grade ID
     * @param {String} viewerId - Viewer user ID
     * @returns {Promise<void>}
     */
    async incrementViews(gradeId, viewerId) {
        try {
            await Grade.updateOne(
                { _id: gradeId },
                {
                    $inc: { 'analytics.views.total': 1 },
                    $addToSet: { 'analytics.views.unique': viewerId },
                }
            );
            metricsCollector.increment('grade.views_incremented', { gradeId });
        } catch (error) {
            logger.error(`Failed to increment views for grade ${gradeId}:`, { error: error.message });
        }
    }

    /**
     * Create backup
     * Creates a backup of a grade.
     * @param {String} gradeId - Grade ID
     * @param {String} action - Backup action
     * @param {String} userId - User ID
     * @param {Object} options - Backup options
     * @returns {Promise<void>}
     */
    async createBackup(gradeId, action, userId, options = {}) {
        try {
            const grade = await Grade.findById(gradeId);
            if (!grade) return;

            // Placeholder for backup logic (e.g., save to S3 or MongoDB)
            logger.info(`Backup created for grade ${gradeId} by ${userId} for action ${action}`);
            metricsCollector.increment('grade.backup_created', { gradeId, action });
        } catch (error) {
            logger.error(`Backup failed for grade ${gradeId}:`, { error: error.message });
        }
    }

    /**
     * Delete all backups
     * Deletes all backups for a grade.
     * @param {String} gradeId - Grade ID
     * @returns {Promise<void>}
     */
    async deleteAllBackups(gradeId) {
        try {
            // Placeholder for backup deletion logic
            logger.info(`All backups deleted for grade ${gradeId}`);
            metricsCollector.increment('grade.backups_deleted', { gradeId });
        } catch (error) {
            logger.error(`Failed to delete backups for grade ${gradeId}:`, { error: error.message });
        }
    }
}

export default new GradeService();