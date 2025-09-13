import Course from '../models/Course.js';
import Organization from '../models/Organization.js';
import { VerificationService } from './VerificationService.js';
import { NotificationService } from './NotificationService.js';
import { validateCourse } from '../validations/course.validation.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { metricsCollector } from '../utils/metrics.js';
import { cacheService } from '../services/cache.service.js';
import { createRateLimiter } from '../utils/rateLimiter.js';
import { CircuitBreaker } from '../utils/circuitBreaker.js';
import { retry } from '../utils/retry.js';
import { elasticsearchClient } from '../config/elasticsearch.js';
import { s3Client } from '../config/s3.js';
import mongoose from 'mongoose';
import sanitizeHtml from 'sanitize-html';
import moment from 'moment';
import { v4 as uuidv4 } from 'uuid';

// Rate limiters for high concurrency
const createLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15-minute window
    max: 5, // Allow 5 creates per user
    skipSuccessfulRequests: true,
    keyGenerator: (data) => `course_create_${data.userId}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const updateLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5-minute window
    max: 15, // Allow 15 updates
    skipSuccessfulRequests: true,
    keyGenerator: (data) => `course_update_${data.userId}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const verifyLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30-minute window
    max: 3, // Strict limit for external verification
    skipSuccessfulRequests: true,
    keyGenerator: (data) => `course_verify_${data.userId}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

class CourseService {
    constructor() {
        this.verificationService = new VerificationService();
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
    }

    /**
     * Create a new course
     * @param {Object} data - Course data (title, description, organizationId, etc.)
     * @param {Object} options - Mongoose session options and request metadata
     * @returns {Promise<Object>} - Created course
     */
    async createCourse(data, options = {}) {
        const startTime = Date.now();
        const { userId, ip, userAgent, geoip, referrer } = options.request || {};
        const validation = validateCourse(data);
        if (!validation.valid) {
            metricsCollector.increment('course.validation_failed', { userId, errors: validation.errors.length });
            throw new AppError(`Validation failed: ${validation.message}`, 400);
        }

        await createLimiter({ userId }, null, () => { });

        const sanitizedData = this.sanitizeInput(data);
        sanitizedData.title = sanitizedData.title?.trim();
        sanitizedData.description = sanitizedData.description ? sanitizeHtml(sanitizedData.description) : null;

        const session = options.session || await mongoose.startSession();
        try {
            if (!options.session) session.startTransaction();

            const organization = await Organization.findById(sanitizedData.organizationId).session(session);
            if (!organization || organization.status === 'deleted') {
                throw new AppError('Organization not found', 404);
            }

            const existingCourse = await Course.findOne({
                title: sanitizedData.title,
                organizationId: sanitizedData.organizationId,
                status: { $ne: 'deleted' },
            }).session(session);
            if (existingCourse) {
                throw new AppError('Course with this title already exists for this organization', 409);
            }

            const course = await Course.create([{
                ...sanitizedData,
                createdBy: userId,
                metadata: {
                    ...sanitizedData.metadata,
                    createdBy: {
                        userId,
                        ip: ip || 'unknown',
                        userAgent: userAgent || 'unknown',
                        location: geoip || { country: 'unknown', city: 'unknown' },
                        referrer: referrer || 'direct',
                    },
                    importSource: sanitizedData.metadata?.importSource || 'manual',
                    version: 1,
                    updateCount: 0,
                },
                analytics: {
                    views: { total: 0, unique: 0, byDate: [] },
                    enrollments: { total: 0, byUser: [] },
                    interactions: { total: 0, byType: {} },
                },
                verification: {
                    status: 'pending',
                    confidence: 0,
                    verifiedBy: null,
                    verifiedAt: null,
                    details: [],
                },
                status: 'pending',
                privacy: {
                    isPublic: false,
                    showDetails: true,
                    searchable: true,
                },
            }], { session });

            organization.courses = [...(organization.courses || []), course[0]._id];
            await organization.save({ session });

            this.processNewCourseAsync(course[0]._id, userId).catch((err) => {
                logger.error(`Async processing failed for course ${course[0]._id}:`, err);
                metricsCollector.increment('course.async_processing_failed', { courseId: course[0]._id });
            });

            if (course[0].settings?.autoBackup) {
                await this.createBackup(course[0]._id, 'create', userId, { session });
            }

            metricsCollector.increment('course.created', { userId, title: course[0].title, organizationId: course[0].organizationId });
            metricsCollector.timing('course.create_time', Date.now() - startTime);

            if (!options.session) await session.commitTransaction();
            return course[0];
        } catch (error) {
            if (!options.session) await session.abortTransaction();
            logger.error(`Course creation failed for user ${userId}:`, { error: error.message });
            metricsCollector.increment('course.create_failed', { userId });
            throw error instanceof AppError ? error : new AppError('Failed to create course', 500);
        } finally {
            if (!options.session) session.endSession();
        }
    }

    /**
     * Update course metadata
     * @param {String} courseId - Course ID
     * @param {Object} updates - Update data
     * @param {Object} options - Mongoose session options and request metadata
     * @returns {Promise<Object>} - Updated course
     */
    async updateCourse(courseId, updates, options = {}) {
        const startTime = Date.now();
        const { userId } = options.request || {};
        const sanitizedUpdates = this.sanitizeUpdates(updates);
        if (Object.keys(sanitizedUpdates).length === 0) {
            throw new AppError('No valid update fields provided', 400);
        }

        await updateLimiter({ userId }, null, () => { });

        const session = options.session || await mongoose.startSession();
        try {
            if (!options.session) session.startTransaction();

            const course = await Course.findById(courseId).session(session);
            if (!course || course.status === 'deleted') {
                throw new AppError('Course not found', 404);
            }

            if (sanitizedUpdates.title || sanitizedUpdates.organizationId) {
                course.versions = course.versions || [];
                course.versions.push({
                    versionNumber: course.metadata.version + 1,
                    title: sanitizedUpdates.title || course.title,
                    organizationId: sanitizedUpdates.organizationId || course.organizationId,
                    changeType: 'edit',
                    timestamp: new Date(),
                });
            }

            Object.assign(course, sanitizedUpdates);
            course.metadata.version += 1;
            course.metadata.updateCount += 1;
            course.metadata.lastModifiedBy = {
                userId,
                timestamp: new Date(),
                changes: Object.keys(sanitizedUpdates),
            };

            if (['title', 'organizationId', 'description'].some(field => sanitizedUpdates[field])) {
                course.verification.status = 'pending';
                this.processExternalVerification(course._id, userId).catch((err) => {
                    logger.error(`Re-verification failed for course ${course._id}:`, err);
                });
            }

            await course.save({ session });
            await this.indexForSearch(course);
            await cacheService.deletePattern(`course:${courseId}:*`);

            metricsCollector.increment('course.updated', { courseId });
            metricsCollector.timing('course.update_time', Date.now() - startTime);

            if (!options.session) await session.commitTransaction();
            return course;
        } catch (error) {
            if (!options.session) await session.abortTransaction();
            logger.error(`Course update failed for ${courseId}:`, { error: error.message });
            metricsCollector.increment('course.update_failed', { courseId });
            throw error instanceof AppError ? error : new AppError('Failed to update course', 500);
        } finally {
            if (!options.session) session.endSession();
        }
    }

    /**
     * Verify course
     * @param {Object} data - Verification data (courseId, title, organizationId)
     * @returns {Promise<Object>} - Verification result
     */
    async verifyCourse(data) {
        const startTime = Date.now();
        const { courseId, title, organizationId, userId } = data;

        await verifyLimiter({ userId }, null, () => { });

        try {
            const verificationResult = await this.circuitBreaker.fire(async () => {
                return await retry(() => this.verificationService.verifyCourse({
                    courseId,
                    title,
                    organizationId,
                }), this.retryConfig);
            });

            const session = await mongoose.startSession();
            try {
                session.startTransaction();

                const course = await Course.findById(courseId).session(session);
                if (!course || course.status === 'deleted') {
                    throw new AppError('Course not found', 404);
                }

                course.verification = {
                    status: verificationResult.success ? 'verified' : 'failed',
                    confidence: verificationResult.confidence || 0,
                    verifiedBy: verificationResult.verifiedBy || 'external_api',
                    verifiedAt: new Date(),
                    details: verificationResult.details || [],
                };

                await course.save({ session });
                await this.indexForSearch(course);

                if (verificationResult.success) {
                    await this.notificationService.notifyUser({
                        userId,
                        message: `Course ${course.title} has been successfully verified`,
                        type: 'verification_success',
                    }, { session });
                } else {
                    await this.notificationService.notifyUser({
                        userId,
                        message: `Verification failed for course ${course.title}`,
                        type: 'verification_failed',
                    }, { session });
                }

                metricsCollector.increment('course.verified', { courseId, status: verificationResult.success ? 'verified' : 'failed' });
                metricsCollector.timing('course.verify_time', Date.now() - startTime);

                await session.commitTransaction();
                return verificationResult;
            } catch (error) {
                await session.abortTransaction();
                throw error;
            } finally {
                session.endSession();
            }
        } catch (error) {
            logger.error(`Verification failed for course ${courseId}:`, { error: error.message });
            metricsCollector.increment('course.verify_failed', { courseId });
            throw error instanceof AppError ? error : new AppError('Failed to verify course', 424);
        }
    }

    /**
     * Get course analytics
     * @param {String} courseId - Course ID
     * @returns {Promise<Object>} - Analytics data
     */
    async getCourseAnalytics(courseId) {
        const startTime = Date.now();
        const cacheKey = `course_analytics:${courseId}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('course.analytics_cache_hit', { courseId });
                return cached;
            }

            const course = await Course.findById(courseId)
                .select('analytics')
                .lean();
            if (!course || course.status === 'deleted') {
                throw new AppError('Course not found', 404);
            }

            const analytics = this.computeAnalytics(course.analytics);
            await cacheService.set(cacheKey, analytics, 300, [`course_analytics:${courseId}`]);

            metricsCollector.increment('course.analytics_fetched', { courseId });
            metricsCollector.timing('course.analytics_time', Date.now() - startTime);
            return analytics;
        } catch (error) {
            logger.error(`Failed to fetch analytics for course ${courseId}:`, { error: error.message });
            metricsCollector.increment('course.analytics_failed', { courseId });
            throw error instanceof AppError ? error : new AppError('Failed to fetch course analytics', 500);
        }
    }

    /**
     * Bulk create courses
     * @param {Array} coursesData - Array of course data
     * @param {Object} options - Mongoose session options and request metadata
     * @returns {Promise<Array>} - Created courses
     */
    async bulkCreateCourses(coursesData, options = {}) {
        const startTime = Date.now();
        const { userId } = options.request || {};

        if (!Array.isArray(coursesData) || coursesData.length === 0 || coursesData.length > 20) {
            throw new AppError('Invalid or too many courses (max 20)', 400);
        }

        await createLimiter({ userId }, null, () => { });

        const session = options.session || await mongoose.startSession();
        try {
            if (!options.session) session.startTransaction();

            const validatedCourses = [];
            for (const courseData of coursesData) {
                const validation = validateCourse(courseData);
                if (!validation.valid) {
                    throw new AppError(`Validation failed for course: ${validation.message}`, 400);
                }

                const sanitizedData = this.sanitizeInput(courseData);
                sanitizedData.title = sanitizedData.title?.trim();
                sanitizedData.description = sanitizedData.description ? sanitizeHtml(sanitizedData.description) : null;

                const organization = await Organization.findById(sanitizedData.organizationId).session(session);
                if (!organization || organization.status === 'deleted') {
                    throw new AppError(`Organization ${sanitizedData.organizationId} not found`, 404);
                }

                const existingCourse = await Course.findOne({
                    title: sanitizedData.title,
                    organizationId: sanitizedData.organizationId,
                    status: { $ne: 'deleted' },
                }).session(session);
                if (existingCourse) {
                    throw new AppError(`Course with title ${sanitizedData.title} already exists for organization ${sanitizedData.organizationId}`, 409);
                }

                validatedCourses.push({
                    ...sanitizedData,
                    createdBy: userId,
                    metadata: {
                        ...sanitizedData.metadata,
                        createdBy: {
                            userId,
                            ip: options.request?.ip || 'unknown',
                            userAgent: options.request?.userAgent || 'unknown',
                            location: options.request?.geoip || { country: 'unknown', city: 'unknown' },
                            referrer: options.request?.referrer || 'direct',
                        },
                        importSource: sanitizedData.metadata?.importSource || 'bulk',
                        version: 1,
                        updateCount: 0,
                    },
                    analytics: {
                        views: { total: 0, unique: 0, byDate: [] },
                        enrollments: { total: 0, byUser: [] },
                        interactions: { total: 0, byType: {} },
                    },
                    verification: {
                        status: 'pending',
                        confidence: 0,
                        verifiedBy: null,
                        verifiedAt: null,
                        details: [],
                    },
                    status: 'pending',
                    privacy: {
                        isPublic: false,
                        showDetails: true,
                        searchable: true,
                    },
                });
            }

            const courses = await Course.insertMany(validatedCourses, { session });

            const organizationIds = [...new Set(courses.map(c => c.organizationId))];
            for (const orgId of organizationIds) {
                const org = await Organization.findById(orgId).session(session);
                if (org) {
                    org.courses = [...(org.courses || []), ...courses.filter(c => c.organizationId.toString() === orgId.toString()).map(c => c._id)];
                    await org.save({ session });
                }
            }

            for (const course of courses) {
                this.processNewCourseAsync(course._id, userId).catch((err) => {
                    logger.error(`Async processing failed for course ${course._id}:`, err);
                });
            }

            metricsCollector.increment('course.bulk_created', { userId, count: courses.length });
            metricsCollector.timing('course.bulk_create_time', Date.now() - startTime);

            if (!options.session) await session.commitTransaction();
            return courses;
        } catch (error) {
            if (!options.session) await session.abortTransaction();
            logger.error(`Bulk course creation failed for user ${userId}:`, { error: error.message });
            metricsCollector.increment('course.bulk_create_failed', { userId });
            throw error instanceof AppError ? error : new AppError('Failed to bulk create courses', 500);
        } finally {
            if (!options.session) session.endSession();
        }
    }

    /**
     * Index course for search
     * @param {Object} course - Course document
     * @returns {Promise<void>}
     */
    async indexForSearch(course) {
        try {
            await elasticsearchClient.index({
                index: 'courses',
                id: course._id.toString(),
                body: {
                    title: course.title,
                    organizationId: course.organizationId,
                    status: course.status,
                    searchable: course.privacy.searchable,
                    createdAt: course.createdAt,
                },
            });
            metricsCollector.increment('course.indexed', { courseId: course._id });
        } catch (error) {
            logger.error(`Failed to index course ${course._id}:`, { error: error.message });
            metricsCollector.increment('course.index_failed', { courseId: course._id });
        }
    }

    /**
     * Create backup of course
     * @param {String} courseId - Course ID
     * @param {String} action - Action type
     * @param {String} userId - User ID
     * @param {Object} options - Mongoose session options
     * @returns {Promise<void>}
     */
    async createBackup(courseId, action, userId, options = {}) {
        try {
            const course = await Course.findById(courseId).session(options.session);
            if (!course) return;

            const backupKey = `backups/courses/${courseId}/${uuidv4()}.json`;
            await s3Client.upload({
                Bucket: 'user-backups',
                Key: backupKey,
                Body: Buffer.from(JSON.stringify(course)),
                ContentType: 'application/json',
            }).promise();

            logger.info(`Backup created for course ${courseId} by ${userId} for action ${action}`);
            metricsCollector.increment('course.backup_created', { courseId, action });
        } catch (error) {
            logger.error(`Backup failed for course ${courseId}:`, { error: error.message });
            metricsCollector.increment('course.backup_failed', { courseId });
        }
    }

    /**
     * Update course analytics
     * @param {String} courseId - Course ID
     * @param {String} type - Analytics type (view/enrollment/interaction)
     * @param {String} userId - User ID
     * @param {Object} options - Additional options (e.g., interactionType)
     * @returns {Promise<void>}
     */
    async updateAnalytics(courseId, type, userId, options = {}) {
        const startTime = Date.now();
        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const course = await Course.findById(courseId).session(session);
            if (!course || course.status === 'deleted') {
                throw new AppError('Course not found', 404);
            }

            const today = moment().startOf('day').toDate();
            if (type === 'view') {
                course.analytics.views.total += 1;
                if (!course.analytics.views.byDate) course.analytics.views.byDate = [];
                const viewEntry = course.analytics.views.byDate.find(v => v.date.toDateString() === today.toDateString());
                if (viewEntry) {
                    viewEntry.count += 1;
                } else {
                    course.analytics.views.byDate.push({ date: today, count: 1 });
                }
            } else if (type === 'enrollment') {
                course.analytics.enrollments.total += 1;
                course.analytics.enrollments.byUser.push({ userId, timestamp: new Date() });
            } else if (type === 'interaction') {
                course.analytics.interactions.total += 1;
                course.analytics.interactions.byType[options.interactionType || 'general'] =
                    (course.analytics.interactions.byType[options.interactionType || 'general'] || 0) + 1;
            }

            await course.save({ session });
            await cacheService.deletePattern(`course_analytics:${courseId}:*`);

            metricsCollector.increment(`course.${type}_recorded`, { courseId });
            metricsCollector.timing(`course.${type}_update_time`, Date.now() - startTime);

            await session.commitTransaction();
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Failed to update ${type} analytics for course ${courseId}:`, { error: error.message });
            metricsCollector.increment(`course.${type}_update_failed`, { courseId });
            throw error instanceof AppError ? error : new AppError(`Failed to update ${type} analytics`, 500);
        } finally {
            session.endSession();
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

        return {
            totalViews: analytics.views.total || 0,
            uniqueViews: analytics.views.unique || 0,
            viewsByMonth,
            totalEnrollments: analytics.enrollments.total || 0,
            totalInteractions: analytics.interactions.total || 0,
            interactionsByType: analytics.interactions.byType || {},
        };
    }

    /**
     * Sanitize input data
     * @param {Object} data - Input data
     * @returns {Object} - Sanitized data
     */
    sanitizeInput(data) {
        const sanitized = { ...data };
        if (data.description) sanitized.description = sanitizeHtml(data.description);
        return sanitized;
    }

    /**
     * Sanitize update data
     * @param {Object} updates - Update data
     * @returns {Object} - Sanitized updates
     */
    sanitizeUpdates(updates) {
        const allowedFields = [
            'title',
            'description',
            'organizationId',
            'duration',
            'level',
            'language',
            'tags',
            'privacy',
            'settings',
        ];
        const sanitized = {};
        for (const [key, value] of Object.entries(updates)) {
            if (allowedFields.includes(key)) {
                sanitized[key] = key === 'description' ? sanitizeHtml(value) : value;
            }
        }
        return sanitized;
    }

    /**
     * Process new course asynchronously
     * @param {String} courseId - Course ID
     * @param {String} userId - User ID
     * @returns {Promise<void>}
     */
    async processNewCourseAsync(courseId, userId) {
        try {
            const course = await Course.findById(courseId);
            if (!course) return;

            await this.circuitBreaker.fire(async () => {
                await retry(() => this.verificationService.verifyCourse({
                    courseId,
                    title: course.title,
                    organizationId: course.organizationId,
                }), this.retryConfig);
            });

            await this.indexForSearch(course);
            metricsCollector.increment('course.async_processed', { courseId });
        } catch (error) {
            logger.error(`Async processing failed for course ${courseId}:`, { error: error.message });
            metricsCollector.increment('course.async_processing_failed', { courseId });
        }
    }

    /**
     * Process external verification
     * @param {String} courseId - Course ID
     * @param {String} userId - User ID
     * @returns {Promise<void>}
     */
    async processExternalVerification(courseId, userId) {
        try {
            const course = await Course.findById(courseId);
            if (!course) return;

            const verificationResult = await this.circuitBreaker.fire(async () => {
                return await retry(() => this.verificationService.verifyCourse({
                    courseId,
                    title: course.title,
                    organizationId: course.organizationId,
                }), this.retryConfig);
            });

            course.verification = {
                status: verificationResult.success ? 'verified' : 'failed',
                confidence: verificationResult.confidence || 0,
                verifiedBy: verificationResult.verifiedBy || 'external_api',
                verifiedAt: new Date(),
                details: verificationResult.details || [],
            };

            await course.save();
            await this.indexForSearch(course);

            metricsCollector.increment('course.verification_processed', { courseId });
        } catch (error) {
            logger.error(`External verification failed for course ${courseId}:`, { error: error.message });
            metricsCollector.increment('course.verification_failed', { courseId });
        }
    }
}

export default new CourseService();