import Skill from '../models/Skill.js';
import SkillCategory from '../models/SkillCategory.js';
import SkillTrend from '../models/SkillTrend.js';
import SkillDemand from '../models/SkillDemand.js';
import SkillService from '../services/SkillService.js';
import VerificationService from '../services/VerificationService.js';
import MediaService from '../services/MediaService.js';
import NotificationService from '../services/NotificationService.js';
import { validateSkill, sanitizeInput } from '../validations/skill.validation.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { catchAsync } from '../handler/catchAsync.js';
import { ApiResponse } from '../utils/response.js';
import { createRateLimiter } from '../utils/rateLimiter.js';
import { cacheService } from '../services/cache.service.js';
import { eventEmitter } from '../events/events.js';
import { metricsCollector } from '../utils/metrics.js';
import mongoose from 'mongoose';
import sanitizeHtml from 'sanitize-html';

// Rate limiters for scalability
const createSkillLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 15, // 15 creates per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_skill_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const updateSkillLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 25, // 25 updates per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_skill_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const verificationLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 5, // 5 verification requests per 30 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `verify_skill_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const bulkOperationsLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // 3 bulk operations per hour
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_skill_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const mediaUploadLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 10, // 10 media uploads per 10 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `media_skill_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

class SkillController {
    constructor() {
        this.skillService = new SkillService();
        this.verificationService = new VerificationService();
        this.mediaService = new MediaService();
        this.notificationService = new NotificationService();
    }

    /**
     * Create a new skill
     * POST /api/v1/skills/:userId
     */
    createSkill = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const skillData = req.body;
        const requestingUserId = req.user.id;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied: Cannot create skill for another user', 403));
        }

        await createSkillLimiter(req, res, () => { });

        const validation = validateSkill(skillData);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        const sanitizedData = sanitizeInput(skillData);

        const userSkillCount = await Skill.countDocuments({
            userId,
            'status.isDeleted': false,
        }).cache({ ttl: 300, key: `user_skill_count_${userId}` });

        const limits = this.getUserLimits(req.user.accountType);
        if (userSkillCount >= limits.maxSkills) {
            return next(new AppError(`Skill limit reached (${limits.maxSkills})`, 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const skill = await this.skillService.createSkill({
                ...sanitizedData,
                userId,
                metadata: {
                    ...sanitizedData.metadata,
                    createdBy: {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        location: req.geoip,
                    },
                },
            }, { session });

            this.processNewSkillAsync(skill._id, requestingUserId)
                .catch((err) => logger.error(`Async processing failed for skill ${skill._id}:`, err));

            metricsCollector.increment('skill.created', {
                userId,
                category: skill.categoryId,
            });

            eventEmitter.emit('skill.created', {
                skillId: skill._id,
                userId,
                categoryId: skill.categoryId,
            });

            if (skill.settings?.autoBackup) {
                this.skillService.createBackup(skill._id, 'create', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for skill ${skill._id}:`, err));
            }

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`Skill created successfully: ${skill._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Skill created successfully',
                data: {
                    id: skill._id,
                    userId: skill.userId,
                    name: skill.name,
                    status: skill.status,
                    createdAt: skill.createdAt,
                    processingStatus: 'started',
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Skill creation failed for user ${userId}:`, error);
            metricsCollector.increment('skill.create_failed', { userId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.code === 11000) {
                return next(new AppError('Skill with this name already exists', 409));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out', 504));
            }
            return next(new AppError('Failed to create skill', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get user's skills with filtering and pagination
     * GET /api/v1/skills/:userId
     */
    getSkills = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const {
            page = 1,
            limit = 20,
            status,
            categoryId,
            search,
            sortBy = 'recent',
            proficiencyLevel,
            tags,
            includeAnalytics = 'false',
        } = req.query;

        const query = this.buildSkillQuery({
            userId,
            status,
            categoryId,
            search,
            proficiencyLevel,
            tags,
        });

        const sortOption = this.buildSortOption(sortBy);
        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
        const skip = (pageNum - 1) * limitNum;

        const cacheKey = `skills:${userId}:${JSON.stringify({
            page: pageNum,
            limit: limitNum,
            status,
            categoryId,
            search,
            sortBy,
            proficiencyLevel,
            tags,
        })}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('skill.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const [skills, totalCount] = await Promise.all([
                Skill.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select(this.getSelectFields(includeAnalytics === 'true'))
                    .populate('categoryId', 'name type')
                    .lean(),
                Skill.countDocuments(query).cache({ ttl: 300, key: `skill_count_${userId}` }),
            ]);

            const processedSkills = await Promise.all(
                skills.map((skill) => this.processSkillData(skill, includeAnalytics === 'true')),
            );

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                skills: processedSkills,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages,
                    hasNext: pageNum < totalPages,
                    hasPrev: pageNum > 1,
                    nextPage: pageNum < totalPages ? pageNum + 1 : null,
                    prevPage: pageNum > 1 ? pageNum - 1 : null,
                },
                filters: {
                    status: status || 'all',
                    categoryId: categoryId || 'all',
                    sortBy,
                    search: search || null,
                },
            };

            await cacheService.set(cacheKey, result, 300);
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('skill.fetched', {
                userId,
                count: skills.length,
                cached: false,
            });
            logger.info(`Fetched ${skills.length} skills for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch skills for user ${userId}:`, error);
            metricsCollector.increment('skill.fetch_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid query parameters', 400));
            }
            return next(new AppError('Failed to fetch skills', 500));
        }
    });

    /**
     * Get single skill by ID
     * GET /api/v1/skills/:userId/:id
     */
    getSkillById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { includeAnalytics = 'false', includeVerification = 'false' } = req.query;

        try {
            const cacheKey = `skill:${id}:${userId}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('skill.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const skill = await Skill.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .populate('categoryId', 'name type')
                .cache({ ttl: 600, key: cacheKey });

            if (!skill) {
                return next(new AppError('Skill not found', 404));
            }

            const hasAccess = this.checkSkillAccess(skill, requestingUserId, req.user.isAdmin);
            if (!hasAccess) {
                return next(new AppError('Access denied', 403));
            }

            if (requestingUserId !== userId) {
                skill.analytics.viewCount += 1;
                skill.analytics.lastViewed = new Date();
                await skill.save();
            }

            const responseData = this.processSkillData(skill.toObject(), includeAnalytics === 'true', includeVerification === 'true');

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('skill.viewed', {
                userId,
                viewerId: requestingUserId,
                isOwner: userId === requestingUserId,
            });
            logger.info(`Fetched skill ${id} for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: responseData });
        } catch (error) {
            logger.error(`Failed to fetch skill ${id}:`, error);
            metricsCollector.increment('skill.view_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid skill ID', 400));
            }
            return next(new AppError('Failed to fetch skill', 500));
        }
    });

    /**
     * Update skill
     * PUT /api/v1/skills/:userId/:id
     */
    updateSkill = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const updates = req.body;

        await updateSkillLimiter(req, res, () => { });

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const skill = await Skill.findOne({ _id: id, userId }).session(session);
            if (!skill) {
                return next(new AppError('Skill not found', 404));
            }

            const allowedUpdates = this.getAllowedUpdateFields();
            const sanitizedUpdates = this.sanitizeUpdates(updates, allowedUpdates);

            if (Object.keys(sanitizedUpdates).length === 0) {
                return next(new AppError('No valid update fields provided', 400));
            }

            let versionCreated = false;
            if (sanitizedUpdates.description && sanitizedUpdates.description !== skill.description) {
                await skill.createVersion(sanitizedUpdates.description, sanitizedUpdates.name || skill.name, 'edit', {
                    userId: requestingUserId,
                }, { session });
                versionCreated = true;
            }

            Object.assign(skill, sanitizedUpdates);

            skill.metadata.lastModifiedBy = {
                userId: requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date(),
            };

            if (sanitizedUpdates.proficiency || sanitizedUpdates.categoryId) {
                skill.verification.status = 'pending';
                this.processExternalVerification(skill._id, requestingUserId)
                    .catch((err) => logger.error(`Re-verification failed for skill ${id}:`, err));
            }

            await skill.save({ session });

            if (sanitizedUpdates.description) {
                await skill.calculateQualityScore({ session });
            }

            if (skill.settings?.autoBackup) {
                this.skillService.createBackup(skill._id, 'update', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for skill ${id}:`, err));
            }

            await cacheService.deletePattern(`skill:${id}:*`);
            await cacheService.deletePattern(`skills:${userId}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('skill.updated', {
                userId,
                versionCreated,
                fieldsUpdated: Object.keys(sanitizedUpdates).length,
            });

            eventEmitter.emit('skill.updated', {
                skillId: skill._id,
                userId,
                changes: Object.keys(sanitizedUpdates),
                versionCreated,
            });

            logger.info(`Skill updated successfully: ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Skill updated successfully',
                data: {
                    id: skill._id,
                    name: skill.name,
                    status: skill.status,
                    updatedAt: skill.updatedAt,
                    versionCreated,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Skill update failed for ${id}:`, error);
            metricsCollector.increment('skill.update_failed', { userId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out', 504));
            }
            return next(new AppError('Failed to update skill', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete skill (soft or permanent)
     * DELETE /api/v1/skills/:userId/:id
     */
    deleteSkill = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { permanent = 'false' } = req.query;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const skill = await Skill.findOne({ _id: id, userId }).session(session);
            if (!skill) {
                return next(new AppError('Skill not found', 404));
            }

            if (permanent === 'true') {
                await Skill.findByIdAndDelete(id, { session });
                await this.mediaService.deleteAllMedia(id, 'skill', { session });
                this.skillService.deleteAllBackups(id)
                    .catch((err) => logger.error(`Failed to delete backups for ${id}:`, err));
                metricsCollector.increment('skill.permanently_deleted', { userId });
            } else {
                skill.status.isDeleted = true;
                skill.status.deletedAt = new Date();
                skill.metadata.lastModifiedBy = {
                    userId: requestingUserId,
                    ip: req.ip,
                    userAgent: req.get('User-Agent'),
                    timestamp: new Date(),
                };
                await skill.save({ session });
                metricsCollector.increment('skill.soft_deleted', { userId });
            }

            await cacheService.deletePattern(`skill:${id}:*`);
            await cacheService.deletePattern(`skills:${userId}:*`);

            eventEmitter.emit('skill.deleted', {
                skillId: id,
                userId,
                permanent: permanent === 'true',
            });

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`Skill ${id} deleted (permanent: ${permanent}) in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: permanent === 'true' ? 'Skill permanently deleted' : 'Skill moved to trash',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Skill deletion failed for ${id}:`, error);
            metricsCollector.increment('skill.delete_failed', { userId });
            return next(new AppError('Failed to delete skill', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Bulk operations on skills
     * POST /api/v1/skills/:userId/bulk
     */
    bulkOperations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { operation, skillIds, data = {} } = req.body;

        await bulkOperationsLimiter(req, res, () => { });

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        if (!Array.isArray(skillIds) || skillIds.length === 0) {
            return next(new AppError('Skill IDs array is required', 400));
        }
        if (skillIds.length > 100) {
            return next(new AppError('Maximum 100 skills can be processed at once', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const query = { _id: { $in: skillIds }, userId };
            const { message } = await this.handleBulkOperation(operation, query, data, requestingUserId, req, { session });

            await Promise.all([
                cacheService.deletePattern(`skills:${userId}:*`),
                ...skillIds.map((id) => cacheService.deletePattern(`skill:${id}:*`)),
            ]);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('skill.bulk_operation', {
                userId,
                operation,
                count: skillIds.length,
            });
            logger.info(`Bulk operation ${operation} completed for ${skillIds.length} skills in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message,
                data: {
                    operation,
                    requested: skillIds.length,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk operation failed for user ${userId}:`, error);
            metricsCollector.increment('skill.bulk_operation_failed', { userId, operation });
            return next(new AppError('Bulk operation failed', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get skill analytics
     * GET /api/v1/skills/:userId/:id/analytics
     */
    getAnalytics = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { timeframe = '30d', metrics = 'basic' } = req.query;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        try {
            const cacheKey = `analytics:skill:${id}:${timeframe}:${metrics}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('skill.analytics_cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const skill = await Skill.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('analytics verification metadata createdAt')
                .cache({ ttl: 900, key: cacheKey });

            if (!skill) {
                return next(new AppError('Skill not found', 404));
            }

            const analytics = this.processAnalyticsData(skill, timeframe, metrics);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('skill.analytics_viewed', { userId });
            logger.info(`Fetched analytics for skill ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: analytics });
        } catch (error) {
            logger.error(`Analytics fetch failed for ${id}:`, error);
            metricsCollector.increment('skill.analytics_fetch_failed', { userId });
            return next(new AppError('Failed to fetch analytics', 500));
        }
    });

    /**
     * Duplicate skill
     * POST /api/v1/skills/:userId/:id/duplicate
     */
    duplicateSkill = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { name, includeVersions = 'false' } = req.body;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const originalSkill = await Skill.findOne({ _id: id, userId }).session(session);
            if (!originalSkill) {
                return next(new AppError('Skill not found', 404));
            }

            const userSkillCount = await Skill.countDocuments({
                userId,
                'status.isDeleted': false,
            }).cache({ ttl: 300, key: `user_skill_count_${userId}` });

            const limits = this.getUserLimits(req.user.accountType);
            if (userSkillCount >= limits.maxSkills) {
                return next(new AppError(`Skill limit reached (${limits.maxSkills})`, 403));
            }

            const duplicateData = originalSkill.toObject();
            delete duplicateData._id;
            delete duplicateData.createdAt;
            delete duplicateData.updatedAt;
            delete duplicateData.analytics;

            duplicateData.name = name || `${originalSkill.name} (Copy)`;
            duplicateData.status.isActive = true;
            duplicateData.status.isDeleted = false;
            duplicateData.metadata.createdBy = {
                userId: requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date(),
            };

            if (includeVersions !== 'true') {
                duplicateData.versions = [{
                    versionNumber: 1,
                    description: duplicateData.description,
                    name: duplicateData.name,
                    changeType: 'create',
                    isActive: true,
                }];
            }

            const duplicate = new Skill(duplicateData);
            await duplicate.save({ session });

            if (duplicate.settings?.autoBackup) {
                this.skillService.createBackup(duplicate._id, 'duplicate', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for duplicate ${duplicate._id}:`, err));
            }

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('skill.duplicated', { userId });
            logger.info(`Skill ${id} duplicated as ${duplicate._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Skill duplicated successfully',
                data: {
                    originalId: id,
                    duplicateId: duplicate._id,
                    name: duplicate.name,
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Skill duplication failed for ${id}:`, error);
            metricsCollector.increment('skill.duplicate_failed', { userId });
            return next(new AppError('Failed to duplicate skill', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Verify skill
     * POST /api/v1/skills/:userId/:id/verify
     */
    verifySkill = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        await verificationLimiter(req, res, () => { });

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const skill = await Skill.findOne({ _id: id, userId }).session(session);
            if (!skill) {
                return next(new AppError('Skill not found', 404));
            }

            const verificationResult = await this.processExternalVerification(skill._id, requestingUserId);
            if (!verificationResult.success) {
                return next(new AppError('Verification failed: ' + verificationResult.message, 424));
            }

            skill.verification = {
                status: verificationResult.status,
                confidence: verificationResult.confidence,
                verifiedBy: verificationResult.verifiedBy,
                verifiedAt: new Date(),
                details: verificationResult.details,
            };

            await skill.save({ session });

            this.notificationService.notifyUser(userId, {
                type: 'verification_completed',
                message: `Skill "${skill.name}" verification ${verificationResult.status}`,
                data: { skillId: id },
            }).catch((err) => logger.error(`Notification failed for skill ${id}:`, err));

            await cacheService.deletePattern(`skill:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('skill.verified', {
                userId,
                status: verificationResult.status,
            });
            logger.info(`Skill ${id} verified in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Skill verification completed',
                data: skill.verification,
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Verification failed for skill ${id}:`, error);
            metricsCollector.increment('skill.verify_failed', { userId });
            if (error.message.includes('timeout')) {
                return next(new AppError('External API timeout', 503));
            }
            return next(new AppError('Failed to verify skill', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Upload media for skill
     * POST /api/v1/skills/:userId/:id/media
     */
    uploadMedia = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const files = req.files;

        await mediaUploadLimiter(req, res, () => { });

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const skill = await Skill.findOne({ _id: id, userId }).session(session);
            if (!skill) {
                return next(new AppError('Skill not found', 404));
            }

            const validation = this.validateMediaUpload(files, skill.media);
            if (!validation.valid) {
                return next(new AppError(validation.message, 422));
            }

            const mediaResults = await this.mediaService.uploadMedia({
                files,
                entityId: id,
                entityType: 'skill',
                userId,
            }, { session });

            const scanResults = await this.mediaService.scanMedia(mediaResults);
            if (scanResults.some((result) => result.infected)) {
                return next(new AppError('Media upload failed: Infected file detected', 422));
            }

            skill.media.push(...mediaResults);
            await skill.save({ session });

            await cacheService.deletePattern(`skill:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('skill.media_uploaded', {
                userId,
                count: mediaResults.length,
            });
            logger.info(`Uploaded ${mediaResults.length} media files for skill ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Media uploaded successfully',
                data: { media: mediaResults },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Media upload failed for skill ${id}:`, error);
            metricsCollector.increment('skill.media_upload_failed', { userId });
            return next(new AppError('Failed to upload media', 422));
        } finally {
            session.endSession();
        }
    });

    /**
     * Share skill
     * POST /api/v1/skills/:userId/:id/share
     */
    shareSkill = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { platform } = req.body;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const skill = await Skill.findOne({ _id: id, userId }).session(session);
            if (!skill) {
                return next(new AppError('Skill not found', 404));
            }

            const hasAccess = this.checkSkillAccess(skill, requestingUserId, req.user.isAdmin);
            if (!hasAccess) {
                return next(new AppError('Access denied', 403));
            }

            const shareLink = this.generateShareableLink(skill, platform);

            skill.analytics.shares = skill.analytics.shares || { total: 0, byPlatform: {} };
            skill.analytics.shares.total += 1;
            skill.analytics.shares.byPlatform[platform] = (skill.analytics.shares.byPlatform[platform] || 0) + 1;
            await skill.save({ session });

            await cacheService.deletePattern(`skill:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('skill.shared', { userId, platform });
            logger.info(`Skill ${id} shared on ${platform} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Skill shared successfully',
                data: { shareLink },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Share failed for skill ${id}:`, error);
            metricsCollector.increment('skill.share_failed', { userId });
            return next(new AppError('Failed to share skill', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Endorse skill
     * POST /api/v1/skills/:userId/:id/endorse
     */
    endorseSkill = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const skill = await Skill.findOne({ _id: id, userId }).session(session);
            if (!skill) {
                return next(new AppError('Skill not found', 404));
            }

            const isConnected = await this.skillService.checkConnectionLevel(userId, requestingUserId);
            if (!isConnected) {
                return next(new AppError('Must be connected to endorse', 403));
            }

            if (skill.endorsements.some((e) => e.userId.toString() === requestingUserId)) {
                return next(new AppError('Skill already endorsed by this user', 409));
            }

            skill.endorsements.push({
                userId: requestingUserId,
                endorsedAt: new Date(),
            });
            await skill.save({ session });

            this.notificationService.notifyUser(userId, {
                type: 'endorsement',
                message: `Your skill "${skill.name}" was endorsed`,
                data: { skillId: id, endorserId: requestingUserId },
            }).catch((err) => logger.error(`Notification failed for endorsement ${id}:`, err));

            await cacheService.deletePattern(`skill:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('skill.endorsed', { userId, endorserId: requestingUserId });
            logger.info(`Skill ${id} endorsed in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Skill endorsed successfully',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Endorsement failed for skill ${id}:`, error);
            metricsCollector.increment('skill.endorse_failed', { userId });
            return next(new AppError('Failed to endorse skill', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get verification status
     * GET /api/v1/skills/:userId/:id/verification
     */
    getVerificationStatus = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        try {
            const cacheKey = `verification:skill:${id}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('skill.verification_cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const skill = await Skill.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('verification')
                .cache({ ttl: 60, key: cacheKey });

            if (!skill) {
                return next(new AppError('Skill not found', 404));
            }

            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('skill.verification_viewed', { userId });
            logger.info(`Fetched verification status for skill ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                data: skill.verification,
            });
        } catch (error) {
            logger.error(`Verification status fetch failed for ${id}:`, error);
            metricsCollector.increment('skill.verification_fetch_failed', { userId });
            return next(new AppError('Failed to fetch verification status', 500));
        }
    });

    /**
     * Get trending skills
     * GET /api/v1/skills/trending
     */
    getTrendingSkills = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { timeframe = '7d', categoryId, limit = 20 } = req.query;

        const cacheKey = `trending:skills:${timeframe}:${categoryId || 'all'}:${limit}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('skill.trending_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const skills = await this.skillService.getTrendingSkills(timeframe, categoryId, parseInt(limit));
            const processedSkills = await Promise.all(
                skills.map((skill) => this.processSkillData(skill, false)),
            );

            const result = { skills: processedSkills };
            await cacheService.set(cacheKey, result, 3600);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('skill.trending_viewed', { count: skills.length });
            logger.info(`Fetched ${skills.length} trending skills in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch trending skills:`, error);
            metricsCollector.increment('skill.trending_fetch_failed');
            return next(new AppError('Failed to fetch trending skills', 500));
        }
    });

    /**
     * Get skills by category
     * GET /api/v1/skills/categories/:categoryId
     */
    getSkillsByCategory = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { categoryId } = req.params;
        const { page = 1, limit = 20, sortBy = 'recent' } = req.query;

        const cacheKey = `skills:category:${categoryId}:${page}:${limit}:${sortBy}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('skill.category_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const query = this.buildSkillQuery({ categoryId });
            const sortOption = this.buildSortOption(sortBy);
            const pageNum = Math.max(1, parseInt(page));
            const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
            const skip = (pageNum - 1) * limitNum;

            const [skills, totalCount] = await Promise.all([
                Skill.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select(this.getSelectFields(false))
                    .lean(),
                Skill.countDocuments(query).cache({ ttl: 300, key: `skill_category_count_${categoryId}` }),
            ]);

            const processedSkills = await Promise.all(
                skills.map((skill) => this.processSkillData(skill, false)),
            );

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                skills: processedSkills,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages,
                },
            };

            await cacheService.set(cacheKey, result, 1800);
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('skill.category_viewed', { categoryId, count: skills.length });
            logger.info(`Fetched ${skills.length} skills for category ${categoryId} in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch skills for category ${categoryId}:`, error);
            metricsCollector.increment('skill.category_fetch_failed', { categoryId });
            return next(new AppError('Failed to fetch skills by category', 500));
        }
    });

    /**
     * Search skills
     * GET /api/v1/skills/search
     */
    searchSkills = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { query, page = 1, limit = 20, filters = {} } = req.query;

        const cacheKey = `search:skills:${query}:${JSON.stringify(filters)}:${page}:${limit}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('skill.search_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const searchResults = await this.skillService.searchSkills(query, filters, {
                page: parseInt(page),
                limit: parseInt(limit),
            });

            const result = {
                skills: searchResults.hits,
                totalCount: searchResults.total,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    totalPages: Math.ceil(searchResults.total / parseInt(limit)),
                },
            };

            await cacheService.set(cacheKey, result, 300);
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('skill.searched', { query, count: searchResults.hits.length });
            logger.info(`Search returned ${searchResults.hits.length} skills in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Search failed for query ${query}:`, error);
            metricsCollector.increment('skill.search_failed');
            return next(new AppError('Failed to search skills', 500));
        }
    });

    /**
     * Export skills as CSV
     * GET /api/v1/skills/:userId/export
     */
    exportSkills = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { format = 'csv', fields = 'name,description,categoryId,proficiency.level' } = req.query;

        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        try {
            const skills = await Skill.find({ userId, 'status.isDeleted': false })
                .read('secondaryPreferred')
                .select(fields.split(',').join(' '))
                .lean();

            const csvData = this.convertToCSV(skills, fields.split(','));
            const filename = `skills_${userId}_${Date.now()}.csv`;

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('skill.exported', { userId, format });
            logger.info(`Exported ${skills.length} skills for user ${userId} in ${responseTime}ms`);

            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            return res.send(csvData);
        } catch (error) {
            logger.error(`Export failed for user ${userId}:`, error);
            metricsCollector.increment('skill.export_failed', { userId });
            return next(new AppError('Failed to export skills', 500));
        }
    });

    // Helper Methods

    async processNewSkillAsync(skillId, userId) {
        try {
            const session = await mongoose.startSession();
            session.startTransaction();

            const skill = await Skill.findById(skillId).session(session);
            if (!skill) {
                await session.abortTransaction();
                session.endSession();
                return;
            }

            const skillsExtracted = await this.skillService.extractSkills(skill.description);
            skill.skills = skillsExtracted.slice(0, 20);

            await skill.calculateQualityScore({ session });

            await this.processExternalVerification(skillId, userId);

            await this.skillService.indexForSearch(skill);

            await this.skillService.updateUserStats(userId, { session });

            await skill.save({ session });
            await session.commitTransaction();
            logger.info(`Async processing completed for skill ${skillId}`);
        } catch (error) {
            logger.error(`Async processing failed for skill ${skillId}:`, error);
        } finally {
            session.endSession();
        }
    }

    checkSkillAccess(skill, requestingUserId, isAdmin) {
        if (isAdmin) return true;
        if (skill.userId.toString() === requestingUserId) return true;
        if (skill.visibility === 'public') return true;
        return false;
    }

    getAllowedUpdateFields() {
        return [
            'name',
            'description',
            'categoryId',
            'tags',
            'skills',
            'proficiency',
            'visibility',
            'status',
        ];
    }

    sanitizeUpdates(updates, allowedFields) {
        const sanitized = {};
        allowedFields.forEach((field) => {
            if (updates[field] !== undefined) {
                sanitized[field] = field === 'description' ? sanitizeHtml(updates[field]) : sanitizeInput(updates[field]);
            }
        });
        return sanitized;
    }

    processAnalyticsData(skill, timeframe, metrics) {
        const analytics = skill.analytics || {};
        const timeframeDate = new Date();

        switch (timeframe) {
            case '7d':
                timeframeDate.setDate(timeframeDate.getDate() - 7);
                break;
            case '30d':
                timeframeDate.setDate(timeframeDate.getDate() - 30);
                break;
            case '90d':
                timeframeDate.setDate(timeframeDate.getDate() - 90);
                break;
            default:
                timeframeDate.setDate(timeframeDate.getDate() - 30);
        }

        const filteredAnalytics = {
            viewCount: analytics.viewCount || 0,
            searchAppearances: analytics.searchAppearances || 0,
            engagementScore: analytics.engagementScore || 0,
            lastViewed: analytics.lastViewed || null,
            clickThroughRate: analytics.clickThroughRate || 0,
            userInteractions: analytics.userInteractions || 0,
            shares: {
                total: analytics.shares?.total || 0,
                byPlatform: analytics.shares?.byPlatform || {},
            },
            endorsements: skill.endorsements?.length || 0,
        };

        if (metrics === 'detailed') {
            filteredAnalytics.verification = skill.verification;
        }

        return filteredAnalytics;
    }

    getUserLimits(accountType) {
        const limits = {
            free: { maxSkills: 20, maxMedia: 5, maxSizeMB: 50 },
            premium: { maxSkills: 100, maxMedia: 20, maxSizeMB: 200 },
            enterprise: { maxSkills: 500, maxMedia: 50, maxSizeMB: 500 },
        };
        return limits[accountType] || limits.free;
    }

    buildSkillQuery({ userId, status, categoryId, search, proficiencyLevel, tags }) {
        const query = { userId, 'status.isDeleted': false };

        if (status && status !== 'all') {
            query['status.isActive'] = status === 'active';
        }
        if (categoryId && categoryId !== 'all') {
            query.categoryId = categoryId;
        }
        if (proficiencyLevel) {
            query['proficiency.level'] = proficiencyLevel;
        }
        if (tags) {
            const tagArray = tags.split(',').map((tag) => tag.trim().toLowerCase());
            query.tags = { $in: tagArray };
        }
        if (search) {
            query.$text = { $search: search };
        }

        return query;
    }

    buildSortOption(sortBy) {
        const sortOptions = {
            recent: { updatedAt: -1 },
            oldest: { createdAt: 1 },
            name: { name: 1 },
            popular: { 'analytics.viewCount': -1 },
            quality: { 'metadata.qualityScore': -1 },
            verified: { 'verification.confidence': -1 },
        };
        return sortOptions[sortBy] || sortOptions.recent;
    }

    getSelectFields(includeAnalytics) {
        const baseFields = 'name description categoryId tags skills proficiency visibility status createdAt updatedAt';
        return includeAnalytics ? baseFields + ' analytics' : baseFields;
    }

    async processSkillData(skill, includeAnalytics = false, includeVerification = false) {
        const processed = {
            ...skill,
            proficiencyLevel: skill.proficiency?.level,
        };

        if (!includeAnalytics) {
            delete processed.analytics;
        }
        if (!includeVerification) {
            delete processed.verification;
        }

        return processed;
    }

    calculateTrendingScore(skill) {
        const viewsWeight = 0.4;
        const sharesWeight = 0.3;
        const endorsementsWeight = 0.2;
        const recencyWeight = 0.1;

        const daysSinceCreated = (Date.now() - new Date(skill.createdAt)) / (1000 * 60 * 60 * 24);
        const recencyScore = Math.max(0, 10 - daysSinceCreated);

        return (
            (skill.analytics.viewCount * viewsWeight) +
            ((skill.analytics.shares?.total || 0) * sharesWeight) +
            (skill.endorsements.length * endorsementsWeight) +
            (recencyScore * recencyWeight)
        );
    }

    validateMediaUpload(files, existingMedia) {
        const limits = this.getUserLimits('premium');
        const totalSize = files.reduce((sum, file) => sum + file.size, 0);
        const totalMedia = existingMedia.length + files.length;

        if (totalMedia > limits.maxMedia) {
            return { valid: false, message: `Maximum ${limits.maxMedia} media files allowed` };
        }
        if (totalSize > limits.maxSizeMB * 1024 * 1024) {
            return { valid: false, message: `Total media size exceeds ${limits.maxSizeMB}MB` };
        }

        return { valid: true };
    }

    async processExternalVerification(skillId, userId) {
        try {
            const skill = await Skill.findById(skillId);
            const result = await this.verificationService.verifySkill({
                skillId,
                userId,
                name: skill.name,
                proficiency: skill.proficiency,
                categoryId: skill.categoryId,
            });

            return result;
        } catch (error) {
            logger.error(`External verification failed for skill ${skillId}:`, error);
            return { success: false, message: error.message };
        }
    }

    generateShareableLink(skill, platform) {
        const baseUrl = process.env.APP_URL || 'https://app.example.com';
        return `${baseUrl}/skills/${skill._id}/share?platform=${platform}`;
    }

    async handleBulkOperation(operation, query, data, requestingUserId, req, options = {}) {
        let updateData = {};
        let message = '';

        switch (operation) {
            case 'delete':
                updateData = {
                    'status.isDeleted': true,
                    'status.deletedAt': new Date(),
                    updatedAt: new Date(),
                    'metadata.lastModifiedBy': {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = 'Skills moved to trash';
                break;
            case 'archive':
                updateData = {
                    'status.isActive': false,
                    updatedAt: new Date(),
                    'metadata.lastModifiedBy': {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = 'Skills archived';
                break;
            case 'publish':
                updateData = {
                    'status.isActive': true,
                    visibility: 'public',
                    updatedAt: new Date(),
                    'metadata.lastModifiedBy': {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = 'Skills published';
                break;
            case 'updateCategory':
                if (!data.categoryId) {
                    throw new AppError('Category ID is required', 400);
                }
                updateData = {
                    categoryId: data.categoryId,
                    updatedAt: new Date(),
                    'metadata.lastModifiedBy': {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = `Category updated to ${data.categoryId}`;
                break;
            case 'updateTags':
                if (!Array.isArray(data.tags)) {
                    throw new AppError('Tags array is required', 400);
                }
                updateData = {
                    $addToSet: {
                        tags: { $each: data.tags.map((tag) => tag.trim().toLowerCase()).slice(0, 15) },
                    },
                    updatedAt: new Date(),
                    'metadata.lastModifiedBy': {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = 'Tags updated';
                break;
            case 'updateVisibility':
                if (!data.visibility) {
                    throw new AppError('Visibility is required', 400);
                }
                updateData = {
                    visibility: data.visibility,
                    updatedAt: new Date(),
                    'metadata.lastModifiedBy': {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = `Visibility updated to ${data.visibility}`;
                break;
        }

        const result = await Skill.updateMany(query, updateData, options);
        return { message, result };
    }

    convertToCSV(data, fields) {
        const headers = fields.join(',');
        const rows = data.map((item) => {
            return fields.map((field) => {
                const value = field.includes('.') ? field.split('.').reduce((obj, key) => obj?.[key] || '', item) : item[field] || '';
                return `"${value.toString().replace(/"/g, '""')}"`;
            }).join(',');
        });
        return `${headers}\n${rows.join('\n')}`;
    }
}

export default new SkillController();