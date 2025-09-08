import csrf from 'csurf';
import { Router } from 'express';
import promClient from 'prom-client';
import compression from 'compression';
import mongoose from 'mongoose';
import { logger } from '../utils/logger.js';
import { upload } from '../middlewares/upload.middleware.js';
import { requireRole } from '../middlewares/role.middleware.js';
import { validateRequest } from '../middlewares/validateRequest.middleware.js';
import authProfileMiddleware from '../middlewares/profile.middleware.js';
import { AnalyticsService } from '../services/AnalyticsService.js';
import {
    bulkDeleteProfiles,
    bulkUpdateCompletionScores,
    createProfile,
    createProfileLimiter,
    deleteProfile,
    endorseSkill,
    getAnalyticsSummary,
    getCareerProgression,
    getNearbyProfiles,
    getProfile,
    getProfileAnalytics,
    getRecommendations,
    getTrendingProfiles,
    handleProfileErrors,
    healthCheck,
    searchLimiter,
    searchProfiles,
    updateProfile,
    updateProfileLimiter,
    uploadProfilePhoto,
} from '../controllers/profile.controller.js';
import { ApiError, ApiResponse } from '../utils/apiResponse.js';
import { deleteFromCloudinary, uploadToCloudinary } from '../utils/cloudinary.js';
import { deleteCacheData, generateCacheKey } from '../utils/cache.js';
import { profileEventEmitter } from '../utils/eventEmitter.js';
import { validateImageFile } from '../utils/validateImage.js';
import Profile from '../models/Profile.js';

const router = Router();

// ===========================
// MIDDLEWARE SETUP
// ===========================
router.use((req, res, next) => {
    logger.info(`API Request: ${req.method} ${req.path}`, {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        userId: req.user?.userId || 'anonymous',
        timestamp: new Date().toISOString(),
    });
    next();
});

router.use((req, res, next) => {
    res.set({
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
    });
    next();
});

router.use(compression());

const csrfProtection = csrf({ cookie: true });
router.use((req, res, next) => {
    if (['POST', 'PATCH', 'DELETE'].includes(req.method)) {
        csrfProtection(req, res, next);
    } else {
        next();
    }
});

const auditLog = async (req, res, next) => {
    const AuditLog = mongoose.model('AuditLog', new mongoose.Schema({
        userId: String,
        action: String,
        timestamp: { type: Date, default: Date.now },
        details: mongoose.Schema.Types.Mixed,
    }));
    const originalSend = res.send;
    res.send = function (body) {
        if (req.method !== 'GET' && res.statusCode < 400) {
            AuditLog.create({
                userId: req.user?.userId || 'anonymous',
                action: `${req.method} ${req.path}`,
                details: {
                    params: req.params,
                    body: req.body,
                    response: body,
                },
            }).catch(err => logger.warn('Audit log failed:', err.message));
        }
        return originalSend.call(this, body);
    };
    next();
};

const adminLimiter = require('express-rate-limit')({
    windowMs: 15 * 60 * 1000,
    max: 50,
    message: 'Too many admin requests, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.user.userId,
});

const analyticsLimiter = require('express-rate-limit')({
    windowMs: 10 * 60 * 1000,
    max: 100,
    message: 'Too many analytics requests, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.user.userId,
});

// ===========================
// VALIDATION SCHEMAS
// ===========================
const validateUserId = [
    param('userId')
        .isMongoId()
        .withMessage('Invalid user ID format')
        .customSanitizer(value => value.trim()),
];

const validateIdentifier = [
    param('identifier')
        .custom((value) => {
            const mongoIdRegex = /^[0-9a-fA-F]{24}$/;
            const slugRegex = /^[a-zA-Z0-9-_]{3,50}$/;
            if (!mongoIdRegex.test(value) && !slugRegex.test(value)) {
                throw new Error('Identifier must be a valid user ID or profile slug');
            }
            return true;
        })
        .customSanitizer(value => value.trim().toLowerCase()),
];

const validateSkillName = [
    param('skillName')
        .isLength({ min: 1, max: 100 })
        .withMessage('Skill name must be between 1 and 100 characters')
        .matches(/^[a-zA-Z0-9\s\-\+\#\.]+$/)
        .withMessage('Skill name contains invalid characters')
        .customSanitizer(value => value.trim()),
];

const validateBulkDelete = [
    body('userIds')
        .isArray({ min: 1, max: 1000 })
        .withMessage('userIds must be an array with 1-1000 items'),
    body('userIds.*')
        .isMongoId()
        .withMessage('Each user ID must be a valid MongoDB ObjectId'),
];

const validateBulkUpdateScores = [
    body('batchSize')
        .optional()
        .isInt({ min: 100, max: 10000 })
        .withMessage('Batch size must be between 100 and 10000')
        .toInt(),
];

const validateCreateProfile = [
    body('personalInfo.firstName')
        .trim()
        .isLength({ min: 1, max: 50 })
        .withMessage('First name is required and must be 1-50 characters'),
    body('personalInfo.lastName')
        .trim()
        .isLength({ min: 1, max: 50 })
        .withMessage('Last name is required and must be 1-50 characters'),
    body('contact.primaryEmail')
        .isEmail()
        .normalizeEmail()
        .withMessage('Valid email address is required'),
    body('settings.profileSlug')
        .optional()
        .matches(/^[a-zA-Z0-9-_]{3,50}$/)
        .withMessage('Profile slug must be 3-50 characters (letters, numbers, hyphens, underscores only)'),
    body('skills.*.name')
        .optional()
        .isLength({ min: 1, max: 50 })
        .withMessage('Skill name must be 1-50 characters'),
    body('experience.*.company')
        .optional()
        .isLength({ min: 1, max: 200 })
        .withMessage('Company name must be 1-200 characters'),
    body('experience.*.position')
        .optional()
        .isLength({ min: 1, max: 200 })
        .withMessage('Position must be 1-200 characters'),
];

const validateUpdateProfile = [
    body('personalInfo.firstName')
        .optional()
        .trim()
        .isLength({ min: 1, max: 50 })
        .withMessage('First name must be 1-50 characters'),
    body('personalInfo.lastName')
        .optional()
        .trim()
        .isLength({ min: 1, max: 50 })
        .withMessage('Last name must be 1-50 characters'),
    body('contact.primaryEmail')
        .optional()
        .isEmail()
        .normalizeEmail()
        .withMessage('Must be a valid email address'),
    body('settings.profileSlug')
        .optional()
        .matches(/^[a-zA-Z0-9-_]{3,50}$/)
        .withMessage('Profile slug must be 3-50 characters (letters, numbers, hyphens, underscores only)'),
    body('skills.*.name')
        .optional()
        .isLength({ min: 1, max: 50 })
        .withMessage('Skill name must be 1-50 characters'),
    body('experience.*.company')
        .optional()
        .isLength({ min: 1, max: 200 })
        .withMessage('Company name must be 1-200 characters'),
    body('experience.*.position')
        .optional()
        .isLength({ min: 1, max: 200 })
        .withMessage('Position must be 1-200 characters'),
];

const searchValidation = [
    query('page').optional().isInt({ min: 1 }).toInt().withMessage('Page must be a positive integer'),
    query('limit').optional().isInt({ min: 1, max: 50 }).toInt().withMessage('Limit must be between 1 and 50'),
    query('minExperience').optional().isInt({ min: 0 }).toInt().withMessage('minExperience must be a non-negative integer'),
    query('maxExperience').optional().isInt({ max: 50 }).toInt().withMessage('maxExperience must be <= 50'),
    query('verifiedOnly').optional().isBoolean().toBoolean().withMessage('verifiedOnly must be a boolean'),
];

const nearbyValidation = [
    query('longitude').isFloat().toFloat().withMessage('Longitude must be a valid number'),
    query('latitude').isFloat().toFloat().withMessage('Latitude must be a valid number'),
    query('maxDistance').optional().isInt({ min: 1000, max: 100000 }).toInt().withMessage('maxDistance must be between 1000 and 100000'),
    query('limit').optional().isInt({ min: 1, max: 50 }).toInt().withMessage('Limit must be between 1 and 50'),
];

const analyticsValidation = [
    query('timeframe').optional().isIn(['7d', '30d', '90d', '1y']).withMessage('Timeframe must be 7d, 30d, 90d, or 1y'),
    query('category').optional().isLength({ min: 1, max: 50 }).withMessage('Category must be 1-50 characters'),
    query('limit').optional().isInt({ min: 1, max: 100 }).toInt().withMessage('Limit must be between 1 and 100'),
];

const resourceValidation = [
    param('id').isMongoId().withMessage('Invalid resource ID format'),
    query('timeframe').optional().isIn(['7d', '30d', '90d', '1y']).withMessage('Timeframe must be 7d, 30d, 90d, or 1y'),
];

const platformValidation = [
    param('id').isMongoId().withMessage('Invalid resource ID format'),
    query('timeframe').optional().isIn(['7d', '30d', '90d', '1y']).withMessage('Timeframe must be 7d, 30d, 90d, or 1y'),
    query('platform').isIn(['linkedin', 'twitter', 'facebook', 'web']).withMessage('Platform must be linkedin, twitter, facebook, or web'),
];

const updateMetricsValidation = [
    param('id').isMongoId().withMessage('Invalid resource ID format'),
    body('metrics.views').optional().isInt({ min: 0 }).toInt().withMessage('Views must be a non-negative integer'),
    body('metrics.likes').optional().isInt({ min: 0 }).toInt().withMessage('Likes must be a non-negative integer'),
    body('metrics.downloads').optional().isInt({ min: 0 }).toInt().withMessage('Downloads must be a non-negative integer'),
    body('metrics.shares').optional().isInt({ min: 0 }).toInt().withMessage('Shares must be a non-negative integer'),
    body('metrics.comments').optional().isInt({ min: 0 }).toInt().withMessage('Comments must be a non-negative integer'),
    body('metrics.platform').optional().isIn(['linkedin', 'twitter', 'facebook', 'web']).withMessage('Platform must be linkedin, twitter, facebook, or web'),
];

const bulkUpdateMetricsValidation = [
    body('ids').isArray({ min: 1, max: 1000 }).withMessage('IDs must be an array with 1-1000 items'),
    body('ids.*').isMongoId().withMessage('Each ID must be a valid MongoDB ObjectId'),
    body('metrics.views').optional().isInt({ min: 0 }).toInt().withMessage('Views must be a non-negative integer'),
    body('metrics.likes').optional().isInt({ min: 0 }).toInt().withMessage('Likes must be a non-negative integer'),
    body('metrics.downloads').optional().isInt({ min: 0 }).toInt().withMessage('Downloads must be a non-negative integer'),
    body('metrics.shares').optional().isInt({ min: 0 }).toInt().withMessage('Shares must be a non-negative integer'),
    body('metrics.comments').optional().isInt({ min: 0 }).toInt().withMessage('Comments must be a non-negative integer'),
    body('metrics.platform').optional().isIn(['linkedin', 'twitter', 'facebook', 'web']).withMessage('Platform must be linkedin, twitter, facebook, or web'),
];

// ===========================
// PUBLIC ROUTES
// ===========================
router.get('/health', healthCheck);
router.get('/public/:identifier', validateIdentifier, validateRequest, getProfile);
router.get('/metrics', requireRole('admin'), async (req, res) => {
    res.set('Content-Type', promClient.register.contentType);
    res.end(await promClient.register.metrics());
});

// ===========================
// AUTHENTICATED ROUTES
// ===========================
router.use(authProfileMiddleware);
router.use(['/:userId', '/:userId/', '/admin/', '/covers/', '/designs/'], auditLog);

// ===========================
// PROFILE CRUD OPERATIONS
// ===========================
router.post('/', createProfileLimiter, validateCreateProfile, validateRequest, createProfile);
router.get('/:identifier', validateIdentifier, validateRequest, getProfile);
router.patch('/:userId', updateProfileLimiter, validateUserId, validateUpdateProfile, validateRequest, updateProfile);
router.delete('/:userId', validateUserId, validateRequest, deleteProfile);

// ===========================
// PROFILE ENHANCEMENT
// ===========================
router.post('/:userId/photo', validateUserId, upload.single('photo'), validateRequest, uploadProfilePhoto);

router.post('/:userId/cover', validateUserId, upload.single('cover'), validateRequest, async (req, res, next) => {
    const start = Date.now();
    const endpoint = 'uploadCoverPhoto';
    const { userId } = req.params;
    const requesterId = req.user.userId;
    const requestCounter = promClient.register.getSingleMetric('request_counter');
    const requestLatency = promClient.register.getSingleMetric('request_latency_seconds');

    try {
        if (userId !== requesterId) {
            requestCounter.inc({ endpoint, method: 'POST', status: 403 });
            throw new ApiError(403, 'Unauthorized to update this profile');
        }

        if (!req.file) {
            requestCounter.inc({ endpoint, method: 'POST', status: 400 });
            throw new ApiError(400, 'No image file provided');
        }

        validateImageFile(req.file);

        const profile = await Profile.findOne({ userId, status: 'active' });
        if (!profile) {
            requestCounter.inc({ endpoint, method: 'POST', status: 404 });
            throw new ApiError(404, 'Profile not found');
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();
            let oldCoverUrl = profile.media.coverPhoto.url;

            let uploadResult;
            let retries = 3;
            while (retries > 0) {
                try {
                    uploadResult = await uploadToCloudinary(req.file.buffer, {
                        folder: 'profiles/covers',
                        transformation: [
                            { width: 1200, height: 400, crop: 'fill' },
                            { quality: 'auto', format: 'auto' },
                        ],
                    });
                    break;
                } catch (error) {
                    retries--;
                    if (retries === 0) throw error;
                    await new Promise(resolve => setTimeout(resolve, 1000));
                }
            }

            profile.media.coverPhoto = {
                url: uploadResult.secure_url,
                uploadedAt: new Date(),
                size: req.file.size,
                format: uploadResult.format,
            };

            await profile.save({ session });
            await session.commitTransaction();

            if (oldCoverUrl) {
                setImmediate(async () => {
                    try {
                        await deleteFromCloudinary(oldCoverUrl);
                    } catch (error) {
                        logger.warn('Failed to delete old cover photo:', error.message);
                    }
                });
            }

            await deleteCacheData(generateCacheKey('user', userId));
            await deleteCacheData(generateCacheKey('slug', profile.settings.profileSlug));

            profileEventEmitter.emit('coverPhotoUpdated', {
                userId,
                profileId: profile._id,
                coverUrl: uploadResult.secure_url,
            });

            logger.info(`Cover photo updated for user: ${userId}`);
            requestCounter.inc({ endpoint, method: 'POST', status: 200 });
            requestLatency.observe({ endpoint, method: 'POST' }, (Date.now() - start) / 1000);

            res.json(new ApiResponse(200, profile.media.coverPhoto, 'Cover photo updated successfully'));
        } catch (error) {
            await session.abortTransaction();
            throw new ApiError(500, 'Failed to upload cover photo');
        } finally {
            session.endSession();
        }
    } catch (error) {
        requestCounter.inc({ endpoint, method: 'POST', status: error.statusCode || 500 });
        throw error;
    }
});

router.post('/:userId/skills/:skillName/endorse', validateUserId, validateSkillName, validateRequest, endorseSkill);

router.delete('/:userId/skills/:skillName/endorse', validateUserId, validateSkillName, validateRequest, async (req, res, next) => {
    const start = Date.now();
    const endpoint = 'removeSkillEndorsement';
    const { userId, skillName } = req.params;
    const removerId = req.user.userId;
    const requestCounter = promClient.register.getSingleMetric('request_counter');
    const requestLatency = promClient.register.getSingleMetric('request_latency_seconds');

    try {
        if (userId === removerId) {
            requestCounter.inc({ endpoint, method: 'DELETE', status: 400 });
            throw new ApiError(400, 'Cannot remove endorsements from your own skills');
        }

        const profile = await Profile.findOne({ userId, status: 'active' });
        if (!profile) {
            requestCounter.inc({ endpoint, method: 'DELETE', status: 404 });
            throw new ApiError(404, 'Profile not found');
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();
            const skill = profile.skills.find(s => s.name.toLowerCase() === skillName.toLowerCase());
            if (!skill) {
                await session.abortTransaction();
                requestCounter.inc({ endpoint, method: 'DELETE', status: 400 });
                throw new ApiError(400, 'Skill not found');
            }
            if (skill.endorsements.count > 0) {
                skill.endorsements.count = Math.max(0, skill.endorsements.count - 1);
                skill.endorsements.lastEndorsedAt = new Date();
                await profile.save({ session });
            }
            await session.commitTransaction();

            await deleteCacheData(generateCacheKey('user', userId));
            await deleteCacheData(generateCacheKey('slug', profile.settings.profileSlug));

            profileEventEmitter.emit('skillEndorsementRemoved', {
                userId,
                skillName,
                removerId,
                profileId: profile._id,
            });

            logger.info(`Skill "${skillName}" endorsement removed by ${removerId} for user: ${userId}`);
            requestCounter.inc({ endpoint, method: 'DELETE', status: 200 });
            requestLatency.observe({ endpoint, method: 'DELETE' }, (Date.now() - start) / 1000);

            res.json(new ApiResponse(200, null, 'Skill endorsement removed successfully'));
        } catch (error) {
            await session.abortTransaction();
            throw error;
        } finally {
            session.endSession();
        }
    } catch (error) {
        requestCounter.inc({ endpoint, method: 'DELETE', status: error.statusCode || 500 });
        throw error;
    }
});

// ===========================
// SEARCH AND DISCOVERY
// ===========================
router.get('/search', searchLimiter, searchValidation, validateRequest, searchProfiles);
router.get('/trending', getTrendingProfiles);
router.get('/nearby', nearbyValidation, validateRequest, getNearbyProfiles);
router.get('/recommendations', getRecommendations);

// ===========================
// PROFILE ANALYTICS
// ===========================
router.get('/:userId/analytics', validateUserId, validateRequest, getProfileAnalytics);
router.get('/:userId/career-progression', validateUserId, validateRequest, getCareerProgression);

// ===========================
// COVER AND DESIGN ANALYTICS
// ===========================
router.get('/covers/summary', analyticsLimiter, analyticsValidation, validateRequest, async (req, res, next) => {
    const start = Date.now();
    const endpoint = 'getCoverAnalyticsSummary';
    const { timeframe = '30d', category = 'all' } = req.query;
    const userId = req.user.userId;
    const requestCounter = promClient.register.getSingleMetric('request_counter');
    const requestLatency = promClient.register.getSingleMetric('request_latency_seconds');

    try {
        const summary = await AnalyticsService.getCoverAnalyticsSummary(userId, timeframe, category, req.user.groups || []);
        logger.info(`Cover analytics summary retrieved for user: ${userId}, timeframe: ${timeframe}, category: ${category}`);
        requestCounter.inc({ endpoint, method: 'GET', status: 200 });
        requestLatency.observe({ endpoint, method: 'GET' }, (Date.now() - start) / 1000);
        res.json(new ApiResponse(200, summary, 'Cover analytics summary retrieved successfully'));
    } catch (error) {
        requestCounter.inc({ endpoint, method: 'GET', status: error.statusCode || 500 });
        throw error;
    }
});

router.get('/designs/summary', analyticsLimiter, analyticsValidation, validateRequest, async (req, res, next) => {
    const start = Date.now();
    const endpoint = 'getDesignAnalyticsSummary';
    const { timeframe = '30d', category = 'all' } = req.query;
    const userId = req.user.userId;
    const requestCounter = promClient.register.getSingleMetric('request_counter');
    const requestLatency = promClient.register.getSingleMetric('request_latency_seconds');

    try {
        const summary = await AnalyticsService.getDesignAnalyticsSummary(userId, timeframe, category, req.user.groups || []);
        logger.info(`Design analytics summary retrieved for user: ${userId}, timeframe: ${timeframe}, category: ${category}`);
        requestCounter.inc({ endpoint, method: 'GET', status: 200 });
        requestLatency.observe({ endpoint, method: 'GET' }, (Date.now() - start) / 1000);
        res.json(new ApiResponse(200, summary, 'Design analytics summary retrieved successfully'));
    } catch (error) {
        requestCounter.inc({ endpoint, method: 'GET', status: error.statusCode || 500 });
        throw error;
    }
});

router.get('/covers/trending', analyticsLimiter, analyticsValidation, validateRequest, async (req, res, next) => {
    const start = Date.now();
    const endpoint = 'getTrendingCovers';
    const { timeframe = '7d', limit = 10, category = 'all' } = req.query;
    const userId = req.user.userId;
    const requestCounter = promClient.register.getSingleMetric('request_counter');
    const requestLatency = promClient.register.getSingleMetric('request_latency_seconds');

    try {
        const covers = await AnalyticsService.getTrendingCovers(timeframe, limit, category, userId, req.user.groups || []);
        logger.info(`Trending covers retrieved for user: ${userId}, timeframe: ${timeframe}, category: ${category}, limit: ${limit}`);
        requestCounter.inc({ endpoint, method: 'GET', status: 200 });
        requestLatency.observe({ endpoint, method: 'GET' }, (Date.now() - start) / 1000);
        res.json(new ApiResponse(200, covers, 'Trending covers retrieved successfully'));
    } catch (error) {
        requestCounter.inc({ endpoint, method: 'GET', status: error.statusCode || 500 });
        throw error;
    }
});

router.get('/designs/trending', analyticsLimiter, analyticsValidation, validateRequest, async (req, res, next) => {
    const start = Date.now();
    const endpoint = 'getTrendingDesigns';
    const { timeframe = '7d', limit = 10, category = 'all' } = req.query;
    const userId = req.user.userId;
    const requestCounter = promClient.register.getSingleMetric('request_counter');
    const requestLatency = promClient.register.getSingleMetric('request_latency_seconds');

    try {
        const designs = await AnalyticsService.getTrendingDesigns(timeframe, limit, category, userId, req.user.groups || []);
        logger.info(`Trending designs retrieved for user: ${userId}, timeframe: ${timeframe}, category: ${category}, limit: ${limit}`);
        requestCounter.inc({ endpoint, method: 'GET', status: 200 });
        requestLatency.observe({ endpoint, method: 'GET' }, (Date.now() - start) / 1000);
        res.json(new ApiResponse(200, designs, 'Trending designs retrieved successfully'));
    } catch (error) {
        requestCounter.inc({ endpoint, method: 'GET', status: error.statusCode || 500 });
        throw error;
    }
});

router.get('/covers/:id/analytics', analyticsLimiter, resourceValidation, validateRequest, async (req, res, next) => {
    const start = Date.now();
    const endpoint = 'getCoverAnalytics';
    const { id } = req.params;
    const { timeframe = '30d' } = req.query;
    const userId = req.user.userId;
    const requestCounter = promClient.register.getSingleMetric('request_counter');
    const requestLatency = promClient.register.getSingleMetric('request_latency_seconds');

    try {
        const analytics = await AnalyticsService.getCoverAnalytics(id, timeframe, userId, req.user.groups || []);
        logger.info(`Cover analytics retrieved for cover: ${id}, user: ${userId}, timeframe: ${timeframe}`);
        requestCounter.inc({ endpoint, method: 'GET', status: 200 });
        requestLatency.observe({ endpoint, method: 'GET' }, (Date.now() - start) / 1000);
        res.json(new ApiResponse(200, analytics, 'Cover analytics retrieved successfully'));
    } catch (error) {
        requestCounter.inc({ endpoint, method: 'GET', status: error.statusCode || 500 });
        throw error;
    }
});

router.get('/designs/:id/analytics', analyticsLimiter, resourceValidation, validateRequest, async (req, res, next) => {
    const start = Date.now();
    const endpoint = 'getDesignAnalytics';
    const { id } = req.params;
    const { timeframe = '30d' } = req.query;
    const userId = req.user.userId;
    const requestCounter = promClient.register.getSingleMetric('request_counter');
    const requestLatency = promClient.register.getSingleMetric('request_latency_seconds');

    try {
        const analytics = await AnalyticsService.getDesignAnalytics(id, timeframe, userId, req.user.groups || []);
        logger.info(`Design analytics retrieved for design: ${id}, user: ${userId}, timeframe: ${timeframe}`);
        requestCounter.inc({ endpoint, method: 'GET', status: 200 });
        requestLatency.observe({ endpoint, method: 'GET' }, (Date.now() - start) / 1000);
        res.json(new ApiResponse(200, analytics, 'Design analytics retrieved successfully'));
    } catch (error) {
        requestCounter.inc({ endpoint, method: 'GET', status: error.statusCode || 500 });
        throw error;
    }
});

router.post('/covers/:id/insights', analyticsLimiter, resourceValidation, validateRequest, async (req, res, next) => {
    const start = Date.now();
    const endpoint = 'generateCoverAnalyticsInsights';
    const { id } = req.params;
    const { timeframe = '30d' } = req.query;
    const userId = req.user.userId;
    const requestCounter = promClient.register.getSingleMetric('request_counter');
    const requestLatency = promClient.register.getSingleMetric('request_latency_seconds');

    try {
        const insights = await AnalyticsService.generateAnalyticsInsights(id, 'cover', timeframe, userId, req.user.groups || []);
        logger.info(`Cover analytics insights generated for cover: ${id}, user: ${userId}, timeframe: ${timeframe}`);
        requestCounter.inc({ endpoint, method: 'POST', status: 200 });
        requestLatency.observe({ endpoint, method: 'POST' }, (Date.now() - start) / 1000);
        res.json(new ApiResponse(200, insights, 'Cover analytics insights generated successfully'));
    } catch (error) {
        requestCounter.inc({ endpoint, method: 'POST', status: error.statusCode || 500 });
        throw error;
    }
});

router.post('/designs/:id/insights', analyticsLimiter, resourceValidation, validateRequest, async (req, res, next) => {
    const start = Date.now();
    const endpoint = 'generateDesignAnalyticsInsights';
    const { id } = req.params;
    const { timeframe = '30d' } = req.query;
    const userId = req.user.userId;
    const requestCounter = promClient.register.getSingleMetric('request_counter');
    const requestLatency = promClient.register.getSingleMetric('request_latency_seconds');

    try {
        const insights = await AnalyticsService.generateAnalyticsInsights(id, 'design', timeframe, userId, req.user.groups || []);
        logger.info(`Design analytics insights generated for design: ${id}, user: ${userId}, timeframe: ${timeframe}`);
        requestCounter.inc({ endpoint, method: 'POST', status: 200 });
        requestLatency.observe({ endpoint, method: 'POST' }, (Date.now() - start) / 1000);
        res.json(new ApiResponse(200, insights, 'Design analytics insights generated successfully'));
    } catch (error) {
        requestCounter.inc({ endpoint, method: 'POST', status: error.statusCode || 500 });
        throw error;
    }
});

router.get('/covers/:id/platform', analyticsLimiter, platformValidation, validateRequest, async (req, res, next) => {
    const start = Date.now();
    const endpoint = 'getCoverPlatformAnalytics';
    const { id } = req.params;
    const { timeframe = '30d', platform } = req.query;
    const userId = req.user.userId;
    const requestCounter = promClient.register.getSingleMetric('request_counter');
    const requestLatency = promClient.register.getSingleMetric('request_latency_seconds');

    try {
        const analytics = await AnalyticsService.getPlatformAnalytics(id, 'cover', timeframe, platform, userId, req.user.groups || []);
        logger.info(`Cover platform analytics retrieved for cover: ${id}, user: ${userId}, platform: ${platform}, timeframe: ${timeframe}`);
        requestCounter.inc({ endpoint, method: 'GET', status: 200 });
        requestLatency.observe({ endpoint, method: 'GET' }, (Date.now() - start) / 1000);
        res.json(new ApiResponse(200, analytics, 'Cover platform analytics retrieved successfully'));
    } catch (error) {
        requestCounter.inc({ endpoint, method: 'GET', status: error.statusCode || 500 });
        throw error;
    }
});

router.get('/designs/:id/platform', analyticsLimiter, platformValidation, validateRequest, async (req, res, next) => {
    const start = Date.now();
    const endpoint = 'getDesignPlatformAnalytics';
    const { id } = req.params;
    const { timeframe = '30d', platform } = req.query;
    const userId = req.user.userId;
    const requestCounter = promClient.register.getSingleMetric('request_counter');
    const requestLatency = promClient.register.getSingleMetric('request_latency_seconds');

    try {
        const analytics = await AnalyticsService.getPlatformAnalytics(id, 'design', timeframe, platform, userId, req.user.groups || []);
        logger.info(`Design platform analytics retrieved for design: ${id}, user: ${userId}, platform: ${platform}, timeframe: ${timeframe}`);
        requestCounter.inc({ endpoint, method: 'POST', status: 200 });
        requestLatency.observe({ endpoint, method: 'POST' }, (Date.now() - start) / 1000);
        res.json(new ApiResponse(200, analytics, 'Design platform analytics retrieved successfully'));
    } catch (error) {
        requestCounter.inc({ endpoint, method: 'POST', status: error.statusCode || 500 });
        throw error;
    }
});

router.patch('/covers/:id/metrics', analyticsLimiter, updateMetricsValidation, validateRequest, async (req, res, next) => {
    const start = Date.now();
    const endpoint = 'updateCoverAnalyticsMetrics';
    const { id } = req.params;
    const { metrics } = req.body;
    const userId = req.user.userId;
    const requestCounter = promClient.register.getSingleMetric('request_counter');
    const requestLatency = promClient.register.getSingleMetric('request_latency_seconds');

    try {
        const result = await AnalyticsService.updateAnalyticsMetrics(id, 'cover', metrics, userId, req.user.groups || []);
        logger.info(`Cover analytics metrics updated for cover: ${id}, user: ${userId}`);
        requestCounter.inc({ endpoint, method: 'PATCH', status: 200 });
        requestLatency.observe({ endpoint, method: 'PATCH' }, (Date.now() - start) / 1000);
        res.json(new ApiResponse(200, result, 'Cover analytics metrics updated successfully'));
    } catch (error) {
        requestCounter.inc({ endpoint, method: 'PATCH', status: error.statusCode || 500 });
        throw error;
    }
});

router.patch('/designs/:id/metrics', analyticsLimiter, updateMetricsValidation, validateRequest, async (req, res, next) => {
    const start = Date.now();
    const endpoint = 'updateDesignAnalyticsMetrics';
    const { id } = req.params;
    const { metrics } = req.body;
    const userId = req.user.userId;
    const requestCounter = promClient.register.getSingleMetric('request_counter');
    const requestLatency = promClient.register.getSingleMetric('request_latency_seconds');

    try {
        const result = await AnalyticsService.updateAnalyticsMetrics(id, 'design', metrics, userId, req.user.groups || []);
        logger.info(`Design analytics metrics updated for design: ${id}, user: ${userId}`);
        requestCounter.inc({ endpoint, method: 'PATCH', status: 200 });
        requestLatency.observe({ endpoint, method: 'PATCH' }, (Date.now() - start) / 1000);
        res.json(new ApiResponse(200, result, 'Design analytics metrics updated successfully'));
    } catch (error) {
        requestCounter.inc({ endpoint, method: 'PATCH', status: error.statusCode || 500 });
        throw error;
    }
});

router.patch('/covers/bulk-metrics', analyticsLimiter, bulkUpdateMetricsValidation, validateRequest, async (req, res, next) => {
    const start = Date.now();
    const endpoint = 'bulkUpdateCoverAnalyticsMetrics';
    const { ids, metrics } = req.body;
    const userId = req.user.userId;
    const requestCounter = promClient.register.getSingleMetric('request_counter');
    const requestLatency = promClient.register.getSingleMetric('request_latency_seconds');

    try {
        const result = await AnalyticsService.bulkUpdateAnalyticsMetrics(ids, 'cover', metrics, userId, req.user.groups || []);
        logger.info(`Bulk cover analytics metrics updated for ${ids.length} covers by user: ${userId}`);
        requestCounter.inc({ endpoint, method: 'PATCH', status: 200 });
        requestLatency.observe({ endpoint, method: 'PATCH' }, (Date.now() - start) / 1000);
        res.json(new ApiResponse(200, result, 'Bulk cover analytics metrics updated successfully'));
    } catch (error) {
        requestCounter.inc({ endpoint, method: 'PATCH', status: error.statusCode || 500 });
        throw error;
    }
});

router.patch('/designs/bulk-metrics', analyticsLimiter, bulkUpdateMetricsValidation, validateRequest, async (req, res, next) => {
    const start = Date.now();
    const endpoint = 'bulkUpdateDesignAnalyticsMetrics';
    const { ids, metrics } = req.body;
    const userId = req.user.userId;
    const requestCounter = promClient.register.getSingleMetric('request_counter');
    const requestLatency = promClient.register.getSingleMetric('request_latency_seconds');

    try {
        const result = await AnalyticsService.bulkUpdateAnalyticsMetrics(ids, 'design', metrics, userId, req.user.groups || []);
        logger.info(`Bulk design analytics metrics updated for ${ids.length} designs by user: ${userId}`);
        requestCounter.inc({ endpoint, method: 'PATCH', status: 200 });
        requestLatency.observe({ endpoint, method: 'PATCH' }, (Date.now() - start) / 1000);
        res.json(new ApiResponse(200, result, 'Bulk design analytics metrics updated successfully'));
    } catch (error) {
        requestCounter.inc({ endpoint, method: 'PATCH', status: error.statusCode || 500 });
        throw error;
    }
});

router.get('/covers/:id/trends', analyticsLimiter, resourceValidation, validateRequest, async (req, res, next) => {
    const start = Date.now();
    const endpoint = 'getCoverEngagementTrends';
    const { id } = req.params;
    const { timeframe = '30d' } = req.query;
    const userId = req.user.userId;
    const requestCounter = promClient.register.getSingleMetric('request_counter');
    const requestLatency = promClient.register.getSingleMetric('request_latency_seconds');

    try {
        const trends = await AnalyticsService.getEngagementTrends(id, 'cover', timeframe, userId, req.user.groups || []);
        logger.info(`Cover engagement trends retrieved for cover: ${id}, user: ${userId}, timeframe: ${timeframe}`);
        requestCounter.inc({ endpoint, method: 'GET', status: 200 });
        requestLatency.observe({ endpoint, method: 'GET' }, (Date.now() - start) / 1000);
        res.json(new ApiResponse(200, trends, 'Cover engagement trends retrieved successfully'));
    } catch (error) {
        requestCounter.inc({ endpoint, method: 'GET', status: error.statusCode || 500 });
        throw error;
    }
});

router.get('/designs/:id/trends', analyticsLimiter, resourceValidation, validateRequest, async (req, res, next) => {
    const start = Date.now();
    const endpoint = 'getDesignEngagementTrends';
    const { id } = req.params;
    const { timeframe = '30d' } = req.query;
    const userId = req.user.userId;
    const requestCounter = promClient.register.getSingleMetric('request_counter');
    const requestLatency = promClient.register.getSingleMetric('request_latency_seconds');

    try {
        const trends = await AnalyticsService.getEngagementTrends(id, 'design', timeframe, userId, req.user.groups || []);
        logger.info(`Design engagement trends retrieved for design: ${id}, user: ${userId}, timeframe: ${timeframe}`);
        requestCounter.inc({ endpoint, method: 'GET', status: 200 });
        requestLatency.observe({ endpoint, method: 'GET' }, (Date.now() - start) / 1000);
        res.json(new ApiResponse(200, trends, 'Design engagement trends retrieved successfully'));
    } catch (error) {
        requestCounter.inc({ endpoint, method: 'GET', status: error.statusCode || 500 });
        throw error;
    }
});

// ===========================
// ADMIN ROUTES
// ===========================
router.use('/admin', adminLimiter, requireRole('admin'));

router.get('/admin/analytics', getAnalyticsSummary);
router.post('/admin/bulk-update-scores', validateBulkUpdateScores, validateRequest, bulkUpdateCompletionScores);
router.post('/admin/bulk-delete', validateBulkDelete, validateRequest, bulkDeleteProfiles);
router.get('/admin/profiles', searchValidation, validateRequest, searchProfiles);

router.patch('/admin/verify/:userId', validateUserId, [
    body('action').isIn(['approve', 'reject']).withMessage('Action must be approve or reject'),
    body('verificationType').isIn(['identity', 'professional', 'education']).withMessage('Verification type must be identity, professional, or education'),
    body('reason').optional().trim().isLength({ max: 500 }).withMessage('Reason must be less than 500 characters'),
], validateRequest, async (req, res, next) => {
    const start = Date.now();
    const endpoint = 'verifyProfile';
    const { userId } = req.params;
    const { action, verificationType, reason } = req.body;
    const requestCounter = promClient.register.getSingleMetric('request_counter');
    const requestLatency = promClient.register.getSingleMetric('request_latency_seconds');

    try {
        const profile = await Profile.findOne({ userId, status: 'active' });
        if (!profile) {
            requestCounter.inc({ endpoint, method: 'PATCH', status: 404 });
            throw new ApiError(404, 'Profile not found');
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();
            if (action === 'approve') {
                profile.verification = {
                    ...profile.verification,
                    isVerified: true,
                    verifiedAt: new Date(),
                    verifiedBy: req.user.userId,
                    verificationLevel: verificationType,
                    badges: [...(profile.verification.badges || []), `verified - ${verificationType}`],
                };
            } else {
                profile.verification = {
                    ...profile.verification,
                    isVerified: false,
                    verificationLevel: 'basic',
                    verifiedAt: null,
                    verifiedBy: null,
                };
            }
            await profile.save({ session });
            await session.commitTransaction();

            await deleteCacheData(generateCacheKey('user', userId));
            await deleteCacheData(generateCacheKey('slug', profile.settings.profileSlug));

            profileEventEmitter.emit('verificationProcessed', {
                userId,
                profileId: profile._id,
                action,
                verificationType,
                reason,
            });

            logger.info(`Verification ${action} for user: ${userId}, type: ${verificationType}`);
            requestCounter.inc({ endpoint, method: 'PATCH', status: 200 });
            requestLatency.observe({ endpoint, method: 'PATCH' }, (Date.now() - start) / 1000);

            res.json(new ApiResponse(200, null, `Verification ${action} successfully`));
        } catch (error) {
            await session.abortTransaction();
            throw error;
        } finally {
            session.endSession();
        }
    } catch (error) {
        requestCounter.inc({ endpoint, method: 'PATCH', status: error.statusCode || 500 });
        throw error;
    }
});

// ===========================
// PROFILE VERIFICATION
// ===========================
router.post('/:userId/verify/request', validateUserId, [
    body('verificationType').isIn(['identity', 'professional', 'education']).withMessage('Verification type must be identity, professional, or education'),
    body('documents').isArray({ min: 1, max: 5 }).withMessage('Documents array must contain 1-5 items'),
    body('documents.*.url').isURL().withMessage('Each document must have a valid URL'),
], validateRequest, async (req, res, next) => {
    const start = Date.now();
    const endpoint = 'requestVerification';
    const { userId } = req.params;
    const { verificationType, documents } = req.body;
    const requestCounter = promClient.register.getSingleMetric('request_counter');
    const requestLatency = promClient.register.getSingleMetric('request_latency_seconds');

    try {
        if (userId !== req.user.userId) {
            requestCounter.inc({ endpoint, method: 'POST', status: 403 });
            throw new ApiError(403, 'Unauthorized to request verification for this profile');
        }

        const profile = await Profile.findOne({ userId, status: 'active' });
        if (!profile) {
            requestCounter.inc({ endpoint, method: 'POST', status: 404 });
            throw new ApiError(404, 'Profile not found');
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();
            profile.verification = {
                ...profile.verification,
                isVerified: false,
                verificationLevel: 'pending',
                verifiedAt: null,
                verifiedBy: null,
                badges: profile.verification.badges || [],
            };
            await profile.save({ session });
            await session.commitTransaction();

            profileEventEmitter.emit('verificationRequested', {
                userId,
                profileId: profile._id,
                verificationType,
                documents,
            });

            logger.info(`Verification requested for user: ${userId}, type: ${verificationType}`);
            requestCounter.inc({ endpoint, method: 'POST', status: 200 });
            requestLatency.observe({ endpoint, method: 'POST' }, (Date.now() - start) / 1000);

            res.json(new ApiResponse(200, null, 'Verification request submitted'));
        } catch (error) {
            await session.abortTransaction();
            throw error;
        } finally {
            session.endSession();
        }
    } catch (error) {
        requestCounter.inc({ endpoint, method: 'POST', status: error.statusCode || 500 });
        throw error;
    }
});

// ===========================
// PROFILE IMPORT/EXPORT
// ===========================
router.get('/:userId/export', validateUserId, validateRequest, async (req, res, next) => {
    const start = Date.now();
    const endpoint = 'exportProfile';
    const { userId } = req.params;
    const requestCounter = promClient.register.getSingleMetric('request_counter');
    const requestLatency = promClient.register.getSingleMetric('request_latency_seconds');

    try {
        if (userId !== req.user.userId && req.user.role !== 'admin') {
            requestCounter.inc({ endpoint, method: 'GET', status: 403 });
            throw new ApiError(403, 'Unauthorized to export this profile');
        }

        const profile = await Profile.findOne({ userId, status: 'active' }).lean();
        if (!profile) {
            requestCounter.inc({ endpoint, method: 'GET', status: 404 });
            throw new ApiError(404, 'Profile not found');
        }

        const exportData = profile.getPublicProfile();
        delete exportData.analytics;

        profileEventEmitter.emit('profileExported', {
            userId,
            profileId: profile._id,
        });

        logger.info(`Profile exported for user: ${userId}`);
        requestCounter.inc({ endpoint, method: 'GET', status: 200 });
        requestLatency.observe({ endpoint, method: 'GET' }, (Date.now() - start) / 1000);

        res.json(new ApiResponse(200, exportData, 'Profile exported successfully'));
    } catch (error) {
        requestCounter.inc({ endpoint, method: 'GET', status: error.statusCode || 500 });
        throw error;
    }
});

router.post('/:userId/import', validateUserId, upload.single('importFile'), [
    body('platform').isIn(['linkedin', 'resume', 'json']).withMessage('Platform must be linkedin, resume, or json'),
], validateRequest, async (req, res, next) => {
    const start = Date.now();
    const endpoint = 'importProfile';
    const { userId } = req.params;
    const { platform } = req.body;
    const requestCounter = promClient.register.getSingleMetric('request_counter');
    const requestLatency = promClient.register.getSingleMetric('request_latency_seconds');

    try {
        if (userId !== req.user.userId) {
            requestCounter.inc({ endpoint, method: 'POST', status: 403 });
            throw new ApiError(403, 'Unauthorized to import to this profile');
        }

        if (!req.file) {
            requestCounter.inc({ endpoint, method: 'POST', status: 400 });
            throw new ApiError(400, 'No import file provided');
        }

        const profile = await Profile.findOne({ userId, status: 'active' });
        if (!profile) {
            requestCounter.inc({ endpoint, method: 'POST', status: 404 });
            throw new ApiError(404, 'Profile not found');
        }

        let importData;
        if (platform === 'json') {
            importData = JSON.parse(req.file.buffer.toString());
        } else {
            requestCounter.inc({ endpoint, method: 'POST', status: 501 });
            throw new ApiError(501, 'Import from LinkedIn/resume not yet implemented');
        }

        const validatedData = await validateProfileData(importData, true);
        const session = await mongoose.startSession();
        try {
            session.startTransaction();
            await Profile.updateOne(
                { userId, status: { $ne: 'deleted' } },
                { $set: validatedData },
                { session }
            );
            await session.commitTransaction();

            const updatedProfile = await Profile.findOne({ userId }).lean();
            await deleteCacheData(generateCacheKey('user', userId));
            await deleteCacheData(generateCacheKey('slug', updatedProfile.settings.profileSlug));

            profileEventEmitter.emit('profileImported', {
                userId,
                profileId: updatedProfile._id,
                platform,
            });

            logger.info(`Profile imported for user: ${userId}, platform: ${platform}`);
            requestCounter.inc({ endpoint, method: 'POST', status: 200 });
            requestLatency.observe({ endpoint, method: 'POST' }, (Date.now() - start) / 1000);

            res.json(new ApiResponse(200, updatedProfile.getPublicProfile(), 'Profile imported successfully'));
        } catch (error) {
            await session.abortTransaction();
            throw error;
        } finally {
            session.endSession();
        }
    } catch (error) {
        requestCounter.inc({ endpoint, method: 'POST', status: error.statusCode || 500 });
        throw error;
    }
});

// ===========================
// ERROR HANDLING
// ===========================
router.use('*', (req, res) => {
    logger.warn(`API 404: ${req.method} ${req.originalUrl}`, {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
    });
    res.status(404).json({
        success: false,
        message: 'API endpoint not found',
        path: req.originalUrl,
        method: req.method,
        timestamp: new Date().toISOString(),
    });
});

router.use(handleProfileErrors);

// ===========================
// ROUTE DOCUMENTATION
// ===========================
if (process.env.NODE_ENV === 'development') {
    router.get('/docs', (req, res) => {
        res.json({
            name: 'Profile and Analytics API',
            version: '1.0.0',
            description: 'RESTful API for profile management and cover/design analytics',
            baseUrl: '/api/v1',
            routes: {
                public: [
                    'GET /health - Health check',
                    'GET /public/:identifier - Get public profile',
                    'GET /metrics - Prometheus metrics (admin-only)',
                ],
                authenticated: [
                    'POST / - Create profile',
                    'GET /:identifier - Get profile',
                    'PATCH /:userId - Update profile',
                    'DELETE /:userId - Delete profile',
                    'GET /search - Search profiles',
                    'GET /trending - Get trending profiles',
                    'GET /nearby - Get nearby profiles',
                    'GET /recommendations - Get recommendations',
                    'POST /:userId/photo - Upload profile photo',
                    'POST /:userId/cover - Upload cover photo',
                    'POST /:userId/skills/:skillName/endorse - Endorse skill',
                    'DELETE /:userId/skills/:skillName/endorse - Remove skill endorsement',
                    'GET /:userId/analytics - Get profile analytics',
                    'GET /:userId/career-progression - Get career progression',
                    'POST /:userId/verify/request - Request profile verification',
                    'GET /:userId/export - Export profile data',
                    'POST /:userId/import - Import profile data',
                    'GET /covers/summary - Get cover analytics summary',
                    'GET /designs/summary - Get design analytics summary',
                    'GET /covers/trending - Get trending covers',
                    'GET /designs/trending - Get trending designs',
                    'GET /covers/:id/analytics - Get cover analytics',
                    'GET /designs/:id/analytics - Get design analytics',
                    'POST /covers/:id/insights - Generate cover analytics insights',
                    'POST /designs/:id/insights - Generate design analytics insights',
                    'GET /covers/:id/platform - Get cover platform analytics',
                    'GET /designs/:id/platform - Get design platform analytics',
                    'PATCH /covers/:id/metrics - Update cover analytics metrics',
                    'PATCH /designs/:id/metrics - Update design analytics metrics',
                    'PATCH /covers/bulk-metrics - Bulk update cover analytics metrics',
                    'PATCH /designs/bulk-metrics - Bulk update design analytics metrics',
                    'GET /covers/:id/trends - Get cover engagement trends',
                    'GET /designs/:id/trends - Get design engagement trends',
                ],
                admin: [
                    'GET /admin/analytics - Get analytics summary',
                    'POST /admin/bulk-update-scores - Bulk update scores',
                    'POST /admin/bulk-delete - Bulk delete profiles',
                    'GET /admin/profiles - Get all profiles',
                    'PATCH /admin/verify/:userId - Approve/reject verification',
                ],
            },
            rateLimits: {
                createProfile: '5 requests per 15 minutes per user',
                updateProfile: '20 requests per 5 minutes per user',
                search: '100 requests per minute per user/IP',
                analytics: '100 requests per 10 minutes per user',
                admin: '50 requests per 15 minutes per admin',
            },
        });
    });
}

export default router;