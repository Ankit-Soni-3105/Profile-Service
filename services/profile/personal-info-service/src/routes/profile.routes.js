// profile-service/src/routes/profileRoutes.js
import csrf from 'csurf';
import { Router } from 'express';
import promClient from 'prom-client';
import compression from 'compression';
import { logger } from '../utils/logger.js';
import { upload } from '../middlewares/upload.middleware.js';
import { requireRole } from '../middlewares/role.middleware.js';
import { validateRequest } from '../middlewares/validateRequest.middleware.js';
import authProfileMiddleware from '../middlewares/profile.middleware.js';

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

const router = Router();

// ===========================
// MIDDLEWARE SETUP
// ===========================
// Request logging middleware
router.use((req, res, next) => {
    logger.info(`Profile API Request: ${req.method} ${req.path},`, {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        userId: req.user?.userId || 'anonymous',
        timestamp: new Date().toISOString(),
    });
    next();
});

// Security headers middleware
router.use((req, res, next) => {
    res.set({
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
    });
    next();
});

// Compression middleware
router.use(compression());

// CSRF protection for state-changing routes
const csrfProtection = csrf({ cookie: true });
router.use((req, res, next) => {
    if (['POST', 'PATCH', 'DELETE'].includes(req.method)) {
        csrfProtection(req, res, next);
    } else {
        next();
    }
});

// Audit logging middleware
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

// Admin rate limiter
const adminLimiter = require('express-rate-limit')({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 50,
    message: 'Too many admin requests, please try again later',
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

// ===========================
// PUBLIC ROUTES
// ===========================
// Health check endpoint (no auth required)
router.get('/health', healthCheck);

// Public profile view (limited data, no auth required)
router.get('/public/:identifier', validateIdentifier, validateRequest, getProfile);

// Metrics endpoint (admin-only)
router.get('/metrics', requireRole('admin'), async (req, res) => {
    res.set('Content-Type', promClient.register.contentType);
    res.end(await promClient.register.metrics());
});

// ===========================
// AUTHENTICATED ROUTES
// ===========================
router.use(authProfileMiddleware);

// Apply audit logging to state-changing routes
router.use(['/:userId', '/:userId/', '/admin/'], auditLog);

// ===========================
// PROFILE CRUD OPERATIONS
// ===========================
router.post('/', createProfileLimiter, validateCreateProfile, validateRequest, createProfile);
router.get('/:identifier', validateIdentifier, validateRequest, getProfile);
router.patch('/:userId', updateProfileLimiter, validateUserId, validateUpdateProfile, validateRequest, updateProfile);
router.delete('/:userId', validateUserId, validateRequest, deleteProfile);

// ===========================
// SEARCH AND DISCOVERY
// ===========================
router.get('/search', searchLimiter, searchValidation, validateRequest, searchProfiles);
router.get('/trending', getTrendingProfiles);
router.get('/nearby', nearbyValidation, validateRequest, getNearbyProfiles);
router.get('/recommendations', getRecommendations);

// ===========================
// PROFILE ENHANCEMENT
// ===========================
router.post('/:userId/photo', validateUserId, upload.single('photo'), validateRequest, uploadProfilePhoto);

// Upload cover photo (new controller)
router.post('/:userId/cover', validateUserId, upload.single('cover'), validateRequest, async (req, res, next) => {
    const start = Date.now();
    const endpoint = 'uploadCoverPhoto';
    const { userId } = req.params;
    const requesterId = req.user.userId;

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

// Remove skill endorsement (new controller)
router.delete('/:userId/skills/:skillName/endorse', validateUserId, validateSkillName, validateRequest, async (req, res, next) => {
    const start = Date.now();
    const endpoint = 'removeSkillEndorsement';
    const { userId, skillName } = req.params;
    const removerId = req.user.userId;

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

router.get('/:userId/analytics', validateUserId, validateRequest, getProfileAnalytics);
router.get('/:userId/career-progression', validateUserId, validateRequest, getCareerProgression);

// ===========================
// ADMIN ROUTES
// ===========================
router.use('/admin', adminLimiter, requireRole('admin'));

router.get('/admin/analytics', getAnalyticsSummary);
router.post('/admin/bulk-update-scores', validateBulkUpdateScores, validateRequest, bulkUpdateCompletionScores);
router.post('/admin/bulk-delete', validateBulkDelete, validateRequest, bulkDeleteProfiles);
router.get('/admin/profiles', searchValidation, validateRequest, searchProfiles);

// ===========================
// PROFILE VERIFICATION
// ===========================
router.post(
    '/:userId/verify/request',
    validateUserId,
    [
        body('verificationType').isIn(['identity', 'professional', 'education']).withMessage('Verification type must be identity, professional, or education'),
        body('documents').isArray({ min: 1, max: 5 }).withMessage('Documents array must contain 1-5 items'),
        body('documents.*.url').isURL().withMessage('Each document must have a valid URL'),
    ],
    validateRequest,
    async (req, res, next) => {
        const start = Date.now();
        const endpoint = 'requestVerification';
        const { userId } = req.params;
        const { verificationType, documents } = req.body;

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
    }
);

router.patch(
    '/admin/verify/:userId',
    validateUserId,
    [
        body('action').isIn(['approve', 'reject']).withMessage('Action must be approve or reject'),
        body('verificationType').isIn(['identity', 'professional', 'education']).withMessage('Verification type must be identity, professional, or education'),
        body('reason').optional().trim().isLength({ max: 500 }).withMessage('Reason must be less than 500 characters'),
    ],
    validateRequest,
    async (req, res, next) => {
        const start = Date.now();
        const endpoint = 'verifyProfile';
        const { userId } = req.params;
        const { action, verificationType, reason } = req.body;

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
    }
);

// ===========================
// PROFILE IMPORT/EXPORT
// ===========================
router.get('/:userId/export', validateUserId, validateRequest, async (req, res, next) => {
    const start = Date.now();
    const endpoint = 'exportProfile';
    const { userId } = req.params;

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
        delete exportData.analytics; // Remove sensitive analytics for GDPR compliance

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

router.post(
    '/:userId/import',
    validateUserId,
    upload.single('importFile'),
    [
        body('platform').isIn(['linkedin', 'resume', 'json']).withMessage('Platform must be linkedin, resume, or json'),
    ],
    validateRequest,
    async (req, res, next) => {
        const start = Date.now();
        const endpoint = 'importProfile';
        const { userId } = req.params;
        const { platform } = req.body;

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

            // Placeholder: Parse import file based on platform (implement parsing logic as needed)
            let importData;
            if (platform === 'json') {
                importData = JSON.parse(req.file.buffer.toString());
            } else {
                // Implement LinkedIn/resume parsing logic
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
    }
);

// ===========================
// ERROR HANDLING
// ===========================
router.use('*', (req, res) => {
    logger.warn(`Profile API 404: ${req.method} ${req.originalUrl}`, {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
    });
    res.status(404).json({
        success: false,
        message: 'Profile API endpoint not found',
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
            name: 'Profile Service API',
            version: '1.0.0',
            description: 'RESTful API for profile management',
            baseUrl: '/api/v1/profiles',
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
                    'GET /:userId/analytics - Get analytics',
                    'GET /:userId/career-progression - Get career progression',
                    'POST /:userId/verify/request - Request profile verification',
                    'GET /:userId/export - Export profile data',
                    'POST /:userId/import - Import profile data',
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
                admin: '50 requests per 15 minutes per admin',
            },
        });
    });
}

export default router;