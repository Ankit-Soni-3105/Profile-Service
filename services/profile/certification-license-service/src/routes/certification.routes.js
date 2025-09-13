import csrf from 'csurf';
import { Router } from 'express';
import promClient from 'prom-client';
import compression from 'compression';
import mongoose from 'mongoose';
import { logger } from '../utils/logger.js';
import { createRateLimiter } from '../utils/rateLimiter.js';
import { certificationValidations, validate } from '../validations/certification.validation.js';
import CertificationController from '../controllers/CertificationController.js';
import { AppError } from '../errors/app.error.js';
import { cacheService } from '../services/cache.service.js';
import { metricsCollector } from '../utils/metrics.js';
import { eventEmitter } from '../events/events.js';
import authenticateUser, { authorize } from '../middlewares/profile.middleware.js';
import multer from 'multer';

// Multer configuration for file uploads
const storage = multer.memoryStorage();
const upload = multer({
    storage,
    limits: {
        fileSize: 10 * 1024 * 1024, // 10MB limit
        files: 5, // Max 5 files
    },
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'];
        if (!allowedTypes.includes(file.mimetype)) {
            return cb(new AppError('Invalid file type. Only JPEG, PNG, GIF, and PDF are allowed', 400));
        }
        cb(null, true);
    },
});

const router = Router();

// ===========================
// MIDDLEWARE SETUP
// ===========================
// Request logging middleware
router.use((req, res, next) => {
    logger.info(`Certification API Request: ${req.method} ${req.path}`, {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        userId: req.user?.id || 'anonymous',
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
        'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none';",
    });
    next();
});

// Compression middleware
router.use(compression({
    level: 6,
    filter: (req, res) => {
        if (req.headers['x-no-compression']) return false;
        return compression.filter(req, res);
    },
}));

// CSRF protection for state-changing routes
const csrfProtection = csrf({ cookie: { secure: true, httpOnly: true, sameSite: 'strict' } });
router.use((req, res, next) => {
    if (['POST', 'PUT', 'DELETE'].includes(req.method)) {
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
                userId: req.user?.id || 'anonymous',
                action: `${req.method} ${req.path}`,
                details: {
                    params: req.params,
                    body: req.body,
                    response: typeof body === 'string' ? JSON.parse(body) : body,
                },
            }).catch(err => logger.warn('Audit log failed:', err.message));
        }
        return originalSend.call(this, body);
    };
    next();
};

// Admin rate limiter
const adminLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 50,
    message: 'Too many admin requests, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.user.id,
    redisClient: cacheService.getRedisClient(),
});

// Rate limiters from controller
const createCertificationLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 15,
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_certification_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const updateCertificationLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 25,
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_certification_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const verificationLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 5,
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `verify_certification_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const bulkOperationsLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3,
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_certification_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const mediaUploadLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 10,
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `media_certification_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const deleteCertificationLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10,
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `delete_certification_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const shareCertificationLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 20,
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `share_certification_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const endorseCertificationLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 20,
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `endorse_certification_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const searchCertificationsLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 50,
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `search_certification_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

// Cache middleware for read-heavy routes
const cacheMiddleware = (ttl = 300) => async (req, res, next) => {
    const cacheKey = `route:${req.method}:${req.path}:${JSON.stringify(req.query)}:${JSON.stringify(req.body)}:${req.user?.id}`;
    const cached = await cacheService.get(cacheKey);
    if (cached) {
        metricsCollector.increment('route.cache_hit', { path: req.path, userId: req.user?.id });
        return res.json(cached);
    }
    const originalSend = res.send;
    res.send = async function (body) {
        if (res.statusCode < 400) {
            await cacheService.set(cacheKey, body, ttl);
        }
        return originalSend.call(this, body);
    };
    next();
};

// ===========================
// PUBLIC ROUTES
// ===========================
// Health check endpoint (no auth required)
router.get('/health', (req, res) => {
    metricsCollector.increment('health_check', { service: 'certification' });
    res.status(200).json({ status: 'OK', service: 'Certification Service', timestamp: new Date().toISOString() });
});

// Metrics endpoint (admin-only)
router.get('/metrics', authorize('admin'), async (req, res) => {
    res.set('Content-Type', promClient.register.contentType);
    res.end(await promClient.register.metrics());
});

// ===========================
// AUTHENTICATED ROUTES
// ===========================
router.use(authenticateUser);

// Apply audit logging to state-changing routes
router.use([
    '/:userId/:id',
    '/:userId/:id/',
    '/:userId/:id/media',
    '/:userId/:id/verify',
    '/:userId/:id/share',
    '/:userId/:id/endorse',
    '/:userId/:id/duplicate',
    '/:userId/bulk',
], auditLog);

// ===========================
// CERTIFICATION CRUD OPERATIONS
// ===========================
router.post(
    '/:userId',
    createCertificationLimiter,
    certificationValidations.createCertification,
    validate,
    CertificationController.createCertification
);

router.get(
    '/:userId',
    cacheMiddleware(300),
    certificationValidations.getCertifications,
    validate,
    CertificationController.getCertifications
);

router.get(
    '/:userId/:id',
    cacheMiddleware(600),
    certificationValidations.getCertificationById,
    validate,
    CertificationController.getCertificationById
);

router.put(
    '/:userId/:id',
    updateCertificationLimiter,
    certificationValidations.updateCertification,
    validate,
    CertificationController.updateCertification
);

router.delete(
    '/:userId/:id',
    deleteCertificationLimiter,
    certificationValidations.deleteCertification,
    validate,
    CertificationController.deleteCertification
);

// ===========================
// MEDIA UPLOAD
// ===========================
router.post(
    '/:userId/:id/media',
    mediaUploadLimiter,
    upload.array('files', 5),
    certificationValidations.uploadMedia,
    validate,
    CertificationController.uploadMedia
);

// ===========================
// CERTIFICATION OPERATIONS
// ===========================
router.post(
    '/:userId/bulk',
    bulkOperationsLimiter,
    certificationValidations.bulkOperations,
    validate,
    CertificationController.bulkOperations
);

router.get(
    '/:userId/:id/analytics',
    cacheMiddleware(900),
    certificationValidations.getAnalytics,
    validate,
    CertificationController.getAnalytics
);

router.post(
    '/:userId/:id/duplicate',
    createCertificationLimiter,
    certificationValidations.duplicateCertification,
    validate,
    CertificationController.duplicateCertification
);

router.post(
    '/:userId/:id/verify',
    verificationLimiter,
    certificationValidations.verifyCertification,
    validate,
    CertificationController.verifyCertification
);

router.post(
    '/:userId/:id/share',
    shareCertificationLimiter,
    certificationValidations.shareCertification,
    validate,
    CertificationController.shareCertification
);

router.post(
    '/:userId/:id/endorse',
    endorseCertificationLimiter,
    certificationValidations.endorseCertification,
    validate,
    CertificationController.endorseCertification
);

router.get(
    '/:userId/:id/verification',
    cacheMiddleware(60),
    certificationValidations.getVerificationStatus,
    validate,
    CertificationController.getVerificationStatus
);

// ===========================
// QUERY AND TRENDING OPERATIONS
// ===========================
router.get(
    '/trending',
    cacheMiddleware(3600),
    certificationValidations.getTrendingCertifications,
    validate,
    CertificationController.getTrendingCertifications
);

router.get(
    '/categories/:category',
    cacheMiddleware(1800),
    certificationValidations.getCertificationsByCategory,
    validate,
    CertificationController.getCertificationsByCategory
);

router.get(
    '/search',
    searchCertificationsLimiter,
    certificationValidations.searchCertifications,
    validate,
    CertificationController.searchCertifications
);

// ===========================
// EXPORT OPERATIONS
// ===========================
router.get(
    '/:userId/export',
    cacheMiddleware(300),
    certificationValidations.exportCertifications,
    validate,
    CertificationController.exportCertifications
);

// ===========================
// ADMIN ROUTES
// ===========================
router.use('/admin', adminLimiter, authorize('admin'));

router.get(
    '/admin/:userId/:id',
    cacheMiddleware(600),
    certificationValidations.getCertificationById,
    validate,
    CertificationController.getCertificationById
);

router.get(
    '/admin/:userId/:id/verification',
    cacheMiddleware(60),
    certificationValidations.getVerificationStatus,
    validate,
    CertificationController.getVerificationStatus
);

router.get(
    '/admin/:userId/:id/analytics',
    cacheMiddleware(900),
    certificationValidations.getAnalytics,
    validate,
    CertificationController.getAnalytics
);

// ===========================
// ERROR HANDLING
// ===========================
const handleCertificationErrors = (err, req, res, next) => {
    logger.error(`Certification API Error: ${err.message}`, {
        stack: err.stack,
        path: req.path,
        method: req.method,
        userId: req.user?.id,
        ip: req.ip,
        timestamp: new Date().toISOString(),
    });

    metricsCollector.increment('error', {
        path: req.path,
        status: err.statusCode || 500,
        userId: req.user?.id,
    });

    if (err instanceof AppError) {
        return res.status(err.statusCode).json({
            success: false,
            message: err.message,
            errors: err.errors || [],
        });
    }

    if (err instanceof multer.MulterError) {
        return res.status(400).json({
            success: false,
            message: `File upload error: ${err.message}`,
            errors: [],
        });
    }

    res.status(500).json({
        success: false,
        message: 'Internal Server Error',
        error: process.env.NODE_ENV === 'development' ? err.message : undefined,
    });
};

router.use('*', (req, res) => {
    logger.warn(`Certification API 404: ${req.method} ${req.originalUrl}`, {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        timestamp: new Date().toISOString(),
    });
    metricsCollector.increment('not_found', { path: req.originalUrl });
    res.status(404).json({
        success: false,
        message: 'Certification API endpoint not found',
        path: req.originalUrl,
        method: req.method,
        timestamp: new Date().toISOString(),
    });
});

router.use(handleCertificationErrors);

// ===========================
// ROUTE DOCUMENTATION
// ===========================
if (process.env.NODE_ENV === 'development') {
    router.get('/docs', (req, res) => {
        res.json({
            name: 'Certification Service API',
            version: '1.0.0',
            description: 'RESTful API for managing certifications and related operations',
            baseUrl: '/api/v1/certifications',
            routes: {
                public: [
                    'GET /health - Health check',
                    'GET /metrics - Prometheus metrics (admin-only)',
                ],
                authenticated: [
                    'POST /:userId - Create a new certification',
                    'GET /:userId - Get certifications with filters and pagination',
                    'GET /:userId/:id - Get certification by ID',
                    'PUT /:userId/:id - Update certification',
                    'DELETE /:userId/:id - Delete certification (soft or permanent)',
                    'POST /:userId/:id/media - Upload media for certification (max 5 files, 10MB each)',
                    'POST /:userId/bulk - Bulk operations (delete, archive, publish, updateCategory, updateTags, updateVisibility)',
                    'GET /:userId/:id/analytics - Get certification analytics',
                    'POST /:userId/:id/duplicate - Duplicate certification',
                    'POST /:userId/:id/verify - Verify certification',
                    'POST /:userId/:id/share - Share certification',
                    'POST /:userId/:id/endorse - Endorse certification',
                    'GET /:userId/:id/verification - Get verification status',
                    'GET /trending - Get trending certifications',
                    'GET /categories/:category - Get certifications by category',
                    'GET /search - Search certifications with filters',
                    'GET /:userId/export - Export certifications as CSV',
                ],
                admin: [
                    'GET /admin/:userId/:id - Get any certification by ID',
                    'GET /admin/:userId/:id/verification - Get verification status for any certification',
                    'GET /admin/:userId/:id/analytics - Get analytics for any certification',
                ],
            },
            rateLimits: {
                createCertification: '15 requests per 15 minutes per user',
                updateCertification: '25 requests per 5 minutes per user',
                deleteCertification: '10 requests per 15 minutes per user',
                mediaUpload: '10 requests per 10 minutes per user',
                bulkOperations: '3 requests per hour per user',
                verification: '5 requests per 30 minutes per user',
                shareCertification: '20 requests per 5 minutes per user',
                endorseCertification: '20 requests per 5 minutes per user',
                searchCertifications: '50 requests per 5 minutes per user',
                admin: '50 requests per 15 minutes per admin',
            },
            validations: {
                createCertification: 'Requires userId, badgeDetails.title, duration.issueDate; optional badgeDetails.description, badgeDetails.category, badgeDetails.tags, badgeDetails.skills, organization.organizationId, templateId, duration.expirationDate, settings.autoBackup',
                getCertifications: 'Requires userId; optional page, limit, status, category, search, sortBy, templateId, tags, startDate, endDate, includeAnalytics',
                getCertificationById: 'Requires userId, id; optional includeAnalytics, includeVerification',
                updateCertification: 'Requires userId, id; optional badgeDetails.title, badgeDetails.description, badgeDetails.category, badgeDetails.tags, badgeDetails.skills, organization.organizationId, templateId, duration.issueDate, duration.expirationDate, status.workflow, status.isActive',
                deleteCertification: 'Requires userId, id; optional permanent',
                bulkOperations: 'Requires userId, operation, certificationIds; optional data.category, data.tags, data.visibility',
                getAnalytics: 'Requires userId, id; optional timeframe (7d, 30d, 90d), metrics (basic, detailed)',
                duplicateCertification: 'Requires userId, id; optional title, includeVersions',
                verifyCertification: 'Requires userId, id',
                uploadMedia: 'Requires userId, id, files (max 5, JPEG/PNG/GIF/PDF, 10MB each)',
                shareCertification: 'Requires userId, id, platform (linkedin, twitter, email, portfolio)',
                endorseCertification: 'Requires userId, id',
                getVerificationStatus: 'Requires userId, id',
                getTrendingCertifications: 'Optional timeframe (7d, 30d, 90d), category, limit (max 50)',
                getCertificationsByCategory: 'Requires category; optional page, limit, sortBy',
                searchCertifications: 'Requires query; optional page, limit, filters.status, filters.category, filters.tags',
                exportCertifications: 'Requires userId; optional format (csv), fields (badgeDetails.title, badgeDetails.description, badgeDetails.category, status.workflow, duration.issueDate, duration.expirationDate, organization.organizationId, templateId)',
            },
            notes: [
                'All state-changing operations are protected with CSRF tokens',
                'Media uploads are handled via multipart/form-data with Multer',
                'Caching is implemented for read-heavy routes with Redis',
                'Rate limiting is enforced to prevent abuse',
                'Audit logging is enabled for all state-changing operations',
                'All routes require authentication except health and metrics',
                'Admin routes require admin role authorization',
                'Backup operations use AWS S3 for data persistence',
                'MongoDB transactions ensure data consistency',
                'Virus scanning is performed on uploaded media',
                'External verification is triggered for critical updates',
            ],
        });
    });
}

// ===========================
// HELPER MIDDLEWARE
// ===========================
const requestTimeoutMiddleware = (req, res, next) => {
    req.setTimeout(30000, () => {
        logger.error('Request timed out', {
            method: req.method,
            path: req.path,
            userId: req.user?.id,
            ip: req.ip,
        });
        metricsCollector.increment('request_timeout', { path: req.path });
        res.status(504).json({
            success: false,
            message: 'Request timed out',
        });
    });
    next();
};

router.use(requestTimeoutMiddleware);

// ===========================
// PERFORMANCE MONITORING
// ===========================
router.use((req, res, next) => {
    const startTime = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - startTime;
        metricsCollector.histogram('request_duration_ms', duration, {
            method: req.method,
            path: req.path,
            status: res.statusCode,
        });
        if (duration > 1000) {
            logger.warn(`Slow request detected: ${req.method} ${req.path} took ${duration}ms`, {
                userId: req.user?.id,
                ip: req.ip,
            });
        }
    });
    next();
});

// ===========================
// REQUEST VALIDATION
// ===========================
const validateRequestSize = (req, res, next) => {
    const contentLength = parseInt(req.get('content-length') || '0');
    const maxSize = 10 * 1024 * 1024; // 10MB
    if (contentLength > maxSize) {
        logger.warn(`Request body too large: ${contentLength} bytes`, {
            path: req.path,
            userId: req.user?.id,
        });
        metricsCollector.increment('request_too_large', { path: req.path });
        return res.status(413).json({
            success: false,
            message: 'Request body too large',
        });
    }
    next();
};

router.use(['/:userId/:id/media', '/:userId/bulk', '/search'], validateRequestSize);

// ===========================
// IP WHITELISTING
// ===========================
const ipWhitelist = process.env.IP_WHITELIST ? process.env.IP_WHITELIST.split(',') : [];
const ipWhitelistMiddleware = (req, res, next) => {
    if (ipWhitelist.length > 0 && !ipWhitelist.includes(req.ip)) {
        logger.warn(`Unauthorized IP access: ${req.ip}`, {
            path: req.path,
            userId: req.user?.id,
        });
        metricsCollector.increment('unauthorized_ip_access', { path: req.path });
        return res.status(403).json({
            success: false,
            message: 'Access denied from this IP address',
        });
    }
    next();
};

router.use(ipWhitelistMiddleware);

// ===========================
// CORS CONFIGURATION
// ===========================
router.use((req, res, next) => {
    res.set({
        'Access-Control-Allow-Origin': process.env.CORS_ORIGIN || '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-CSRF-Token',
        'Access-Control-Expose-Headers': 'X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset',
    });
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    next();
});

// ===========================
// RATE LIMITER MONITORING
// ===========================
const monitorRateLimits = (req, res, next) => {
    res.on('finish', () => {
        const rateLimitHeaders = {
            limit: res.get('X-RateLimit-Limit'),
            remaining: res.get('X-RateLimit-Remaining'),
            reset: res.get('X-RateLimit-Reset'),
        };
        if (rateLimitHeaders.remaining && parseInt(rateLimitHeaders.remaining) < 5) {
            logger.warn(`Rate limit nearing exhaustion`, {
                path: req.path,
                userId: req.user?.id,
                remaining: rateLimitHeaders.remaining,
            });
            metricsCollector.increment('rate_limit_warning', { path: req.path });
        }
    });
    next();
};

router.use(monitorRateLimits);

// ===========================
// REQUEST ID TRACKING
// ===========================
router.use((req, res, next) => {
    req.requestId = require('uuid').v4();
    res.set('X-Request-ID', req.requestId);
    logger.info(`Request ID assigned: ${req.requestId}`, {
        method: req.method,
        path: req.path,
        userId: req.user?.id,
    });
    next();
});

// ===========================
// DATABASE CONNECTION MONITORING
// ===========================
const monitorDatabase = (req, res, next) => {
    if (mongoose.connection.readyState !== 1) {
        logger.error('Database connection not ready', {
            path: req.path,
            userId: req.user?.id,
        });
        metricsCollector.increment('database_connection_error', { path: req.path });
        return res.status(503).json({
            success: false,
            message: 'Service unavailable: Database connection error',
        });
    }
    next();
};

router.use(monitorDatabase);

// ===========================
// CACHE CONSISTENCY CHECK
// ===========================
const checkCacheConsistency = async (req, res, next) => {
    if (['POST', 'PUT', 'DELETE'].includes(req.method)) {
        const cacheKeys = await cacheService.keys(`certification:${req.params.id}:*`);
        if (cacheKeys.length > 0) {
            logger.info(`Clearing ${cacheKeys.length} cache entries for certification ${req.params.id}`, {
                path: req.path,
                userId: req.user?.id,
            });
            await cacheService.deletePattern(`certification:${req.params.id}:*`);
            metricsCollector.increment('cache_cleared', { path: req.path, count: cacheKeys.length });
        }
    }
    next();
};

router.use(['/:userId/:id', '/:userId/:id/media', '/:userId/:id/verify', '/:userId/:id/share', '/:userId/:id/endorse', '/:userId/:id/duplicate'], checkCacheConsistency);

// ===========================
// SESSION VALIDATION
// ===========================
const validateSession = (req, res, next) => {
    if (!req.user || !req.user.id) {
        logger.warn('Invalid session detected', {
            path: req.path,
            ip: req.ip,
        });
        metricsCollector.increment('invalid_session', { path: req.path });
        return res.status(401).json({
            success: false,
            message: 'Invalid or expired session',
        });
    }
    next();
};

router.use(validateSession);

// ===========================
// RESPONSE FORMATTING
// ===========================
const formatResponse = (req, res, next) => {
    const originalJson = res.json;
    res.json = function (data) {
        return originalJson.call(this, {
            success: data.success !== false,
            message: data.message || 'Request processed successfully',
            data: data.data || data,
            timestamp: new Date().toISOString(),
            requestId: req.requestId,
        });
    };
    next();
};

router.use(formatResponse);

// ===========================
// API VERSIONING
// ===========================
router.use((req, res, next) => {
    const apiVersion = req.get('X-API-Version') || '1.0.0';
    if (apiVersion !== '1.0.0') {
        logger.warn(`Unsupported API version: ${apiVersion}`, {
            path: req.path,
            userId: req.user?.id,
        });
        metricsCollector.increment('unsupported_api_version', { version: apiVersion });
        return res.status(400).json({
            success: false,
            message: 'Unsupported API version',
        });
    }
    next();
});

// ===========================
// REQUEST VALIDATION LOGGING
// ===========================
const logValidationErrors = (req, res, next) => {
    const originalValidate = validate;
    validate = (validations) => {
        return async (req, res, next) => {
            try {
                await Promise.all(validations.map(validation => validation.run(req)));
                const errors = validationResult(req);
                if (!errors.isEmpty()) {
                    logger.warn(`Validation errors: ${JSON.stringify(errors.array())}`, {
                        path: req.path,
                        userId: req.user?.id,
                    });
                    metricsCollector.increment('validation_error', { path: req.path, count: errors.array().length });
                }
            } catch (error) {
                logger.error('Validation processing error:', {
                    error: error.message,
                    path: req.path,
                    userId: req.user?.id,
                });
            }
            originalValidate(validations)(req, res, next);
        };
    };
    next();
};

router.use(logValidationErrors);

// ===========================
// REQUEST THROTTLING
// ===========================
const throttleHeavyRequests = (req, res, next) => {
    if (['/:userId/bulk', '/search'].includes(req.path)) {
        const requestCount = cacheService.get(`throttle:${req.user.id}:${req.path}`) || 0;
        if (requestCount >= 10) {
            logger.warn(`Heavy request throttling triggered`, {
                path: req.path,
                userId: req.user?.id,
                requestCount,
            });
            metricsCollector.increment('request_throttled', { path: req.path });
            return res.status(429).json({
                success: false,
                message: 'Too many heavy requests, please try again later',
            });
        }
        cacheService.incr(`throttle:${req.user.id}:${req.path}`);
        cacheService.expire(`throttle:${req.user.id}:${req.path}`, 300);
    }
    next();
};

router.use(throttleHeavyRequests);

// ===========================
// REQUEST SANITIZATION
// ===========================
const sanitizeRequest = (req, res, next) => {
    if (req.body) {
        const sanitizeObject = (obj) => {
            for (const key in obj) {
                if (typeof obj[key] === 'string') {
                    obj[key] = require('sanitize-html')(obj[key], {
                        allowedTags: [],
                        allowedAttributes: {},
                    });
                } else if (typeof obj[key] === 'object' && obj[key] !== null) {
                    sanitizeObject(obj[key]);
                }
            }
        };
        sanitizeObject(req.body);
    }
    next();
};

router.use(['/:userId/:id/media', '/:userId/bulk', '/search'], sanitizeRequest);

// ===========================
// LOAD BALANCING HEADERS
// ===========================
router.use((req, res, next) => {
    res.set('X-Load-Balancer', process.env.INSTANCE_ID || 'unknown');
    next();
});

// ===========================
// REQUEST TRACING
// ===========================
router.use((req, res, next) => {
    const traceId = req.get('X-Trace-ID') || require('uuid').v4();
    req.traceId = traceId;
    res.set('X-Trace-ID', traceId);
    logger.info(`Trace ID assigned: ${traceId}`, {
        method: req.method,
        path: req.path,
        userId: req.user?.id,
    });
    next();
});

// ===========================
// RESPONSE CACHING HEADERS
// ===========================
router.use((req, res, next) => {
    if (['GET'].includes(req.method)) {
        res.set('Cache-Control', 'private, max-age=300');
    } else {
        res.set('Cache-Control', 'no-store');
    }
    next();
});

// ===========================
// ERROR RATE MONITORING
// ===========================
router.use((req, res, next) => {
    res.on('finish', () => {
        if (res.statusCode >= 400) {
            metricsCollector.increment('error_rate', {
                path: req.path,
                status: res.statusCode,
            });
        }
    });
    next();
});

// ===========================
// API USAGE TRACKING
// ===========================
router.use((req, res, next) => {
    metricsCollector.increment('api_usage', {
        method: req.method,
        path: req.path,
        userId: req.user?.id,
    });
    next();
});

// ===========================
// SECURITY AUDIT HEADERS
// ===========================
router.use((req, res, next) => {
    res.set('X-Security-Audit', 'Enabled');
    next();
});

// ===========================
// REQUEST LOGGING ENHANCEMENT
// ===========================
router.use((req, res, next) => {
    req.logContext = {
        requestId: req.requestId,
        traceId: req.traceId,
        userId: req.user?.id,
        ip: req.ip,
        method: req.method,
        path: req.path,
        timestamp: new Date().toISOString(),
    };
    next();
});

// ===========================
// RESPONSE TIME MONITORING
// ===========================
router.use((req, res, next) => {
    const start = process.hrtime();
    res.on('finish', () => {
        const [seconds, nanoseconds] = process.hrtime(start);
        const durationMs = (seconds * 1000) + (nanoseconds / 1e6);
        logger.info(`Request completed`, {
            ...req.logContext,
            durationMs,
            status: res.statusCode,
        });
    });
    next();
});

// ===========================
// DATABASE QUERY LOGGING
// ===========================
router.use((req, res, next) => {
    const originalQuery = mongoose.Query.prototype.exec;
    mongoose.Query.prototype.exec = async function (...args) {
        const start = Date.now();
        const result = await originalQuery.apply(this, args);
        const duration = Date.now() - start;
        logger.info(`Database query executed`, {
            ...req.logContext,
            collection: this.model.collection.name,
            query: this.getQuery(),
            duration,
        });
        metricsCollector.histogram('database_query_duration_ms', duration, {
            collection: this.model.collection.name,
        });
        return result;
    };
    next();
});

// ===========================
// SESSION ACTIVITY TRACKING
// ===========================
router.use((req, res, next) => {
    cacheService.set(`session_activity:${req.user.id}`, Date.now(), 3600);
    next();
});

// ===========================
// REQUEST BODY SIZE MONITORING
// ===========================
router.use((req, res, next) => {
    const contentLength = parseInt(req.get('content-length') || '0');
    metricsCollector.histogram('request_body_size_bytes', contentLength, {
        method: req.method,
        path: req.path,
    });
    next();
});

// ===========================
// CACHE HIT RATE MONITORING
// ===========================
router.use((req, res, next) => {
    const originalCacheGet = cacheService.get;
    cacheService.get = async function (key) {
        const result = await originalCacheGet.apply(this, [key]);
        metricsCollector.increment(result ? 'cache_hit' : 'cache_miss', { key });
        return result;
    };
    next();
});

// ===========================
// EVENT EMISSION LOGGING
// ===========================
const originalEmit = eventEmitter.emit;
eventEmitter.emit = function (event, ...args) {
    logger.info(`Event emitted: ${event}`, {
        data: args,
        timestamp: new Date().toISOString(),
    });
    metricsCollector.increment('event_emitted', { event });
    return originalEmit.apply(this, [event, ...args]);
};

// ===========================
// ROUTE-SPECIFIC MIDDLEWARE
// ===========================
router.use('/:userId/bulk', (req, res, next) => {
    logger.info(`Bulk operation initiated`, {
        ...req.logContext,
        itemCount: req.body.certificationIds?.length || 0,
    });
    metricsCollector.increment('bulk_operation_initiated', {
        path: req.path,
        itemCount: req.body.certificationIds?.length || 0,
    });
    next();
});

router.use('/:userId/:id/media', (req, res, next) => {
    logger.info(`Media upload initiated`, {
        ...req.logContext,
        fileCount: req.files?.length || 0,
    });
    metricsCollector.increment('media_upload_initiated', {
        path: req.path,
        fileCount: req.files?.length || 0,
    });
    next();
});

// ===========================
// ENVIRONMENT-SPECIFIC CONFIG
// ===========================
if (process.env.NODE_ENV === 'production') {
    router.use((req, res, next) => {
        res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
        next();
    });
}

// ===========================
// REQUEST QUEUE MONITORING
// ===========================
let activeRequests = 0;
router.use((req, res, next) => {
    activeRequests++;
    metricsCollector.gauge('active_requests', activeRequests, { path: req.path });
    res.on('finish', () => {
        activeRequests--;
        metricsCollector.gauge('active_requests', activeRequests, { path: req.path });
    });
    next();
});

// ===========================
// API DEPRECATION WARNING
// ===========================
router.use((req, res, next) => {
    if (req.path.includes('/legacy')) {
        logger.warn('Deprecated endpoint accessed', {
            ...req.logContext,
        });
        res.set('Warning', 'This endpoint is deprecated and will be removed in a future version');
    }
    next();
});

// ===========================
// RESPONSE SIGNATURE
// ===========================
router.use((req, res, next) => {
    res.set('X-Response-Signature', require('crypto').createHash('sha256')
        .update(`${req.requestId}:${process.env.SIGNATURE_SECRET || 'secret'}`)
        .digest('hex'));
    next();
});

// ===========================
// REQUEST BODY LOGGING
// ===========================
router.use((req, res, next) => {
    if (['POST', 'PUT'].includes(req.method) && process.env.NODE_ENV !== 'production') {
        logger.debug(`Request body`, {
            ...req.logContext,
            body: req.body,
        });
    }
    next();
});

// ===========================
// ERROR RECOVERY
// ===========================
router.use((err, req, res, next) => {
    if (err instanceof mongoose.Error) {
        logger.error('MongoDB error', {
            ...req.logContext,
            error: err.message,
            stack: err.stack,
        });
        metricsCollector.increment('mongodb_error', { path: req.path });
        return res.status(503).json({
            success: false,
            message: 'Database error occurred',
            error: process.env.NODE_ENV === 'development' ? err.message : undefined,
        });
    }
    next(err);
});

// ===========================
// FINAL ROUTE DOCUMENTATION
// ===========================
router.get('/docs', (req, res) => {
    const doc = router.stack.reduce((acc, layer) => {
        if (layer.route) {
            const path = layer.route.path;
            const methods = Object.keys(layer.route.methods).map(m => m.toUpperCase());
            acc.push({ path, methods });
        }
        return acc;
    }, []);
    res.json({
        ...res.json({}).data,
        availableRoutes: doc,
    });
});

export default router;