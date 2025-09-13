import csrf from 'csurf';
import { Router } from 'express';
import promClient from 'prom-client';
import compression from 'compression';
import mongoose from 'mongoose';
import { logger } from '../utils/logger.js';
import { createRateLimiter } from '../utils/rateLimiter.js';
import { badgeValidations } from '../validations/badge.validation.js';
import { validate } from '../validations/badge.validation.js';
import badgeController from '../controllers/BadgeController.js';
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
        fileSize: 5 * 1024 * 1024, // 5MB limit
        files: 5, // Max 5 files
    },
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
        if (!allowedTypes.includes(file.mimetype)) {
            return cb(new AppError('Invalid file type. Only JPEG, PNG, and GIF are allowed', 400));
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
    logger.info(`Badge API Request: ${req.method} ${req.path}`, {
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
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
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

// Rate limiters for badge operations
const createBadgeLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // 10 creates per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_badge_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const updateBadgeLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 20, // 20 updates per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_badge_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const issueBadgeLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 5, // 5 issuance requests per 30 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `issue_badge_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const mediaUploadLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 10, // 10 media uploads per 10 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `media_badge_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const bulkOperationLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 5, // 5 bulk operations per 30 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_badge_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const searchLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 50, // 50 searches per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `search_badge_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const deleteBadgeLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // 10 deletes per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `delete_badge_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const verifyBadgeLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 20, // 20 verifications per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `verify_badge_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const archiveBadgeLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // 10 archive operations per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `archive_badge_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const restoreBadgeLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // 10 restore operations per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `restore_badge_${req.user.id}`,
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
    metricsCollector.increment('health_check', { service: 'badge' });
    res.status(200).json({ status: 'OK', service: 'Badge Service', timestamp: new Date().toISOString() });
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
    '/:id',
    '/:id/',
    '/:id/issue',
    '/:id/revoke',
    '/:id/verify',
    '/:id/media',
    '/:id/archive',
    '/:id/restore',
    '/bulk',
    '/admin/',
], auditLog);

// ===========================
// BADGE CRUD OPERATIONS
// ===========================
router.post(
    '/',
    createBadgeLimiter,
    badgeValidations.createBadge,
    validate,
    badgeController.createBadge
);

router.get(
    '/:id',
    cacheMiddleware(600),
    badgeValidations.getBadgeById,
    validate,
    badgeController.getBadgeById
);

router.put(
    '/:id',
    updateBadgeLimiter,
    badgeValidations.updateBadge,
    validate,
    badgeController.updateBadge
);

router.delete(
    '/:id',
    deleteBadgeLimiter,
    badgeValidations.deleteBadge,
    validate,
    badgeController.deleteBadge
);

// ===========================
// BADGE ISSUANCE AND VERIFICATION
// ===========================
router.post(
    '/:id/issue',
    issueBadgeLimiter,
    badgeValidations.issueBadge,
    validate,
    badgeController.issueBadge
);

router.post(
    '/:id/revoke',
    issueBadgeLimiter,
    badgeValidations.revokeBadge,
    validate,
    badgeController.revokeBadge
);

router.post(
    '/:id/verify',
    verifyBadgeLimiter,
    badgeValidations.verifyBadge,
    validate,
    badgeController.verifyBadge
);

// ===========================
// MEDIA UPLOAD
// ===========================
router.post(
    '/:id/media',
    mediaUploadLimiter,
    upload.array('files', 5),
    badgeValidations.uploadMedia,
    validate,
    badgeController.uploadMedia
);

// ===========================
// BADGE QUERY OPERATIONS
// ===========================
router.get(
    '/',
    cacheMiddleware(300),
    badgeValidations.getBadges,
    validate,
    badgeController.getBadges
);

router.post(
    '/search',
    searchLimiter,
    badgeValidations.searchBadges,
    validate,
    badgeController.searchBadges
);

router.get(
    '/trending',
    cacheMiddleware(300),
    badgeValidations.getTrendingBadges,
    validate,
    badgeController.getTrendingBadges
);

// ===========================
// BULK OPERATIONS
// ===========================
router.post(
    '/bulk',
    bulkOperationLimiter,
    badgeValidations.bulkCreateBadges,
    validate,
    badgeController.bulkCreateBadges
);

router.put(
    '/bulk',
    bulkOperationLimiter,
    badgeValidations.bulkUpdateBadges,
    validate,
    badgeController.bulkUpdateBadges
);

// ===========================
// ANALYTICS AND EXPORT
// ===========================
router.get(
    '/:id/analytics',
    cacheMiddleware(300),
    badgeValidations.getBadgeAnalytics,
    validate,
    badgeController.getBadgeAnalytics
);

router.get(
    '/:id/export',
    cacheMiddleware(300),
    badgeValidations.exportBadge,
    validate,
    badgeController.exportBadge
);

router.get(
    '/:id/stats',
    cacheMiddleware(3600),
    badgeValidations.getBadgeStats,
    validate,
    badgeController.getBadgeStats
);

// ===========================
// ARCHIVE AND RESTORE
// ===========================
router.post(
    '/:id/archive',
    archiveBadgeLimiter,
    badgeValidations.archiveBadge,
    validate,
    badgeController.archiveBadge
);

router.post(
    '/:id/restore',
    restoreBadgeLimiter,
    badgeValidations.restoreBadge,
    validate,
    badgeController.restoreBadge
);

// ===========================
// AUDIT LOGS
// ===========================
router.get(
    '/:id/audit',
    cacheMiddleware(300),
    badgeValidations.getAuditLogs,
    validate,
    badgeController.getAuditLogs
);

// ===========================
// ADMIN ROUTES
// ===========================
router.use('/admin', adminLimiter, authorize('admin'));

router.get(
    '/admin/:id',
    cacheMiddleware(600),
    badgeValidations.getBadgeById,
    validate,
    badgeController.getBadgeById
);

router.get(
    '/admin/:id/audit',
    cacheMiddleware(300),
    badgeValidations.getAuditLogs,
    validate,
    badgeController.getAuditLogs
);

// ===========================
// ERROR HANDLING
// ===========================
const handleBadgeErrors = (err, req, res, next) => {
    logger.error(`Badge API Error: ${err.message}`, {
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
    logger.warn(`Badge API 404: ${req.method} ${req.originalUrl}`, {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        timestamp: new Date().toISOString(),
    });
    metricsCollector.increment('not_found', { path: req.originalUrl });
    res.status(404).json({
        success: false,
        message: 'Badge API endpoint not found',
        path: req.originalUrl,
        method: req.method,
        timestamp: new Date().toISOString(),
    });
});

router.use(handleBadgeErrors);

// ===========================
// ROUTE DOCUMENTATION
// ===========================
if (process.env.NODE_ENV === 'development') {
    router.get('/docs', (req, res) => {
        res.json({
            name: 'Badge Service API',
            version: '1.0.0',
            description: 'RESTful API for managing badges and related operations',
            baseUrl: '/api/v1/badges',
            routes: {
                public: [
                    'GET /health - Health check',
                    'GET /metrics - Prometheus metrics (admin-only)',
                ],
                authenticated: [
                    'POST / - Create a new badge',
                    'GET /:id - Get badge by ID',
                    'PUT /:id - Update badge',
                    'DELETE /:id - Delete badge (soft or permanent)',
                    'POST /:id/issue - Issue badge to user',
                    'POST /:id/revoke - Revoke badge from user',
                    'POST /:id/verify - Verify badge',
                    'POST /:id/media - Upload media for badge (max 5 files, 5MB each)',
                    'GET / - Get badges with filters and pagination',
                    'POST /search - Search badges with advanced filters',
                    'GET /trending - Get trending badges',
                    'POST /bulk - Bulk create badges (max 100)',
                    'PUT /bulk - Bulk update badges (max 100)',
                    'GET /:id/analytics - Get badge analytics',
                    'GET /:id/export - Export badge data (JSON or CSV)',
                    'GET /:id/stats - Get badge statistics',
                    'POST /:id/archive - Archive badge',
                    'POST /:id/restore - Restore archived badge',
                    'GET /:id/audit - Get badge audit logs',
                ],
                admin: [
                    'GET /admin/:id - Get any badge by ID',
                    'GET /admin/:id/audit - Get audit logs for any badge',
                ],
            },
            rateLimits: {
                createBadge: '10 requests per 15 minutes per user',
                updateBadge: '20 requests per 5 minutes per user',
                deleteBadge: '10 requests per 15 minutes per user',
                issueBadge: '5 requests per 30 minutes per user',
                verifyBadge: '20 requests per 15 minutes per user',
                mediaUpload: '10 requests per 10 minutes per user',
                bulkOperations: '5 requests per 30 minutes per user',
                searchBadges: '50 requests per 5 minutes per user',
                archiveBadge: '10 requests per 15 minutes per user',
                restoreBadge: '10 requests per 15 minutes per user',
                admin: '50 requests per 15 minutes per admin',
            },
            validations: {
                createBadge: 'Requires name, type; optional image, description, criteria, tags, metadata.expiryDate, metadata.isTransferable',
                getBadgeById: 'Requires id',
                updateBadge: 'Requires id; optional name, type, image, description, criteria, tags, status.workflow, metadata.expiryDate, metadata.isTransferable',
                deleteBadge: 'Requires id; optional permanent',
                issueBadge: 'Requires id, recipientId; optional comment, issueDate',
                revokeBadge: 'Requires id, recipientId; optional reason',
                verifyBadge: 'Requires id',
                uploadMedia: 'Requires id, files (max 5, JPEG/PNG/GIF, 5MB each)',
                getBadges: 'Optional page, limit, status, type, search',
                searchBadges: 'Requires query; optional filters (status, type, tags), page, limit',
                getTrendingBadges: 'Optional timeframe (7d, 30d, 90d), type, limit (max 50)',
                bulkCreateBadges: 'Requires badges array (1-100 items); each with name, type; optional image, description, criteria, tags, metadata.expiryDate, metadata.isTransferable',
                bulkUpdateBadges: 'Requires updates array (1-100 items); each with id, data (optional name, type, image, description, criteria, tags, status.workflow, metadata.expiryDate, metadata.isTransferable)',
                getBadgeAnalytics: 'Requires id; optional timeframe (7d, 30d, 90d)',
                exportBadge: 'Requires id; optional format (json, csv)',
                getBadgeStats: 'Requires id',
                archiveBadge: 'Requires id',
                restoreBadge: 'Requires id',
                getAuditLogs: 'Requires id; optional page, limit, action',
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

router.use(['/:id/issue', '/:id/revoke', '/:id/verify', '/:id/media', '/bulk', '/search'], validateRequestSize);

// ===========================
// IP WHITELISTING (Optional for enterprise environments)
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
        const cacheKeys = await cacheService.keys(`badge:${req.params.id}:*`);
        if (cacheKeys.length > 0) {
            logger.info(`Clearing ${cacheKeys.length} cache entries for badge ${req.params.id}`, {
                path: req.path,
                userId: req.user?.id,
            });
            await cacheService.deletePattern(`badge:${req.params.id}:*`);
            metricsCollector.increment('cache_cleared', { path: req.path, count: cacheKeys.length });
        }
    }
    next();
};

router.use(['/:id', '/:id/issue', '/:id/revoke', '/:id/verify', '/:id/media', '/:id/archive', '/:id/restore'], checkCacheConsistency);

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
    if (['/bulk', '/search'].includes(req.path)) {
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

router.use(['/:id/issue', '/:id/revoke', '/:id/verify', '/bulk', '/search'], sanitizeRequest);

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
router.use('/bulk', (req, res, next) => {
    logger.info(`Bulk operation initiated`, {
        ...req.logContext,
        itemCount: req.body.badges?.length || req.body.updates?.length || 0,
    });
    metricsCollector.increment('bulk_operation_initiated', {
        path: req.path,
        itemCount: req.body.badges?.length || req.body.updates?.length || 0,
    });
    next();
});

router.use('/:id/media', (req, res, next) => {
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