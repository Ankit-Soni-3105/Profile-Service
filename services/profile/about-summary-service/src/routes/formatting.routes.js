import csrf from 'csurf';
import { Router } from 'express';
import promClient from 'prom-client';
import compression from 'compression';
import mongoose from 'mongoose';
import { logger } from '../utils/logger.js';
import { createRateLimiter } from '../utils/rateLimiter.js';
import { authorize } from '../middlewares/profile.middleware.js';
import { formattingValidations, validate } from '../validations/formatiing.validation.js';
import authenticateUser from '../middlewares/profile.middleware.js';
import formattingController from '../controllers/formatting.controller.js';
import { AppError } from '../errors/app.error.js';
import { cacheService } from '../services/redis.service.js';
import { metricsCollector } from '../utils/metrics.js';
import { eventEmitter } from '../events/events.js';

const router = Router();

// ===========================
// MIDDLEWARE SETUP
// ===========================
// Request logging middleware
router.use((req, res, next) => {
    logger.info(`Formatting API Request: ${req.method} ${req.path} `, {
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

// Compression middleware (using Brotli for better performance)
router.use(compression({
    level: 6, filter: (req, res) => {
        if (req.headers['x-no-compression']) return false;
        return compression.filter(req, res);
    }
}));

// CSRF protection for state-changing routes
const csrfProtection = csrf({ cookie: { secure: true, httpOnly: true, sameSite: 'strict' } });
router.use((req, res, next) => {
    if (['POST', 'PATCH'].includes(req.method)) {
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
                action: `${req.method} ${req.path} `,
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
});

// Rate limiters from controller
const applyFormatLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 100, // 100 format applications per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `format_apply_${req.user.id}_${req.params.summaryId} `,
});

const previewFormatLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 200, // 200 format previews per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `format_preview_${req.user.id}_${req.params.summaryId} `,
});

// Cache middleware for read-heavy routes
const cacheMiddleware = (ttl = 300) => async (req, res, next) => {
    const cacheKey = `route:${req.method}:${req.path}:${JSON.stringify(req.query)}:${req.user?.id} `;
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
    metricsCollector.increment('health_check', { service: 'formatting' });
    res.status(200).json({ status: 'OK', service: 'Formatting Service', timestamp: new Date().toISOString() });
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
router.use(['/:userId', '/:userId/', '/:userId/:summaryId', '/:userId/:summaryId/'], auditLog);

// ===========================
// FORMATTING OPERATIONS
// ===========================
router.patch(
    '/:userId/:summaryId',
    applyFormatLimiter,
    formattingValidations.applyFormatting,
    validate,
    formattingController.applyFormatting
);

router.post(
    '/:userId/:summaryId/preview',
    previewFormatLimiter,
    formattingValidations.previewFormatting,
    validate,
    formattingController.previewFormatting
);

router.get(
    '/:userId/:summaryId/styles',
    cacheMiddleware(3600), // 1 hour cache for styles
    formattingValidations.getFormattingStyles,
    validate,
    formattingController.getFormattingStyles
);

router.post(
    '/:userId/bulk',
    applyFormatLimiter, // Reuse apply limiter for bulk
    formattingValidations.bulkApplyFormatting,
    validate,
    formattingController.bulkApplyFormatting
);

router.get(
    '/:userId/:summaryId/history',
    cacheMiddleware(300),
    formattingValidations.getFormattingHistory,
    validate,
    formattingController.getFormattingHistory
);

router.post(
    '/:userId/:summaryId/revert',
    applyFormatLimiter, // Reuse apply limiter for revert
    formattingValidations.revertFormatting,
    validate,
    formattingController.revertFormatting
);

// ===========================
// ADMIN ROUTES
// ===========================
router.use('/admin', adminLimiter, authorize('admin'));

router.get(
    '/admin/:userId/:summaryId/styles',
    cacheMiddleware(3600),
    formattingValidations.getFormattingStyles,
    validate,
    formattingController.getFormattingStyles
);

router.get(
    '/admin/:userId/:summaryId/history',
    cacheMiddleware(300),
    formattingValidations.getFormattingHistory,
    validate,
    formattingController.getFormattingHistory
);

// ===========================
// ERROR HANDLING
// ===========================
const handleFormattingErrors = (err, req, res, next) => {
    logger.error(`Formatting API Error: ${err.message} `, {
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

    res.status(500).json({
        success: false,
        message: 'Internal Server Error',
        error: process.env.NODE_ENV === 'development' ? err.message : undefined,
    });
};

router.use('*', (req, res) => {
    logger.warn(`Formatting API 404: ${req.method} ${req.originalUrl} `, {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        timestamp: new Date().toISOString(),
    });
    metricsCollector.increment('not_found', { path: req.originalUrl });
    res.status(404).json({
        success: false,
        message: 'Formatting API endpoint not found',
        path: req.originalUrl,
        method: req.method,
        timestamp: new Date().toISOString(),
    });
});

router.use(handleFormattingErrors);

// ===========================
// ROUTE DOCUMENTATION
// ===========================
if (process.env.NODE_ENV === 'development') {
    router.get('/docs', (req, res) => {
        res.json({
            name: 'Formatting Service API',
            version: '1.0.0',
            description: 'RESTful API for text formatting operations',
            baseUrl: '/api/v1/formatting',
            routes: {
                public: [
                    'GET /health - Health check',
                    'GET /metrics - Prometheus metrics (admin-only)',
                ],
                authenticated: [
                    'PATCH /:userId/:summaryId - Apply formatting to summary content',
                    'POST /:userId/:summaryId/preview - Preview formatting without saving',
                    'GET /:userId/:summaryId/styles - Get available formatting styles',
                    'POST /:userId/bulk - Bulk apply formatting to multiple summaries',
                    'GET /:userId/:summaryId/history - Get formatting history',
                    'POST /:userId/:summaryId/revert - Revert to previous formatting',
                ],
                admin: [
                    'GET /admin/:userId/:summaryId/styles - Get any user\'s formatting styles',
                    'GET /admin/:userId/:summaryId/history - Get any user\'s formatting history',
                ],
            },
            rateLimits: {
                applyFormatting: '100 requests per 5 minutes per user per summary',
                previewFormatting: '200 requests per 5 minutes per user per summary',
                bulkApplyFormatting: '100 requests per 5 minutes per user (shared with apply)',
                revertFormatting: '100 requests per 5 minutes per user (shared with apply)',
                admin: '50 requests per 15 minutes per admin',
            },
            validations: {
                applyFormatting: 'Requires userId, summaryId, formatType, content; optional options',
                previewFormatting: 'Requires userId, summaryId, formatType, content; optional options',
                getFormattingStyles: 'Requires userId, summaryId',
                bulkApplyFormatting: 'Requires userId, summaryIds, formatType; optional options',
                getFormattingHistory: 'Requires userId, summaryId; optional page, limit',
                revertFormatting: 'Requires userId, summaryId, formatId',
            },
        });
    });
}

export default router;