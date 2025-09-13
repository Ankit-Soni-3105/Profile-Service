import csrf from 'csurf';
import { Router } from 'express';
import promClient from 'prom-client';
import compression from 'compression';
import mongoose from 'mongoose';
import { logger } from '../utils/logger.js';
import { createRateLimiter } from '../utils/rateLimiter.js';
import { translationValidations } from '../validations/translation.validations.js';
import { validate } from '../validations/translation.validations.js';
import translationController from '../controllers/translation.controller.js';
import { AppError } from '../errors/app.error.js';
import { cacheService } from '../services/redis.service.js';
import { metricsCollector } from '../utils/metrics.js';
import { eventEmitter } from '../events/events.js';
import authenticateUser, { authorize } from '../middlewares/profile.middleware.js';

const router = Router();

// ===========================
// MIDDLEWARE SETUP
// ===========================
// Request logging middleware
router.use((req, res, next) => {
    logger.info(`Translation API Request: ${req.method} ${req.path}`, {
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
    }
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
});

// Rate limiters for translation operations
const translateLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 10, // 10 translations per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `translate_${req.user.id}_${req.params.summaryId}`,
});

const bulkTranslateLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5, // 5 bulk translations per hour
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_translate_${req.user.id}`,
});

const applyTranslationLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 20, // 20 apply operations per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `apply_translation_${req.user.id}`,
});

const cancelTranslationLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // 10 cancel operations per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `cancel_translation_${req.user.id}`,
});

const retryTranslationLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 retry operations per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `retry_translation_${req.user.id}`,
});

// Cache middleware for read-heavy routes
const cacheMiddleware = (ttl = 300) => async (req, res, next) => {
    const cacheKey = `route:${req.method}:${req.path}:${JSON.stringify(req.query)}:${req.user?.id}`;
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
    metricsCollector.increment('health_check', { service: 'translation' });
    res.status(200).json({ status: 'OK', service: 'Translation Service', timestamp: new Date().toISOString() });
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
router.use(['/:userId', '/:userId/', '/:userId/:summaryId', '/:userId/:summaryId/', '/:userId/:translationId', '/admin/'], auditLog);

// ===========================
// TRANSLATION OPERATIONS
// ===========================
router.post(
    '/:userId/:summaryId',
    translateLimiter,
    translationValidations.translateContent,
    validate,
    translationController.translateContent
);

router.get(
    '/:userId/:summaryId/languages',
    cacheMiddleware(86400), // 1 day cache for supported languages
    translationValidations.getSupportedLanguages,
    validate,
    translationController.getSupportedLanguages
);

router.get(
    '/:userId/:summaryId/history',
    cacheMiddleware(300),
    translationValidations.getTranslationHistory,
    validate,
    translationController.getTranslationHistory
);

router.patch(
    '/:userId/:summaryId/apply',
    applyTranslationLimiter,
    translationValidations.applyTranslation,
    validate,
    translationController.applyTranslation
);

router.post(
    '/:userId/bulk',
    bulkTranslateLimiter,
    translationValidations.bulkTranslate,
    validate,
    translationController.bulkTranslate
);

router.post(
    '/:userId/:translationId/cancel',
    cancelTranslationLimiter,
    translationValidations.cancelTranslation,
    validate,
    translationController.cancelTranslation
);

router.post(
    '/:userId/:translationId/retry',
    retryTranslationLimiter,
    translationValidations.retryTranslation,
    validate,
    translationController.retryTranslation
);

router.get(
    '/:userId/:translationId/status',
    cacheMiddleware(300),
    translationValidations.getTranslationStatus,
    validate,
    translationController.getTranslationStatus
);

// ===========================
// ADMIN ROUTES
// ===========================
router.use('/admin', adminLimiter, authorize('admin'));

router.get(
    '/admin/:userId/:summaryId/history',
    cacheMiddleware(300),
    translationValidations.getTranslationHistory,
    validate,
    translationController.getTranslationHistory
);

// ===========================
// ERROR HANDLING
// ===========================
const handleTranslationErrors = (err, req, res, next) => {
    logger.error(`Translation API Error: ${err.message}`, {
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
    logger.warn(`Translation API 404: ${req.method} ${req.originalUrl}`, {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        timestamp: new Date().toISOString(),
    });
    metricsCollector.increment('not_found', { path: req.originalUrl });
    res.status(404).json({
        success: false,
        message: 'Translation API endpoint not found',
        path: req.originalUrl,
        method: req.method,
        timestamp: new Date().toISOString(),
    });
});

router.use(handleTranslationErrors);

// ===========================
// ROUTE DOCUMENTATION
// ===========================
if (process.env.NODE_ENV === 'development') {
    router.get('/docs', (req, res) => {
        res.json({
            name: 'Translation Service API',
            version: '1.0.0',
            description: 'RESTful API for translation management',
            baseUrl: '/api/v1/translation',
            routes: {
                public: [
                    'GET /health - Health check',
                    'GET /metrics - Prometheus metrics (admin-only)',
                ],
                authenticated: [
                    'POST /:userId/:summaryId - Translate summary content',
                    'GET /:userId/:summaryId/languages - Get supported languages',
                    'GET /:userId/:summaryId/history - Get translation history',
                    'PATCH /:userId/:summaryId/apply - Apply a translation to a summary',
                    'POST /:userId/bulk - Bulk translate summaries',
                    'POST /:userId/:translationId/cancel - Cancel a translation',
                    'POST /:userId/:translationId/retry - Retry a failed translation',
                    'GET /:userId/:translationId/status - Get translation status',
                ],
                admin: [
                    'GET /admin/:userId/:summaryId/history - Get any user\'s translation history',
                ],
            },
            rateLimits: {
                translateContent: '10 requests per 5 minutes per user per summary',
                bulkTranslate: '5 requests per hour per user',
                applyTranslation: '20 requests per 5 minutes per user',
                cancelTranslation: '10 requests per 15 minutes per user',
                retryTranslation: '5 requests per 15 minutes per user',
                admin: '50 requests per 15 minutes per admin',
            },
            validations: {
                translateContent: 'Requires userId, summaryId, targetLanguage; optional sourceLanguage, options, context, priority, callbackUrl',
                getSupportedLanguages: 'Requires userId, summaryId; optional includeDetails, region',
                getTranslationHistory: 'Requires userId, summaryId; optional page, limit, sortBy, sortOrder, status, startDate, endDate, targetLanguage',
                applyTranslation: 'Requires userId, summaryId, translationId; optional applyMode, versionComment',
                bulkTranslate: 'Requires userId, summaryIds, targetLanguage; optional sourceLanguage, options, batchName, priority, callbackUrl, context',
                cancelTranslation: 'Requires userId, translationId; optional reason',
                retryTranslation: 'Requires userId, translationId; optional options, priority',
                getTranslationStatus: 'Requires userId, translationId; optional includeDetails',
            },
        });
    });
}

export default router;