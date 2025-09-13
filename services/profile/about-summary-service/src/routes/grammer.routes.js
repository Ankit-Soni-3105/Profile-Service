import csrf from 'csurf';
import { Router } from 'express';
import promClient from 'prom-client';
import compression from 'compression';
import mongoose from 'mongoose';
import { logger } from '../utils/logger.js';
import { createRateLimiter } from '../utils/rateLimiter.js';
import { authorize } from '../middlewares/profile.middleware.js';
import { grammarValidations, validate } from '../validations/grammer.validation.js';
import authenticateUser from '../middlewares/profile.middleware.js';
import grammarController from '../controllers/grammer.controller.js';
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
    logger.info(`Grammar API Request: ${ req.method } ${ req.path } `, {
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
router.use(compression({ level: 6, filter: (req, res) => {
    if (req.headers['x-no-compression']) return false;
    return compression.filter(req, res);
}}));

// CSRF protection for state-changing routes
const csrfProtection = csrf({ cookie: { secure: true, httpOnly: true, sameSite: 'strict' } });
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
                userId: req.user?.id || 'anonymous',
                action: `${ req.method } ${ req.path } `,
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
const checkGrammarLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 20, // 20 grammar checks per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `grammar_check_${ req.user.id }_${ req.params.summaryId } `,
});

const applyGrammarLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 50, // 50 apply operations per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `grammar_apply_${ req.user.id }_${ req.params.summaryId } `,
});

// Cache middleware for read-heavy routes
const cacheMiddleware = (ttl = 300) => async (req, res, next) => {
    const cacheKey = `route:${ req.method }:${ req.path }:${ JSON.stringify(req.query) }:${ req.user?.id } `;
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
    metricsCollector.increment('health_check', { service: 'grammar' });
    res.status(200).json({ status: 'OK', service: 'Grammar Service', timestamp: new Date().toISOString() });
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
router.use(['/:userId', '/:userId/', '/:userId/:summaryId', '/:userId/:summaryId/', '/:userId/:summaryId/:issueId'], auditLog);

// ===========================
// GRAMMAR OPERATIONS
// ===========================
router.get(
    '/:userId/:summaryId',
    checkGrammarLimiter,
    grammarValidations.checkGrammar,
    validate,
    grammarController.checkGrammar
);

router.patch(
    '/:userId/:summaryId/apply',
    applyGrammarLimiter,
    grammarValidations.applyGrammarCorrection,
    validate,
    grammarController.applyGrammarCorrection
);

router.get(
    '/:userId/:summaryId/history',
    cacheMiddleware(300),
    grammarValidations.getGrammarHistory,
    validate,
    grammarController.getGrammarHistory
);

router.post(
    '/:userId/bulk',
    applyGrammarLimiter, // Reuse apply limiter for bulk
    grammarValidations.bulkApplyGrammarCorrections,
    validate,
    grammarController.bulkApplyGrammarCorrections
);

router.delete(
    '/:userId/:summaryId/:issueId',
    applyGrammarLimiter, // Reuse apply limiter for discard
    grammarValidations.discardGrammarIssue,
    validate,
    grammarController.discardGrammarIssue
);

// ===========================
// ADMIN ROUTES
// ===========================
router.use('/admin', adminLimiter, authorize('admin'));

router.get(
    '/admin/:userId/:summaryId/history',
    cacheMiddleware(300),
    grammarValidations.getGrammarHistory,
    validate,
    grammarController.getGrammarHistory
);

// ===========================
// ERROR HANDLING
// ===========================
const handleGrammarErrors = (err, req, res, next) => {
    logger.error(`Grammar API Error: ${ err.message } `, {
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
    logger.warn(`Grammar API 404: ${ req.method } ${ req.originalUrl } `, {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        timestamp: new Date().toISOString(),
    });
    metricsCollector.increment('not_found', { path: req.originalUrl });
    res.status(404).json({
        success: false,
        message: 'Grammar API endpoint not found',
        path: req.originalUrl,
        method: req.method,
        timestamp: new Date().toISOString(),
    });
});

router.use(handleGrammarErrors);

// ===========================
// ROUTE DOCUMENTATION
// ===========================
if (process.env.NODE_ENV === 'development') {
    router.get('/docs', (req, res) => {
        res.json({
            name: 'Grammar Service API',
            version: '1.0.0',
            description: 'RESTful API for grammar and style checking operations',
            baseUrl: '/api/v1/grammar',
            routes: {
                public: [
                    'GET /health - Health check',
                    'GET /metrics - Prometheus metrics (admin-only)',
                ],
                authenticated: [
                    'GET /:userId/:summaryId - Check grammar and style for summary content',
                    'PATCH /:userId/:summaryId/apply - Apply grammar corrections',
                    'GET /:userId/:summaryId/history - Get grammar check history',
                    'POST /:userId/bulk - Bulk apply grammar corrections',
                    'DELETE /:userId/:summaryId/:issueId - Discard a grammar issue',
                ],
                admin: [
                    'GET /admin/:userId/:summaryId/history - Get any user\'s grammar history',
                ],
            },
            rateLimits: {
                checkGrammar: '20 requests per 5 minutes per user per summary',
                applyGrammarCorrection: '50 requests per 5 minutes per user per summary',
                bulkApplyGrammarCorrections: '50 requests per 5 minutes per user (shared with apply)',
                discardGrammarIssue: '50 requests per 5 minutes per user (shared with apply)',
                admin: '50 requests per 15 minutes per admin',
            },
            validations: {
                checkGrammar: 'Requires userId, summaryId; optional language, checkType',
                applyGrammarCorrection: 'Requires userId, summaryId, issueId, correction',
                getGrammarHistory: 'Requires userId, summaryId; optional page, limit',
                bulkApplyGrammarCorrections: 'Requires userId, summaryIds, issueIds, corrections',
                discardGrammarIssue: 'Requires userId, summaryId, issueId',
            },
        });
    });
}

export default router;