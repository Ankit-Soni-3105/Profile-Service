import csrf from 'csurf';
import { Router } from 'express';
import promClient from 'prom-client';
import compression from 'compression';
import mongoose from 'mongoose';
import { logger } from '../utils/logger.js';
import { createRateLimiter } from '../utils/rateLimiter.js';
import { voiceInputValidations } from '../validations/voice.input.validation.js';
import { validate } from '../validations/voice.input.validation.js';
import voiceInputController from '../controllers/voiceInput.controller.js';
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
    logger.info(`Voice API Request: ${req.method} ${req.path}`, {
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

// Rate limiters for voice operations
const processVoiceLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 10, // 10 voice inputs per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `voice_process_${req.user.id}_${req.params.summaryId || 'new'}`,
});

const bulkVoiceLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5, // 5 bulk operations per hour
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_voice_${req.user.id}`,
});

const deleteVoiceLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // 10 delete operations per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `delete_voice_${req.user.id}`,
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
    metricsCollector.increment('health_check', { service: 'voice' });
    res.status(200).json({ status: 'OK', service: 'Voice Input Service', timestamp: new Date().toISOString() });
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
router.use(['/:userId', '/:userId/', '/:userId/:summaryId', '/:userId/:summaryId/', '/:userId/:summaryId/:voiceInputId', '/admin/'], auditLog);

// ===========================
// VOICE INPUT OPERATIONS
// ===========================
router.post(
    '/:userId/:summaryId?',
    processVoiceLimiter,
    voiceInputValidations.processVoiceInput,
    validate,
    voiceInputController.processVoiceInput
);

router.get(
    '/:userId/languages',
    cacheMiddleware(86400), // 1 day cache for supported languages
    voiceInputValidations.getSupportedLanguages,
    validate,
    voiceInputController.getSupportedLanguages
);

router.get(
    '/:userId/:summaryId/history',
    cacheMiddleware(300),
    voiceInputValidations.getVoiceInputHistory,
    validate,
    voiceInputController.getVoiceInputHistory
);

router.post(
    '/:userId/bulk',
    bulkVoiceLimiter,
    voiceInputValidations.bulkProcessVoiceInputs,
    validate,
    voiceInputController.bulkProcessVoiceInputs
);

router.delete(
    '/:userId/:summaryId/:voiceInputId',
    deleteVoiceLimiter,
    voiceInputValidations.deleteVoiceInput,
    validate,
    voiceInputController.deleteVoiceInput
);

// ===========================
// ADMIN ROUTES
// ===========================
router.use('/admin', adminLimiter, authorize('admin'));

router.get(
    '/admin/:userId/:summaryId/history',
    cacheMiddleware(300),
    voiceInputValidations.getVoiceInputHistory,
    validate,
    voiceInputController.getVoiceInputHistory
);

// ===========================
// ERROR HANDLING
// ===========================
const handleVoiceErrors = (err, req, res, next) => {
    logger.error(`Voice API Error: ${err.message}`, {
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
    logger.warn(`Voice API 404: ${req.method} ${req.originalUrl}`, {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        timestamp: new Date().toISOString(),
    });
    metricsCollector.increment('not_found', { path: req.originalUrl });
    res.status(404).json({
        success: false,
        message: 'Voice API endpoint not found',
        path: req.originalUrl,
        method: req.method,
        timestamp: new Date().toISOString(),
    });
});

router.use(handleVoiceErrors);

// ===========================
// ROUTE DOCUMENTATION
// ===========================
if (process.env.NODE_ENV === 'development') {
    router.get('/docs', (req, res) => {
        res.json({
            name: 'Voice Input Service API',
            version: '1.0.0',
            description: 'RESTful API for voice input management',
            baseUrl: '/api/v1/voice',
            routes: {
                public: [
                    'GET /health - Health check',
                    'GET /metrics - Prometheus metrics (admin-only)',
                ],
                authenticated: [
                    'POST /:userId/:summaryId? - Process voice input to create or update a summary',
                    'GET /:userId/languages - Get supported voice input languages',
                    'GET /:userId/:summaryId/history - Get voice input history for a summary',
                    'POST /:userId/bulk - Bulk process voice inputs',
                    'DELETE /:userId/:summaryId/:voiceInputId - Delete a voice input',
                ],
                admin: [
                    'GET /admin/:userId/:summaryId/history - Get any user\'s voice input history',
                ],
            },
            rateLimits: {
                processVoiceInput: '10 requests per 5 minutes per user per summary',
                bulkProcessVoiceInputs: '5 requests per hour per user',
                deleteVoiceInput: '10 requests per 15 minutes per user',
                admin: '50 requests per 15 minutes per admin',
            },
            validations: {
                processVoiceInput: 'Requires userId, audioData; optional summaryId, language, options, context, priority, callbackUrl',
                getSupportedLanguages: 'Requires userId; optional includeDetails, region',
                getVoiceInputHistory: 'Requires userId, summaryId; optional page, limit, sortBy, sortOrder, status, startDate, endDate, language',
                bulkProcessVoiceInputs: 'Requires userId, inputs; optional language, options, batchName, priority, callbackUrl',
                deleteVoiceInput: 'Requires userId, summaryId, voiceInputId; optional reason',
            },
        });
    });
}

export default router;