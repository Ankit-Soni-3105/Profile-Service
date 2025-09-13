import csrf from 'csurf';
import { Router } from 'express';
import promClient from 'prom-client';
import compression from 'compression';
import mongoose from 'mongoose';
import { logger } from '../utils/logger.js';
import { createRateLimiter } from '../utils/rateLimiter.js';
import { authorize } from '../middlewares/profile.middleware.js';
import { editorValidations, validate } from '../validations/editor.validation.js';
import authenticateUser from '../middlewares/profile.middleware.js';
import editorController from '../controllers/editor.controller.js';
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
    logger.info(`Editor API Request: ${req.method} ${req.path} `, {
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
        'Content-Security-Policy': "default-src 'self'; connect-src 'self' ws: wss:; frame-ancestors 'none';",
    });
    next();
});

// Compression middleware (using Brotli for better performance, excluding WebSocket routes)
router.use(compression({
    level: 6, filter: (req, res) => {
        if (req.headers['upgrade'] === 'websocket' || req.headers['x-no-compression']) return false;
        return compression.filter(req, res);
    }
}));

// CSRF protection for state-changing routes
const csrfProtection = csrf({ cookie: { secure: true, httpOnly: true, sameSite: 'strict' } });
router.use((req, res, next) => {
    if (['POST', 'PATCH', 'DELETE'].includes(req.method) && !req.path.includes('/ws')) {
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
        if (req.method !== 'GET' && res.statusCode < 400 && !req.path.includes('/ws')) {
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
const updateContentLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 100, // 100 content updates per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `editor_update_${req.user.id}_${req.params.summaryId} `,
});

const stateUpdateLimiter = createRateLimiter({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 200, // 200 state updates per minute
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `editor_state_${req.user.id}_${req.params.summaryId} `,
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
    metricsCollector.increment('health_check', { service: 'editor' });
    res.status(200).json({ status: 'OK', service: 'Editor Service', timestamp: new Date().toISOString() });
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
router.use(['/:userId', '/:userId/', '/:userId/:summaryId', '/:userId/:summaryId/', '/admin/'], auditLog);

// ===========================
// EDITOR OPERATIONS
// ===========================
router.patch(
    '/:userId/:summaryId',
    updateContentLimiter,
    editorValidations.updateContent,
    validate,
    editorController.updateContent
);

router.patch(
    '/:userId/:summaryId/state',
    stateUpdateLimiter,
    editorValidations.saveEditorState,
    validate,
    editorController.saveEditorState
);

router.get(
    '/:userId/:summaryId/collaborators',
    cacheMiddleware(300),
    editorValidations.getCollaborators,
    validate,
    editorController.getCollaborators
);

router.post(
    '/:userId/:summaryId/undo',
    updateContentLimiter, // Reuse update limiter for undo
    editorValidations.undoChange,
    validate,
    editorController.undoChange
);

router.post(
    '/:userId/:summaryId/redo',
    updateContentLimiter, // Reuse update limiter for redo
    editorValidations.redoChange,
    validate,
    editorController.redoChange
);

router.get(
    '/:userId/:summaryId/history',
    cacheMiddleware(300),
    editorValidations.getHistory,
    validate,
    editorController.getHistory
);

// ===========================
// WEBSOCKET ROUTE
// ===========================
// WebSocket endpoint (handled via upgrade, no explicit route needed here)
// Note: WebSocket authentication is handled in controller's handleWebSocketUpgrade

// ===========================
// ADMIN ROUTES
// ===========================
router.use('/admin', adminLimiter, authorize('admin'));

router.get(
    '/admin/:userId/:summaryId/collaborators',
    cacheMiddleware(300),
    editorValidations.getCollaborators,
    validate,
    editorController.getCollaborators
);

router.get(
    '/admin/:userId/:summaryId/history',
    cacheMiddleware(300),
    editorValidations.getHistory,
    validate,
    editorController.getHistory
);

// ===========================
// ERROR HANDLING
// ===========================
const handleEditorErrors = (err, req, res, next) => {
    logger.error(`Editor API Error: ${err.message} `, {
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
    logger.warn(`Editor API 404: ${req.method} ${req.originalUrl} `, {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        timestamp: new Date().toISOString(),
    });
    metricsCollector.increment('not_found', { path: req.originalUrl });
    res.status(404).json({
        success: false,
        message: 'Editor API endpoint not found',
        path: req.originalUrl,
        method: req.method,
        timestamp: new Date().toISOString(),
    });
});

router.use(handleEditorErrors);

// ===========================
// ROUTE DOCUMENTATION
// ===========================
if (process.env.NODE_ENV === 'development') {
    router.get('/docs', (req, res) => {
        res.json({
            name: 'Editor Service API',
            version: '1.0.0',
            description: 'RESTful and WebSocket API for real-time editor management',
            baseUrl: '/api/v1/editor',
            routes: {
                public: [
                    'GET /health - Health check',
                    'GET /metrics - Prometheus metrics (admin-only)',
                ],
                authenticated: [
                    'PATCH /:userId/:summaryId - Update summary content in real-time',
                    'PATCH /:userId/:summaryId/state - Save editor state (cursor position, selection)',
                    'GET /:userId/:summaryId/collaborators - Get active collaborators for a summary',
                    'POST /:userId/:summaryId/undo - Undo last change',
                    'POST /:userId/:summaryId/redo - Redo last undone change',
                    'GET /:userId/:summaryId/history - Get editor history',
                    'WS /:userId/:summaryId - WebSocket for real-time collaboration',
                ],
                admin: [
                    'GET /admin/:userId/:summaryId/collaborators - Get any user\'s collaborators for a summary',
                    'GET /admin/:userId/:summaryId/history - Get any user\'s editor history',
                ],
            },
            rateLimits: {
                updateContent: '100 requests per 5 minutes per user per summary',
                saveEditorState: '200 requests per minute per user per summary',
                undoRedo: '100 requests per 5 minutes per user per summary (shared with update)',
                admin: '50 requests per 15 minutes per admin',
            },
            validations: {
                updateContent: 'Requires userId, summaryId, content; optional cursorPosition',
                saveEditorState: 'Requires userId, summaryId; optional cursorPosition, selectionRange',
                getCollaborators: 'Requires userId, summaryId',
                undoChange: 'Requires userId, summaryId',
                redoChange: 'Requires userId, summaryId',
                getHistory: 'Requires userId, summaryId; optional page, limit',
            },
        });
    });
}

export default router;
