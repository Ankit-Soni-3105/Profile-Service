import csrf from 'csurf';
import { Router } from 'express';
import promClient from 'prom-client';
import compression from 'compression';
import mongoose from 'mongoose';
import { logger } from '../utils/logger.js';
import { createRateLimiter } from '../utils/rateLimiter.js';
import { authorize } from '../middlewares/profile.middleware.js';
import { backupValidations, validate } from '../validations/backup.validation.js';
import authenticateUser from '../middlewares/profile.middleware.js';
import backupController from '../controllers/backup.controller.js';
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
    logger.info(`Backup API Request: ${ req.method } ${ req.path } `, {
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
const createBackupLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // 10 backup creations per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `backup_create_${ req.user.id }_${ req.params.summaryId } `,
});

const restoreBackupLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 restore operations per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `backup_restore_${ req.user.id }_${ req.params.summaryId } `,
});

// Cache middleware for read-heavy routes
const cacheMiddleware = (ttl = 3600) => async (req, res, next) => {
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
    metricsCollector.increment('health_check', { service: 'backup' });
    res.status(200).json({ status: 'OK', service: 'Backup Service', timestamp: new Date().toISOString() });
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
router.use(['/:userId', '/:userId/', '/:userId/:summaryId', '/:userId/:summaryId/', '/:userId/:backupId', '/:userId/:backupId/', '/admin/'], auditLog);

// ===========================
// BACKUP CRUD OPERATIONS
// ===========================
router.post(
    '/:userId/:summaryId',
    createBackupLimiter,
    backupValidations.createBackup,
    validate,
    backupController.createBackup
);

router.post(
    '/:userId/:backupId/restore',
    restoreBackupLimiter,
    backupValidations.restoreBackup,
    validate,
    backupController.restoreBackup
);

router.get(
    '/:userId/:summaryId',
    cacheMiddleware(3600),
    backupValidations.getBackups,
    validate,
    backupController.getBackups
);

router.delete(
    '/:userId/:backupId',
    backupValidations.deleteBackup,
    validate,
    backupController.deleteBackup
);

// ===========================
// BULK OPERATIONS
// ===========================
router.post(
    '/:userId/bulk',
    createBackupLimiter, // Reuse create limiter for bulk operations
    backupValidations.bulkCreateBackups,
    validate,
    backupController.bulkCreateBackups
);

// ===========================
// ADMIN ROUTES
// ===========================
router.use('/admin', adminLimiter, authorize('admin'));

// Admin can access any user's backups
router.get(
    '/admin/:userId/:summaryId',
    cacheMiddleware(3600),
    backupValidations.getBackups,
    validate,
    backupController.getBackups
);

// ===========================
// ERROR HANDLING
// ===========================
const handleBackupErrors = (err, req, res, next) => {
    logger.error(`Backup API Error: ${ err.message } `, {
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
    logger.warn(`Backup API 404: ${ req.method } ${ req.originalUrl } `, {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        timestamp: new Date().toISOString(),
    });
    metricsCollector.increment('not_found', { path: req.originalUrl });
    res.status(404).json({
        success: false,
        message: 'Backup API endpoint not found',
        path: req.originalUrl,
        method: req.method,
        timestamp: new Date().toISOString(),
    });
});

router.use(handleBackupErrors);

// ===========================
// ROUTE DOCUMENTATION
// ===========================
if (process.env.NODE_ENV === 'development') {
    router.get('/docs', (req, res) => {
        res.json({
            name: 'Backup Service API',
            version: '1.0.0',
            description: 'RESTful API for backup management',
            baseUrl: '/api/v1/backup',
            routes: {
                public: [
                    'GET /health - Health check',
                    'GET /metrics - Prometheus metrics (admin-only)',
                ],
                authenticated: [
                    'POST /:userId/:summaryId - Create a backup for a summary',
                    'POST /:userId/:backupId/restore - Restore a backup to a summary',
                    'GET /:userId/:summaryId - Get backups for a summary',
                    'DELETE /:userId/:backupId - Delete a backup',
                    'POST /:userId/bulk - Bulk create backups for multiple summaries',
                ],
                admin: [
                    'GET /admin/:userId/:summaryId - Get any user\'s backups for a summary',
                ],
            },
            rateLimits: {
                createBackup: '10 requests per 15 minutes per user per summary',
                restoreBackup: '5 requests per 15 minutes per user per summary',
                bulkCreate: '10 requests per 15 minutes per user (shared with create)',
                admin: '50 requests per 15 minutes per admin',
            },
            validations: {
                createBackup: 'Requires userId, summaryId; optional notes',
                restoreBackup: 'Requires userId, backupId; optional merge (boolean)',
                getBackups: 'Requires userId, summaryId; optional page, limit',
                deleteBackup: 'Requires userId, backupId',
                bulkCreateBackups: 'Requires userId, summaryIds (array); optional notes',
            },
        });
    });
}

export default router;