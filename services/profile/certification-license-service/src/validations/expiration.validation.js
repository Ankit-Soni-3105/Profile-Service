import { body, param, query, validationResult } from 'express-validator';
import { isValidObjectId } from 'mongoose';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';

// Utility to validate ObjectId
const validateObjectId = (field, location = 'params') => {
    return (location === 'params' ? param(field) : body(field))
        .custom((value) => {
            if (!value || !isValidObjectId(value)) {
                throw new AppError(`${field} must be a valid ObjectId`, 400);
            }
            return true;
        })
        .withMessage(`${field} must be a valid ObjectId`);
};

// Utility to validate expiration status
const validStatuses = ['active', 'pending', 'expired', 'archived'];

const validateStatus = (field, location = 'body') => {
    return (location === 'body' ? body(field) : query(field))
        .optional()
        .isIn(validStatuses).withMessage(`${field} must be one of ${validStatuses.join(', ')}`);
};

// Utility to validate entity type
const validEntityTypes = ['certification', 'license', 'membership', 'subscription'];

const validateEntityType = (field, location = 'body') => {
    return (location === 'body' ? body(field) : query(field))
        .notEmpty().withMessage(`${field} is required`)
        .isIn(validEntityTypes).withMessage(`${field} must be one of ${validEntityTypes.join(', ')}`);
};

// Utility to validate date
const validateDate = (field, optional = false) => {
    return body(field)
    [optional ? 'optional' : 'notEmpty']()
        .isISO8601().withMessage(`${field} must be a valid ISO 8601 date`)
        .toDate()
        .custom((value) => {
            if (new Date(value) < new Date()) {
                throw new AppError(`${field} must be a future date`, 400);
            }
            return true;
        });
};

// Utility to validate export format
const validFormats = ['json', 'csv'];

const validateExportFormat = (field) => {
    return query(field)
        .optional()
        .isIn(validFormats).withMessage(`Format must be one of ${validFormats.join(', ')}`);
};

// Utility to validate audit action
const validActions = ['create', 'update', 'delete', 'archive', 'restore', 'renew', 'media_upload', 'reminder'];

const validateAction = (field) => {
    return query(field)
        .optional()
        .isIn(validActions).withMessage(`Action must be one of ${validActions.join(', ')}`);
};

const expirationValidations = {
    createExpiration: [
        // Validate body
        validateEntityType('entityType'),
        validateObjectId('entityId', 'body'),
        validateDate('expirationDate', false),

        body('description')
            .optional()
            .trim()
            .isLength({ max: 1000 }).withMessage('Description must not exceed 1000 characters')
            .matches(/^[a-zA-Z0-9\s.,!?'-]+$/)
            .withMessage('Description contains invalid characters'),

        validateStatus('status.workflow', 'body'),

        // Custom sanitization
        body('entityType').trim().escape(),
        body('entityId').trim().escape(),
        body('description').trim().escape(),
        body('*').trim().escape()
    ],

    getExpirationById: [
        // Validate params
        validateObjectId('id')
    ],

    updateExpiration: [
        // Validate params
        validateObjectId('id'),

        // Validate body
        validateEntityType('entityType').optional(),
        validateObjectId('entityId', 'body').optional(),
        validateDate('expirationDate', true),

        body('description')
            .optional()
            .trim()
            .isLength({ max: 1000 }).withMessage('Description must not exceed 1000 characters')
            .matches(/^[a-zA-Z0-9\s.,!?'-]+$/)
            .withMessage('Description contains invalid characters'),

        validateStatus('status.workflow', 'body'),

        // Custom sanitization
        body('entityType').trim().escape(),
        body('entityId').trim().escape(),
        body('description').trim().escape(),
        body('*').trim().escape()
    ],

    deleteExpiration: [
        // Validate params
        validateObjectId('id'),

        // Validate query
        query('permanent')
            .optional()
            .isBoolean().withMessage('permanent must be a boolean')
            .toBoolean()
    ],

    uploadMedia: [
        // Validate params
        validateObjectId('id'),

        // Validate files
        body('files')
            .custom((value, { req }) => {
                if (!req.files || req.files.length === 0) {
                    throw new AppError('At least one file is required', 400);
                }
                if (req.files.length > 3) {
                    throw new AppError('Maximum 3 files allowed', 400);
                }
                return req.files.every(file => {
                    const allowedTypes = ['image/jpeg', 'image/png', 'application/pdf'];
                    if (!allowedTypes.includes(file.mimetype)) {
                        throw new AppError('Invalid file type. Only JPEG, PNG, and PDF are allowed', 400);
                    }
                    if (file.size > 3 * 1024 * 1024) { // 3MB limit
                        throw new AppError('File size must not exceed 3MB', 400);
                    }
                    return true;
                });
            }).withMessage('Invalid file upload')
    ],

    getExpirations: [
        // Validate query parameters
        query('page')
            .optional()
            .isInt({ min: 1 }).withMessage('Page must be a positive integer')
            .toInt(),

        query('limit')
            .optional()
            .isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100')
            .toInt(),

        validateStatus('status', 'query'),
        validateEntityType('entityType', 'query').optional(),
        validateObjectId('entityId', 'query').optional(),

        query('search')
            .optional()
            .trim()
            .isLength({ max: 100 }).withMessage('Search query must not exceed 100 characters')
            .matches(/^[a-zA-Z0-9\s_-]+$/)
            .withMessage('Search query contains invalid characters'),

        query('sortBy')
            .optional()
            .isIn(['expirationDate', 'recent', 'entityType', 'popularity']).withMessage('Invalid sortBy value'),

        // Custom sanitization
        query('search').trim().escape(),
        query('entityType').trim().escape()
    ],

    searchExpirations: [
        // Validate body
        body('query')
            .trim()
            .notEmpty().withMessage('Search query is required')
            .isLength({ max: 100 }).withMessage('Search query must not exceed 100 characters')
            .matches(/^[a-zA-Z0-9\s_-]+$/)
            .withMessage('Search query contains invalid characters'),

        body('filters.status')
            .optional()
            .isIn(validStatuses).withMessage(`Status must be one of ${validStatuses.join(', ')}`),

        validateEntityType('filters.entityType', 'body').optional(),
        validateObjectId('filters.entityId', 'body').optional(),

        body('page')
            .optional()
            .isInt({ min: 1 }).withMessage('Page must be a positive integer')
            .toInt(),

        body('limit')
            .optional()
            .isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100')
            .toInt(),

        // Custom sanitization
        body('query').trim().escape(),
        body('filters.entityType').trim().escape(),
        body('filters.*').trim().escape()
    ],

    getUpcomingExpirations: [
        // Validate query parameters
        query('days')
            .optional()
            .isInt({ min: 1, max: 365 }).withMessage('Days must be between 1 and 365')
            .toInt(),

        validateEntityType('entityType', 'query').optional(),

        query('limit')
            .optional()
            .isInt({ min: 1, max: 50 }).withMessage('Limit must be between 1 and 50')
            .toInt(),

        // Custom sanitization
        query('entityType').trim().escape()
    ],

    renewExpiration: [
        // Validate params
        validateObjectId('id'),

        // Validate body
        validateDate('newExpirationDate', false),

        // Custom sanitization
        body('newExpirationDate').trim()
    ],

    triggerReminder: [
        // Validate params
        validateObjectId('id')
    ],

    bulkCreateExpirations: [
        // Validate body
        body('expirations')
            .isArray({ min: 1, max: 30 }).withMessage('Expirations must be an array with 1-30 items'),

        validateEntityType('expirations.*.entityType'),
        validateObjectId('expirations.*.entityId', 'body'),
        validateDate('expirations.*.expirationDate', false),

        body('expirations.*.description')
            .optional()
            .trim()
            .isLength({ max: 1000 }).withMessage('Description must not exceed 1000 characters')
            .matches(/^[a-zA-Z0-9\s.,!?'-]+$/)
            .withMessage('Description contains invalid characters'),

        validateStatus('expirations.*.status.workflow', 'body'),

        // Custom sanitization
        body('expirations.*.entityType').trim().escape(),
        body('expirations.*.entityId').trim().escape(),
        body('expirations.*.description').trim().escape(),
        body('expirations.*.*').trim().escape()
    ],

    bulkUpdateExpirations: [
        // Validate body
        body('updates')
            .isArray({ min: 1, max: 30 }).withMessage('Updates must be an array with 1-30 items'),

        validateObjectId('updates.*.id', 'body'),
        validateEntityType('updates.*.data.entityType').optional(),
        validateObjectId('updates.*.data.entityId', 'body').optional(),
        validateDate('updates.*.data.expirationDate', true),

        body('updates.*.data.description')
            .optional()
            .trim()
            .isLength({ max: 1000 }).withMessage('Description must not exceed 1000 characters')
            .matches(/^[a-zA-Z0-9\s.,!?'-]+$/)
            .withMessage('Description contains invalid characters'),

        validateStatus('updates.*.data.status.workflow', 'body'),

        // Custom sanitization
        body('updates.*.data.entityType').trim().escape(),
        body('updates.*.data.entityId').trim().escape(),
        body('updates.*.data.description').trim().escape(),
        body('updates.*.data.*').trim().escape()
    ],

    getExpirationAnalytics: [
        // Validate params
        validateObjectId('id'),

        // Validate query
        query('timeframe')
            .optional()
            .isIn(['7d', '30d', '90d']).withMessage('Invalid timeframe')
    ],

    exportExpiration: [
        // Validate params
        validateObjectId('id'),

        // Validate query
        validateExportFormat('format')
    ],

    getExpirationStats: [
        // Validate params
        validateObjectId('id')
    ],

    archiveExpiration: [
        // Validate params
        validateObjectId('id')
    ],

    restoreExpiration: [
        // Validate params
        validateObjectId('id')
    ],

    getAuditLogs: [
        // Validate params
        validateObjectId('id'),

        // Validate query parameters
        query('page')
            .optional()
            .isInt({ min: 1 }).withMessage('Page must be a positive integer')
            .toInt(),

        query('limit')
            .optional()
            .isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100')
            .toInt(),

        validateAction('action')
    ]
};

// Validation middleware to handle errors
const validate = (validations) => {
    return async (req, res, next) => {
        try {
            // Run all validations concurrently
            await Promise.all(validations.map(validation => validation.run(req)));

            // Check for validation errors
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                const errorMessages = errors.array().map(e => e.msg).join(', ');
                logger.warn(`Validation failed: ${JSON.stringify(errors.array())}`, {
                    path: req.originalUrl,
                    method: req.method,
                    userId: req.user?.id
                });
                return next(new AppError(`Validation failed: ${errorMessages}`, 400));
            }

            // Additional validation for high-scale systems
            if (req.body.expirations && req.body.expirations.length > 15) {
                logger.warn(`High volume request detected: ${req.body.expirations.length} expirations`, {
                    userId: req.user?.id,
                    path: req.originalUrl
                });
            }
            if (req.body.updates && req.body.updates.length > 15) {
                logger.warn(`High volume request detected: ${req.body.updates.length} updates`, {
                    userId: req.user?.id,
                    path: req.originalUrl
                });
            }

            next();
        } catch (error) {
            logger.error('Validation middleware error:', {
                error: error.message,
                stack: error.stack,
                path: req.originalUrl,
                userId: req.user?.id
            });
            return next(new AppError('Validation processing error', 500));
        }
    };
};

// Validation functions for compatibility with existing code
const validateExpiration = (data, isUpdate = false) => {
    const errors = [];

    if (!isUpdate || data.entityType) {
        if (!data.entityType) errors.push('entityType is required');
        else if (!validEntityTypes.includes(data.entityType)) {
            errors.push(`entityType must be one of ${validEntityTypes.join(', ')}`);
        }
    }

    if (!isUpdate || data.entityId) {
        if (!data.entityId || !isValidObjectId(data.entityId)) {
            errors.push('entityId must be a valid ObjectId');
        }
    }

    if (!isUpdate || data.expirationDate) {
        if (!data.expirationDate || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.*Z$/.test(data.expirationDate)) {
            errors.push('expirationDate must be a valid ISO 8601 date');
        } else if (new Date(data.expirationDate) < new Date()) {
            errors.push('expirationDate must be a future date');
        }
    }

    if (data.description && (typeof data.description !== 'string' || data.description.length > 1000)) {
        errors.push('Description must not exceed 1000 characters');
    }

    if (data.status?.workflow && !validStatuses.includes(data.status.workflow)) {
        errors.push(`Status must be one of ${validStatuses.join(', ')}`);
    }

    return errors.length > 0 ? { valid: false, message: errors.join(', ') } : { valid: true };
};

const validateBulkExpiration = (expirations) => {
    if (!Array.isArray(expirations) || expirations.length === 0 || expirations.length > 30) {
        return { valid: false, message: 'Expirations must be an array with 1-30 items' };
    }

    const errors = [];
    expirations.forEach((expiration, index) => {
        const validation = validateExpiration(expiration);
        if (!validation.valid) {
            errors.push(`Expiration at index ${index}: ${validation.message}`);
        }
    });

    return errors.length > 0 ? { valid: false, message: errors.join('; ') } : { valid: true };
};

const validateSearch = ({ query, filters }) => {
    const errors = [];

    if (!query || typeof query !== 'string' || query.length > 100) {
        errors.push('Search query must be a string not exceeding 100 characters');
    } else if (!/^[a-zA-Z0-9\s_-]+$/.test(query)) {
        errors.push('Search query contains invalid characters');
    }

    if (filters) {
        if (filters.status && !validStatuses.includes(filters.status)) {
            errors.push(`Status must be one of ${validStatuses.join(', ')}`);
        }
        if (filters.entityType && !validEntityTypes.includes(filters.entityType)) {
            errors.push(`entityType must be one of ${validEntityTypes.join(', ')}`);
        }
        if (filters.entityId && !isValidObjectId(filters.entityId)) {
            errors.push('Invalid entityId in filters');
        }
    }

    return errors.length > 0 ? { valid: false, message: errors.join(', ') } : { valid: true };
};

export { expirationValidations, validate, validateExpiration, validateBulkExpiration, validateSearch };