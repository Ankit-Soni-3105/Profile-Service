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

// Utility to validate badge types
const validBadgeTypes = [
    'achievement', 'certification', 'skill', 'contribution', 'recognition',
    'attendance', 'leadership', 'innovation', 'teamwork', 'other'
];

const validateBadgeType = (field, location = 'body') => {
    return (location === 'body' ? body(field) : query(field))
        .trim()
        .notEmpty().withMessage(`${field} is required`)
        .isIn(validBadgeTypes).withMessage(`${field} must be a valid badge type`)
        .isLength({ max: 50 }).withMessage(`${field} must not exceed 50 characters`);
};

// Utility to validate badge status
const validStatuses = ['draft', 'published', 'archived', 'pending'];

const validateStatus = (field, location = 'body') => {
    return (location === 'body' ? body(field) : query(field))
        .optional()
        .isIn(validStatuses).withMessage(`${field} must be one of ${validStatuses.join(', ')}`);
};

// Utility to validate tags array
const validateTags = (field) => {
    return body(field)
        .optional()
        .isArray().withMessage(`${field} must be an array`)
        .custom((tags) => {
            if (tags.length > 20) {
                throw new AppError('Maximum 20 tags allowed', 400);
            }
            return tags.every(tag => typeof tag === 'string' && tag.length <= 30 && /^[a-zA-Z0-9_-]+$/.test(tag));
        }).withMessage('Each tag must be a string, not exceed 30 characters, and contain only letters, numbers, underscores, or hyphens');
};

// Utility to validate badge criteria
const validateCriteria = (field) => {
    return body(field)
        .optional()
        .isArray().withMessage(`${field} must be an array`)
        .custom((criteria) => {
            if (criteria.length > 10) {
                throw new AppError('Maximum 10 criteria allowed', 400);
            }
            return criteria.every(criterion => typeof criterion === 'string' && criterion.length <= 500 && /^[a-zA-Z0-9\s.,!?'-]+$/.test(criterion));
        }).withMessage('Each criterion must be a string, not exceed 500 characters, and contain only allowed characters');
};

// Utility to validate image URL
const validateImageUrl = (field) => {
    return body(field)
        .optional()
        .isURL({ require_protocol: true }).withMessage(`${field} must be a valid URL`)
        .isLength({ max: 500 }).withMessage(
            `${field} must not exceed 500 characters`
        );
};

const badgeValidations = {
    createBadge: [
        // Validate body
        body('name')
            .trim()
            .notEmpty().withMessage('Badge name is required')
            .isLength({ min: 3, max: 100 }).withMessage('Badge name must be between 3 and 100 characters')
            .matches(/^[a-zA-Z0-9\s_-]+$/).withMessage('Badge name contains invalid characters'),

        validateBadgeType('type'),
        validateImageUrl('image'),
        validateCriteria('criteria'),

        body('description')
            .optional()
            .trim()
            .isLength({ max: 1000 }).withMessage('Description must not exceed 1000 characters')
            .matches(/^[a-zA-Z0-9\s.,!?'-]+$/).withMessage('Description contains invalid characters'),

        validateTags('tags'),

        body('metadata.expiryDate')
            .optional()
            .isISO8601().withMessage('Expiry date must be a valid ISO date')
            .toDate(),

        body('metadata.isTransferable')
            .optional()
            .isBoolean().withMessage('isTransferable must be a boolean'),

        // Custom sanitization
        body('name').trim().escape(),
        body('description').trim().escape(),
        body('criteria.*').trim().escape(),
        body('*').trim().escape()
    ],

    getBadgeById: [
        // Validate params
        validateObjectId('id')
    ],

    updateBadge: [
        // Validate params
        validateObjectId('id'),

        // Validate body
        body('name')
            .optional()
            .trim()
            .isLength({ min: 3, max: 100 }).withMessage('Badge name must be between 3 and 100 characters')
            .matches(/^[a-zA-Z0-9\s_-]+$/).withMessage('Badge name contains invalid characters'),

        validateBadgeType('type').optional(),
        validateImageUrl('image'),
        validateCriteria('criteria'),
        validateStatus('status.workflow', 'body'),

        body('description')
            .optional()
            .trim()
            .isLength({ max: 1000 }).withMessage('Description must not exceed 1000 characters')
            .matches(/^[a-zA-Z0-9\s.,!?'-]+$/).withMessage('Description contains invalid characters'),

        validateTags('tags'),

        body('metadata.expiryDate')
            .optional()
            .isISO8601().withMessage('Expiry date must be a valid ISO date')
            .toDate(),

        body('metadata.isTransferable')
            .optional()
            .isBoolean().withMessage('isTransferable must be a boolean'),

        // Custom sanitization
        body('name').trim().escape(),
        body('description').trim().escape(),
        body('criteria.*').trim().escape(),
        body('*').trim().escape()
    ],

    deleteBadge: [
        // Validate params
        validateObjectId('id'),

        // Validate query
        query('permanent')
            .optional()
            .isBoolean().withMessage('permanent must be a boolean')
            .toBoolean()
    ],

    issueBadge: [
        // Validate params
        validateObjectId('id'),

        // Validate body
        validateObjectId('recipientId', 'body'),

        body('comment')
            .optional()
            .trim()
            .isLength({ max: 500 }).withMessage('Comment must not exceed 500 characters')
            .matches(/^[a-zA-Z0-9\s.,!?'-]+$/).withMessage('Comment contains invalid characters'),

        body('issueDate')
            .optional()
            .isISO8601().withMessage('Issue date must be a valid ISO date')
            .toDate(),

        // Custom sanitization
        body('comment').trim().escape(),
        body('*').trim().escape()
    ],

    revokeBadge: [
        // Validate params
        validateObjectId('id'),

        // Validate body
        validateObjectId('recipientId', 'body'),

        body('reason')
            .optional()
            .trim()
            .isLength({ max: 500 }).withMessage('Reason must not exceed 500 characters')
            .matches(/^[a-zA-Z0-9\s.,!?'-]+$/).withMessage('Reason contains invalid characters'),

        // Custom sanitization
        body('reason').trim().escape(),
        body('*').trim().escape()
    ],

    verifyBadge: [
        // Validate params
        validateObjectId('id')
    ],

    uploadMedia: [
        // Validate params
        validateObjectId('id'),

        // Validate files (handled by multer middleware, basic validation here)
        body('files')
            .custom((value, { req }) => {
                if (!req.files || req.files.length === 0) {
                    throw new AppError('At least one file is required', 400);
                }
                if (req.files.length > 5) {
                    throw new AppError('Maximum 5 files allowed', 400);
                }
                return req.files.every(file => {
                    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
                    if (!allowedTypes.includes(file.mimetype)) {
                        throw new AppError('Invalid file type. Only JPEG, PNG, and GIF are allowed', 400);
                    }
                    if (file.size > 5 * 1024 * 1024) { // 5MB limit
                        throw new AppError('File size must not exceed 5MB', 400);
                    }
                    return true;
                });
            }).withMessage('Invalid file upload')
    ],

    getBadges: [
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
        validateBadgeType('type', 'query'),

        query('search')
            .optional()
            .trim()
            .isLength({ max: 100 }).withMessage('Search query must not exceed 100 characters')
            .matches(/^[a-zA-Z0-9\s_-]+$/).withMessage('Search query contains invalid characters')
    ],

    searchBadges: [
        // Validate body
        body('query')
            .trim()
            .notEmpty().withMessage('Search query is required')
            .isLength({ max: 100 }).withMessage('Search query must not exceed 100 characters')
            .matches(/^[a-zA-Z0-9\s_-]+$/).withMessage('Search query contains invalid characters'),

        body('filters.status')
            .optional()
            .isIn(validStatuses).withMessage(`Status must be one of ${validStatuses.join(', ')}`),

        body('filters.type')
            .optional()
            .isIn(validBadgeTypes).withMessage(`Type must be one of ${validBadgeTypes.join(', ')}`),

        body('filters.tags')
            .optional()
            .isArray().withMessage('Tags must be an array')
            .custom((tags) => {
                if (tags.length > 20) {
                    throw new AppError('Maximum 20 tags allowed', 400);
                }
                return tags.every(tag => typeof tag === 'string' && tag.length <= 30 && /^[a-zA-Z0-9_-]+$/.test(tag));
            }).withMessage('Each tag must be a string, not exceed 30 characters, and contain only letters, numbers, underscores, or hyphens'),

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
        body('filters.tags.*').trim().escape(),
        body('*').trim().escape()
    ],

    getTrendingBadges: [
        // Validate query parameters
        query('timeframe')
            .optional()
            .isIn(['7d', '30d', '90d']).withMessage('Invalid timeframe'),

        query('type')
            .optional()
            .isIn(validBadgeTypes).withMessage(`Type must be one of ${validBadgeTypes.join(', ')}`),

        query('limit')
            .optional()
            .isInt({ min: 1, max: 50 }).withMessage('Limit must be between 1 and 50')
            .toInt()
    ],

    bulkCreateBadges: [
        // Validate body
        body('badges')
            .isArray({ min: 1, max: 100 }).withMessage('Badges must be an array with 1-100 items')
            .custom((badges) => {
                return badges.every(badge => {
                    if (!badge.name || typeof badge.name !== 'string') {
                        throw new AppError('Each badge must have a valid name', 400);
                    }
                    if (!badge.type || !validBadgeTypes.includes(badge.type)) {
                        throw new AppError(`Each badge must have a valid type: ${validBadgeTypes.join(', ')}`, 400);
                    }
                    return true;
                });
            }).withMessage('All badges must be valid'),

        body('badges.*.name')
            .trim()
            .isLength({ min: 3, max: 100 }).withMessage('Badge name must be between 3 and 100 characters')
            .matches(/^[a-zA-Z0-9\s_-]+$/).withMessage('Badge name contains invalid characters'),

        body('badges.*.type')
            .isIn(validBadgeTypes).withMessage(`Badge type must be one of ${validBadgeTypes.join(', ')}`),

        body('badges.*.image')
            .optional()
            .isURL({ require_protocol: true }).withMessage('Image must be a valid URL')
            .isLength({ max: 500 }).withMessage('Image URL must not exceed 500 characters'),

        body('badges.*.description')
            .optional()
            .trim()
            .isLength({ max: 1000 }).withMessage('Description must not exceed 1000 characters')
            .matches(/^[a-zA-Z0-9\s.,!?'-]+$/).withMessage('Description contains invalid characters'),

        body('badges.*.criteria')
            .optional()
            .isArray().withMessage('Criteria must be an array')
            .custom((criteria) => {
                if (criteria.length > 10) {
                    throw new AppError('Maximum 10 criteria allowed per badge', 400);
                }
                return criteria.every(criterion => typeof criterion === 'string' && criterion.length <= 500 && /^[a-zA-Z0-9\s.,!?'-]+$/.test(criterion));
            }).withMessage('Each criterion must be a string, not exceed 500 characters, and contain only allowed characters'),

        body('badges.*.tags')
            .optional()
            .isArray().withMessage('Tags must be an array')
            .custom((tags) => {
                if (tags.length > 20) {
                    throw new AppError('Maximum 20 tags allowed per badge', 400);
                }
                return tags.every(tag => typeof tag === 'string' && tag.length <= 30 && /^[a-zA-Z0-9_-]+$/.test(tag));
            }).withMessage('Each tag must be a string, not exceed 30 characters, and contain only letters, numbers, underscores, or hyphens'),

        body('badges.*.metadata.expiryDate')
            .optional()
            .isISO8601().withMessage('Expiry date must be a valid ISO date')
            .toDate(),

        body('badges.*.metadata.isTransferable')
            .optional()
            .isBoolean().withMessage('isTransferable must be a boolean'),

        // Custom sanitization
        body('badges.*.name').trim().escape(),
        body('badges.*.description').trim().escape(),
        body('badges.*.criteria.*').trim().escape(),
        body('badges.*.tags.*').trim().escape(),
        body('*').trim().escape()
    ],

    bulkUpdateBadges: [
        // Validate body
        body('updates')
            .isArray({ min: 1, max: 100 }).withMessage('Updates must be an array with 1-100 items')
            .custom((updates) => {
                return updates.every(update => {
                    if (!update.id || !isValidObjectId(update.id)) {
                        throw new AppError('Each update must have a valid badge ID', 400);
                    }
                    return true;
                });
            }).withMessage('All updates must have valid badge IDs'),

        body('updates.*.id')
            .custom((value) => {
                if (!isValidObjectId(value)) {
                    throw new AppError('Badge ID must be a valid ObjectId', 400);
                }
                return true;
            }).withMessage('Badge ID must be a valid ObjectId'),

        body('updates.*.data.name')
            .optional()
            .trim()
            .isLength({ min: 3, max: 100 }).withMessage('Badge name must be between 3 and 100 characters')
            .matches(/^[a-zA-Z0-9\s_-]+$/).withMessage('Badge name contains invalid characters'),

        body('updates.*.data.type')
            .optional()
            .isIn(validBadgeTypes).withMessage(`Badge type must be one of ${validBadgeTypes.join(', ')}`),

        body('updates.*.data.image')
            .optional()
            .isURL({ require_protocol: true }).withMessage('Image must be a valid URL')
            .isLength({ max: 500 }).withMessage('Image URL must not exceed 500 characters'),

        body('updates.*.data.description')
            .optional()
            .trim()
            .isLength({ max: 1000 }).withMessage('Description must not exceed 1000 characters')
            .matches(/^[a-zA-Z0-9\s.,!?'-]+$/).withMessage('Description contains invalid characters'),

        body('updates.*.data.criteria')
            .optional()
            .isArray().withMessage('Criteria must be an array')
            .custom((criteria) => {
                if (criteria.length > 10) {
                    throw new AppError('Maximum 10 criteria allowed per badge', 400);
                }
                return criteria.every(criterion => typeof criterion === 'string' && criterion.length <= 500 && /^[a-zA-Z0-9\s.,!?'-]+$/.test(criterion));
            }).withMessage('Each criterion must be a string, not exceed 500 characters, and contain only allowed characters'),

        body('updates.*.data.tags')
            .optional()
            .isArray().withMessage('Tags must be an array')
            .custom((tags) => {
                if (tags.length > 20) {
                    throw new AppError('Maximum 20 tags allowed per badge', 400);
                }
                return tags.every(tag => typeof tag === 'string' && tag.length <= 30 && /^[a-zA-Z0-9_-]+$/.test(tag));
            }).withMessage('Each tag must be a string, not exceed 30 characters, and contain only letters, numbers, underscores, or hyphens'),

        body('updates.*.data.status.workflow')
            .optional()
            .isIn(validStatuses).withMessage(`Status must be one of ${validStatuses.join(', ')}`),

        body('updates.*.data.metadata.expiryDate')
            .optional()
            .isISO8601().withMessage('Expiry date must be a valid ISO date')
            .toDate(),

        body('updates.*.data.metadata.isTransferable')
            .optional()
            .isBoolean().withMessage('isTransferable must be a boolean'),

        // Custom sanitization
        body('updates.*.data.name').trim().escape(),
        body('updates.*.data.description').trim().escape(),
        body('updates.*.data.criteria.*').trim().escape(),
        body('updates.*.data.tags.*').trim().escape(),
        body('*').trim().escape()
    ],

    getBadgeAnalytics: [
        // Validate params
        validateObjectId('id'),

        // Validate query
        query('timeframe')
            .optional()
            .isIn(['7d', '30d', '90d']).withMessage('Invalid timeframe')
    ],

    exportBadge: [
        // Validate params
        validateObjectId('id'),

        // Validate query
        query('format')
            .optional()
            .isIn(['json', 'csv']).withMessage('Format must be json or csv')
    ],

    getBadgeStats: [
        // Validate params
        validateObjectId('id')
    ],

    archiveBadge: [
        // Validate params
        validateObjectId('id')
    ],

    restoreBadge: [
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

        query('action')
            .optional()
            .isIn(['create', 'update', 'delete', 'issue', 'revoke', 'verify', 'archive', 'restore'])
            .withMessage('Invalid action filter')
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
            if (req.body.badges && req.body.badges.length > 50) {
                logger.warn(`High volume request detected: ${req.body.badges.length} badges`, {
                    userId: req.user?.id,
                    path: req.originalUrl
                });
            }
            if (req.body.updates && req.body.updates.length > 50) {
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

export { badgeValidations, validate };