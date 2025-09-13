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

// Utility to validate category status
const validStatuses = ['active', 'inactive', 'pending', 'archived'];

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

// Utility to validate icon URL
const validateIconUrl = (field) => {
    return body(field)
        .optional()
        .isURL({ require_protocol: true }).withMessage(
            `${field} must be a valid URL`
        )
        .isLength({ max: 500 }).withMessage(`${field} must not exceed 500 characters`);
};

const categoryValidations = {
    createCategory: [
        // Validate body
        body('name')
            .trim()
            .notEmpty().withMessage('Category name is required')
            .isLength({ min: 3, max: 100 }).withMessage('Category name must be between 3 and 100 characters')
            .matches(/^[a-zA-Z0-9\s_-]+$/).withMessage('Category name contains invalid characters'),

        validateIconUrl('icon'),

        body('description')
            .optional()
            .trim()
            .isLength({ max: 1000 }).withMessage('Description must not exceed 1000 characters')
            .matches(/^[a-zA-Z0-9\s.,!?'-]+$/).withMessage('Description contains invalid characters'),

        validateObjectId('parentId', 'body').optional(),

        validateTags('tags'),

        body('metadata.isRestricted')
            .optional()
            .isBoolean().withMessage('isRestricted must be a boolean'),

        body('metadata.priority')
            .optional()
            .isInt({ min: 1, max: 10 }).withMessage('Priority must be between 1 and 10')
            .toInt(),

        // Custom sanitization
        body('name').trim().escape(),
        body('description').trim().escape(),
        body('tags.*').trim().escape(),
        body('*').trim().escape()
    ],

    getCategoryById: [
        // Validate params
        validateObjectId('id')
    ],

    updateCategory: [
        // Validate params
        validateObjectId('id'),

        // Validate body
        body('name')
            .optional()
            .trim()
            .isLength({ min: 3, max: 100 }).withMessage('Category name must be between 3 and 100 characters')
            .matches(/^[a-zA-Z0-9\s_-]+$/).withMessage('Category name contains invalid characters'),

        validateIconUrl('icon'),
        validateStatus('status.workflow', 'body'),

        body('description')
            .optional()
            .trim()
            .isLength({ max: 1000 }).withMessage('Description must not exceed 1000 characters')
            .matches(/^[a-zA-Z0-9\s.,!?'-]+$/).withMessage('Description contains invalid characters'),

        validateObjectId('parentId', 'body').optional(),
        validateTags('tags'),

        body('metadata.isRestricted')
            .optional()
            .isBoolean().withMessage('isRestricted must be a boolean'),

        body('metadata.priority')
            .optional()
            .isInt({ min: 1, max: 10 }).withMessage('Priority must be between 1 and 10')
            .toInt(),

        // Custom sanitization
        body('name').trim().escape(),
        body('description').trim().escape(),
        body('tags.*').trim().escape(),
        body('*').trim().escape()
    ],

    deleteCategory: [
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

    getCategories: [
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
        validateObjectId('parentId', 'query').optional(),

        query('search')
            .optional()
            .trim()
            .isLength({ max: 100 }).withMessage('Search query must not exceed 100 characters')
            .matches(/^[a-zA-Z0-9\s_-]+$/).withMessage('Search query contains invalid characters')
    ],

    searchCategories: [
        // Validate body
        body('query')
            .trim()
            .notEmpty().withMessage('Search query is required')
            .isLength({ max: 100 }).withMessage('Search query must not exceed 100 characters')
            .matches(/^[a-zA-Z0-9\s_-]+$/).withMessage('Search query contains invalid characters'),

        body('filters.status')
            .optional()
            .isIn(validStatuses).withMessage(`Status must be one of ${validStatuses.join(', ')}`),

        body('filters.parentId')
            .optional()
            .custom((value) => {
                if (!value || !isValidObjectId(value)) {
                    throw new AppError('parentId must be a valid ObjectId', 400);
                }
                return true;
            }).withMessage('parentId must be a valid ObjectId'),

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

    getTrendingCategories: [
        // Validate query parameters
        query('timeframe')
            .optional()
            .isIn(['7d', '30d', '90d']).withMessage('Invalid timeframe'),

        validateObjectId('parentId', 'query').optional(),

        query('limit')
            .optional()
            .isInt({ min: 1, max: 50 }).withMessage('Limit must be between 1 and 50')
            .toInt()
    ],

    bulkCreateCategories: [
        // Validate body
        body('categories')
            .isArray({ min: 1, max: 100 }).withMessage('Categories must be an array with 1-100 items')
            .custom((categories) => {
                return categories.every(category => {
                    if (!category.name || typeof category.name !== 'string') {
                        throw new AppError('Each category must have a valid name', 400);
                    }
                    return true;
                });
            }).withMessage('All categories must be valid'),

        body('categories.*.name')
            .trim()
            .isLength({ min: 3, max: 100 }).withMessage('Category name must be between 3 and 100 characters')
            .matches(/^[a-zA-Z0-9\s_-]+$/).withMessage('Category name contains invalid characters'),

        body('categories.*.icon')
            .optional()
            .isURL({ require_protocol: true }).withMessage('Icon must be a valid URL')
            .isLength({ max: 500 }).withMessage('Icon URL must not exceed 500 characters'),

        body('categories.*.description')
            .optional()
            .trim()
            .isLength({ max: 1000 }).withMessage('Description must not exceed 1000 characters')
            .matches(/^[a-zA-Z0-9\s.,!?'-]+$/).withMessage('Description contains invalid characters'),

        body('categories.*.parentId')
            .optional()
            .custom((value) => {
                if (!value || !isValidObjectId(value)) {
                    throw new AppError('parentId must be a valid ObjectId', 400);
                }
                return true;
            }).withMessage('parentId must be a valid ObjectId'),

        body('categories.*.tags')
            .optional()
            .isArray().withMessage('Tags must be an array')
            .custom((tags) => {
                if (tags.length > 20) {
                    throw new AppError('Maximum 20 tags allowed per category', 400);
                }
                return tags.every(tag => typeof tag === 'string' && tag.length <= 30 && /^[a-zA-Z0-9_-]+$/.test(tag));
            }).withMessage('Each tag must be a string, not exceed 30 characters, and contain only letters, numbers, underscores, or hyphens'),

        body('categories.*.metadata.isRestricted')
            .optional()
            .isBoolean().withMessage('isRestricted must be a boolean'),

        body('categories.*.metadata.priority')
            .optional()
            .isInt({ min: 1, max: 10 }).withMessage('Priority must be between 1 and 10')
            .toInt(),

        // Custom sanitization
        body('categories.*.name').trim().escape(),
        body('categories.*.description').trim().escape(),
        body('categories.*.tags.*').trim().escape(),
        body('*').trim().escape()
    ],

    bulkUpdateCategories: [
        // Validate body
        body('updates')
            .isArray({ min: 1, max: 100 }).withMessage('Updates must be an array with 1-100 items')
            .custom((updates) => {
                return updates.every(update => {
                    if (!update.id || !isValidObjectId(update.id)) {
                        throw new AppError('Each update must have a valid category ID', 400);
                    }
                    return true;
                });
            }).withMessage('All updates must have valid category IDs'),

        body('updates.*.id')
            .custom((value) => {
                if (!isValidObjectId(value)) {
                    throw new AppError('Category ID must be a valid ObjectId', 400);
                }
                return true;
            }).withMessage('Category ID must be a valid ObjectId'),

        body('updates.*.data.name')
            .optional()
            .trim()
            .isLength({ min: 3, max: 100 }).withMessage('Category name must be between 3 and 100 characters')
            .matches(/^[a-zA-Z0-9\s_-]+$/).withMessage('Category name contains invalid characters'),

        body('updates.*.data.icon')
            .optional()
            .isURL({ require_protocol: true }).withMessage('Icon must be a valid URL')
            .isLength({ max: 500 }).withMessage('Icon URL must not exceed 500 characters'),

        body('updates.*.data.description')
            .optional()
            .trim()
            .isLength({ max: 1000 }).withMessage('Description must not exceed 1000 characters')
            .matches(/^[a-zA-Z0-9\s.,!?'-]+$/).withMessage('Description contains invalid characters'),

        body('updates.*.data.parentId')
            .optional()
            .custom((value) => {
                if (!value || !isValidObjectId(value)) {
                    throw new AppError('parentId must be a valid ObjectId', 400);
                }
                return true;
            }).withMessage('parentId must be a valid ObjectId'),

        body('updates.*.data.status.workflow')
            .optional()
            .isIn(validStatuses).withMessage(`Status must be one of ${validStatuses.join(', ')}`),

        body('updates.*.data.tags')
            .optional()
            .isArray().withMessage('Tags must be an array')
            .custom((tags) => {
                if (tags.length > 20) {
                    throw new AppError('Maximum 20 tags allowed per category', 400);
                }
                return tags.every(tag => typeof tag === 'string' && tag.length <= 30 && /^[a-zA-Z0-9_-]+$/.test(tag));
            }).withMessage('Each tag must be a string, not exceed 30 characters, and contain only letters, numbers, underscores, or hyphens'),

        body('updates.*.data.metadata.isRestricted')
            .optional()
            .isBoolean().withMessage('isRestricted must be a boolean'),

        body('updates.*.data.metadata.priority')
            .optional()
            .isInt({ min: 1, max: 10 }).withMessage('Priority must be between 1 and 10')
            .toInt(),

        // Custom sanitization
        body('updates.*.data.name').trim().escape(),
        body('updates.*.data.description').trim().escape(),
        body('updates.*.data.tags.*').trim().escape(),
        body('*').trim().escape()
    ],

    getCategoryAnalytics: [
        // Validate params
        validateObjectId('id'),

        // Validate query
        query('timeframe')
            .optional()
            .isIn(['7d', '30d', '90d']).withMessage('Invalid timeframe')
    ],

    exportCategory: [
        // Validate params
        validateObjectId('id'),

        // Validate query
        query('format')
            .optional()
            .isIn(['json', 'csv']).withMessage('Format must be json or csv')
    ],

    getCategoryStats: [
        // Validate params
        validateObjectId('id')
    ],

    archiveCategory: [
        // Validate params
        validateObjectId('id')
    ],

    restoreCategory: [
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
            .isIn(['create', 'update', 'delete', 'archive', 'restore'])
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
            if (req.body.categories && req.body.categories.length > 50) {
                logger.warn(`High volume request detected: ${req.body.categories.length} categories`, {
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

export { categoryValidations, validate };