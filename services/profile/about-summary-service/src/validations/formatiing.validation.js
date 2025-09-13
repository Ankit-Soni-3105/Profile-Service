import { body, param, query, ValidationChain } from 'express-validator';
import { isValidObjectId } from 'mongoose';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { validationResult } from 'express-validator';

// Utility function to validate ObjectId
// Enhanced with explicit type checking and null/undefined handling
// Uses bail() for early exit to optimize performance
const validateObjectId = (
    field,
    location = 'params'
) => {
    return (location === 'params' ? param(field) : body(field))
        .exists({ checkFalsy: true }).withMessage(`${field} is required`)
        .isString().withMessage(`${field} must be a string`)
        .custom((value) => {
            if (!isValidObjectId(value)) {
                throw new AppError(`${field} must be a valid ObjectId`, 400);
            }
            return true;
        })
        .withMessage(`${field} must be a valid ObjectId`)
        .bail();
};

// Allowed format types (consistent with controller's getAllowedFormatTypes)
const ALLOWED_FORMAT_TYPES = ['markdown', 'html', 'custom'];

// Allowed options per format type (consistent with controller's validateOptions)
const ALLOWED_OPTIONS = {
    markdown: ['renderer', 'sanitize'],
    html: ['sanitize', 'allowedTags'],
    custom: ['styleName', 'parameters']
};

// Enhanced validation rules for formatting operations
// Optimized for scalability with millions of users:
// - Fail-fast with .bail()
// - No database queries in validations
// - Strong sanitization to prevent XSS and injection
// - O(1) time complexity for all checks
const formattingValidations = {
    /**
     * Validations for applyFormatting endpoint
     * PATCH /api/v1/formatting/:userId/:summaryId
     */
    applyFormatting: [
        // Validate path parameters
        validateObjectId('userId'),
        validateObjectId('summaryId'),

        // Validate body fields
        body('formatType')
            .exists({ checkFalsy: true }).withMessage('formatType is required')
            .isString().withMessage('formatType must be a string')
            .trim()
            .notEmpty().withMessage('formatType cannot be empty')
            .isIn(ALLOWED_FORMAT_TYPES).withMessage(`formatType must be one of: ${ALLOWED_FORMAT_TYPES.join(', ')}`)
            .bail(),

        body('content')
            .exists({ checkFalsy: true }).withMessage('content is required')
            .isString().withMessage('content must be a string')
            .trim()
            .notEmpty().withMessage('content cannot be empty after trimming')
            .isLength({ min: 1, max: 10000 }).withMessage('content must be between 1 and 10,000 characters')
            .bail()
            .custom((value) => {
                // Prevent control characters except newline/tab
                if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(value)) {
                    throw new AppError('content contains invalid control characters', 400);
                }
                return true;
            })
            .escape(),

        body('options')
            .optional({ nullable: true })
            .isObject().withMessage('options must be an object')
            .bail()
            .custom((value, { req }) => {
                if (value == null) return true;
                if (typeof value !== 'object' || value === null) {
                    throw new AppError('options must be a non-null object', 400);
                }
                const formatType = req.body.formatType;
                if (!formatType) return true; // Will fail at formatType validation
                const allowedKeys = ALLOWED_OPTIONS[formatType] || [];
                for (const key of Object.keys(value)) {
                    if (!allowedKeys.includes(key)) {
                        throw new AppError(`Invalid option '${key}' for formatType '${formatType}'`, 400);
                    }
                }
                // Additional validation for specific options
                if (formatType === 'html' && value.allowedTags) {
                    if (!Array.isArray(value.allowedTags)) {
                        throw new AppError('options.allowedTags must be an array', 400);
                    }
                    if (value.allowedTags.some(tag => typeof tag !== 'string' || tag.length > 50)) {
                        throw new AppError('options.allowedTags must contain valid strings (max 50 characters each)', 400);
                    }
                }
                if (formatType === 'custom' && value.parameters) {
                    if (typeof value.parameters !== 'object' || value.parameters === null) {
                        throw new AppError('options.parameters must be a non-null object', 400);
                    }
                }
                return true;
            }).withMessage('options must contain valid keys for the specified formatType'),

        // Global body sanitizer
        body('*').trim().escape()
    ],

    /**
     * Validations for previewFormatting endpoint
     * POST /api/v1/formatting/:userId/:summaryId/preview
     */
    previewFormatting: [
        // Validate path parameters
        validateObjectId('userId'),
        validateObjectId('summaryId'),

        // Validate body fields (same as applyFormatting)
        body('formatType')
            .exists({ checkFalsy: true }).withMessage('formatType is required')
            .isString().withMessage('formatType must be a string')
            .trim()
            .notEmpty().withMessage('formatType cannot be empty')
            .isIn(ALLOWED_FORMAT_TYPES).withMessage(`formatType must be one of: ${ALLOWED_FORMAT_TYPES.join(', ')}`)
            .bail(),

        body('content')
            .exists({ checkFalsy: true }).withMessage('content is required')
            .isString().withMessage('content must be a string')
            .trim()
            .notEmpty().withMessage('content cannot be empty after trimming')
            .isLength({ min: 1, max: 10000 }).withMessage('content must be between 1 and 10,000 characters')
            .bail()
            .custom((value) => {
                if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(value)) {
                    throw new AppError('content contains invalid control characters', 400);
                }
                return true;
            })
            .escape(),

        body('options')
            .optional({ nullable: true })
            .isObject().withMessage('options must be an object')
            .bail()
            .custom((value, { req }) => {
                if (value == null) return true;
                if (typeof value !== 'object' || value === null) {
                    throw new AppError('options must be a non-null object', 400);
                }
                const formatType = req.body.formatType;
                if (!formatType) return true;
                const allowedKeys = ALLOWED_OPTIONS[formatType] || [];
                for (const key of Object.keys(value)) {
                    if (!allowedKeys.includes(key)) {
                        throw new AppError(`Invalid option '${key}' for formatType '${formatType}'`, 400);
                    }
                }
                if (formatType === 'html' && value.allowedTags) {
                    if (!Array.isArray(value.allowedTags)) {
                        throw new AppError('options.allowedTags must be an array', 400);
                    }
                    if (value.allowedTags.some(tag => typeof tag !== 'string' || tag.length > 50)) {
                        throw new AppError('options.allowedTags must contain valid strings (max 50 characters each)', 400);
                    }
                }
                if (formatType === 'custom' && value.parameters) {
                    if (typeof value.parameters !== 'object' || value.parameters === null) {
                        throw new AppError('options.parameters must be a non-null object', 400);
                    }
                }
                return true;
            }).withMessage('options must contain valid keys for the specified formatType'),

        // Global body sanitizer
        body('*').trim().escape()
    ],

    /**
     * Validations for getFormattingStyles endpoint
     * GET /api/v1/formatting/:userId/:summaryId/styles
     */
    getFormattingStyles: [
        validateObjectId('userId'),
        validateObjectId('summaryId'),
    ],

    /**
     * Validations for bulkApplyFormatting endpoint
     * POST /api/v1/formatting/:userId/bulk
     */
    bulkApplyFormatting: [
        // Validate path parameters
        validateObjectId('userId'),

        // Validate body fields
        body('summaryIds')
            .exists({ checkFalsy: true }).withMessage('summaryIds is required')
            .isArray({ min: 1, max: 100 }).withMessage('summaryIds must be an array with 1-100 items')
            .bail()
            .custom((value) => {
                if (!value.every(id => isValidObjectId(id))) {
                    throw new AppError('All summaryIds must be valid ObjectIds', 400);
                }
                return true;
            }).withMessage('All summaryIds must be valid ObjectIds'),

        body('formatType')
            .exists({ checkFalsy: true }).withMessage('formatType is required')
            .isString().withMessage('formatType must be a string')
            .trim()
            .notEmpty().withMessage('formatType cannot be empty')
            .isIn(ALLOWED_FORMAT_TYPES).withMessage(`formatType must be one of: ${ALLOWED_FORMAT_TYPES.join(', ')}`)
            .bail(),

        body('options')
            .optional({ nullable: true })
            .isObject().withMessage('options must be an object')
            .bail()
            .custom((value, { req }) => {
                if (value == null) return true;
                if (typeof value !== 'object' || value === null) {
                    throw new AppError('options must be a non-null object', 400);
                }
                const formatType = req.body.formatType;
                if (!formatType) return true;
                const allowedKeys = ALLOWED_OPTIONS[formatType] || [];
                for (const key of Object.keys(value)) {
                    if (!allowedKeys.includes(key)) {
                        throw new AppError(`Invalid option '${key}' for formatType '${formatType}'`, 400);
                    }
                }
                if (formatType === 'html' && value.allowedTags) {
                    if (!Array.isArray(value.allowedTags)) {
                        throw new AppError('options.allowedTags must be an array', 400);
                    }
                    if (value.allowedTags.some(tag => typeof tag !== 'string' || tag.length > 50)) {
                        throw new AppError('options.allowedTags must contain valid strings (max 50 characters each)', 400);
                    }
                }
                if (formatType === 'custom' && value.parameters) {
                    if (typeof value.parameters !== 'object' || value.parameters === null) {
                        throw new AppError('options.parameters must be a non-null object', 400);
                    }
                }
                return true;
            }).withMessage('options must contain valid keys for the specified formatType'),

        // Global body sanitizer
        body('*').trim().escape()
    ],

    /**
     * Validations for getFormattingHistory endpoint
     * GET /api/v1/formatting/:userId/:summaryId/history
     */
    getFormattingHistory: [
        validateObjectId('userId'),
        validateObjectId('summaryId'),

        query('page')
            .optional()
            .isInt({ min: 1, max: 1000 }).withMessage('Page must be an integer between 1 and 1000')
            .toInt(),

        query('limit')
            .optional()
            .isInt({ min: 1, max: 100 }).withMessage('Limit must be an integer between 1 and 100')
            .toInt(),

        query('*').trim().escape()
    ],

    /**
     * Validations for revertFormatting endpoint
     * POST /api/v1/formatting/:userId/:summaryId/revert
     */
    revertFormatting: [
        validateObjectId('userId'),
        validateObjectId('summaryId'),

        body('formatId')
            .exists({ checkFalsy: true }).withMessage('formatId is required')
            .isString().withMessage('formatId must be a string')
            .custom((value) => {
                if (!isValidObjectId(value)) {
                    throw new AppError('formatId must be a valid ObjectId', 400);
                }
                return true;
            })
            .withMessage('formatId must be a valid ObjectId')
            .bail(),

        body('*').trim().escape()
    ]
};

/**
 * Validation middleware to handle errors
 * Optimized for high throughput with parallel validation execution
 * Detailed logging for monitoring in production
 */
const validate = (validations) => {
    return async (req, res, next) => {
        try {
            await Promise.all(validations.map(validation => validation.run(req)));

            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                logger.warn(`Validation failed for request ${req.method} ${req.path}: ${JSON.stringify(errors.array())}`);
                const errorMessages = errors.array().map(e => e.msg).join(', ');
                return next(new AppError(`Validation failed: ${errorMessages}`, 400));
            }

            next();
        } catch (error) {
            logger.error(`Validation middleware error for request ${req.method} ${req.path}:`, error);
            return next(new AppError('Validation processing error', 500));
        }
    };
};

/**
 * Manual validation function for formatting input
 * Used in controller for runtime checks
 * Matches controller's validateOptions and getAllowedFormatTypes
 */
const validateFormattingInput = ({ formatType, content, options }) => {
    if (formatType !== undefined) {
        if (typeof formatType !== 'string') {
            return { valid: false, message: 'formatType must be a string' };
        }
        if (!ALLOWED_FORMAT_TYPES.includes(formatType)) {
            return { valid: false, message: `formatType must be one of: ${ALLOWED_FORMAT_TYPES.join(', ')}` };
        }
    }

    if (content !== undefined) {
        if (typeof content !== 'string') {
            return { valid: false, message: 'content must be a string' };
        }
        if (content.length > 10000) {
            return { valid: false, message: 'content must not exceed 10,000 characters' };
        }
        if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(content)) {
            return { valid: false, message: 'content contains invalid control characters' };
        }
    }

    if (options !== undefined) {
        if (typeof options !== 'object' || options === null) {
            return { valid: false, message: 'options must be a non-null object' };
        }
        if (formatType) {
            const allowedKeys = ALLOWED_OPTIONS[formatType] || [];
            for (const key of Object.keys(options)) {
                if (!allowedKeys.includes(key)) {
                    return { valid: false, message: `Invalid option '${key}' for formatType '${formatType}'` };
                }
            }
            if (formatType === 'html' && options.allowedTags) {
                if (!Array.isArray(options.allowedTags)) {
                    return { valid: false, message: 'options.allowedTags must be an array' };
                }
                if (options.allowedTags.some(tag => typeof tag !== 'string' || tag.length > 50)) {
                    return { valid: false, message: 'options.allowedTags must contain valid strings (max 50 characters each)' };
                }
            }
            if (formatType === 'custom' && options.parameters) {
                if (typeof options.parameters !== 'object' || options.parameters === null) {
                    return { valid: false, message: 'options.parameters must be a non-null object' };
                }
            }
        }
    }

    return { valid: true, message: '' };
};

export { formattingValidations, validate, validateFormattingInput };