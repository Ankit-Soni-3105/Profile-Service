import { body, param, query, validationResult } from 'express-validator';
import { isValidObjectId } from 'mongoose';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';

// Valid license categories
const validCategories = ['professional', 'technical', 'academic', 'certification', 'other'];

// Valid license statuses
const validStatuses = ['pending', 'verified', 'expired', 'archived', 'draft'];

// Valid platforms for sharing
const validPlatforms = ['linkedin', 'twitter', 'email', 'direct'];

// Valid bulk operations
const validBulkOperations = ['delete', 'archive', 'publish', 'updateCategory', 'updateVisibility'];

// Valid visibilities
const validVisibilities = ['public', 'private'];

// Valid metrics for analytics
const validMetrics = ['basic', 'detailed'];

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

// Utility to validate category
const validateCategory = (field, location = 'body') => {
    return (location === 'body' ? body(field) : query(field))
        .optional()
        .isIn(validCategories)
        .withMessage(`Category must be one of ${validCategories.join(', ')}`);
};

// Utility to validate status
const validateStatus = (field, location = 'body') => {
    return (location === 'body' ? body(field) : query(field))
        .optional()
        .isIn(validStatuses)
        .withMessage(`Status must be one of ${validStatuses.join(', ')}`);
};

// Utility to validate date
const validateDate = (field, optional = false) => {
    return body(field)
    [optional ? 'optional' : 'notEmpty']()
        .isISO8601()
        .withMessage(`${field} must be a valid ISO 8601 date`)
        .toDate()
        .custom((value) => {
            if (field.includes('expirationDate') && new Date(value) < new Date()) {
                throw new AppError(`${field} must be a future date`, 400);
            }
            return true;
        });
};

// Utility to validate timeframe
const validateTimeframe = (field) => {
    return query(field)
        .optional()
        .isIn(['7d', '30d', '90d'])
        .withMessage(`Timeframe must be one of 7d, 30d, 90d`);
};

// Utility to validate metrics
const validateMetrics = (field) => {
    return query(field)
        .optional()
        .isIn(validMetrics)
        .withMessage(`Metrics must be one of ${validMetrics.join(', ')}`);
};

// Utility to validate platform
const validatePlatform = (field) => {
    return body(field)
        .notEmpty()
        .withMessage('Platform is required')
        .isIn(validPlatforms)
        .withMessage(`Platform must be one of ${validPlatforms.join(', ')}`);
};

// Utility to validate bulk operation
const validateBulkOperation = (field) => {
    return body(field)
        .notEmpty()
        .withMessage('Operation is required')
        .isIn(validBulkOperations)
        .withMessage(`Operation must be one of ${validBulkOperations.join(', ')}`);
};

// Validation rules for all endpoints
const licenseValidations = {
    createLicense: [
        // Validate params
        validateObjectId('userId'),

        // Validate body
        body('licenseDetails.title')
            .notEmpty()
            .withMessage('Title is required')
            .trim()
            .isLength({ max: 100 })
            .withMessage('Title must not exceed 100 characters')
            .matches(/^[a-zA-Z0-9\s.,-]+$/)
            .withMessage('Title contains invalid characters'),

        body('licenseDetails.description')
            .optional()
            .trim()
            .isLength({ max: 1000 })
            .withMessage('Description must not exceed 1000 characters')
            .matches(/^[a-zA-Z0-9\s.,!?'-]+$/)
            .withMessage('Description contains invalid characters'),

        validateCategory('licenseDetails.category'),
        validateObjectId('organization.organizationId', 'body').optional(),
        validateDate('duration.issueDate', false),
        validateDate('duration.expirationDate', false),
        validateStatus('status.workflow', 'body'),
        validateObjectId('templateId', 'body').optional(),

        body('licenseDetails.tags')
            .optional()
            .isArray()
            .withMessage('Tags must be an array')
            .custom((tags) => {
                if (tags.length > 10) {
                    throw new AppError('Maximum 10 tags allowed', 400);
                }
                return tags.every(tag => typeof tag === 'string' && tag.length <= 50 && /^[a-zA-Z0-9\s_-]+$/.test(tag));
            })
            .withMessage('Each tag must be a string, max 50 characters, with valid characters'),

        // Custom sanitization
        body('licenseDetails.title').trim().escape(),
        body('licenseDetails.description').trim().escape(),
        body('licenseDetails.category').trim().escape(),
        body('licenseDetails.tags.*').trim().escape(),
        body('*').trim().escape(),
    ],

    getLicenses: [
        // Validate params
        validateObjectId('userId'),

        // Validate query parameters
        query('page')
            .optional()
            .isInt({ min: 1 })
            .withMessage('Page must be a positive integer')
            .toInt(),

        query('limit')
            .optional()
            .isInt({ min: 1, max: 100 })
            .withMessage('Limit must be between 1 and 100')
            .toInt(),

        validateStatus('status', 'query'),
        validateCategory('category', 'query'),
        validateObjectId('templateId', 'query').optional(),

        query('search')
            .optional()
            .trim()
            .isLength({ max: 100 })
            .withMessage('Search query must not exceed 100 characters')
            .matches(/^[a-zA-Z0-9\s_-]+$/)
            .withMessage('Search query contains invalid characters'),

        query('sortBy')
            .optional()
            .isIn(['recent', 'oldest', 'title', 'popular', 'verified'])
            .withMessage('Invalid sortBy value'),

        query('tags')
            .optional()
            .trim()
            .custom((value) => {
                const tags = value.split(',').map(tag => tag.trim());
                return tags.every(tag => /^[a-zA-Z0-9\s_-]+$/.test(tag) && tag.length <= 50);
            })
            .withMessage('Tags must be valid strings, max 50 characters each'),

        query('startDate')
            .optional()
            .isISO8601()
            .withMessage('startDate must be a valid ISO 8601 date')
            .toDate(),

        query('endDate')
            .optional()
            .isISO8601()
            .withMessage('endDate must be a valid ISO 8601 date')
            .toDate(),

        query('includeAnalytics')
            .optional()
            .isBoolean()
            .withMessage('includeAnalytics must be a boolean')
            .toBoolean(),

        // Custom sanitization
        query('search').trim().escape(),
        query('category').trim().escape(),
        query('tags').trim().escape(),
    ],

    getLicenseById: [
        // Validate params
        validateObjectId('userId'),
        validateObjectId('id'),

        // Validate query parameters
        query('includeAnalytics')
            .optional()
            .isBoolean()
            .withMessage('includeAnalytics must be a boolean')
            .toBoolean(),

        query('includeVerification')
            .optional()
            .isBoolean()
            .withMessage('includeVerification must be a boolean')
            .toBoolean(),
    ],

    updateLicense: [
        // Validate params
        validateObjectId('userId'),
        validateObjectId('id'),

        // Validate body
        body('licenseDetails.title')
            .optional()
            .trim()
            .isLength({ max: 100 })
            .withMessage('Title must not exceed 100 characters')
            .matches(/^[a-zA-Z0-9\s.,-]+$/)
            .withMessage('Title contains invalid characters'),

        body('licenseDetails.description')
            .optional()
            .trim()
            .isLength({ max: 1000 })
            .withMessage('Description must not exceed 1000 characters')
            .matches(/^[a-zA-Z0-9\s.,!?'-]+$/)
            .withMessage('Description contains invalid characters'),

        validateCategory('licenseDetails.category'),
        validateObjectId('organization.organizationId', 'body').optional(),
        validateDate('duration.issueDate', true),
        validateDate('duration.expirationDate', true),
        validateStatus('status.workflow', 'body'),
        validateObjectId('templateId', 'body').optional(),

        body('licenseDetails.tags')
            .optional()
            .isArray()
            .withMessage('Tags must be an array')
            .custom((tags) => {
                if (tags.length > 10) {
                    throw new AppError('Maximum 10 tags allowed', 400);
                }
                return tags.every(tag => typeof tag === 'string' && tag.length <= 50 && /^[a-zA-Z0-9\s_-]+$/.test(tag));
            })
            .withMessage('Each tag must be a string, max 50 characters, with valid characters'),

        // Custom sanitization
        body('licenseDetails.title').trim().escape(),
        body('licenseDetails.description').trim().escape(),
        body('licenseDetails.category').trim().escape(),
        body('licenseDetails.tags.*').trim().escape(),
        body('*').trim().escape(),
    ],

    deleteLicense: [
        // Validate params
        validateObjectId('userId'),
        validateObjectId('id'),

        // Validate query
        query('permanent')
            .optional()
            .isBoolean()
            .withMessage('permanent must be a boolean')
            .toBoolean(),
    ],

    bulkOperations: [
        // Validate params
        validateObjectId('userId'),

        // Validate body
        validateBulkOperation('operation'),
        body('licenseIds')
            .isArray({ min: 1, max: 100 })
            .withMessage('licenseIds must be an array with 1-100 items')
            .custom((ids) => ids.every(id => isValidObjectId(id)))
            .withMessage('All licenseIds must be valid ObjectIds'),

        body('data.category')
            .optional()
            .isIn(validCategories)
            .withMessage(`Category must be one of ${validCategories.join(', ')}`),

        body('data.visibility')
            .optional()
            .isIn(validVisibilities)
            .withMessage(`Visibility must be one of ${validVisibilities.join(', ')}`),

        // Custom sanitization
        body('data.category').trim().escape(),
        body('data.visibility').trim().escape(),
        body('*').trim().escape(),
    ],

    getAnalytics: [
        // Validate params
        validateObjectId('userId'),
        validateObjectId('id'),

        // Validate query
        validateTimeframe('timeframe'),
        validateMetrics('metrics'),
    ],

    verifyLicense: [
        // Validate params
        validateObjectId('userId'),
        validateObjectId('id'),
    ],

    uploadMedia: [
        // Validate params
        validateObjectId('userId'),
        validateObjectId('id'),

        // Validate files
        body('files')
            .custom((value, { req }) => {
                if (!req.files || req.files.length === 0) {
                    throw new AppError('At least one file is required', 400);
                }
                if (req.files.length > 5) {
                    throw new AppError('Maximum 5 files allowed', 400);
                }
                return req.files.every(file => {
                    const allowedTypes = ['image/jpeg', 'image/png', 'application/pdf'];
                    if (!allowedTypes.includes(file.mimetype)) {
                        throw new AppError('Invalid file type. Only JPEG, PNG, and PDF are allowed', 400);
                    }
                    if (file.size > 5 * 1024 * 1024) { // 5MB limit
                        throw new AppError('File size must not exceed 5MB', 400);
                    }
                    return true;
                });
            })
            .withMessage('Invalid file upload'),
    ],

    shareLicense: [
        // Validate params
        validateObjectId('userId'),
        validateObjectId('id'),

        // Validate body
        validatePlatform('platform'),
    ],

    endorseLicense: [
        // Validate params
        validateObjectId('userId'),
        validateObjectId('id'),
    ],

    getVerificationStatus: [
        // Validate params
        validateObjectId('userId'),
        validateObjectId('id'),
    ],

    getTrendingLicenses: [
        // Validate query
        validateTimeframe('timeframe'),
        validateCategory('category', 'query'),
        query('limit')
            .optional()
            .isInt({ min: 1, max: 50 })
            .withMessage('Limit must be between 1 and 50')
            .toInt(),

        // Custom sanitization
        query('category').trim().escape(),
    ],

    getLicensesByCategory: [
        // Validate params
        validateCategory('category', 'params'),

        // Validate query
        query('page')
            .optional()
            .isInt({ min: 1 })
            .withMessage('Page must be a positive integer')
            .toInt(),

        query('limit')
            .optional()
            .isInt({ min: 1, max: 100 })
            .withMessage('Limit must be between 1 and 100')
            .toInt(),

        query('sortBy')
            .optional()
            .isIn(['recent', 'oldest', 'title', 'popular', 'verified'])
            .withMessage('Invalid sortBy value'),

        // Custom sanitization
        query('category').trim().escape(),
    ],

    searchLicenses: [
        // Validate query
        query('query')
            .trim()
            .notEmpty()
            .withMessage('Search query is required')
            .isLength({ max: 100 })
            .withMessage('Search query must not exceed 100 characters')
            .matches(/^[a-zA-Z0-9\s_-]+$/)
            .withMessage('Search query contains invalid characters'),

        query('filters.status')
            .optional()
            .isIn(validStatuses)
            .withMessage(`Status must be one of ${validStatuses.join(', ')}`),

        validateCategory('filters.category', 'query'),
        validateObjectId('filters.templateId', 'query').optional(),

        query('filters.tags')
            .optional()
            .trim()
            .custom((value) => {
                const tags = value.split(',').map(tag => tag.trim());
                return tags.every(tag => /^[a-zA-Z0-9\s_-]+$/.test(tag) && tag.length <= 50);
            })
            .withMessage('Tags must be valid strings, max 50 characters each'),

        query('page')
            .optional()
            .isInt({ min: 1 })
            .withMessage('Page must be a positive integer')
            .toInt(),

        query('limit')
            .optional()
            .isInt({ min: 1, max: 100 })
            .withMessage('Limit must be between 1 and 100')
            .toInt(),

        // Custom sanitization
        query('query').trim().escape(),
        query('filters.category').trim().escape(),
        query('filters.tags').trim().escape(),
    ],
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
                    userId: req.user?.id,
                });
                return next(new AppError(`Validation failed: ${errorMessages}`, 400));
            }

            // Additional validation for high-scale systems
            if (req.body.licenseIds && req.body.licenseIds.length > 50) {
                logger.warn(`High volume bulk operation detected: ${req.body.licenseIds.length} licenses`, {
                    userId: req.user?.id,
                    path: req.originalUrl,
                });
            }

            next();
        } catch (error) {
            logger.error('Validation middleware error:', {
                error: error.message,
                stack: error.stack,
                path: req.originalUrl,
                userId: req.user?.id,
            });
            return next(new AppError('Validation processing error', 500));
        }
    };
};

// Legacy validation function for compatibility
const validateLicense = (data) => {
    const errors = [];

    if (!data.licenseDetails?.title) {
        errors.push('Title is required');
    } else if (data.licenseDetails.title.length > 100) {
        errors.push('Title must not exceed 100 characters');
    } else if (!/^[a-zA-Z0-9\s.,-]+$/.test(data.licenseDetails.title)) {
        errors.push('Title contains invalid characters');
    }

    if (data.licenseDetails?.description && data.licenseDetails.description.length > 1000) {
        errors.push('Description must not exceed 1000 characters');
    } else if (data.licenseDetails?.description && !/^[a-zA-Z0-9\s.,!?'-]+$/.test(data.licenseDetails.description)) {
        errors.push('Description contains invalid characters');
    }

    if (!data.licenseDetails?.category || !validCategories.includes(data.licenseDetails.category)) {
        errors.push(`Category must be one of ${validCategories.join(', ')}`);
    }

    if (data.organization?.organizationId && !isValidObjectId(data.organization.organizationId)) {
        errors.push('organizationId must be a valid ObjectId');
    }

    if (!data.duration?.issueDate || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.*Z$/.test(data.duration.issueDate)) {
        errors.push('issueDate must be a valid ISO 8601 date');
    }

    if (!data.duration?.expirationDate || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.*Z$/.test(data.duration.expirationDate)) {
        errors.push('expirationDate must be a valid ISO 8601 date');
    } else if (new Date(data.duration.expirationDate) < new Date()) {
        errors.push('expirationDate must be a future date');
    }

    if (data.status?.workflow && !validStatuses.includes(data.status.workflow)) {
        errors.push(`Status must be one of ${validStatuses.join(', ')}`);
    }

    if (data.templateId && !isValidObjectId(data.templateId)) {
        errors.push('templateId must be a valid ObjectId');
    }

    if (data.licenseDetails?.tags) {
        if (!Array.isArray(data.licenseDetails.tags)) {
            errors.push('Tags must be an array');
        } else if (data.licenseDetails.tags.length > 10) {
            errors.push('Maximum 10 tags allowed');
        } else if (!data.licenseDetails.tags.every(tag => typeof tag === 'string' && tag.length <= 50 && /^[a-zA-Z0-9\s_-]+$/.test(tag))) {
            errors.push('Each tag must be a string, max 50 characters, with valid characters');
        }
    }

    return errors.length > 0 ? { valid: false, message: errors.join(', ') } : { valid: true };
};

// Legacy sanitization function for compatibility
const sanitizeInput = (data) => {
    const sanitized = { ...data };

    if (sanitized.licenseDetails?.title) {
        sanitized.licenseDetails.title = sanitized.licenseDetails.title.trim();
    }
    if (sanitized.licenseDetails?.description) {
        sanitized.licenseDetails.description = sanitized.licenseDetails.description.trim();
    }
    if (sanitized.licenseDetails?.category) {
        sanitized.licenseDetails.category = sanitized.licenseDetails.category.trim();
    }
    if (sanitized.licenseDetails?.tags) {
        sanitized.licenseDetails.tags = sanitized.licenseDetails.tags.map(tag => tag.trim());
    }

    return sanitized;
};

export { licenseValidations, validate, validateLicense, sanitizeInput };