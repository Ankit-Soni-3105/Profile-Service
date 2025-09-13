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

// Utility to validate education status
const validStatuses = ['draft', 'pending', 'verified', 'rejected', 'archived'];

const validateStatus = (field, location = 'body') => {
    return (location === 'body' ? body(field) : query(field))
        .optional()
        .isIn(validStatuses).withMessage(`${field} must be one of ${validStatuses.join(', ')}`);
};

// Utility to validate date
const validateDate = (field, optional = true) => {
    return body(field)
    [optional ? 'optional' : 'notEmpty']()
        .isISO8601().withMessage(`${field} must be a valid ISO 8601 date`)
        .toDate()
        .custom((value, { req }) => {
            if (field === 'endDate' && req.body.startDate && value && new Date(value) < new Date(req.body.startDate)) {
                throw new AppError('endDate must be after startDate', 400);
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
const validActions = ['create', 'update', 'delete', 'archive', 'restore', 'media_upload'];

const validateAction = (field) => {
    return query(field)
        .optional()
        .isIn(validActions).withMessage(`Action must be one of ${validActions.join(', ')}`);
};

const educationValidations = {
    createEducation: [
        // Validate body
        body('title')
            .trim()
            .notEmpty().withMessage('Title is required')
            .isLength({ min: 3, max: 100 }).withMessage('Title must be between 3 and 100 characters')
            .matches(/^[a-zA-Z0-9\s.,-]+$/)
            .withMessage('Title contains invalid characters'),

        body('institution')
            .trim()
            .notEmpty().withMessage('Institution is required')
            .isLength({ min: 3, max: 150 }).withMessage('Institution must be between 3 and 150 characters')
            .matches(/^[a-zA-Z0-9\s.,-]+$/)
            .withMessage('Institution contains invalid characters'),

        body('description')
            .optional()
            .trim()
            .isLength({ max: 2000 }).withMessage('Description must not exceed 2000 characters')
            .matches(/^[a-zA-Z0-9\s.,!?'-]+$/)
            .withMessage('Description contains invalid characters'),

        validateObjectId('categoryId', 'body').optional(),
        validateStatus('status.workflow', 'body'),

        validateDate('startDate', false),
        validateDate('endDate', true),

        // Custom sanitization
        body('title').trim().escape(),
        body('institution').trim().escape(),
        body('description').trim().escape(),
        body('*').trim().escape()
    ],

    getEducationById: [
        // Validate params
        validateObjectId('id')
    ],

    updateEducation: [
        // Validate params
        validateObjectId('id'),

        // Validate body
        body('title')
            .optional()
            .trim()
            .isLength({ min: 3, max: 100 }).withMessage('Title must be between 3 and 100 characters')
            .matches(/^[a-zA-Z0-9\s.,-]+$/)
            .withMessage('Title contains invalid characters'),

        body('institution')
            .optional()
            .trim()
            .isLength({ min: 3, max: 150 }).withMessage('Institution must be between 3 and 150 characters')
            .matches(/^[a-zA-Z0-9\s.,-]+$/)
            .withMessage('Institution contains invalid characters'),

        body('description')
            .optional()
            .trim()
            .isLength({ max: 2000 }).withMessage('Description must not exceed 2000 characters')
            .matches(/^[a-zA-Z0-9\s.,!?'-]+$/)
            .withMessage('Description contains invalid characters'),

        validateObjectId('categoryId', 'body').optional(),
        validateStatus('status.workflow', 'body'),

        validateDate('startDate', true),
        validateDate('endDate', true),

        // Custom sanitization
        body('title').trim().escape(),
        body('institution').trim().escape(),
        body('description').trim().escape(),
        body('*').trim().escape()
    ],

    deleteEducation: [
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
            }).withMessage('Invalid file upload')
    ],

    getEducations: [
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

        validateObjectId('categoryId', 'query').optional(),

        query('search')
            .optional()
            .trim()
            .isLength({ max: 100 }).withMessage('Search query must not exceed 100 characters')
            .matches(/^[a-zA-Z0-9\s_-]+$/)
            .withMessage('Search query contains invalid characters'),

        query('sortBy')
            .optional()
            .isIn(['recent', 'title', 'popularity']).withMessage('Invalid sortBy value'),

        // Custom sanitization
        query('search').trim().escape()
    ],

    searchEducations: [
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

        validateObjectId('filters.categoryId', 'body').optional(),

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
        body('filters.*').trim().escape()
    ],

    getTrendingEducations: [
        // Validate query parameters
        query('timeframe')
            .optional()
            .isIn(['7d', '30d', '90d']).withMessage('Invalid timeframe'),

        validateObjectId('categoryId', 'query').optional(),

        query('limit')
            .optional()
            .isInt({ min: 1, max: 50 }).withMessage('Limit must be between 1 and 50')
            .toInt()
    ],

    bulkCreateEducations: [
        // Validate body
        body('educations')
            .isArray({ min: 1, max: 50 }).withMessage('Educations must be an array with 1-50 items'),

        body('educations.*.title')
            .trim()
            .notEmpty().withMessage('Title is required for each education')
            .isLength({ min: 3, max: 100 }).withMessage('Title must be between 3 and 100 characters')
            .matches(/^[a-zA-Z0-9\s.,-]+$/)
            .withMessage('Title contains invalid characters'),

        body('educations.*.institution')
            .trim()
            .notEmpty().withMessage('Institution is required for each education')
            .isLength({ min: 3, max: 150 }).withMessage('Institution must be between 3 and 150 characters')
            .matches(/^[a-zA-Z0-9\s.,-]+$/)
            .withMessage('Institution contains invalid characters'),

        body('educations.*.description')
            .optional()
            .trim()
            .isLength({ max: 2000 }).withMessage('Description must not exceed 2000 characters')
            .matches(/^[a-zA-Z0-9\s.,!?'-]+$/)
            .withMessage('Description contains invalid characters'),

        validateObjectId('educations.*.categoryId', 'body').optional(),
        validateStatus('educations.*.status.workflow', 'body'),

        validateDate('educations.*.startDate', false),
        validateDate('educations.*.endDate', true),

        // Custom sanitization
        body('educations.*.title').trim().escape(),
        body('educations.*.institution').trim().escape(),
        body('educations.*.description').trim().escape(),
        body('educations.*.*').trim().escape()
    ],

    bulkUpdateEducations: [
        // Validate body
        body('updates')
            .isArray({ min: 1, max: 50 }).withMessage('Updates must be an array with 1-50 items'),

        validateObjectId('updates.*.id', 'body'),

        body('updates.*.data.title')
            .optional()
            .trim()
            .isLength({ min: 3, max: 100 }).withMessage('Title must be between 3 and 100 characters')
            .matches(/^[a-zA-Z0-9\s.,-]+$/)
            .withMessage('Title contains invalid characters'),

        body('updates.*.data.institution')
            .optional()
            .trim()
            .isLength({ min: 3, max: 150 }).withMessage('Institution must be between 3 and 150 characters')
            .matches(/^[a-zA-Z0-9\s.,-]+$/)
            .withMessage('Institution contains invalid characters'),

        body('updates.*.data.description')
            .optional()
            .trim()
            .isLength({ max: 2000 }).withMessage('Description must not exceed 2000 characters')
            .matches(/^[a-zA-Z0-9\s.,!?'-]+$/)
            .withMessage('Description contains invalid characters'),

        validateObjectId('updates.*.data.categoryId', 'body').optional(),
        validateStatus('updates.*.data.status.workflow', 'body'),

        validateDate('updates.*.data.startDate', true),
        validateDate('updates.*.data.endDate', true),

        // Custom sanitization
        body('updates.*.data.title').trim().escape(),
        body('updates.*.data.institution').trim().escape(),
        body('updates.*.data.description').trim().escape(),
        body('updates.*.data.*').trim().escape()
    ],

    getEducationAnalytics: [
        // Validate params
        validateObjectId('id'),

        // Validate query
        query('timeframe')
            .optional()
            .isIn(['7d', '30d', '90d']).withMessage('Invalid timeframe')
    ],

    exportEducation: [
        // Validate params
        validateObjectId('id'),

        // Validate query
        validateExportFormat('format')
    ],

    getEducationStats: [
        // Validate params
        validateObjectId('id')
    ],

    archiveEducation: [
        // Validate params
        validateObjectId('id')
    ],

    restoreEducation: [
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
            if (req.body.educations && req.body.educations.length > 20) {
                logger.warn(`High volume request detected: ${req.body.educations.length} educations`, {
                    userId: req.user?.id,
                    path: req.originalUrl
                });
            }
            if (req.body.updates && req.body.updates.length > 20) {
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
const validateEducation = (data, isUpdate = false) => {
    const errors = [];

    if (!isUpdate || data.title) {
        if (!data.title) errors.push('Title is required');
        else if (typeof data.title !== 'string' || data.title.length < 3 || data.title.length > 100) {
            errors.push('Title must be between 3 and 100 characters');
        } else if (!/^[a-zA-Z0-9\s.,-]+$/.test(data.title)) {
            errors.push('Title contains invalid characters');
        }
    }

    if (!isUpdate || data.institution) {
        if (!data.institution) errors.push('Institution is required');
        else if (typeof data.institution !== 'string' || data.institution.length < 3 || data.institution.length > 150) {
            errors.push('Institution must be between 3 and 150 characters');
        } else if (!/^[a-zA-Z0-9\s.,-]+$/.test(data.institution)) {
            errors.push('Institution contains invalid characters');
        }
    }

    if (data.description && (typeof data.description !== 'string' || data.description.length > 2000)) {
        errors.push('Description must not exceed 2000 characters');
    }

    if (data.categoryId && !isValidObjectId(data.categoryId)) {
        errors.push('Invalid categoryId');
    }

    if (data.status?.workflow && !validStatuses.includes(data.status.workflow)) {
        errors.push(`Status must be one of ${validStatuses.join(', ')}`);
    }

    if (!isUpdate || data.startDate) {
        if (!data.startDate || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.*Z$/.test(data.startDate)) {
            errors.push('startDate must be a valid ISO 8601 date');
        }
    }

    if (data.endDate) {
        if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.*Z$/.test(data.endDate)) {
            errors.push('endDate must be a valid ISO 8601 date');
        } else if (data.startDate && new Date(data.endDate) < new Date(data.startDate)) {
            errors.push('endDate must be after startDate');
        }
    }

    return errors.length > 0 ? { valid: false, message: errors.join(', ') } : { valid: true };
};

const validateBulkEducation = (educations) => {
    if (!Array.isArray(educations) || educations.length === 0 || educations.length > 50) {
        return { valid: false, message: 'Educations must be an array with 1-50 items' };
    }

    const errors = [];
    educations.forEach((education, index) => {
        const validation = validateEducation(education);
        if (!validation.valid) {
            errors.push(`Education at index ${index}: ${validation.message}`);
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
        if (filters.categoryId && !isValidObjectId(filters.categoryId)) {
            errors.push('Invalid categoryId in filters');
        }
    }

    return errors.length > 0 ? { valid: false, message: errors.join(', ') } : { valid: true };
};

export { educationValidations, validate, validateEducation, validateBulkEducation, validateSearch };