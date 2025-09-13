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

// Utility to validate certification status
const validStatuses = ['draft', 'pending', 'verified', 'rejected', 'archived'];

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
            if (tags.length > 15) {
                throw new AppError('Maximum 15 tags allowed', 400);
            }
            return tags.every(tag => typeof tag === 'string' && tag.length <= 30 && /^[a-zA-Z0-9_-]+$/.test(tag));
        }).withMessage('Each tag must be a string, not exceed 30 characters, and contain only letters, numbers, underscores, or hyphens');
};

// Utility to validate skills array
const validateSkills = (field) => {
    return body(field)
        .optional()
        .isArray().withMessage(`${field} must be an array`)
        .custom((skills) => {
            if (skills.length > 20) {
                throw new AppError('Maximum 20 skills allowed', 400);
            }
            return skills.every(skill => typeof skill === 'string' && skill.length <= 50 && /^[a-zA-Z0-9\s_-]+$/.test(skill));
        }).withMessage('Each skill must be a string, not exceed 50 characters, and contain only letters, numbers, spaces, underscores, or hyphens');
};

// Utility to validate date
const validateDate = (field, optional = true) => {
    return body(field)
    [optional ? 'optional' : 'notEmpty']()
        .isISO8601().withMessage(`${field} must be a valid ISO 8601 date`)
        .toDate();
};

// Utility to validate platform
const validPlatforms = ['linkedin', 'twitter', 'email', 'portfolio'];

const validatePlatform = (field) => {
    return body(field)
        .notEmpty().withMessage(`${field} is required`)
        .isIn(validPlatforms).withMessage(`${field} must be one of ${validPlatforms.join(', ')}`);
};

const certificationValidations = {
    createCertification: [
        // Validate params
        validateObjectId('userId'),

        // Validate body
        body('badgeDetails.title')
            .trim()
            .notEmpty().withMessage('Certification title is required')
            .isLength({ min: 3, max: 100 }).withMessage('Title must be between 3 and 100 characters')
            .matches(/^[a-zA-Z0-9\s_-]+$/).withMessage('Title contains invalid characters'),

        body('badgeDetails.description')
            .optional()
            .trim()
            .isLength({ max: 2000 }).withMessage('Description must not exceed 2000 characters')
            .matches(/^[a-zA-Z0-9\s.,!?'-]+$/).withMessage('Description contains invalid characters'),

        body('badgeDetails.category')
            .optional()
            .trim()
            .isLength({ max: 50 }).withMessage('Category must not exceed 50 characters')
            .matches(/^[a-zA-Z0-9\s_-]+$/).withMessage('Category contains invalid characters'),

        validateTags('badgeDetails.tags'),
        validateSkills('badgeDetails.skills'),

        validateObjectId('organization.organizationId', 'body').optional(),
        validateObjectId('templateId', 'body').optional(),

        validateDate('duration.issueDate', false),
        validateDate('duration.expirationDate', true),

        body('settings.autoBackup')
            .optional()
            .isBoolean().withMessage('autoBackup must be a boolean')
            .toBoolean(),

        // Custom sanitization
        body('badgeDetails.title').trim().escape(),
        body('badgeDetails.description').trim().escape(),
        body('badgeDetails.category').trim().escape(),
        body('badgeDetails.tags.*').trim().escape(),
        body('badgeDetails.skills.*').trim().escape(),
        body('*').trim().escape()
    ],

    getCertifications: [
        // Validate params
        validateObjectId('userId'),

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
        query('category')
            .optional()
            .trim()
            .isLength({ max: 50 }).withMessage('Category must not exceed 50 characters')
            .matches(/^[a-zA-Z0-9\s_-]+$/).withMessage('Category contains invalid characters'),

        query('search')
            .optional()
            .trim()
            .isLength({ max: 100 }).withMessage('Search query must not exceed 100 characters')
            .matches(/^[a-zA-Z0-9\s_-]+$/).withMessage('Search query contains invalid characters'),

        query('sortBy')
            .optional()
            .isIn(['recent', 'oldest', 'title', 'popular', 'verified']).withMessage('Invalid sortBy value'),

        validateObjectId('templateId', 'query').optional(),

        query('tags')
            .optional()
            .custom((value) => {
                const tags = value.split(',').map(tag => tag.trim());
                if (tags.length > 15) {
                    throw new AppError('Maximum 15 tags allowed', 400);
                }
                return tags.every(tag => /^[a-zA-Z0-9_-]+$/.test(tag));
            }).withMessage('Tags must contain only letters, numbers, underscores, or hyphens'),

        query('startDate')
            .optional()
            .isISO8601().withMessage('startDate must be a valid ISO 8601 date')
            .toDate(),

        query('endDate')
            .optional()
            .isISO8601().withMessage('endDate must be a valid ISO 8601 date')
            .toDate(),

        query('includeAnalytics')
            .optional()
            .isIn(['true', 'false']).withMessage('includeAnalytics must be true or false')
            .toBoolean()
    ],

    getCertificationById: [
        // Validate params
        validateObjectId('userId'),
        validateObjectId('id'),

        // Validate query parameters
        query('includeAnalytics')
            .optional()
            .isIn(['true', 'false']).withMessage('includeAnalytics must be true or false')
            .toBoolean(),

        query('includeVerification')
            .optional()
            .isIn(['true', 'false']).withMessage('includeVerification must be true or false')
            .toBoolean()
    ],

    updateCertification: [
        // Validate params
        validateObjectId('userId'),
        validateObjectId('id'),

        // Validate body
        body('badgeDetails.title')
            .optional()
            .trim()
            .isLength({ min: 3, max: 100 }).withMessage('Title must be between 3 and 100 characters')
            .matches(/^[a-zA-Z0-9\s_-]+$/).withMessage('Title contains invalid characters'),

        body('badgeDetails.description')
            .optional()
            .trim()
            .isLength({ max: 2000 }).withMessage('Description must not exceed 2000 characters')
            .matches(/^[a-zA-Z0-9\s.,!?'-]+$/).withMessage('Description contains invalid characters'),

        body('badgeDetails.category')
            .optional()
            .trim()
            .isLength({ max: 50 }).withMessage('Category must not exceed 50 characters')
            .matches(/^[a-zA-Z0-9\s_-]+$/).withMessage('Category contains invalid characters'),

        validateTags('badgeDetails.tags'),
        validateSkills('badgeDetails.skills'),

        validateObjectId('organization.organizationId', 'body').optional(),
        validateObjectId('templateId', 'body').optional(),

        validateDate('duration.issueDate', true),
        validateDate('duration.expirationDate', true),

        validateStatus('status.workflow', 'body'),

        body('status.isActive')
            .optional()
            .isBoolean().withMessage('isActive must be a boolean')
            .toBoolean(),

        // Custom sanitization
        body('badgeDetails.title').trim().escape(),
        body('badgeDetails.description').trim().escape(),
        body('badgeDetails.category').trim().escape(),
        body('badgeDetails.tags.*').trim().escape(),
        body('badgeDetails.skills.*').trim().escape(),
        body('*').trim().escape()
    ],

    deleteCertification: [
        // Validate params
        validateObjectId('userId'),
        validateObjectId('id'),

        // Validate query
        query('permanent')
            .optional()
            .isIn(['true', 'false']).withMessage('permanent must be true or false')
            .toBoolean()
    ],

    bulkOperations: [
        // Validate params
        validateObjectId('userId'),

        // Validate body
        body('operation')
            .notEmpty().withMessage('Operation is required')
            .isIn(['delete', 'archive', 'publish', 'updateCategory', 'updateTags', 'updateVisibility'])
            .withMessage('Invalid operation type'),

        body('certificationIds')
            .isArray({ min: 1, max: 100 }).withMessage('certificationIds must be an array with 1-100 items')
            .custom((ids) => {
                return ids.every(id => isValidObjectId(id));
            }).withMessage('All certificationIds must be valid ObjectIds'),

        body('data.category')
            .if(body('operation').equals('updateCategory'))
            .notEmpty().withMessage('Category is required for updateCategory operation')
            .trim()
            .isLength({ max: 50 }).withMessage('Category must not exceed 50 characters')
            .matches(/^[a-zA-Z0-9\s_-]+$/).withMessage('Category contains invalid characters'),

        body('data.tags')
            .if(body('operation').equals('updateTags'))
            .isArray({ min: 1, max: 15 }).withMessage('Tags must be an array with 1-15 items')
            .custom((tags) => {
                return tags.every(tag => typeof tag === 'string' && tag.length <= 30 && /^[a-zA-Z0-9_-]+$/.test(tag));
            }).withMessage('Each tag must be a string, not exceed 30 characters, and contain only letters, numbers, underscores, or hyphens'),

        body('data.visibility')
            .if(body('operation').equals('updateVisibility'))
            .notEmpty().withMessage('Visibility is required for updateVisibility operation')
            .isIn(['public', 'private']).withMessage('Visibility must be public or private'),

        // Custom sanitization
        body('data.category').trim().escape(),
        body('data.tags.*').trim().escape(),
        body('*').trim().escape()
    ],

    getAnalytics: [
        // Validate params
        validateObjectId('userId'),
        validateObjectId('id'),

        // Validate query
        query('timeframe')
            .optional()
            .isIn(['7d', '30d', '90d']).withMessage('Invalid timeframe'),

        query('metrics')
            .optional()
            .isIn(['basic', 'detailed']).withMessage('Metrics must be basic or detailed')
    ],

    duplicateCertification: [
        // Validate params
        validateObjectId('userId'),
        validateObjectId('id'),

        // Validate body
        body('title')
            .optional()
            .trim()
            .isLength({ min: 3, max: 100 }).withMessage('Title must be between 3 and 100 characters')
            .matches(/^[a-zA-Z0-9\s_-]+$/).withMessage('Title contains invalid characters'),

        body('includeVersions')
            .optional()
            .isIn(['true', 'false']).withMessage('includeVersions must be true or false')
            .toBoolean(),

        // Custom sanitization
        body('title').trim().escape()
    ],

    verifyCertification: [
        // Validate params
        validateObjectId('userId'),
        validateObjectId('id')
    ],

    uploadMedia: [
        // Validate params
        validateObjectId('userId'),
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
                    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'];
                    if (!allowedTypes.includes(file.mimetype)) {
                        throw new AppError('Invalid file type. Only JPEG, PNG, GIF, and PDF are allowed', 400);
                    }
                    if (file.size > 10 * 1024 * 1024) { // 10MB limit
                        throw new AppError('File size must not exceed 10MB', 400);
                    }
                    return true;
                });
            }).withMessage('Invalid file upload')
    ],

    shareCertification: [
        // Validate params
        validateObjectId('userId'),
        validateObjectId('id'),

        // Validate body
        validatePlatform('platform')
    ],

    endorseCertification: [
        // Validate params
        validateObjectId('userId'),
        validateObjectId('id')
    ],

    getVerificationStatus: [
        // Validate params
        validateObjectId('userId'),
        validateObjectId('id')
    ],

    getTrendingCertifications: [
        // Validate query parameters
        query('timeframe')
            .optional()
            .isIn(['7d', '30d', '90d']).withMessage('Invalid timeframe'),

        query('category')
            .optional()
            .trim()
            .isLength({ max: 50 }).withMessage('Category must not exceed 50 characters')
            .matches(/^[a-zA-Z0-9\s_-]+$/).withMessage('Category contains invalid characters'),

        query('limit')
            .optional()
            .isInt({ min: 1, max: 50 }).withMessage('Limit must be between 1 and 50')
            .toInt()
    ],

    getCertificationsByCategory: [
        // Validate params
        param('category')
            .trim()
            .notEmpty().withMessage('Category is required')
            .isLength({ max: 50 }).withMessage('Category must not exceed 50 characters')
            .matches(/^[a-zA-Z0-9\s_-]+$/).withMessage('Category contains invalid characters'),

        // Validate query parameters
        query('page')
            .optional()
            .isInt({ min: 1 }).withMessage('Page must be a positive integer')
            .toInt(),

        query('limit')
            .optional()
            .isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100')
            .toInt(),

        query('sortBy')
            .optional()
            .isIn(['recent', 'oldest', 'title', 'popular', 'verified']).withMessage('Invalid sortBy value')
    ],

    searchCertifications: [
        // Validate query parameters
        query('query')
            .trim()
            .notEmpty().withMessage('Search query is required')
            .isLength({ max: 100 }).withMessage('Search query must not exceed 100 characters')
            .matches(/^[a-zA-Z0-9\s_-]+$/).withMessage('Search query contains invalid characters'),

        query('page')
            .optional()
            .isInt({ min: 1 }).withMessage('Page must be a positive integer')
            .toInt(),

        query('limit')
            .optional()
            .isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100')
            .toInt(),

        query('filters.status')
            .optional()
            .isIn(validStatuses).withMessage(`Status must be one of ${validStatuses.join(', ')}`),

        query('filters.category')
            .optional()
            .trim()
            .isLength({ max: 50 }).withMessage('Category must not exceed 50 characters')
            .matches(/^[a-zA-Z0-9\s_-]+$/).withMessage('Category contains invalid characters'),

        query('filters.tags')
            .optional()
            .custom((value) => {
                const tags = value.split(',').map(tag => tag.trim());
                if (tags.length > 15) {
                    throw new AppError('Maximum 15 tags allowed', 400);
                }
                return tags.every(tag => /^[a-zA-Z0-9_-]+$/.test(tag));
            }).withMessage('Tags must contain only letters, numbers, underscores, or hyphens'),

        // Custom sanitization
        query('query').trim().escape(),
        query('filters.category').trim().escape(),
        query('filters.tags').trim()
    ],

    exportCertifications: [
        // Validate params
        validateObjectId('userId'),

        // Validate query parameters
        query('format')
            .optional()
            .isIn(['csv']).withMessage('Format must be csv'),

        query('fields')
            .optional()
            .custom((value) => {
                const fields = value.split(',');
                const allowedFields = [
                    'badgeDetails.title',
                    'badgeDetails.description',
                    'badgeDetails.category',
                    'status.workflow',
                    'duration.issueDate',
                    'duration.expirationDate',
                    'organization.organizationId',
                    'templateId'
                ];
                return fields.every(field => allowedFields.includes(field.trim()));
            }).withMessage('Invalid fields specified')
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
            if (req.body.certificationIds && req.body.certificationIds.length > 50) {
                logger.warn(`High volume request detected: ${req.body.certificationIds.length} certifications`, {
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

export { certificationValidations, validate };