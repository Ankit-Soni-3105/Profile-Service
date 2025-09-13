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

// Utility to validate template categories
const validCategories = [
    'business', 'education', 'marketing', 'technical', 'creative',
    'legal', 'medical', 'personal', 'research', 'other'
];

const validateCategory = (field, location = 'body') => {
    return (location === 'body' ? body(field) : query(field))
        .optional()
        .trim()
        .isIn(validCategories).withMessage(`${field} must be a valid category`)
        .isLength({ max: 50 }).withMessage(`${field} must not exceed 50 characters`);
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

// Utility to validate visibility
const validVisibilities = ['public', 'private', 'team'];

const validateVisibility = (field, location = 'body') => {
    return (location === 'body' ? body(field) : query(field))
        .optional()
        .isIn(validVisibilities).withMessage(`${field} must be one of ${validVisibilities.join(', ')}`);
};

// Utility to validate template content
const validateTemplateContent = (field) => {
    return body(field)
        .trim()
        .notEmpty().withMessage(`${field} is required`)
        .isLength({ min: 10, max: 10000 }).withMessage(`${field} must be between 10 and 10,000 characters`)
        .custom((value) => {
            const variablePattern = /\{\{[^}]+\}\}/g;
            const variables = value.match(variablePattern) || [];
            if (variables.length > 50) {
                throw new AppError('Maximum 50 template variables allowed', 400);
            }
            return true;
        }).withMessage('Template content contains too many variables');
};

const templateValidations = {
    createTemplate: [
        // Validate body
        body('name')
            .trim()
            .notEmpty().withMessage('Template name is required')
            .isLength({ min: 3, max: 200 }).withMessage('Template name must be between 3 and 200 characters')
            .matches(/^[a-zA-Z0-9\s_-]+$/).withMessage('Template name contains invalid characters'),

        validateTemplateContent('content'),
        validateCategory('category'),
        validateTags('tags'),
        validateVisibility('visibility'),

        body('settings.autoGenerate')
            .optional()
            .isBoolean().withMessage('autoGenerate must be a boolean'),

        body('settings.aiEnhancements')
            .optional()
            .isBoolean().withMessage('aiEnhancements must be a boolean'),

        body('metadata.description')
            .optional()
            .trim()
            .isLength({ max: 500 }).withMessage('Description must not exceed 500 characters')
            .matches(/^[a-zA-Z0-9\s.,!?'-]+$/).withMessage('Description contains invalid characters'),

        // Custom sanitization
        body('name').trim().escape(),
        body('content').trim().escape(),
        body('metadata.description').trim().escape(),
        body('*').trim().escape()
    ],

    getTemplates: [
        // Validate query parameters
        query('page')
            .optional()
            .isInt({ min: 1 }).withMessage('Page must be a positive integer')
            .toInt(),

        query('limit')
            .optional()
            .isInt({ min: 1, max: 100 }).withMessage('Limit must be between 1 and 100')
            .toInt(),

        validateCategory('category', 'query'),
        validateVisibility('visibility', 'query'),

        query('search')
            .optional()
            .trim()
            .isLength({ max: 100 }).withMessage('Search query must not exceed 100 characters')
            .matches(/^[a-zA-Z0-9\s_-]+$/).withMessage('Search query contains invalid characters'),

        query('sortBy')
            .optional()
            .isIn(['recent', 'oldest', 'name', 'popular']).withMessage('Invalid sortBy value'),

        query('tags')
            .optional()
            .custom((value) => {
                if (value) {
                    const tags = value.split(',').map(tag => tag.trim());
                    if (tags.length > 20) {
                        throw new AppError('Maximum 20 tags allowed', 400);
                    }
                    return tags.every(tag => tag.length <= 30 && /^[a-zA-Z0-9_-]+$/.test(tag));
                }
                return true;
            }).withMessage('Each tag must not exceed 30 characters and contain only letters, numbers, underscores, or hyphens'),

        query('startDate')
            .optional()
            .isISO8601().withMessage('startDate must be a valid ISO date')
            .toDate(),

        query('endDate')
            .optional()
            .isISO8601().withMessage('endDate must be a valid ISO date')
            .toDate()
            .custom((endDate, { req }) => {
                if (req.query.startDate && endDate < new Date(req.query.startDate)) {
                    throw new AppError('endDate must be after startDate', 400);
                }
                return true;
            })
    ],

    getTemplateById: [
        // Validate params
        validateObjectId('templateId')
    ],

    updateTemplate: [
        // Validate params
        validateObjectId('templateId'),

        // Validate body
        body('name')
            .optional()
            .trim()
            .isLength({ min: 3, max: 200 }).withMessage('Template name must be between 3 and 200 characters')
            .matches(/^[a-zA-Z0-9\s_-]+$/).withMessage('Template name contains invalid characters'),

        body('content')
            .optional()
            .trim()
            .isLength({ min: 10, max: 10000 }).withMessage('Content must be between 10 and 10,000 characters')
            .custom((value) => {
                const variablePattern = /\{\{[^}]+\}\}/g;
                const variables = value.match(variablePattern) || [];
                if (variables.length > 50) {
                    throw new AppError('Maximum 50 template variables allowed', 400);
                }
                return true;
            }).withMessage('Template content contains too many variables'),

        validateCategory('category'),
        validateTags('tags'),
        validateVisibility('visibility'),

        body('settings.autoGenerate')
            .optional()
            .isBoolean().withMessage('autoGenerate must be a boolean'),

        body('settings.aiEnhancements')
            .optional()
            .isBoolean().withMessage('aiEnhancements must be a boolean'),

        body('metadata.description')
            .optional()
            .trim()
            .isLength({ max: 500 }).withMessage('Description must not exceed 500 characters')
            .matches(/^[a-zA-Z0-9\s.,!?'-]+$/).withMessage('Description contains invalid characters'),

        // Custom sanitization
        body('name').trim().escape(),
        body('content').trim().escape(),
        body('metadata.description').trim().escape(),
        body('*').trim().escape()
    ],

    deleteTemplate: [
        // Validate params
        validateObjectId('templateId'),

        // Validate query
        query('permanent')
            .optional()
            .isIn(['true', 'false']).withMessage('permanent must be true or false')
            .toBoolean()
    ],

    bulkOperations: [
        // Validate body
        body('operation')
            .notEmpty().withMessage('Operation is required')
            .isIn(['delete', 'updateCategory', 'updateVisibility', 'updateTags'])
            .withMessage('Invalid operation'),

        body('templateIds')
            .isArray({ min: 1, max: 100 }).withMessage('templateIds must be an array with 1-100 items')
            .custom((ids) => {
                if (!ids.every(id => isValidObjectId(id))) {
                    throw new AppError('All templateIds must be valid ObjectIds', 400);
                }
                return true;
            }).withMessage('All templateIds must be valid ObjectIds'),

        validateCategory('data.category')
            .if(body('operation').equals('updateCategory'))
            .notEmpty().withMessage('Category is required for updateCategory operation'),

        validateTags('data.tags')
            .if(body('operation').equals('updateTags'))
            .notEmpty().withMessage('Tags are required for updateTags operation'),

        validateVisibility('data.visibility')
            .if(body('operation').equals('updateVisibility'))
            .notEmpty().withMessage('Visibility is required for updateVisibility operation'),

        // Custom sanitization
        body('data.category').trim().escape(),
        body('data.tags.*').trim().escape(),
        body('*').trim().escape()
    ],

    getAnalytics: [
        // Validate params
        validateObjectId('templateId'),

        // Validate query
        query('timeframe')
            .optional()
            .isIn(['7d', '30d', '90d']).withMessage('Invalid timeframe'),

        query('metrics')
            .optional()
            .isIn(['basic', 'detailed']).withMessage('Invalid metrics type')
    ],

    duplicateTemplate: [
        // Validate params
        validateObjectId('templateId'),

        // Validate body
        body('name')
            .optional()
            .trim()
            .isLength({ min: 3, max: 200 }).withMessage('Template name must be between 3 and 200 characters')
            .matches(/^[a-zA-Z0-9\s_-]+$/).withMessage('Template name contains invalid characters'),

        // Custom sanitization
        body('name').trim().escape(),
        body('*').trim().escape()
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
            if (req.body.templateIds && req.body.templateIds.length > 50) {
                logger.warn(`High volume request detected: ${req.body.templateIds.length} items`, {
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

export { templateValidations, validate };