import { body, param, query } from 'express-validator';
import { isValidObjectId } from 'mongoose';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';

const validateObjectId = (field, location = 'params') => {
    return (location === 'params' ? param(field) : body(field))
        .custom((value) => {
            if (!isValidObjectId(value)) {
                throw new AppError(`${field} must be a valid ObjectId`, 400);
            }
            return true;
        })
        .withMessage(`${field} must be a valid ObjectId`);
};

const summaryValidations = {
    createSummary: [
        // Validate userId in params
        validateObjectId('userId'),

        // Validate summary data in body
        body('title')
            .trim()
            .notEmpty().withMessage('Title is required')
            .isLength({ min: 3, max: 200 }).withMessage('Title must be between 3 and 200 characters'),

        body('content')
            .trim()
            .notEmpty().withMessage('Content is required')
            .isLength({ min: 10, max: 10000 }).withMessage('Content must be between 10 and 10,000 characters'),

        body('category')
            .optional()
            .trim()
            .isLength({ max: 50 }).withMessage('Category must not exceed 50 characters'),

        body('tags')
            .optional()
            .isArray().withMessage('Tags must be an array')
            .custom((tags) => {
                if (tags.length > 20) throw new AppError('Maximum 20 tags allowed', 400);
                return tags.every(tag => typeof tag === 'string' && tag.length <= 30);
            }).withMessage('Each tag must be a string and not exceed 30 characters'),

        body('status')
            .optional()
            .isIn(['draft', 'active', 'archived']).withMessage('Invalid status value'),

        body('sharing.visibility')
            .optional()
            .isIn(['public', 'private', 'team']).withMessage('Invalid visibility value'),

        body('settings.autoBackup')
            .optional()
            .isBoolean().withMessage('autoBackup must be a boolean'),

        body('settings.aiEnhancements')
            .optional()
            .isBoolean().withMessage('aiEnhancements must be a boolean'),

        body('templateId')
            .optional()
            .custom((value) => {
                if (value && !isValidObjectId(value)) {
                    throw new AppError('templateId must be a valid ObjectId', 400);
                }
                return true;
            }).withMessage('templateId must be a valid ObjectId'),

        // Custom sanitizer to prevent XSS and SQL injection
        body('*').trim().escape()
    ],

    getSummaries: [
        // Validate userId in params
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

        query('status')
            .optional()
            .isIn(['all', 'draft', 'active', 'archived', 'deleted']).withMessage('Invalid status filter'),

        query('category')
            .optional()
            .trim()
            .isLength({ max: 50 }).withMessage('Category must not exceed 50 characters'),

        query('search')
            .optional()
            .trim()
            .isLength({ max: 100 }).withMessage('Search query must not exceed 100 characters'),

        query('sortBy')
            .optional()
            .isIn(['recent', 'oldest', 'title', 'popular', 'quality', 'status']).withMessage('Invalid sort option'),

        query('templateId')
            .optional()
            .custom((value) => {
                if (value && !isValidObjectId(value)) {
                    throw new AppError('templateId must be a valid ObjectId', 400);
                }
                return true;
            }).withMessage('templateId must be a valid ObjectId'),

        query('tags')
            .optional()
            .custom((value) => {
                if (value) {
                    const tags = value.split(',');
                    if (tags.length > 20) throw new AppError('Maximum 20 tags allowed', 400);
                    return tags.every(tag => tag.trim().length <= 30);
                }
                return true;
            }).withMessage('Each tag must not exceed 30 characters'),

        query('startDate')
            .optional()
            .isISO8601().withMessage('startDate must be a valid ISO date')
            .toDate(),

        query('endDate')
            .optional()
            .isISO8601().withMessage('endDate must be a valid ISO date')
            .toDate(),

        query('includeAnalytics')
            .optional()
            .isIn(['true', 'false']).withMessage('includeAnalytics must be true or false')
    ],

    getSummaryById: [
        // Validate params
        validateObjectId('userId'),
        validateObjectId('summaryId'),

        // Validate query parameters
        query('includeVersions')
            .optional()
            .isIn(['true', 'false']).withMessage('includeVersions must be true or false'),

        query('includeAnalytics')
            .optional()
            .isIn(['true', 'false']).withMessage('includeAnalytics must be true or false')
    ],

    updateSummary: [
        // Validate params
        validateObjectId('userId'),
        validateObjectId('summaryId'),

        // Validate update fields
        body('title')
            .optional()
            .trim()
            .isLength({ min: 3, max: 200 }).withMessage('Title must be between 3 and 200 characters'),

        body('content')
            .optional()
            .trim()
            .isLength({ min: 10, max: 10000 }).withMessage('Content must be between 10 and 10,000 characters'),

        body('category')
            .optional()
            .trim()
            .isLength({ max: 50 }).withMessage('Category must not exceed 50 characters'),

        body('tags')
            .optional()
            .isArray().withMessage('Tags must be an array')
            .custom((tags) => {
                if (tags.length > 20) throw new AppError('Maximum 20 tags allowed', 400);
                return tags.every(tag => typeof tag === 'string' && tag.length <= 30);
            }).withMessage('Each tag must be a string and not exceed 30 characters'),

        body('status')
            .optional()
            .isIn(['draft', 'active', 'archived']).withMessage('Invalid status value'),

        body('sharing.visibility')
            .optional()
            .isIn(['public', 'private', 'team']).withMessage('Invalid visibility value'),

        body('settings.autoBackup')
            .optional()
            .isBoolean().withMessage('autoBackup must be a boolean'),

        body('settings.aiEnhancements')
            .optional()
            .isBoolean().withMessage('aiEnhancements must be a boolean'),

        body('templateId')
            .optional()
            .custom((value) => {
                if (value && !isValidObjectId(value)) {
                    throw new AppError('templateId must be a valid ObjectId', 400);
                }
                return true;
            }).withMessage('templateId must be a valid ObjectId'),

        // Custom sanitizer
        body('*').trim().escape()
    ],

    deleteSummary: [
        // Validate params
        validateObjectId('userId'),
        validateObjectId('summaryId'),

        // Validate query
        query('permanent')
            .optional()
            .isIn(['true', 'false']).withMessage('permanent must be true or false')
    ],

    bulkOperations: [
        // Validate params
        validateObjectId('userId'),

        // Validate body
        body('operation')
            .notEmpty().withMessage('Operation is required')
            .isIn(['delete', 'archive', 'publish', 'updateCategory', 'updateTags', 'updateVisibility'])
            .withMessage('Invalid operation'),

        body('summaryIds')
            .isArray({ min: 1, max: 100 }).withMessage('summaryIds must be an array with 1-100 items')
            .custom((ids) => {
                if (!ids.every(id => isValidObjectId(id))) {
                    throw new AppError('All summaryIds must be valid ObjectIds', 400);
                }
                return true;
            }).withMessage('All summaryIds must be valid ObjectIds'),

        body('data.category')
            .if(body('operation').equals('updateCategory'))
            .notEmpty().withMessage('Category is required for updateCategory operation')
            .trim()
            .isLength({ max: 50 }).withMessage('Category must not exceed 50 characters'),

        body('data.tags')
            .if(body('operation').equals('updateTags'))
            .isArray({ min: 1, max: 20 }).withMessage('Tags must be an array with 1-20 items')
            .custom((tags) => {
                return tags.every(tag => typeof tag === 'string' && tag.length <= 30);
            }).withMessage('Each tag must be a string and not exceed 30 characters'),

        body('data.visibility')
            .if(body('operation').equals('updateVisibility'))
            .notEmpty().withMessage('Visibility is required for updateVisibility operation')
            .isIn(['public', 'private', 'team']).withMessage('Invalid visibility value'),

        // Custom sanitizer
        body('*').trim().escape()
    ],

    getAnalytics: [
        // Validate params
        validateObjectId('userId'),
        validateObjectId('summaryId'),

        // Validate query
        query('timeframe')
            .optional()
            .isIn(['7d', '30d', '90d']).withMessage('Invalid timeframe'),

        query('metrics')
            .optional()
            .isIn(['basic', 'detailed']).withMessage('Invalid metrics type')
    ],

    duplicateSummary: [
        // Validate params
        validateObjectId('userId'),
        validateObjectId('summaryId'),

        // Validate body
        body('title')
            .optional()
            .trim()
            .isLength({ min: 3, max: 200 }).withMessage('Title must be between 3 and 200 characters'),

        body('includeVersions')
            .optional()
            .isIn(['true', 'false']).withMessage('includeVersions must be true or false'),

        // Custom sanitizer
        body('*').trim().escape()
    ]
};

// Validation middleware to handle errors
const validate = (validations) => {
    return async (req, res, next) => {
        try {
            await Promise.all(validations.map(validation => validation.run(req)));

            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                logger.warn(`Validation failed: ${JSON.stringify(errors.array())}`);
                return next(new AppError('Validation failed: ' + errors.array().map(e => e.msg).join(', '), 400));
            }

            next();
        } catch (error) {
            logger.error('Validation middleware error:', error);
            return next(new AppError('Validation processing error', 500));
        }
    };
};

export { summaryValidations, validate };