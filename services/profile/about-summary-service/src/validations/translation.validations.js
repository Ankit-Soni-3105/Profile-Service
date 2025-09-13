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

// Utility to validate language codes against a predefined list
const validLanguageCodes = [
    'en', 'es', 'fr', 'de', 'it', 'pt', 'zh', 'ja', 'ko', 'ar', 'ru',
    'nl', 'sv', 'pl', 'tr', 'hi', 'bn', 'ur', 'th', 'vi', 'id', 'ms'
];

const validateLanguageCode = (field, location = 'body') => {
    return (location === 'body' ? body(field) : query(field))
        .trim()
        .notEmpty().withMessage(`${field} is required`)
        .isLength({ min: 2, max: 50 }).withMessage(`${field} must be between 2 and 50 characters`)
        .matches(/^[a-zA-Z\-]+$/).withMessage(`${field} must contain only letters and hyphens`)
        .isIn(validLanguageCodes).withMessage(`${field} must be a supported language code`);
};

// Utility to validate translation options
const validateTranslationOptions = (field) => {
    return body(field)
        .optional()
        .isObject().withMessage(`${field} must be an object`)
        .custom((options) => {
            const allowedOptions = ['formal', 'informal', 'preserveFormatting', 'contextAware', 'glossaryId'];
            if (Object.keys(options).some(key => !allowedOptions.includes(key))) {
                throw new AppError('Invalid translation options provided', 400);
            }
            for (const [key, value] of Object.entries(options)) {
                if (key === 'glossaryId') {
                    if (!isValidObjectId(value)) {
                        throw new AppError('glossaryId must be a valid ObjectId', 400);
                    }
                } else if (typeof value !== 'boolean') {
                    throw new AppError(`Option ${key} must be a boolean`, 400);
                }
            }
            return true;
        }).withMessage('Translation options must be valid');
};

// Utility to validate array of ObjectIds
const validateObjectIdArray = (field) => {
    return body(field)
        .isArray({ min: 1, max: 100 }).withMessage(`${field} must be an array with 1-100 items`)
        .custom((ids) => {
            if (!ids.every(id => isValidObjectId(id))) {
                throw new AppError('All IDs in array must be valid ObjectIds', 400);
            }
            return true;
        }).withMessage('All IDs in array must be valid ObjectIds');
};

const translationValidations = {
    translateContent: [
        // Validate params
        validateObjectId('userId'),
        validateObjectId('summaryId'),

        // Validate body
        validateLanguageCode('targetLanguage'),
        validateLanguageCode('sourceLanguage', 'body').optional(),
        validateTranslationOptions('options'),

        body('context')
            .optional()
            .trim()
            .isLength({ max: 500 }).withMessage('Context must not exceed 500 characters')
            .matches(/^[a-zA-Z0-9\s.,!?'-]+$/).withMessage('Context contains invalid characters'),

        body('priority')
            .optional()
            .isIn(['low', 'medium', 'high']).withMessage('Priority must be low, medium, or high'),

        body('callbackUrl')
            .optional()
            .isURL({ require_protocol: true }).withMessage('Callback URL must be a valid URL')
            .isLength({ max: 200 }).withMessage('Callback URL must not exceed 200 characters'),

        // Custom sanitization
        body('context').trim().escape(),
        body('*').trim().escape()
    ],

    getSupportedLanguages: [
        // Validate params
        validateObjectId('userId'),
        validateObjectId('summaryId'),

        // Validate query
        query('includeDetails')
            .optional()
            .isBoolean().withMessage('includeDetails must be a boolean')
            .toBoolean(),

        query('region')
            .optional()
            .trim()
            .isLength({ max: 50 }).withMessage('Region must not exceed 50 characters')
            .matches(/^[a-zA-Z\-]+$/).withMessage('Region must contain only letters and hyphens')
    ],

    getTranslationHistory: [
        // Validate params
        validateObjectId('userId'),
        validateObjectId('summaryId'),

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
            .isIn(['createdAt', 'targetLanguage', 'status']).withMessage('Invalid sortBy value'),

        query('sortOrder')
            .optional()
            .isIn(['asc', 'desc']).withMessage('Sort order must be asc or desc'),

        query('status')
            .optional()
            .isIn(['pending', 'completed', 'failed', 'cancelled']).withMessage('Invalid status filter'),

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
            }),

        query('targetLanguage')
            .optional()
            .isIn(validLanguageCodes).withMessage('Target language must be a supported language code')
    ],

    applyTranslation: [
        // Validate params
        validateObjectId('userId'),
        validateObjectId('summaryId'),

        // Validate body
        validateObjectId('translationId', 'body'),

        body('applyMode')
            .optional()
            .isIn(['replace', 'merge']).withMessage('Apply mode must be replace or merge'),

        body('versionComment')
            .optional()
            .trim()
            .isLength({ max: 200 }).withMessage('Version comment must not exceed 200 characters')
            .matches(/^[a-zA-Z0-9\s.,!?'-]+$/).withMessage('Version comment contains invalid characters'),

        // Custom sanitization
        body('versionComment').trim().escape(),
        body('*').trim().escape()
    ],

    bulkTranslate: [
        // Validate params
        validateObjectId('userId'),

        // Validate body
        validateObjectIdArray('summaryIds'),
        validateLanguageCode('targetLanguage'),
        validateLanguageCode('sourceLanguage', 'body').optional(),
        validateTranslationOptions('options'),

        body('batchName')
            .optional()
            .trim()
            .isLength({ max: 100 }).withMessage('Batch name must not exceed 100 characters')
            .matches(/^[a-zA-Z0-9\s_-]+$/).withMessage('Batch name contains invalid characters'),

        body('priority')
            .optional()
            .isIn(['low', 'medium', 'high']).withMessage('Priority must be low, medium, or high'),

        body('callbackUrl')
            .optional()
            .isURL({ require_protocol: true }).withMessage('Callback URL must be a valid URL')
            .isLength({ max: 200 }).withMessage('Callback URL must not exceed 200 characters'),

        body('context')
            .optional()
            .trim()
            .isLength({ max: 500 }).withMessage('Context must not exceed 500 characters')
            .matches(/^[a-zA-Z0-9\s.,!?'-]+$/).withMessage('Context contains invalid characters'),

        // Custom sanitization
        body('batchName').trim().escape(),
        body('context').trim().escape(),
        body('*').trim().escape()
    ],

    cancelTranslation: [
        // Validate params
        validateObjectId('userId'),
        validateObjectId('translationId'),

        // Validate body
        body('reason')
            .optional()
            .trim()
            .isLength({ max: 200 }).withMessage('Cancellation reason must not exceed 200 characters')
            .matches(/^[a-zA-Z0-9\s.,!?'-]+$/).withMessage('Cancellation reason contains invalid characters'),

        // Custom sanitization
        body('reason').trim().escape(),
        body('*').trim().escape()
    ],

    retryTranslation: [
        // Validate params
        validateObjectId('userId'),
        validateObjectId('translationId'),

        // Validate body
        body('options')
            .optional()
            .isObject().withMessage('Options must be an object')
            .custom((options) => {
                const allowedOptions = ['formal', 'informal', 'preserveFormatting', 'contextAware', 'glossaryId'];
                if (Object.keys(options).some(key => !allowedOptions.includes(key))) {
                    throw new AppError('Invalid retry options provided', 400);
                }
                for (const [key, value] of Object.entries(options)) {
                    if (key === 'glossaryId') {
                        if (!isValidObjectId(value)) {
                            throw new AppError('glossaryId must be a valid ObjectId', 400);
                        }
                    } else if (typeof value !== 'boolean') {
                        throw new AppError(`Option ${key} must be a boolean`, 400);
                    }
                }
                return true;
            }).withMessage('Retry options must be valid'),

        body('priority')
            .optional()
            .isIn(['low', 'medium', 'high']).withMessage('Priority must be low, medium, or high'),

        // Custom sanitization
        body('*').trim().escape()
    ],

    getTranslationStatus: [
        // Validate params
        validateObjectId('userId'),
        validateObjectId('translationId'),

        // Validate query
        query('includeDetails')
            .optional()
            .isBoolean().withMessage('includeDetails must be a boolean')
            .toBoolean()
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
                    method: req.method
                });
                return next(new AppError(`Validation failed: ${errorMessages}`, 400));
            }

            // Additional custom validation for high-scale systems
            if (req.body.summaryIds && req.body.summaryIds.length > 50) {
                logger.warn(`High volume request detected: ${req.body.summaryIds.length} items`, {
                    userId: req.params.userId,
                    path: req.originalUrl
                });
            }

            next();
        } catch (error) {
            logger.error('Validation middleware error:', {
                error: error.message,
                stack: error.stack,
                path: req.originalUrl,
                userId: req.params.userId
            });
            return next(new AppError('Validation processing error', 500));
        }
    };
};

export { translationValidations, validate };