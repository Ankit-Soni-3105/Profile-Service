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

// Utility to validate language codes
const validLanguageCodes = [
    'en-US', 'en-GB', 'es-ES', 'fr-FR', 'de-DE', 'it-IT', 'pt-PT', 'zh-CN',
    'ja-JP', 'ko-KR', 'ar-SA', 'ru-RU', 'nl-NL', 'sv-SE', 'pl-PL', 'tr-TR',
    'hi-IN', 'bn-IN', 'ur-PK', 'th-TH', 'vi-VN', 'id-ID', 'ms-MY'
];

const validateLanguageCode = (field, location = 'body') => {
    return (location === 'body' ? body(field) : query(field))
        .trim()
        .notEmpty().withMessage(`${field} is required`)
        .isIn(validLanguageCodes).withMessage(`${field} must be a supported language code`)
        .isLength({ min: 2, max: 5 }).withMessage(`${field} must be between 2 and 5 characters`);
};

// Utility to validate voice input options
const validateVoiceOptions = (field) => {
    return body(field)
        .optional()
        .isObject().withMessage(`${field} must be an object`)
        .custom((options) => {
            const allowedOptions = ['noiseCancellation', 'accent', 'speechRate', 'contextAware'];
            if (Object.keys(options).some(key => !allowedOptions.includes(key))) {
                throw new AppError('Invalid voice input options provided', 400);
            }
            for (const [key, value] of Object.entries(options)) {
                if (key === 'accent' && typeof value !== 'string') {
                    throw new AppError('Accent must be a string', 400);
                }
                if (key === 'speechRate' && (typeof value !== 'number' || value < 0.5 || value > 2)) {
                    throw new AppError('Speech rate must be a number between 0.5 and 2', 400);
                }
                if (['noiseCancellation', 'contextAware'].includes(key) && typeof value !== 'boolean') {
                    throw new AppError(`${key} must be a boolean`, 400);
                }
            }
            return true;
        }).withMessage('Voice input options must be valid');
};

// Utility to validate audio data
const validateAudioData = (field) => {
    return body(field)
        .notEmpty().withMessage(`${field} is required`)
        .isString().withMessage(`${field} must be a string`)
        .custom((value) => {
            // Basic validation for Base64 audio data
            const base64Pattern = /^data:audio\/(wav|mp3|ogg);base64,[A-Za-z0-9+/=]+$/;
            if (!base64Pattern.test(value)) {
                throw new AppError(`${field} must be a valid Base64 - encoded audio string`, 400);
            }
            const dataSize = Buffer.from(value.split(',')[1], 'base64').length;
            if (dataSize > 10 * 1024 * 1024) { // 10MB limit
                throw new AppError(`${field} size must not exceed 10MB`, 400);
            }
            return true;
        }).withMessage(`${field} must be a valid Base64 - encoded audio string`);
};

// Utility to validate array of inputs for bulk processing
const validateInputsArray = (field) => {
    return body(field)
        .isArray({ min: 1, max: 100 }).withMessage(`${field} must be an array with 1 - 100 items`)
        .custom((inputs) => {
            return inputs.every(input => {
                if (!input.summaryId && !input.audioData) {
                    throw new AppError('Each input must have either summaryId or audioData', 400);
                }
                if (input.summaryId && !isValidObjectId(input.summaryId)) {
                    throw new AppError('Invalid summaryId in inputs array', 400);
                }
                if (input.audioData) {
                    const base64Pattern = /^data:audio\/(wav|mp3|ogg);base64,[A-Za-z0-9+/=]+$/;
                    if (!base64Pattern.test(input.audioData)) {
                        throw new AppError('Invalid audioData in inputs array', 400);
                    }
                    const dataSize = Buffer.from(input.audioData.split(',')[1], 'base64').length;
                    if (dataSize > 10 * 1024 * 1024) {
                        throw new AppError('Audio data size must not exceed 10MB', 400);
                    }
                }
                return true;
            });
        }).withMessage('All inputs must be valid');
};

const voiceInputValidations = {
    processVoiceInput: [
        // Validate params
        validateObjectId('userId'),
        validateObjectId('summaryId').optional(),

        // Validate body
        validateAudioData('audioData'),
        validateLanguageCode('language').optional(),
        validateVoiceOptions('options'),

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

    getVoiceInputHistory: [
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
            .isIn(['createdAt', 'language', 'status']).withMessage('Invalid sortBy value'),

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

        query('language')
            .optional()
            .isIn(validLanguageCodes).withMessage('Language must be a supported language code')
    ],

    bulkProcessVoiceInputs: [
        // Validate params
        validateObjectId('userId'),

        // Validate body
        validateInputsArray('inputs'),
        validateLanguageCode('language').optional(),
        validateVoiceOptions('options'),

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

        // Custom sanitization
        body('batchName').trim().escape(),
        body('inputs.*.context').trim().escape(),
        body('*').trim().escape()
    ],

    deleteVoiceInput: [
        // Validate params
        validateObjectId('userId'),
        validateObjectId('summaryId'),
        validateObjectId('voiceInputId'),

        // Validate body
        body('reason')
            .optional()
            .trim()
            .isLength({ max: 200 }).withMessage('Deletion reason must not exceed 200 characters')
            .matches(/^[a-zA-Z0-9\s.,!?'-]+$/).withMessage('Deletion reason contains invalid characters'),

        // Custom sanitization
        body('reason').trim().escape(),
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
                logger.warn(`Validation failed: ${JSON.stringify(errors.array())} `, {
                    path: req.originalUrl,
                    method: req.method,
                    userId: req.user?.id
                });
                return next(new AppError(`Validation failed: ${errorMessages} `, 400));
            }

            // Additional validation for high-scale systems
            if (req.body.inputs && req.body.inputs.length > 50) {
                logger.warn(`High volume request detected: ${req.body.inputs.length} items`, {
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

export { voiceInputValidations, validate };