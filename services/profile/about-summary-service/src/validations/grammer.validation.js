import { body, param, query } from 'express-validator';
import { isValidObjectId } from 'mongoose';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { validationResult } from 'express-validator';

// Utility function to validate ObjectId
// Matches summaryValidations style: simple, no TypeScript, with custom error
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

// Allowed grammar check types (from GrammarController's validateCheckType)
const ALLOWED_CHECK_TYPES = ['grammar', 'style', 'all'];

// Supported languages (from GrammarController's getSupportedLanguages)
const SUPPORTED_LANGUAGES = ['en-US', 'en-GB', 'es', 'fr', 'de'];

// Validation rules for grammar operations
// Designed for scalability with millions of users:
// - Fail-fast with early exits
// - No database queries
// - Sanitization to prevent XSS and injection
// - O(1) time complexity
const grammarValidations = {
    /**
     * Validations for checkGrammar endpoint
     * GET /api/v1/grammar/:userId/:summaryId
     */
    checkGrammar: [
        // Validate path parameters
        validateObjectId('userId'),
        validateObjectId('summaryId'),

        // Validate query parameters
        query('language')
            .optional()
            .trim()
            .isIn(SUPPORTED_LANGUAGES).withMessage(`language must be one of: ${SUPPORTED_LANGUAGES.join(', ')}`),

        query('checkType')
            .optional()
            .trim()
            .isIn(ALLOWED_CHECK_TYPES).withMessage(`checkType must be one of: ${ALLOWED_CHECK_TYPES.join(', ')}`),

        // Custom sanitizer
        query('*').trim().escape()
    ],

    /**
     * Validations for applyGrammarCorrection endpoint
     * PATCH /api/v1/grammar/:userId/:summaryId/apply
     */
    applyGrammarCorrection: [
        // Validate path parameters
        validateObjectId('userId'),
        validateObjectId('summaryId'),

        // Validate body fields
        body('issueId')
            .trim()
            .notEmpty().withMessage('issueId is required')
            .custom((value) => {
                if (!isValidObjectId(value)) {
                    throw new AppError('issueId must be a valid ObjectId', 400);
                }
                return true;
            }).withMessage('issueId must be a valid ObjectId'),

        body('correction')
            .trim()
            .notEmpty().withMessage('correction is required')
            .isLength({ min: 1, max: 10000 }).withMessage('correction must be between 1 and 10,000 characters')
            .custom((value) => {
                if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(value)) {
                    throw new AppError('correction contains invalid control characters', 400);
                }
                return true;
            }).withMessage('correction contains invalid control characters'),

        // Custom sanitizer
        body('*').trim().escape()
    ],

    /**
     * Validations for getGrammarHistory endpoint
     * GET /api/v1/grammar/:userId/:summaryId/history
     */
    getGrammarHistory: [
        // Validate path parameters
        validateObjectId('userId'),
        validateObjectId('summaryId'),

        // Validate query parameters
        query('page')
            .optional()
            .isInt({ min: 1 }).withMessage('page must be a positive integer')
            .toInt(),

        query('limit')
            .optional()
            .isInt({ min: 1, max: 100 }).withMessage('limit must be between 1 and 100')
            .toInt(),

        // Custom sanitizer
        query('*').trim().escape()
    ],

    /**
     * Validations for bulkApplyGrammarCorrections endpoint
     * POST /api/v1/grammar/:userId/bulk
     */
    bulkApplyGrammarCorrections: [
        // Validate path parameters
        validateObjectId('userId'),

        // Validate body fields
        body('summaryIds')
            .isArray({ min: 1, max: 100 }).withMessage('summaryIds must be an array with 1-100 items')
            .custom((ids) => {
                if (!ids.every(id => isValidObjectId(id))) {
                    throw new AppError('All summaryIds must be valid ObjectIds', 400);
                }
                return true;
            }).withMessage('All summaryIds must be valid ObjectIds'),

        body('issueIds')
            .isArray({ min: 1, max: 100 }).withMessage('issueIds must be an array with 1-100 items')
            .custom((ids) => {
                if (!ids.every(id => isValidObjectId(id))) {
                    throw new AppError('All issueIds must be valid ObjectIds', 400);
                }
                return true;
            }).withMessage('All issueIds must be valid ObjectIds'),

        body('corrections')
            .isArray({ min: 1, max: 100 }).withMessage('corrections must be an array with 1-100 items')
            .custom((corrections) => {
                if (!corrections.every(c => typeof c === 'string' && c.length >= 1 && c.length <= 10000)) {
                    throw new AppError('All corrections must be strings between 1 and 10,000 characters', 400);
                }
                if (corrections.some(c => /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(c))) {
                    throw new AppError('Corrections contain invalid control characters', 400);
                }
                return true;
            }).withMessage('All corrections must be valid strings'),

        // Ensure corrections array length matches issueIds
        body().custom((body) => {
            if (body.issueIds.length !== body.corrections.length) {
                throw new AppError('issueIds and corrections arrays must have the same length', 400);
            }
            return true;
        }).withMessage('issueIds and corrections arrays must have the same length'),

        // Custom sanitizer
        body('*').trim().escape()
    ],

    /**
     * Validations for discardGrammarIssue endpoint
     * DELETE /api/v1/grammar/:userId/:summaryId/:issueId
     */
    discardGrammarIssue: [
        // Validate path parameters
        validateObjectId('userId'),
        validateObjectId('summaryId'),
        validateObjectId('issueId')
    ]
};

// Validation middleware to handle errors
// Matches summaryValidations: parallel execution, consistent logging
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

// Manual validation function for grammar input
// Matches controller's validateCheckType and getSupportedLanguages
const validateGrammarInput = ({ language, checkType, issueId, correction }) => {
    if (language !== undefined) {
        if (!SUPPORTED_LANGUAGES.includes(language)) {
            return { valid: false, message: `language must be one of: ${SUPPORTED_LANGUAGES.join(', ')}` };
        }
    }

    if (checkType !== undefined) {
        if (!ALLOWED_CHECK_TYPES.includes(checkType)) {
            return { valid: false, message: `checkType must be one of: ${ALLOWED_CHECK_TYPES.join(', ')}` };
        }
    }

    if (issueId !== undefined) {
        if (!isValidObjectId(issueId)) {
            return { valid: false, message: 'issueId must be a valid ObjectId' };
        }
    }

    if (correction !== undefined) {
        if (typeof correction !== 'string') {
            return { valid: false, message: 'correction must be a string' };
        }
        if (correction.length < 1 || correction.length > 10000) {
            return { valid: false, message: 'correction must be between 1 and 10,000 characters' };
        }
        if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(correction)) {
            return { valid: false, message: 'correction contains invalid control characters' };
        }
    }

    return { valid: true, message: '' };
};

export { grammarValidations, validate, validateGrammarInput };