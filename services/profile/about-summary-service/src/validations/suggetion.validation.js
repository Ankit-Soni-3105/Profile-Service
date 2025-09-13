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

// Allowed suggestion types (from SuggestionController's validateSuggestionType)
const ALLOWED_SUGGESTION_TYPES = ['clarity', 'engagement', 'seo', 'all'];

// Allowed apply options (from SuggestionController's getAllowedApplyOptions)
const ALLOWED_APPLY_OPTIONS = ['replace', 'merge', 'append'];

// Validation rules for suggestion operations
// Designed for scalability with millions of users:
// - Fail-fast with early exits
// - No database queries
// - Sanitization to prevent XSS and injection
// - O(1) time complexity
const suggestionValidations = {
    /**
     * Validations for generateSuggestions endpoint
     * GET /api/v1/suggestions/:userId/:summaryId
     */
    generateSuggestions: [
        // Validate path parameters
        validateObjectId('userId'),
        validateObjectId('summaryId'),

        // Validate query parameters
        query('type')
            .optional()
            .trim()
            .isIn(ALLOWED_SUGGESTION_TYPES).withMessage(`type must be one of: ${ALLOWED_SUGGESTION_TYPES.join(', ')}`),

        query('maxSuggestions')
            .optional()
            .isInt({ min: 1, max: 20 }).withMessage('maxSuggestions must be between 1 and 20')
            .toInt(),

        // Custom sanitizer
        query('*').trim().escape()
    ],

    /**
     * Validations for applySuggestion endpoint
     * PATCH /api/v1/suggestions/:userId/:summaryId/apply
     */
    applySuggestion: [
        // Validate path parameters
        validateObjectId('userId'),
        validateObjectId('summaryId'),

        // Validate body fields
        body('suggestionId')
            .trim()
            .notEmpty().withMessage('suggestionId is required')
            .custom((value) => {
                if (!isValidObjectId(value)) {
                    throw new AppError('suggestionId must be a valid ObjectId', 400);
                }
                return true;
            }).withMessage('suggestionId must be a valid ObjectId'),

        body('applyOptions')
            .optional()
            .custom((value) => {
                if (value && typeof value !== 'object') {
                    throw new AppError('applyOptions must be an object', 400);
                }
                if (value && Object.keys(value).length > 0) {
                    const invalidOptions = Object.keys(value).filter(key => !ALLOWED_APPLY_OPTIONS.includes(key));
                    if (invalidOptions.length > 0) {
                        throw new AppError(`Invalid applyOptions: ${invalidOptions.join(', ')}`, 400);
                    }
                }
                return true;
            }).withMessage(`applyOptions must only contain: ${ALLOWED_APPLY_OPTIONS.join(', ')}`),

        // Custom sanitizer
        body('*').trim().escape()
    ],

    /**
     * Validations for getSuggestionHistory endpoint
     * GET /api/v1/suggestions/:userId/:summaryId/history
     */
    getSuggestionHistory: [
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
     * Validations for bulkApplySuggestions endpoint
     * POST /api/v1/suggestions/:userId/bulk
     */
    bulkApplySuggestions: [
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

        body('suggestionIds')
            .isArray({ min: 1, max: 100 }).withMessage('suggestionIds must be an array with 1-100 items')
            .custom((ids) => {
                if (!ids.every(id => isValidObjectId(id))) {
                    throw new AppError('All suggestionIds must be valid ObjectIds', 400);
                }
                return true;
            }).withMessage('All suggestionIds must be valid ObjectIds'),

        body('applyOptions')
            .optional()
            .custom((value) => {
                if (value && typeof value !== 'object') {
                    throw new AppError('applyOptions must be an object', 400);
                }
                if (value && Object.keys(value).length > 0) {
                    const invalidOptions = Object.keys(value).filter(key => !ALLOWED_APPLY_OPTIONS.includes(key));
                    if (invalidOptions.length > 0) {
                        throw new AppError(`Invalid applyOptions: ${invalidOptions.join(', ')}`, 400);
                    }
                }
                return true;
            }).withMessage(`applyOptions must only contain: ${ALLOWED_APPLY_OPTIONS.join(', ')}`),

        // Custom sanitizer
        body('*').trim().escape()
    ],

    /**
     * Validations for discardSuggestion endpoint
     * DELETE /api/v1/suggestions/:userId/:summaryId/:suggestionId
     */
    discardSuggestion: [
        // Validate path parameters
        validateObjectId('userId'),
        validateObjectId('summaryId'),
        validateObjectId('suggestionId')
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

// Manual validation function for suggestion input
// Matches controller's validateSuggestionType and getAllowedApplyOptions
const validateSuggestionInput = ({ type, maxSuggestions, suggestionId, applyOptions }) => {
    if (type !== undefined) {
        if (!ALLOWED_SUGGESTION_TYPES.includes(type)) {
            return { valid: false, message: `type must be one of: ${ALLOWED_SUGGESTION_TYPES.join(', ')}` };
        }
    }

    if (maxSuggestions !== undefined) {
        if (!Number.isInteger(maxSuggestions) || maxSuggestions < 1 || maxSuggestions > 20) {
            return { valid: false, message: 'maxSuggestions must be an integer between 1 and 20' };
        }
    }

    if (suggestionId !== undefined) {
        if (!isValidObjectId(suggestionId)) {
            return { valid: false, message: 'suggestionId must be a valid ObjectId' };
        }
    }

    if (applyOptions !== undefined) {
        if (typeof applyOptions !== 'object' || applyOptions === null) {
            return { valid: false, message: 'applyOptions must be a non-null object' };
        }
        if (Object.keys(applyOptions).length > 0) {
            const invalidOptions = Object.keys(applyOptions).filter(key => !ALLOWED_APPLY_OPTIONS.includes(key));
            if (invalidOptions.length > 0) {
                return { valid: false, message: `Invalid applyOptions: ${invalidOptions.join(', ')}` };
            }
        }
    }

    return { valid: true, message: '' };
};

export { suggestionValidations, validate, validateSuggestionInput };