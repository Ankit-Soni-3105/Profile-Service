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
    location = 'params',
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

// Enhanced validation rules for editor operations
// Optimized for scalability with 1M users:
// - Fail-fast validation with .bail()
// - No database queries in validations
// - Strong sanitization to prevent XSS and injection
// - O(1) time complexity for all checks
const editorValidations = {
    /**
     * Validations for updateContent endpoint
     * PATCH /api/v1/editor/:userId/:summaryId
     */
    updateContent: [
        // Validate path parameters
        validateObjectId('userId'),
        validateObjectId('summaryId'),

        // Validate body fields
        body('content')
            .exists({ checkFalsy: true }).withMessage('Content is required')
            .isString().withMessage('Content must be a string')
            .trim()
            .notEmpty().withMessage('Content cannot be empty after trimming')
            .isLength({ min: 1, max: 10000 }).withMessage('Content must be between 1 and 10,000 characters')
            .bail()
            // Custom validation for content safety
            .custom((value) => {
                // Prevent control characters except newline/tab
                if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(value)) {
                    throw new AppError('Content contains invalid control characters', 400);
                }
                return true;
            })
            .escape(), // Escape HTML to prevent XSS

        body('cursorPosition')
            .optional({ nullable: true })
            .isObject().withMessage('cursorPosition must be an object')
            .bail()
            .custom((value) => {
                if (value == null) return true;
                if (typeof value !== 'object' || value === null) {
                    throw new AppError('cursorPosition must be a non-null object', 400);
                }
                if (!Number.isInteger(value.line) || value.line < 0) {
                    throw new AppError('cursorPosition.line must be a non-negative integer', 400);
                }
                if (!Number.isInteger(value.column) || value.column < 0) {
                    throw new AppError('cursorPosition.column must be a non-negative integer', 400);
                }
                // Additional check for reasonable values to prevent abuse
                if (value.line > 1000000 || value.column > 1000000) {
                    throw new AppError('cursorPosition values are too large', 400);
                }
                return true;
            }).withMessage('cursorPosition must have valid line and column integers'),

        // Global body sanitizer
        body('*').trim().escape()
    ],

    /**
     * Validations for saveEditorState endpoint
     * PATCH /api/v1/editor/:userId/:summaryId/state
     */
    saveEditorState: [
        // Validate path parameters
        validateObjectId('userId'),
        validateObjectId('summaryId'),

        // Validate body fields
        body('cursorPosition')
            .optional({ nullable: true })
            .isObject().withMessage('cursorPosition must be an object')
            .bail()
            .custom((value) => {
                if (value == null) return true;
                if (typeof value !== 'object' || value === null) {
                    throw new AppError('cursorPosition must be a non-null object', 400);
                }
                if (!Number.isInteger(value.line) || value.line < 0) {
                    throw new AppError('cursorPosition.line must be a non-negative integer', 400);
                }
                if (!Number.isInteger(value.column) || value.column < 0) {
                    throw new AppError('cursorPosition.column must be a non-negative integer', 400);
                }
                if (value.line > 1000000 || value.column > 1000000) {
                    throw new AppError('cursorPosition values are too large', 400);
                }
                return true;
            }).withMessage('cursorPosition must have valid line and column integers'),

        body('selectionRange')
            .optional({ nullable: true })
            .isObject().withMessage('selectionRange must be an object')
            .bail()
            .custom((value) => {
                if (value == null) return true;
                if (typeof value !== 'object' || value === null) {
                    throw new AppError('selectionRange must be a non-null object', 400);
                }
                const fields = ['startLine', 'startColumn', 'endLine', 'endColumn'];
                for (const field of fields) {
                    if (!Number.isInteger(value[field]) || value[field] < 0) {
                        throw new AppError(`selectionRange.${field} must be a non-negative integer`, 400);
                    }
                    if (value[field] > 1000000) {
                        throw new AppError(`selectionRange.${field} value is too large`, 400);
                    }
                }
                if (value.startLine > value.endLine ||
                    (value.startLine === value.endLine && value.startColumn > value.endColumn)) {
                    throw new AppError('selectionRange start must be before or equal to end', 400);
                }
                return true;
            }).withMessage('selectionRange must have valid startLine, startColumn, endLine, and endColumn integers'),

        // Global body sanitizer
        body('*').trim().escape()
    ],

    /**
     * Validations for getCollaborators endpoint
     * GET /api/v1/editor/:userId/:summaryId/collaborators
     */
    getCollaborators: [
        validateObjectId('userId'),
        validateObjectId('summaryId'),
    ],

    /**
     * Validations for undoChange endpoint
     * POST /api/v1/editor/:userId/:summaryId/undo
     */
    undoChange: [
        validateObjectId('userId'),
        validateObjectId('summaryId'),
    ],

    /**
     * Validations for redoChange endpoint
     * POST /api/v1/editor/:userId/:summaryId/redo
     */
    redoChange: [
        validateObjectId('userId'),
        validateObjectId('summaryId'),
    ],

    /**
     * Validations for getHistory endpoint
     * GET /api/v1/editor/:userId/:summaryId/history
     */
    getHistory: [
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
    ]
};

/**
 * Validation middleware to handle errors
 * Optimized for high throughput with parallel validation execution
 * Detailed logging for monitoring in large-scale systems
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
 * Manual validation function for editor input
 * Used in controller for runtime checks
 * Enhanced with strict type checking and bounds validation
 */
const validateEditorInput = ({ content, cursorPosition, selectionRange }) => {
    if (content !== undefined) {
        if (typeof content !== 'string') {
            return { valid: false, message: 'Content must be a string' };
        }
        if (content.length > 10000) {
            return { valid: false, message: 'Content must not exceed 10,000 characters' };
        }
        if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(content)) {
            return { valid: false, message: 'Content contains invalid control characters' };
        }
    }

    if (cursorPosition !== undefined) {
        if (typeof cursorPosition !== 'object' || cursorPosition === null) {
            return { valid: false, message: 'cursorPosition must be a non-null object' };
        }
        if (!Number.isInteger(cursorPosition.line) || cursorPosition.line < 0) {
            return { valid: false, message: 'cursorPosition.line must be a non-negative integer' };
        }
        if (!Number.isInteger(cursorPosition.column) || cursorPosition.column < 0) {
            return { valid: false, message: 'cursorPosition.column must be a non-negative integer' };
        }
        if (cursorPosition.line > 1000000 || cursorPosition.column > 1000000) {
            return { valid: false, message: 'cursorPosition values are too large' };
        }
    }

    if (selectionRange !== undefined) {
        if (typeof selectionRange !== 'object' || selectionRange === null) {
            return { valid: false, message: 'selectionRange must be a non-null object' };
        }
        const fields = ['startLine', 'startColumn', 'endLine', 'endColumn'];
        for (const field of fields) {
            if (!Number.isInteger(selectionRange[field]) || selectionRange[field] < 0) {
                return { valid: false, message: `selectionRange.${field} must be a non-negative integer` };
            }
            if (selectionRange[field] > 1000000) {
                return { valid: false, message: `selectionRange.${field} value is too large` };
            }
        }
        if (selectionRange.startLine > selectionRange.endLine ||
            (selectionRange.startLine === selectionRange.endLine && selectionRange.startColumn > selectionRange.endColumn)) {
            return { valid: false, message: 'selectionRange start must be before or equal to end' };
        }
    }

    return { valid: true, message: '' };
};

export { editorValidations, validate, validateEditorInput };