import { body, param, query } from 'express-validator';
import { isValidObjectId } from 'mongoose';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { validationResult } from 'express-validator';

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

const backupValidations = {
    createBackup: [
        // Validate params
        validateObjectId('userId'),
        validateObjectId('summaryId'),

        // Validate body
        body('notes')
            .optional()
            .trim()
            .isLength({ max: 1000 }).withMessage('Notes must not exceed 1000 characters'),

        // Custom sanitizer
        body('*').trim().escape()
    ],

    restoreBackup: [
        // Validate params
        validateObjectId('userId'),
        validateObjectId('backupId'),

        // Validate body
        body('merge')
            .optional()
            .isBoolean().withMessage('merge must be a boolean'),

        // Custom sanitizer
        body('*').trim().escape()
    ],

    getBackups: [
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

        // Custom sanitizer
        query('*').trim().escape()
    ],

    deleteBackup: [
        // Validate params
        validateObjectId('userId'),
        validateObjectId('backupId'),
    ],

    bulkCreateBackups: [
        // Validate params
        validateObjectId('userId'),

        // Validate body
        body('summaryIds')
            .isArray({ min: 1, max: 100 }).withMessage('summaryIds must be an array with 1-100 items')
            .custom((ids) => {
                if (!ids.every(id => isValidObjectId(id))) {
                    throw new AppError('All summaryIds must be valid ObjectIds', 400);
                }
                return true;
            }).withMessage('All summaryIds must be valid ObjectIds'),

        body('notes')
            .optional()
            .trim()
            .isLength({ max: 1000 }).withMessage('Notes must not exceed 1000 characters'),

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

export { backupValidations, validate };