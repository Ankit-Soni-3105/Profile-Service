import { validationResult } from 'express-validator';
import { ApiError } from '../services/apierrors.service.js';
import { logger } from '../utils/logger.js';

export const validateRequest = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        logger.warn('Validation errors in request', { errors: errors.array(), path: req.path });
        throw new ApiError(400, 'Validation failed', errors.array());
    }
    next();
};