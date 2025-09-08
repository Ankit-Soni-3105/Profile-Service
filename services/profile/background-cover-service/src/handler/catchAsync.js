import { logger } from './logger.js';

export const catchAsync = (fn) => {
    return (req, res, next) => {
        try {
            const result = fn(req, res, next);
            if (result && typeof result.then === 'function') {
                result.catch(err => {
                    logger.error('Async error in controller', { error: err.message, stack: err.stack });
                    next(err);
                });
            }
        } catch (err) {
            logger.error('Sync error in controller', { error: err.message, stack: err.stack });
            next(err);
        }
    };
};