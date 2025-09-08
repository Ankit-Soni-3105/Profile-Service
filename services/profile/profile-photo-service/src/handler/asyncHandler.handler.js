/**
 * Improved asyncHandler for high scalability and robust error handling.
 * Ensures all errors are caught and passed to the error middleware, even for sync errors.
 * Designed for high concurrency (1M+ users) by minimizing event loop blocking.
 */
export const asyncHandler = (fn) => {
    return function asyncUtilWrap(req, res, next) {
        try {
            const maybePromise = fn(req, res, next);
            // If the handler returns a promise, catch errors
            if (maybePromise && typeof maybePromise.then === 'function') {
                maybePromise.catch((err) => {
                    // Log error for observability in high-scale environments
                    console.error('Async error:', err);
                    next(err);
                });
            }
        } catch (err) {
            // Catch synchronous errors
            console.error('Sync error:', err);
            next(err);
        }
    };
};