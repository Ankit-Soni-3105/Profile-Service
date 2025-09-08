/**
 * Async Handler Utility
 * Wraps async functions to automatically catch errors and pass them to error middleware
 * @param {Function} requestHandler - Async function to wrap
 * @returns {Function} Wrapped function with error handling
 */
const asyncHandler = (requestHandler) => {
    return (req, res, next) => {
        Promise.resolve(requestHandler(req, res, next)).catch((err) => {
            // Log the error for debugging
            console.error(`AsyncHandler Error: ${err.message}`);
            next(err);
        });
    };
};

export default asyncHandler;