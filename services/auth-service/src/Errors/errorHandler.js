import logger from '../config/logger.js';
import ApiError from '../utils/apiError.js';

/**
 * Global Error Handler Middleware
 * Handles all types of errors and sends standardized error responses
 */
const errorHandler = (err, req, res, next) => {
    let error = err;

    // Convert non-ApiError instances to ApiError
    if (!(error instanceof ApiError)) {
        const statusCode = error.statusCode || error.status || 500;
        const message = error.message || "Something went wrong";
        error = new ApiError(statusCode, message, error.errors || [], err.stack);
    }

    // Comprehensive error logging
    const errorLog = {
        message: error.message,
        statusCode: error.statusCode,
        stack: error.stack,
        url: req.originalUrl,
        method: req.method,
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent'),
        userId: req.user?.id || req.user?._id || 'Anonymous',
        timestamp: new Date().toISOString(),
        headers: req.headers,
        body: req.method !== 'GET' ? req.body : undefined,
        query: req.query,
        params: req.params
    };

    // Log based on severity
    if (error.statusCode >= 500) {
        logger.error('Server Error', errorLog);
    } else if (error.statusCode >= 400) {
        logger.warn('Client Error', errorLog);
    } else {
        logger.info('Error Info', errorLog);
    }

    // Handle specific error types
    if (error.name === "ValidationError") {
        const errorMessage = Object.values(error.errors).map(val => val.message);
        error = ApiError.badRequest("Validation Error", errorMessage);
    }

    // MongoDB duplicate key error
    if (error.code === 11000) {
        const duplicateFields = Object.keys(error.keyValue || {});
        const message = `Duplicate field value: ${duplicateFields.join(', ')}`;
        error = ApiError.conflict(message);
    }

    // MongoDB cast error
    if (error.name === "CastError") {
        const message = `Invalid ${error.path}: ${error.value}`;
        error = ApiError.badRequest(message);
    }

    // JWT errors
    if (error.name === "JsonWebTokenError") {
        error = ApiError.unauthorized("Invalid token");
    }

    if (error.name === "TokenExpiredError") {
        error = ApiError.unauthorized("Token expired");
    }

    // Rate limiting error
    if (error.status === 429 || error.statusCode === 429) {
        error = ApiError.tooManyRequests("Too many requests, please try again later");
    }

    // Multer errors
    if (error.code === 'LIMIT_FILE_SIZE') {
        error = ApiError.badRequest("File too large");
    }

    if (error.code === 'LIMIT_FILE_COUNT') {
        error = ApiError.badRequest("Too many files");
    }

    if (error.code === 'LIMIT_UNEXPECTED_FILE') {
        error = ApiError.badRequest("Unexpected file field");
    }

    // Redis errors
    if (error.name === 'RedisError' || error.message?.includes('Redis')) {
        logger.error('Redis Error', { error: error.message, stack: error.stack });
        error = ApiError.serviceUnavailable("Cache service temporarily unavailable");
    }

    // Database connection errors
    if (error.name === 'MongoNetworkError' || error.name === 'MongooseServerSelectionError') {
        logger.error('Database Connection Error', { error: error.message, stack: error.stack });
        error = ApiError.serviceUnavailable("Database service temporarily unavailable");
    }

    // Prepare error response
    const errorResponse = {
        success: false,
        statusCode: error.statusCode,
        message: error.message,
        errors: error.errors.length > 0 ? error.errors : undefined,
        timestamp: error.timestamp,
        path: req.originalUrl,
        method: req.method,
        ...(process.env.NODE_ENV === 'development' && {
            stack: error.stack,
            details: {
                name: error.name,
                code: error.code
            }
        })
    };

    // Send error response
    res.status(error.statusCode).json(errorResponse);
};

export default errorHandler;