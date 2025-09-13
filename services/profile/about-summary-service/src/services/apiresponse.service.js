// utils/response.js
import { logger } from '../utils/logger.js';
import { metricsCollector } from '../utils/metrics.js';

export class ApiResponse {
    static success(res, data, status = 200) {
        logger.info('API success response', { status, path: res.req.path });
        metricsCollector.increment('api.response', { status });
        return res.status(status).json({
            success: true,
            ...data,
        });
    }

    static error(res, message, status = 500, details = {}) {
        logger.error('API error response', { status, message, path: res.req.path, details });
        metricsCollector.increment('api.response', { status });
        return res.status(status).json({
            success: false,
            message,
            details,
        });
    }
}