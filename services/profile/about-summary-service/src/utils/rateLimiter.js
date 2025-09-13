// utils/rateLimiter.js
import rateLimit from 'express-rate-limit'; // Requires 'express-rate-limit' (npm install express-rate-limit)
import RedisStore from 'rate-limit-redis'; // Requires 'rate-limit-redis' (npm install rate-limit-redis)
import redisService from '../services/redis.service.js'; // Use the combined RedisService
import { logger } from './logger.js';
import { metricsCollector } from './metrics.js';

export const createRateLimiter = (options) => {
    const {
        windowMs = 15 * 60 * 1000, // Default 15 min
        max = 100, // Default max requests
        skipSuccessfulRequests = false,
        keyGenerator = (req) => req.ip, // Default by IP
        message = 'Too many requests, please try again later.',
        statusCode = 429,
    } = options;

    const limiter = rateLimit({
        windowMs,
        max,
        message,
        statusCode,
        skipSuccessfulRequests,
        keyGenerator,
        store: new RedisStore({
            sendCommand: (...args) => redisService.client.call(...args), // Integrate with RedisService
            prefix: 'rate_limit:',
        }),
        handler: (req, res, next, options) => {
            logger.warn('Rate limit exceeded', { ip: req.ip, path: req.path });
            metricsCollector.increment('rate_limit.exceeded', { path: req.path });
            res.status(options.statusCode).send(options.message);
        },
    });

    logger.info('Rate limiter created', { windowMs, max, skipSuccessful: skipSuccessfulRequests });
    return limiter;
};