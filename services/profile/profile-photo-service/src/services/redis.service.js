import Redis from 'ioredis';
import config from '../config/config.js';
import { logger } from '../utils/logger.js'; // Use structured logger

// Redis cluster configuration with retry strategy and connection options
const redisClient = new Redis.Cluster({
    rootNodes: config.REDIS_CLUSTER_NODES.split(',').map(node => ({ url: `redis://${node.trim()}` })),
    defaults: {
        retryStrategy: (times) => {
            const delay = Math.min(times * 100, 3000); // Max delay 3s
            return delay;
        },
        maxRetriesPerRequest: 3,
        enableReadyCheck: true,
        socket: {
            connectTimeout: 10000, // 10s timeout
            keepAlive: 1000, // Keep-alive every 1s
        },
    },
});

// Event handlers for connection management
redisClient.on('error', (err) => {
    logger.error('Redis Cluster Error:', { message: err.message, stack: err.stack });
});

redisClient.on('connect', () => logger.info('Redis Cluster connecting...'));
redisClient.on('ready', () => logger.info('Redis Cluster connected (Profile Service)'));
redisClient.on('end', () => logger.warn('Redis Cluster disconnected'));

// Async connection setup with retry
export const connectCache = async (maxRetries = 5) => {
    let attempts = 0;
    while (attempts < maxRetries) {
        try {
            await redisClient.connect();
            logger.info('Redis Cluster connection established');
            return;
        } catch (error) {
            attempts++;
            logger.error(`Redis connection attempt ${attempts} failed`, { message: error.message });
            if (attempts === maxRetries) {
                throw new Error(`Failed to connect to Redis after ${maxRetries} attempts: ${error.message}`);
            }
            await new Promise(resolve => setTimeout(resolve, 2000 * attempts));
        }
    }
};

// Health check for Redis cluster
export const isHealthy = async () => {
    try {
        await redisClient.ping();
        return true;
    } catch (error) {
        logger.error('Redis health check failed', { message: error.message });
        return false;
    }
};

// Cache set with error handling and TTL validation
export const setCache = async (key, value, ttl = 3600) => {
    try {
        if (!key || typeof key !== 'string') {
            throw new Error('Invalid cache key');
        }
        if (!Number.isInteger(ttl) || ttl <= 0) {
            throw new Error('TTL must be a positive integer');
        }
        const stringValue = typeof value === 'string' ? value : JSON.stringify(value);
        await redisClient.set(key, stringValue, { EX: ttl });
        logger.info(`Cache set for key: ${key}`, { ttl });
    } catch (error) {
        logger.error(`Failed to set cache for key ${key}`, { message: error.message });
        throw error;
    }
};

// Cache get with error handling and JSON parsing
export const getCache = async (key) => {
    try {
        if (!key || typeof key !== 'string') {
            throw new Error('Invalid cache key');
        }
        const data = await redisClient.get(key);
        if (data) {
            logger.info(`Cache hit for key: ${key}`);
            try {
                return JSON.parse(data);
            } catch (parseError) {
                logger.error(`Failed to parse cache data for key ${key}`, { message: parseError.message });
                return data; // Return raw data if parsing fails
            }
        }
        logger.info(`Cache miss for key: ${key}`);
        return null;
    } catch (error) {
        logger.error(`Failed to get cache for key ${key}`, { message: error.message });
        throw error;
    }
};

// Cache delete with error handling
export const deleteCache = async (key) => {
    try {
        if (!key || typeof key !== 'string') {
            throw new Error('Invalid cache key');
        }
        await redisClient.del(key);
        logger.info(`Cache deleted for key: ${key}`);
    } catch (error) {
        logger.error(`Failed to delete cache for key ${key}`, { message: error.message });
        throw error;
    }
};

// Graceful disconnection
export const disconnectCache = async () => {
    try {
        await redisClient.quit();
        logger.info('Redis Cluster disconnected gracefully');
    } catch (error) {
        logger.error('Error during Redis disconnection', { message: error.message });
        throw error;
    }
};

// Export client for advanced usage
export { redisClient };