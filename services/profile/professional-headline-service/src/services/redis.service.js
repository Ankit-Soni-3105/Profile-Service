import Redis from 'ioredis';
import { logger } from '../utils/logger.js';
import ApiError from '../services/apierrors.service.js';

/**
 * Optimized Redis Service for High-Scale Applications
 * Supports clustering, batch operations, and comprehensive error handling
 */
class RedisService {
    constructor() {
        this.client = null;
        this.isConnected = false;
        this.retryAttempts = 0;
        this.maxRetries = parseInt(process.env.REDIS_MAX_RETRIES) || 5;
        this.baseRetryDelay = parseInt(process.env.REDIS_RETRY_DELAY) || 2000;
        this.maxConnections = parseInt(process.env.REDIS_MAX_CONNECTIONS) || 100;

        this.initialize();
    }

    async initialize() {
        try {
            const redisConfig = {
                retryStrategy: (times) => {
                    const delay = Math.min(times * this.baseRetryDelay, 10000);
                    logger.warn('Redis retry attempt', {
                        attempt: times,
                        delay: `${delay}ms`,
                        maxRetries: this.maxRetries,
                        pid: process.pid,
                    });
                    return delay;
                },
                maxRetriesPerRequest: 3,
                enableReadyCheck: true,
                lazyConnect: true,
                connectTimeout: parseInt(process.env.REDIS_CONNECT_TIMEOUT) || 10000,
                commandTimeout: parseInt(process.env.REDIS_COMMAND_TIMEOUT) || 5000,
                socket: {
                    keepAlive: 1000,
                    reconnectOnError: (err) => err.message.includes('READONLY'),
                },
                enableOfflineQueue: false,
                showFriendlyErrorStack: process.env.NODE_ENV === 'development',
                maxClients: this.maxConnections,
            };

            // Cluster configuration
            if (process.env.REDIS_CLUSTER_ENABLED === 'true') {
                const clusterNodes = (process.env.REDIS_CLUSTER_NODES || 'localhost:6379')
                    .split(',')
                    .map((node) => {
                        const [host, port] = node.trim().split(':');
                        return { host, port: parseInt(port) || 6379 };
                    });
                this.client = new Redis.Cluster(clusterNodes, {
                    redisOptions: {
                        ...redisConfig,
                        password: process.env.REDIS_PASSWORD,
                    },
                    enableOfflineQueue: false,
                    scaleReads: 'slave',
                    maxRedirections: 16,
                });
                logger.info('Redis Cluster client initialized', { nodes: clusterNodes.length, pid: process.pid });
            } else {
                this.client = new Redis({
                    ...redisConfig,
                    host: process.env.REDIS_HOST || 'localhost',
                    port: parseInt(process.env.REDIS_PORT) || 6379,
                    password: process.env.REDIS_PASSWORD,
                    db: parseInt(process.env.REDIS_DB) || 0,
                });
                logger.info('Redis single instance client initialized', { pid: process.pid });
            }

            this.setupEventHandlers();
            await this.connect();
        } catch (error) {
            logger.error('Redis initialization failed', {
                error: error.message,
                stack: error.stack,
                pid: process.pid,
            });
            throw new ApiError(500, 'Redis initialization failed');
        }
    }

    setupEventHandlers() {
        this.client.on('connect', () => {
            logger.info('Redis client connecting', { pid: process.pid });
        });

        this.client.on('ready', () => {
            logger.info('Redis client ready and connected', { pid: process.pid });
            this.isConnected = true;
            this.retryAttempts = 0;
        });

        this.client.on('error', (error) => {
            logger.error('Redis client error', {
                message: error.message,
                code: error.code,
                errno: error.errno,
                stack: error.stack,
                pid: process.pid,
            });
            this.isConnected = false;
        });

        this.client.on('close', () => {
            logger.warn('Redis connection closed', { pid: process.pid });
            this.isConnected = false;
        });

        this.client.on('reconnecting', (time) => {
            logger.info('Redis client reconnecting', { delay: `${time}ms`, pid: process.pid });
        });

        this.client.on('end', () => {
            logger.warn('Redis connection ended', { pid: process.pid });
            this.isConnected = false;
        });

        if (this.client.isCluster) {
            this.client.on('node error', (error, node) => {
                logger.error('Redis cluster node error', {
                    error: error.message,
                    node: `${node.options.host}:${node.options.port}`,
                    stack: error.stack,
                    pid: process.pid,
                });
            });
        }
    }

    async connect(maxRetries = this.maxRetries) {
        let attempts = 0;
        while (attempts < maxRetries) {
            try {
                await this.client.connect();
                logger.info('Redis connection established successfully', { pid: process.pid });
                return;
            } catch (error) {
                attempts++;
                this.retryAttempts = attempts;
                logger.error('Redis connection attempt failed', {
                    attempt: attempts,
                    maxRetries,
                    message: error.message,
                    code: error.code,
                    pid: process.pid,
                });
                if (attempts === maxRetries) {
                    logger.error('Max Redis connection retries reached', { pid: process.pid });
                    throw new ApiError(500, 'Failed to connect to Redis after max retries');
                }
                const delay = this.baseRetryDelay * Math.pow(2, attempts);
                await new Promise((resolve) => setTimeout(resolve, delay));
            }
        }
    }

    // Health check with detailed metrics
    async healthCheck() {
        try {
            if (!this.isConnected) return { healthy: false, message: 'Redis not connected' };
            const start = Date.now();
            const result = await this.client.ping();
            const latency = Date.now() - start;
            const info = await this.client.info('memory');
            const memoryUsed = info.match(/used_memory:(\d+)/)?.[1] || 'N/A';
            return {
                healthy: result === 'PONG',
                latency: `${latency}ms`,
                memoryUsed: memoryUsed,
                connected: this.isConnected,
            };
        } catch (error) {
            logger.error('Redis health check failed', {
                error: error.message,
                pid: process.pid,
            });
            return { healthy: false, message: error.message };
        }
    }

    // Redis operations
    async get(key) {
        if (!this.isConnected) {
            logger.warn('Redis not connected, skipping cache GET', { key, pid: process.pid });
            return null;
        }
        try {
            if (!this.validateKey(key)) throw new ApiError(400, 'Invalid cache key');
            const start = Date.now();
            const data = await this.client.get(key);
            logger.cache('Cache GET', {
                key,
                hit: !!data,
                latency: `${Date.now() - start}ms`,
                pid: process.pid,
            });
            return data ? JSON.parse(data) : null;
        } catch (error) {
            logger.error('Redis GET operation failed', {
                key,
                error: error.message,
                pid: process.pid,
            });
            return null;
        }
    }

    async setEx(key, value, ttl = 3600) {
        if (!this.isConnected) {
            logger.warn('Redis not connected, skipping cache SET', { key, pid: process.pid });
            return false;
        }
        try {
            if (!this.validateKey(key)) throw new ApiError(400, 'Invalid cache key');
            if (!this.validateTTL(ttl)) throw new ApiError(400, 'Invalid TTL');
            const stringValue = typeof value === 'string' ? value : JSON.stringify(value);
            const start = Date.now();
            const result = await this.client.setex(key, ttl, stringValue);
            logger.cache('Cache SET', {
                key,
                ttl,
                success: result === 'OK',
                latency: `${Date.now() - start}ms`,
                pid: process.pid,
            });
            return result === 'OK';
        } catch (error) {
            logger.error('Redis SET operation failed', {
                key,
                ttl,
                error: error.message,
                pid: process.pid,
            });
            return false;
        }
    }

    async del(key) {
        if (!this.isConnected) {
            logger.warn('Redis not connected, skipping cache DELETE', { key, pid: process.pid });
            return 0;
        }
        try {
            if (!this.validateKey(key)) throw new ApiError(400, 'Invalid cache key');
            const start = Date.now();
            const result = await this.client.del(key);
            logger.cache('Cache DELETE', {
                key,
                deleted: result,
                latency: `${Date.now() - start}ms`,
                pid: process.pid,
            });
            return result;
        } catch (error) {
            logger.error('Redis DELETE operation failed', {
                key,
                error: error.message,
                pid: process.pid,
            });
            return 0;
        }
    }

    async exists(key) {
        if (!this.isConnected) return false;
        try {
            if (!this.validateKey(key)) return false;
            const start = Date.now();
            const result = await this.client.exists(key);
            logger.cache('Cache EXISTS', {
                key,
                exists: result === 1,
                latency: `${Date.now() - start}ms`,
                pid: process.pid,
            });
            return result === 1;
        } catch (error) {
            logger.error('Redis EXISTS operation failed', {
                key,
                error: error.message,
                pid: process.pid,
            });
            return false;
        }
    }

    async keys(pattern = '*', limit = 1000) {
        if (!this.isConnected) {
            logger.warn('Redis not connected, skipping SCAN', { pattern, pid: process.pid });
            return [];
        }
        try {
            const start = Date.now();
            const keys = [];
            const stream = this.client.scanStream({ match: pattern, count: 100 });
            return new Promise((resolve, reject) => {
                stream.on('data', (resultKeys) => {
                    keys.push(...resultKeys);
                    if (keys.length >= limit) {
                        stream.destroy();
                        resolve(keys.slice(0, limit));
                    }
                });
                stream.on('end', () => {
                    logger.cache('Cache SCAN completed', {
                        pattern,
                        keyCount: keys.length,
                        latency: `${Date.now() - start}ms`,
                        pid: process.pid,
                    });
                    resolve(keys);
                });
                stream.on('error', (error) => {
                    logger.error('Redis SCAN operation failed', {
                        pattern,
                        error: error.message,
                        pid: process.pid,
                    });
                    reject(new ApiError(500, 'Redis SCAN failed'));
                });
            });
        } catch (error) {
            logger.error('Redis KEYS operation failed', {
                pattern,
                error: error.message,
                pid: process.pid,
            });
            return [];
        }
    }

    async pipeline(commands) {
        if (!this.isConnected) {
            logger.warn('Redis not connected, skipping pipeline', { pid: process.pid });
            return [];
        }
        try {
            const start = Date.now();
            const pipeline = this.client.pipeline();
            commands.forEach(({ method, args }) => pipeline[method](...args));
            const results = await pipeline.exec();
            logger.cache('Pipeline executed', {
                commandCount: commands.length,
                latency: `${Date.now() - start}ms`,
                pid: process.pid,
            });
            return results;
        } catch (error) {
            logger.error('Redis pipeline error', {
                error: error.message,
                commandCount: commands.length,
                pid: process.pid,
            });
            return [];
        }
    }

    validateKey(key) {
        return key && typeof key === 'string' && key.trim().length > 0;
    }

    validateTTL(ttl) {
        return Number.isInteger(ttl) && ttl > 0;
    }

    getStatus() {
        return {
            connected: this.isConnected,
            retryAttempts: this.retryAttempts,
            maxRetries: this.maxRetries,
            isCluster: this.client?.isCluster || false,
            maxConnections: this.maxConnections,
        };
    }

    async disconnect() {
        try {
            if (this.client) {
                await this.client.quit();
                logger.info('Redis client disconnected gracefully', { pid: process.pid });
                this.isConnected = false;
            }
        } catch (error) {
            logger.error('Redis disconnection error', {
                error: error.message,
                pid: process.pid,
            });
            this.client?.disconnect();
        }
    }
}

export default new RedisService();