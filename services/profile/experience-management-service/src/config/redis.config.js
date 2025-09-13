import Redis from 'ioredis';
import ApiError from '../services/apierrors.service.js';
import { logger } from '../utils/logger.js';
import config from './config.js';

/**
 * Optimized Redis Client for High-Scale Applications
 * Supports clustering, connection pooling, and advanced error handling
 */
class RedisClient {
    constructor() {
        this.client = null;
        this.isConnected = false;
        this.retryAttempts = 0;
        this.maxRetries = config.redis.maxRetries;
        this.baseRetryDelay = config.redis.retryDelay;
        this.maxConnections = config.redis.maxConnections;

        this.connect();
    }

    async connect() {
        try {
            const redisConfig = {
                host: config.redis.host,
                port: config.redis.port,
                password: config.redis.password || undefined,
                db: config.redis.db,
                maxRetriesPerRequest: 3,
                retryStrategy: (times) => {
                    const delay = Math.min(times * this.baseRetryDelay, 10000);
                    logger.warn(`Redis retry attempt ${times}/${this.maxRetries}, delay: ${delay}ms`);
                    return delay;
                },
                enableReadyCheck: true,
                showFriendlyErrorStack: config.app.nodeEnv === 'development',
                lazyConnect: true,
                connectTimeout: config.redis.connectTimeout,
                commandTimeout: config.redis.commandTimeout,
                maxClients: this.maxConnections,
                enableOfflineQueue: false,
            };

            // Cluster configuration
            if (config.redis.clusterEnabled) {
                const clusterNodes = config.redis.clusterNodes.map((node) => {
                    const [host, port] = node.trim().split(':');
                    return { host, port: parseInt(port) };
                });
                this.client = new Redis.Cluster(clusterNodes, {
                    redisOptions: redisConfig,
                    scaleReads: 'slave',
                    maxRedirections: 16,
                });
                logger.info('Redis Cluster initialized', { nodes: clusterNodes.length });
            } else {
                this.client = new Redis(redisConfig);
                logger.info('Redis single instance initialized');
            }

            this.setupEventListeners();
            await this.client.connect();
            logger.info('Redis connection established');
            this.isConnected = true;
            this.retryAttempts = 0;
        } catch (error) {
            logger.error('Redis client initialization failed', {
                error: error.message,
                stack: error.stack,
            });
            this.handleConnectionError(error);
        }
    }

    setupEventListeners() {
        this.client.on('connect', () => {
            logger.info('Redis client connected');
            this.isConnected = true;
        });

        this.client.on('ready', () => {
            logger.info('Redis client ready');
            this.isConnected = true;
        });

        this.client.on('error', (error) => {
            logger.error('Redis client error', {
                error: error.message,
                code: error.code,
                stack: error.stack,
            });
            this.isConnected = false;
            this.handleConnectionError(error);
        });

        this.client.on('close', () => {
            logger.warn('Redis connection closed');
            this.isConnected = false;
        });

        this.client.on('reconnecting', (time) => {
            logger.info(`Redis client reconnecting in ${time}ms`);
        });

        this.client.on('end', () => {
            logger.warn('Redis connection ended');
            this.isConnected = false;
        });

        if (this.client.isCluster) {
            this.client.on('node error', (error, node) => {
                logger.error('Redis cluster node error', {
                    error: error.message,
                    node: `${node.options.host}:${node.options.port}`,
                });
            });
        }
    }

    handleConnectionError(error) {
        if (this.retryAttempts < this.maxRetries) {
            this.retryAttempts++;
            const delay = this.baseRetryDelay * Math.pow(2, this.retryAttempts);
            logger.warn(`Redis connection retry ${this.retryAttempts}/${this.maxRetries} in ${delay}ms`);
            setTimeout(() => this.connect(), delay);
        } else {
            logger.error('Max Redis connection retries reached. Operating without cache.');
            throw new ApiError(500, 'Failed to connect to Redis after max retries');
        }
    }

    // Optimized Redis operations
    async get(key) {
        if (!this.isConnected) {
            logger.warn('Redis not connected, skipping cache get', { key });
            return null;
        }
        try {
            const result = await this.client.get(key);
            logger.cache('Cache GET', { key, hit: !!result });
            return result ? JSON.parse(result) : null;
        } catch (error) {
            logger.error('Redis GET error', { key, error: error.message });
            return null;
        }
    }

    async setEx(key, value, ttl = 3600) {
        if (!this.isConnected) {
            logger.warn('Redis not connected, skipping cache set', { key });
            return false;
        }
        try {
            const stringValue = typeof value === 'string' ? value : JSON.stringify(value);
            const result = await this.client.setex(key, ttl, stringValue);
            logger.cache('Cache SET', { key, ttl, success: result === 'OK' });
            return result === 'OK';
        } catch (error) {
            logger.error('Redis SET error', { key, ttl, error: error.message });
            return false;
        }
    }

    async del(key) {
        if (!this.isConnected) {
            logger.warn('Redis not connected, skipping cache delete', { key });
            return 0;
        }
        try {
            const result = await this.client.del(key);
            logger.cache('Cache DELETE', { key, deleted: result });
            return result;
        } catch (error) {
            logger.error('Redis DELETE error', { key, error: error.message });
            return 0;
        }
    }

    async exists(key) {
        if (!this.isConnected) return false;
        try {
            const result = await this.client.exists(key);
            return result === 1;
        } catch (error) {
            logger.error('Redis EXISTS error', { key, error: error.message });
            return false;
        }
    }

    async pipeline(commands) {
        if (!this.isConnected) {
            logger.warn('Redis not connected, skipping pipeline');
            return [];
        }
        try {
            const pipeline = this.client.pipeline();
            commands.forEach(({ method, args }) => pipeline[method](...args));
            const results = await pipeline.exec();
            logger.cache('Pipeline executed', { commandCount: commands.length });
            return results;
        } catch (error) {
            logger.error('Redis pipeline error', { error: error.message });
            return [];
        }
    }

    async healthCheck() {
        try {
            const result = await this.client.ping();
            return result === 'PONG';
        } catch (error) {
            logger.error('Redis health check failed', { error: error.message });
            return false;
        }
    }

    async disconnect() {
        try {
            if (this.client) {
                await this.client.quit();
                logger.info('Redis client disconnected gracefully');
                this.isConnected = false;
            }
        } catch (error) {
            logger.error('Redis disconnection error', { error: error.message });
            this.client?.disconnect();
        }
    }
}

export default new RedisClient();