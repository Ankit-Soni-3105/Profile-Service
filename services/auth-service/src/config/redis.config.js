import Redis from 'ioredis';
import logger from './logger.js';

/**
 * Redis Configuration and Connection
 * Handles Redis connection with retry logic and error handling
 */
class RedisClient {
    constructor() {
        this.client = null;
        this.isConnected = false;
        this.retryAttempts = 0;
        this.maxRetries = 5;
        this.retryDelay = 2000;

        this.connect();
    }

    connect() {
        try {
            const redisConfig = {
                host: process.env.REDIS_HOST || 'localhost',
                port: process.env.REDIS_PORT || 6379,
                password: process.env.REDIS_PASSWORD || undefined,
                db: process.env.REDIS_DB || 0,
                retryDelayOnFailover: 100,
                enableReadyCheck: true,
                showFriendlyErrorStack: true,
                lazyConnect: true,
                maxRetriesPerRequest: 3,
                retryDelayOnClusterDown: 300,
                enableOfflineQueue: false,
                connectTimeout: 10000,
                commandTimeout: 5000,
                family: 4, // IPv4
            };

            // Add cluster configuration if cluster mode is enabled
            if (process.env.REDIS_CLUSTER_ENABLED === 'true') {
                const clusterNodes = process.env.REDIS_CLUSTER_NODES?.split(',') || [];
                this.client = new Redis.Cluster(clusterNodes, {
                    redisOptions: redisConfig,
                    enableOfflineQueue: false
                });
            } else {
                this.client = new Redis(redisConfig);
            }

            this.setupEventListeners();

            // Connect to Redis
            this.client.connect().catch(error => {
                logger.error('Failed to connect to Redis', { error: error.message });
                this.handleConnectionError(error);
            });

        } catch (error) {
            logger.error('Redis client initialization failed', { error: error.message });
            this.handleConnectionError(error);
        }
    }

    setupEventListeners() {
        this.client.on('connect', () => {
            logger.info('Redis client connected');
            this.isConnected = true;
            this.retryAttempts = 0;
        });

        this.client.on('ready', () => {
            logger.info('Redis client ready');
            this.isConnected = true;
        });

        this.client.on('error', (error) => {
            logger.error('Redis client error', { error: error.message });
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
    }

    handleConnectionError(error) {
        if (this.retryAttempts < this.maxRetries) {
            this.retryAttempts++;
            const delay = this.retryDelay * this.retryAttempts;

            logger.warn(`Redis connection retry ${this.retryAttempts}/${this.maxRetries} in ${delay}ms`);

            setTimeout(() => {
                this.connect();
            }, delay);
        } else {
            logger.error('Max Redis connection retries reached. Operating without cache.');
        }
    }

    // Wrapper methods with error handling
    async get(key) {
        try {
            if (!this.isConnected) {
                logger.warn('Redis not connected, skipping cache get');
                return null;
            }

            const result = await this.client.get(key);
            logger.cache('Cache GET', { key, hit: !!result });
            return result;
        } catch (error) {
            logger.error('Redis GET error', { key, error: error.message });
            return null;
        }
    }

    async set(key, value, ttl = 3600) {
        try {
            if (!this.isConnected) {
                logger.warn('Redis not connected, skipping cache set');
                return false;
            }

            const result = await this.client.setex(key, ttl, value);
            logger.cache('Cache SET', { key, ttl, success: result === 'OK' });
            return result === 'OK';
        } catch (error) {
            logger.error('Redis SET error', { key, error: error.message });
            return false;
        }
    }

    async setex(key, ttl, value) {
        return this.set(key, value, ttl);
    }

    async del(key) {
        try {
            if (!this.isConnected) {
                logger.warn('Redis not connected, skipping cache delete');
                return 0;
            }

            const result = await this.client.del(key);
            logger.cache('Cache DELETE', { key, deleted: result });
            return result;
        } catch (error) {
            logger.error('Redis DELETE error', { key, error: error.message });
            return 0;
        }
    }

    async exists(key) {
        try {
            if (!this.isConnected) return false;

            const result = await this.client.exists(key);
            return result === 1;
        } catch (error) {
            logger.error('Redis EXISTS error', { key, error: error.message });
            return false;
        }
    }

    async expire(key, ttl) {
        try {
            if (!this.isConnected) return false;

            const result = await this.client.expire(key, ttl);
            return result === 1;
        } catch (error) {
            logger.error('Redis EXPIRE error', { key, error: error.message });
            return false;
        }
    }

    async flushall() {
        try {
            if (!this.isConnected) return false;

            await this.client.flushall();
            logger.cache('Cache FLUSH ALL');
            return true;
        } catch (error) {
            logger.error('Redis FLUSHALL error', { error: error.message });
            return false;
        }
    }

    async keys(pattern = '*') {
        try {
            if (!this.isConnected) return [];

            const keys = await this.client.keys(pattern);
            return keys;
        } catch (error) {
            logger.error('Redis KEYS error', { pattern, error: error.message });
            return [];
        }
    }

    // Hash operations
    async hget(key, field) {
        try {
            if (!this.isConnected) return null;

            const result = await this.client.hget(key, field);
            return result;
        } catch (error) {
            logger.error('Redis HGET error', { key, field, error: error.message });
            return null;
        }
    }

    async hset(key, field, value) {
        try {
            if (!this.isConnected) return false;

            const result = await this.client.hset(key, field, value);
            return result >= 0;
        } catch (error) {
            logger.error('Redis HSET error', { key, field, error: error.message });
            return false;
        }
    }
    async hdel(key, field) {
        try {
            if (!this.isConnected) return false;
            const result = await this.client.hdel(key, field);
            return result;
        } catch (error) {
            logger.error('Redis HDEL error', { key, field, error: error.message });
            return false;
        }
    }

    async hgetall(key) {
        try {
            if (!this.isConnected) return null;
            const result = await this.client.hgetall(key);
            return result;
        } catch (error) {
            logger.error('Redis HGETALL error', { key, error: error.message });
            return null;
        }
    }
}

export default new RedisClient();