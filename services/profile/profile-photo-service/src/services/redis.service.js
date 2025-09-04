import redis from 'ioredis';
import config from '../config/config.js'; // REDIS_CLUSTER_NODES = 'redis-node-1:7001,...'

// Redis cluster configuration with retry strategy and connection options
const redisClient = new redis.Cluster({
    rootNodes: config.REDIS_CLUSTER_NODES.split(',').map(node => ({ url: `redis://${node}` })),
    defaults: {
        retryStrategy: (times) => {
            const delay = Math.min(times * 100, 3000); // Max delay 3s
            return delay;
        },  
        maxRetriesPerRequest: 3, // Retry 3 times per request
        enableReadyCheck: true, // Wait for cluster to be ready
    },
});

// Event handlers for connection management
redisClient.on('error', (err) => {
    console.error('Redis Cluster Error:', err.message);
});

redisClient.on('connect', () => console.log('ℹ️ Redis Cluster connecting...'));
redisClient.on('ready', () => console.log('✅ Redis Cluster connected (Profile Service)'));
redisClient.on('end', () => console.log('🔴 Redis Cluster disconnected'));

// Async connection setup with retry
export const connectCache = async (maxRetries = 5) => {
    let attempts = 0;
    while (attempts < maxRetries) {
        try {
            await redisClient.connect();
            return; // Success
        } catch (error) {
            attempts++;
            console.error(`Redis connection attempt ${attempts} failed: ${error.message}`);
            if (attempts === maxRetries) throw error;
            await new Promise(resolve => setTimeout(resolve, 2000 * attempts)); // Exponential backoff
        }
    }
};

// Cache set with error handling and logging
export const setCache = async (key, value, ttl = 3600) => {
    try {
        const stringValue = typeof value === 'string' ? value : JSON.stringify(value);
        await redisClient.set(key, stringValue, { EX: ttl });
        console.log(`Cache set for key: ${key} with TTL: ${ttl}s`);
    } catch (error) {
        console.error(`Failed to set cache for key ${key}: ${error.message}`);
        throw error; // Propagate error for handling
    }
};

// Cache get with error handling and JSON parsing
export const getCache = async (key) => {
    try {
        const data = await redisClient.get(key);
        if (data) {
            console.log(`Cache hit for key: ${key}`);
            return JSON.parse(data);
        }
        console.log(`Cache miss for key: ${key}`);
        return null;
    } catch (error) {
        console.error(`Failed to get cache for key ${key}: ${error.message}`);
        throw error; // Propagate error for handling
    }
};

// Graceful disconnection
export const disconnectCache = async () => {
    try {
        await redisClient.quit();
        console.log('🔴 Redis Cluster disconnected gracefully');
    } catch (error) {
        console.error('Error during Redis disconnection:', error.message);
    }
};

// Export client for advanced usage if needed
export { redisClient };
