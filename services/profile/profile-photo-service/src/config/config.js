import "dotenv/config";
import { logger } from '../utils/logger.js';
import ApiError from '../services/apierrors.service.js';


// Validation helper
const validateEnv = (key, value, type, required = true) => {
  if (required && (value === undefined || value === null)) {
    logger.error(`Missing required environment variable: ${key}`);
    throw new ApiError(500, `Missing required environment variable: ${key}`);
  }
  if (value && type === 'number' && isNaN(parseInt(value))) {
    logger.error(`Invalid ${key}: must be a number, got ${value}`);
    throw new ApiError(500, `Invalid ${key}: must be a number`);
  }
  if (value && type === 'boolean' && !['true', 'false'].includes(value.toLowerCase())) {
    logger.error(`Invalid ${key}: must be true/false, got ${value}`);
    throw new ApiError(500, `Invalid ${key}: must be true/false`);
  }
  return type === 'number' ? parseInt(value) : type === 'boolean' ? value.toLowerCase() === 'true' : value;
};

// Log level validation
const validLogLevels = ['error', 'warn', 'info', 'http', 'verbose', 'debug', 'silly'];
const validateLogLevel = (level) => {
  if (!level || !validLogLevels.includes(level.toLowerCase())) {
    logger.warn(`Invalid LOG_LEVEL: ${level}, defaulting to 'info'`);
    return 'info';
  }
  return level.toLowerCase();
};

// Config object
const _config = {
  app: {
    port: validateEnv('PORT', process.env.PORT, 'number', true),
    nodeEnv: validateEnv('NODE_ENV', process.env.NODE_ENV || 'production', 'string'),
    instanceId: validateEnv('INSTANCE_ID', process.env.INSTANCE_ID, 'number', false) || 1,
    healthCheckInterval: validateEnv('HEALTHCHECK_INTERVAL', process.env.HEALTHCHECK_INTERVAL || '30s', 'string'),
    requireEmailVerification: validateEnv('REQUIRE_EMAIL_VERIFICATION', process.env.REQUIRE_EMAIL_VERIFICATION || 'false', 'boolean', false),
  },
  mongo: {
    uri: validateEnv('MONGO_URI', process.env.MONGO_URI, 'string', true),
    maxPoolSize: validateEnv('MONGO_MAX_POOL_SIZE', process.env.MONGO_MAX_POOL_SIZE || '100', 'number', false) || 100,
    minPoolSize: validateEnv('MONGO_MIN_POOL_SIZE', process.env.MONGO_MIN_POOL_SIZE || '10', 'number', false) || 10,
    serverSelectionTimeoutMS: validateEnv('MONGO_SERVER_SELECTION_TIMEOUT_MS', process.env.MONGO_SERVER_SELECTION_TIMEOUT_MS || '5000', 'number', false) || 5000,
    socketTimeoutMS: validateEnv('MONGO_SOCKET_TIMEOUT_MS', process.env.MONGO_SOCKET_TIMEOUT_MS || '45000', 'number', false) || 45000,
    connectTimeoutMS: validateEnv('MONGO_CONNECT_TIMEOUT_MS', process.env.MONGO_CONNECT_TIMEOUT_MS || '10000', 'number', false) || 10000,
  },
  jwt: {
    secret: validateEnv('JWT_SECRET', process.env.JWT_SECRET, 'string', true),
    expiration: validateEnv('JWT_EXPIRATION', process.env.JWT_EXPIRATION || '1d', 'string'),
    algorithm: validateEnv('JWT_ALG', process.env.JWT_ALG || 'RS256', 'string'),
    privateKeyPath: validateEnv('JWT_PRIVATE_KEY_PATH', process.env.JWT_PRIVATE_KEY_PATH, 'string', false),
  },
  kafka: {
    brokers: validateEnv('KAFKA_BROKERS', process.env.KAFKA_BROKERS, 'string', true).split(','),
    clientId: validateEnv('KAFKA_CLIENT_ID', process.env.KAFKA_CLIENT_ID || 'profile-service', 'string'),
    groupMinSessionTimeoutMs: validateEnv('KAFKA_GROUP_MIN_SESSION_TIMEOUT_MS', process.env.KAFKA_GROUP_MIN_SESSION_TIMEOUT_MS, 'number', false) || 6000,
    groupMaxSessionTimeoutMs: validateEnv('KAFKA_GROUP_MAX_SESSION_TIMEOUT_MS', process.env.KAFKA_GROUP_MAX_SESSION_TIMEOUT_MS, 'number', false) || 300000,
    profileEventsTopic: validateEnv('PROFILE_EVENTS_TOPIC', process.env.PROFILE_EVENTS_TOPIC || 'profile-events', 'string'),
  },
  redis: {
    clusterEnabled: validateEnv('REDIS_CLUSTER_ENABLED', process.env.REDIS_CLUSTER_ENABLED || 'true', 'boolean'),
    clusterNodes: validateEnv('REDIS_CLUSTER_NODES', process.env.REDIS_CLUSTER_NODES, 'string', true).split(','),
    cacheTtl: validateEnv('REDIS_CACHE_TTL', process.env.REDIS_CACHE_TTL, 'number', false) || 3600,
    maxMemory: validateEnv('REDIS_MAXMEMORY', process.env.REDIS_MAXMEMORY || '400mb', 'string'),
    maxRetries: validateEnv('REDIS_MAX_RETRIES', process.env.REDIS_MAX_RETRIES, 'number', false) || 5,
    retryDelay: validateEnv('REDIS_RETRY_DELAY', process.env.REDIS_RETRY_DELAY, 'number', false) || 2000,
    connectTimeout: validateEnv('REDIS_CONNECT_TIMEOUT', process.env.REDIS_CONNECT_TIMEOUT, 'number', false) || 10000,
    commandTimeout: validateEnv('REDIS_COMMAND_TIMEOUT', process.env.REDIS_COMMAND_TIMEOUT, 'number', false) || 5000,
    maxConnections: validateEnv('REDIS_MAX_CONNECTIONS', process.env.REDIS_MAX_CONNECTIONS, 'number', false) || 100,
  },
  logging: {
    level: validateLogLevel(process.env.LOG_LEVEL || 'info'),
    directory: validateEnv('LOG_DIR', process.env.LOG_DIR || '/var/log/profile-service', 'string'),
  },
};

// Freeze the config to prevent modifications
const config = Object.freeze(_config);

// Log loaded configuration (excluding sensitive data)
logger.info('Configuration loaded', {
  app: {
    port: config.app.port,
    nodeEnv: config.app.nodeEnv,
    instanceId: config.app.instanceId
  },
  kafka: {
    clientId: config.kafka.clientId,
    brokersCount: config.kafka.brokers.length
  },
  redis: {
    clusterEnabled: config.redis.clusterEnabled,
    nodesCount: config.redis.clusterNodes.length
  },
  logging: {
    level: config.logging.level
  },
});

export default config;


// const _config = {
//   PORT: process.env.PORT,
//   MONGO_URI: process.env.MONGO_URI,
//   JWT_SECRET: process.env.JWT_SECRET,
//   REDIS_CLUSTER_NODES: process.env.REDIS_CLUSTER_NODES,
//   KAFKA_BROKERS: process.env.KAFKA_BROKERS,
//   KAFKA_GROUP_MIN_SESSION_TIMEOUT_MS: process.env.KAFKA_GROUP_MIN_SESSION_TIMEOUT_MS,
//   KAFKA_GROUP_MAX_SESSION_TIMEOUT_MS: process.env.KAFKA_GROUP_MAX_SESSION_TIMEOUT_MS,
//   KAFKA_CLIENT_ID: process.env.KAFKA_CLIENT_ID,
//   PROFILE_EVENTS_TOPIC: process.env.PROFILE_EVENTS_TOPIC,
//   REDIS_CACHE_TTL: process.env.REDIS_CACHE_TTL,
//   REDIS_MAXMEMORY: process.env.REDIS_MAXMEMORY,
// };

// const config = Object.freeze(_config);

// export default config;
