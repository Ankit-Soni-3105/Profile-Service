import "dotenv/config";

const _config = {
  PORT: process.env.PORT,
  MONGO_URI: process.env.MONGO_URI,
  JWT_SECRET: process.env.JWT_SECRET,
  REDIS_CLUSTER_NODES: process.env.REDIS_CLUSTER_NODES,
  KAFKA_BROKERS: process.env.KAFKA_BROKERS,
  KAFKA_GROUP_MIN_SESSION_TIMEOUT_MS: process.env.KAFKA_GROUP_MIN_SESSION_TIMEOUT_MS,
  KAFKA_GROUP_MAX_SESSION_TIMEOUT_MS: process.env.KAFKA_GROUP_MAX_SESSION_TIMEOUT_MS,
  KAFKA_CLIENT_ID: process.env.KAFKA_CLIENT_ID,
  PROFILE_EVENTS_TOPIC: process.env.PROFILE_EVENTS_TOPIC,
  REDIS_CACHE_TTL: process.env.REDIS_CACHE_TTL,
  REDIS_MAXMEMORY: process.env.REDIS_MAXMEMORY,
};

const config = Object.freeze(_config);

export default config;
