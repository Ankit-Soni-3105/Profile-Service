import Redis from 'ioredis';
import config from '../config/config.js';

const redisNodes = [
  { host: 'redis-node-1', port: 7001 },
  { host: 'redis-node-2', port: 7002 },
  { host: 'redis-node-3', port: 7003 },
  { host: 'redis-node-4', port: 7004 },
  { host: 'redis-node-5', port: 7005 },
  { host: 'redis-node-6', port: 7006 },
];

const redisCluster = new Redis.Cluster(redisNodes, {
  redisOptions: {
    password: config.REDIS_PASSWORD || undefined, // Agar password nahi hai to undefined rakhein
    tls: config.REDIS_TLS === 'true' ? {} : undefined, // Agar TLS use karna ho
  },
  scaleReads: 'all', // Load balancing ke liye
  clusterRetryStrategy: (times) => Math.min(100 + times * 200, 1000), // Retry strategy
});

redisCluster.on('connect', () => {
  console.log('Connected to Redis Cluster');
});

redisCluster.on('error', (err) => {
  console.error('Redis Cluster error:', err);
});

export default redisCluster;








// import redis from 'ioredis';
// import config from '../config/config.js';

// const redisClient = new redis({
//     host: config.REDIS_HOST,
//     port: config.REDIS_PORT,
//     password: config.REDIS_PASSWORD
// });
// redisClient.on('connect', () => {
//     console.log('Connected to Redis');
// });

// redisClient.on('error', (err) => {
//     console.error('Redis error:', err);
// });
    
// export default redisClient;
