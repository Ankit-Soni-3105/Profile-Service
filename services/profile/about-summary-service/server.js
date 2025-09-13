import app from './src/app.js';
import http from 'http';
import config from './src/config/config.js';
import { connectDB } from './src/db/db.js';
import { connectCache, disconnectCache } from './src/services/redis.service.js';

const PORT = config.PORT;

const server = http.createServer(app);

connectDB();

connectCache().catch(err => {
  console.error('Failed to connect to Redis:', err.message);
  process.exit(1); // Exit if Redis fails
});

server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  await disconnectCache();
  process.exit(0);
});
