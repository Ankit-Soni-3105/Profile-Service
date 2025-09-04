import app from './src/app.js';
import http from 'http';
import config from './src/config/config.js';
import { connectDB } from './src/db/db.js';
import cron from 'node-cron';
import { blockInactiveUsers } from './src/cron/inactiveUserBlocker.js';
import { connectProducer } from './src/kafka/producer.js';

const port = config.PORT;
const server = http.createServer(app);

cron.schedule('0 0 * * *', async () => {
    await blockInactiveUsers();
});

const startServer = async () => {
    try {
        await connectProducer();
        // MongoDB connection (if not already here)
        await connectDB();
        server.listen(port, () => {
            console.log(`🚀 Auth Service running on port ${port}`);
        });
    } catch (error) {
        console.error("Failed to start server:", error);
        process.exit(1);
    }
};

startServer();
