import mongoose from 'mongoose';
import { logger } from '../utils/logger.js';
import ApiError from '../services/apierrors.service.js';
import config from '../config/config.js';

const connectDB = async () => {
    try {
        const maxRetries = 5;
        let retryAttempts = 0;

        const mongooseConfig = {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            maxPoolSize: config.mongo.maxPoolSize,
            minPoolSize: config.mongo.minPoolSize,
            serverSelectionTimeoutMS: config.mongo.serverSelectionTimeoutMS,
            socketTimeoutMS: config.mongo.socketTimeoutMS,
            connectTimeoutMS: config.mongo.connectTimeoutMS,
        };

        while (retryAttempts < maxRetries) {
            try {
                const conn = await mongoose.connect(config.mongo.uri, mongooseConfig);
                logger.info('MongoDB connected successfully', {
                    host: conn.connection.host,
                    port: conn.connection.port,
                    db: conn.connection.name,
                    maxPoolSize: mongooseConfig.maxPoolSize,
                });
                return;
            } catch (error) {
                retryAttempts++;
                const delay = Math.pow(2, retryAttempts) * 1000;
                logger.warn(`MongoDB connection attempt ${retryAttempts}/${maxRetries} failed, retrying in ${delay}ms`, {
                    error: error.message,
                });
                if (retryAttempts === maxRetries) {
                    logger.error('Max MongoDB connection retries reached');
                    throw new ApiError(500, 'Failed to connect to MongoDB after max retries');
                }
                await new Promise((resolve) => setTimeout(resolve, delay));
            }
        }
    } catch (error) {
        logger.error('MongoDB connection failed', {
            error: error.message,
            stack: error.stack,
        });
        throw new ApiError(500, 'MongoDB connection error');
    }
};

mongoose.connection.on('disconnected', () => {
    logger.warn('MongoDB disconnected');
});

mongoose.connection.on('error', (err) => {
    logger.error('MongoDB error', {
        error: err.message,
        stack: err.stack,
    });
});

const healthCheck = async () => {
    try {
        await mongoose.connection.db.admin().ping();
        return true;
    } catch (error) {
        logger.error('MongoDB health check failed', { error: error.message });
        return false;
    }
};

export { connectDB, healthCheck };