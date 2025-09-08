import winston from 'winston';
import config from '../config/config.js';

// Define log format
const logFormat = winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.json(),
    winston.format.metadata(),
    winston.format.printf(({ timestamp, level, message, metadata }) => {
        return `${timestamp} [${level.toUpperCase()}]: ${message} ${Object.keys(metadata).length ? JSON.stringify(metadata) : ''}`;
    })
);

// Create logger
export const logger = winston.createLogger({
    level: config.LOG_LEVEL || 'info',
    format: logFormat,
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({
            filename: 'logs/error.log',
            level: 'error',
        }),
        new winston.transports.File({
            filename: 'logs/combined.log',
        }),
    ],
});

// Add stream for Morgan (HTTP request logging)
logger.stream = {
    write: (message) => logger.info(message.trim()),
};