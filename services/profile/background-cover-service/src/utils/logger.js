import winston from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';
import config from '../config/config.js';

// Define log format with optimized performance
const logFormat = winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }), // Add milliseconds for precision
    winston.format.errors({ stack: true }), // Capture stack traces for errors
    winston.format.json(), // Use JSON for structured logging
    winston.format.metadata({ fillExcept: ['message', 'level', 'timestamp'] }) // Optimize metadata handling
);

// Create logger with optimized transports
export const logger = winston.createLogger({
    level: config.LOG_LEVEL || 'info',
    format: logFormat,
    transports: [
        // Console transport for development
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(), // Colorized output for readability
                winston.format.printf(({ timestamp, level, message, metadata }) => {
                    const metaString = Object.keys(metadata).length ? ` | ${JSON.stringify(metadata, null, 2)}` : '';
                    return `${timestamp} [${level.toUpperCase()}]: ${message}${metaString}`;
                })
            )
        }),
        // Error log with daily rotation
        new DailyRotateFile({
            filename: 'logs/error-%DATE%.log',
            datePattern: 'YYYY-MM-DD',
            level: 'error',
            maxSize: '20m', // Max 20MB per file
            maxFiles: '14d', // Keep 14 days
            zippedArchive: true, // Compress old logs
            handleExceptions: true // Capture uncaught exceptions
        }),
        // Combined log with daily rotation
        new DailyRotateFile({
            filename: 'logs/combined-%DATE%.log',
            datePattern: 'YYYY-MM-DD',
            maxSize: '20m',
            maxFiles: '30d',
            zippedArchive: true
        })
    ],
    exceptionHandlers: [
        new DailyRotateFile({
            filename: 'logs/exceptions-%DATE%.log',
            datePattern: 'YYYY-MM-DD',
            maxSize: '20m',
            maxFiles: '14d',
            zippedArchive: true
        })
    ],
    // Handle transport errors
    handleExceptions: true,
    silent: process.env.NODE_ENV === 'test' // Disable logging in test environment
});

// Morgan stream for HTTP request logging
logger.stream = {
    write: (message) => {
        logger.info(message.trim(), { source: 'morgan', type: 'http' });
    }
};

// Handle transport errors
logger.on('error', (error) => {
    console.error('Logger transport error:', error);
});