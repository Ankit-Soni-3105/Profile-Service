import winston from 'winston';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Create logs directory if it doesn't exist
const logsDir = path.join(__dirname, '../logs');
if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
}

// Custom format for better readability
const logFormat = winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.json(),
    winston.format.prettyPrint()
);

// Console format for development
const consoleFormat = winston.format.combine(
    winston.format.colorize(),
    winston.format.timestamp({ format: 'HH:mm:ss' }),
    winston.format.printf(({ timestamp, level, message, service, ...meta }) => {
        let log = `${timestamp} [${service || 'APP'}] ${level}: ${message}`;
        if (Object.keys(meta).length > 0) {
            log += ` ${JSON.stringify(meta, null, 2)}`;
        }
        return log;
    })
);

// Main logger configuration
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: logFormat,
    defaultMeta: {
        service: process.env.SERVICE_NAME || 'microservice',
        environment: process.env.NODE_ENV || 'development',
        version: process.env.SERVICE_VERSION || '1.0.0'
    },
    transports: [
        // Error logs
        new winston.transports.File({
            filename: path.join(logsDir, 'error.log'),
            level: 'error',
            maxsize: 10485760, // 10MB
            maxFiles: 10,
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.json()
            )
        }),

        // Combined logs
        new winston.transports.File({
            filename: path.join(logsDir, 'combined.log'),
            maxsize: 10485760, // 10MB
            maxFiles: 10,
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.json()
            )
        }),

        // Info logs
        new winston.transports.File({
            filename: path.join(logsDir, 'info.log'),
            level: 'info',
            maxsize: 10485760, // 10MB
            maxFiles: 5,
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.json()
            )
        }),

        // Debug logs (only in development)
        ...(process.env.NODE_ENV === 'development' ? [
            new winston.transports.File({
                filename: path.join(logsDir, 'debug.log'),
                level: 'debug',
                maxsize: 5242880, // 5MB
                maxFiles: 3
            })
        ] : [])
    ],

    // Exception handling
    exceptionHandlers: [
        new winston.transports.File({
            filename: path.join(logsDir, 'exceptions.log'),
            maxsize: 10485760,
            maxFiles: 5
        })
    ],

    // Rejection handling
    rejectionHandlers: [
        new winston.transports.File({
            filename: path.join(logsDir, 'rejections.log'),
            maxsize: 10485760,
            maxFiles: 5
        })
    ]
});

// Console logging for non-production environments
if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({
        format: consoleFormat,
        level: 'debug'
    }));
}

// Custom logging methods for different types of logs
logger.api = (message, meta = {}) => {
    logger.info(message, { type: 'API', ...meta });
};

logger.db = (message, meta = {}) => {
    logger.info(message, { type: 'DATABASE', ...meta });
};

logger.cache = (message, meta = {}) => {
    logger.info(message, { type: 'CACHE', ...meta });
};

logger.auth = (message, meta = {}) => {
    logger.info(message, { type: 'AUTH', ...meta });
};

logger.performance = (message, meta = {}) => {
    logger.info(message, { type: 'PERFORMANCE', ...meta });
};

export default logger;