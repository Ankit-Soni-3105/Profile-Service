import { createLogger, format, transports } from 'winston';

const { combine, timestamp, printf, errors } = format;

// Custom format for error handling
const errorFormat = printf(({ level, message, timestamp, stack }) => {
    return `${timestamp} [${level}]: ${stack || message}`;
});

const logger = createLogger({
    level: 'info',
    format: combine(
        timestamp(),
        errors({ stack: true }), // Capture stack trace for errors
        errorFormat
    ),
    transports: [
        new transports.Console(),
        // You can add file transport for error logs if needed
        // new transports.File({ filename: 'error.log', level: 'error' })
    ],
    exceptionHandlers: [
        new transports.Console(),
        // new transports.File({ filename: 'exceptions.log' })
    ],
    rejectionHandlers: [
        new transports.Console(),
        // new transports.File({ filename: 'rejections.log' })
    ]
});

export default logger;
