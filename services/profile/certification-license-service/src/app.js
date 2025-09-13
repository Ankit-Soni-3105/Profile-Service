import express from 'express';

const app = express();
import morgan from 'morgan';
import profileRoutes from './routes/profile.routes.js';
import { logger } from './utils/logger.js';
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(morgan(
    'combined',
    { stream: logger.stream })
); // HTTP request logging

// Routes
app.use(
    '/profiles',
    profileRoutes
);

// Global error handler (optional, as controller has its own)
app.use((err, req, res, next) => {
    logger.error('Unhandled error', { message: err.message, stack: err.stack });
    res.status(500).json({ message: 'Internal server error' });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

export default app;