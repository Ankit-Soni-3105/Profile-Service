import express from 'express';

const app = express();
import morgan from 'morgan';

import summaryRoutes from './routes/summary.routes.js';
import backupRoutes from './routes/backup.routes.js';
import editorRoutes from './routes/editor.routes.js';
import formattingRoutes from './routes/formatting.routes.js';
import suggestionsRoutes from './routes/suggetion.routes.js';
import grammarRoutes from './routes/grammer.routes.js';
import templateRoutes from './routes/template.routes.js';
import translationRoutes from './routes/translations.routes.js';
import voiceInputRoutes from './routes/voice.input.routes.js';

import { logger } from './utils/logger.js';
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(morgan(
    'combined',
    { stream: logger.stream })
); // HTTP request logging

// Routes
app.use(
    '/profiles/about-summary/summary',
    summaryRoutes
);

app.use(
    '/profiles/about-summary/backup',
    backupRoutes
);

app.use(
    '/profiles/about-summary/editor',
    editorRoutes
);

app.use(
    '/profiles/about-summary/formatting',
    formattingRoutes
);

app.use(
    '/profiles/about-summary/suggestions',
    suggestionsRoutes
);

app.use(
    '/profiles/about-summary/grammar',
    grammarRoutes
);

app.use(
    '/profiles/about-summary/template',
    templateRoutes
);

app.use(
    '/profiles/about-summary/translation',
    translationRoutes
);

app.use(
    '/profiles/about-summary/voice-input',
    voiceInputRoutes
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