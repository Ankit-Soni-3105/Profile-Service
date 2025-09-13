import http from 'http';
import { WebSocketServer } from 'ws';
import EditorService from '../services/editor.service.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { catchAsync } from '../handler/catchAsync.js';
import { createRateLimiter } from '../utils/rateLimiter.js';
import { cacheService } from '../services/cache.service.js';
import { metricsCollector } from '../utils/metrics.js'; 
import { eventEmitter } from '../events/events.js';
import { validateEditorInput } from '../validations/editor.validation.js';
import { sanitizeInput } from '../utils/sanitizer.js';
import { ApiResponse } from '../utils/response.js';

// Rate limiters for editor operations
const updateContentLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 100, // 100 content updates per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `editor_update_${req.user.id}_${req.params.summaryId}`,
});

const stateUpdateLimiter = createRateLimiter({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 200, // 200 state updates per minute
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `editor_state_${req.user.id}_${req.params.summaryId}`,
});

class EditorController {
    constructor() {
        this.editorService = new EditorService();
        this.initializeWebSocket();
    }

    /**
     * Initialize WebSocket server for real-time collaboration
     */
    initializeWebSocket() {
        this.wss = new WebSocketServer({ noServer: true });
        this.wss.on('connection', (ws, req) => {
            const userId = req.user?.id;
            const summaryId = req.url?.split('/').pop();

            if (!userId || !summaryId) {
                ws.close(1008, 'Invalid user or summary ID');
                return;
            }

            this.editorService.handleWebSocketConnection(ws, userId, summaryId)
                .catch(err => {
                    logger.error(`WebSocket connection error for ${summaryId}:`, err);
                    ws.close(1011, 'Server error');
                });

            ws.on('message', async (data) => {
                try {
                    const message = JSON.parse(data);
                    await this.editorService.handleWebSocketMessage(ws, userId, summaryId, message);
                } catch (err) {
                    logger.error(`WebSocket message error for ${summaryId}:`, err);
                    ws.send(JSON.stringify({ error: 'Invalid message' }));
                }
            });

            ws.on('close', () => {
                this.editorService.handleWebSocketClose(userId, summaryId);
            });
        });
    }

    /**
     * Handle WebSocket upgrade
     */
    handleWebSocketUpgrade(server) {
        server.on('upgrade', (req, socket, head) => {
            if (req.url.startsWith('/api/v1/editor/ws')) {
                this.wss.handleUpgrade(req, socket, head, (ws) => {
                    this.wss.emit('connection', ws, req);
                });
            }
        });
    }

    /**
     * Update summary content in real-time
     * PATCH /api/v1/editor/:userId/:summaryId
     */
    updateContent = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, summaryId } = req.params;
        const requestingUserId = req.user.id;
        const { content, cursorPosition } = req.body;

        // Apply rate limiting
        await updateContentLimiter(req, res, () => { });

        // Validate input
        const validation = validateEditorInput({ content, cursorPosition });
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        // Sanitize input
        const sanitizedData = sanitizeInput({ content, cursorPosition });

        try {
            // Verify access
            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            // Update content
            const updatedSummary = await this.editorService.updateContent(
                summaryId,
                requestingUserId,
                sanitizedData.content,
                sanitizedData.cursorPosition
            );

            // Clear cache
            await cacheService.deletePattern(`summary:${summaryId}:*`);

            // Emit event for real-time collaboration
            eventEmitter.emit('editor.content_updated', {
                summaryId,
                userId: requestingUserId,
                content: sanitizedData.content,
                cursorPosition: sanitizedData.cursorPosition,
            });

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('editor.content_updated', {
                userId: requestingUserId,
                summaryId,
            });
            logger.info(`Content updated for summary ${summaryId} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Content updated successfully',
                data: {
                    summaryId,
                    content: updatedSummary.content,
                    version: updatedSummary.versions[updatedSummary.versions.length - 1].versionNumber,
                },
            });
        } catch (error) {
            logger.error(`Content update failed for summary ${summaryId}:`, error);
            metricsCollector.increment('editor.content_update_failed', { userId: requestingUserId });
            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.message.includes('not found')) {
                return next(new AppError('Summary not found', 404));
            }
            return next(new AppError('Failed to update content', 500));
        }
    });

    /**
     * Save editor state (cursor position, selection)
     * PATCH /api/v1/editor/:userId/:summaryId/state
     */
    saveEditorState = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, summaryId } = req.params;
        const requestingUserId = req.user.id;
        const { cursorPosition, selectionRange } = req.body;

        // Apply rate limiting
        await stateUpdateLimiter(req, res, () => { });

        // Validate input
        const validation = validateEditorInput({ cursorPosition, selectionRange });
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        try {
            // Verify access
            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            // Save editor state
            await this.editorService.saveEditorState(summaryId, requestingUserId, {
                cursorPosition,
                selectionRange,
            });

            // Cache state
            const cacheKey = `editor_state:${summaryId}:${requestingUserId}`;
            await cacheService.set(cacheKey, { cursorPosition, selectionRange }, 300); // 5 minutes

            // Emit event for real-time collaboration
            eventEmitter.emit('editor.state_updated', {
                summaryId,
                userId: requestingUserId,
                cursorPosition,
                selectionRange,
            });

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('editor.state_updated', {
                userId: requestingUserId,
                summaryId,
            });
            logger.info(`Editor state updated for summary ${summaryId} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Editor state saved successfully',
            });
        } catch (error) {
            logger.error(`Editor state update failed for summary ${summaryId}:`, error);
            metricsCollector.increment('editor.state_update_failed', { userId: requestingUserId });
            return next(new AppError('Failed to save editor state', 500));
        }
    });

    /**
     * Get active collaborators for a summary
     * GET /api/v1/editor/:userId/:summaryId/collaborators
     */
    getCollaborators = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, summaryId } = req.params;
        const requestingUserId = req.user.id;

        try {
            // Verify access
            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            // Get collaborators
            const collaborators = await this.editorService.getCollaborators(summaryId, requestingUserId);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('editor.collaborators_fetched', {
                userId: requestingUserId,
                summaryId,
            });
            logger.info(`Fetched collaborators for summary ${summaryId} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                data: collaborators,
            });
        } catch (error) {
            logger.error(`Collaborators fetch failed for summary ${summaryId}:`, error);
            metricsCollector.increment('editor.collaborators_fetch_failed', { userId: requestingUserId });
            if (error.message.includes('not found')) {
                return next(new AppError('Summary not found', 404));
            }
            return next(new AppError('Failed to fetch collaborators', 500));
        }
    });

    /**
     * Undo last change
     * POST /api/v1/editor/:userId/:summaryId/undo
     */
    undoChange = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, summaryId } = req.params;
        const requestingUserId = req.user.id;

        try {
            // Verify access
            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            // Perform undo
            const updatedSummary = await this.editorService.undoChange(summaryId, requestingUserId);

            // Clear cache
            await cacheService.deletePattern(`summary:${summaryId}:*`);

            // Emit event
            eventEmitter.emit('editor.undo', {
                summaryId,
                userId: requestingUserId,
                version: updatedSummary.versions[updatedSummary.versions.length - 1].versionNumber,
            });

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('editor.undo', {
                userId: requestingUserId,
                summaryId,
            });
            logger.info(`Undo performed for summary ${summaryId} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Undo successful',
                data: {
                    summaryId,
                    content: updatedSummary.content,
                    version: updatedSummary.versions[updatedSummary.versions.length - 1].versionNumber,
                },
            });
        } catch (error) {
            logger.error(`Undo failed for summary ${summaryId}:`, error);
            metricsCollector.increment('editor.undo_failed', { userId: requestingUserId });
            if (error.message.includes('not found')) {
                return next(new AppError('Summary or version not found', 404));
            }
            return next(new AppError('Failed to undo change', 500));
        }
    });

    /**
     * Redo last undone change
     * POST /api/v1/editor/:userId/:summaryId/redo
     */
    redoChange = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, summaryId } = req.params;
        const requestingUserId = req.user.id;

        try {
            // Verify access
            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            // Perform redo
            const updatedSummary = await this.editorService.redoChange(summaryId, requestingUserId);

            // Clear cache
            await cacheService.deletePattern(`summary:${summaryId}:*`);

            // Emit event
            eventEmitter.emit('editor.redo', {
                summaryId,
                userId: requestingUserId,
                version: updatedSummary.versions[updatedSummary.versions.length - 1].versionNumber,
            });

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('editor.redo', {
                userId: requestingUserId,
                summaryId,
            });
            logger.info(`Redo performed for summary ${summaryId} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Redo successful',
                data: {
                    summaryId,
                    content: updatedSummary.content,
                    version: updatedSummary.versions[updatedSummary.versions.length - 1].versionNumber,
                },
            });
        } catch (error) {
            logger.error(`Redo failed for summary ${summaryId}:`, error);
            metricsCollector.increment('editor.redo_failed', { userId: requestingUserId });
            if (error.message.includes('not found')) {
                return next(new AppError('Summary or version not found', 404));
            }
            return next(new AppError('Failed to redo change', 500));
        }
    });

    /**
     * Get editor history
     * GET /api/v1/editor/:userId/:summaryId/history
     */
    getHistory = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, summaryId } = req.params;
        const requestingUserId = req.user.id;
        const { page = 1, limit = 10 } = req.query;

        try {
            // Verify access
            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            // Get history
            const history = await this.editorService.getHistory(
                summaryId,
                requestingUserId,
                { page: parseInt(page), limit: parseInt(limit) }
            );

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('editor.history_fetched', {
                userId: requestingUserId,
                summaryId,
            });
            logger.info(`Fetched history for summary ${summaryId} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                data: history,
            });
        } catch (error) {
            logger.error(`History fetch failed for summary ${summaryId}:`, error);
            metricsCollector.increment('editor.history_fetch_failed', { userId: requestingUserId });
            if (error.message.includes('not found')) {
                return next(new AppError('Summary not found', 404));
            }
            return next(new AppError('Failed to fetch history', 500));
        }
    });

    // Helper Methods

    /**
     * Check if user has access to summary
     */
    checkSummaryAccess(summary, userId, isAdmin) {
        if (isAdmin) return true;
        if (summary.userId === userId) return true;
        if (summary.sharing?.isPublic) return true;
        if (summary.sharing?.collaborators?.some(c => c.userId === userId && c.status === 'accepted')) {
            return true;
        }
        return false;
    }
}

export default new EditorController();