import mongoose from 'mongoose';
import { diffWords } from 'diff';
import Summary from '../models/summary.model.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { cacheService } from '../services/cache.service.js';
import { metricsCollector } from '../utils/metrics.js';
import { eventEmitter } from '../events/events.js';

class EditorService {
    constructor() {
        this.model = Summary;
        this.defaultCacheTTL = 300; // 5 minutes
        this.collaborators = new Map(); // Track active collaborators per summary
    }

    /**
     * Handle WebSocket connection
     */
    async handleWebSocketConnection(ws, userId, summaryId) {
        const summary = await this.model.findById(summaryId).lean();
        if (!summary) {
            throw new AppError('Summary not found', 404);
        }

        // Check access
        const hasAccess = this.checkAccess(summary, userId);
        if (!hasAccess) {
            throw new AppError('Access denied', 403);
        }

        // Add collaborator
        if (!this.collaborators.has(summaryId)) {
            this.collaborators.set(summaryId, new Map());
        }
        this.collaborators.get(summaryId).set(userId, ws);

        // Send initial state
        ws.send(JSON.stringify({
            type: 'initial_state',
            data: {
                content: summary.content,
                collaborators: Array.from(this.collaborators.get(summaryId).keys()),
            },
        }));

        logger.info(`User ${userId} connected to editor for summary ${summaryId}`);
        metricsCollector.increment('editor.websocket_connected', { userId, summaryId });
    }

    /**
     * Handle WebSocket message
     */
    async handleWebSocketMessage(ws, userId, summaryId, message) {
        switch (message.type) {
            case 'content_update':
                await this.handleContentUpdateMessage(summaryId, userId, message.data);
                break;
            case 'state_update':
                await this.handleStateUpdateMessage(summaryId, userId, message.data);
                break;
            default:
                throw new AppError('Invalid message type', 400);
        }
    }

    /**
     * Handle WebSocket close
     */
    handleWebSocketClose(userId, summaryId) {
        if (this.collaborators.has(summaryId)) {
            this.collaborators.get(summaryId).delete(userId);
            if (this.collaborators.get(summaryId).size === 0) {
                this.collaborators.delete(summaryId);
            }

            // Broadcast updated collaborator list
            this.broadcast(summaryId, {
                type: 'collaborator_update',
                data: {
                    collaborators: Array.from(this.collaborators.get(summaryId)?.keys() || []),
                },
            });

            logger.info(`User ${userId} disconnected from editor for summary ${summaryId}`);
            metricsCollector.increment('editor.websocket_disconnected', { userId, summaryId });
        }
    }

    /**
     * Handle content update message
     */
    async handleContentUpdateMessage(summaryId, userId, data) {
        const { content, cursorPosition } = data;
        try {
            const updatedSummary = await this.updateContent(summaryId, userId, content, cursorPosition);

            // Broadcast update to other collaborators
            this.broadcast(summaryId, {
                type: 'content_update',
                data: {
                    userId,
                    content,
                    cursorPosition,
                    version: updatedSummary.versions[updatedSummary.versions.length - 1].versionNumber,
                },
            }, userId);

            metricsCollector.increment('editor.content_broadcast', { userId, summaryId });
        } catch (error) {
            logger.error(`Content update broadcast failed for ${summaryId}:`, error);
            throw error;
        }
    }

    /**
     * Handle state update message
     */
    async handleStateUpdateMessage(summaryId, userId, data) {
        const { cursorPosition, selectionRange } = data;
        try {
            await this.saveEditorState(summaryId, userId, { cursorPosition, selectionRange });

            // Broadcast state update
            this.broadcast(summaryId, {
                type: 'state_update',
                data: {
                    userId,
                    cursorPosition,
                    selectionRange,
                },
            }, userId);

            metricsCollector.increment('editor.state_broadcast', { userId, summaryId });
        } catch (error) {
            logger.error(`State update broadcast failed for ${summaryId}:`, error);
            throw error;
        }
    }

    /**
     * Broadcast message to all collaborators except sender
     */
    broadcast(summaryId, message, excludeUserId) {
        const collaborators = this.collaborators.get(summaryId);
        if (collaborators) {
            collaborators.forEach((ws, userId) => {
                if (userId !== excludeUserId && ws.readyState === ws.OPEN) {
                    ws.send(JSON.stringify(message));
                }
            });
        }
    }

    /**
     * Update summary content
     */
    async updateContent(summaryId, userId, content, cursorPosition) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const summary = await this.model.findById(summaryId).session(session);
            if (!summary) {
                throw new AppError('Summary not found', 404);
            }

            // Check access
            if (!this.checkAccess(summary, userId)) {
                throw new AppError('Access denied', 403);
            }

            // Calculate diff
            const currentContent = summary.content || '';
            const changes = diffWords(currentContent, content);
            const hasChanges = changes.some(change => change.added || change.removed);

            if (hasChanges) {
                // Create new version
                const newVersion = {
                    versionNumber: summary.versions.length + 1,
                    content,
                    title: summary.title,
                    changeType: 'edit',
                    isActive: true,
                    createdAt: new Date(),
                    stats: {
                        characterCount: content.length,
                        wordCount: content.trim().split(/\s+/).length,
                        paragraphCount: content.split('\n\n').length,
                        sentenceCount: content.split(/[.!?]+/).length - 1,
                    },
                    editorState: { cursorPosition },
                };

                // Deactivate previous versions
                summary.versions.forEach(v => (v.isActive = false));
                summary.versions.push(newVersion);

                // Limit versions
                if (summary.versions.length > summary.settings.maxVersions) {
                    summary.versions = summary.versions.slice(-summary.settings.maxVersions);
                }

                // Update content and metadata
                summary.content = content;
                summary.metadata.wordCount = content.trim().split(/\s+/).length;
                summary.metadata.characterCount = content.length;
                summary.metadata.lastEditedBy = { userId, timestamp: new Date() };
            }

            // Save editor state
            if (cursorPosition) {
                summary.editorState = summary.editorState || {};
                summary.editorState[userId] = { cursorPosition, updatedAt: new Date() };
            }

            const updatedSummary = await summary.save({ session });

            // Update user stats
            await this.updateUserStats(userId, 'edit', session);

            await session.commitTransaction();

            // Clear cache
            await this.clearSummaryCache(summaryId, userId);

            // Schedule async processing
            this.scheduleAsyncProcessing(summaryId, content);

            return updatedSummary;
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Content update failed for summary ${summaryId}:`, error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    /**
     * Save editor state
     */
    async saveEditorState(summaryId, userId, { cursorPosition, selectionRange }) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const summary = await this.model.findById(summaryId).session(session);
            if (!summary) {
                throw new AppError('Summary not found', 404);
            }

            // Check access
            if (!this.checkAccess(summary, userId)) {
                throw new AppError('Access denied', 403);
            }

            // Update editor state
            summary.editorState = summary.editorState || {};
            summary.editorState[userId] = {
                cursorPosition,
                selectionRange,
                updatedAt: new Date(),
            };

            await summary.save({ session });

            await session.commitTransaction();

            // Cache state
            const cacheKey = `editor_state:${summaryId}:${userId}`;
            await cacheService.set(cacheKey, { cursorPosition, selectionRange }, this.defaultCacheTTL);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Editor state save failed for summary ${summaryId}:`, error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    /**
     * Get active collaborators
     */
    async getCollaborators(summaryId, userId) {
        try {
            const summary = await this.model.findById(summaryId).lean();
            if (!summary) {
                throw new AppError('Summary not found', 404);
            }

            // Check access
            if (!this.checkAccess(summary, userId)) {
                throw new AppError('Access denied', 403);
            }

            const activeCollaborators = this.collaborators.get(summaryId)
                ? Array.from(this.collaborators.get(summaryId).keys())
                : [];

            const collaborators = (summary.sharing?.collaborators || [])
                .filter(c => c.status === 'accepted')
                .map(c => ({
                    userId: c.userId,
                    role: c.role,
                    isActive: activeCollaborators.includes(c.userId),
                }));

            return collaborators;
        } catch (error) {
            logger.error(`Collaborators fetch failed for summary ${summaryId}:`, error);
            throw error;
        }
    }

    /**
     * Undo last change
     */
    async undoChange(summaryId, userId) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const summary = await this.model.findById(summaryId).session(session);
            if (!summary) {
                throw new AppError('Summary not found', 404);
            }

            // Check access
            if (!this.checkAccess(summary, userId)) {
                throw new AppError('Access denied', 403);
            }

            // Find last active version
            const activeVersion = summary.versions.find(v => v.isActive);
            if (!activeVersion || activeVersion.versionNumber === 1) {
                throw new AppError('No previous version to undo', 400);
            }

            // Find previous version
            const previousVersion = summary.versions.find(
                v => v.versionNumber === activeVersion.versionNumber - 1
            );
            if (!previousVersion) {
                throw new AppError('Previous version not found', 404);
            }

            // Update versions
            summary.versions.forEach(v => (v.isActive = false));
            previousVersion.isActive = true;
            summary.content = previousVersion.content;

            // Update metadata
            summary.metadata.wordCount = previousVersion.stats.wordCount;
            summary.metadata.characterCount = previousVersion.stats.characterCount;
            summary.metadata.lastEditedBy = { userId, timestamp: new Date() };

            const updatedSummary = await summary.save({ session });

            // Update user stats
            await this.updateUserStats(userId, 'undo', session);

            await session.commitTransaction();

            // Clear cache
            await this.clearSummaryCache(summaryId, userId);

            return updatedSummary;
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Undo failed for summary ${summaryId}:`, error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    /**
     * Redo last undone change
     */
    async redoChange(summaryId, userId) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const summary = await this.model.findById(summaryId).session(session);
            if (!summary) {
                throw new AppError('Summary not found', 404);
            }

            // Check access
            if (!this.checkAccess(summary, userId)) {
                throw new AppError('Access denied', 403);
            }

            // Find current active version
            const activeVersion = summary.versions.find(v => v.isActive);
            if (!activeVersion) {
                throw new AppError('No active version found', 400);
            }

            // Find next version
            const nextVersion = summary.versions.find(
                v => v.versionNumber === activeVersion.versionNumber + 1
            );
            if (!nextVersion) {
                throw new AppError('No next version to redo', 400);
            }

            // Update versions
            summary.versions.forEach(v => (v.isActive = false));
            nextVersion.isActive = true;
            summary.content = nextVersion.content;

            // Update metadata
            summary.metadata.wordCount = nextVersion.stats.wordCount;
            summary.metadata.characterCount = nextVersion.stats.characterCount;
            summary.metadata.lastEditedBy = { userId, timestamp: new Date() };

            const updatedSummary = await summary.save({ session });

            // Update user stats
            await this.updateUserStats(userId, 'redo', session);

            await session.commitTransaction();

            // Clear cache
            await this.clearSummaryCache(summaryId, userId);

            return updatedSummary;
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Redo failed for summary ${summaryId}:`, error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    /**
     * Get editor history
     */
    async getHistory(summaryId, userId, { page, limit }) {
        try {
            const summary = await this.model.findById(summaryId).lean();
            if (!summary) {
                throw new AppError('Summary not found', 404);
            }

            // Check access
            if (!this.checkAccess(summary, userId)) {
                throw new AppError('Access denied', 403);
            }

            const skip = (page - 1) * limit;
            const versions = summary.versions
                .slice()
                .sort((a, b) => b.createdAt - a.createdAt)
                .slice(skip, skip + limit)
                .map(v => ({
                    versionNumber: v.versionNumber,
                    content: v.content,
                    title: v.title,
                    changeType: v.changeType,
                    createdAt: v.createdAt,
                    stats: v.stats,
                }));

            const totalCount = summary.versions.length;
            const totalPages = Math.ceil(totalCount / limit);

            return {
                versions,
                pagination: {
                    page,
                    limit,
                    totalCount,
                    totalPages,
                    hasNext: page < totalPages,
                    hasPrev: page > 1,
                },
            };
        } catch (error) {
            logger.error(`History fetch failed for summary ${summaryId}:`, error);
            throw error;
        }
    }

    // Helper Methods

    /**
     * Check access permissions
     */
    checkAccess(summary, userId) {
        if (summary.sharing?.isPublic) return true;
        if (summary.userId === userId) return true;
        if (summary.sharing?.collaborators?.some(c => c.userId === userId && c.status === 'accepted')) {
            return true;
        }
        return false;
    }

    /**
     * Update user stats
     */
    async updateUserStats(userId, action, session) {
        try {
            metricsCollector.increment(`editor.${action}`, { userId });
        } catch (error) {
            logger.error(`Failed to update user stats for ${userId}:`, error);
        }
    }

    /**
     * Clear summary cache
     */
    async clearSummaryCache(summaryId, userId) {
        try {
            const patterns = [
                `summary:${summaryId}:*`,
                `summaries:${userId}:*`,
                `editor_state:${summaryId}:*`,
            ];
            await Promise.all(patterns.map(pattern => cacheService.deletePattern(pattern)));
        } catch (error) {
            logger.error(`Cache clearing failed for summary ${summaryId}:`, error);
        }
    }

    /**
     * Schedule async processing (e.g., quality scoring, AI suggestions)
     */
    scheduleAsyncProcessing(summaryId, content) {
        setTimeout(async () => {
            try {
                // Placeholder for async tasks (e.g., quality scoring, AI analysis)
                logger.info(`Async processing completed for summary ${summaryId}`);
            } catch (error) {
                logger.error(`Async processing failed for summary ${summaryId}:`, error);
            }
        }, 1000);
    }
}

export default EditorService;