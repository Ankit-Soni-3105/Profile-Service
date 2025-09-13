import mongoose from 'mongoose';
import Summary from '../models/Summary.js';
import SummaryBackup from '../models/SummaryBackup.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { cacheService } from '../services/cache.service.js';
import { metricsCollector } from '../utils/metrics.js';
import { eventEmitter } from '../events/events.js';

class BackupService {
    constructor() {
        this.summaryModel = Summary;
        this.backupModel = SummaryBackup;
        this.defaultCacheTTL = 3600; // 1 hour
    }

    /**
     * Create a backup for a summary
     */
    async createBackup(summaryId, userId, notes) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const summary = await this.summaryModel.findById(summaryId).session(session);
            if (!summary) {
                throw new AppError('Summary not found', 404);
            }

            // Check access
            if (!this.checkAccess(summary, userId)) {
                throw new AppError('Access denied', 403);
            }

            // Create backup
            const backup = new this.backupModel({
                summaryId,
                userId,
                content: summary.content,
                title: summary.title,
                metadata: summary.metadata,
                versions: summary.versions,
                translations: summary.translations,
                ai: summary.ai,
                quality: summary.quality,
                settings: summary.settings,
                sharing: summary.sharing,
                notes,
                createdAt: new Date(),
            });

            const savedBackup = await backup.save({ session });

            // Update summary metadata
            summary.metadata.lastBackedUp = { userId, timestamp: new Date() };
            await summary.save({ session });

            // Update user stats
            await this.updateUserStats(userId, 'create_backup', session);

            await session.commitTransaction();

            // Schedule async processing
            this.scheduleAsyncProcessing(summaryId, savedBackup._id);

            return savedBackup;
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Backup creation failed for summary ${summaryId}:`, error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    /**
     * Restore a backup to a summary
     */
    async restoreBackup(backupId, userId, merge) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const backup = await this.backupModel.findById(backupId).session(session);
            if (!backup) {
                throw new AppError('Backup not found', 404);
            }

            const summary = await this.summaryModel.findById(backup.summaryId).session(session);
            if (!summary) {
                throw new AppError('Summary not found', 404);
            }

            // Check access
            if (!this.checkAccess(summary, userId)) {
                throw new AppError('Access denied', 403);
            }

            let newContent = backup.content;
            if (merge) {
                newContent = this.mergeContent(summary.content, backup.content);
            }

            // Create new version
            const newVersion = {
                versionNumber: summary.versions.length + 1,
                content: newContent,
                title: backup.title,
                changeType: 'backup_restore',
                isActive: true,
                createdAt: new Date(),
                stats: {
                    characterCount: newContent.length,
                    wordCount: newContent.trim().split(/\s+/).length,
                    paragraphCount: newContent.split('\n\n').length,
                    sentenceCount: newContent.split(/[.!?]+/).length - 1,
                },
                backup: {
                    backupId,
                    restoredBy: userId,
                    restoredAt: new Date(),
                },
            };

            // Deactivate previous versions
            summary.versions.forEach(v => (v.isActive = false));
            summary.versions.push(newVersion);

            // Limit versions
            if (summary.versions.length > summary.settings.maxVersions) {
                summary.versions = summary.versions.slice(-summary.settings.maxVersions);
            }

            // Update summary
            summary.content = newContent;
            summary.title = backup.title;
            summary.metadata = { ...summary.metadata, ...backup.metadata };
            summary.translations = backup.translations || summary.translations;
            summary.ai = backup.ai || summary.ai;
            summary.quality = backup.quality || summary.quality;
            summary.settings = { ...summary.settings, ...backup.settings };
            summary.sharing = { ...summary.sharing, ...backup.sharing };
            summary.metadata.lastRestored = { userId, timestamp: new Date() };

            const updatedSummary = await summary.save({ session });

            // Update backup status
            backup.status = 'restored';
            backup.restoredAt = new Date();
            backup.restoredBy = userId;
            await backup.save({ session });

            // Update user stats
            await this.updateUserStats(userId, 'restore_backup', session);

            await session.commitTransaction();

            // Clear cache
            await this.clearSummaryCache(backup.summaryId, userId);

            return updatedSummary;
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Backup restoration failed for backup ${backupId}:`, error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    /**
     * Get backups for a summary
     */
    async getBackups(summaryId, userId, { page, limit }) {
        try {
            const summary = await this.summaryModel.findById(summaryId).select('_id userId').lean();
            if (!summary) {
                throw new AppError('Summary not found', 404);
            }

            // Check access
            if (!this.checkAccess(summary, userId)) {
                throw new AppError('Access denied', 403);
            }

            const skip = (page - 1) * limit;
            const backups = await this.backupModel
                .find({ summaryId, userId })
                .sort({ createdAt: -1 })
                .skip(skip)
                .limit(limit)
                .lean()
                .select('_id summaryId title content notes createdAt restoredAt status');

            const totalCount = await this.backupModel.countDocuments({ summaryId, userId });
            const totalPages = Math.ceil(totalCount / limit);

            return {
                backups: backups.map(b => ({
                    backupId: b._id,
                    summaryId: b.summaryId,
                    title: b.title,
                    content: b.content,
                    notes: b.notes,
                    createdAt: b.createdAt,
                    restoredAt: b.restoredAt,
                    status: b.status,
                })),
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
            logger.error(`Backup fetch failed for summary ${summaryId}:`, error);
            throw error;
        }
    }

    /**
     * Delete a backup
     */
    async deleteBackup(backupId, userId) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const backup = await this.backupModel.findById(backupId).session(session);
            if (!backup) {
                throw new AppError('Backup not found', 404);
            }

            // Check access
            if (backup.userId !== userId) {
                throw new AppError('Access denied', 403);
            }

            await backup.deleteOne({ session });
            await this.updateUserStats(userId, 'delete_backup', session);

            await session.commitTransaction();

            return { summaryId: backup.summaryId };
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Backup deletion failed for backup ${backupId}:`, error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    /**
     * Bulk create backups
     */
    async bulkCreateBackups(summaryIds, userId, notes) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const query = { _id: { $in: summaryIds }, userId, 'flags.isDeleted': false };
            const summaries = await this.summaryModel.find(query).session(session);

            if (summaries.length === 0) {
                throw new AppError('No summaries found', 404);
            }

            if (summaries.length !== summaryIds.length) {
                throw new AppError('Some summaries not found or access denied', 403);
            }

            const backups = await Promise.all(
                summaries.map(async summary => {
                    const backup = new this.backupModel({
                        summaryId: summary._id,
                        userId,
                        content: summary.content,
                        title: summary.title,
                        metadata: summary.metadata,
                        versions: summary.versions,
                        translations: summary.translations,
                        ai: summary.ai,
                        quality: summary.quality,
                        settings: summary.settings,
                        sharing: summary.sharing,
                        notes,
                        createdAt: new Date(),
                    });

                    const savedBackup = await backup.save({ session });
                    summary.metadata.lastBackedUp = { userId, timestamp: new Date() };
                    await summary.save({ session });

                    return savedBackup;
                })
            );

            // Update user stats
            await this.updateUserStats(userId, 'bulk_create_backups', session);

            await session.commitTransaction();

            // Schedule async processing
            backups.forEach(backup => {
                this.scheduleAsyncProcessing(backup.summaryId, backup._id);
            });

            return {
                requested: summaryIds.length,
                created: backups.length,
            };
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk backup creation failed for user ${userId}:`, error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    // Helper Methods

    /**
     * Merge content for restoration
     */
    mergeContent(currentContent, backupContent) {
        // Simple merge: combine sentences, avoiding duplicates
        const currentSentences = currentContent.split(/[.!?]+/).map(s => s.trim()).filter(s => s);
        const backupSentences = backupContent.split(/[.!?]+/).map(s => s.trim()).filter(s => s);
        const merged = [...new Set([...currentSentences, ...backupSentences])].join('. ');
        return merged;
    }

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
            metricsCollector.increment(`backup.${action}`, { userId });
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
                `backups:${summaryId}:*`,
            ];
            await Promise.all(patterns.map(pattern => cacheService.deletePattern(pattern)));
        } catch (error) {
            logger.error(`Cache clearing failed for summary ${summaryId}:`, error);
        }
    }

    /**
     * Schedule async processing
     */
    scheduleAsyncProcessing(summaryId, backupId) {
        setTimeout(async () => {
            try {
                // Placeholder for async tasks (e.g., backup validation, compression)
                logger.info(`Async processing completed for backup ${backupId} in summary ${summaryId}`);
            } catch (error) {
                logger.error(`Async processing failed for backup ${backupId}:`, error);
            }
        }, 1000);
    }
}

export default BackupService;