import BackupService from '../services/BackupService.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { catchAsync } from '../handler/catchAsync.js';
import { ApiResponse } from '../utils/response.js';
import { createRateLimiter } from '../utils/rateLimiter.js';
import { cacheService } from '../services/cache.service.js';
import { metricsCollector } from '../utils/metrics.js';
import { eventEmitter } from '../events/events.js';
import { validateBackupInput } from '../validations/backup.validation.js';
import { sanitizeInput } from '../utils/sanitizer.js';

// Rate limiters for backup operations
const createBackupLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // 10 backup creations per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `backup_create_${req.user.id}_${req.params.summaryId}`,
});

const restoreBackupLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 restore operations per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `backup_restore_${req.user.id}_${req.params.summaryId}`,
});

class BackupController {
    constructor() {
        this.backupService = new BackupService();
    }

    /**
     * Create a backup for a summary
     * POST /api/v1/backup/:userId/:summaryId
     */
    createBackup = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, summaryId } = req.params;
        const requestingUserId = req.user.id;
        const { notes = '' } = req.body;

        // Apply rate limiting
        await createBackupLimiter(req, res, () => { });

        // Validate input
        const validation = validateBackupInput({ notes });
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        // Sanitize input
        const sanitizedData = sanitizeInput({ notes });

        try {
            // Verify access
            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            // Create backup
            const backup = await this.backupService.createBackup(
                summaryId,
                requestingUserId,
                sanitizedData.notes
            );

            // Clear cache
            await cacheService.deletePattern(`backups:${summaryId}:*`);

            // Emit event
            eventEmitter.emit('backup.created', {
                summaryId,
                userId: requestingUserId,
                backupId: backup._id,
            });

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('backup.created', {
                userId: requestingUserId,
                summaryId,
            });
            logger.info(`Backup created for summary ${summaryId} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Backup created successfully',
                data: {
                    backupId: backup._id,
                    summaryId,
                    createdAt: backup.createdAt,
                },
            });
        } catch (error) {
            logger.error(`Backup creation failed for summary ${summaryId}:`, error);
            metricsCollector.increment('backup.create_failed', { userId: requestingUserId });
            if (error.message.includes('not found')) {
                return next(new AppError('Summary not found', 404));
            }
            return next(new AppError('Failed to create backup', 500));
        }
    });

    /**
     * Restore a backup for a summary
     * POST /api/v1/backup/:userId/:backupId/restore
     */
    restoreBackup = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, backupId } = req.params;
        const requestingUserId = req.user.id;
        const { merge = false } = req.body;

        // Apply rate limiting
        await restoreBackupLimiter(req, res, () => { });

        // Validate input
        const validation = validateBackupInput({ merge });
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        try {
            // Verify access
            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            // Restore backup
            const restoredSummary = await this.backupService.restoreBackup(
                backupId,
                requestingUserId,
                merge
            );

            // Clear cache
            await cacheService.deletePattern(`summary:${restoredSummary._id}:*`);
            await cacheService.deletePattern(`backups:${restoredSummary._id}:*`);

            // Emit event
            eventEmitter.emit('backup.restored', {
                summaryId: restoredSummary._id,
                userId: requestingUserId,
                backupId,
            });

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('backup.restored', {
                userId: requestingUserId,
                summaryId: restoredSummary._id,
            });
            logger.info(`Backup ${backupId} restored for summary ${restoredSummary._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Backup restored successfully',
                data: {
                    summaryId: restoredSummary._id,
                    content: restoredSummary.content,
                    version: restoredSummary.versions[restoredSummary.versions.length - 1].versionNumber,
                },
            });
        } catch (error) {
            logger.error(`Backup restoration failed for backup ${backupId}:`, error);
            metricsCollector.increment('backup.restore_failed', { userId: requestingUserId });
            if (error.message.includes('not found')) {
                return next(new AppError('Backup or summary not found', 404));
            }
            return next(new AppError('Failed to restore backup', 500));
        }
    });

    /**
     * Get backups for a summary
     * GET /api/v1/backup/:userId/:summaryId
     */
    getBackups = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, summaryId } = req.params;
        const requestingUserId = req.user.id;
        const { page = 1, limit = 10 } = req.query;

        try {
            // Verify access
            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            // Cache key
            const cacheKey = `backups:${summaryId}:${requestingUserId}:${page}:${limit}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('backup.cache_hit', { userId: requestingUserId });
                return ApiResponse.success(res, {
                    message: 'Backups retrieved from cache',
                    data: cached,
                });
            }

            // Get backups
            const backups = await this.backupService.getBackups(
                summaryId,
                requestingUserId,
                { page: parseInt(page), limit: parseInt(limit) }
            );

            // Cache result
            await cacheService.set(cacheKey, backups, 3600); // 1 hour

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('backup.fetched', {
                userId: requestingUserId,
                summaryId,
            });
            logger.info(`Fetched backups for summary ${summaryId} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Backups retrieved successfully',
                data: backups,
            });
        } catch (error) {
            logger.error(`Backup fetch failed for summary ${summaryId}:`, error);
            metricsCollector.increment('backup.fetch_failed', { userId: requestingUserId });
            if (error.message.includes('not found')) {
                return next(new AppError('Summary not found', 404));
            }
            return next(new AppError('Failed to fetch backups', 500));
        }
    });

    /**
     * Delete a backup
     * DELETE /api/v1/backup/:userId/:backupId
     */
    deleteBackup = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, backupId } = req.params;
        const requestingUserId = req.user.id;

        try {
            // Verify access
            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            // Delete backup
            const deletedBackup = await this.backupService.deleteBackup(backupId, requestingUserId);

            // Clear cache
            await cacheService.deletePattern(`backups:${deletedBackup.summaryId}:*`);

            // Emit event
            eventEmitter.emit('backup.deleted', {
                summaryId: deletedBackup.summaryId,
                userId: requestingUserId,
                backupId,
            });

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('backup.deleted', {
                userId: requestingUserId,
                summaryId: deletedBackup.summaryId,
            });
            logger.info(`Backup ${backupId} deleted for summary ${deletedBackup.summaryId} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Backup deleted successfully',
            });
        } catch (error) {
            logger.error(`Backup deletion failed for backup ${backupId}:`, error);
            metricsCollector.increment('backup.delete_failed', { userId: requestingUserId });
            if (error.message.includes('not found')) {
                return next(new AppError('Backup not found', 404));
            }
            return next(new AppError('Failed to delete backup', 500));
        }
    });

    /**
     * Bulk create backups
     * POST /api/v1/backup/:userId/bulk
     */
    bulkCreateBackups = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { summaryIds, notes = '' } = req.body;

        // Validate input
        if (!Array.isArray(summaryIds) || summaryIds.length === 0 || summaryIds.length > 100) {
            return next(new AppError('Invalid summary IDs array (1-100 IDs required)', 400));
        }

        // Sanitize input
        const sanitizedData = sanitizeInput({ notes });

        try {
            // Verify access
            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            // Create bulk backups
            const result = await this.backupService.bulkCreateBackups(
                summaryIds,
                requestingUserId,
                sanitizedData.notes
            );

            // Clear cache
            await Promise.all(summaryIds.map(id => cacheService.deletePattern(`backups:${id}:*`)));

            // Emit event
            eventEmitter.emit('backup.bulk_created', {
                userId: requestingUserId,
                summaryIds,
            });

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('backup.bulk_created', {
                userId: requestingUserId,
                count: result.created,
            });
            logger.info(`Bulk created ${result.created} backups in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Bulk backups created successfully',
                data: {
                    requested: summaryIds.length,
                    created: result.created,
                },
            });
        } catch (error) {
            logger.error(`Bulk backup creation failed for user ${requestingUserId}:`, error);
            metricsCollector.increment('backup.bulk_create_failed', { userId: requestingUserId });
            return next(new AppError('Failed to create bulk backups', 500));
        }
    });

    // Helper Methods

    /**
     * Check summary access
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

    /**
     * Validate backup notes
     */
    validateNotes(notes) {
        return typeof notes === 'string' && notes.length <= 1000;
    }
}

export default new BackupController();