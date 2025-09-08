import { Op } from 'sequelize';
import { v4 as uuidv4 } from 'uuid';
import Photo from '../models/Photo.js';
import PhotoSettings from '../models/PhotoSettings.js';
import PhotoHistory from '../models/PhotoHistory.js';
import { logger } from '../utils/logger.js';
import { ApiError } from '../utils/ApiError.js';
import { ApiResponse } from '../utils/ApiResponse.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import { setCacheData, getCacheData, deleteCacheData } from '../services/redis.service.js';
import promClient from 'prom-client';
import { validationResult } from 'express-validator';

// Metrics setup
const requestCounter = new promClient.Counter({
    name: 'photo_visibility_requests_total',
    help: 'Total number of photo visibility requests',
    labelNames: ['endpoint', 'method', 'status'],
});

const requestLatency = new promClient.Histogram({
    name: 'photo_visibility_duration_seconds',
    help: 'Photo visibility request latency in seconds',
    labelNames: ['endpoint', 'method'],
    buckets: [0.05, 0.1, 0.5, 1, 2, 5],
});

// Cache TTL configurations
const CACHE_TTL = {
    PHOTO: 300, // 5 minutes
    VISIBILITY: 180, // 3 minutes
    HISTORY: 1800, // 30 minutes
};

// Generate cache key
const generateCacheKey = (type, ...params) => {
    const key = `photo:visibility:${type}:${params.join(':')}`;
    return require('crypto').createHash('md5').update(key).digest('hex');
};

class VisibilityController {
    /**
     * Update photo visibility
     * PATCH /api/v1/photos/:photoId/visibility
     */
    updateVisibility = asyncHandler(async (req, res) => {
        const startTime = Date.now();
        const requestId = uuidv4();
        const endpoint = 'updateVisibility';
        const { photoId } = req.params;
        const { userId } = req.user;
        const { visibility, allowedUsers = [], allowedGroups = [] } = req.body;

        try {
            // Validate request
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                requestCounter.inc({ endpoint, method: 'PATCH', status: 400 });
                throw new ApiError(400, 'Validation failed', errors.array());
            }

            // Find photo with authorization check
            const photo = await Photo.findOne({
                where: { id: photoId, userId, deletedAt: null },
                include: [{ model: PhotoSettings, as: 'settings' }]
            });

            if (!photo) {
                requestCounter.inc({ endpoint, method: 'PATCH', status: 404 });
                throw new ApiError(404, 'Photo not found or access denied');
            }

            const settings = photo.settings || await PhotoSettings.create({
                photoId: photo.id,
                userId,
                visibilitySettings: { visibility: 'private', allowedUsers: [], allowedGroups: [] }
            });

            const beforeState = {
                visibility: photo.visibility || settings.visibilitySettings?.visibility || 'private',
                allowedUsers: settings.visibilitySettings?.allowedUsers || [],
                allowedGroups: settings.visibilitySettings?.allowedGroups || [],
                version: photo.version
            };

            // Start transaction
            const transaction = await Photo.sequelize.transaction();
            try {
                // Update visibility
                const visibilityData = {
                    visibility,
                    allowedUsers: visibility === 'restricted' ? allowedUsers : [],
                    allowedGroups: visibility === 'restricted' ? allowedGroups : []
                };

                await photo.update({
                    visibility,
                    version: photo.version + 1
                }, { transaction, context: { userId } });

                await settings.update({
                    visibilitySettings: visibilityData
                }, { transaction });

                // Log visibility change
                await PhotoHistory.create({
                    photoId,
                    userId,
                    action: 'update_visibility',
                    actionDescription: `Updated visibility to ${visibility}`,
                    actionData: {
                        newVisibility: visibility,
                        allowedUsers,
                        allowedGroups,
                        previousVisibility: beforeState.visibility
                    },
                    beforeState,
                    afterState: {
                        visibility,
                        allowedUsers: visibilityData.allowedUsers,
                        allowedGroups: visibilityData.allowedGroups,
                        version: photo.version + 1
                    },
                    source: req.headers['user-agent']?.includes('Mobile') ? 'mobile_app' : 'web',
                    ipAddress: req.ip,
                    userAgent: req.headers['user-agent'],
                    sessionId: req.sessionID,
                    requestId,
                    processingTime: Date.now() - startTime
                }, { transaction });

                await transaction.commit();

                // Invalidate cache
                await deleteCacheData(generateCacheKey('photo', photoId));
                await deleteCacheData(generateCacheKey('visibility', photoId));

                requestCounter.inc({ endpoint, method: 'PATCH', status: 200 });
                requestLatency.observe({ endpoint, method: 'PATCH' }, (Date.now() - startTime) / 1000);

                res.json(new ApiResponse(200, {
                    id: photo.id,
                    visibility,
                    allowedUsers: visibilityData.allowedUsers,
                    allowedGroups: visibilityData.allowedGroups,
                    version: photo.version
                }, 'Visibility updated successfully', [], requestId));
            } catch (error) {
                await transaction.rollback();
                throw error;
            }
        } catch (error) {
            logger.error('Visibility update error:', { message: error.message, stack: error.stack, requestId });
            requestCounter.inc({ endpoint, method: 'PATCH', status: error.statusCode || 500 });

            // Log failed visibility update
            await PhotoHistory.create({
                photoId,
                userId,
                action: 'update_visibility',
                actionDescription: 'Visibility update failed',
                actionData: {
                    params: req.body,
                    error: error.message
                },
                source: req.headers['user-agent']?.includes('Mobile') ? 'mobile_app' : 'web',
                ipAddress: req.ip,
                userAgent: req.headers['user-agent'],
                requestId,
                processingTime: Date.now() - startTime,
                success: false,
                errorMessage: error.message,
                errorCode: 'VISIBILITY_UPDATE_FAILED'
            }).catch(historyError => {
                logger.error('Failed to log visibility update error:', { message: historyError.message });
            });

            throw error instanceof ApiError ? error : new ApiError(500, 'Visibility update failed');
        }
    });

    /**
     * Get photo visibility
     * GET /api/v1/photos/:photoId/visibility
     */
    getVisibility = asyncHandler(async (req, res) => {
        const startTime = Date.now();
        const requestId = uuidv4();
        const endpoint = 'getVisibility';
        const { photoId } = req.params;
        const { userId } = req.user;

        try {
            // Validate request
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                requestCounter.inc({ endpoint, method: 'GET', status: 400 });
                throw new ApiError(400, 'Validation failed', errors.array());
            }

            const cacheKey = generateCacheKey('visibility', photoId);
            let visibilityData = await getCacheData(cacheKey);

            if (!visibilityData) {
                const photo = await Photo.findOne({
                    where: { id: photoId, userId, deletedAt: null },
                    include: [{ model: PhotoSettings, as: 'settings' }]
                });

                if (!photo) {
                    requestCounter.inc({ endpoint, method: 'GET', status: 404 });
                    throw new ApiError(404, 'Photo not found or access denied');
                }

                const settings = photo.settings || { visibilitySettings: { visibility: 'private', allowedUsers: [], allowedGroups: [] } };

                visibilityData = {
                    id: photo.id,
                    visibility: photo.visibility || settings.visibilitySettings?.visibility || 'private',
                    allowedUsers: settings.visibilitySettings?.allowedUsers || [],
                    allowedGroups: settings.visibilitySettings?.allowedGroups || [],
                    version: photo.version
                };

                await setCacheData(cacheKey, visibilityData, CACHE_TTL.VISIBILITY);
            }

            requestCounter.inc({ endpoint, method: 'GET', status: 200 });
            requestLatency.observe({ endpoint, method: 'GET' }, (Date.now() - startTime) / 1000);

            res.json(new ApiResponse(200, visibilityData, 'Visibility retrieved successfully', [], requestId));
        } catch (error) {
            logger.error('Get visibility error:', { message: error.message, stack: error.stack, requestId });
            requestCounter.inc({ endpoint, method: 'GET', status: error.statusCode || 500 });
            throw error instanceof ApiError ? error : new ApiError(500, 'Failed to retrieve visibility');
        }
    });

    /**
     * Get visibility change history
     * GET /api/v1/photos/:photoId/visibility-history
     */
    getVisibilityHistory = asyncHandler(async (req, res) => {
        const startTime = Date.now();
        const requestId = uuidv4();
        const endpoint = 'getVisibilityHistory';
        const { photoId } = req.params;
        const { userId } = req.user;
        const { page = 1, limit = 20 } = req.query;

        try {
            // Validate request
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                requestCounter.inc({ endpoint, method: 'GET', status: 400 });
                throw new ApiError(400, 'Validation failed', errors.array());
            }

            const cacheKey = generateCacheKey('history', photoId, page, limit);
            let history = await getCacheData(cacheKey);

            if (!history) {
                const photo = await Photo.findOne({
                    where: { id: photoId, userId, deletedAt: null }
                });

                if (!photo) {
                    requestCounter.inc({ endpoint, method: 'GET', status: 404 });
                    throw new ApiError(404, 'Photo not found or access denied');
                }

                const pageNum = Math.max(1, parseInt(page));
                const limitNum = Math.min(50, Math.max(1, parseInt(limit)));

                const { rows, count } = await PhotoHistory.findAndCountAll({
                    where: {
                        photoId,
                        userId,
                        action: 'update_visibility'
                    },
                    order: [['createdAt', 'DESC']],
                    offset: (pageNum - 1) * limitNum,
                    limit: limitNum
                });

                history = {
                    history: rows,
                    pagination: {
                        page: pageNum,
                        limit: limitNum,
                        total: count,
                        pages: Math.ceil(count / limitNum),
                        hasNext: pageNum < Math.ceil(count / limitNum),
                        hasPrev: pageNum > 1
                    }
                };

                await setCacheData(cacheKey, history, CACHE_TTL.HISTORY);
            }

            requestCounter.inc({ endpoint, method: 'GET', status: 200 });
            requestLatency.observe({ endpoint, method: 'GET' }, (Date.now() - startTime) / 1000);

            res.json(new ApiResponse(200, history, 'Visibility history retrieved successfully', [], requestId));
        } catch (error) {
            logger.error('Get visibility history error:', { message: error.message, stack: error.stack, requestId });
            requestCounter.inc({ endpoint, method: 'GET', status: error.statusCode || 500 });
            throw error instanceof ApiError ? error : new ApiError(500, 'Failed to retrieve visibility history');
        }
    });

    /**
     * Bulk update visibility for multiple photos
     * PATCH /api/v1/photos/bulk-visibility
     */
    bulkUpdateVisibility = asyncHandler(async (req, res) => {
        const startTime = Date.now();
        const requestId = uuidv4();
        const batchId = uuidv4();
        const endpoint = 'bulkUpdateVisibility';
        const { userId } = req.user;
        const { photoIds, visibility, allowedUsers = [], allowedGroups = [] } = req.body;

        try {
            // Validate request
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                requestCounter.inc({ endpoint, method: 'PATCH', status: 400 });
                throw new ApiError(400, 'Validation failed', errors.array());
            }

            if (!photoIds || !Array.isArray(photoIds) || photoIds.length === 0) {
                requestCounter.inc({ endpoint, method: 'PATCH', status: 400 });
                throw new ApiError(400, 'Photo IDs array is required');
            }

            if (photoIds.length > 100) {
                requestCounter.inc({ endpoint, method: 'PATCH', status: 400 });
                throw new ApiError(400, 'Maximum 100 photos per batch');
            }

            // Find photos with authorization
            const photos = await Photo.findAll({
                where: {
                    id: { [Op.in]: photoIds },
                    userId,
                    deletedAt: null
                },
                include: [{ model: PhotoSettings, as: 'settings' }]
            });

            if (photos.length === 0) {
                requestCounter.inc({ endpoint, method: 'PATCH', status: 404 });
                throw new ApiError(404, 'No accessible photos found');
            }

            const results = [];
            const errors = [];

            // Process in batches to ensure atomicity
            const batchSize = 10;
            for (let i = 0; i < photos.length; i += batchSize) {
                const batch = photos.slice(i, i + batchSize);
                const transaction = await Photo.sequelize.transaction();
                try {
                    const batchPromises = batch.map(async (photo) => {
                        try {
                            const settings = photo.settings || await PhotoSettings.create({
                                photoId: photo.id,
                                userId,
                                visibilitySettings: { visibility: 'private', allowedUsers: [], allowedGroups: [] }
                            }, { transaction });

                            const beforeState = {
                                visibility: photo.visibility || settings.visibilitySettings?.visibility || 'private',
                                allowedUsers: settings.visibilitySettings?.allowedUsers || [],
                                allowedGroups: settings.visibilitySettings?.allowedGroups || [],
                                version: photo.version
                            };

                            const visibilityData = {
                                visibility,
                                allowedUsers: visibility === 'restricted' ? allowedUsers : [],
                                allowedGroups: visibility === 'restricted' ? allowedGroups : []
                            };

                            await photo.update({
                                visibility,
                                version: photo.version + 1
                            }, { transaction, context: { userId } });

                            await settings.update({
                                visibilitySettings: visibilityData
                            }, { transaction });

                            // Log visibility change
                            await PhotoHistory.create({
                                photoId: photo.id,
                                userId,
                                action: 'update_visibility',
                                actionDescription: `Bulk updated visibility to ${visibility}`,
                                actionData: {
                                    newVisibility: visibility,
                                    allowedUsers,
                                    allowedGroups,
                                    previousVisibility: beforeState.visibility,
                                    batchId
                                },
                                beforeState,
                                afterState: {
                                    visibility,
                                    allowedUsers: visibilityData.allowedUsers,
                                    allowedGroups: visibilityData.allowedGroups,
                                    version: photo.version + 1
                                },
                                source: req.headers['user-agent']?.includes('Mobile') ? 'mobile_app' : 'web',
                                ipAddress: req.ip,
                                userAgent: req.headers['user-agent'],
                                sessionId: req.sessionID,
                                requestId,
                                batchId,
                                processingTime: Date.now() - startTime
                            }, { transaction });

                            results.push({
                                photoId: photo.id,
                                visibility,
                                allowedUsers: visibilityData.allowedUsers,
                                allowedGroups: visibilityData.allowedGroups
                            });
                        } catch (error) {
                            errors.push({
                                photoId: photo.id,
                                error: error.message
                            });
                        }
                    });

                    await Promise.all(batchPromises);
                    await transaction.commit();

                    // Invalidate cache for processed photos
                    for (const photo of batch) {
                        await deleteCacheData(generateCacheKey('photo', photo.id));
                        await deleteCacheData(generateCacheKey('visibility', photo.id));
                    }
                } catch (error) {
                    await transaction.rollback();
                    throw error;
                }
            }

            // Log batch visibility update
            await PhotoHistory.create({
                userId,
                action: 'bulk_update_visibility',
                actionDescription: `Bulk visibility update: ${results.length} successful, ${errors.length} failed`,
                actionData: {
                    batchSize: photos.length,
                    successful: results.length,
                    failed: errors.length,
                    visibility,
                    allowedUsers,
                    allowedGroups,
                    batchId
                },
                source: req.headers['user-agent']?.includes('Mobile') ? 'mobile_app' : 'web',
                ipAddress: req.ip,
                userAgent: req.headers['user-agent'],
                sessionId: req.sessionID,
                requestId,
                batchId,
                processingTime: Date.now() - startTime,
                success: results.length > 0
            });

            requestCounter.inc({ endpoint, method: 'PATCH', status: 200 });
            requestLatency.observe({ endpoint, method: 'PATCH' }, (Date.now() - startTime) / 1000);

            res.json(new ApiResponse(200, {
                successful: results,
                failed: errors,
                summary: {
                    total: photos.length,
                    successful: results.length,
                    failed: errors.length
                }
            }, 'Bulk visibility update completed', [], requestId));
        } catch (error) {
            logger.error('Bulk visibility update error:', { message: error.message, stack: error.stack, requestId, batchId });
            requestCounter.inc({ endpoint, method: 'PATCH', status: error.statusCode || 500 });
            throw error instanceof ApiError ? error : new ApiError(500, 'Bulk visibility update failed');
        }
    });
}

export default new VisibilityController();