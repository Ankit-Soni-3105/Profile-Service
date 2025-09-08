import { Op } from 'sequelize';
import sharp from 'sharp';
import { v4 as uuidv4 } from 'uuid';
import Photo from '../models/photo.model.js';
import PhotoSettings from '../models/photo.setting.js';
import PhotoHistory from '../models/photo.history.model.js';
import { logger } from '../utils/logger.js';
import { ApiError } from '../utils/ApiError.js';
import { ApiResponse } from '../utils/ApiResponse.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import { uploadToCloudinary, deleteFromCloudinary } from '../services/cloudinaryService.js';
import { setCacheData, getCacheData, deleteCacheData } from '../services/redis.service.js';
import promClient from 'prom-client';
import { validationResult } from 'express-validator';

// Metrics setup
const requestCounter = new promClient.Counter({
    name: 'photo_optimization_requests_total',
    help: 'Total number of photo optimization requests',
    labelNames: ['endpoint', 'method', 'status'],
});

const requestLatency = new promClient.Histogram({
    name: 'photo_optimization_duration_seconds',
    help: 'Photo optimization request latency in seconds',
    labelNames: ['endpoint', 'method'],
    buckets: [0.1, 0.5, 1, 2, 5, 10],
});

// Cache TTL configurations
const CACHE_TTL = {
    PHOTO: 300, // 5 minutes
    PREVIEW: 180, // 3 minutes
    RECOMMENDATIONS: 600, // 10 minutes
    HISTORY: 1800, // 30 minutes
};

// Generate cache key
const generateCacheKey = (type, ...params) => {
    const key = `photo:optimization:${type}:${params.join(':')}`;
    return require('crypto').createHash('md5').update(key).digest('hex');
};

class OptimizationController {
    /**
     * Optimize a single photo
     * POST /api/v1/photos/:photoId/optimize
     */
    optimizePhoto = asyncHandler(async (req, res) => {
        const startTime = Date.now();
        const requestId = uuidv4();
        const endpoint = 'optimizePhoto';
        const { photoId } = req.params;
        const { userId } = req.user;
        const {
            quality,
            format,
            maxWidth,
            maxHeight,
            targetFileSize,
            progressive = true,
            stripMetadata = true
        } = req.body;

        try {
            // Validate request
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                requestCounter.inc({ endpoint, method: 'POST', status: 400 });
                throw new ApiError(400, 'Validation failed', errors.array());
            }

            // Find photo with authorization check
            const photo = await Photo.findOne({
                where: {
                    id: photoId,
                    userId,
                    deletedAt: null
                },
                include: [{
                    model: PhotoSettings,
                    as: 'settings'
                }]
            });

            if (!photo) {
                requestCounter.inc({ endpoint, method: 'POST', status: 404 });
                throw new ApiError(404, 'Photo not found or access denied');
            }

            const settings = photo.settings || await PhotoSettings.create({
                photoId: photo.id,
                userId,
                jpegQuality: 85,
                webpQuality: 80,
                enableAutoFormat: true,
                enableProgressiveJpeg: true,
                enableExifStripping: true,
                optimizationLevel: 'medium'
            });

            const beforeState = {
                width: photo.width,
                height: photo.height,
                fileSize: photo.fileSize,
                mimeType: photo.mimeType,
                compressionLevel: photo.compressionLevel,
                version: photo.version
            };

            // Determine optimization parameters
            const optimizationConfig = this.buildOptimizationConfig(
                { quality, format, maxWidth, maxHeight, targetFileSize, progressive, stripMetadata },
                settings
            );

            // Perform optimization
            const result = await this.performOptimization(photo, optimizationConfig);

            // Start transaction
            const transaction = await Photo.sequelize.transaction();
            try {
                // Update photo record
                await photo.update({
                    width: result.metadata.width,
                    height: result.metadata.height,
                    fileSize: result.buffer.length,
                    mimeType: result.format,
                    compressionLevel: optimizationConfig.quality,
                    aspectRatio: (result.metadata.width / result.metadata.height).toFixed(4),
                    processingStatus: 'completed',
                    isProcessed: true,
                    version: photo.version + 1,
                    qualityScore: await this.calculateQualityScore(result.buffer, result.metadata)
                }, { transaction, context: { userId } });

                // Store optimized image
                const uploadResult = await this.storeOptimizedImage(photo, result.buffer);

                // Generate variants if enabled
                let variants = {};
                if (settings?.generateThumbnails && settings?.thumbnailSizes) {
                    variants = await this.generateVariants(photo, result.buffer, settings.thumbnailSizes);
                    await photo.update({ variants }, { transaction, context: { userId } });
                }

                // Log optimization history
                await PhotoHistory.create({
                    photoId: photo.id,
                    userId,
                    action: 'optimize',
                    actionDescription: `Photo optimized with ${optimizationConfig.level} compression`,
                    actionData: {
                        optimizationConfig,
                        sizeBefore: beforeState.fileSize,
                        sizeAfter: result.buffer.length,
                        compressionRatio: ((beforeState.fileSize - result.buffer.length) / beforeState.fileSize * 100).toFixed(2),
                        formatChange: beforeState.mimeType !== result.format,
                        variantsGenerated: Object.keys(variants).length,
                        cloudinaryUrl: uploadResult.secure_url
                    },
                    beforeState,
                    afterState: {
                        width: result.metadata.width,
                        height: result.metadata.height,
                        fileSize: result.buffer.length,
                        mimeType: result.format,
                        compressionLevel: optimizationConfig.quality
                    },
                    source: req.headers['user-agent']?.includes('Mobile') ? 'mobile_app' : 'web',
                    ipAddress: req.ip,
                    userAgent: req.headers['user-agent'],
                    sessionId: req.sessionID,
                    requestId,
                    processingTime: Date.now() - startTime,
                    fileSizeBefore: beforeState.fileSize,
                    fileSizeAfter: result.buffer.length,
                    dimensionsBefore: { width: beforeState.width, height: beforeState.height },
                    dimensionsAfter: { width: result.metadata.width, height: result.metadata.height },
                    qualityBefore: photo.qualityScore,
                    qualityAfter: await this.calculateQualityScore(result.buffer, result.metadata)
                }, { transaction });

                await transaction.commit();

                // Invalidate cache
                await deleteCacheData(generateCacheKey('photo', photoId));
                await deleteCacheData(generateCacheKey('recommendations', userId));

                requestCounter.inc({ endpoint, method: 'POST', status: 200 });
                requestLatency.observe({ endpoint, method: 'POST' }, (Date.now() - startTime) / 1000);

                res.json(new ApiResponse(200, {
                    id: photo.id,
                    optimization: {
                        originalSize: beforeState.fileSize,
                        optimizedSize: result.buffer.length,
                        compressionRatio: ((beforeState.fileSize - result.buffer.length) / beforeState.fileSize * 100).toFixed(2) + '%',
                        spaceSaved: beforeState.fileSize - result.buffer.length,
                        quality: optimizationConfig.quality,
                        format: result.format,
                        dimensions: {
                            width: result.metadata.width,
                            height: result.metadata.height
                        },
                        cloudinaryUrl: uploadResult.secure_url
                    },
                    variants: Object.keys(variants),
                    qualityScore: await this.calculateQualityScore(result.buffer, result.metadata)
                }, 'Photo optimized successfully', [], requestId));
            } catch (error) {
                await transaction.rollback();
                throw error;
            }
        } catch (error) {
            logger.error('Optimization error:', { message: error.message, stack: error.stack, requestId });
            requestCounter.inc({ endpoint, method: 'POST', status: error.statusCode || 500 });

            // Log failed optimization
            await PhotoHistory.create({
                photoId,
                userId,
                action: 'optimize',
                actionDescription: 'Photo optimization failed',
                actionData: {
                    optimizationParams: req.body,
                    error: error.message
                },
                source: req.headers['user-agent']?.includes('Mobile') ? 'mobile_app' : 'web',
                ipAddress: req.ip,
                userAgent: req.headers['user-agent'],
                requestId,
                processingTime: Date.now() - startTime,
                success: false,
                errorMessage: error.message,
                errorCode: 'OPTIMIZATION_FAILED'
            }).catch(historyError => {
                logger.error('Failed to log optimization error:', { message: historyError.message });
            });

            throw error instanceof ApiError ? error : new ApiError(500, 'Optimization failed');
        }
    });

    /**
     * Batch optimize multiple photos
     * POST /api/v1/photos/batch-optimize
     */
    batchOptimize = asyncHandler(async (req, res) => {
        const startTime = Date.now();
        const requestId = uuidv4();
        const batchId = uuidv4();
        const endpoint = 'batchOptimize';
        const { userId } = req.user;
        const { photoIds, optimizationLevel = 'medium', targetFileSize } = req.body;

        try {
            // Validate request
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                requestCounter.inc({ endpoint, method: 'POST', status: 400 });
                throw new ApiError(400, 'Validation failed', errors.array());
            }

            if (!photoIds || !Array.isArray(photoIds) || photoIds.length === 0) {
                requestCounter.inc({ endpoint, method: 'POST', status: 400 });
                throw new ApiError(400, 'Photo IDs array is required');
            }

            if (photoIds.length > 100) {
                requestCounter.inc({ endpoint, method: 'POST', status: 400 });
                throw new ApiError(400, 'Maximum 100 photos per batch');
            }

            // Find photos with authorization
            const photos = await Photo.findAll({
                where: {
                    id: { [Op.in]: photoIds },
                    userId,
                    deletedAt: null
                },
                include: [{
                    model: PhotoSettings,
                    as: 'settings'
                }]
            });

            if (photos.length === 0) {
                requestCounter.inc({ endpoint, method: 'POST', status: 404 });
                throw new ApiError(404, 'No accessible photos found');
            }

            const results = [];
            const errors = [];
            let totalSizeBefore = 0;
            let totalSizeAfter = 0;

            // Process in batches to prevent memory issues
            const batchSize = 5;
            for (let i = 0; i < photos.length; i += batchSize) {
                const batch = photos.slice(i, i + batchSize);
                const transaction = await Photo.sequelize.transaction();
                try {
                    const batchPromises = batch.map(async (photo) => {
                        try {
                            const beforeSize = photo.fileSize;
                            totalSizeBefore += beforeSize;

                            const settings = photo.settings || await PhotoSettings.create({
                                photoId: photo.id,
                                userId,
                                jpegQuality: 85,
                                webpQuality: 80,
                                enableAutoFormat: true,
                                enableProgressiveJpeg: true,
                                enableExifStripping: true,
                                optimizationLevel: 'medium'
                            }, { transaction });

                            const optimizationConfig = this.buildOptimizationConfig(
                                { optimizationLevel, targetFileSize },
                                settings
                            );

                            const result = await this.performOptimization(photo, optimizationConfig);
                            totalSizeAfter += result.buffer.length;

                            await photo.update({
                                width: result.metadata.width,
                                height: result.metadata.height,
                                fileSize: result.buffer.length,
                                mimeType: result.format,
                                compressionLevel: optimizationConfig.quality,
                                aspectRatio: (result.metadata.width / result.metadata.height).toFixed(4),
                                processingStatus: 'completed',
                                isProcessed: true,
                                version: photo.version + 1,
                                qualityScore: await this.calculateQualityScore(result.buffer, result.metadata)
                            }, { transaction, context: { userId } });

                            const uploadResult = await this.storeOptimizedImage(photo, result.buffer);

                            results.push({
                                photoId: photo.id,
                                originalSize: beforeSize,
                                optimizedSize: result.buffer.length,
                                compressionRatio: ((beforeSize - result.buffer.length) / beforeSize * 100).toFixed(2) + '%',
                                spaceSaved: beforeSize - result.buffer.length,
                                cloudinaryUrl: uploadResult.secure_url
                            });

                            // Log history
                            await PhotoHistory.create({
                                photoId: photo.id,
                                userId,
                                action: 'optimize',
                                actionDescription: `Batch optimization with ${optimizationConfig.level} compression`,
                                actionData: {
                                    optimizationConfig,
                                    sizeBefore: beforeSize,
                                    sizeAfter: result.buffer.length,
                                    compressionRatio: ((beforeSize - result.buffer.length) / beforeSize * 100).toFixed(2),
                                    formatChange: photo.mimeType !== result.format,
                                    cloudinaryUrl: uploadResult.secure_url
                                },
                                beforeState: {
                                    width: photo.width,
                                    height: photo.height,
                                    fileSize: beforeSize,
                                    mimeType: photo.mimeType,
                                    compressionLevel: photo.compressionLevel
                                },
                                afterState: {
                                    width: result.metadata.width,
                                    height: result.metadata.height,
                                    fileSize: result.buffer.length,
                                    mimeType: result.format,
                                    compressionLevel: optimizationConfig.quality
                                },
                                source: req.headers['user-agent']?.includes('Mobile') ? 'mobile_app' : 'web',
                                ipAddress: req.ip,
                                userAgent: req.headers['user-agent'],
                                sessionId: req.sessionID,
                                requestId,
                                batchId,
                                processingTime: Date.now() - startTime
                            }, { transaction });
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
                    }
                } catch (error) {
                    await transaction.rollback();
                    throw error;
                }
            }

            // Log batch optimization
            await PhotoHistory.create({
                userId,
                action: 'batch_optimize',
                actionDescription: `Batch optimization: ${results.length} successful, ${errors.length} failed`,
                actionData: {
                    batchSize: photos.length,
                    successful: results.length,
                    failed: errors.length,
                    optimizationLevel,
                    targetFileSize,
                    totalSizeBefore,
                    totalSizeAfter,
                    totalSpaceSaved: totalSizeBefore - totalSizeAfter,
                    overallCompressionRatio: ((totalSizeBefore - totalSizeAfter) / totalSizeBefore * 100).toFixed(2) + '%'
                },
                source: req.headers['user-agent']?.includes('Mobile') ? 'mobile_app' : 'web',
                ipAddress: req.ip,
                userAgent: req.headers['user-agent'],
                sessionId: req.sessionID,
                requestId,
                batchId,
                processingTime: Date.now() - startTime,
                fileSizeBefore: totalSizeBefore,
                fileSizeAfter: totalSizeAfter,
                success: results.length > 0
            });

            // Invalidate recommendations cache
            await deleteCacheData(generateCacheKey('recommendations', userId));

            requestCounter.inc({ endpoint, method: 'POST', status: 200 });
            requestLatency.observe({ endpoint, method: 'POST' }, (Date.now() - startTime) / 1000);

            res.json(new ApiResponse(200, {
                successful: results,
                failed: errors,
                summary: {
                    total: photos.length,
                    successful: results.length,
                    failed: errors.length,
                    totalSizeBefore,
                    totalSizeAfter,
                    totalSpaceSaved: totalSizeBefore - totalSizeAfter,
                    overallCompressionRatio: ((totalSizeBefore - totalSizeAfter) / totalSizeBefore * 100).toFixed(2) + '%'
                }
            }, 'Batch optimization completed', [], requestId));
        } catch (error) {
            logger.error('Batch optimization error:', { message: error.message, stack: error.stack, requestId, batchId });
            requestCounter.inc({ endpoint, method: 'POST', status: error.statusCode || 500 });
            throw error instanceof ApiError ? error : new ApiError(500, 'Batch optimization failed');
        }
    });

    /**
     * Get optimization preview
     * GET /api/v1/photos/:photoId/optimize-preview
     */
    getOptimizationPreview = asyncHandler(async (req, res) => {
        const startTime = Date.now();
        const requestId = uuidv4();
        const endpoint = 'getOptimizationPreview';
        const { photoId } = req.params;
        const { userId } = req.user;
        const { quality = 85, format, maxWidth, maxHeight } = req.query;

        try {
            // Validate request
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                requestCounter.inc({ endpoint, method: 'GET', status: 400 });
                throw new ApiError(400, 'Validation failed', errors.array());
            }

            const cacheKey = generateCacheKey('preview', photoId, quality, format || 'default', maxWidth || 'default', maxHeight || 'default');
            let preview = await getCacheData(cacheKey);

            if (!preview) {
                const photo = await Photo.findOne({
                    where: { id: photoId, userId, deletedAt: null },
                    include: [{
                        model: PhotoSettings,
                        as: 'settings'
                    }]
                });

                if (!photo) {
                    requestCounter.inc({ endpoint, method: 'GET', status: 404 });
                    throw new ApiError(404, 'Photo not found');
                }

                const settings = photo.settings || await PhotoSettings.findOne({ where: { photoId } });

                const optimizationConfig = this.buildOptimizationConfig(
                    { quality: parseInt(quality), format, maxWidth: maxWidth ? parseInt(maxWidth) : null, maxHeight: maxHeight ? parseInt(maxHeight) : null },
                    settings
                );

                preview = await this.generateOptimizationPreview(photo, optimizationConfig);
                await setCacheData(cacheKey, preview, CACHE_TTL.PREVIEW);
            }

            requestCounter.inc({ endpoint, method: 'GET', status: 200 });
            requestLatency.observe({ endpoint, method: 'GET' }, (Date.now() - startTime) / 1000);

            res.json(new ApiResponse(200, {
                preview,
                recommendations: this.getOptimizationRecommendations(photo, photo.settings)
            }, 'Optimization preview generated successfully', [], requestId));
        } catch (error) {
            logger.error('Optimization preview error:', { message: error.message, stack: error.stack, requestId });
            requestCounter.inc({ endpoint, method: 'GET', status: error.statusCode || 500 });
            throw error instanceof ApiError ? error : new ApiError(500, 'Failed to generate optimization preview');
        }
    });

    /**
     * Get optimization recommendations
     * GET /api/v1/photos/recommendations
     */
    getOptimizationRecommendations = asyncHandler(async (req, res) => {
        const startTime = Date.now();
        const requestId = uuidv4();
        const endpoint = 'getOptimizationRecommendations';
        const { userId } = req.user;

        try {
            const cacheKey = generateCacheKey('recommendations', userId);
            let recommendations = await getCacheData(cacheKey);

            if (!recommendations) {
                const candidates = await Photo.findAll({
                    where: {
                        userId,
                        deletedAt: null,
                        [Op.or]: [
                            { fileSize: { [Op.gt]: 5 * 1024 * 1024 } }, // > 5MB
                            { compressionLevel: { [Op.lt]: 80 } }, // Low compression
                            { isProcessed: false }
                        ]
                    },
                    include: [{
                        model: PhotoSettings,
                        as: 'settings'
                    }],
                    order: [['fileSize', 'DESC']],
                    limit: 50
                });

                recommendations = candidates.map(photo => {
                    const potential = this.calculateOptimizationPotential(photo, photo.settings);
                    return {
                        photoId: photo.id,
                        fileName: photo.fileName,
                        currentSize: photo.fileSize,
                        estimatedOptimizedSize: potential.estimatedSize,
                        potentialSavings: potential.savings,
                        compressionRatio: potential.compressionRatio,
                        priority: potential.priority,
                        reasons: potential.reasons
                    };
                }).filter(r => r.potentialSavings > 100 * 1024); // Only show if > 100KB savings

                const totalPotentialSavings = recommendations.reduce((sum, r) => sum + r.potentialSavings, 0);

                recommendations = {
                    recommendations: recommendations.slice(0, 20), // Top 20
                    summary: {
                        totalCandidates: candidates.length,
                        totalCurrentSize: candidates.reduce((sum, p) => sum + p.fileSize, 0),
                        totalPotentialSavings,
                        estimatedSpaceRecovery: ((totalPotentialSavings / (1024 * 1024 * 1024)) * 100).toFixed(2) + ' GB'
                    }
                };

                await setCacheData(cacheKey, recommendations, CACHE_TTL.RECOMMENDATIONS);
            }

            requestCounter.inc({ endpoint, method: 'GET', status: 200 });
            requestLatency.observe({ endpoint, method: 'GET' }, (Date.now() - startTime) / 1000);

            res.json(new ApiResponse(200, recommendations, 'Optimization recommendations retrieved successfully', [], requestId));
        } catch (error) {
            logger.error('Get optimization recommendations error:', { message: error.message, stack: error.stack, requestId });
            requestCounter.inc({ endpoint, method: 'GET', status: error.statusCode || 500 });
            throw error instanceof ApiError ? error : new ApiError(500, 'Failed to get optimization recommendations');
        }
    });

    /**
     * Revert to previous optimization version
     * POST /api/v1/photos/:photoId/revert-optimization
     */
    revertOptimization = asyncHandler(async (req, res) => {
        const startTime = Date.now();
        const requestId = uuidv4();
        const endpoint = 'revertOptimization';
        const { photoId } = req.params;
        const { userId } = req.user;
        const { version } = req.body;

        try {
            // Validate request
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                requestCounter.inc({ endpoint, method: 'POST', status: 400 });
                throw new ApiError(400, 'Validation failed', errors.array());
            }

            const photo = await Photo.findOne({
                where: { id: photoId, userId, deletedAt: null }
            });

            if (!photo) {
                requestCounter.inc({ endpoint, method: 'POST', status: 404 });
                throw new ApiError(404, 'Photo not found or access denied');
            }

            const history = await PhotoHistory.findOne({
                where: {
                    photoId,
                    action: 'optimize',
                    'beforeState.version': version
                },
                order: [['createdAt', 'DESC']]
            });

            if (!history) {
                requestCounter.inc({ endpoint, method: 'POST', status: 404 });
                throw new ApiError(404, 'Optimization version not found');
            }

            const transaction = await Photo.sequelize.transaction();
            try {
                // Update photo to previous state
                await photo.update({
                    width: history.beforeState.width,
                    height: history.beforeState.height,
                    fileSize: history.beforeState.fileSize,
                    mimeType: history.beforeState.mimeType,
                    compressionLevel: history.beforeState.compressionLevel,
                    aspectRatio: (history.beforeState.width / history.beforeState.height).toFixed(4),
                    processingStatus: 'completed',
                    isProcessed: true,
                    version: photo.version + 1,
                    qualityScore: history.qualityBefore
                }, { transaction, context: { userId } });

                // Revert image in storage
                await this.storeOptimizedImage(photo, Buffer.alloc(history.beforeState.fileSize)); // Mock for now

                // Log revert action
                await PhotoHistory.create({
                    photoId,
                    userId,
                    action: 'revert_optimization',
                    actionDescription: `Reverted optimization to version ${version}`,
                    actionData: {
                        revertedVersion: version,
                        previousState: history.afterState
                    },
                    beforeState: {
                        width: history.afterState.width,
                        height: history.afterState.height,
                        fileSize: history.afterState.fileSize,
                        mimeType: history.afterState.mimeType,
                        compressionLevel: history.afterState.compressionLevel
                    },
                    afterState: history.beforeState,
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
                await deleteCacheData(generateCacheKey('recommendations', userId));

                requestCounter.inc({ endpoint, method: 'POST', status: 200 });
                requestLatency.observe({ endpoint, method: 'POST' }, (Date.now() - startTime) / 1000);

                res.json(new ApiResponse(200, {
                    id: photo.id,
                    version: photo.version,
                    dimensions: {
                        width: photo.width,
                        height: photo.height
                    },
                    fileSize: photo.fileSize
                }, 'Optimization reverted successfully', [], requestId));
            } catch (error) {
                await transaction.rollback();
                throw error;
            }
        } catch (error) {
            logger.error('Revert optimization error:', { message: error.message, stack: error.stack, requestId });
            requestCounter.inc({ endpoint, method: 'POST', status: error.statusCode || 500 });
            throw error instanceof ApiError ? error : new ApiError(500, 'Failed to revert optimization');
        }
    });

    /**
     * Get optimization history
     * GET /api/v1/photos/:photoId/optimization-history
     */
    getOptimizationHistory = asyncHandler(async (req, res) => {
        const startTime = Date.now();
        const requestId = uuidv4();
        const endpoint = 'getOptimizationHistory';
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
                        action: { [Op.in]: ['optimize', 'revert_optimization', 'batch_optimize'] }
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

            res.json(new ApiResponse(200, history, 'Optimization history retrieved successfully', [], requestId));
        } catch (error) {
            logger.error('Get optimization history error:', { message: error.message, stack: error.stack, requestId });
            requestCounter.inc({ endpoint, method: 'GET', status: error.statusCode || 500 });
            throw error instanceof ApiError ? error : new ApiError(500, 'Failed to get optimization history');
        }
    });

    /**
     * Preview batch optimization
     * POST /api/v1/photos/batch-optimize-preview
     */
    batchOptimizePreview = asyncHandler(async (req, res) => {
        const startTime = Date.now();
        const requestId = uuidv4();
        const batchId = uuidv4();
        const endpoint = 'batchOptimizePreview';
        const { userId } = req.user;
        const { photoIds, optimizationLevel = 'medium', targetFileSize } = req.body;

        try {
            // Validate request
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                requestCounter.inc({ endpoint, method: 'POST', status: 400 });
                throw new ApiError(400, 'Validation failed', errors.array());
            }

            if (!photoIds || !Array.isArray(photoIds) || photoIds.length === 0) {
                requestCounter.inc({ endpoint, method: 'POST', status: 400 });
                throw new ApiError(400, 'Photo IDs array is required');
            }

            if (photoIds.length > 100) {
                requestCounter.inc({ endpoint, method: 'POST', status: 400 });
                throw new ApiError(400, 'Maximum 100 photos per batch');
            }

            const cacheKey = generateCacheKey('batch_preview', userId, optimizationLevel, photoIds.join(':'));
            let previews = await getCacheData(cacheKey);

            if (!previews) {
                const photos = await Photo.findAll({
                    where: {
                        id: { [Op.in]: photoIds },
                        userId,
                        deletedAt: null
                    },
                    include: [{
                        model: PhotoSettings,
                        as: 'settings'
                    }]
                });

                if (photos.length === 0) {
                    requestCounter.inc({ endpoint, method: 'POST', status: 404 });
                    throw new ApiError(404, 'No accessible photos found');
                }

                previews = await Promise.all(photos.map(async (photo) => {
                    const settings = photo.settings || await PhotoSettings.findOne({ where: { photoId: photo.id } });
                    const optimizationConfig = this.buildOptimizationConfig(
                        { optimizationLevel, targetFileSize },
                        settings
                    );

                    const preview = await this.generateOptimizationPreview(photo, optimizationConfig);
                    return {
                        photoId: photo.id,
                        originalSize: photo.fileSize,
                        estimatedSize: preview.estimatedSize,
                        compressionRatio: preview.compressionRatio,
                        spaceSaved: photo.fileSize - preview.estimatedSize,
                        quality: optimizationConfig.quality,
                        format: optimizationConfig.format || photo.mimeType,
                        estimatedDimensions: preview.dimensions
                    };
                }));

                await setCacheData(cacheKey, previews, CACHE_TTL.PREVIEW);
            }

            const summary = {
                total: previews.length,
                totalOriginalSize: previews.reduce((sum, p) => sum + p.originalSize, 0),
                totalEstimatedSize: previews.reduce((sum, p) => sum + p.estimatedSize, 0),
                totalSpaceSaved: previews.reduce((sum, p) => sum + (p.originalSize - p.estimatedSize), 0),
                overallCompressionRatio: ((previews.reduce((sum, p) => sum + (p.originalSize - p.estimatedSize), 0) / previews.reduce((sum, p) => sum + p.originalSize, 0)) * 100).toFixed(2) + '%'
            };

            requestCounter.inc({ endpoint, method: 'POST', status: 200 });
            requestLatency.observe({ endpoint, method: 'POST' }, (Date.now() - startTime) / 1000);

            res.json(new ApiResponse(200, { previews, summary }, 'Batch optimization preview generated successfully', [], requestId));
        } catch (error) {
            logger.error('Batch optimization preview error:', { message: error.message, stack: error.stack, requestId, batchId });
            requestCounter.inc({ endpoint, method: 'POST', status: error.statusCode || 500 });
            throw error instanceof ApiError ? error : new ApiError(500, 'Failed to generate batch optimization preview');
        }
    });

    // Helper methods
    buildOptimizationConfig(params, settings) {
        const config = {
            quality: params.quality || settings?.jpegQuality || 85,
            webpQuality: settings?.webpQuality || 80,
            format: params.format || (settings?.enableAutoFormat ? 'webp' : null),
            maxWidth: params.maxWidth || settings?.maxWidth,
            maxHeight: params.maxHeight || settings?.maxHeight,
            progressive: params.progressive !== false && (settings?.enableProgressiveJpeg !== false),
            stripMetadata: params.stripMetadata !== false && (settings?.enableExifStripping !== false),
            level: params.optimizationLevel || settings?.optimizationLevel || 'medium',
            targetFileSize: params.targetFileSize || settings?.targetFileSize
        };

        // Adjust quality based on optimization level
        if (params.optimizationLevel && !params.quality) {
            const qualityMap = {
                none: 95,
                low: 90,
                medium: 85,
                high: 75,
                aggressive: 65
            };
            config.quality = qualityMap[params.optimizationLevel] || 85;
        }

        // Validate parameters
        if (config.quality < 1 || config.quality > 100) {
            throw new ApiError(400, 'Quality must be between 1 and 100');
        }
        if (config.maxWidth && config.maxWidth < 1) {
            throw new ApiError(400, 'maxWidth must be a positive integer');
        }
        if (config.maxHeight && config.maxHeight < 1) {
            throw new ApiError(400, 'maxHeight must be a positive integer');
        }
        if (config.targetFileSize && config.targetFileSize < 1024) {
            throw new ApiError(400, 'targetFileSize must be at least 1KB');
        }

        return config;
    }

    async performOptimization(photo, config) {
        try {
            // Fetch image from Cloudinary (assuming storage is handled by Cloudinary)
            const imageBuffer = Buffer.alloc(photo.fileSize); // Mock for now, replace with actual fetch
            let sharpInstance = sharp(imageBuffer);

            // Apply transformations
            if (config.maxWidth || config.maxHeight) {
                sharpInstance = sharpInstance.resize({
                    width: config.maxWidth,
                    height: config.maxHeight,
                    fit: 'inside',
                    withoutEnlargement: true
                });
            }

            if (config.stripMetadata) {
                sharpInstance = sharpInstance.withMetadata(false);
            }

            const format = config.format || photo.mimeType.split('/')[1];
            sharpInstance = sharpInstance.toFormat(format, {
                quality: config.format === 'webp' ? config.webpQuality : config.quality,
                progressive: config.progressive
            });

            const buffer = await sharpInstance.toBuffer();
            const metadata = await sharp(buffer).metadata();

            return {
                buffer,
                metadata,
                format: `image/${metadata.format}`
            };
        } catch (error) {
            logger.error('Optimization failed:', { message: error.message, photoId: photo.id });
            throw new ApiError(500, `Optimization failed: ${error.message}`);
        }
    }

    async storeOptimizedImage(photo, buffer) {
        try {
            const fileExtension = this.getFileExtension(photo.mimeType);
            const uniqueFileName = `${uuidv4()}_optimized_${Date.now()}.${fileExtension}`;
            const folder = `photos/${photo.userId}/${new Date().getFullYear()}/${new Date().getMonth() + 1}`;

            const uploadResult = await uploadToCloudinary(buffer, {
                folder,
                public_id: uniqueFileName,
                resource_type: 'image'
            });

            // Update photo with new storage details
            await photo.update({
                storagePath: uploadResult.public_id,
                cloudinaryUrl: uploadResult.secure_url
            });

            return uploadResult;
        } catch (error) {
            logger.error('Store optimized image error:', { message: error.message, photoId: photo.id });
            throw new ApiError(500, 'Failed to store optimized image');
        }
    }

    async generateVariants(photo, buffer, thumbnailSizes) {
        const variants = {};
        for (const size of thumbnailSizes) {
            try {
                const variantBuffer = await sharp(buffer)
                    .resize({
                        width: size.width,
                        height: size.height,
                        fit: 'cover',
                        withoutEnlargement: true
                    })
                    .toBuffer();

                const fileExtension = this.getFileExtension(photo.mimeType);
                const uniqueFileName = `${uuidv4()}_thumbnail_${size.width}x${size.height}_${Date.now()}.${fileExtension}`;
                const folder = `photos/${photo.userId}/thumbnails`;

                const uploadResult = await uploadToCloudinary(variantBuffer, {
                    folder,
                    public_id: uniqueFileName,
                    resource_type: 'image'
                });

                variants[`${size.width}x${size.height}`] = {
                    url: uploadResult.secure_url,
                    publicId: uploadResult.public_id,
                    width: size.width,
                    height: size.height
                };
            } catch (error) {
                logger.warn('Failed to generate thumbnail:', { message: error.message, size });
            }
        }
        return variants;
    }

    async generateOptimizationPreview(photo, config) {
        const estimatedCompressionRatio = this.getEstimatedCompressionRatio(config.quality, config.level);
        const estimatedSize = Math.floor(photo.fileSize * (1 - estimatedCompressionRatio));

        const dimensions = {
            width: config.maxWidth ? Math.min(photo.width, config.maxWidth) : photo.width,
            height: config.maxHeight ? Math.min(photo.height, config.maxHeight) : photo.height
        };

        return {
            estimatedSize,
            compressionRatio: (estimatedCompressionRatio * 100).toFixed(2) + '%',
            dimensions
        };
    }

    getEstimatedCompressionRatio(quality, level) {
        const baseRatio = (100 - quality) / 100 * 0.5; // Quality impact
        const levelMultipliers = {
            none: 0,
            low: 0.1,
            medium: 0.3,
            high: 0.5,
            aggressive: 0.7
        };

        return Math.min(baseRatio + (levelMultipliers[level] || 0.3), 0.8);
    }

    async calculateQualityScore(buffer, metadata) {
        const sizePerPixel = buffer.length / (metadata.width * metadata.height);
        const baseScore = Math.min(sizePerPixel * 100, 10);
        const resolutionBonus = Math.min((metadata.width * metadata.height) / (1920 * 1080), 1);
        return Math.min(baseScore + resolutionBonus, 10);
    }

    calculateOptimizationPotential(photo, settings) {
        const currentSize = photo.fileSize;
        let estimatedSize = currentSize;
        const reasons = [];
        let priority = 'low';

        if (currentSize > 10 * 1024 * 1024) { // > 10MB
            estimatedSize *= 0.4; // 60% reduction potential
            reasons.push('Very large file size');
            priority = 'high';
        } else if (currentSize > 5 * 1024 * 1024) { // > 5MB
            estimatedSize *= 0.6; // 40% reduction potential
            reasons.push('Large file size');
            priority = priority === 'low' ? 'medium' : priority;
        }

        if (photo.compressionLevel < 80) {
            estimatedSize *= 0.8; // 20% additional reduction
            reasons.push('Low compression level');
            priority = priority === 'low' ? 'medium' : priority;
        }

        if (photo.width > 4000 || photo.height > 4000) {
            estimatedSize *= 0.5; // 50% reduction from resizing
            reasons.push('Very high resolution');
            priority = 'high';
        }

        if (!photo.isProcessed) {
            estimatedSize *= 0.7; // 30% reduction from initial processing
            reasons.push('Not optimized');
            priority = priority === 'low' ? 'medium' : priority;
        }

        const savings = currentSize - estimatedSize;
        const compressionRatio = ((savings / currentSize) * 100).toFixed(2) + '%';

        return {
            estimatedSize: Math.floor(estimatedSize),
            savings: Math.floor(savings),
            compressionRatio,
            priority,
            reasons
        };
    }

    getOptimizationRecommendations(photo, settings) {
        const recommendations = [];

        if (photo.fileSize > 5 * 1024 * 1024) {
            recommendations.push({
                type: 'file_size',
                message: 'Consider reducing file size for faster loading',
                impact: 'high'
            });
        }

        if (!photo.isProcessed) {
            recommendations.push({
                type: 'processing',
                message: 'Photo has not been optimized yet',
                impact: 'medium'
            });
        }

        if (photo.width > 3000 || photo.height > 3000) {
            recommendations.push({
                type: 'resolution',
                message: 'Consider resizing to reduce dimensions',
                impact: 'high'
            });
        }

        if (photo.mimeType !== 'image/webp' && (!settings || settings.enableAutoFormat)) {
            recommendations.push({
                type: 'format',
                message: 'Convert to WebP for better compression',
                impact: 'medium'
            });
        }

        return recommendations;
    }

    getFileExtension(mimeType) {
        const mimeMap = {
            'image/jpeg': 'jpg',
            'image/jpg': 'jpg',
            'image/png': 'png',
            'image/webp': 'webp',
            'image/gif': 'gif',
            'image/bmp': 'bmp',
            'image/tiff': 'tiff'
        };
        return mimeMap[mimeType] || 'jpg';
    }
}

export default new OptimizationController();