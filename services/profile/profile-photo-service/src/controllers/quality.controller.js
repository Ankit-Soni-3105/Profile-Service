import { Op } from 'sequelize';
import sharp from 'sharp';
import { v4 as uuidv4 } from 'uuid';
import Photo from '../models/Photo.js';
import PhotoSettings from '../models/PhotoSettings.js';
import PhotoHistory from '../models/PhotoHistory.js';
import { logger } from '../utils/logger.js';
import { ApiError } from '../utils/ApiError.js';
import { ApiResponse } from '../utils/ApiResponse.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import { uploadToCloudinary } from '../services/cloudinaryService.js';
import { setCacheData, getCacheData, deleteCacheData } from '../services/redis.service.js';
import promClient from 'prom-client';
import { validationResult } from 'express-validator';

// Metrics setup
const requestCounter = new promClient.Counter({
    name: 'photo_quality_requests_total',
    help: 'Total number of photo quality requests',
    labelNames: ['endpoint', 'method', 'status'],
});

const requestLatency = new promClient.Histogram({
    name: 'photo_quality_duration_seconds',
    help: 'Photo quality request latency in seconds',
    labelNames: ['endpoint', 'method'],
    buckets: [0.1, 0.5, 1, 2, 5, 10],
});

// Cache TTL configurations
const CACHE_TTL = {
    PHOTO: 300, // 5 minutes
    QUALITY_ASSESSMENT: 180, // 3 minutes
    HISTORY: 1800, // 30 minutes
};

// Generate cache key
const generateCacheKey = (type, ...params) => {
    const key = `photo:quality:${type}:${params.join(':')}`;
    return require('crypto').createHash('md5').update(key).digest('hex');
};

class QualityController {
    /**
     * Assess photo quality
     * GET /api/v1/photos/:photoId/assess-quality
     */
    assessQuality = asyncHandler(async (req, res) => {
        const startTime = Date.now();
        const requestId = uuidv4();
        const endpoint = 'assessQuality';
        const { photoId } = req.params;
        const { userId } = req.user;

        try {
            // Validate request
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                requestCounter.inc({ endpoint, method: 'GET', status: 400 });
                throw new ApiError(400, 'Validation failed', errors.array());
            }

            const cacheKey = generateCacheKey('assessment', photoId);
            let qualityAssessment = await getCacheData(cacheKey);

            if (!qualityAssessment) {
                const photo = await Photo.findOne({
                    where: { id: photoId, userId, deletedAt: null },
                    include: [{ model: PhotoSettings, as: 'settings' }]
                });

                if (!photo) {
                    requestCounter.inc({ endpoint, method: 'GET', status: 404 });
                    throw new ApiError(404, 'Photo not found or access denied');
                }

                // Mock image buffer fetch
                const imageBuffer = Buffer.alloc(photo.fileSize); // Replace with actual storage fetch
                const metadata = await sharp(imageBuffer).metadata();

                qualityAssessment = await this.calculateQualityMetrics(imageBuffer, metadata, photo);
                await setCacheData(cacheKey, qualityAssessment, CACHE_TTL.QUALITY_ASSESSMENT);

                // Log assessment history
                await PhotoHistory.create({
                    photoId,
                    userId,
                    action: 'assess_quality',
                    actionDescription: 'Photo quality assessed',
                    actionData: {
                        qualityScore: qualityAssessment.score,
                        metrics: qualityAssessment.metrics
                    },
                    source: req.headers['user-agent']?.includes('Mobile') ? 'mobile_app' : 'web',
                    ipAddress: req.ip,
                    userAgent: req.headers['user-agent'],
                    sessionId: req.sessionID,
                    requestId,
                    processingTime: Date.now() - startTime
                });
            }

            requestCounter.inc({ endpoint, method: 'GET', status: 200 });
            requestLatency.observe({ endpoint, method: 'GET' }, (Date.now() - startTime) / 1000);

            res.json(new ApiResponse(200, qualityAssessment, 'Quality assessment completed successfully', [], requestId));
        } catch (error) {
            logger.error('Quality assessment error:', { message: error.message, stack: error.stack, requestId });
            requestCounter.inc({ endpoint, method: 'GET', status: error.statusCode || 500 });

            // Log failed assessment
            await PhotoHistory.create({
                photoId,
                userId,
                action: 'assess_quality',
                actionDescription: 'Photo quality assessment failed',
                actionData: { error: error.message },
                source: req.headers['user-agent']?.includes('Mobile') ? 'mobile_app' : 'web',
                ipAddress: req.ip,
                userAgent: req.headers['user-agent'],
                requestId,
                processingTime: Date.now() - startTime,
                success: false,
                errorMessage: error.message,
                errorCode: 'QUALITY_ASSESSMENT_FAILED'
            }).catch(historyError => {
                logger.error('Failed to log quality assessment error:', { message: historyError.message });
            });

            throw error instanceof ApiError ? error : new ApiError(500, 'Quality assessment failed');
        }
    });

    /**
     * Enhance photo quality
     * POST /api/v1/photos/:photoId/enhance-quality
     */
    enhanceQuality = asyncHandler(async (req, res) => {
        const startTime = Date.now();
        const requestId = uuidv4();
        const endpoint = 'enhanceQuality';
        const { photoId } = req.params;
        const { userId } = req.user;
        const { sharpness = 1.0, noiseReduction = 'medium', contrast = 1.0, createNewVersion = true } = req.body;

        try {
            // Validate request
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                requestCounter.inc({ endpoint, method: 'POST', status: 400 });
                throw new ApiError(400, 'Validation failed', errors.array());
            }

            const photo = await Photo.findOne({
                where: { id: photoId, userId, deletedAt: null },
                include: [{ model: PhotoSettings, as: 'settings' }]
            });

            if (!photo) {
                requestCounter.inc({ endpoint, method: 'POST', status: 404 });
                throw new ApiError(404, 'Photo not found or access denied');
            }

            const settings = photo.settings || await PhotoSettings.create({
                photoId: photo.id,
                userId,
                qualityEnhancementSettings: { enableQualityEnhancement: true }
            });

            const beforeState = {
                width: photo.width,
                height: photo.height,
                fileSize: photo.fileSize,
                mimeType: photo.mimeType,
                version: photo.version,
                qualityScore: photo.qualityScore
            };

            // Perform quality enhancement
            const enhancementConfig = this.buildEnhancementConfig({ sharpness, noiseReduction, contrast }, settings);
            const result = await this.performQualityEnhancement(photo, enhancementConfig);

            // Start transaction
            const transaction = await Photo.sequelize.transaction();
            try {
                let newPhoto = photo;
                if (createNewVersion) {
                    const fileExtension = this.getFileExtension(photo.mimeType);
                    const uniqueFileName = `${uuidv4()}_enhanced_${Date.now()}.${fileExtension}`;
                    const storagePath = `photos/${userId}/${new Date().getFullYear()}/${new Date().getMonth() + 1}/${uniqueFileName}`;

                    newPhoto = await Photo.create({
                        userId,
                        originalFileName: `enhanced_${photo.originalFileName}`,
                        fileName: uniqueFileName,
                        storageProvider: photo.storageProvider,
                        storagePath,
                        bucketName: photo.bucketName,
                        region: photo.region,
                        mimeType: result.format,
                        fileSize: result.buffer.length,
                        checksum: require('crypto').createHash('sha256').update(result.buffer).digest('hex'),
                        width: result.metadata.width,
                        height: result.metadata.height,
                        aspectRatio: (result.metadata.width / result.metadata.height).toFixed(4),
                        processingStatus: 'completed',
                        isProcessed: true,
                        parentPhotoId: photo.id,
                        version: photo.version + 1,
                        qualityEnhancementData: enhancementConfig,
                        qualityScore: await this.calculateQualityScore(result.buffer, result.metadata)
                    }, { transaction, context: { userId } });

                    // Copy settings from parent
                    if (settings) {
                        await PhotoSettings.create({
                            ...settings.toJSON(),
                            id: uuidv4(),
                            photoId: newPhoto.id,
                            lastModifiedBy: userId
                        }, { transaction });
                    }
                } else {
                    await photo.update({
                        width: result.metadata.width,
                        height: result.metadata.height,
                        fileSize: result.buffer.length,
                        mimeType: result.format,
                        aspectRatio: (result.metadata.width / result.metadata.height).toFixed(4),
                        processingStatus: 'completed',
                        isProcessed: true,
                        version: photo.version + 1,
                        qualityEnhancementData: enhancementConfig,
                        qualityScore: await this.calculateQualityScore(result.buffer, result.metadata)
                    }, { transaction, context: { userId } });
                }

                // Store enhanced image
                const uploadResult = await this.storeEnhancedImage(newPhoto, result.buffer);

                // Log enhancement history
                await PhotoHistory.create({
                    photoId: newPhoto.id,
                    userId,
                    action: 'enhance_quality',
                    actionDescription: `Photo quality enhanced with sharpness=${enhancementConfig.sharpness}, noiseReduction=${enhancementConfig.noiseReduction}, contrast=${enhancementConfig.contrast}`,
                    actionData: {
                        enhancementConfig,
                        sizeBefore: beforeState.fileSize,
                        sizeAfter: result.buffer.length,
                        formatChange: beforeState.mimeType !== result.format,
                        cloudinaryUrl: uploadResult.secure_url,
                        parentPhotoId: createNewVersion ? photo.id : null
                    },
                    beforeState,
                    afterState: {
                        width: result.metadata.width,
                        height: result.metadata.height,
                        fileSize: result.buffer.length,
                        mimeType: result.format,
                        qualityScore: await this.calculateQualityScore(result.buffer, result.metadata)
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
                    qualityBefore: beforeState.qualityScore,
                    qualityAfter: await this.calculateQualityScore(result.buffer, result.metadata)
                }, { transaction });

                await transaction.commit();

                // Invalidate cache
                await deleteCacheData(generateCacheKey('photo', newPhoto.id));
                await deleteCacheData(generateCacheKey('photo', photoId));
                await deleteCacheData(generateCacheKey('assessment', photoId));

                requestCounter.inc({ endpoint, method: 'POST', status: 200 });
                requestLatency.observe({ endpoint, method: 'POST' }, (Date.now() - startTime) / 1000);

                res.json(new ApiResponse(200, {
                    id: newPhoto.id,
                    fileName: newPhoto.fileName,
                    originalFileName: newPhoto.originalFileName,
                    dimensions: {
                        width: newPhoto.width,
                        height: newPhoto.height
                    },
                    aspectRatio: newPhoto.aspectRatio,
                    fileSize: newPhoto.fileSize,
                    qualityEnhancementData: newPhoto.qualityEnhancementData,
                    version: newPhoto.version,
                    isNewVersion: createNewVersion,
                    parentPhotoId: createNewVersion ? photo.id : null,
                    cloudinaryUrl: uploadResult.secure_url,
                    qualityScore: newPhoto.qualityScore
                }, 'Quality enhancement completed successfully', [], requestId));
            } catch (error) {
                await transaction.rollback();
                throw error;
            }
        } catch (error) {
            logger.error('Quality enhancement error:', { message: error.message, stack: error.stack, requestId });
            requestCounter.inc({ endpoint, method: 'POST', status: error.statusCode || 500 });

            // Log failed enhancement
            await PhotoHistory.create({
                photoId,
                userId,
                action: 'enhance_quality',
                actionDescription: 'Photo quality enhancement failed',
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
                errorCode: 'QUALITY_ENHANCEMENT_FAILED'
            }).catch(historyError => {
                logger.error('Failed to log quality enhancement error:', { message: historyError.message });
            });

            throw error instanceof ApiError ? error : new ApiError(500, 'Quality enhancement failed');
        }
    });

    /**
     * Revert quality enhancement
     * POST /api/v1/photos/:photoId/revert-quality-enhancement
     */
    revertQualityEnhancement = asyncHandler(async (req, res) => {
        const startTime = Date.now();
        const requestId = uuidv4();
        const endpoint = 'revertQualityEnhancement';
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
                    action: 'enhance_quality',
                    'beforeState.version': version
                },
                order: [['createdAt', 'DESC']]
            });

            if (!history) {
                requestCounter.inc({ endpoint, method: 'POST', status: 404 });
                throw new ApiError(404, 'Quality enhancement version not found');
            }

            const transaction = await Photo.sequelize.transaction();
            try {
                // Update photo to previous state
                await photo.update({
                    width: history.beforeState.width,
                    height: history.beforeState.height,
                    fileSize: history.beforeState.fileSize,
                    mimeType: history.beforeState.mimeType,
                    aspectRatio: (history.beforeState.width / history.beforeState.height).toFixed(4),
                    processingStatus: 'completed',
                    isProcessed: true,
                    version: photo.version + 1,
                    qualityEnhancementData: null,
                    qualityScore: history.beforeState.qualityScore
                }, { transaction, context: { userId } });

                // Revert image in storage
                await this.storeEnhancedImage(photo, Buffer.alloc(history.beforeState.fileSize)); // Mock for now

                // Log revert action
                await PhotoHistory.create({
                    photoId,
                    userId,
                    action: 'revert_quality_enhancement',
                    actionDescription: `Reverted quality enhancement to version ${version}`,
                    actionData: {
                        revertedVersion: version,
                        previousState: history.afterState
                    },
                    beforeState: {
                        width: history.afterState.width,
                        height: history.afterState.height,
                        fileSize: history.afterState.fileSize,
                        mimeType: history.afterState.mimeType,
                        qualityScore: history.afterState.qualityScore
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
                await deleteCacheData(generateCacheKey('assessment', photoId));

                requestCounter.inc({ endpoint, method: 'POST', status: 200 });
                requestLatency.observe({ endpoint, method: 'POST' }, (Date.now() - startTime) / 1000);

                res.json(new ApiResponse(200, {
                    id: photo.id,
                    version: photo.version,
                    dimensions: {
                        width: photo.width,
                        height: photo.height
                    },
                    fileSize: photo.fileSize,
                    qualityScore: photo.qualityScore
                }, 'Quality enhancement reverted successfully', [], requestId));
            } catch (error) {
                await transaction.rollback();
                throw error;
            }
        } catch (error) {
            logger.error('Revert quality enhancement error:', { message: error.message, stack: error.stack, requestId });
            requestCounter.inc({ endpoint, method: 'POST', status: error.statusCode || 500 });
            throw error instanceof ApiError ? error : new ApiError(500, 'Failed to revert quality enhancement');
        }
    });

    /**
     * Get quality enhancement history
     * GET /api/v1/photos/:photoId/quality-enhancement-history
     */
    getQualityEnhancementHistory = asyncHandler(async (req, res) => {
        const startTime = Date.now();
        const requestId = uuidv4();
        const endpoint = 'getQualityEnhancementHistory';
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
                        action: { [Op.in]: ['enhance_quality', 'revert_quality_enhancement'] }
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

            res.json(new ApiResponse(200, history, 'Quality enhancement history retrieved successfully', [], requestId));
        } catch (error) {
            logger.error('Get quality enhancement history error:', { message: error.message, stack: error.stack, requestId });
            requestCounter.inc({ endpoint, method: 'GET', status: error.statusCode || 500 });
            throw error instanceof ApiError ? error : new ApiError(500, 'Failed to get quality enhancement history');
        }
    });

    // Helper methods
    buildEnhancementConfig(params, settings) {
        const config = {
            sharpness: params.sharpness || settings?.qualityEnhancementSettings?.sharpness || 1.0,
            noiseReduction: params.noiseReduction || settings?.qualityEnhancementSettings?.noiseReduction || 'medium',
            contrast: params.contrast || settings?.qualityEnhancementSettings?.contrast || 1.0
        };

        // Validate parameters
        if (config.sharpness < 0 || config.sharpness > 2) {
            throw new ApiError(400, 'Sharpness must be between 0 and 2');
        }
        if (!['none', 'low', 'medium', 'high'].includes(config.noiseReduction)) {
            throw new ApiError(400, 'Invalid noise reduction level');
        }
        if (config.contrast < 0.5 || config.contrast > 2) {
            throw new ApiError(400, 'Contrast must be between 0.5 and 2');
        }

        return config;
    }

    async performQualityEnhancement(photo, config) {
        try {
            // Mock image buffer fetch
            const imageBuffer = Buffer.alloc(photo.fileSize); // Replace with actual storage fetch
            let sharpInstance = sharp(imageBuffer);

            // Apply enhancements
            sharpInstance = sharpInstance.sharpen({ sigma: config.sharpness });
            if (config.noiseReduction !== 'none') {
                const sigma = { low: 1, medium: 2, high: 3 }[config.noiseReduction];
                sharpInstance = sharpInstance.blur(sigma); // Mock noise reduction
            }
            sharpInstance = sharpInstance.modulate({ brightness: 1, contrast: config.contrast });

            const buffer = await sharpInstance.toBuffer();
            const metadata = await sharp(buffer).metadata();

            return {
                buffer,
                metadata,
                format: metadata.format ? `image/${metadata.format}` : photo.mimeType
            };
        } catch (error) {
            logger.error('Quality enhancement failed:', { message: error.message, photoId: photo.id });
            throw new ApiError(500, `Quality enhancement failed: ${error.message}`);
        }
    }

    async calculateQualityMetrics(buffer, metadata, photo) {
        // Mock quality metrics calculation
        const sizePerPixel = buffer.length / (metadata.width * metadata.height);
        const baseScore = Math.min(sizePerPixel * 100, 10);
        const resolutionBonus = Math.min((metadata.width * metadata.height) / (1920 * 1080), 1);
        const qualityScore = Math.min(baseScore + resolutionBonus, 10);

        return {
            score: qualityScore.toFixed(2),
            metrics: {
                sharpness: 8.0, // Mock value
                noise: 2.0, // Mock value
                resolution: `${metadata.width}x${metadata.height}`,
                fileSize: buffer.length,
                sizePerPixel: sizePerPixel.toFixed(4)
            }
        };
    }

    async calculateQualityScore(buffer, metadata) {
        const sizePerPixel = buffer.length / (metadata.width * metadata.height);
        const baseScore = Math.min(sizePerPixel * 100, 10);
        const resolutionBonus = Math.min((metadata.width * metadata.height) / (1920 * 1080), 1);
        return Math.min(baseScore + resolutionBonus, 10);
    }

    async storeEnhancedImage(photo, buffer) {
        try {
            const fileExtension = this.getFileExtension(photo.mimeType);
            const uniqueFileName = `${uuidv4()}_enhanced_${Date.now()}.${fileExtension}`;
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
            logger.error('Store enhanced image error:', { message: error.message, photoId: photo.id });
            throw new ApiError(500, 'Failed to store enhanced image');
        }
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

export default new QualityController();