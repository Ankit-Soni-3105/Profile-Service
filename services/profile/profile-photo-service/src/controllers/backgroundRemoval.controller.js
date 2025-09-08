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
import { uploadToCloudinary, deleteFromCloudinary } from '../services/cloudinaryService.js';
import { setCacheData, getCacheData, deleteCacheData } from '../services/redis.service.js';
import promClient from 'prom-client';
import { validationResult } from 'express-validator';

// Metrics setup
const requestCounter = new promClient.Counter({
    name: 'photo_background_removal_requests_total',
    help: 'Total number of background removal requests',
    labelNames: ['endpoint', 'method', 'status'],
});

const requestLatency = new promClient.Histogram({
    name: 'photo_background_removal_duration_seconds',
    help: 'Background removal request latency in seconds',
    labelNames: ['endpoint', 'method'],
    buckets: [0.1, 0.5, 1, 2, 5, 10],
});

// Cache TTL configurations
const CACHE_TTL = {
    PHOTO: 300, // 5 minutes
    PREVIEW: 180, // 3 minutes
    HISTORY: 1800, // 30 minutes
};

// Generate cache key
const generateCacheKey = (type, ...params) => {
    const key = `photo:background_removal:${type}:${params.join(':')}`;
    return require('crypto').createHash('md5').update(key).digest('hex');
};

class BackgroundRemovalController {
    /**
     * Remove background from a photo
     * POST /api/v1/photos/:photoId/remove-background
     */
    removeBackground = asyncHandler(async (req, res) => {
        const startTime = Date.now();
        const requestId = uuidv4();
        const endpoint = 'removeBackground';
        const { photoId } = req.params;
        const { userId } = req.user;
        const { backgroundColor, createNewVersion = true } = req.body;

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
                backgroundRemovalSettings: { enableBackgroundRemoval: true }
            });

            const beforeState = {
                width: photo.width,
                height: photo.height,
                fileSize: photo.fileSize,
                mimeType: photo.mimeType,
                version: photo.version
            };

            // Perform background removal
            const result = await this.performBackgroundRemoval(photo, { backgroundColor });

            // Start transaction
            const transaction = await Photo.sequelize.transaction();
            try {
                let newPhoto = photo;
                if (createNewVersion) {
                    const fileExtension = this.getFileExtension(photo.mimeType);
                    const uniqueFileName = `${uuidv4()}_nobg_${Date.now()}.${fileExtension}`;
                    const storagePath = `photos/${userId}/${new Date().getFullYear()}/${new Date().getMonth() + 1}/${uniqueFileName}`;

                    newPhoto = await Photo.create({
                        userId,
                        originalFileName: `nobg_${photo.originalFileName}`,
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
                        backgroundRemovalData: { backgroundColor },
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
                        backgroundRemovalData: { backgroundColor },
                    }, { transaction, context: { userId } });
                }

                // Store processed image
                const uploadResult = await this.storeProcessedImage(newPhoto, result.buffer);

                // Log background removal history
                await PhotoHistory.create({
                    photoId: newPhoto.id,
                    userId,
                    action: 'remove_background',
                    actionDescription: `Background removed${backgroundColor ? ` with color ${backgroundColor}` : ''}`,
                    actionData: {
                        backgroundColor,
                        createNewVersion,
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
                        mimeType: result.format
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
                    dimensionsAfter: { width: result.metadata.width, height: result.metadata.height }
                }, { transaction });

                await transaction.commit();

                // Invalidate cache
                await deleteCacheData(generateCacheKey('photo', newPhoto.id));
                await deleteCacheData(generateCacheKey('photo', photoId));

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
                    backgroundRemovalData: newPhoto.backgroundRemovalData,
                    version: newPhoto.version,
                    isNewVersion: createNewVersion,
                    parentPhotoId: createNewVersion ? photo.id : null,
                    cloudinaryUrl: uploadResult.secure_url
                }, 'Background removed successfully', [], requestId));
            } catch (error) {
                await transaction.rollback();
                throw error;
            }
        } catch (error) {
            logger.error('Background removal error:', { message: error.message, stack: error.stack, requestId });
            requestCounter.inc({ endpoint, method: 'POST', status: error.statusCode || 500 });

            // Log failed operation
            await PhotoHistory.create({
                photoId,
                userId,
                action: 'remove_background',
                actionDescription: 'Background removal failed',
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
                errorCode: 'BACKGROUND_REMOVAL_FAILED'
            }).catch(historyError => {
                logger.error('Failed to log background removal error:', { message: historyError.message });
            });

            throw error instanceof ApiError ? error : new ApiError(500, 'Background removal failed');
        }
    });

    /**
     * Preview background removal
     * GET /api/v1/photos/:photoId/remove-background-preview
     */
    getBackgroundRemovalPreview = asyncHandler(async (req, res) => {
        const startTime = Date.now();
        const requestId = uuidv4();
        const endpoint = 'getBackgroundRemovalPreview';
        const { photoId } = req.params;
        const { userId } = req.user;
        const { backgroundColor } = req.query;

        try {
            // Validate request
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                requestCounter.inc({ endpoint, method: 'GET', status: 400 });
                throw new ApiError(400, 'Validation failed', errors.array());
            }

            const cacheKey = generateCacheKey('preview', photoId, backgroundColor || 'transparent');
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

                preview = await this.generateBackgroundRemovalPreview(photo, { backgroundColor });
                await setCacheData(cacheKey, preview, CACHE_TTL.PREVIEW);
            }

            requestCounter.inc({ endpoint, method: 'GET', status: 200 });
            requestLatency.observe({ endpoint, method: 'GET' }, (Date.now() - startTime) / 1000);

            res.json(new ApiResponse(200, preview, 'Background removal preview generated successfully', [], requestId));
        } catch (error) {
            logger.error('Background removal preview error:', { message: error.message, stack: error.stack, requestId });
            requestCounter.inc({ endpoint, method: 'GET', status: error.statusCode || 500 });
            throw error instanceof ApiError ? error : new ApiError(500, 'Failed to generate background removal preview');
        }
    });

    /**
     * Revert background removal
     * POST /api/v1/photos/:photoId/revert-background-removal
     */
    revertBackgroundRemoval = asyncHandler(async (req, res) => {
        const startTime = Date.now();
        const requestId = uuidv4();
        const endpoint = 'revertBackgroundRemoval';
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
                    action: 'remove_background',
                    'beforeState.version': version
                },
                order: [['createdAt', 'DESC']]
            });

            if (!history) {
                requestCounter.inc({ endpoint, method: 'POST', status: 404 });
                throw new ApiError(404, 'Background removal version not found');
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
                    backgroundRemovalData: null
                }, { transaction, context: { userId } });

                // Revert image in storage
                await this.storeProcessedImage(photo, Buffer.alloc(history.beforeState.fileSize)); // Mock for now

                // Log revert action
                await PhotoHistory.create({
                    photoId,
                    userId,
                    action: 'revert_background_removal',
                    actionDescription: `Reverted background removal to version ${version}`,
                    actionData: {
                        revertedVersion: version,
                        previousState: history.afterState
                    },
                    beforeState: {
                        width: history.afterState.width,
                        height: history.afterState.height,
                        fileSize: history.afterState.fileSize,
                        mimeType: history.afterState.mimeType
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
                }, 'Background removal reverted successfully', [], requestId));
            } catch (error) {
                await transaction.rollback();
                throw error;
            }
        } catch (error) {
            logger.error('Revert background removal error:', { message: error.message, stack: error.stack, requestId });
            requestCounter.inc({ endpoint, method: 'POST', status: error.statusCode || 500 });
            throw error instanceof ApiError ? error : new ApiError(500, 'Failed to revert background removal');
        }
    });

    /**
     * Get background removal history
     * GET /api/v1/photos/:photoId/background-removal-history
     */
    getBackgroundRemovalHistory = asyncHandler(async (req, res) => {
        const startTime = Date.now();
        const requestId = uuidv4();
        const endpoint = 'getBackgroundRemovalHistory';
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
                        action: { [Op.in]: ['remove_background', 'revert_background_removal'] }
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

            res.json(new ApiResponse(200, history, 'Background removal history retrieved successfully', [], requestId));
        } catch (error) {
            logger.error('Get background removal history error:', { message: error.message, stack: error.stack, requestId });
            requestCounter.inc({ endpoint, method: 'GET', status: error.statusCode || 500 });
            throw error instanceof ApiError ? error : new ApiError(500, 'Failed to get background removal history');
        }
    });

    // Helper methods
    async performBackgroundRemoval(photo, config) {
        try {
            // Mock background removal (replace with actual AI service like Cloudinary AI or Remove.bg)
            const imageBuffer = Buffer.alloc(photo.fileSize); // Mock for now
            let sharpInstance = sharp(imageBuffer);

            if (config.backgroundColor) {
                sharpInstance = sharpInstance.flatten({ background: config.backgroundColor });
            } else {
                sharpInstance = sharpInstance.png(); // Ensure transparency support
            }

            const buffer = await sharpInstance.toBuffer();
            const metadata = await sharp(buffer).metadata();

            return {
                buffer,
                metadata,
                format: metadata.format ? `image/${metadata.format}` : photo.mimeType
            };
        } catch (error) {
            logger.error('Background removal failed:', { message: error.message, photoId: photo.id });
            throw new ApiError(500, `Background removal failed: ${error.message}`);
        }
    }

    async generateBackgroundRemovalPreview(photo, config) {
        // Simplified preview (no actual processing)
        const estimatedSize = Math.floor(photo.fileSize * 0.9); // Assume 10% size reduction
        return {
            estimatedSize,
            compressionRatio: ((photo.fileSize - estimatedSize) / photo.fileSize * 100).toFixed(2) + '%',
            dimensions: {
                width: photo.width,
                height: photo.height
            },
            backgroundColor: config.backgroundColor || 'transparent'
        };
    }

    async storeProcessedImage(photo, buffer) {
        try {
            const fileExtension = this.getFileExtension(photo.mimeType);
            const uniqueFileName = `${uuidv4()}_nobg_${Date.now()}.${fileExtension}`;
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
            logger.error('Store processed image error:', { message: error.message, photoId: photo.id });
            throw new ApiError(500, 'Failed to store processed image');
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
        return mimeMap[mimeType] || 'png';
    }
}

export default new BackgroundRemovalController();