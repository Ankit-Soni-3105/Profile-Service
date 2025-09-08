import { Op } from 'sequelize';
import sharp from 'sharp';
import { v4 as uuidv4 } from 'uuid';
import Photo from '../models/Photo.js';
import PhotoSettings from '../models/PhotoSettings.js';
import PhotoHistory from '../models/PhotoHistory.js';

class CroppingController {
    async cropPhoto(req, res) {
        const startTime = Date.now();
        const requestId = uuidv4();

        try {
            const { photoId } = req.params;
            const { userId } = req.user;
            const { x, y, width, height, aspectRatio, presetName } = req.body;

            // Validate crop parameters
            if (!x && x !== 0 || !y && y !== 0 || !width || !height) {
                return res.status(400).json({
                    success: false,
                    error: 'Invalid crop parameters. x, y, width, and height are required.',
                    requestId
                });
            }

            // Find photo with authorization check
            const photo = await Photo.findOne({
                where: {
                    id: photoId,
                    userId,
                    deletedAt: null
                }
            });

            if (!photo) {
                return res.status(404).json({
                    success: false,
                    error: 'Photo not found or access denied',
                    requestId
                });
            }

            // Validate crop bounds
            if (x < 0 || y < 0 || width <= 0 || height <= 0 ||
                x + width > photo.width || y + height > photo.height) {
                return res.status(400).json({
                    success: false,
                    error: 'Crop bounds exceed image dimensions',
                    requestId
                });
            }

            // Get photo settings for processing preferences
            const settings = await PhotoSettings.findOne({
                where: { photoId }
            });

            const beforeState = {
                width: photo.width,
                height: photo.height,
                aspectRatio: photo.aspectRatio,
                fileSize: photo.fileSize
            };

            // Perform crop operation
            const croppedBuffer = await this.performCrop(photo, { x, y, width, height });
            const metadata = await sharp(croppedBuffer).metadata();

            // Create new photo version or update existing
            let newPhoto;
            const shouldCreateVersion = req.body.createNewVersion !== false; // Default true

            if (shouldCreateVersion) {
                // Create new photo version
                const fileExtension = this.getFileExtension(photo.mimeType);
                const uniqueFileName = `${uuidv4()}_cropped_${Date.now()}.${fileExtension}`;
                const storagePath = `photos/${userId}/${new Date().getFullYear()}/${new Date().getMonth() + 1}/${uniqueFileName}`;

                newPhoto = await Photo.create({
                    userId,
                    originalFileName: `cropped_${photo.originalFileName}`,
                    fileName: uniqueFileName,
                    storageProvider: photo.storageProvider,
                    storagePath,
                    bucketName: photo.bucketName,
                    region: photo.region,
                    mimeType: photo.mimeType,
                    fileSize: croppedBuffer.length,
                    checksum: require('crypto').createHash('sha256').update(croppedBuffer).digest('hex'),
                    width: metadata.width,
                    height: metadata.height,
                    aspectRatio: (metadata.width / metadata.height).toFixed(4),
                    processingStatus: 'completed',
                    isProcessed: true,
                    parentPhotoId: photo.id,
                    version: photo.version + 1,
                    cropData: { x, y, width, height, aspectRatio, presetName },
                    uploadedAt: new Date()
                }, {
                    context: { userId }
                });

                // Copy settings from parent
                if (settings) {
                    await PhotoSettings.create({
                        ...settings.toJSON(),
                        id: uuidv4(),
                        photoId: newPhoto.id,
                        lastModifiedBy: userId
                    });
                }
            } else {
                // Update existing photo
                await photo.update({
                    width: metadata.width,
                    height: metadata.height,
                    aspectRatio: (metadata.width / metadata.height).toFixed(4),
                    fileSize: croppedBuffer.length,
                    cropData: { x, y, width, height, aspectRatio, presetName },
                    processingStatus: 'completed',
                    isProcessed: true,
                    version: photo.version + 1
                }, {
                    context: { userId }
                });

                newPhoto = photo;
            }

            // Store cropped image (would typically upload to cloud storage)
            await this.storeImage(newPhoto, croppedBuffer);

            // Update crop settings if preset was used
            if (presetName && settings) {
                const currentCropSettings = settings.cropSettings || {};
                const presets = currentCropSettings.presets || [];

                // Add or update preset
                const existingPresetIndex = presets.findIndex(p => p.name === presetName);
                const presetData = { name: presetName, x, y, width, height, aspectRatio };

                if (existingPresetIndex >= 0) {
                    presets[existingPresetIndex] = presetData;
                } else {
                    presets.push(presetData);
                }

                await settings.update({
                    cropSettings: {
                        ...currentCropSettings,
                        presets,
                        lastUsed: presetData
                    }
                }, {
                    context: { userId }
                });
            }

            // Log crop history
            await PhotoHistory.create({
                photoId: newPhoto.id,
                userId,
                action: 'crop',
                actionDescription: `Photo cropped to ${width}x${height} at position (${x}, ${y})`,
                actionData: {
                    cropBounds: { x, y, width, height },
                    aspectRatio,
                    presetName,
                    createNewVersion: shouldCreateVersion,
                    parentPhotoId: shouldCreateVersion ? photo.id : null
                },
                beforeState,
                afterState: {
                    width: metadata.width,
                    height: metadata.height,
                    aspectRatio: (metadata.width / metadata.height).toFixed(4),
                    fileSize: croppedBuffer.length
                },
                source: req.headers['user-agent']?.includes('Mobile') ? 'mobile_app' : 'web',
                ipAddress: req.ip,
                userAgent: req.headers['user-agent'],
                sessionId: req.sessionID,
                requestId,
                processingTime: Date.now() - startTime,
                fileSizeBefore: photo.fileSize,
                fileSizeAfter: croppedBuffer.length,
                dimensionsBefore: { width: photo.width, height: photo.height },
                dimensionsAfter: { width: metadata.width, height: metadata.height }
            });

            res.json({
                success: true,
                data: {
                    id: newPhoto.id,
                    fileName: newPhoto.fileName,
                    originalFileName: newPhoto.originalFileName,
                    dimensions: {
                        width: newPhoto.width,
                        height: newPhoto.height
                    },
                    aspectRatio: newPhoto.aspectRatio,
                    fileSize: newPhoto.fileSize,
                    cropData: newPhoto.cropData,
                    version: newPhoto.version,
                    isNewVersion: shouldCreateVersion,
                    parentPhotoId: shouldCreateVersion ? photo.id : null
                },
                requestId,
                processingTime: Date.now() - startTime
            });

        } catch (error) {
            console.error('Crop error:', error);

            // Log failed crop
            if (req.params.photoId && req.user?.id) {
                await PhotoHistory.create({
                    photoId: req.params.photoId,
                    userId: req.user.id,
                    action: 'crop',
                    actionDescription: 'Photo crop failed',
                    actionData: {
                        cropBounds: req.body,
                        error: error.message
                    },
                    source: req.headers['user-agent']?.includes('Mobile') ? 'mobile_app' : 'web',
                    ipAddress: req.ip,
                    userAgent: req.headers['user-agent'],
                    requestId,
                    processingTime: Date.now() - startTime,
                    success: false,
                    errorMessage: error.message,
                    errorCode: 'CROP_FAILED'
                }).catch(historyError => {
                    console.error('Failed to log crop error:', historyError);
                });
            }

            res.status(500).json({
                success: false,
                error: 'Crop operation failed',
                message: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error',
                requestId
            });
        }
    }

    async getCropPresets(req, res) {
        try {
            const { photoId } = req.params;
            const { userId } = req.user;

            const photo = await Photo.findOne({
                where: { id: photoId, userId, deletedAt: null },
                attributes: ['id', 'width', 'height', 'aspectRatio']
            });

            if (!photo) {
                return res.status(404).json({
                    success: false,
                    error: 'Photo not found'
                });
            }

            const settings = await PhotoSettings.findOne({
                where: { photoId },
                attributes: ['cropSettings', 'cropAspectRatio', 'customAspectRatio']
            });

            // Generate common aspect ratio presets
            const commonPresets = this.generateCommonPresets(photo);

            // Get user's custom presets
            const customPresets = settings?.cropSettings?.presets || [];

            res.json({
                success: true,
                data: {
                    photoInfo: {
                        width: photo.width,
                        height: photo.height,
                        aspectRatio: photo.aspectRatio
                    },
                    commonPresets,
                    customPresets,
                    preferredAspectRatio: settings?.cropAspectRatio || 'free',
                    customAspectRatio: settings?.customAspectRatio,
                    lastUsed: settings?.cropSettings?.lastUsed
                }
            });

        } catch (error) {
            console.error('Get crop presets error:', error);
            res.status(500).json({
                success: false,
                error: 'Failed to get crop presets'
            });
        }
    }

    async saveCropPreset(req, res) {
        try {
            const { photoId } = req.params;
            const { userId } = req.user;
            const { name, x, y, width, height, aspectRatio } = req.body;

            if (!name || !x && x !== 0 || !y && y !== 0 || !width || !height) {
                return res.status(400).json({
                    success: false,
                    error: 'Missing required preset parameters'
                });
            }

            const photo = await Photo.findOne({
                where: { id: photoId, userId, deletedAt: null }
            });

            if (!photo) {
                return res.status(404).json({
                    success: false,
                    error: 'Photo not found'
                });
            }

            const settings = await PhotoSettings.findOne({
                where: { photoId }
            });

            if (!settings) {
                return res.status(404).json({
                    success: false,
                    error: 'Photo settings not found'
                });
            }

            const cropSettings = settings.cropSettings || {};
            const presets = cropSettings.presets || [];

            // Check for duplicate names
            const existingPresetIndex = presets.findIndex(p => p.name === name);
            const presetData = { name, x, y, width, height, aspectRatio, createdAt: new Date() };

            if (existingPresetIndex >= 0) {
                presets[existingPresetIndex] = presetData;
            } else {
                presets.push(presetData);
            }

            await settings.update({
                cropSettings: {
                    ...cropSettings,
                    presets
                }
            }, {
                context: { userId }
            });

            res.json({
                success: true,
                data: {
                    preset: presetData,
                    totalPresets: presets.length
                }
            });

        } catch (error) {
            console.error('Save crop preset error:', error);
            res.status(500).json({
                success: false,
                error: 'Failed to save crop preset'
            });
        }
    }

    async deleteCropPreset(req, res) {
        try {
            const { photoId, presetName } = req.params;
            const { userId } = req.user;

            const settings = await PhotoSettings.findOne({
                where: { photoId, userId }
            });

            if (!settings) {
                return res.status(404).json({
                    success: false,
                    error: 'Photo settings not found'
                });
            }

            const cropSettings = settings.cropSettings || {};
            const presets = cropSettings.presets || [];

            const presetIndex = presets.findIndex(p => p.name === presetName);

            if (presetIndex === -1) {
                return res.status(404).json({
                    success: false,
                    error: 'Preset not found'
                });
            }

            presets.splice(presetIndex, 1);

            await settings.update({
                cropSettings: {
                    ...cropSettings,
                    presets
                }
            }, {
                context: { userId }
            });

            res.json({
                success: true,
                data: {
                    deletedPreset: presetName,
                    remainingPresets: presets.length
                }
            });

        } catch (error) {
            console.error('Delete crop preset error:', error);
            res.status(500).json({
                success: false,
                error: 'Failed to delete crop preset'
            });
        }
    }

    async getCropSuggestions(req, res) {
        try {
            const { photoId } = req.params;
            const { userId } = req.user;

            const photo = await Photo.findOne({
                where: { id: photoId, userId, deletedAt: null },
                attributes: ['id', 'width', 'height', 'aspectRatio']
            });

            if (!photo) {
                return res.status(404).json({
                    success: false,
                    error: 'Photo not found'
                });
            }

            // Generate AI-based crop suggestions (simplified version)
            const suggestions = this.generateCropSuggestions(photo);

            res.json({
                success: true,
                data: {
                    photoId: photo.id,
                    suggestions,
                    totalSuggestions: suggestions.length
                }
            });

        } catch (error) {
            console.error('Get crop suggestions error:', error);
            res.status(500).json({
                success: false,
                error: 'Failed to get crop suggestions'
            });
        }
    }

    // Helper methods
    async performCrop(photo, cropData) {
        try {
            // In a real application, you would fetch the image from storage
            // For now, we'll simulate the crop operation
            const { x, y, width, height } = cropData;

            // This would typically be:
            // const imageBuffer = await storageService.getImage(photo.storagePath);
            // return await sharp(imageBuffer).extract({ left: x, top: y, width, height }).toBuffer();

            // Simulated crop operation
            const mockBuffer = Buffer.alloc(width * height * 3); // RGB mock buffer
            return mockBuffer;

        } catch (error) {
            console.error('Perform crop error:', error);
            throw new Error('Crop operation failed');
        }
    }

    async storeImage(photo, buffer) {
        try {
            // In a real application, this would upload to cloud storage
            // await storageService.uploadImage(photo.storagePath, buffer);
            console.log(`Stored cropped image for photo ${photo.id}`);
        } catch (error) {
            console.error('Store image error:', error);
            throw new Error('Failed to store cropped image');
        }
    }

    generateCommonPresets(photo) {
        const { width, height } = photo;
        const presets = [];

        const ratios = [
            { name: 'Square (1:1)', ratio: 1, description: 'Perfect for profile pictures' },
            { name: 'Portrait (3:4)', ratio: 3 / 4, description: 'Standard portrait orientation' },
            { name: 'Landscape (4:3)', ratio: 4 / 3, description: 'Standard landscape orientation' },
            { name: 'Widescreen (16:9)', ratio: 16 / 9, description: 'HD video format' },
            { name: 'Instagram Portrait (4:5)', ratio: 4 / 5, description: 'Instagram feed format' },
            { name: 'Instagram Story (9:16)', ratio: 9 / 16, description: 'Instagram story format' }
        ];

        ratios.forEach(({ name, ratio, description }) => {
            let cropWidth, cropHeight, x, y;

            if (width / height > ratio) {
                // Image is wider than target ratio
                cropHeight = height;
                cropWidth = Math.floor(height * ratio);
                x = Math.floor((width - cropWidth) / 2);
                y = 0;
            } else {
                // Image is taller than target ratio
                cropWidth = width;
                cropHeight = Math.floor(width / ratio);
                x = 0;
                y = Math.floor((height - cropHeight) / 2);
            }

            if (cropWidth > 0 && cropHeight > 0 && cropWidth <= width && cropHeight <= height) {
                presets.push({
                    name,
                    description,
                    x,
                    y,
                    width: cropWidth,
                    height: cropHeight,
                    aspectRatio: ratio,
                    resultingSize: `${cropWidth}×${cropHeight}`
                });
            }
        });

        return presets;
    }

    generateCropSuggestions(photo) {
        const { width, height } = photo;
        const suggestions = [];

        // Rule of thirds suggestions
        suggestions.push({
            name: 'Rule of Thirds - Center',
            description: 'Centered composition following rule of thirds',
            x: Math.floor(width * 0.1),
            y: Math.floor(height * 0.1),
            width: Math.floor(width * 0.8),
            height: Math.floor(height * 0.8),
            confidence: 0.8,
            reason: 'Classic composition technique'
        });

        // Golden ratio suggestion
        const goldenRatio = 1.618;
        if (width / height > goldenRatio) {
            suggestions.push({
                name: 'Golden Ratio Landscape',
                description: 'Crop using golden ratio proportions',
                x: Math.floor((width - height * goldenRatio) / 2),
                y: 0,
                width: Math.floor(height * goldenRatio),
                height: height,
                confidence: 0.75,
                reason: 'Aesthetically pleasing proportions'
            });
        }

        // Smart crop for social media
        suggestions.push({
            name: 'Social Media Optimized',
            description: 'Optimized for social media sharing',
            x: Math.floor(width * 0.05),
            y: Math.floor(height * 0.1),
            width: Math.floor(width * 0.9),
            height: Math.floor(height * 0.8),
            confidence: 0.9,
            reason: 'Maximizes impact on social platforms'
        });

        return suggestions.filter(s => s.width > 0 && s.height > 0);
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

export default CroppingController;