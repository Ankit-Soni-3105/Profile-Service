import { Op } from 'sequelize';
import sharp from 'sharp';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import multer from 'multer';
import rateLimit from 'express-rate-limit';
import Photo from '../models/photo.model.js';
import PhotoSettings from '../models/photo.setting.js';
import PhotoHistory from '../models/photo.history.model.js';

export const PhotoUploadController = class {
    constructor() {
        this.uploadLimiter = rateLimit({
            windowMs: 15 * 60 * 1000, // 15 minutes
            max: 50, // Limit each user to 50 uploads per windowMs
            message: 'Too many upload attempts, please try again later.',
            standardHeaders: true,
            legacyHeaders: false,
            keyGenerator: (req) => req.user?.id || req.ip
        });

        this.upload = multer({
            storage: multer.memoryStorage(),
            limits: {
                fileSize: 52428800, // 50MB
                files: 10 // Maximum 10 files per request
            },
            fileFilter: this.fileFilter.bind(this)
        });
    }

    fileFilter(req, file, cb) {
        const allowedMimes = [
            'image/jpeg', 'image/jpg', 'image/png',
            'image/webp', 'image/gif', 'image/bmp', 'image/tiff'
        ];

        if (allowedMimes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only images are allowed.'), false);
        }
    }

    async uploadSingle(req, res) {
        const startTime = Date.now();
        const requestId = uuidv4();

        try {
            const { userId } = req.user;
            const file = req.file;

            if (!file) {
                return res.status(400).json({
                    success: false,
                    error: 'No file uploaded',
                    requestId
                });
            }

            // Check user's photo quota (prevent abuse)
            const userPhotoCount = await Photo.count({
                where: {
                    userId,
                    deletedAt: null
                }
            });

            if (userPhotoCount >= 10000) { // 10k photos per user limit
                return res.status(429).json({
                    success: false,
                    error: 'Photo quota exceeded',
                    requestId
                });
            }

            // Generate file hash for duplicate detection
            const fileHash = crypto
                .createHash('sha256')
                .update(file.buffer)
                .digest('hex');

            // Check for duplicates
            const existingPhoto = await Photo.findOne({
                where: { checksum: fileHash, userId }
            });

            if (existingPhoto) {
                return res.status(409).json({
                    success: false,
                    error: 'Duplicate file detected',
                    existingPhotoId: existingPhoto.id,
                    requestId
                });
            }

            // Extract metadata using Sharp
            const metadata = await sharp(file.buffer).metadata();

            if (!metadata.width || !metadata.height) {
                return res.status(400).json({
                    success: false,
                    error: 'Invalid image file',
                    requestId
                });
            }

            // Generate unique filename
            const fileExtension = this.getFileExtension(file.mimetype);
            const uniqueFileName = `${uuidv4()}_${Date.now()}.${fileExtension}`;
            const storagePath = `photos/${userId}/${new Date().getFullYear()}/${new Date().getMonth() + 1}/${uniqueFileName}`;

            // Create photo record
            const photo = await Photo.create({
                userId,
                originalFileName: file.originalname,
                fileName: uniqueFileName,
                storageProvider: process.env.STORAGE_PROVIDER || 'aws-s3',
                storagePath,
                bucketName: process.env.STORAGE_BUCKET,
                region: process.env.STORAGE_REGION,
                mimeType: file.mimetype,
                fileSize: file.size,
                checksum: fileHash,
                width: metadata.width,
                height: metadata.height,
                aspectRatio: (metadata.width / metadata.height).toFixed(4),
                processingStatus: 'pending',
                uploadedAt: new Date()
            }, {
                context: { userId },
                fileBuffer: file.buffer // For validation hook
            });

            // Create default settings for the photo
            await PhotoSettings.create({
                photoId: photo.id,
                userId,
                lastModifiedBy: userId
            });

            // Log upload history
            await PhotoHistory.create({
                photoId: photo.id,
                userId,
                action: 'upload',
                actionDescription: 'Photo uploaded successfully',
                actionData: {
                    fileName: file.originalname,
                    fileSize: file.size,
                    dimensions: { width: metadata.width, height: metadata.height }
                },
                source: req.headers['user-agent']?.includes('Mobile') ? 'mobile_app' : 'web',
                ipAddress: req.ip,
                userAgent: req.headers['user-agent'],
                sessionId: req.sessionID,
                requestId,
                processingTime: Date.now() - startTime,
                fileSizeAfter: file.size,
                dimensionsAfter: { width: metadata.width, height: metadata.height }
            });

            // Queue for async processing
            await this.queueForProcessing(photo, file.buffer);

            res.status(201).json({
                success: true,
                data: {
                    id: photo.id,
                    fileName: photo.fileName,
                    originalFileName: photo.originalFileName,
                    fileSize: photo.fileSize,
                    dimensions: {
                        width: photo.width,
                        height: photo.height
                    },
                    processingStatus: photo.processingStatus,
                    uploadedAt: photo.uploadedAt
                },
                requestId,
                processingTime: Date.now() - startTime
            });

        } catch (error) {
            console.error('Upload error:', error);

            // Log failed upload
            if (req.user?.id && req.file) {
                await PhotoHistory.create({
                    userId: req.user.id,
                    action: 'upload',
                    actionDescription: 'Photo upload failed',
                    actionData: {
                        fileName: req.file.originalname,
                        error: error.message
                    },
                    source: req.headers['user-agent']?.includes('Mobile') ? 'mobile_app' : 'web',
                    ipAddress: req.ip,
                    userAgent: req.headers['user-agent'],
                    requestId,
                    processingTime: Date.now() - startTime,
                    success: false,
                    errorMessage: error.message,
                    errorCode: 'UPLOAD_FAILED'
                }).catch(historyError => {
                    console.error('Failed to log upload error:', historyError);
                });
            }

            res.status(500).json({
                success: false,
                error: 'Upload failed',
                message: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error',
                requestId
            });
        }
    }

    async uploadMultiple(req, res) {
        const startTime = Date.now();
        const requestId = uuidv4();
        const batchId = uuidv4();

        try {
            const { userId } = req.user;
            const files = req.files;

            if (!files || files.length === 0) {
                return res.status(400).json({
                    success: false,
                    error: 'No files uploaded',
                    requestId
                });
            }

            // Check batch size limit
            if (files.length > 10) {
                return res.status(400).json({
                    success: false,
                    error: 'Maximum 10 files per batch',
                    requestId
                });
            }

            const results = [];
            const errors = [];

            // Process files in parallel with concurrency limit
            const concurrency = 3;
            for (let i = 0; i < files.length; i += concurrency) {
                const batch = files.slice(i, i + concurrency);
                const batchPromises = batch.map(async (file, index) => {
                    try {
                        const result = await this.processSingleFile(file, userId, batchId, i + index);
                        results.push(result);
                    } catch (error) {
                        errors.push({
                            fileName: file.originalname,
                            error: error.message
                        });
                    }
                });

                await Promise.all(batchPromises);
            }

            // Log batch upload history
            await PhotoHistory.create({
                userId,
                action: 'upload',
                actionDescription: `Batch upload completed: ${results.length} successful, ${errors.length} failed`,
                actionData: {
                    batchSize: files.length,
                    successful: results.length,
                    failed: errors.length,
                    errors: errors.length > 0 ? errors : undefined
                },
                source: req.headers['user-agent']?.includes('Mobile') ? 'mobile_app' : 'web',
                ipAddress: req.ip,
                userAgent: req.headers['user-agent'],
                sessionId: req.sessionID,
                requestId,
                batchId,
                batchSize: files.length,
                processingTime: Date.now() - startTime,
                success: results.length > 0
            });

            res.status(results.length > 0 ? 201 : 400).json({
                success: results.length > 0,
                data: {
                    successful: results,
                    failed: errors,
                    summary: {
                        total: files.length,
                        successful: results.length,
                        failed: errors.length
                    }
                },
                requestId,
                batchId,
                processingTime: Date.now() - startTime
            });

        } catch (error) {
            console.error('Batch upload error:', error);

            res.status(500).json({
                success: false,
                error: 'Batch upload failed',
                message: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error',
                requestId,
                batchId
            });
        }
    }

    async processSingleFile(file, userId, batchId, fileIndex) {
        // Generate file hash
        const fileHash = crypto
            .createHash('sha256')
            .update(file.buffer)
            .digest('hex');

        // Check for duplicates
        const existingPhoto = await Photo.findOne({
            where: { checksum: fileHash, userId }
        });

        if (existingPhoto) {
            throw new Error('Duplicate file detected');
        }

        // Extract metadata
        const metadata = await sharp(file.buffer).metadata();

        if (!metadata.width || !metadata.height) {
            throw new Error('Invalid image file');
        }

        // Generate unique filename
        const fileExtension = this.getFileExtension(file.mimetype);
        const uniqueFileName = `${batchId}_${fileIndex}_${Date.now()}.${fileExtension}`;
        const storagePath = `photos/${userId}/${new Date().getFullYear()}/${new Date().getMonth() + 1}/${uniqueFileName}`;

        // Create photo record
        const photo = await Photo.create({
            userId,
            originalFileName: file.originalname,
            fileName: uniqueFileName,
            storageProvider: process.env.STORAGE_PROVIDER || 'aws-s3',
            storagePath,
            bucketName: process.env.STORAGE_BUCKET,
            region: process.env.STORAGE_REGION,
            mimeType: file.mimetype,
            fileSize: file.size,
            checksum: fileHash,
            width: metadata.width,
            height: metadata.height,
            aspectRatio: (metadata.width / metadata.height).toFixed(4),
            processingStatus: 'pending',
            uploadedAt: new Date()
        }, {
            context: { userId },
            fileBuffer: file.buffer
        });

        // Create default settings
        await PhotoSettings.create({
            photoId: photo.id,
            userId,
            lastModifiedBy: userId
        });

        // Queue for processing
        await this.queueForProcessing(photo, file.buffer);

        return {
            id: photo.id,
            fileName: photo.fileName,
            originalFileName: photo.originalFileName,
            fileSize: photo.fileSize,
            dimensions: {
                width: photo.width,
                height: photo.height
            },
            processingStatus: photo.processingStatus
        };
    }

    async queueForProcessing(photo, buffer) {
        try {
            // In a real application, this would queue the photo for background processing
            // For now, we'll just mark it as queued
            console.log(`Queued photo ${photo.id} for processing`);

            // You could integrate with Redis Queue, AWS SQS, or similar
            // Example: await photoProcessingQueue.add('process-photo', { photoId: photo.id });

        } catch (error) {
            console.error('Failed to queue photo for processing:', error);
        }
    }

    async getUploadProgress(req, res) {
        try {
            const { userId } = req.user;
            const { requestId } = req.params;

            const recentUploads = await Photo.findAll({
                where: {
                    userId,
                    createdAt: {
                        [Op.gte]: new Date(Date.now() - 30 * 60 * 1000) // Last 30 minutes
                    }
                },
                attributes: ['id', 'fileName', 'originalFileName', 'processingStatus', 'isProcessed', 'uploadedAt'],
                order: [['createdAt', 'DESC']],
                limit: 20
            });

            // Get processing statistics
            const processingStats = await Photo.findAll({
                where: { userId },
                attributes: [
                    'processingStatus',
                    [Photo.sequelize.fn('COUNT', Photo.sequelize.col('id')), 'count']
                ],
                group: ['processingStatus'],
                raw: true
            });

            const stats = processingStats.reduce((acc, stat) => {
                acc[stat.processingStatus] = parseInt(stat.count);
                return acc;
            }, {});

            res.json({
                success: true,
                data: {
                    recentUploads,
                    statistics: stats,
                    quotaUsed: await Photo.count({ where: { userId, deletedAt: null } }),
                    quotaLimit: 10000
                }
            });

        } catch (error) {
            console.error('Get upload progress error:', error);
            res.status(500).json({
                success: false,
                error: 'Failed to get upload progress'
            });
        }
    }

    async validateFile(req, res) {
        try {
            const file = req.file;

            if (!file) {
                return res.status(400).json({
                    success: false,
                    error: 'No file provided'
                });
            }

            // Validate file using Sharp
            const metadata = await sharp(file.buffer).metadata();

            const validation = {
                isValid: true,
                errors: [],
                warnings: [],
                metadata: {
                    format: metadata.format,
                    width: metadata.width,
                    height: metadata.height,
                    size: file.size,
                    hasAlpha: metadata.hasAlpha,
                    channels: metadata.channels
                }
            };

            // Validation checks
            if (!metadata.width || !metadata.height) {
                validation.isValid = false;
                validation.errors.push('Invalid image dimensions');
            }

            if (metadata.width > 10000 || metadata.height > 10000) {
                validation.warnings.push('Image dimensions are very large');
            }

            if (file.size > 50 * 1024 * 1024) { // 50MB
                validation.isValid = false;
                validation.errors.push('File size exceeds 50MB limit');
            }

            if (metadata.density && metadata.density > 600) {
                validation.warnings.push('High DPI image detected - may increase processing time');
            }

            res.json({
                success: true,
                data: validation
            });

        } catch (error) {
            console.error('File validation error:', error);
            res.status(400).json({
                success: false,
                error: 'Invalid file format',
                message: error.message
            });
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

    // Middleware functions
    getUploadLimiter() {
        return this.uploadLimiter;
    }

    getMulterUpload() {
        return this.upload;
    }
}
