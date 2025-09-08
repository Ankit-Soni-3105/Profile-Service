import { Model, DataTypes, Op } from 'sequelize';

class PhotoSettings extends Model {
    static init(sequelize) {
        return super.init(
            {
                id: {
                    type: DataTypes.UUID,
                    defaultValue: DataTypes.UUIDV4,
                    primaryKey: true,
                    comment: 'Unique identifier for photo settings',
                },
                photoId: {
                    type: DataTypes.UUID,
                    allowNull: false,
                    unique: true,
                    references: { model: 'photos', key: 'id' },
                    onDelete: 'CASCADE',
                    onUpdate: 'CASCADE',
                    comment: 'Reference to the photo',
                },
                userId: {
                    type: DataTypes.UUID,
                    allowNull: false,
                    references: { model: 'users', key: 'id' },
                    onDelete: 'CASCADE',
                    onUpdate: 'CASCADE',
                    comment: 'Reference to user who owns the photo',
                },
                cropSettings: {
                    type: DataTypes.JSONB,
                    allowNull: true,
                    defaultValue: {},
                    comment: 'Crop configuration and presets',
                    validate: {
                        isValidCropSettings(value) {
                            if (value && typeof value === 'object') {
                                if (value.presets && Array.isArray(value.presets)) {
                                    value.presets.forEach((preset) => {
                                        if (!preset.name || !preset.x || !preset.y || !preset.width || !preset.height) {
                                            throw new Error('Invalid crop preset format');
                                        }
                                    });
                                }
                            }
                        },
                    },
                },
                enableAutoCrop: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: false,
                    allowNull: false,
                    comment: 'Whether to automatically crop to optimal dimensions',
                },
                cropAspectRatio: {
                    type: DataTypes.ENUM('free', '1:1', '4:3', '16:9', '3:2', 'custom'),
                    defaultValue: 'free',
                    allowNull: false,
                    comment: 'Preferred aspect ratio for cropping',
                },
                customAspectRatio: {
                    type: DataTypes.DECIMAL(5, 4),
                    allowNull: true,
                    comment: 'Custom aspect ratio value when cropAspectRatio is custom',
                },
                optimizationLevel: {
                    type: DataTypes.ENUM('none', 'low', 'medium', 'high', 'aggressive'),
                    defaultValue: 'medium',
                    allowNull: false,
                    comment: 'Image optimization level',
                },
                enableAutoOptimization: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: true,
                    allowNull: false,
                    comment: 'Whether to automatically optimize uploaded images',
                },
                targetFileSize: {
                    type: DataTypes.INTEGER,
                    allowNull: true,
                    validate: { min: 10240, max: 52428800 }, // 10KB to 50MB
                    comment: 'Target file size in bytes for optimization',
                },
                maxWidth: {
                    type: DataTypes.INTEGER,
                    allowNull: true,
                    validate: { min: 100, max: 10000 },
                    comment: 'Maximum width for auto-resizing',
                },
                maxHeight: {
                    type: DataTypes.INTEGER,
                    allowNull: true,
                    validate: { min: 100, max: 10000 },
                    comment: 'Maximum height for auto-resizing',
                },
                jpegQuality: {
                    type: DataTypes.INTEGER,
                    defaultValue: 85,
                    allowNull: false,
                    validate: { min: 1, max: 100 },
                    comment: 'JPEG compression quality (1-100)',
                },
                webpQuality: {
                    type: DataTypes.INTEGER,
                    defaultValue: 80,
                    allowNull: false,
                    validate: { min: 1, max: 100 },
                    comment: 'WebP compression quality (1-100)',
                },
                enableProgressiveJpeg: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: true,
                    allowNull: false,
                    comment: 'Whether to use progressive JPEG encoding',
                },
                enableAutoFormat: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: true,
                    allowNull: false,
                    comment: 'Whether to automatically convert to optimal format',
                },
                preferredFormat: {
                    type: DataTypes.ENUM('original', 'jpeg', 'png', 'webp', 'avif'),
                    defaultValue: 'webp',
                    allowNull: false,
                    comment: 'Preferred output format for converted images',
                },
                enableAvifFallback: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: true,
                    allowNull: false,
                    comment: 'Whether to generate AVIF with fallbacks',
                },
                generateThumbnails: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: true,
                    allowNull: false,
                    comment: 'Whether to automatically generate thumbnails',
                },
                thumbnailSizes: {
                    type: DataTypes.JSONB,
                    allowNull: true,
                    defaultValue: {
                        thumbnail: { width: 150, height: 150 },
                        small: { width: 300, height: 300 },
                        medium: { width: 600, height: 600 },
                        large: { width: 1200, height: 1200 },
                    },
                    comment: 'Thumbnail size configurations',
                    validate: {
                        isValidThumbnailSizes(value) {
                            if (value && typeof value === 'object') {
                                const sizeNames = Object.keys(value);
                                if (new Set(sizeNames).size !== sizeNames.length) {
                                    throw new Error('Thumbnail size names must be unique');
                                }
                                for (const [size, dimensions] of Object.entries(value)) {
                                    if (!dimensions.width || !dimensions.height) {
                                        throw new Error(`Invalid dimensions for thumbnail size: ${size}`);
                                    }
                                    if (
                                        dimensions.width <= 0 ||
                                        dimensions.height <= 0 ||
                                        dimensions.width > 10000 ||
                                        dimensions.height > 10000
                                    ) {
                                        throw new Error(`Thumbnail dimensions must be between 1 and 10000: ${size}`);
                                    }
                                }
                            }
                        },
                    },
                },
                enableResponsiveImages: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: true,
                    allowNull: false,
                    comment: 'Whether to generate responsive image variants',
                },
                enableAutoBackgroundRemoval: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: false,
                    allowNull: false,
                    comment: 'Whether to automatically remove background',
                },
                backgroundRemovalProvider: {
                    type: DataTypes.ENUM('remove-bg', 'photoscissors', 'ai-internal', 'manual'),
                    defaultValue: 'ai-internal',
                    allowNull: false,
                    comment: 'Preferred background removal service',
                },
                backgroundRemovalQuality: {
                    type: DataTypes.ENUM('preview', 'full', 'hd', '4k'),
                    defaultValue: 'full',
                    allowNull: false,
                    comment: 'Quality level for background removal',
                },
                enableWatermark: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: false,
                    allowNull: false,
                    comment: 'Whether to apply watermark',
                },
                watermarkSettings: {
                    type: DataTypes.JSONB,
                    allowNull: true,
                    defaultValue: {},
                    comment: 'Watermark configuration (position, opacity, text/image)',
                    validate: {
                        isValidWatermarkSettings(value) {
                            if (value && value.enabled) {
                                if (!value.type || !['text', 'image'].includes(value.type)) {
                                    throw new Error('Watermark type must be "text" or "image" when enabled');
                                }
                                if (value.type === 'text' && !value.text) {
                                    throw new Error('Watermark text is required for text type');
                                }
                                if (value.type === 'image' && !value.imageUrl) {
                                    throw new Error('Watermark imageUrl is required for image type');
                                }
                                if (value.opacity && (value.opacity < 0 || value.opacity > 1)) {
                                    throw new Error('Watermark opacity must be between 0 and 1');
                                }
                            }
                        },
                    },
                },
                enableExifStripping: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: true,
                    allowNull: false,
                    comment: 'Whether to strip EXIF data for privacy',
                },
                preserveColorProfile: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: false,
                    allowNull: false,
                    comment: 'Whether to preserve color profiles',
                },
                enableGeotagging: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: false,
                    allowNull: false,
                    comment: 'Whether to preserve or add GPS coordinates',
                },
                enableCdnUpload: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: true,
                    allowNull: false,
                    comment: 'Whether to upload to CDN automatically',
                },
                cdnRegion: {
                    type: DataTypes.STRING(50),
                    allowNull: true,
                    comment: 'Preferred CDN region for uploads',
                },
                storageClass: {
                    type: DataTypes.ENUM('standard', 'standard-ia', 'cold', 'archive'),
                    defaultValue: 'standard',
                    allowNull: false,
                    comment: 'Storage class for cost optimization',
                },
                enableAutoArchive: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: false,
                    allowNull: false,
                    comment: 'Whether to auto-archive old photos',
                },
                archiveAfterDays: {
                    type: DataTypes.INTEGER,
                    allowNull: true,
                    validate: { min: 30, max: 3650 },
                    comment: 'Days after which to archive photo',
                },
                processingPriority: {
                    type: DataTypes.ENUM('low', 'normal', 'high', 'urgent'),
                    defaultValue: 'normal',
                    allowNull: false,
                    comment: 'Processing queue priority',
                },
                enableAsyncProcessing: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: true,
                    allowNull: false,
                    comment: 'Whether to process images asynchronously',
                },
                maxProcessingTime: {
                    type: DataTypes.INTEGER,
                    defaultValue: 300,
                    allowNull: false,
                    validate: { min: 30, max: 3600 },
                    comment: 'Maximum processing time in seconds',
                },
                enableAiAnalysis: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: true,
                    allowNull: false,
                    comment: 'Whether to run AI analysis on photos',
                },
                enableFaceDetection: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: false,
                    allowNull: false,
                    comment: 'Whether to detect faces in photos',
                },
                enableObjectDetection: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: true,
                    allowNull: false,
                    comment: 'Whether to detect objects for tagging',
                },
                enableContentModeration: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: true,
                    allowNull: false,
                    comment: 'Whether to run automated content moderation',
                },
                moderationSensitivity: {
                    type: DataTypes.ENUM('low', 'medium', 'high'),
                    defaultValue: 'medium',
                    allowNull: false,
                    comment: 'Content moderation sensitivity level',
                },
                enableAltTextGeneration: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: true,
                    allowNull: false,
                    comment: 'Whether to auto-generate alt text',
                },
                altTextLanguage: {
                    type: DataTypes.STRING(10),
                    defaultValue: 'en',
                    allowNull: false,
                    comment: 'Language for auto-generated alt text',
                },
                enableColorBlindnessSupport: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: false,
                    allowNull: false,
                    comment: 'Whether to add colorblindness indicators',
                },
                notifyOnProcessingComplete: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: false,
                    allowNull: false,
                    comment: 'Whether to notify when processing is complete',
                },
                notifyOnModerationFlag: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: true,
                    allowNull: false,
                    comment: 'Whether to notify when content is flagged',
                },
                notificationChannels: {
                    type: DataTypes.JSONB,
                    allowNull: true,
                    defaultValue: ['email'],
                    comment: 'Preferred notification channels',
                    validate: {
                        isValidChannels(value) {
                            if (value && Array.isArray(value)) {
                                const validChannels = ['email', 'sms', 'push'];
                                if (!value.every((channel) => validChannels.includes(channel))) {
                                    throw new Error('Invalid notification channel');
                                }
                            }
                        },
                    },
                },
                enableAnalytics: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: true,
                    allowNull: false,
                    comment: 'Whether to collect analytics on photo usage',
                },
                trackViewMetrics: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: true,
                    allowNull: false,
                    comment: 'Whether to track view counts and patterns',
                },
                enableInsights: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: false,
                    allowNull: false,
                    comment: 'Whether to generate usage insights',
                },
                customProcessingPipeline: {
                    type: DataTypes.JSONB,
                    allowNull: true,
                    comment: 'Custom processing pipeline configuration',
                    validate: {
                        isValidPipeline(value) {
                            if (value && Array.isArray(value.steps)) {
                                const validSteps = ['crop', 'resize', 'optimize', 'watermark', 'convert'];
                                if (!value.steps.every((step) => validSteps.includes(step.type))) {
                                    throw new Error('Invalid processing pipeline step type');
                                }
                            }
                        },
                    },
                },
                enableExperimentalFeatures: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: false,
                    allowNull: false,
                    comment: 'Whether to enable experimental features',
                },
                apiVersion: {
                    type: DataTypes.STRING(10),
                    defaultValue: 'v1',
                    allowNull: false,
                    comment: 'API version for processing preferences',
                },
                lastModifiedBy: {
                    type: DataTypes.UUID,
                    allowNull: true,
                    references: { model: 'users', key: 'id' },
                    comment: 'User who last modified these settings',
                },
                createdAt: {
                    type: DataTypes.DATE,
                    allowNull: false,
                    defaultValue: DataTypes.NOW,
                },
                updatedAt: {
                    type: DataTypes.DATE,
                    allowNull: false,
                    defaultValue: DataTypes.NOW,
                },
            },
            {
                sequelize,
                modelName: 'PhotoSettings',
                tableName: 'photo_settings',
                timestamps: true,
                underscored: true,
                indexes: [
                    { fields: ['photo_id'], unique: true, name: 'unique_photo_settings_photo_id' },
                    { fields: ['user_id'], name: 'idx_photo_settings_user_id' },
                    { fields: ['enable_auto_optimization'], name: 'idx_photo_settings_auto_opt' },
                    { fields: ['enable_async_processing'], name: 'idx_photo_settings_async' },
                    { fields: ['processing_priority'], name: 'idx_photo_settings_priority' },
                    { fields: ['enable_ai_analysis'], name: 'idx_photo_settings_ai' },
                    { fields: ['enable_content_moderation'], name: 'idx_photo_settings_moderation' },
                    { fields: ['storage_class'], name: 'idx_photo_settings_storage_class' },
                    { fields: ['enable_auto_archive', 'archive_after_days'], name: 'idx_photo_settings_archive' },
                    { fields: ['enable_cdn_upload'], name: 'idx_photo_settings_cdn' },
                    { fields: ['cdn_region'], name: 'idx_photo_settings_cdn_region' }, // Added for CDN queries
                    {
                        fields: ['enable_auto_optimization', 'processing_priority', 'enable_async_processing'],
                        name: 'idx_photo_settings_processing_workflow',
                    },
                    { fields: ['enable_analytics'], name: 'idx_photo_settings_analytics' },
                    { fields: ['last_modified_by'], name: 'idx_photo_settings_modified_by' },
                    { fields: ['updated_at'], name: 'idx_photo_settings_updated' },
                ],
                validate: {
                    customAspectRatioRequired() {
                        if (this.cropAspectRatio === 'custom' && !this.customAspectRatio) {
                            throw new Error('Custom aspect ratio value is required when crop aspect ratio is set to custom');
                        }
                    },
                    archiveSettingsConsistency() {
                        if (this.enableAutoArchive && !this.archiveAfterDays) {
                            throw new Error('Archive after days is required when auto archive is enabled');
                        }
                    },
                    processingTimeLimits() {
                        if (this.maxProcessingTime && this.processingPriority === 'low' && this.maxProcessingTime > 1800) {
                            throw new Error('Low priority processing cannot exceed 30 minutes');
                        }
                    },
                },
                hooks: {
                    beforeUpdate: async (settings, options) => {
                        if (settings.changed()) {
                            settings.lastModifiedBy = options.context?.userId || settings.userId;
                        }
                    },
                    afterCreate: async (settings) => {
                        try {
                            // Log settings creation for audit
                            // await sequelize.models.PhotoHistory.create({
                            //   photoId: settings.photoId,
                            //   userId: settings.lastModifiedBy || settings.userId,
                            //   action: 'settings_create',
                            //   actionData: { settings: settings.toJSON() },
                            //   source: 'web',
                            // });
                        } catch (error) {
                            console.error('Failed to log settings creation:', error);
                        }
                    },
                    afterUpdate: async (settings) => {
                        try {
                            const changes = settings.changed();
                            if (changes && changes.length > 0) {
                                // await sequelize.models.PhotoHistory.create({
                                //   photoId: settings.photoId,
                                //   userId: settings.lastModifiedBy || settings.userId,
                                //   action: 'settings_update',
                                //   actionData: { changedFields: changes },
                                //   source: 'web',
                                // });
                            }
                        } catch (error) {
                            console.error('Failed to log settings update:', error);
                        }
                    },
                },
                getterMethods: {
                    optimizationPreset() {
                        return {
                            level: this.optimizationLevel,
                            jpegQuality: this.jpegQuality,
                            webpQuality: this.webpQuality,
                            enableProgressive: this.enableProgressiveJpeg,
                            targetFileSize: this.targetFileSize,
                        };
                    },
                    processingConfig() {
                        return {
                            priority: this.processingPriority,
                            async: this.enableAsyncProcessing,
                            maxTime: this.maxProcessingTime,
                            enableAI: this.enableAiAnalysis,
                            enableModeration: this.enableContentModeration,
                        };
                    },
                    hasAiFeatures() {
                        return (
                            this.enableAiAnalysis ||
                            this.enableFaceDetection ||
                            this.enableObjectDetection ||
                            this.enableContentModeration ||
                            this.enableAltTextGeneration
                        );
                    },
                    storageConfig() {
                        return {
                            class: this.storageClass,
                            cdnEnabled: this.enableCdnUpload,
                            region: this.cdnRegion,
                            autoArchive: this.enableAutoArchive,
                            archiveAfterDays: this.archiveAfterDays,
                        };
                    },
                },
                instanceMethods: {
                    async applyToProcessing(photo) {
                        const config = {
                            crop: this.cropSettings,
                            optimization: this.optimizationPreset,
                            format: {
                                preferred: this.preferredFormat,
                                autoConvert: this.enableAutoFormat,
                            },
                            variants: this.generateThumbnails ? this.thumbnailSizes : null,
                            ai: {
                                enabled: this.enableAiAnalysis,
                                faceDetection: this.enableFaceDetection,
                                objectDetection: this.enableObjectDetection,
                                contentModeration: this.enableContentModeration,
                            },
                        };
                        return config;
                    },
                    validateCompatibility() {
                        const issues = [];
                        if (this.optimizationLevel === 'aggressive' && this.jpegQuality > 70) {
                            issues.push('High JPEG quality with aggressive optimization may not provide optimal results');
                        }
                        if (this.storageClass === 'archive' && this.enableCdnUpload) {
                            issues.push('Archived storage is not compatible with CDN uploads');
                        }
                        if (this.processingPriority === 'urgent' && this.maxProcessingTime > 600) {
                            issues.push('Urgent priority should have shorter processing time limits');
                        }
                        return issues;
                    },
                    getRecommendedSettings(photoType = 'profile') {
                        const presets = {
                            profile: {
                                cropAspectRatio: '1:1',
                                optimizationLevel: 'medium',
                                jpegQuality: 85,
                                enableAutoOptimization: true,
                                generateThumbnails: true,
                                enableAiAnalysis: true,
                            },
                            cover: {
                                cropAspectRatio: '16:9',
                                optimizationLevel: 'high',
                                jpegQuality: 90,
                                maxWidth: 1920,
                                maxHeight: 1080,
                            },
                            gallery: {
                                optimizationLevel: 'medium',
                                enableResponsiveImages: true,
                                generateThumbnails: true,
                                enableAutoFormat: true,
                            },
                        };
                        return presets[photoType] || presets.profile;
                    },
                },
                classMethods: {
                    getDefaultSettings() {
                        return {
                            optimizationLevel: 'medium',
                            jpegQuality: 85,
                            webpQuality: 80,
                            enableAutoOptimization: true,
                            generateThumbnails: true,
                            enableAiAnalysis: true,
                            enableContentModeration: true,
                            enableExifStripping: true,
                            processingPriority: 'normal',
                        };
                    },
                    async bulkUpdateSettings(photoIds, settingsUpdate) {
                        return sequelize.transaction(async (t) => {
                            return this.update(settingsUpdate, {
                                where: { photoId: { [Op.in]: photoIds } },
                                returning: true,
                                transaction: t,
                            });
                        });
                    },
                    async getUserTemplate(userId) {
                        const userSettings = await this.findAll({
                            where: { userId },
                            order: [['updatedAt', 'DESC']],
                            limit: 10,
                        });
                        if (userSettings.length === 0) {
                            return this.getDefaultSettings();
                        }
                        const template = {};
                        const fields = [
                            'optimizationLevel',
                            'jpegQuality',
                            'webpQuality',
                            'enableAutoOptimization',
                            'generateThumbnails',
                            'enableAiAnalysis',
                            'processingPriority',
                        ];
                        fields.forEach((field) => {
                            const values = userSettings.map((s) => s[field]);
                            template[field] = this.getMostCommon(values);
                        });
                        return template;
                    },
                    getMostCommon(array) {
                        const frequency = {};
                        let maxCount = 0;
                        let mostCommon = array[0];
                        array.forEach((item) => {
                            frequency[item] = (frequency[item] || 0) + 1;
                            if (frequency[item] > maxCount) {
                                maxCount = frequency[item];
                                mostCommon = item;
                            }
                        });
                        return mostCommon;
                    },
                    async findOptimizationCandidates() {
                        return this.findAll({
                            where: {
                                [Op.or]: [
                                    { optimizationLevel: 'none' },
                                    { enableAutoOptimization: false },
                                    { jpegQuality: { [Op.gt]: 95 } },
                                    { enableExifStripping: false },
                                ],
                            },
                            include: [
                                {
                                    model: sequelize.models.Photo,
                                    as: 'photo',
                                    where: { fileSize: { [Op.gt]: 5242880 } }, // Files > 5MB
                                },
                            ],
                        });
                    },
                },
            }
        );
    }

    static associate(models) {
        PhotoSettings.belongsTo(models.Photo, { foreignKey: 'photoId', as: 'photo', onDelete: 'CASCADE' });
        PhotoSettings.belongsTo(models.User, { foreignKey: 'userId', as: 'user', onDelete: 'CASCADE' });
        PhotoSettings.belongsTo(models.User, { foreignKey: 'lastModifiedBy', as: 'modifier', onDelete: 'SET NULL' });
    }
}

export default PhotoSettings;