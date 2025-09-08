import { Model, DataTypes, Op } from 'sequelize';
import sharp from 'sharp'; // Added for file format validation

class Photo extends Model {
    static init(sequelize) {
        return super.init(
            {
                id: {
                    type: DataTypes.UUID,
                    defaultValue: DataTypes.UUIDV4,
                    primaryKey: true,
                    comment: 'Unique identifier for photo',
                },
                userId: {
                    type: DataTypes.UUID,
                    allowNull: false,
                    references: { model: 'users', key: 'id' },
                    onDelete: 'CASCADE',
                    onUpdate: 'CASCADE',
                    comment: 'Reference to user who owns this photo',
                },
                originalFileName: {
                    type: DataTypes.STRING(255),
                    allowNull: false,
                    comment: 'Original filename when uploaded',
                },
                fileName: {
                    type: DataTypes.STRING(255),
                    allowNull: false,
                    unique: true,
                    comment: 'Unique filename in storage',
                },
                storageProvider: {
                    type: DataTypes.ENUM('aws-s3', 'azure-blob', 'gcp-cloud-storage', 'local'),
                    allowNull: false,
                    defaultValue: 'aws-s3',
                    comment: 'Storage provider used',
                },
                storagePath: {
                    type: DataTypes.STRING(512),
                    allowNull: false,
                    comment: 'Full path/key in storage provider',
                    validate: {
                        isValidPath(value) {
                            if (!/^[a-zA-Z0-9\/._-]+$/.test(value)) {
                                throw new Error('Invalid storage path format');
                            }
                        },
                    },
                },
                bucketName: {
                    type: DataTypes.STRING(100),
                    allowNull: false,
                    comment: 'Storage bucket/container name',
                },
                region: {
                    type: DataTypes.STRING(50),
                    allowNull: true,
                    comment: 'Primary storage region for performance optimization',
                },
                replicationRegions: {
                    type: DataTypes.JSONB,
                    allowNull: true,
                    defaultValue: [],
                    comment: 'Secondary regions for storage replication',
                    validate: {
                        isValidRegions(value) {
                            if (value && Array.isArray(value)) {
                                if (!value.every((region) => typeof region === 'string' && region.length <= 50)) {
                                    throw new Error('Replication regions must be an array of strings with max length 50');
                                }
                            }
                        },
                    },
                },
                mimeType: {
                    type: DataTypes.STRING(100),
                    allowNull: false,
                    validate: {
                        isIn: [['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'image/bmp', 'image/tiff']],
                    },
                    comment: 'MIME type of the image',
                },
                fileSize: {
                    type: DataTypes.BIGINT,
                    allowNull: false,
                    validate: { min: 1, max: 52428800 }, // 50MB max
                    comment: 'File size in bytes',
                },
                checksum: {
                    type: DataTypes.STRING(64),
                    allowNull: false,
                    unique: true,
                    comment: 'SHA-256 checksum for duplicate detection',
                },
                width: {
                    type: DataTypes.INTEGER,
                    allowNull: false,
                    validate: { min: 1, max: 10000 },
                    comment: 'Image width in pixels',
                },
                height: {
                    type: DataTypes.INTEGER,
                    allowNull: false,
                    validate: { min: 1, max: 10000 },
                    comment: 'Image height in pixels',
                },
                aspectRatio: {
                    type: DataTypes.DECIMAL(5, 4),
                    allowNull: true,
                    comment: 'Aspect ratio (width/height)',
                },
                isProcessed: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: false,
                    allowNull: false,
                    comment: 'Whether image has been processed',
                },
                processingStatus: {
                    type: DataTypes.ENUM('pending', 'processing', 'completed', 'failed'),
                    defaultValue: 'pending',
                    allowNull: false,
                    comment: 'Current processing status',
                },
                processingError: {
                    type: DataTypes.TEXT,
                    allowNull: true,
                    comment: 'Error message if processing failed',
                },
                compressionLevel: {
                    type: DataTypes.INTEGER,
                    allowNull: true,
                    validate: { min: 0, max: 100 },
                    comment: 'Compression level applied (0-100)',
                },
                qualityScore: {
                    type: DataTypes.DECIMAL(3, 2),
                    allowNull: true,
                    validate: { min: 0, max: 10 },
                    comment: 'AI-generated quality score (0-10)',
                },
                variants: {
                    type: DataTypes.JSONB,
                    allowNull: true,
                    defaultValue: {},
                    comment: 'Different size variants (thumbnail, small, medium, large, or custom)',
                    validate: {
                        isValidVariants(value) {
                            if (value && typeof value === 'object') {
                                for (let key in value) {
                                    if (typeof key !== 'string' || key.length > 50) {
                                        throw new Error(`Invalid variant key: ${key}`);
                                    }
                                }
                            }
                        },
                    },
                },
                cropData: {
                    type: DataTypes.JSONB,
                    allowNull: true,
                    comment: 'Crop coordinates and settings',
                    validate: {
                        isValidCropData(value) {
                            if (value) {
                                const required = ['x', 'y', 'width', 'height'];
                                for (let field of required) {
                                    if (typeof value[field] !== 'number') {
                                        throw new Error(`Crop data missing required field: ${field}`);
                                    }
                                }
                            }
                        },
                    },
                },
                hasBackgroundRemoval: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: false,
                    allowNull: false,
                    comment: 'Whether background has been removed',
                },
                backgroundRemovalProvider: {
                    type: DataTypes.ENUM('remove-bg', 'photoscissors', 'ai-internal', 'manual'),
                    allowNull: true,
                    comment: 'Service used for background removal',
                },
                visibility: {
                    type: DataTypes.ENUM('private', 'public', 'unlisted', 'friends-only'),
                    defaultValue: 'private',
                    allowNull: false,
                    comment: 'Photo visibility setting',
                },
                isProfilePicture: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: false,
                    allowNull: false,
                    comment: 'Whether this is the current profile picture',
                },
                altText: {
                    type: DataTypes.TEXT,
                    allowNull: true,
                    validate: { len: [0, 500] },
                    comment: 'Alternative text for accessibility',
                },
                aiGeneratedDescription: {
                    type: DataTypes.TEXT,
                    allowNull: true,
                    comment: 'AI-generated description of image content',
                },
                contentTags: {
                    type: DataTypes.JSONB,
                    allowNull: true,
                    defaultValue: [],
                    comment: 'AI-detected content tags',
                    validate: {
                        isValidTags(value) {
                            if (value && Array.isArray(value)) {
                                if (!value.every((tag) => typeof tag === 'string' && tag.length <= 50)) {
                                    throw new Error('Content tags must be an array of strings with max length 50');
                                }
                            }
                        },
                    },
                },
                moderationStatus: {
                    type: DataTypes.ENUM('pending', 'approved', 'rejected', 'flagged'),
                    defaultValue: 'pending',
                    allowNull: false,
                    comment: 'Content moderation status',
                },
                moderationScore: {
                    type: DataTypes.DECIMAL(3, 2),
                    allowNull: true,
                    validate: { min: 0, max: 1 },
                    comment: 'AI moderation confidence score',
                },
                viewCount: {
                    type: DataTypes.BIGINT,
                    defaultValue: 0,
                    allowNull: false,
                    comment: 'Number of times photo has been viewed',
                },
                downloadCount: {
                    type: DataTypes.BIGINT,
                    defaultValue: 0,
                    allowNull: false,
                    comment: 'Number of times photo has been downloaded',
                },
                lastAccessedAt: {
                    type: DataTypes.DATE,
                    allowNull: true,
                    comment: 'Last time photo was accessed',
                },
                expiresAt: {
                    type: DataTypes.DATE,
                    allowNull: true,
                    comment: 'When temporary photo expires',
                },
                isTemporary: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: false,
                    allowNull: false,
                    comment: 'Whether this is a temporary photo',
                },
                version: {
                    type: DataTypes.INTEGER,
                    defaultValue: 1,
                    allowNull: false,
                    comment: 'Photo version for tracking edits',
                },
                parentPhotoId: {
                    type: DataTypes.UUID,
                    allowNull: true,
                    references: { model: 'photos', key: 'id' },
                    onDelete: 'SET NULL',
                    comment: 'Reference to original photo if this is an edited version',
                },
                gdprStatus: {
                    type: DataTypes.ENUM('active', 'deletion-requested', 'deleted', 'anonymized'),
                    defaultValue: 'active',
                    allowNull: false,
                    comment: 'GDPR compliance status',
                },
                deletionRequestedAt: {
                    type: DataTypes.DATE,
                    allowNull: true,
                    comment: 'When deletion was requested',
                },
                lastModifiedBy: {
                    type: DataTypes.UUID,
                    allowNull: true,
                    references: { model: 'users', key: 'id' },
                    comment: 'User who last modified the photo',
                },
                uploadedAt: {
                    type: DataTypes.DATE,
                    allowNull: false,
                    defaultValue: DataTypes.NOW,
                    comment: 'When photo was uploaded',
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
                deletedAt: {
                    type: DataTypes.DATE,
                    allowNull: true,
                    comment: 'Soft delete timestamp',
                },
            },
            {
                sequelize,
                modelName: 'Photo',
                tableName: 'photos',
                paranoid: true,
                timestamps: true,
                underscored: true,
                indexes: [
                    { fields: ['user_id'], name: 'idx_photos_user_id' },
                    { fields: ['user_id', 'is_profile_picture'], name: 'idx_photos_user_profile' },
                    { fields: ['user_id', 'created_at'], name: 'idx_photos_user_created' },
                    { fields: ['processing_status'], name: 'idx_photos_processing_status' },
                    { fields: ['moderation_status'], name: 'idx_photos_moderation_status' },
                    { fields: ['is_processed', 'processing_status'], name: 'idx_photos_processing' },
                    { fields: ['expires_at'], name: 'idx_photos_expires_at' },
                    { fields: ['is_temporary', 'expires_at'], name: 'idx_photos_temp_cleanup' },
                    { fields: ['gdpr_status'], name: 'idx_photos_gdpr_status' },
                    { fields: ['deletion_requested_at'], name: 'idx_photos_deletion_requested' },
                    { fields: ['visibility'], name: 'idx_photos_visibility' },
                    { fields: ['storage_provider'], name: 'idx_photos_storage_provider' },
                    { fields: ['mime_type'], name: 'idx_photos_mime_type' },
                    { fields: ['uploaded_at'], name: 'idx_photos_uploaded_at' },
                    { fields: ['last_accessed_at'], name: 'idx_photos_last_accessed' },
                    { fields: ['checksum'], unique: true, name: 'unique_photos_checksum' },
                    { fields: ['file_name'], unique: true, name: 'unique_photos_filename' },
                    { fields: ['visibility', 'moderation_status', 'created_at'], name: 'idx_photos_public_moderated' },
                    { fields: ['processing_status', 'created_at'], name: 'idx_photos_processing_queue' },
                    { fields: ['last_modified_by'], name: 'idx_photos_last_modified_by' },
                ],
                hooks: {
                    beforeCreate: async (photo, options) => {
                        // Validate file format using sharp
                        if (options.fileBuffer) {
                            try {
                                const metadata = await sharp(options.fileBuffer).metadata();
                                if (!['jpeg', 'png', 'webp', 'gif', 'bmp', 'tiff'].includes(metadata.format)) {
                                    throw new Error('Invalid image format');
                                }
                                photo.width = metadata.width;
                                photo.height = metadata.height;
                            } catch (error) {
                                throw new Error(`File validation failed: ${error.message}`);
                            }
                        }
                        // Calculate aspect ratio
                        if (photo.width && photo.height) {
                            photo.aspectRatio = (photo.width / photo.height).toFixed(4);
                        }
                        // Set upload timestamp
                        photo.uploadedAt = new Date();
                        // Validate checksum
                        if (!photo.checksum) {
                            throw new Error('Checksum is required before creation');
                        }
                    },
                    beforeUpdate: async (photo, options) => {
                        // Recalculate aspect ratio if dimensions changed
                        if (photo.changed('width') || photo.changed('height')) {
                            if (photo.width && photo.height) {
                                photo.aspectRatio = (photo.width / photo.height).toFixed(4);
                            }
                        }
                        // Update version if content changed
                        if (photo.changed('fileName') || photo.changed('cropData')) {
                            photo.version += 1;
                        }
                        // Update lastModifiedBy if provided
                        if (options.context?.userId) {
                            photo.lastModifiedBy = options.context.userId;
                        }
                    },
                    afterCreate: async (photo) => {
                        try {
                            // Trigger analytics event
                            // await AnalyticsService.trackPhotoUpload(photo);
                        } catch (error) {
                            console.error('Failed to track photo upload analytics:', error);
                        }
                    },
                    beforeDestroy: async (photo) => {
                        try {
                            // Mark for cleanup in storage
                            // await StorageService.markForDeletion(photo.storagePath);
                        } catch (error) {
                            console.error('Failed to mark photo for deletion in storage:', error);
                        }
                    },
                    afterDestroy: async (photo) => {
                        // Log deletion for audit purposes
                        // await AuditLogService.logDeletion(photo.id, photo.userId);
                    },
                },
                getterMethods: {
                    publicUrl() {
                        if (this.visibility === 'private') return null;
                        const cdnUrl = process.env.CDN_URL || 'https://cdn.default.com';
                        return `${cdnUrl}/${this.storagePath}`;
                    },
                    fileSizeFormatted() {
                        const bytes = this.fileSize;
                        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
                        if (bytes === 0) return '0 Bytes';
                        const i = Math.floor(Math.log(bytes) / Math.log(1024));
                        return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${sizes[i]}`;
                    },
                    needsProcessing() {
                        return !this.isProcessed && this.processingStatus === 'pending';
                    },
                },
                classMethods: {
                    findReadyForProcessing(limit = 100) {
                        return this.findAll({
                            where: { processingStatus: 'pending', isProcessed: false },
                            order: [['createdAt', 'ASC']],
                            limit,
                        });
                    },
                    findExpiredPhotos() {
                        return this.findAll({
                            where: { isTemporary: true, expiresAt: { [Op.lt]: new Date() } },
                        });
                    },
                    findProfilePicture(userId) {
                        return this.findOne({
                            where: { userId, isProfilePicture: true, moderationStatus: 'approved' },
                        });
                    },
                    cleanupSoftDeleted(retentionDays = 30) {
                        const threshold = new Date();
                        threshold.setDate(threshold.getDate() - retentionDays);
                        return this.destroy({
                            where: { deletedAt: { [Op.lt]: threshold } },
                            force: true,
                        });
                    },
                },
                instanceMethods: {
                    async setAsProfilePicture() {
                        return sequelize.transaction(async (t) => {
                            await Photo.update(
                                { isProfilePicture: false },
                                { where: { userId: this.userId, isProfilePicture: true }, transaction: t }
                            );
                            this.isProfilePicture = true;
                            await this.save({ transaction: t });
                        });
                    },
                    async generateVariants() {
                        return {
                            thumbnail: `${this.storagePath}_thumb`,
                            small: `${this.storagePath}_small`,
                            medium: `${this.storagePath}_medium`,
                            large: `${this.storagePath}_large`,
                        };
                    },
                },
            }
        );
    }

    static associate(models) {
        Photo.belongsTo(models.User, { foreignKey: 'userId', as: 'user', onDelete: 'CASCADE' });
        Photo.belongsTo(models.User, { foreignKey: 'lastModifiedBy', as: 'lastModifiedByUser', onDelete: 'SET NULL' });
        Photo.belongsTo(models.Photo, { foreignKey: 'parentPhotoId', as: 'parentPhoto', onDelete: 'SET NULL' });
        Photo.hasMany(models.Photo, { foreignKey: 'parentPhotoId', as: 'childPhotos', onDelete: 'SET NULL' });
        Photo.hasMany(models.PhotoHistory, { foreignKey: 'photoId', as: 'history', onDelete: 'CASCADE' });
        Photo.hasOne(models.PhotoSettings, { foreignKey: 'photoId', as: 'settings', onDelete: 'CASCADE' });
    }
}

export default Photo;