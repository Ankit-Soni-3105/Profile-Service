import { Model, DataTypes, Op } from 'sequelize';
import { v4 as uuidv4 } from 'uuid'; // Added for UUID generation

class PhotoHistory extends Model {
    static init(sequelize) {
        return super.init(
            {
                id: {
                    type: DataTypes.UUID,
                    defaultValue: DataTypes.UUIDV4,
                    primaryKey: true,
                    comment: 'Unique identifier for history entry',
                },
                photoId: {
                    type: DataTypes.UUID,
                    allowNull: false,
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
                    comment: 'Reference to user who performed action',
                },
                action: {
                    type: DataTypes.ENUM(
                        'upload',
                        'crop',
                        'resize',
                        'compress',
                        'optimize',
                        'background_remove',
                        'filter_apply',
                        'rotate',
                        'flip',
                        'quality_adjust',
                        'format_convert',
                        'visibility_change',
                        'profile_set',
                        'profile_unset',
                        'download',
                        'view',
                        'moderate',
                        'flag',
                        'restore',
                        'delete',
                        'gdpr_request'
                    ),
                    allowNull: false,
                    comment: 'Type of action performed',
                },
                actionDescription: {
                    type: DataTypes.STRING(500),
                    allowNull: true,
                    comment: 'Human-readable description of the action',
                },
                actionData: {
                    type: DataTypes.JSONB,
                    allowNull: true,
                    defaultValue: {},
                    comment: 'Detailed data about the action performed',
                    validate: {
                        isValidActionData(value) {
                            if (value && typeof value !== 'object') {
                                throw new Error('Action data must be a valid JSON object');
                            }
                        },
                    },
                },
                beforeState: {
                    type: DataTypes.JSONB,
                    allowNull: true,
                    comment: 'Photo state before the action',
                },
                afterState: {
                    type: DataTypes.JSONB,
                    allowNull: true,
                    comment: 'Photo state after the action',
                },
                source: {
                    type: DataTypes.ENUM('web', 'mobile_app', 'api', 'admin_panel', 'system', 'cron_job'),
                    allowNull: false,
                    defaultValue: 'web',
                    comment: 'Source of the action',
                },
                sourceVersion: {
                    type: DataTypes.STRING(50),
                    allowNull: true,
                    comment: 'Version of the source application',
                },
                ipAddress: {
                    type: DataTypes.INET,
                    allowNull: true,
                    comment: 'IP address from where action was performed',
                },
                userAgent: {
                    type: DataTypes.TEXT,
                    allowNull: true,
                    comment: 'User agent string',
                },
                sessionId: {
                    type: DataTypes.STRING(255),
                    allowNull: true,
                    comment: 'Session identifier',
                },
                requestId: {
                    type: DataTypes.UUID,
                    allowNull: true,
                    comment: 'Unique request identifier for tracing',
                },
                processingTime: {
                    type: DataTypes.INTEGER,
                    allowNull: true,
                    validate: { min: 0 },
                    comment: 'Processing time in milliseconds',
                },
                success: {
                    type: DataTypes.BOOLEAN,
                    allowNull: false,
                    defaultValue: true,
                    comment: 'Whether the action was successful',
                },
                errorMessage: {
                    type: DataTypes.TEXT,
                    allowNull: true,
                    comment: 'Error message if action failed',
                },
                errorCode: {
                    type: DataTypes.STRING(50),
                    allowNull: true,
                    comment: 'Error code for debugging',
                },
                fileSizeBefore: {
                    type: DataTypes.BIGINT,
                    allowNull: true,
                    validate: { min: 0 },
                    comment: 'File size before action in bytes',
                },
                fileSizeAfter: {
                    type: DataTypes.BIGINT,
                    allowNull: true,
                    validate: { min: 0 },
                    comment: 'File size after action in bytes',
                },
                dimensionsBefore: {
                    type: DataTypes.JSONB,
                    allowNull: true,
                    comment: 'Image dimensions before action {width, height}',
                    validate: {
                        isValidDimensions(value) {
                            if (value && (!value.width || !value.height)) {
                                throw new Error('Dimensions must include width and height');
                            }
                        },
                    },
                },
                dimensionsAfter: {
                    type: DataTypes.JSONB,
                    allowNull: true,
                    comment: 'Image dimensions after action {width, height}',
                    validate: {
                        isValidDimensions(value) {
                            if (value && (!value.width || !value.height)) {
                                throw new Error('Dimensions must include width and height');
                            }
                        },
                    },
                },
                qualityBefore: {
                    type: DataTypes.DECIMAL(3, 2),
                    allowNull: true,
                    validate: { min: 0, max: 10 },
                    comment: 'Quality score before action',
                },
                qualityAfter: {
                    type: DataTypes.DECIMAL(3, 2),
                    allowNull: true,
                    validate: { min: 0, max: 10 },
                    comment: 'Quality score after action',
                },
                location: {
                    type: DataTypes.JSONB,
                    allowNull: true,
                    comment: 'Geographic location data {country, region, city}',
                    validate: {
                        isValidLocation(value) {
                            if (value) {
                                const required = ['country'];
                                for (const field of required) {
                                    if (!value[field]) {
                                        throw new Error(`Location data missing required field: ${field}`);
                                    }
                                }
                            }
                        },
                    },
                },
                device: {
                    type: DataTypes.JSONB,
                    allowNull: true,
                    comment: 'Device information {type, os, browser}',
                    validate: {
                        isValidDevice(value) {
                            if (value) {
                                const required = ['type', 'os'];
                                for (const field of required) {
                                    if (!value[field]) {
                                        throw new Error(`Device data missing required field: ${field}`);
                                    }
                                }
                            }
                        },
                    },
                },
                bandwidth: {
                    type: DataTypes.BIGINT,
                    allowNull: true,
                    validate: { min: 0 },
                    comment: 'Bandwidth used in bytes',
                },
                cdnHit: {
                    type: DataTypes.BOOLEAN,
                    allowNull: true,
                    comment: 'Whether request was served from CDN',
                },
                retentionPeriod: {
                    type: DataTypes.INTEGER,
                    allowNull: true,
                    validate: { min: 1, max: 3650 }, // Max 10 years
                    comment: 'How long to retain this history entry (days)',
                },
                isAuditable: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: true,
                    allowNull: false,
                    comment: 'Whether this action should be audited',
                },
                auditLevel: {
                    type: DataTypes.ENUM('low', 'medium', 'high', 'critical'),
                    defaultValue: 'low',
                    allowNull: false,
                    comment: 'Audit importance level',
                },
                gdprRelevant: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: false,
                    allowNull: false,
                    comment: 'Whether action is relevant for GDPR compliance',
                },
                personalDataInvolved: {
                    type: DataTypes.BOOLEAN,
                    defaultValue: false,
                    allowNull: false,
                    comment: 'Whether personal data was involved in action',
                },
                batchId: {
                    type: DataTypes.UUID,
                    allowNull: true,
                    comment: 'Batch identifier for bulk operations',
                },
                batchSize: {
                    type: DataTypes.INTEGER,
                    allowNull: true,
                    validate: { min: 1 },
                    comment: 'Size of the batch if part of bulk operation',
                },
                actionTimestamp: {
                    type: DataTypes.DATE,
                    allowNull: false,
                    defaultValue: DataTypes.NOW,
                    comment: 'When the action was performed',
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
                    comment: 'When the history entry was last updated',
                },
            },
            {
                sequelize,
                modelName: 'PhotoHistory',
                tableName: 'photo_history',
                timestamps: true, // Enable timestamps for createdAt/updatedAt
                underscored: true,
                indexes: [
                    { fields: ['photo_id'], name: 'idx_photo_history_photo_id' },
                    { fields: ['user_id'], name: 'idx_photo_history_user_id' },
                    { fields: ['photo_id', 'action_timestamp'], name: 'idx_photo_history_photo_timeline' },
                    { fields: ['user_id', 'action_timestamp'], name: 'idx_photo_history_user_timeline' },
                    { fields: ['action'], name: 'idx_photo_history_action' },
                    { fields: ['action', 'action_timestamp'], name: 'idx_photo_history_action_time' },
                    { fields: ['success'], name: 'idx_photo_history_success' },
                    { fields: ['success', 'action_timestamp'], name: 'idx_photo_history_error_tracking' },
                    { fields: ['source'], name: 'idx_photo_history_source' },
                    { fields: ['request_id'], name: 'idx_photo_history_request_id' },
                    { fields: ['session_id'], name: 'idx_photo_history_session' },
                    { fields: ['batch_id'], name: 'idx_photo_history_batch' },
                    { fields: ['batch_id', 'action_timestamp'], name: 'idx_photo_history_batch_timeline' }, // Added for batch queries
                    { fields: ['audit_level'], name: 'idx_photo_history_audit_level' },
                    { fields: ['gdpr_relevant'], name: 'idx_photo_history_gdpr' },
                    { fields: ['is_auditable', 'audit_level'], name: 'idx_photo_history_audit_filter' },
                    { fields: ['action_timestamp'], name: 'idx_photo_history_timestamp' },
                    { fields: ['cdn_hit'], name: 'idx_photo_history_cdn' },
                    { fields: ['processing_time'], name: 'idx_photo_history_performance' },
                    { fields: ['retention_period', 'created_at'], name: 'idx_photo_history_cleanup' },
                    {
                        fields: ['user_id', 'action', 'success', 'action_timestamp'],
                        name: 'idx_photo_history_user_analytics',
                    },
                    {
                        fields: ['photo_id', 'action', 'success'],
                        name: 'idx_photo_history_photo_analytics',
                    },
                    {
                        fields: ['action_timestamp', 'source', 'action'],
                        name: 'idx_photo_history_source_analytics',
                    },
                ],
                validate: {
                    errorFieldsConsistency() {
                        if (!this.success && !this.errorMessage) {
                            throw new Error('Error message is required when success is false');
                        }
                    },
                    fileSizeConsistency() {
                        if (this.fileSizeBefore !== null && this.fileSizeAfter !== null) {
                            if (this.fileSizeBefore < 0 || this.fileSizeAfter < 0) {
                                throw new Error('File sizes cannot be negative');
                            }
                        }
                    },
                },
                hooks: {
                    beforeCreate: async (history) => {
                        if (!history.actionTimestamp) {
                            history.actionTimestamp = new Date();
                        }
                        if (!history.retentionPeriod) {
                            const retentionPeriods = {
                                low: 30,
                                medium: 90,
                                high: 365,
                                critical: 2555,
                            };
                            history.retentionPeriod = retentionPeriods[history.auditLevel];
                        }
                        const personalDataActions = [
                            'upload',
                            'view',
                            'download',
                            'profile_set',
                            'moderate',
                            'gdpr_request',
                        ];
                        if (personalDataActions.includes(history.action)) {
                            history.personalDataInvolved = true;
                            history.gdprRelevant = true;
                        }
                        if (!history.actionDescription) {
                            history.actionDescription = history.generateActionDescription();
                        }
                        // Validate actionData for specific actions
                        if (history.action === 'crop' && history.actionData) {
                            const required = ['x', 'y', 'width', 'height'];
                            for (const field of required) {
                                if (typeof history.actionData[field] !== 'number') {
                                    throw new Error(`Crop action data missing required field: ${field}`);
                                }
                            }
                        }
                    },
                    afterCreate: async (history) => {
                        try {
                            if (history.auditLevel === 'high' || history.auditLevel === 'critical') {
                                // await AnalyticsService.trackAuditableAction(history);
                            }
                        } catch (error) {
                            console.error('Failed to track auditable action:', error);
                        }
                    },
                },
                getterMethods: {
                    fileSizeChange() {
                        if (this.fileSizeBefore !== null && this.fileSizeAfter !== null) {
                            return this.fileSizeAfter - this.fileSizeBefore;
                        }
                        return null;
                    },
                    qualityImprovement() {
                        if (this.qualityBefore !== null && this.qualityAfter !== null) {
                            return this.qualityAfter - this.qualityBefore;
                        }
                        return null;
                    },
                    isDestructive() {
                        const destructiveActions = ['delete', 'crop', 'compress'];
                        return destructiveActions.includes(this.action);
                    },
                    processingTimeFormatted() {
                        if (!this.processingTime) return null;
                        if (this.processingTime < 1000) return `${this.processingTime} ms`;
                        return `${(this.processingTime / 1000).toFixed(2)} s`;
                    },
                },
                instanceMethods: {
                    generateActionDescription() {
                        const descriptions = {
                            upload: 'Photo uploaded to the system',
                            crop: 'Photo cropped to new dimensions',
                            resize: 'Photo resized',
                            compress: 'Photo compressed to reduce file size',
                            optimize: 'Photo optimized for better quality',
                            background_remove: 'Background removed from photo',
                            filter_apply: 'Filter applied to photo',
                            rotate: 'Photo rotated',
                            flip: 'Photo flipped',
                            quality_adjust: 'Photo quality adjusted',
                            format_convert: 'Photo format converted',
                            visibility_change: 'Photo visibility settings changed',
                            profile_set: 'Set as profile picture',
                            profile_unset: 'Removed as profile picture',
                            download: 'Photo downloaded',
                            view: 'Photo viewed',
                            moderate: 'Photo moderated',
                            flag: 'Photo flagged for review',
                            restore: 'Photo restored from trash',
                            delete: 'Photo deleted',
                            gdpr_request: 'GDPR data request processed',
                        };
                        return descriptions[this.action] || `Unknown action: ${this.action}`;
                    },
                    shouldExpire() {
                        if (!this.retentionPeriod) return false;
                        const expiryDate = new Date(this.createdAt);
                        expiryDate.setDate(expiryDate.getDate() + this.retentionPeriod);
                        return new Date() > expiryDate;
                    },
                },
                classMethods: {
                    async getPhotoTimeline(photoId, options = {}) {
                        return sequelize.transaction(async (t) => {
                            const { limit = 50, offset = 0, actions = null, startDate = null, endDate = null } = options;
                            const where = { photoId };
                            if (actions && actions.length > 0) {
                                where.action = { [Op.in]: actions };
                            }
                            if (startDate) {
                                where.actionTimestamp = { [Op.gte]: startDate };
                            }
                            if (endDate) {
                                where.actionTimestamp = { ...where.actionTimestamp, [Op.lte]: endDate };
                            }
                            return this.findAll({
                                where,
                                order: [['actionTimestamp', 'DESC']],
                                limit,
                                offset,
                                include: [{ model: sequelize.models.User, as: 'user', attributes: ['id', 'username', 'email'] }],
                                transaction: t,
                            });
                        });
                    },
                    async getUserActivity(userId, options = {}) {
                        return sequelize.transaction(async (t) => {
                            const { limit = 100, offset = 0, actions = null, startDate = null, endDate = null } = options;
                            const where = { userId };
                            if (actions && actions.length > 0) {
                                where.action = { [Op.in]: actions };
                            }
                            if (startDate || endDate) {
                                where.actionTimestamp = {};
                                if (startDate) where.actionTimestamp[Op.gte] = startDate;
                                if (endDate) where.actionTimestamp[Op.lte] = endDate;
                            }
                            return this.findAll({
                                where,
                                order: [['actionTimestamp', 'DESC']],
                                limit,
                                offset,
                                include: [{ model: sequelize.models.Photo, as: 'photo', attributes: ['id', 'fileName', 'visibility'] }],
                                transaction: t,
                            });
                        });
                    },
                    async getAnalytics(options = {}) {
                        return sequelize.transaction(async (t) => {
                            const { groupBy = 'action', startDate = null, endDate = null, actions = null } = options;
                            const where = {};
                            if (actions && actions.length > 0) {
                                where.action = { [Op.in]: actions };
                            }
                            if (startDate || endDate) {
                                where.actionTimestamp = {};
                                if (startDate) where.actionTimestamp[Op.gte] = startDate;
                                if (endDate) where.actionTimestamp[Op.lte] = endDate;
                            }
                            return this.findAll({
                                where,
                                attributes: [
                                    groupBy,
                                    [sequelize.fn('COUNT', sequelize.col('id')), 'count'],
                                    [sequelize.fn('AVG', sequelize.col('processing_time')), 'avgProcessingTime'],
                                    [sequelize.fn('SUM', sequelize.col('bandwidth')), 'totalBandwidth'],
                                ],
                                group: [groupBy],
                                order: [[sequelize.fn('COUNT', sequelize.col('id')), 'DESC']],
                                transaction: t,
                            });
                        });
                    },
                    async findExpiredEntries() {
                        return sequelize.transaction(async (t) => {
                            return this.findAll({
                                where: {
                                    retentionPeriod: { [Op.ne]: null },
                                    createdAt: {
                                        [Op.lt]: sequelize.literal(`NOW() - INTERVAL '1 day' * retention_period`)
                                    },
                                },
                                transaction: t,
                            });
                        });
                    },
                    async bulkLog(entries) {
                        return sequelize.transaction(async (t) => {
                            const timestamp = new Date();
                            const processedEntries = entries.map((entry) => ({
                                ...entry,
                                id: entry.id || uuidv4(),
                                actionTimestamp: entry.actionTimestamp || timestamp,
                                createdAt: timestamp,
                            }));
                            return this.bulkCreate(processedEntries, {
                                validate: true,
                                returning: true,
                                transaction: t,
                            });
                        });
                    },
                },
            }
        );
    }

    static associate(models) {
        PhotoHistory.belongsTo(models.Photo, { foreignKey: 'photoId', as: 'photo', onDelete: 'CASCADE' });
        PhotoHistory.belongsTo(models.User, { foreignKey: 'userId', as: 'user', onDelete: 'CASCADE' });
    }
}

export default PhotoHistory;