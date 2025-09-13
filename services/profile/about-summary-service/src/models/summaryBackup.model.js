import mongoose from 'mongoose';
import { v4 as uuidv4 } from 'uuid';
import validator from 'validator';
import crypto from 'crypto';

// Validation functions
const validateUserId = (userId) => {
    return validator.isUUID(userId) || validator.isMongoId(userId);
};

const validateEmail = (email) => {
    return validator.isEmail(email);
};

const validateURL = (url) => {
    return !url || validator.isURL(url);
};

const validateBackupData = (data) => {
    if (!data || typeof data !== 'object') return false;
    return Object.keys(data).length > 0;
};

const validateChecksumMD5 = (checksum) => {
    return !checksum || /^[a-f0-9]{32}$/i.test(checksum);
};

const validateChecksumSHA256 = (checksum) => {
    return !checksum || /^[a-f0-9]{64}$/i.test(checksum);
};

// Sub-schemas for better organization and performance
const metadataSchema = new mongoose.Schema({
    originalSize: {
        type: Number,
        required: true,
        min: 0,
    },
    compressedSize: {
        type: Number,
        required: true,
        min: 0,
    },
    compressionRatio: {
        type: Number,
        min: 0,
        max: 1,
    },
    encoding: {
        type: String,
        enum: ['utf8', 'base64', 'gzip', 'brotli', 'deflate'],
        default: 'utf8',
    },
    mimeType: {
        type: String,
        default: 'application/json',
        maxlength: 100,
    },
    fileExtension: {
        type: String,
        maxlength: 10,
        default: 'json',
    },
    structure: {
        tables: {
            type: Number,
            default: 1,
            min: 0,
        },
        records: {
            type: Number,
            default: 1,
            min: 0,
        },
        fields: {
            type: Number,
            default: 0,
            min: 0,
        },
        relationships: {
            type: Number,
            default: 0,
            min: 0,
        },
    },
    dataTypes: [{
        field: {
            type: String,
            required: true,
            maxlength: 100,
        },
        type: {
            type: String,
            required: true,
            enum: ['string', 'number', 'boolean', 'date', 'array', 'object', 'null'],
        },
        nullable: {
            type: Boolean,
            default: true,
        },
        indexed: {
            type: Boolean,
            default: false,
        },
    }],
    dependencies: [{
        type: {
            type: String,
            enum: ['summary', 'template', 'user', 'analytics', 'media'],
            required: true,
        },
        id: {
            type: String,
            required: true,
        },
        version: String,
        critical: {
            type: Boolean,
            default: false,
        },
    }],
}, { _id: false });

const integritySchema = new mongoose.Schema({
    checksums: {
        md5: {
            type: String,
            validate: [validateChecksumMD5, 'Invalid MD5 checksum'],
            index: true,
        },
        sha256: {
            type: String,
            validate: [validateChecksumSHA256, 'Invalid SHA256 checksum'],
            index: true,
        },
        crc32: {
            type: String,
            maxlength: 8,
        },
    },
    verification: {
        status: {
            type: String,
            enum: ['pending', 'verified', 'corrupted', 'suspicious', 'failed'],
            default: 'pending',
            index: true,
        },
        verifiedAt: Date,
        verificationMethod: {
            type: String,
            enum: ['automatic', 'manual', 'scheduled', 'on_demand'],
            default: 'automatic',
        },
        verifiedBy: String,
        attempts: {
            type: Number,
            default: 0,
            min: 0,
        },
        lastAttempt: Date,
        errors: [{
            code: String,
            message: String,
            timestamp: {
                type: Date,
                default: Date.now,
            },
            resolved: {
                type: Boolean,
                default: false,
            },
        }],
    },
    redundancy: {
        copies: {
            type: Number,
            default: 1,
            min: 1,
            max: 10,
        },
        locations: [{
            type: {
                type: String,
                enum: ['local', 'cloud', 'remote', 'distributed'],
                required: true,
            },
            provider: {
                type: String,
                enum: ['aws_s3', 'google_cloud', 'azure', 'local_storage', 'custom'],
                required: true,
            },
            region: String,
            path: String,
            url: {
                type: String,
                validate: [validateURL, 'Invalid storage URL'],
            },
            checksum: String,
            verified: {
                type: Boolean,
                default: false,
            },
            lastChecked: Date,
            accessible: {
                type: Boolean,
                default: true,
            },
        }],
        syncStatus: {
            type: String,
            enum: ['synced', 'syncing', 'out_of_sync', 'failed'],
            default: 'synced',
            index: true,
        },
        lastSync: Date,
    },
}, { _id: false });

const recoverySchema = new mongoose.Schema({
    isRecoverable: {
        type: Boolean,
        default: true,
        index: true,
    },
    difficulty: {
        type: String,
        enum: ['easy', 'medium', 'hard', 'expert', 'impossible'],
        default: 'easy',
    },
    estimatedTime: {
        type: Number,
        min: 0, // in seconds
        default: 60,
    },
    requirements: [{
        type: {
            type: String,
            enum: ['password', 'key', 'certificate', 'biometric', 'multi_factor', 'admin_approval'],
            required: true,
        },
        description: String,
        optional: {
            type: Boolean,
            default: false,
        },
        obtained: {
            type: Boolean,
            default: false,
        },
    }],
    attempts: [{
        attemptId: {
            type: String,
            default: () => uuidv4(),
        },
        initiatedBy: String,
        startedAt: {
            type: Date,
            default: Date.now,
        },
        completedAt: Date,
        status: {
            type: String,
            enum: ['in_progress', 'completed', 'failed', 'cancelled', 'partial'],
            default: 'in_progress',
        },
        method: {
            type: String,
            enum: ['full_restore', 'partial_restore', 'data_only', 'structure_only', 'incremental'],
        },
        progress: {
            type: Number,
            min: 0,
            max: 100,
            default: 0,
        },
        dataRestored: {
            type: Number,
            min: 0,
            default: 0,
        },
        errors: [{
            code: String,
            message: String,
            timestamp: {
                type: Date,
                default: Date.now,
            },
            severity: {
                type: String,
                enum: ['low', 'medium', 'high', 'critical'],
            },
            resolved: {
                type: Boolean,
                default: false,
            },
        }],
        logs: [{
            level: {
                type: String,
                enum: ['debug', 'info', 'warn', 'error'],
                required: true,
            },
            message: {
                type: String,
                required: true,
                maxlength: 1000,
            },
            timestamp: {
                type: Date,
                default: Date.now,
            },
            context: mongoose.Schema.Types.Mixed,
        }],
    }],
    policy: {
        maxAttempts: {
            type: Number,
            default: 5,
            min: 1,
            max: 100,
        },
        cooldownPeriod: {
            type: Number,
            default: 300, // 5 minutes in seconds
            min: 0,
        },
        requireApproval: {
            type: Boolean,
            default: false,
        },
        notifyOnFailure: {
            type: Boolean,
            default: true,
        },
        autoRetry: {
            type: Boolean,
            default: false,
        },
        retryInterval: {
            type: Number,
            default: 3600, // 1 hour in seconds
            min: 60,
        },
    },
}, { _id: false });

const securitySchema = new mongoose.Schema({
    encryption: {
        enabled: {
            type: Boolean,
            default: true,
        },
        algorithm: {
            type: String,
            enum: ['AES-256-GCM', 'AES-256-CBC', 'ChaCha20-Poly1305', 'RSA-OAEP'],
            default: 'AES-256-GCM',
        },
        keyId: {
            type: String,
            maxlength: 64,
        },
        ivLength: {
            type: Number,
            min: 12,
            max: 16,
            default: 16,
        },
        authenticated: {
            type: Boolean,
            default: true,
        },
        keyRotation: {
            enabled: {
                type: Boolean,
                default: true,
            },
            frequency: {
                type: Number,
                default: 90, // days
                min: 1,
            },
            lastRotated: Date,
            nextRotation: Date,
        },
    },
    access: {
        level: {
            type: String,
            enum: ['public', 'internal', 'restricted', 'confidential', 'top_secret'],
            default: 'internal',
            index: true,
        },
        permissions: [{
            userId: {
                type: String,
                required: true,
                validate: [validateUserId, 'Invalid user ID'],
            },
            role: {
                type: String,
                enum: ['owner', 'admin', 'editor', 'viewer', 'auditor'],
                required: true,
            },
            actions: [{
                type: String,
                enum: ['read', 'restore', 'delete', 'share', 'audit'],
            }],
            grantedAt: {
                type: Date,
                default: Date.now,
            },
            grantedBy: String,
            expiresAt: Date,
            conditions: [{
                type: {
                    type: String,
                    enum: ['ip_address', 'location', 'time_range', 'device', 'mfa'],
                },
                value: String,
                operator: {
                    type: String,
                    enum: ['equals', 'not_equals', 'contains', 'in_range', 'greater', 'less'],
                },
            }],
        }],
        auditTrail: [{
            userId: String,
            action: {
                type: String,
                enum: ['create', 'read', 'update', 'delete', 'restore', 'share', 'audit', 'verify'],
                required: true,
            },
            ip: String,
            userAgent: String,
            location: {
                country: String,
                city: String,
                coordinates: {
                    lat: Number,
                    lng: Number,
                },
            },
            timestamp: {
                type: Date,
                default: Date.now,
            },
            success: {
                type: Boolean,
                default: true,
            },
            details: mongoose.Schema.Types.Mixed,
            risk_score: {
                type: Number,
                min: 0,
                max: 100,
                default: 0,
            },
        }],
    },
    compliance: {
        classifications: [{
            standard: {
                type: String,
                enum: ['GDPR', 'CCPA', 'HIPAA', 'SOX', 'PCI_DSS', 'ISO_27001', 'NIST', 'custom'],
                required: true,
            },
            level: {
                type: String,
                enum: ['public', 'internal', 'confidential', 'restricted'],
                required: true,
            },
            requirements: [String],
            compliant: {
                type: Boolean,
                default: false,
            },
            lastAssessed: Date,
            assessedBy: String,
            notes: String,
        }],
        dataSubjects: [{
            type: {
                type: String,
                enum: ['eu_citizen', 'ca_resident', 'minor', 'employee', 'customer', 'other'],
            },
            rights: [String],
            notifications: [{
                type: {
                    type: String,
                    enum: ['data_breach', 'access_request', 'deletion_request', 'update_notification', 'consent_update'],
                    required: true,
                },
                status: {
                    type: String,
                    enum: ['pending', 'sent', 'delivered', 'failed', 'acknowledged'],
                    default: 'pending',
                },
                method: {
                    type: String,
                    enum: ['email', 'sms', 'push', 'in_app', 'mail'],
                    default: 'email',
                },
                recipient: {
                    email: {
                        type: String,
                        validate: [validateEmail, 'Invalid email format'],
                    },
                    phone: String,
                    address: String,
                },
                sentAt: Date,
                deliveredAt: Date,
                content: {
                    type: String,
                    maxlength: 5000,
                },
                errors: [{
                    code: String,
                    message: String,
                    timestamp: {
                        type: Date,
                        default: Date.now,
                    },
                    resolved: {
                        type: Boolean,
                        default: false,
                    },
                }],
            }],
        }],
    },
}, { _id: false });

// Main SummaryBackup Schema
const summaryBackupSchema = new mongoose.Schema({
    _id: {
        type: String,
        default: () => uuidv4(),
    },
    userId: {
        type: String,
        required: [true, 'User ID is required'],
        validate: [validateUserId, 'Invalid user ID format'],
        index: true,
    },
    summaryId: {
        type: String,
        required: [true, 'Summary ID is required'],
        validate: [validateUserId, 'Invalid summary ID format'],
        index: true,
    },
    templateId: {
        type: String,
        validate: [validateUserId, 'Invalid template ID format'],
        index: true,
    },
    version: {
        type: String,
        required: [true, 'Version is required'],
        match: /^\d+\.\d+\.\d+$/,
        default: '1.0.0',
    },
    data: {
        type: mongoose.Schema.Types.Mixed,
        required: [true, 'Backup data is required'],
        validate: [validateBackupData, 'Invalid backup data'],
    },
    metadata: metadataSchema,
    integrity: integritySchema,
    recovery: recoverySchema,
    security: securitySchema,
    status: {
        type: String,
        enum: ['active', 'archived', 'corrupted', 'pending', 'failed'],
        default: 'pending',
        index: true,
    },
    backupType: {
        type: String,
        enum: ['full', 'incremental', 'differential', 'snapshot', 'mirror'],
        default: 'full',
        index: true,
    },
    source: {
        type: String,
        enum: ['manual', 'automatic', 'scheduled', 'api', 'event_triggered'],
        default: 'manual',
        index: true,
    },
    environment: {
        type: String,
        enum: ['production', 'staging', 'development', 'testing'],
        default: 'production',
        index: true,
    },
    retention: {
        period: {
            type: Number,
            default: 365, // days
            min: 1,
        },
        expiresAt: {
            type: Date,
            index: true,
        },
        autoDelete: {
            type: Boolean,
            default: true,
        },
    },
    analytics: {
        backupCount: {
            type: Number,
            default: 1,
            min: 1,
        },
        restoreCount: {
            type: Number,
            default: 0,
            min: 0,
        },
        verificationCount: {
            type: Number,
            default: 0,
            min: 0,
        },
        failureCount: {
            type: Number,
            default: 0,
            min: 0,
        },
        lastBackup: {
            type: Date,
            default: Date.now,
        },
        lastRestored: Date,
        lastVerified: Date,
        averageBackupTime: {
            type: Number,
            default: 0,
            min: 0,
        },
        averageRestoreTime: {
            type: Number,
            default: 0,
            min: 0,
        },
    },
}, {
    timestamps: true,
    collection: 'summaryBackups',
    versionKey: false,
    minimize: false,
    strict: true,
});

// Compound Indexes for Scale (optimized for 1M+ users)
summaryBackupSchema.index({ userId: 1, summaryId: 1, createdAt: -1 });
summaryBackupSchema.index({ templateId: 1, status: 1, createdAt: -1 });
summaryBackupSchema.index({ status: 1, backupType: 1, environment: 1 });
summaryBackupSchema.index({ 'integrity.verification.status': 1, createdAt: -1 });
summaryBackupSchema.index({ 'security.access.level': 1, userId: 1 });
summaryBackupSchema.index({ 'retention.expiresAt': 1 }, { partialFilterExpression: { 'retention.autoDelete': true } });

// Partial indexes for better performance
summaryBackupSchema.index({ 'integrity.redundancy.syncStatus': 1 }, { partialFilterExpression: { 'integrity.redundancy.syncStatus': { $in: ['syncing', 'out_of_sync', 'failed'] } } });
summaryBackupSchema.index({ 'recovery.isRecoverable': 1 }, { partialFilterExpression: { 'recovery.isRecoverable': true } });
summaryBackupSchema.index({ 'security.compliance.classifications.standard': 1 }, { partialFilterExpression: { 'security.compliance.classifications.compliant': false } });

// TTL index for auto-deletion of expired backups
summaryBackupSchema.index({ 'retention.expiresAt': 1 }, {
    expireAfterSeconds: 0,
    partialFilterExpression: { 'retention.autoDelete': true }
});

// Virtual properties
summaryBackupSchema.virtual('backupSizeMB').get(function () {
    return this.metadata.compressedSize ? (this.metadata.compressedSize / (1024 * 1024)).toFixed(2) : 0;
});

summaryBackupSchema.virtual('isExpired').get(function () {
    return this.retention.expiresAt && new Date() > this.retention.expiresAt;
});

summaryBackupSchema.virtual('complianceStatus').get(function () {
    const nonCompliant = this.security.compliance.classifications.some(c => !c.compliant);
    return nonCompliant ? 'non_compliant' : 'compliant';
});

summaryBackupSchema.virtual('criticalDependencies').get(function () {
    return this.metadata.dependencies.filter(d => d.critical).length;
});

// Instance Methods
summaryBackupSchema.methods.verifyIntegrity = async function (data) {
    const currentData = JSON.stringify(this.data);
    const currentMD5 = crypto.createHash('md5').update(currentData).digest('hex');
    const currentSHA256 = crypto.createHash('sha256').update(currentData).digest('hex');

    const providedMD5 = this.integrity.checksums.md5;
    const providedSHA256 = this.integrity.checksums.sha256;

    const isValid = providedMD5 === currentMD5 && providedSHA256 === currentSHA256;

    this.integrity.verification.status = isValid ? 'verified' : 'corrupted';
    this.integrity.verification.verifiedAt = new Date();
    this.integrity.verification.attempts += 1;
    this.integrity.verification.lastAttempt = new Date();
    this.analytics.verificationCount += 1;
    this.analytics.lastVerified = new Date();

    if (!isValid) {
        this.integrity.verification.errors.push({
            code: 'CHECKSUM_MISMATCH',
            message: `Checksum verification failed. MD5: ${providedMD5} vs ${currentMD5}, SHA256: ${providedSHA256} vs ${currentSHA256}`,
            timestamp: new Date(),
            resolved: false,
        });
        this.status = 'corrupted';
        this.analytics.failureCount += 1;
    } else {
        this.status = 'active';
    }

    return this.save();
};

summaryBackupSchema.methods.initiateRecovery = async function (userId, method = 'full_restore', context = {}) {
    if (!this.recovery.isRecoverable) {
        throw new Error('Backup is not recoverable');
    }

    const required = this.recovery.requirements.filter(r => !r.optional && !r.obtained);
    if (required.length > 0) {
        throw new Error(`Missing required recovery requirements: ${required.map(r => r.type).join(', ')}`);
    }

    if (this.recovery.attempts.length >= this.recovery.policy.maxAttempts) {
        throw new Error('Maximum recovery attempts exceeded');
    }

    const attempt = {
        attemptId: uuidv4(),
        initiatedBy: userId,
        startedAt: new Date(),
        status: 'in_progress',
        method,
        progress: 0,
        dataRestored: 0,
        errors: [],
        logs: [{
            level: 'info',
            message: `Recovery initiated by ${userId} using ${method}`,
            timestamp: new Date(),
            context,
        }],
    };

    this.recovery.attempts.push(attempt);
    this.security.access.auditTrail.push({
        userId,
        action: 'restore',
        timestamp: new Date(),
        success: true,
        details: { method, attemptId: attempt.attemptId },
        risk_score: method === 'full_restore' ? 50 : 30,
    });

    return this.save();
};

summaryBackupSchema.methods.completeRecovery = async function (attemptId, dataRestored, success = true, errors = []) {
    const attempt = this.recovery.attempts.find(a => a.attemptId === attemptId);
    if (!attempt) {
        throw new Error('Recovery attempt not found');
    }

    attempt.completedAt = new Date();
    attempt.status = success ? 'completed' : 'failed';
    attempt.dataRestored = dataRestored;
    attempt.progress = success ? 100 : attempt.progress;

    if (errors.length > 0) {
        attempt.errors.push(...errors.map(e => ({
            code: e.code || 'UNKNOWN',
            message: e.message,
            timestamp: new Date(),
            severity: e.severity || 'medium',
            resolved: false,
        })));
    }

    attempt.logs.push({
        level: success ? 'info' : 'error',
        message: `Recovery ${success ? 'completed' : 'failed'} with ${dataRestored} bytes restored`,
        timestamp: new Date(),
        context: { errors },
    });

    this.analytics.restoreCount += 1;
    this.analytics.lastRestored = new Date();
    if (!success) {
        this.analytics.failureCount += 1;
    }

    return this.save();
};

summaryBackupSchema.methods.updateCompression = async function (originalSize, compressedSize) {
    this.metadata.originalSize = originalSize;
    this.metadata.compressedSize = compressedSize;
    this.metadata.compressionRatio = originalSize > 0 ? compressedSize / originalSize : 0;
    return this.save();
};

summaryBackupSchema.methods.sendComplianceNotification = async function (type, recipient, content) {
    const notification = {
        type,
        status: 'pending',
        method: recipient.email ? 'email' : recipient.phone ? 'sms' : 'in_app',
        recipient,
        content,
        sentAt: new Date(),
        errors: [],
    };

    const dataSubject = this.security.compliance.dataSubjects.find(ds => ds.type === 'customer') ||
        this.security.compliance.dataSubjects[0] || { notifications: [] };
    dataSubject.notifications.push(notification);

    this.security.access.auditTrail.push({
        userId: 'system',
        action: 'notify',
        timestamp: new Date(),
        success: true,
        details: { notificationType: type, recipient },
        risk_score: 10,
    });

    return this.save();
};

// Static Methods for Scalability
summaryBackupSchema.statics.findByUser = async function (userId, options = {}) {
    const { status = 'active', limit = 20, skip = 0, sort = { createdAt: -1 } } = options;
    return this.find({
        userId,
        status,
        'security.compliance.classifications.compliant': true
    })
        .select('summaryId templateId version status backupType createdAt metadata.compressedSize')
        .sort(sort)
        .skip(skip)
        .limit(limit)
        .lean()
        .cache(3600); // Cache for 1 hour
};

summaryBackupSchema.statics.findBySummary = async function (summaryId, options = {}) {
    const { status = 'active', limit = 20, skip = 0, sort = { createdAt: -1 } } = options;
    return this.find({
        summaryId,
        status,
        'security.compliance.classifications.compliant': true
    })
        .select('userId templateId version status backupType createdAt metadata.compressedSize')
        .sort(sort)
        .skip(skip)
        .limit(limit)
        .lean()
        .cache(3600); // Cache for 1 hour
};

summaryBackupSchema.statics.getBackupAnalytics = async function (userId, timeRange = '30d') {
    const date = new Date();
    let startDate;

    switch (timeRange) {
        case '7d':
            startDate = new Date(date.setDate(date.getDate() - 7));
            break;
        case '30d':
            startDate = new Date(date.setDate(date.getDate() - 30));
            break;
        case '90d':
            startDate = new Date(date.setDate(date.getDate() - 90));
            break;
        default:
            startDate = new Date(date.setDate(date.getDate() - 30));
    }

    return this.aggregate([
        { $match: { userId, createdAt: { $gte: startDate }, 'security.compliance.classifications.compliant': true } },
        {
            $group: {
                _id: '$backupType',
                totalBackups: { $sum: 1 },
                totalSize: { $sum: '$metadata.compressedSize' },
                averageBackupTime: { $avg: '$analytics.averageBackupTime' },
                successRate: {
                    $avg: { $cond: [{ $eq: ['$status', 'active'] }, 1, 0] }
                },
                restoreCount: { $sum: '$analytics.restoreCount' },
                verificationCount: { $sum: '$analytics.verificationCount' },
                failureCount: { $sum: '$analytics.failureCount' },
            }
        },
        { $sort: { totalBackups: -1 } }
    ]).cache(1800); // Cache for 30 minutes
};

summaryBackupSchema.statics.bulkVerifyBackups = async function (backupIds) {
    const results = await Promise.all(backupIds.map(async id => {
        const backup = await this.findById(id);
        if (!backup) return { id, status: 'not_found' };
        await backup.verifyIntegrity();
        return { id, status: backup.integrity.verification.status };
    }));
    return results;
};

summaryBackupSchema.statics.cleanupExpired = async function () {
    const now = new Date();
    return this.deleteMany({
        'retention.expiresAt': { $lte: now },
        'retention.autoDelete': true,
        status: { $ne: 'corrupted' }
    });
};

summaryBackupSchema.statics.getNonCompliantBackups = async function (options = {}) {
    const { limit = 20, skip = 0, standard } = options;
    const query = { 'security.compliance.classifications.compliant': false };
    if (standard) query['security.compliance.classifications.standard'] = standard;

    return this.find(query)
        .select('userId summaryId templateId status security.compliance.classifications')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean()
        .cache(3600); // Cache for 1 hour
};

summaryBackupSchema.statics.rotateEncryptionKeys = async function () {
    const now = new Date();
    const backups = await this.find({
        'security.encryption.keyRotation.enabled': true,
        'security.encryption.keyRotation.nextRotation': { $lte: now }
    });

    const results = await Promise.all(backups.map(async backup => {
        backup.security.encryption.keyId = uuidv4();
        backup.security.encryption.lastRotated = now;
        backup.security.encryption.nextRotation = new Date(now.getTime() + (backup.security.encryption.keyRotation.frequency * 24 * 60 * 60 * 1000));
        backup.security.access.auditTrail.push({
            userId: 'system',
            action: 'key_rotation',
            timestamp: new Date(),
            success: true,
            details: { newKeyId: backup.security.encryption.keyId },
            risk_score: 20,
        });
        await backup.save();
        return { id: backup._id, status: 'rotated' };
    }));

    return results;
};

summaryBackupSchema.statics.getBackupHealth = async function (options = {}) {
    const { userId, status, limit = 20, skip = 0 } = options;
    const query = { 'security.compliance.classifications.compliant': true };
    if (userId) query.userId = userId;
    if (status) query.status = status;

    return this.find(query)
        .select('summaryId templateId status integrity.verification.status metadata.compressedSize analytics')
        .sort({ 'analytics.failureCount': -1, createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean()
        .cache(3600); // Cache for 1 hour
};

summaryBackupSchema.statics.updateBackupStatus = async function (backupIds, status) {
    return this.updateMany(
        { _id: { $in: backupIds }, 'security.compliance.classifications.compliant': true },
        {
            $set: {
                status,
                updatedAt: new Date(),
                'security.access.auditTrail': {
                    $push: {
                        userId: 'system',
                        action: 'status_update',
                        timestamp: new Date(),
                        success: true,
                        details: { newStatus: status },
                        risk_score: 15,
                    }
                }
            }
        },
        { multi: true }
    );
};

// Pre-save middleware for checksum generation and metadata update
summaryBackupSchema.pre('save', function (next) {
    const dataStr = JSON.stringify(this.data);
    this.integrity.checksums.md5 = crypto.createHash('md5').update(dataStr).digest('hex');
    this.integrity.checksums.sha256 = crypto.createHash('sha256').update(dataStr).digest('hex');

    if (this.metadata.originalSize > 0) {
        this.metadata.compressionRatio = this.metadata.compressedSize / this.metadata.originalSize;
    }

    if (!this.retention.expiresAt) {
        const expires = new Date();
        expires.setDate(expires.getDate() + this.retention.period);
        this.retention.expiresAt = expires;
    }

    this.security.access.auditTrail.push({
        userId: this.userId,
        action: this.isNew ? 'create' : 'update',
        timestamp: new Date(),
        success: true,
        details: { backupType: this.backupType, environment: this.environment },
        risk_score: this.security.encryption.enabled ? 10 : 30,
    });

    next();
});

// Pre-update middleware for audit trail
summaryBackupSchema.pre(['updateOne', 'updateMany', 'findOneAndUpdate'], function (next) {
    this.set({
        'security.access.auditTrail': {
            $push: {
                userId: this.getOptions().userId || 'system',
                action: this.getOptions().action || 'update',
                ip: this.getOptions().ip,
                userAgent: this.getOptions().userAgent,
                timestamp: new Date(),
                success: true,
                risk_score: 20,
            }
        }
    });
    next();
});

// Model
const SummaryBackup = mongoose.model('SummaryBackup', summaryBackupSchema);

export default SummaryBackup;