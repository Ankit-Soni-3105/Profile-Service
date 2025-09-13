import mongoose, { Schema } from 'mongoose';
import aggregatePaginate from 'mongoose-aggregate-paginate-v2';
import mongooseAlgolia from 'mongoose-algolia';
import sanitizeHtml from 'sanitize-html';
import redis from 'redis';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';

// Initialize Redis client
const redisClient = redis.createClient({ url: process.env.REDIS_URL || 'redis://localhost:6379' });
redisClient.connect().catch(err => console.error('Redis connection error:', err));

// Validation Functions
const validateURL = (value) => !value || /^https?:\/\/[^\s$.?#].[^\s]*$/.test(value);
const validateString = (value) => !value || (typeof value === 'string' && value.trim().length > 0);
const validateIP = (value) => !value || /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(value);

// Sub-Schemas
const fileSchema = new Schema({
    originalName: { type: String, required: [true, 'Original filename is required'], trim: true, maxlength: 255, validate: { validator: validateString, message: 'Invalid filename' } },
    systemName: { type: String, required: [true, 'System filename is required'], unique: true, index: true },
    extension: { type: String, required: [true, 'Extension is required'], lowercase: true, maxlength: 10 },
    mimeType: { type: String, required: [true, 'MIME type is required'], index: true },
    size: { type: Number, required: [true, 'File size is required'], min: 1, max: 100 * 1024 * 1024, index: true },
    dimensions: {
        width: { type: Number, min: 1 },
        height: { type: Number, min: 1 },
        aspectRatio: { type: Number },
        resolution: { type: String, maxlength: 20 }
    },
    duration: { type: Number, min: 0 },
    technical: {
        colorSpace: { type: String, maxlength: 50 },
        bitRate: { type: Number, min: 0 },
        frameRate: { type: Number, min: 0 },
        codec: { type: String, maxlength: 50 },
        channels: { type: Number, min: 1 },
        sampleRate: { type: Number, min: 0 }
    },
    hash: {
        md5: { type: String, required: [true, 'MD5 hash is required'], index: true },
        sha256: { type: String, required: [true, 'SHA256 hash is required'] }
    }
}, { _id: false });

const storageSchema = new Schema({
    primary: {
        provider: { type: String, enum: ['aws-s3', 'cloudinary', 'azure-blob', 'gcp-storage'], required: [true, 'Storage provider is required'] },
        bucket: { type: String, required: [true, 'Bucket is required'], maxlength: 100 },
        key: { type: String, required: [true, 'Storage key is required'], unique: true },
        region: { type: String, required: [true, 'Region is required'], maxlength: 50 },
        url: { type: String, required: [true, 'Primary URL is required'], validate: { validator: validateURL, message: 'Invalid primary URL' } },
        publicId: { type: String, maxlength: 100 }
    },
    backup: {
        provider: { type: String, enum: ['aws-s3', 'cloudinary', 'azure-blob', 'gcp-storage'] },
        bucket: { type: String, maxlength: 100 },
        key: { type: String },
        url: { type: String, validate: { validator: validateURL, message: 'Invalid backup URL' } }
    },
    cdn: {
        provider: { type: String, enum: ['cloudfront', 'cloudinary', 'fastly', 'cloudflare'], required: [true, 'CDN provider is required'] },
        distributionId: { type: String, maxlength: 100 },
        baseUrl: { type: String, required: [true, 'CDN base URL is required'], validate: { validator: validateURL, message: 'Invalid CDN URL' } },
        cachedUrls: {
            original: { type: String, validate: { validator: validateURL, message: 'Invalid original URL' } },
            thumbnail: { type: String, validate: { validator: validateURL, message: 'Invalid thumbnail URL' } },
            small: { type: String, validate: { validator: validateURL, message: 'Invalid small URL' } },
            medium: { type: String, validate: { validator: validateURL, message: 'Invalid medium URL' } },
            large: { type: String, validate: { validator: validateURL, message: 'Invalid large URL' } },
            webp: { type: String, validate: { validator: validateURL, message: 'Invalid WebP URL' } },
            avif: { type: String, validate: { validator: validateURL, message: 'Invalid AVIF URL' } }
        },
        cacheStatus: { type: String, enum: ['pending', 'cached', 'failed', 'expired'], default: 'pending', index: true },
        lastCacheUpdate: { type: Date, default: Date.now, index: true }
    }
}, { _id: false });

const processingSchema = new Schema({
    status: { type: String, enum: ['pending', 'processing', 'completed', 'failed', 'skipped'], default: 'pending', index: true },
    startedAt: { type: Date },
    completedAt: { type: Date },
    failureReason: { type: String, maxlength: 500 },
    retryCount: { type: Number, default: 0, max: 3 },
    variants: [{
        type: { type: String, enum: ['thumbnail', 'small', 'medium', 'large', 'webp', 'avif', 'compressed'], required: true },
        dimensions: { width: { type: Number }, height: { type: Number } },
        size: { type: Number, min: 0 },
        url: { type: String, validate: { validator: validateURL, message: 'Invalid variant URL' } },
        quality: { type: Number, min: 0, max: 100 },
        format: { type: String, maxlength: 10 },
        processingTime: { type: Number, min: 0 }
    }],
    aiAnalysis: {
        labels: [{ name: { type: String, maxlength: 100 }, confidence: { type: Number, min: 0, max: 1 }, category: { type: String, maxlength: 50 } }],
        faces: [{ boundingBox: { x: Number, y: Number, width: Number, height: Number }, confidence: { type: Number, min: 0, max: 1 }, emotions: Schema.Types.Mixed, ageRange: { low: Number, high: Number } }],
        text: [{ content: { type: String, maxlength: 1000 }, confidence: { type: Number, min: 0, max: 1 }, boundingBox: Schema.Types.Mixed }],
        inappropriate: { isInappropriate: { type: Boolean, default: false }, confidence: { type: Number, min: 0, max: 1 }, categories: [{ type: String, maxlength: 50 }] },
        processedAt: { type: Date }
    }
}, { _id: false });

const metadataSchema = new Schema({
    title: { type: String, trim: true, maxlength: 200, index: 'text', set: v => v ? sanitizeHtml(v, { allowedTags: [], allowedAttributes: {} }) : v },
    description: { type: String, trim: true, maxlength: 2000, index: 'text', set: v => v ? sanitizeHtml(v, { allowedTags: [], allowedAttributes: {} }) : v },
    altText: { type: String, trim: true, maxlength: 500, set: v => v ? sanitizeHtml(v, { allowedTags: [], allowedAttributes: {} }) : v },
    tags: [{ type: String, trim: true, lowercase: true, maxlength: 50, validate: { validator: validateString, message: 'Invalid tag' } }],
    exif: {
        camera: { make: { type: String, maxlength: 100 }, model: { type: String, maxlength: 100 }, software: { type: String, maxlength: 100 } },
        settings: { iso: { type: Number, min: 0 }, aperture: { type: String, maxlength: 20 }, shutterSpeed: { type: String, maxlength: 20 }, focalLength: { type: String, maxlength: 20 }, flash: { type: Boolean } },
        location: { latitude: { type: Number, min: -90, max: 90 }, longitude: { type: Number, min: -180, max: 180 }, altitude: { type: Number }, city: { type: String, maxlength: 100 }, country: { type: String, maxlength: 100 } },
        timestamp: { type: Date }
    },
    category: { type: String, enum: ['professional', 'portfolio', 'certification', 'document', 'presentation', 'screenshot', 'photo', 'video', 'audio', 'design', 'code', 'other'], default: 'other', index: true },
    industry: [{ type: String, maxlength: 100, validate: { validator: validateString, message: 'Invalid industry' } }],
    skills: [{ type: String, maxlength: 100, validate: { validator: validateString, message: 'Invalid skill' } }],
    license: { type: String, enum: ['all-rights-reserved', 'cc-by', 'cc-by-sa', 'cc-by-nc', 'public-domain'], default: 'all-rights-reserved' },
    attribution: { type: String, maxlength: 200 },
    source: { type: String, maxlength: 200 }
}, { _id: false });

const permissionsSchema = new Schema({
    visibility: { type: String, enum: ['public', 'connections', 'company', 'private'], default: 'private', index: true },
    allowDownload: { type: Boolean, default: false, index: true },
    allowEmbedding: { type: Boolean, default: false },
    allowSharing: { type: Boolean, default: true },
    accessList: [{
        userId: { type: Schema.Types.ObjectId, ref: 'User' },
        permission: { type: String, enum: ['view', 'download', 'edit', 'admin'], default: 'view' },
        grantedAt: { type: Date, default: Date.now },
        expiresAt: { type: Date }
    }],
    ipRestrictions: {
        allowedIPs: [{ type: String, validate: { validator: validateIP, message: 'Invalid IP address' } }],
        blockedIPs: [{ type: String, validate: { validator: validateIP, message: 'Invalid IP address' } }],
        allowedCountries: [{ type: String, maxlength: 100 }],
        blockedCountries: [{ type: String, maxlength: 100 }]
    }
}, { _id: false });

const analyticsSchema = new Schema({
    views: {
        total: { type: Number, default: 0, min: 0, index: true },
        unique: { type: Number, default: 0, min: 0 },
        lastViewed: { type: Date },
        dailyViews: [{ date: { type: Date }, count: { type: Number, min: 0 } }]
    },
    downloads: {
        total: { type: Number, default: 0, min: 0, index: true },
        lastDownloaded: { type: Date },
        downloadHistory: [{
            userId: { type: Schema.Types.ObjectId, ref: 'User' },
            downloadedAt: { type: Date, default: Date.now },
            ipAddress: { type: String, validate: { validator: validateIP, message: 'Invalid IP address' } },
            userAgent: { type: String, maxlength: 500 },
            variant: { type: String, maxlength: 50 }
        }]
    },
    shares: {
        total: { type: Number, default: 0, min: 0 },
        platforms: [{ platform: { type: String, enum: ['linkedin', 'twitter', 'facebook', 'email', 'direct-link', 'other'] }, count: { type: Number, default: 0, min: 0 } }]
    },
    embeds: {
        total: { type: Number, default: 0, min: 0 },
        domains: [{ domain: { type: String, maxlength: 200 }, count: { type: Number, min: 0 } }]
    },
    performance: {
        averageLoadTime: { type: Number, min: 0 },
        cacheHitRate: { type: Number, min: 0, max: 1 },
        bandwidthUsed: { type: Number, default: 0, min: 0 },
        storageUsed: { type: Number, default: 0, min: 0 }
    }
}, { _id: false });

const securitySchema = new Schema({
    virusScan: {
        status: { type: String, enum: ['pending', 'clean', 'infected', 'failed'], default: 'pending', index: true },
        scannedAt: { type: Date },
        scanner: { type: String, maxlength: 100 },
        signature: { type: String, maxlength: 200 },
        quarantined: { type: Boolean, default: false, index: true }
    },
    moderation: {
        status: { type: String, enum: ['pending', 'approved', 'rejected', 'review-required'], default: 'pending', index: true },
        flags: [{
            type: { type: String, enum: ['inappropriate', 'copyright', 'spam', 'privacy', 'violence', 'adult-content', 'fake'], required: true },
            flaggedBy: { userId: { type: Schema.Types.ObjectId, ref: 'User' }, isSystem: { type: Boolean, default: false } },
            flaggedAt: { type: Date, default: Date.now },
            reason: { type: String, maxlength: 500 },
            severity: { type: String, enum: ['low', 'medium', 'high', 'critical'], default: 'medium' }
        }],
        moderatedBy: { type: Schema.Types.ObjectId, ref: 'User' },
        moderatedAt: { type: Date },
        moderationNotes: { type: String, maxlength: 1000, set: v => v ? sanitizeHtml(v, { allowedTags: [], allowedAttributes: {} }) : v },
        autoModerationScore: {
            inappropriate: { type: Number, min: 0, max: 1 },
            violence: { type: Number, min: 0, max: 1 },
            adult: { type: Number, min: 0, max: 1 },
            spam: { type: Number, min: 0, max: 1 },
            overall: { type: Number, min: 0, max: 1 }
        }
    },
    encryption: {
        isEncrypted: { type: Boolean, default: false },
        algorithm: { type: String, maxlength: 50 },
        keyId: { type: String, maxlength: 100 },
        encryptedAt: { type: Date }
    }
}, { _id: false });

const seoSchema = new Schema({
    searchable: { type: Boolean, default: true, index: true },
    openGraph: {
        title: { type: String, maxlength: 200 },
        description: { type: String, maxlength: 500 },
        image: { type: String, validate: { validator: validateURL, message: 'Invalid Open Graph image URL' } },
        type: { type: String, default: 'image' }
    },
    structuredData: Schema.Types.Mixed,
    searchVector: { type: String, index: 'text' },
    relevanceScore: { type: Number, default: 0, index: true }
}, { _id: false });

const lifecycleSchema = new Schema({
    expiresAt: { type: Date, index: { expireAfterSeconds: 0 } },
    archiveAt: { type: Date },
    deleteAfter: { type: Number, default: 2555 },
    lastAccessed: { type: Date, default: Date.now, index: true },
    accessFrequency: { type: Number, default: 0, min: 0 }
}, { _id: false });

const relationshipsSchema = new Schema({
    parent: { type: Schema.Types.ObjectId, ref: 'Media' },
    children: [{ type: Schema.Types.ObjectId, ref: 'Media' }],
    related: [{ mediaId: { type: Schema.Types.ObjectId, ref: 'Media' }, relationship: { type: String, enum: ['variant', 'series', 'similar', 'alternative'], default: 'related' }, similarity: { type: Number, min: 0, max: 1 } }],
    collections: [{ collectionId: { type: Schema.Types.ObjectId, ref: 'Collection' }, addedAt: { type: Date, default: Date.now }, order: { type: Number, default: 0 } }]
}, { _id: false });

const versioningSchema = new Schema({
    version: { type: Number, default: 1 },
    history: [{
        version: { type: Number, required: true },
        changes: Schema.Types.Mixed,
        changedBy: { type: Schema.Types.ObjectId, ref: 'User' },
        changedAt: { type: Date, default: Date.now },
        changeReason: { type: String, maxlength: 500 },
        rollbackData: Schema.Types.Mixed
    }],
    editLock: { lockedBy: { type: Schema.Types.ObjectId, ref: 'User' }, lockedAt: { type: Date }, expiresAt: { type: Date } }
}, { _id: false });

// Main Media Schema
const mediaSchema = new Schema({
    _id: { type: Schema.Types.ObjectId, auto: true },
    owner: {
        userId: { type: Schema.Types.ObjectId, ref: 'User', required: [true, 'Owner user ID is required'], index: true },
        userType: { type: String, enum: ['individual', 'company', 'admin'], default: 'individual', index: true }
    },
    associatedWith: {
        entityType: { type: String, enum: ['experience', 'achievement', 'profile', 'post', 'company', 'project', 'education'], required: [true, 'Entity type is required'], index: true },
        entityId: { type: Schema.Types.ObjectId, required: [true, 'Entity ID is required'], index: true },
        context: { type: String, enum: ['profile-picture', 'cover-image', 'work-sample', 'certificate', 'document', 'screenshot', 'presentation', 'video-demo', 'portfolio-item', 'testimonial-media', 'company-logo', 'award-photo', 'project-image', 'other'], required: [true, 'Context is required'], index: true }
    },
    file: fileSchema,
    storage: storageSchema,
    processing: processingSchema,
    metadata: metadataSchema,
    permissions: permissionsSchema,
    analytics: analyticsSchema,
    security: securitySchema,
    seo: seoSchema,
    status: { type: String, enum: ['active', 'processing', 'archived', 'deleted', 'quarantined', 'expired'], default: 'processing', index: true },
    lifecycle: lifecycleSchema,
    relationships: relationshipsSchema,
    versioning: versioningSchema
}, {
    timestamps: true,
    collection: 'media',
    read: 'secondaryPreferred',
    writeConcern: { w: 'majority', wtimeout: 5000 },
    autoIndex: process.env.NODE_ENV !== 'production',
    toJSON: {
        virtuals: true,
        transform: (doc, ret) => {
            delete ret.security.virusScan.signature;
            delete ret.security.encryption;
            delete ret.file.hash.sha256;
            delete ret.permissions.ipRestrictions;
            delete ret.analytics.downloadHistory;
            delete ret.versioning.history;
            delete ret.__v;
            ret.publicUrl = doc.getPublicUrl();
            ret.thumbnailUrl = doc.getThumbnailUrl();
            return ret;
        }
    },
    toObject: { virtuals: true },
    minimize: false,
    strict: 'throw'
});

// Indexes
mediaSchema.index({ 'owner.userId': 1, status: 1, 'associatedWith.entityType': 1, createdAt: -1 });
mediaSchema.index({ 'associatedWith.entityType': 1, 'associatedWith.entityId': 1, 'associatedWith.context': 1 });
mediaSchema.index({ 'file.hash.md5': 1 });
mediaSchema.index({ 'storage.cdn.cacheStatus': 1, 'processing.status': 1 });
mediaSchema.index({ 'analytics.views.total': -1, 'permissions.visibility': 1 });
mediaSchema.index({ 'metadata.category': 1, 'analytics.views.total': -1, createdAt: -1 });
mediaSchema.index({ 'security.virusScan.status': 1, 'security.moderation.status': 1 });
mediaSchema.index({ 'security.moderation.flags.type': 1, 'security.moderation.flags.severity': 1 });
mediaSchema.index({ 'lifecycle.expiresAt': 1 });
mediaSchema.index({ 'lifecycle.lastAccessed': -1 });
mediaSchema.index({ 'lifecycle.archiveAt': 1 });
mediaSchema.index({ 'metadata.exif.location': '2dsphere' }, { sparse: true });
mediaSchema.index({
    'metadata.title': 'text',
    'metadata.description': 'text',
    'metadata.tags': 'text',
    'file.originalName': 'text',
    'seo.searchVector': 'text'
}, {
    weights: { 'metadata.title': 10, 'metadata.tags': 8, 'file.originalName': 6, 'metadata.description': 4, 'seo.searchVector': 1 },
    name: 'media_search_index'
});

// Virtuals
mediaSchema.virtual('fileType').get(function () {
    const mime = this.file.mimeType?.toLowerCase() || '';
    if (mime.startsWith('image/')) return 'image';
    if (mime.startsWith('video/')) return 'video';
    if (mime.startsWith('audio/')) return 'audio';
    return 'document';
});
mediaSchema.virtual('isRecent').get(function () {
    const oneMonthAgo = new Date();
    oneMonthAgo.setMonth(oneMonthAgo.getMonth() - 1);
    return this.createdAt >= oneMonthAgo;
});
mediaSchema.virtual('contentStatus').get(function () {
    if (this.security.moderation.status === 'rejected' || this.security.virusScan.status === 'infected') return 'unsafe';
    if (this.security.moderation.status === 'approved' && this.security.virusScan.status === 'clean') return 'safe';
    return 'pending';
});
mediaSchema.virtual('cacheEfficiency').get(function () {
    return this.analytics.performance.cacheHitRate || 0;
});

// Middleware
mediaSchema.pre('save', async function (next) {
    try {
        // Generate system filename
        if (!this.file.systemName) {
            const timestamp = Date.now();
            const randomString = crypto.randomBytes(8).toString('hex');
            this.file.systemName = `${timestamp}_${randomString}.${this.file.extension} `;
        }

        // Calculate aspect ratio and resolution
        if (this.file.dimensions?.width && this.file.dimensions?.height) {
            this.file.dimensions.aspectRatio = this.file.dimensions.width / this.file.dimensions.height;
            this.file.dimensions.resolution = `${this.file.dimensions.width}x${this.file.dimensions.height} `;
        }

        // Generate search vector
        this.seo.searchVector = [
            this.metadata.title,
            this.metadata.description,
            ...this.metadata.tags,
            this.file.originalName,
            ...this.metadata.skills,
            ...this.metadata.industry
        ].filter(Boolean).join(' ').toLowerCase();

        // Calculate relevance score
        this.seo.relevanceScore = this.calculateRelevanceScore();

        // Update lifecycle
        this.lifecycle.lastAccessed = new Date();
        this.lifecycle.accessFrequency += 1;

        // Update versioning
        if (!this.isNew) {
            this.versioning.version += 1;
            this.versioning.history.push({
                version: this.versioning.version,
                changedBy: this.owner.userId,
                changedAt: new Date(),
                changeReason: 'Updated media',
                changes: this.getChanges()
            });
        } else {
            this.versioning.history.push({
                version: 1,
                changedBy: this.owner.userId,
                changedAt: new Date(),
                changeReason: 'Created media'
            });
        }

        // Cache in Redis
        await redisClient.setEx(`media:${this._id} `, 300, JSON.stringify(this.toJSON()));

        // Publish updates
        await redisClient.publish('media_updates', JSON.stringify({
            mediaId: this._id,
            status: this.status,
            visibility: this.permissions.visibility,
            relevanceScore: this.seo.relevanceScore
        }));

        next();
    } catch (error) {
        next(new Error(`Pre - save middleware error: ${error.message} `));
    }
});

mediaSchema.pre('remove', async function (next) {
    try {
        this.status = 'deleted';
        this.permissions.visibility = 'private';
        this.permissions.searchable = false;
        this.security.moderation.status = 'rejected';
        await redisClient.del(`media:${this._id} `);
        await this.save();
        next();
    } catch (error) {
        next(new Error(`Pre - remove middleware error: ${error.message} `));
    }
});

mediaSchema.post('save', async function (doc) {
    try {
        // Update related entities
        const entityModels = { experience: 'Experience', achievement: 'Achievement', profile: 'User', post: 'Post', company: 'Company', project: 'Project', education: 'Education' };
        const Model = mongoose.model(entityModels[doc.associatedWith.entityType]);
        if (Model) {
            await Model.updateOne(
                { _id: doc.associatedWith.entityId },
                { $set: { 'analytics.lastUpdated': new Date() }, $inc: { 'analytics.mediaCount': 1 } }
            );
        }

        // Sync to Algolia
        if (doc.permissions.searchable && doc.permissions.visibility === 'public' && doc.status === 'active') {
            try {
                await doc.syncToAlgolia();
            } catch (error) {
                console.error('Algolia sync error:', error.message);
            }
        }

        // Invalidate related caches
        await redisClient.del(`user: media:${doc.owner.userId} `);
        await redisClient.del(`entity: media:${doc.associatedWith.entityType}:${doc.associatedWith.entityId} `);
    } catch (error) {
        console.error('Post-save middleware error:', error.message);
    }
});

// Instance Methods
mediaSchema.methods.calculateRelevanceScore = function () {
    let score = 0;
    if (this.metadata.title) score += 20;
    if (this.metadata.description) score += 15;
    if (this.metadata.tags.length > 0) score += Math.min(this.metadata.tags.length * 5, 15);
    if (this.metadata.altText) score += 5;
    if (this.metadata.skills?.length > 0) score += Math.min(this.metadata.skills.length * 5, 10);
    if (this.metadata.industry?.length > 0) score += Math.min(this.metadata.industry.length * 5, 10);
    score += Math.min(this.analytics.views.total / 100, 20);
    score += Math.min(this.analytics.downloads.total * 2, 15);
    score += Math.min(this.analytics.shares.total * 5, 10);
    if (this.security.virusScan.status === 'clean') score += 5;
    if (this.security.moderation.status === 'approved') score += 5;
    if (this.processing.status === 'completed') score += 5;
    const daysSinceUpload = (Date.now() - this.createdAt) / (1000 * 60 * 60 * 24);
    const recencyBoost = Math.max(0, 5 - (daysSinceUpload / 30));
    score += recencyBoost;
    return Math.min(score, 100);
};

mediaSchema.methods.getOptimizedUrl = function (options = {}) {
    const { size = 'medium', format = 'auto', quality = 'auto', devicePixelRatio = 1 } = options;
    if (this.storage.cdn.cachedUrls[size]) return this.storage.cdn.cachedUrls[size];

    const baseUrl = this.storage.cdn.baseUrl;
    const transformations = [];
    const sizeMap = {
        thumbnail: `w_${150 * devicePixelRatio},h_${150 * devicePixelRatio}, c_fill`,
        small: `w_${400 * devicePixelRatio},h_${400 * devicePixelRatio}, c_limit`,
        medium: `w_${800 * devicePixelRatio},h_${600 * devicePixelRatio}, c_limit`,
        large: `w_${1200 * devicePixelRatio},h_${900 * devicePixelRatio}, c_limit`
    };
    if (size !== 'original') transformations.push(sizeMap[size] || sizeMap.medium);
    if (format !== 'auto' && format !== this.file.extension) transformations.push(`f_${format} `);
    if (quality !== 'auto') transformations.push(`q_${quality} `);
    const transformString = transformations.length > 0 ? transformations.join(',') + '/' : '';
    return `${baseUrl}/${transformString}${this.storage.primary.key}`;
};

mediaSchema.methods.getPublicUrl = function () {
    if (this.permissions.visibility === 'public' && this.status === 'active' && this.security.moderation.status === 'approved') {
        return this.getOptimizedUrl();
    }
    return null;
};

mediaSchema.methods.getThumbnailUrl = function () {
    return this.getOptimizedUrl({ size: 'thumbnail', quality: '80' });
};

mediaSchema.methods.hasAccess = function (userId, permission = 'view') {
    if (this.owner.userId.equals(userId)) return true;
    if (this.permissions.visibility === 'public' && permission === 'view' && this.status === 'active') return true;
    const accessEntry = this.permissions.accessList.find(entry => entry.userId.equals(userId));
    if (accessEntry) {
        const permissionLevels = ['view', 'download', 'edit', 'admin'];
        const userLevel = permissionLevels.indexOf(accessEntry.permission);
        const requiredLevel = permissionLevels.indexOf(permission);
        return userLevel >= requiredLevel && (!accessEntry.expiresAt || accessEntry.expiresAt > new Date());
    }
    return false;
};

// Static Methods
mediaSchema.statics.searchMedia = async function (query, filters = {}, options = {}) {
    const { userId, entityType, category, mimeType, minSize, maxSize, dateRange, hasLocation, sortBy = 'relevance', page = 1, limit = 20 } = options;
    const cacheKey = `search:media:${JSON.stringify({ query, filters, options })}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const pipeline = [
        {
            $match: {
                status: 'active',
                'security.moderation.status': 'approved',
                'security.virusScan.status': 'clean',
                'permissions.visibility': { $in: ['public', 'connections'] },
                ...(query && { $text: { $search: query, $caseSensitive: false } }),
                ...(userId && { 'owner.userId': new mongoose.Types.ObjectId(userId) }),
                ...(entityType && { 'associatedWith.entityType': entityType }),
                ...(category && { 'metadata.category': category }),
                ...(mimeType && { 'file.mimeType': new RegExp(mimeType, 'i') }),
                ...(minSize || maxSize ? { 'file.size': { ...(minSize && { $gte: minSize }), ...(maxSize && { $lte: maxSize }) } } : {}),
                ...(dateRange && { createdAt: { $gte: new Date(dateRange.from), $lte: new Date(dateRange.to) } }),
                ...(hasLocation && { 'metadata.exif.location': { $exists: true } })
            }
        },
        { $addFields: { textScore: { $meta: 'textScore' } } },
        { $lookup: { from: 'users', localField: 'owner.userId', foreignField: '_id', as: 'owner.user', pipeline: [{ $project: { name: 1, profilePicture: 1, headline: 1 } }] } },
        { $unwind: { path: '$owner.user', preserveNullAndEmptyArrays: true } },
        {
            $addFields: {
                relevanceScore: {
                    $add: [
                        { $multiply: [{ $ifNull: ['$textScore', 0] }, 0.4] },
                        { $multiply: [{ $divide: ['$seo.relevanceScore', 100] }, 0.3] },
                        { $multiply: [{ $divide: ['$analytics.views.total', 1000] }, 0.2] },
                        { $multiply: [{ $divide: ['$analytics.shares.total', 100] }, 0.1] }
                    ]
                }
            }
        },
        { $sort: this.getSortQuery(sortBy) },
        {
            $project: {
                'file.originalName': 1,
                'file.mimeType': 1,
                'file.size': 1,
                'file.dimensions': 1,
                'storage.cdn': { baseUrl: 1, cachedUrls: 1, cacheStatus: 1 },
                'metadata.title': 1,
                'metadata.description': { $substr: ['$metadata.description', 0, 200] },
                'metadata.category': 1,
                'metadata.tags': 1,
                'owner': 1,
                'associatedWith': 1,
                'analytics': { views: { total: 1 }, shares: { total: 1 }, downloads: { total: 1 } },
                'seo.relevanceScore': 1,
                createdAt: 1,
                fileType: 1,
                contentStatus: 1,
                publicUrl: 1,
                thumbnailUrl: 1
            }
        }
    ];

    const results = await this.aggregatePaginate(pipeline, { page, limit, customLabels: { totalDocs: 'totalResults', docs: 'media' } });
    await redisClient.setEx(cacheKey, 60, JSON.stringify(results));
    return results;
};

mediaSchema.statics.getSortQuery = function (sortBy) {
    const sortQueries = {
        relevance: { relevanceScore: -1, 'seo.relevanceScore': -1 },
        popular: { 'analytics.views.total': -1, 'analytics.shares.total': -1 },
        recent: { createdAt: -1 },
        size: { 'file.size': -1 },
        name: { 'file.originalName': 1 }
    };
    return sortQueries[sortBy] || sortQueries.relevance;
};

mediaSchema.statics.getTrending = async function (timeframe = '7d', options = {}) {
    const { category, limit = 20 } = options;
    const cacheKey = `trending:media:${JSON.stringify({ timeframe, options })}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const timeframeMap = { '24h': 1, '7d': 7, '30d': 30, '90d': 90 };
    const days = timeframeMap[timeframe] || 7;
    const since = new Date(Date.now() - (days * 24 * 60 * 60 * 1000));

    const pipeline = [
        {
            $match: {
                status: 'active',
                'permissions.visibility': 'public',
                'security.moderation.status': 'approved',
                'security.virusScan.status': 'clean',
                createdAt: { $gte: since },
                ...(category && { 'metadata.category': category })
            }
        },
        { $lookup: { from: 'users', localField: 'owner.userId', foreignField: '_id', as: 'owner.user', pipeline: [{ $project: { name: 1, profilePicture: 1, headline: 1 } }] } },
        { $unwind: { path: '$owner.user', preserveNullAndEmptyArrays: true } },
        { $sort: { 'analytics.views.total': -1, 'analytics.shares.total': -1, 'seo.relevanceScore': -1 } },
        { $limit: limit },
        {
            $project: {
                'file.originalName': 1,
                'file.mimeType': 1,
                'file.size': 1,
                'file.dimensions': 1,
                'storage.cdn': { baseUrl: 1, cachedUrls: 1, cacheStatus: 1 },
                'metadata.title': 1,
                'metadata.description': { $substr: ['$metadata.description', 0, 200] },
                'metadata.category': 1,
                'metadata.tags': 1,
                'owner': 1,
                'associatedWith': 1,
                'analytics': { views: { total: 1 }, shares: { total: 1 }, downloads: { total: 1 } },
                'seo.relevanceScore': 1,
                createdAt: 1,
                fileType: 1,
                contentStatus: 1,
                publicUrl: 1,
                thumbnailUrl: 1
            }
        }
    ];

    const results = await this.aggregatePaginate(pipeline, { page: 1, limit });
    await redisClient.setEx(cacheKey, 3600, JSON.stringify(results));
    return results;
};

mediaSchema.statics.getStorageStats = async function (userId = null) {
    const cacheKey = `storage:stats:${userId || 'global'}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const pipeline = [
        { $match: { status: { $ne: 'deleted' }, ...(userId && { 'owner.userId': new mongoose.Types.ObjectId(userId) }) } },
        {
            $group: {
                _id: '$file.mimeType',
                count: { $sum: 1 },
                totalSize: { $sum: '$file.size' },
                avgSize: { $avg: '$file.size' },
                totalBandwidth: { $sum: '$analytics.performance.bandwidthUsed' },
                categories: { $addToSet: '$metadata.category' }
            }
        },
        {
            $addFields: {
                mimeType: '$_id',
                totalSizeMB: { $divide: ['$totalSize', 1024 * 1024] },
                avgSizeMB: { $divide: ['$avgSize', 1024 * 1024] },
                totalBandwidthMB: { $divide: ['$totalBandwidth', 1024 * 1024] }
            }
        },
        { $sort: { totalSize: -1 } },
        { $project: { _id: 0, mimeType: 1, count: 1, totalSizeMB: { $round: ['$totalSizeMB', 2] }, avgSizeMB: { $round: ['$avgSizeMB', 2] }, totalBandwidthMB: { $round: ['$totalBandwidthMB', 2] }, categories: 1 } }
    ];

    const results = await this.aggregate(pipeline);
    await redisClient.setEx(cacheKey, 43200, JSON.stringify(results));
    return results;
};

mediaSchema.statics.bulkOperations = {
    updateModerationStatus: async function (mediaIds, moderationData) {
        try {
            const bulkOps = mediaIds.map(id => ({
                updateOne: {
                    filter: { _id: new mongoose.Types.ObjectId(id), status: { $in: ['active', 'processing'] } },
                    update: {
                        $set: {
                            'security.moderation.status': moderationData.status,
                            'security.moderation.moderatedBy': moderationData.moderatedBy,
                            'security.moderation.moderatedAt': new Date(),
                            'security.moderation.moderationNotes': moderationData.notes,
                            'versioning.history': {
                                $push: {
                                    version: { $inc: { 'versioning.version': 1 } },
                                    changedBy: moderationData.moderatedBy,
                                    changedAt: new Date(),
                                    changeReason: 'Moderation update',
                                    changes: { 'security.moderation.status': moderationData.status }
                                }
                            }
                        }
                    }
                }
            }));
            const result = await this.bulkWrite(bulkOps);
            for (const id of mediaIds) await redisClient.del(`media:${id}`);
            return result;
        } catch (error) {
            throw new Error(`Bulk moderation error: ${error.message}`);
        }
    },
    archiveMedia: async function (cutoffDate) {
        try {
            const oldMedia = await this.find({ createdAt: { $lt: cutoffDate }, status: 'active', 'security.moderation.status': 'approved' }).lean();
            if (oldMedia.length === 0) return { archived: 0 };
            const ArchiveMedia = mongoose.model('ArchiveMedia', mediaSchema, 'archive_media');
            await ArchiveMedia.insertMany(oldMedia);
            const result = await this.updateMany(
                { _id: { $in: oldMedia.map(m => m._id) } },
                { $set: { status: 'archived', 'permissions.visibility': 'private', 'permissions.searchable': false, 'versioning.history': { $push: { changedAt: new Date(), changeReason: 'Archived' } } } }
            );
            for (const media of oldMedia) await redisClient.del(`media:${media._id}`);
            return { archived: result.modifiedCount };
        } catch (error) {
            throw new Error(`Archive media error: ${error.message}`);
        }
    },
    updateCacheStatus: async function (mediaIds, cacheStatus) {
        try {
            const result = await this.updateMany(
                { _id: { $in: mediaIds.map(id => new mongoose.Types.ObjectId(id)) }, status: 'active' },
                { $set: { 'storage.cdn.cacheStatus': cacheStatus, 'storage.cdn.lastCacheUpdate': new Date(), 'versioning.history': { $push: { changedAt: new Date(), changeReason: 'Cache status update' } } } }
            );
            for (const id of mediaIds) await redisClient.del(`media:${id}`);
            return result;
        } catch (error) {
            throw new Error(`Bulk cache status update error: ${error.message}`);
        }
    }
};

mediaSchema.statics.cleanupIndexes = async function () {
    const indexes = await this.collection.indexes();
    const essentialIndexes = ['_id_', 'media_search_index', 'owner.userId_1_status_1_associatedWith.entityType_1_createdAt_-1', 'file.hash.md5_1'];
    const unusedIndexes = indexes.filter(idx => !essentialIndexes.includes(idx.name) && !idx.name.includes('2dsphere'));
    let dropped = 0;
    for (const idx of unusedIndexes) {
        try {
            await this.collection.dropIndex(idx.name);
            dropped++;
        } catch (err) {
            console.error(`Failed to drop index ${idx.name}:`, err);
        }
    }
    return { dropped };
};

mediaSchema.statics.initChangeStream = function () {
    const changeStream = this.watch([{ $match: { 'operationType': { $in: ['insert', 'update', 'replace'] } } }]);
    changeStream.on('change', async (change) => {
        const mediaId = change.documentKey._id.toString();
        await redisClient.del(`media:${mediaId}`);
        await redisClient.publish('media_updates', JSON.stringify({
            mediaId,
            operation: change.operationType,
            updatedFields: change.updateDescription?.updatedFields
        }));
    });
    return changeStream;
};

// Placeholder for CSFLE
async function encryptField(value) {
    // Requires MongoDB CSFLE setup
    return crypto.createHash('sha256').update(value).digest('hex');
}

// Plugins
mediaSchema.plugin(aggregatePaginate);
if (process.env.ALGOLIA_APP_ID && process.env.ALGOLIA_ADMIN_KEY) {
    mediaSchema.plugin(mongooseAlgolia, {
        appId: process.env.ALGOLIA_APP_ID,
        apiKey: process.env.ALGOLIA_ADMIN_KEY,
        indexName: 'media',
        selector: 'metadata.title metadata.description metadata.tags file.originalName seo.searchVector owner.userId associatedWith.entityType associatedWith.entityId',
        defaults: { author: 'unknown' },
        mappings: {
            'metadata.title': v => v || '',
            'metadata.description': v => v || '',
            'metadata.tags': v => v || [],
            'file.originalName': v => v || '',
            'seo.searchVector': v => v || '',
            'owner.userId': v => v?.toString() || '',
            'associatedWith.entityType': v => v || '',
            'associatedWith.entityId': v => v?.toString() || ''
        },
        debug: process.env.NODE_ENV === 'development'
    });
} else {
    console.warn('Algolia plugin not initialized: Missing ALGOLIA_APP_ID or ALGOLIA_ADMIN_KEY');
}

// Production Indexes
if (process.env.NODE_ENV === 'production') {
    mediaSchema.index({ 'storage.cdn.lastCacheUpdate': -1 }, { background: true });
    mediaSchema.index({ 'analytics.downloads.total': -1, 'permissions.visibility': 1 }, { background: true });
}

export default mongoose.model('Media', mediaSchema);