import mongoose from 'mongoose';
import { createHash } from 'crypto';

// ===========================
// OPTIMIZED SUB-SCHEMAS
// ===========================
const metadataSchema = new mongoose.Schema({
    originalName: {
        type: String,
        required: true,
        trim: true,
        maxlength: 255
    },
    mimetype: {
        type: String,
        required: true,
        enum: ['image/jpeg', 'image/jpg', 'image/png', 'image/webp', 'image/gif'],
        index: true
    },
    size: {
        type: Number,
        required: true,
        min: 0,
        max: 50 * 1024 * 1024, // 50MB max
        index: true
    },
    width: {
        type: Number,
        required: true,
        min: 100,
        max: 8192,
        index: true
    },
    height: {
        type: Number,
        required: true,
        min: 100,
        max: 8192,
        index: true
    },
    aspectRatio: {
        type: Number,
        index: true
    },
    colorProfile: {
        type: String,
        enum: ['sRGB', 'Adobe RGB', 'ProPhoto RGB', 'Display P3'],
        default: 'sRGB'
    },
    orientation: {
        type: String,
        enum: ['landscape', 'portrait', 'square'],
        index: true
    },
    format: {
        type: String,
        enum: ['jpeg', 'jpg', 'png', 'webp', 'gif'],
        required: true,
        index: true
    },
    compression: {
        quality: { type: Number, min: 10, max: 100, default: 85 },
        algorithm: { type: String, enum: ['lossy', 'lossless'], default: 'lossy' }
    },
    exifData: {
        camera: { type: String, default: '', maxlength: 100 },
        lens: { type: String, default: '', maxlength: 100 },
        captureDate: { type: Date },
        location: {
            latitude: { type: Number },
            longitude: { type: Number }
        },
        removed: { type: Boolean, default: true } // Privacy setting
    }
}, { _id: false });

const processingSchema = new mongoose.Schema({
    original: {
        url: { type: String, required: true, trim: true },
        cloudinaryId: { type: String, trim: true },
        s3Key: { type: String, trim: true },
        size: { type: Number, required: true }
    },
    optimized: {
        url: { type: String, default: '', trim: true },
        cloudinaryId: { type: String, trim: true },
        s3Key: { type: String, trim: true },
        size: { type: Number, default: 0 },
        compressionRatio: { type: Number, default: 0 }
    },
    thumbnails: {
        small: {
            url: { type: String, default: '' },
            size: { type: Number, default: 150 },
            cloudinaryId: { type: String, trim: true }
        },
        medium: {
            url: { type: String, default: '' },
            size: { type: Number, default: 400 },
            cloudinaryId: { type: String, trim: true }
        },
        large: {
            url: { type: String, default: '' },
            size: { type: Number, default: 800 },
            cloudinaryId: { type: String, trim: true }
        }
    },
    variants: [{
        name: { type: String, required: true },
        url: { type: String, required: true },
        width: { type: Number, required: true },
        height: { type: Number, required: true },
        size: { type: Number, required: true },
        format: { type: String, required: true },
        cloudinaryId: { type: String, trim: true },
        purpose: {
            type: String,
            enum: ['mobile', 'tablet', 'desktop', 'print', 'social'],
            required: true
        }
    }],
    status: {
        type: String,
        enum: ['pending', 'processing', 'completed', 'failed', 'optimizing'],
        default: 'pending',
        index: true
    },
    processingStartedAt: { type: Date },
    processingCompletedAt: { type: Date },
    processingDuration: { type: Number }, // in milliseconds
    errorMessage: { type: String, default: '' },
    retryCount: { type: Number, default: 0, max: 3 }
}, { _id: false });

const qualitySchema = new mongoose.Schema({
    qualityScore: {
        overall: { type: Number, min: 0, max: 10, default: 0, index: true },
        sharpness: { type: Number, min: 0, max: 10, default: 0 },
        noise: { type: Number, min: 0, max: 10, default: 0 },
        contrast: { type: Number, min: 0, max: 10, default: 0 }
    },
    enhancementData: {
        sharpnessLevel: { type: Number, min: 0, max: 2, default: 1.0 },
        noiseReduction: { type: String, enum: ['none', 'low', 'medium', 'high'], default: 'none' },
        contrastLevel: { type: Number, min: 0.5, max: 2, default: 1.0 }
    },
    lastAssessedAt: { type: Date },
    assessmentVersion: { type: String, default: '1.0' }
}, { _id: false });

const aiAnalysisSchema = new mongoose.Schema({
    dominantColors: [{
        hex: { type: String, match: /^#[0-9A-F]{6}$/i },
        rgb: {
            r: { type: Number, min: 0, max: 255 },
            g: { type: Number, min: 0, max: 255 },
            b: { type: Number, min: 0, max: 255 }
        },
        percentage: { type: Number, min: 0, max: 100 }
    }],
    mood: {
        type: String,
        enum: ['bright', 'dark', 'neutral', 'warm', 'cool', 'vibrant', 'muted'],
        index: true
    },
    style: {
        type: String,
        enum: ['minimalist', 'abstract', 'nature', 'urban', 'professional', 'artistic', 'geometric', 'organic'],
        index: true
    },
    objects: [{
        name: { type: String, maxlength: 50 },
        confidence: { type: Number, min: 0, max: 1 }
    }],
    faces: {
        detected: { type: Boolean, default: false, index: true },
        count: { type: Number, default: 0, min: 0 }
    },
    textDetected: {
        hasText: { type: Boolean, default: false, index: true },
        content: [{ type: String, maxlength: 200 }],
        regions: [{
            text: String,
            confidence: Number,
            boundingBox: {
                x: Number,
                y: Number,
                width: Number,
                height: Number
            }
        }]
    },
    suitability: {
        profileCover: { type: Number, min: 0, max: 100, index: true },
        businessCard: { type: Number, min: 0, max: 100 },
        socialMedia: { type: Number, min: 0, max: 100 },
        presentation: { type: Number, min: 0, max: 100 }
    },
    tags: [{
        type: String,
        trim: true,
        maxlength: 30,
        index: true
    }],
    analysisVersion: { type: String, default: '1.0' },
    analyzedAt: { type: Date }
}, { _id: false });

const usageSchema = new mongoose.Schema({
    totalViews: { type: Number, default: 0, index: true },
    uniqueViews: { type: Number, default: 0 },
    downloads: { type: Number, default: 0, index: true },
    shares: { type: Number, default: 0 },
    likes: { type: Number, default: 0, index: true },
    bookmarks: { type: Number, default: 0 },
    reports: { type: Number, default: 0, index: true },
    lastViewedAt: { type: Date, index: true },
    viewHistory: [{
        userId: { type: String },
        viewedAt: { type: Date, default: Date.now },
        source: {
            type: String,
            enum: ['search', 'recommendation', 'direct', 'template', 'gallery'],
            default: 'direct'
        }
    }],
    popularityScore: {
        type: Number,
        default: 0,
        min: 0,
        max: 100,
        index: true
    },
    trendingScore: {
        type: Number,
        default: 0,
        min: 0,
        max: 100
    }
}, { _id: false });

const accessControlSchema = new mongoose.Schema({
    visibility: {
        type: String,
        enum: ['public', 'private', 'restricted'],
        default: 'private',
        index: true
    },
    allowedUsers: [{
        type: String,
        validate: {
            validator: function (v) {
                return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(v);
            },
            message: 'Invalid user UUID'
        },
        index: true
    }],
    allowedGroups: [{
        type: String,
        validate: {
            validator: function (v) {
                return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(v);
            },
            message: 'Invalid group UUID'
        },
        index: true
    }],
    allowDownload: { type: Boolean, default: true },
    allowShare: { type: Boolean, default: true },
    allowModification: { type: Boolean, default: false },
    licensing: {
        type: String,
        enum: ['personal', 'commercial', 'creative-commons', 'royalty-free', 'rights-managed'],
        default: 'personal',
        index: true
    },
    watermark: {
        enabled: { type: Boolean, default: false },
        text: { type: String, default: '', maxlength: 50 },
        opacity: { type: Number, min: 0.1, max: 1, default: 0.3 },
        position: {
            type: String,
            enum: ['top-left', 'top-right', 'bottom-left', 'bottom-right', 'center'],
            default: 'bottom-right'
        }
    },
    organizationId: { type: String, index: true },
    teamId: { type: String, index: true }
}, { _id: false });

// ===========================
// MAIN COVER PHOTO SCHEMA
// ===========================
const coverPhotoSchema = new mongoose.Schema({
    coverId: {
        type: String,
        required: true,
        unique: true,
        index: true,
        immutable: true
    },
    userId: {
        type: String,
        required: true,
        index: true
    },
    title: {
        type: String,
        required: true,
        trim: true,
        maxlength: 200,
        index: 'text'
    },
    description: {
        type: String,
        default: '',
        maxlength: 1000,
        index: 'text'
    },
    category: {
        type: String,
        enum: ['nature', 'abstract', 'business', 'technology', 'art', 'photography', 'design', 'minimal', 'colorful', 'dark', 'light'],
        required: true,
        index: true
    },
    subcategory: {
        type: String,
        default: '',
        maxlength: 50,
        index: true
    },
    metadata: {
        type: metadataSchema,
        required: true
    },
    processing: {
        type: processingSchema,
        required: true
    },
    quality: {
        type: qualitySchema,
        default: () => ({})
    },
    aiAnalysis: {
        type: aiAnalysisSchema,
        default: () => ({})
    },
    usage: {
        type: usageSchema,
        default: () => ({})
    },
    accessControl: {
        type: accessControlSchema,
        default: () => ({})
    },
    templateId: {
        type: String,
        default: '',
        index: true
    },
    designId: {
        type: String,
        default: '',
        index: true
    },
    collections: [{
        type: String,
        index: true
    }],
    tags: [{
        type: String,
        trim: true,
        maxlength: 30,
        index: true
    }],
    source: {
        type: String,
        enum: ['upload', 'template', 'ai-generated', 'stock', 'url-import'],
        required: true,
        index: true
    },
    sourceReference: {
        originalUrl: { type: String, default: '' },
        stockId: { type: String, default: '' },
        templateVersion: { type: String, default: '' },
        aiPrompt: { type: String, default: '', maxlength: 500 },
        aiModel: { type: String, default: '' }
    },
    brandingElements: {
        logo: {
            enabled: { type: Boolean, default: false },
            url: { type: String, default: '' },
            position: {
                type: String,
                enum: ['top-left', 'top-right', 'bottom-left', 'bottom-right', 'center'],
                default: 'bottom-right'
            },
            size: { type: Number, min: 0.1, max: 1, default: 0.2 },
            opacity: { type: Number, min: 0.1, max: 1, default: 1 }
        },
        companyName: {
            enabled: { type: Boolean, default: false },
            text: { type: String, default: '', maxlength: 100 },
            font: { type: String, default: 'Arial' },
            color: { type: String, default: '#FFFFFF' },
            position: {
                type: String,
                enum: ['top-left', 'top-right', 'bottom-left', 'bottom-right', 'center'],
                default: 'bottom-left'
            },
            size: { type: Number, min: 12, max: 72, default: 24 }
        },
        colorOverlay: {
            enabled: { type: Boolean, default: false },
            color: { type: String, default: '#000000' },
            opacity: { type: Number, min: 0.1, max: 1, default: 0.3 },
            blendMode: {
                type: String,
                enum: ['normal', 'multiply', 'screen', 'overlay', 'soft-light', 'hard-light'],
                default: 'normal'
            }
        }
    },
    abTesting: {
        isTest: { type: Boolean, default: false },
        testGroup: { type: String, default: '' },
        variantId: { type: String, default: '' },
        parentCoverId: { type: String, default: '' },
        testMetrics: {
            impressions: { type: Number, default: 0 },
            clicks: { type: Number, default: 0 },
            conversions: { type: Number, default: 0 },
            engagement: { type: Number, default: 0 }
        }
    },
    scheduling: {
        isScheduled: { type: Boolean, default: false },
        publishAt: { type: Date, index: true },
        unpublishAt: { type: Date, index: true },
        timezone: { type: String, default: 'UTC' },
        autoRotation: {
            enabled: { type: Boolean, default: false },
            interval: { type: Number, min: 3600, default: 86400 }, // seconds
            covers: [{ type: String }] // Array of cover IDs
        }
    },
    analytics: {
        performanceScore: { type: Number, default: 0, min: 0, max: 100, index: true },
        engagementRate: { type: Number, default: 0, min: 0, max: 100 },
        conversionRate: { type: Number, default: 0, min: 0, max: 100 },
        avgTimeViewed: { type: Number, default: 0 }, // seconds
        bounceRate: { type: Number, default: 0, min: 0, max: 100 },
        socialShares: {
            facebook: { type: Number, default: 0 },
            twitter: { type: Number, default: 0 },
            linkedin: { type: Number, default: 0 },
            instagram: { type: Number, default: 0 }
        },
        deviceBreakdown: {
            desktop: { type: Number, default: 0 },
            tablet: { type: Number, default: 0 },
            mobile: { type: Number, default: 0 }
        },
        geographicData: [{
            country: { type: String, required: true },
            views: { type: Number, required: true },
            percentage: { type: Number, min: 0, max: 100 }
        }],
        weeklyViews: [{
            week: { type: Date, required: true },
            views: { type: Number, required: true },
            uniqueViews: { type: Number, default: 0 }
        }]
    },
    moderation: {
        status: {
            type: String,
            enum: ['pending', 'approved', 'rejected', 'flagged', 'under-review'],
            default: 'pending',
            index: true
        },
        reviewedBy: { type: String },
        reviewedAt: { type: Date },
        rejectionReason: { type: String, default: '' },
        flags: [{
            type: {
                type: String,
                enum: ['inappropriate', 'copyright', 'spam', 'low-quality', 'misleading']
            },
            reportedBy: { type: String },
            reportedAt: { type: Date, default: Date.now },
            reason: { type: String, maxlength: 500 }
        }],
        autoModeration: {
            nsfwScore: { type: Number, min: 0, max: 1, default: 0 },
            violenceScore: { type: Number, min: 0, max: 1, default: 0 },
            textModerationScore: { type: Number, min: 0, max: 1, default: 0 },
            copyrightScore: { type: Number, min: 0, max: 1, default: 0 }
        }
    },
    versions: [{
        versionId: { type: String, required: true },
        url: { type: String, required: true },
        createdAt: { type: Date, default: Date.now },
        changes: { type: String, maxlength: 500 },
        isActive: { type: Boolean, default: false },
        quality: { type: qualitySchema, default: () => ({}) }
    }],
    backup: {
        isBackedUp: { type: Boolean, default: false },
        backupUrl: { type: String, default: '' },
        backupDate: { type: Date },
        backupProvider: { type: String, enum: ['s3', 'gcs', 'azure'], default: 's3' }
    },
    status: {
        type: String,
        enum: ['active', 'inactive', 'deleted', 'archived', 'processing'],
        default: 'processing',
        index: true
    },
    createdAt: {
        type: Date,
        default: Date.now,
        index: true
    },
    updatedAt: {
        type: Date,
        default: Date.now,
        index: true
    },
    lastUsedAt: {
        type: Date,
        index: true
    },
    cacheVersion: {
        type: Number,
        default: 0
    }
}, {
    timestamps: {
        createdAt: 'createdAt',
        updatedAt: 'updatedAt'
    },
    versionKey: 'version',
    strict: true,
    collection: 'cover_photos',
    read: 'secondaryPreferred',
    shardKey: { userId: 1, category: 1 },
    toJSON: {
        transform: function (doc, ret) {
            ret.id = ret._id;
            delete ret._id;
            delete ret.__v;
            return ret;
        }
    },
    toObject: {
        transform: function (doc, ret) {
            ret.id = ret._id;
            delete ret._id;
            delete ret.__v;
            return ret;
        }
    }
});

// ===========================
// OPTIMIZED INDEXES
// ===========================
coverPhotoSchema.index({ coverId: 1 }, { unique: true, name: 'idx_coverId_unique' });
coverPhotoSchema.index({ userId: 1, status: 1 }, { name: 'idx_user_status' });
coverPhotoSchema.index({ category: 1, status: 1, 'accessControl.visibility': 1 }, { name: 'idx_category_search' });
coverPhotoSchema.index({ 'processing.status': 1, createdAt: -1 }, { name: 'idx_processing_queue' });
coverPhotoSchema.index({ 'usage.popularityScore': -1, status: 1 }, { name: 'idx_popularity' });
coverPhotoSchema.index({ 'quality.qualityScore.overall': -1, status: 1 }, { name: 'idx_quality' });
coverPhotoSchema.index({ 'scheduling.publishAt': 1, 'scheduling.isScheduled': 1 }, { name: 'idx_scheduling' });
coverPhotoSchema.index({ 'moderation.status': 1, createdAt: -1 }, { name: 'idx_moderation' });
coverPhotoSchema.index({ templateId: 1, status: 1 }, { name: 'idx_template' });
coverPhotoSchema.index({ tags: 1, status: 1, 'accessControl.visibility': 1 }, { name: 'idx_tags' });
coverPhotoSchema.index({ source: 1, createdAt: -1 }, { name: 'idx_source_analytics' });
coverPhotoSchema.index({ 'analytics.performanceScore': -1, status: 1 }, { name: 'idx_performance' });
coverPhotoSchema.index({ 'metadata.aspectRatio': 1, category: 1, status: 1 }, { name: 'idx_aspect_ratio' });
coverPhotoSchema.index({ 'aiAnalysis.style': 1, 'aiAnalysis.mood': 1, status: 1 }, { name: 'idx_style_mood' });
coverPhotoSchema.index({ 'accessControl.organizationId': 1, status: 1 }, { name: 'idx_organization' });
coverPhotoSchema.index({ 'accessControl.allowedUsers': 1, status: 1 }, { name: 'idx_allowed_users' });
coverPhotoSchema.index({ 'accessControl.allowedGroups': 1, status: 1 }, { name: 'idx_allowed_groups' });
coverPhotoSchema.index({ lastUsedAt: -1, userId: 1 }, { name: 'idx_recent_usage' });
coverPhotoSchema.index({ 'usage.totalViews': -1, 'usage.likes': -1, status: 1 }, { name: 'idx_engagement' });
coverPhotoSchema.index({
    title: 'text',
    description: 'text',
    tags: 'text',
    'aiAnalysis.tags': 'text',
    'sourceReference.aiPrompt': 'text'
}, {
    weights: {
        title: 10,
        tags: 8,
        'aiAnalysis.tags': 6,
        description: 4,
        'sourceReference.aiPrompt': 2
    },
    name: 'idx_fulltext_search'
});

// ===========================
// PRE/POST HOOKS
// ===========================
coverPhotoSchema.pre('save', function (next) {
    if (!this.coverId) {
        this.coverId = this.generateCoverId();
    }

    if (this.metadata?.width && this.metadata?.height) {
        this.metadata.aspectRatio = Math.round((this.metadata.width / this.metadata.height) * 100) / 100;
        this.metadata.orientation = this.metadata.width > this.metadata.height ? 'landscape' :
            this.metadata.width < this.metadata.height ? 'portrait' : 'square';
    }

    this.calculatePopularityScore();

    if (this.isModified() && !this.isNew) {
        this.cacheVersion += 1;
    }

    this.updatedAt = new Date();
    next();
});

coverPhotoSchema.pre(/^find/, function (next) {
    if (!this.getQuery().status) {
        this.where({ status: { $ne: 'deleted' } });
    }
    next();
});

coverPhotoSchema.pre(['findOneAndUpdate', 'updateOne', 'updateMany'], function (next) {
    this.set({ updatedAt: new Date(), cacheVersion: { $inc: 1 } });
    next();
});

// ===========================
// INSTANCE METHODS
// ===========================
coverPhotoSchema.methods.generateCoverId = function () {
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substring(2, 8);
    return `cvr_${timestamp}${random}`;
};

coverPhotoSchema.methods.calculatePopularityScore = function () {
    const views = this.usage.totalViews || 0;
    const likes = this.usage.likes || 0;
    const downloads = this.usage.downloads || 0;
    const shares = this.usage.shares || 0;
    const quality = this.quality.qualityScore.overall || 0;

    const ageInDays = (Date.now() - this.createdAt) / (1000 * 60 * 60 * 24);
    const ageFactor = Math.max(0.1, 1 - (ageInDays / 365)); // Decay over year

    const baseScore = (views * 0.1) + (likes * 2) + (downloads * 5) + (shares * 10) + (quality * 3);
    this.usage.popularityScore = Math.min(100, Math.round(baseScore * ageFactor));

    return this.usage.popularityScore;
};

coverPhotoSchema.methods.incrementViews = async function (userId = null, source = 'direct') {
    const now = new Date();
    const hourAgo = new Date(now - 60 * 60 * 1000);

    // Prevent view spam
    if (!this.usage.lastViewedAt || this.usage.lastViewedAt < hourAgo) {
        this.usage.totalViews += 1;
        this.usage.lastViewedAt = now;
        this.lastUsedAt = now;

        // Add to view history (keep last 100)
        this.usage.viewHistory.unshift({ userId, viewedAt: now, source });
        if (this.usage.viewHistory.length > 100) {
            this.usage.viewHistory = this.usage.viewHistory.slice(0, 100);
        }

        // Update weekly views
        const weekStart = new Date(now);
        weekStart.setDate(weekStart.getDate() - weekStart.getDay());
        weekStart.setHours(0, 0, 0, 0);

        const weeklyView = this.analytics.weeklyViews.find(w =>
            w.week.getTime() === weekStart.getTime()
        );

        if (weeklyView) {
            weeklyView.views += 1;
        } else {
            this.analytics.weeklyViews.push({ week: weekStart, views: 1, uniqueViews: 1 });
            if (this.analytics.weeklyViews.length > 12) {
                this.analytics.weeklyViews = this.analytics.weeklyViews.slice(-12);
            }
        }

        this.calculatePopularityScore();
        this.cacheVersion += 1;
        return this.save({ validateBeforeSave: false });
    }
};

coverPhotoSchema.methods.getPublicData = function () {
    const cover = this.toObject();

    // Remove sensitive data
    delete cover.processing.errorMessage;
    delete cover.usage.viewHistory;
    delete cover.moderation.autoModeration;
    delete cover.backup;

    // Simplify analytics for public view
    cover.analytics = {
        performanceScore: cover.analytics.performanceScore,
        totalViews: cover.usage.totalViews,
        likes: cover.usage.likes
    };

    return cover;
};

coverPhotoSchema.methods.createVersion = function (url, changes = '', qualityData = {}) {
    const versionId = `v${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;

    // Mark current versions as inactive
    this.versions.forEach(v => v.isActive = false);

    this.versions.push({
        versionId,
        url,
        changes,
        isActive: true,
        quality: qualityData,
        createdAt: new Date()
    });

    // Keep only last 10 versions
    if (this.versions.length > 10) {
        this.versions = this.versions.slice(-10);
    }

    return versionId;
};

coverPhotoSchema.methods.updateQualityMetrics = function (metrics) {
    this.quality.qualityScore = {
        overall: metrics.overall || this.quality.qualityScore.overall,
        sharpness: metrics.sharpness || this.quality.qualityScore.sharpness,
        noise: metrics.noise || this.quality.qualityScore.noise,
        contrast: metrics.contrast || this.quality.qualityScore.contrast
    };
    this.quality.lastAssessedAt = new Date();
    this.cacheVersion += 1;
    return this.save({ validateBeforeSave: false });
};

// ===========================
// STATIC METHODS
// ===========================
coverPhotoSchema.statics.findByCategory = function (category, options = {}) {
    const {
        page = 1,
        limit = 20,
        sortBy = 'popularity',
        userId,
        visibility = 'public'
    } = options;

    const query = {
        category,
        status: 'active',
        'processing.status': 'completed',
        'moderation.status': 'approved'
    };

    if (visibility === 'public') {
        query['accessControl.visibility'] = 'public';
    } else if (visibility === 'restricted') {
        query['accessControl.visibility'] = 'restricted';
        query.$or = [
            { 'accessControl.allowedUsers': userId },
            { 'accessControl.allowedGroups': { $in: options.allowedGroups || [] } }
        ];
    } else if (userId) {
        query.$or = [
            { 'accessControl.visibility': 'public' },
            { userId },
            { 'accessControl.visibility': 'restricted', 'accessControl.allowedUsers': userId },
            { 'accessControl.visibility': 'restricted', 'accessControl.allowedGroups': { $in: options.allowedGroups || [] } }
        ];
    }

    let sortOption = {};
    switch (sortBy) {
        case 'recent':
            sortOption = { createdAt: -1 };
            break;
        case 'popular':
            sortOption = { 'usage.popularityScore': -1, 'usage.totalViews': -1 };
            break;
        case 'quality':
            sortOption = { 'quality.qualityScore.overall': -1 };
            break;
        default:
            sortOption = { 'usage.popularityScore': -1, createdAt: -1 };
    }

    const skip = (page - 1) * limit;

    return this.find(query)
        .populate({
            path: 'templateId',
            model: 'Template',
            select: 'name description'
        })
        .sort(sortOption)
        .skip(skip)
        .limit(limit)
        .populate({
            path: 'templateId',
            model: 'Template',
            select: 'name description'
        })
        .unwind({
            path: '$template',
            preserveNullAndEmptyArrays: true
        })
        .sort(sortOption)
        .skip(skip)
        .limit(limit)
        .select('-usage.viewHistory -processing.errorMessage -moderation.autoModeration')
        .cache({ key: `covers:category:${category}:${page}:${limit}:${sortBy}:${visibility}` })
        .lean();
};

coverPhotoSchema.statics.searchCovers = function (searchQuery, filters = {}) {
    const {
        categories = [],
        styles = [],
        moods = [],
        minQuality = 0,
        aspectRatios = [],
        colors = [],
        page = 1,
        limit = 20,
        userId,
        allowedGroups = []
    } = filters;

    const pipeline = [];

    const matchStage = {
        status: 'active',
        'processing.status': 'completed',
        'moderation.status': 'approved'
    };

    if (searchQuery && searchQuery.trim()) {
        matchStage.$text = { $search: searchQuery.trim() };
    }

    if (categories.length > 0) {
        matchStage.category = { $in: categories };
    }

    if (styles.length > 0) {
        matchStage['aiAnalysis.style'] = { $in: styles };
    }

    if (moods.length > 0) {
        matchStage['aiAnalysis.mood'] = { $in: moods };
    }

    if (minQuality > 0) {
        matchStage['quality.qualityScore.overall'] = { $gte: minQuality };
    }

    if (aspectRatios.length > 0) {
        matchStage['metadata.aspectRatio'] = { $in: aspectRatios };
    }

    // Visibility filter
    if (userId) {
        matchStage.$or = [
            { 'accessControl.visibility': 'public' },
            { userId },
            { 'accessControl.visibility': 'restricted', 'accessControl.allowedUsers': userId },
            { 'accessControl.visibility': 'restricted', 'accessControl.allowedGroups': { $in: allowedGroups } }
        ];
    } else {
        matchStage['accessControl.visibility'] = 'public';
    }

    pipeline.push({ $match: matchStage });

    // Join with templates
    pipeline.push({
        $lookup: {
            from: 'templates',
            localField: 'templateId',
            foreignField: 'templateId',
            as: 'template'
        }
    });
    pipeline.push({
        $unwind: {
            path: '$template',
            preserveNullAndEmptyArrays: true
        }
    });

    // Add relevance scoring
    pipeline.push({
        $addFields: {
            relevanceScore: {
                $add: [
                    { $multiply: ['$usage.popularityScore', 0.4] },
                    { $multiply: ['$quality.qualityScore.overall', 0.3] },
                    { $multiply: ['$usage.totalViews', 0.0001] },
                    searchQuery && searchQuery.trim() ? { $meta: 'textScore' } : 0
                ]
            }
        }
    });

    pipeline.push({ $sort: { relevanceScore: -1, createdAt: -1 } });

    const skip = (page - 1) * limit;
    pipeline.push({ $skip: skip });
    pipeline.push({ $limit: limit });

    pipeline.push({
        $project: {
            coverId: 1,
            userId: 1,
            title: 1,
            description: 1,
            category: 1,
            'metadata.width': 1,
            'metadata.height': 1,
            'metadata.aspectRatio': 1,
            'metadata.format': 1,
            'processing.optimized.url': 1,
            'processing.thumbnails': 1,
            'aiAnalysis.dominantColors': { $slice: ['$aiAnalysis.dominantColors', 3] },
            'aiAnalysis.style': 1,
            'aiAnalysis.mood': 1,
            'quality.qualityScore.overall': 1,
            'usage.totalViews': 1,
            'usage.likes': 1,
            'usage.popularityScore': 1,
            tags: { $slice: ['$tags', 5] },
            createdAt: 1,
            relevanceScore: 1,
            'template.title': 1,
            'template.category': 1
        }
    });

    return this.aggregate(pipeline).cache({ key: `search:${searchQuery}:${JSON.stringify(filters)}` });
};

coverPhotoSchema.statics.getTrendingCovers = function (timeframe = 7, limit = 20) {
    const daysAgo = new Date();
    daysAgo.setDate(daysAgo.getDate() - timeframe);

    return this.find({
        status: 'active',
        'processing.status': 'completed',
        'moderation.status': 'approved',
        'accessControl.visibility': 'public',
        createdAt: { $gte: daysAgo },
        'usage.totalViews': { $gte: 5 }
    })
        .sort({
            'usage.popularityScore': -1,
            'usage.totalViews': -1,
            createdAt: -1
        })
        .limit(limit)
        .select('coverId title category processing.optimized.url processing.thumbnails usage.totalViews usage.likes aiAnalysis.style aiAnalysis.mood quality.qualityScore.overall')
        .cache({ key: `trending:${timeframe}:${limit}` })
        .lean();
};

coverPhotoSchema.statics.getRecommendations = function (userId, userPreferences = {}) {
    const { categories = [], styles = [], colors = [] } = userPreferences;

    return this.aggregate([
        {
            $match: {
                status: 'active',
                'processing.status': 'completed',
                'moderation.status': 'approved',
                'accessControl.visibility': 'public',
                userId: { $ne: userId }
            }
        },
        {
            $lookup: {
                from: 'templates',
                localField: 'templateId',
                foreignField: 'templateId',
                as: 'template'
            }
        },
        {
            $unwind: {
                path: '$template',
                preserveNullAndEmptyArrays: true
            }
        },
        {
            $addFields: {
                preferenceScore: {
                    $add: [
                        categories.length > 0 ? { $cond: [{ $in: ['$category', categories] }, 20, 0] } : 0,
                        styles.length > 0 ? { $cond: [{ $in: ['$aiAnalysis.style', styles] }, 15, 0] } : 0,
                        { $multiply: ['$usage.popularityScore', 0.5] },
                        { $multiply: ['$quality.qualityScore.overall', 0.3] }
                    ]
                }
            }
        },
        {
            $sort: {
                preferenceScore: -1,
                'usage.popularityScore': -1
            }
        },
        {
            $limit: 20
        },
        {
            $project: {
                coverId: 1,
                title: 1,
                category: 1,
                'processing.optimized.url': 1,
                'processing.thumbnails.medium.url': 1,
                'aiAnalysis.style': 1,
                'aiAnalysis.mood': 1,
                'usage.totalViews': 1,
                'quality.qualityScore.overall': 1,
                preferenceScore: 1,
                'template.title': 1,
                'template.category': 1
            }
        }
    ]).cache({ key: `recommendations:${userId}:${JSON.stringify(userPreferences)}` });
};

// Export model
const CoverPhoto = mongoose.model('CoverPhoto', coverPhotoSchema);

CoverPhoto.createCollection({
    capped: false,
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: ["coverId", "userId", "title", "category", "metadata", "processing"],
            properties: {
                coverId: {
                    bsonType: "string",
                    description: "Cover ID is required and must be a string"
                },
                userId: {
                    bsonType: "string",
                    description: "User ID is required and must be a string"
                },
                title: {
                    bsonType: "string",
                    maxLength: 200,
                    description: "Title is required with max length 200"
                },
                category: {
                    bsonType: "string",
                    enum: ['nature', 'abstract', 'business', 'technology', 'art', 'photography', 'design', 'minimal', 'colorful', 'dark', 'light'],
                    description: "Category must be from predefined list"
                }
            }
        }
    }
}).catch(() => {
    // Collection might already exist
});

export default CoverPhoto;