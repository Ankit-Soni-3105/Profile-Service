import mongoose from 'mongoose';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import validator from 'validator';

// Custom validation functions
const validateContent = (content) => {
    if (!content || typeof content !== 'string') return false;
    const trimmed = content.trim();
    return trimmed.length >= 10 && trimmed.length <= 5000;
};

const validateUserId = (userId) => {
    return validator.isUUID(userId) || validator.isMongoId(userId);
};

const validateEmail = (email) => {
    return validator.isEmail(email);
};

const validateURL = (url) => {
    return !url || validator.isURL(url);
};

const validatePhoneNumber = (phone) => {
    return !phone || validator.isMobilePhone(phone);
};

// Sub-schemas for better organization
const versionSchema = new mongoose.Schema({
    _id: {
        type: String,
        default: () => uuidv4(),
    },
    versionNumber: {
        type: Number,
        required: true,
        min: 1,
    },
    content: {
        type: String,
        required: true,
        validate: [validateContent, 'Content must be between 10-5000 characters'],
        trim: true,
    },
    title: {
        type: String,
        required: true,
        maxlength: 200,
        trim: true,
    },
    changes: {
        type: String,
        maxlength: 1000,
        trim: true,
    },
    changeType: {
        type: String,
        enum: ['create', 'edit', 'grammar_fix', 'ai_enhance', 'template_apply', 'translate'],
        required: true,
    },
    editedBy: {
        userId: String,
        userType: {
            type: String,
            enum: ['owner', 'collaborator', 'ai', 'system'],
            default: 'owner',
        },
    },
    stats: {
        characterCount: {
            type: Number,
            min: 0,
        },
        wordCount: {
            type: Number,
            min: 0,
        },
        paragraphCount: {
            type: Number,
            min: 0,
        },
        sentenceCount: {
            type: Number,
            min: 0,
        },
    },
    quality: {
        grammarScore: {
            type: Number,
            min: 0,
            max: 100,
            default: 0,
        },
        readabilityScore: {
            type: Number,
            min: 0,
            max: 100,
            default: 0,
        },
        seoScore: {
            type: Number,
            min: 0,
            max: 100,
            default: 0,
        },
        engagementScore: {
            type: Number,
            min: 0,
            max: 100,
            default: 0,
        },
    },
    createdAt: {
        type: Date,
        default: Date.now,
        index: true,
    },
    isActive: {
        type: Boolean,
        default: false,
    },
}, { _id: true });

const analyticsSchema = new mongoose.Schema({
    views: {
        total: {
            type: Number,
            default: 0,
            min: 0,
        },
        unique: {
            type: Number,
            default: 0,
            min: 0,
        },
        today: {
            type: Number,
            default: 0,
            min: 0,
        },
        thisWeek: {
            type: Number,
            default: 0,
            min: 0,
        },
        thisMonth: {
            type: Number,
            default: 0,
            min: 0,
        },
    },
    interactions: {
        likes: {
            type: Number,
            default: 0,
            min: 0,
        },
        shares: {
            type: Number,
            default: 0,
            min: 0,
        },
        comments: {
            type: Number,
            default: 0,
            min: 0,
        },
        bookmarks: {
            type: Number,
            default: 0,
            min: 0,
        },
    },
    performance: {
        averageReadTime: {
            type: Number,
            default: 0,
            min: 0, // in seconds
        },
        bounceRate: {
            type: Number,
            default: 0,
            min: 0,
            max: 100,
        },
        completionRate: {
            type: Number,
            default: 0,
            min: 0,
            max: 100,
        },
        engagementRate: {
            type: Number,
            default: 0,
            min: 0,
            max: 100,
        },
    },
    traffic: {
        sources: [{
            source: {
                type: String,
                enum: ['direct', 'linkedin', 'google', 'social', 'referral', 'email'],
            },
            count: {
                type: Number,
                default: 0,
                min: 0,
            },
        }],
        devices: [{
            device: {
                type: String,
                enum: ['mobile', 'desktop', 'tablet'],
            },
            count: {
                type: Number,
                default: 0,
                min: 0,
            },
        }],
        locations: [{
            country: String,
            city: String,
            count: {
                type: Number,
                default: 0,
                min: 0,
            },
        }],
    },
    timeline: [{
        date: {
            type: Date,
            required: true,
        },
        views: {
            type: Number,
            default: 0,
            min: 0,
        },
        interactions: {
            type: Number,
            default: 0,
            min: 0,
        },
    }],
    lastCalculated: {
        type: Date,
        default: Date.now,
    },
}, { _id: false });

const sharingSchema = new mongoose.Schema({
    isPublic: {
        type: Boolean,
        default: false,
        index: true,
    },
    visibility: {
        type: String,
        enum: ['private', 'public', 'unlisted', 'network_only'],
        default: 'private',
        index: true,
    },
    allowComments: {
        type: Boolean,
        default: true,
    },
    allowSharing: {
        type: Boolean,
        default: true,
    },
    collaborators: [{
        userId: {
            type: String,
            required: true,
            validate: [validateUserId, 'Invalid user ID'],
        },
        email: {
            type: String,
            validate: [validateEmail, 'Invalid email format'],
        },
        permission: {
            type: String,
            enum: ['view', 'comment', 'edit', 'admin'],
            default: 'view',
        },
        status: {
            type: String,
            enum: ['pending', 'accepted', 'declined', 'revoked'],
            default: 'pending',
        },
        invitedAt: {
            type: Date,
            default: Date.now,
        },
        respondedAt: Date,
        lastAccessedAt: Date,
        permissions: {
            canEdit: {
                type: Boolean,
                default: false,
            },
            canDelete: {
                type: Boolean,
                default: false,
            },
            canShare: {
                type: Boolean,
                default: false,
            },
            canViewAnalytics: {
                type: Boolean,
                default: false,
            },
        },
    }],
    shareLinks: [{
        _id: {
            type: String,
            default: () => crypto.randomBytes(16).toString('hex'),
        },
        url: String,
        expiresAt: Date,
        accessCount: {
            type: Number,
            default: 0,
            min: 0,
        },
        maxAccess: {
            type: Number,
            min: 1,
        },
        password: String, // hashed
        createdAt: {
            type: Date,
            default: Date.now,
        },
        isActive: {
            type: Boolean,
            default: true,
        },
    }],
}, { _id: false });

const seoSchema = new mongoose.Schema({
    metaTitle: {
        type: String,
        maxlength: 60,
        trim: true,
    },
    metaDescription: {
        type: String,
        maxlength: 160,
        trim: true,
    },
    keywords: [{
        keyword: {
            type: String,
            maxlength: 50,
            trim: true,
        },
        density: {
            type: Number,
            min: 0,
            max: 100,
        },
        relevance: {
            type: Number,
            min: 0,
            max: 100,
        },
    }],
    canonicalUrl: {
        type: String,
        validate: [validateURL, 'Invalid URL format'],
    },
    structuredData: {
        type: mongoose.Schema.Types.Mixed,
    },
    socialMedia: {
        ogTitle: {
            type: String,
            maxlength: 60,
        },
        ogDescription: {
            type: String,
            maxlength: 160,
        },
        ogImage: {
            type: String,
            validate: [validateURL, 'Invalid URL format'],
        },
        twitterCard: {
            type: String,
            enum: ['summary', 'summary_large_image', 'app', 'player'],
            default: 'summary',
        },
    },
    lastOptimized: {
        type: Date,
        default: Date.now,
    },
}, { _id: false });

const aiSchema = new mongoose.Schema({
    isAiGenerated: {
        type: Boolean,
        default: false,
        index: true,
    },
    generationDetails: {
        model: {
            type: String,
            maxlength: 100,
        },
        version: {
            type: String,
            maxlength: 20,
        },
        prompt: {
            type: String,
            maxlength: 2000,
        },
        temperature: {
            type: Number,
            min: 0,
            max: 2,
        },
        confidence: {
            type: Number,
            min: 0,
            max: 1,
        },
        processingTime: {
            type: Number,
            min: 0, // in milliseconds
        },
    },
    enhancements: [{
        type: {
            type: String,
            enum: ['grammar', 'tone', 'structure', 'keywords', 'readability', 'engagement'],
            required: true,
        },
        applied: {
            type: Boolean,
            default: false,
        },
        suggestion: {
            type: String,
            maxlength: 1000,
        },
        confidence: {
            type: Number,
            min: 0,
            max: 1,
        },
        createdAt: {
            type: Date,
            default: Date.now,
        },
    }],
    translations: [{
        language: {
            type: String,
            required: true,
            enum: ['en', 'hi', 'es', 'fr', 'de', 'pt', 'it', 'ja', 'ko', 'zh', 'ar', 'ru'],
        },
        content: {
            type: String,
            required: true,
            maxlength: 5000,
        },
        quality: {
            type: Number,
            min: 0,
            max: 100,
        },
        translatedAt: {
            type: Date,
            default: Date.now,
        },
        model: String,
    }],
    feedback: {
        userRating: {
            type: Number,
            min: 1,
            max: 5,
        },
        userFeedback: {
            type: String,
            maxlength: 1000,
        },
        improvementSuggestions: [{
            suggestion: String,
            priority: {
                type: String,
                enum: ['low', 'medium', 'high', 'critical'],
            },
            status: {
                type: String,
                enum: ['pending', 'in_progress', 'completed', 'dismissed'],
                default: 'pending',
            },
        }],
    },
}, { _id: false });

const complianceSchema = new mongoose.Schema({
    dataProcessing: {
        consent: {
            type: Boolean,
            required: true,
            default: false,
        },
        consentDate: Date,
        purposes: [{
            type: String,
            enum: ['analytics', 'marketing', 'personalization', 'support'],
        }],
        retentionPeriod: {
            type: Number,
            default: 365, // days
        },
        dataMinimization: {
            type: Boolean,
            default: true,
        },
    },
    privacy: {
        encryptionLevel: {
            type: String,
            enum: ['none', 'basic', 'advanced'],
            default: 'basic',
        },
        accessLevel: {
            type: String,
            enum: ['owner_only', 'team', 'organization', 'public'],
            default: 'owner_only',
        },
        dataLocation: {
            type: String,
            enum: ['us', 'eu', 'asia', 'global'],
            default: 'global',
        },
    },
    audit: {
        createdBy: {
            userId: String,
            ip: String,
            userAgent: String,
            location: {
                country: String,
                city: String,
                timezone: String,
            },
        },
        lastModifiedBy: {
            userId: String,
            ip: String,
            userAgent: String,
            timestamp: Date,
        },
        accessLog: [{
            userId: String,
            action: {
                type: String,
                enum: ['view', 'edit', 'share', 'download', 'delete'],
            },
            ip: String,
            userAgent: String,
            timestamp: {
                type: Date,
                default: Date.now,
            },
            success: {
                type: Boolean,
                default: true,
            },
        }],
    },
}, { _id: false });

// Main Summary Schema
const summarySchema = new mongoose.Schema({
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
    title: {
        type: String,
        required: [true, 'Title is required'],
        maxlength: [200, 'Title cannot exceed 200 characters'],
        minlength: [3, 'Title must be at least 3 characters'],
        trim: true,
        index: true,
    },
    content: {
        type: String,
        required: [true, 'Content is required'],
        validate: [validateContent, 'Content must be between 10-5000 characters'],
        trim: true,
    },
    slug: {
        type: String,
        unique: true,
        sparse: true,
        index: true,
    },
    templateId: {
        type: String,
        ref: 'SummaryTemplate',
        index: true,
    },
    category: {
        type: String,
        enum: [
            'professional', 'creative', 'academic', 'entrepreneurial', 'technical',
            'sales', 'marketing', 'leadership', 'student', 'freelancer', 'consultant'
        ],
        index: true,
    },
    tags: [{
        type: String,
        maxlength: 30,
        trim: true,
    }],
    metadata: {
        originalLanguage: {
            type: String,
            default: 'en',
            enum: ['en', 'hi', 'es', 'fr', 'de', 'pt', 'it', 'ja', 'ko', 'zh', 'ar', 'ru'],
            index: true,
        },
        industry: {
            type: String,
            maxlength: 100,
            trim: true,
            index: true,
        },
        jobTitle: {
            type: String,
            maxlength: 100,
            trim: true,
        },
        company: {
            type: String,
            maxlength: 100,
            trim: true,
        },
        experienceLevel: {
            type: String,
            enum: ['entry', 'junior', 'mid', 'senior', 'lead', 'executive', 'c_level', 'founder', 'student', 'fresher'],
            index: true,
        },
        targetAudience: {
            type: String,
            enum: ['recruiters', 'clients', 'peers', 'general', 'investors', 'students'],
        },
        location: {
            country: {
                type: String,
                maxlength: 50,
            },
            city: {
                type: String,
                maxlength: 50,
            },
            timezone: {
                type: String,
                maxlength: 50,
            },
        },
        contact: {
            email: {
                type: String,
                validate: [validateEmail, 'Invalid email format'],
            },
            phone: {
                type: String,
                validate: [validatePhoneNumber, 'Invalid phone number'],
            },
            website: {
                type: String,
                validate: [validateURL, 'Invalid website URL'],
            },
            linkedinUrl: {
                type: String,
                validate: [validateURL, 'Invalid LinkedIn URL'],
            },
            portfolioUrl: {
                type: String,
                validate: [validateURL, 'Invalid portfolio URL'],
            },
        },
    },
    status: {
        type: String,
        enum: ['draft', 'review', 'active', 'archived', 'deleted', 'suspended'],
        default: 'draft',
        index: true,
    },
    priority: {
        type: String,
        enum: ['low', 'normal', 'high', 'urgent'],
        default: 'normal',
    },
    versions: [versionSchema],
    analytics: analyticsSchema,
    sharing: sharingSchema,
    seo: seoSchema,
    ai: aiSchema,
    compliance: complianceSchema,
    settings: {
        autoSave: {
            type: Boolean,
            default: true,
        },
        autoBackup: {
            type: Boolean,
            default: true,
        },
        versionControl: {
            type: Boolean,
            default: true,
        },
        maxVersions: {
            type: Number,
            default: 50,
            min: 1,
            max: 100,
        },
        notifications: {
            email: {
                type: Boolean,
                default: true,
            },
            push: {
                type: Boolean,
                default: false,
            },
            sms: {
                type: Boolean,
                default: false,
            },
        },
        privacy: {
            showInSearch: {
                type: Boolean,
                default: false,
            },
            allowIndexing: {
                type: Boolean,
                default: false,
            },
            requirePassword: {
                type: Boolean,
                default: false,
            },
        },
    },
    integrations: {
        linkedin: {
            connected: {
                type: Boolean,
                default: false,
            },
            profileId: String,
            lastSync: Date,
            autoSync: {
                type: Boolean,
                default: false,
            },
        },
        resume: {
            connected: {
                type: Boolean,
                default: false,
            },
            documentId: String,
            lastSync: Date,
        },
        portfolio: {
            connected: {
                type: Boolean,
                default: false,
            },
            websiteUrl: String,
            lastSync: Date,
        },
    },
    scheduling: {
        publishAt: Date,
        unpublishAt: Date,
        reminderAt: Date,
        reviewAt: Date,
        isScheduled: {
            type: Boolean,
            default: false,
            index: true,
        },
    },
    editorState: {
        type: Map,
        of: {
            cursorPosition: { type: Number, default: 0 },
            selectionRange: {
                start: { type: Number, default: 0 },
                end: { type: Number, default: 0 },
            },
            updatedAt: { type: Date, default: Date.now },
        },
    },
    quality: {
        overallScore: {
            type: Number,
            min: 0,
            max: 100,
            default: 0,
        },
        scores: {
            grammar: {
                type: Number,
                min: 0,
                max: 100,
                default: 0,
            },
            readability: {
                type: Number,
                min: 0,
                max: 100,
                default: 0,
            },
            engagement: {
                type: Number,
                min: 0,
                max: 100,
                default: 0,
            },
            seo: {
                type: Number,
                min: 0,
                max: 100,
                default: 0,
            },
            uniqueness: {
                type: Number,
                min: 0,
                max: 100,
                default: 0,
            },
        },
        issues: [{
            type: {
                type: String,
                enum: ['grammar', 'spelling', 'style', 'structure', 'length', 'keyword'],
                required: true,
            },
            severity: {
                type: String,
                enum: ['low', 'medium', 'high', 'critical'],
                required: true,
            },
            message: {
                type: String,
                required: true,
                maxlength: 500,
            },
            position: {
                start: Number,
                end: Number,
            },
            suggestion: {
                type: String,
                maxlength: 500,
            },
            fixed: {
                type: Boolean,
                default: false,
            },
            createdAt: {
                type: Date,
                default: Date.now,
            },
        }],
        lastAnalyzed: {
            type: Date,
            default: Date.now,
        },
    },
    flags: {
        isDeleted: {
            type: Boolean,
            default: false,
            index: true,
        },
        isBlocked: {
            type: Boolean,
            default: false,
            index: true,
        },
        isFeatured: {
            type: Boolean,
            default: false,
            index: true,
        },
        isPremium: {
            type: Boolean,
            default: false,
            index: true,
        },
        needsReview: {
            type: Boolean,
            default: false,
            index: true,
        },
    },
    cache: {
        renderedHtml: String,
        searchableText: String,
        thumbnailUrl: String,
        lastCached: Date,
    },
}, {
    timestamps: true,
    collection: 'summaries',
    versionKey: false,
    minimize: false,
    strict: true,
});

// Compound Indexes for Scale (optimized for 1M+ users)
summarySchema.index({ userId: 1, status: 1, createdAt: -1 }); // Primary user queries
summarySchema.index({ userId: 1, 'flags.isDeleted': 1, updatedAt: -1 }); // User's non-deleted content
summarySchema.index({ status: 1, 'sharing.isPublic': 1, createdAt: -1 }); // Public content discovery
summarySchema.index({ templateId: 1, status: 1, createdAt: -1 }); // Template usage
summarySchema.index({ 'metadata.industry': 1, 'metadata.experienceLevel': 1, status: 1 }); // Industry analytics
summarySchema.index({ category: 1, status: 1, 'quality.overallScore': -1 }); // Category-based search
summarySchema.index({ 'scheduling.isScheduled': 1, 'scheduling.publishAt': 1 }); // Scheduled content
summarySchema.index({ 'analytics.views.total': -1, status: 1 }); // Popular content
summarySchema.index({ 'flags.isFeatured': 1, 'quality.overallScore': -1 }); // Featured content
summarySchema.index({ 'flags.needsReview': 1, createdAt: 1 }); // Admin review queue

// Partial indexes for better performance
summarySchema.index({ 'ai.isAiGenerated': 1 }, { partialFilterExpression: { 'ai.isAiGenerated': true } });
summarySchema.index({ 'sharing.isPublic': 1 }, { partialFilterExpression: { 'sharing.isPublic': true } });
summarySchema.index({ 'flags.isPremium': 1 }, { partialFilterExpression: { 'flags.isPremium': true } });

// Text search index with weights
summarySchema.index({
    title: 'text',
    content: 'text',
    tags: 'text',
    'metadata.industry': 'text',
    'metadata.jobTitle': 'text',
    'cache.searchableText': 'text'
}, {
    weights: {
        title: 10,
        content: 5,
        tags: 8,
        'metadata.industry': 3,
        'metadata.jobTitle': 3,
        'cache.searchableText': 1
    },
    name: 'summary_search_index'
});

// Geospatial index for location-based queries
summarySchema.index({ 'metadata.location': '2dsphere' });

// TTL index for auto-cleanup of deleted items
summarySchema.index({ deletedAt: 1 }, {
    expireAfterSeconds: 2592000, // 30 days
    partialFilterExpression: { 'flags.isDeleted': true }
});

// Virtual properties
summarySchema.virtual('url').get(function () {
    return `/summary/${this.slug || this._id}`;
});

summarySchema.virtual('currentVersion').get(function () {
    if (!this.versions || this.versions.length === 0) return null;
    return this.versions.find(v => v.isActive) || this.versions[this.versions.length - 1];
});

summarySchema.virtual('wordCount').get(function () {
    return this.content ? this.content.trim().split(/\s+/).length : 0;
});

summarySchema.virtual('readingTime').get(function () {
    const wordsPerMinute = 200;
    return Math.ceil(this.wordCount / wordsPerMinute);
});

summarySchema.virtual('isOwner').get(function () {
    return (userId) => this.userId === userId;
});

// Instance Methods
summarySchema.methods.incrementViews = function (unique = false) {
    this.analytics.views.total += 1;
    if (unique) this.analytics.views.unique += 1;

    const today = new Date();
    today.setHours(0, 0, 0, 0);

    if (this.analytics.views.lastViewDate?.getTime() !== today.getTime()) {
        this.analytics.views.today = 1;
        this.analytics.views.lastViewDate = today;
    } else {
        this.analytics.views.today += 1;
    }

    return this.save();
};

summarySchema.methods.createVersion = function (content, title, changeType = 'edit', editedBy = null) {
    const newVersion = {
        versionNumber: this.versions.length + 1,
        content: content,
        title: title || this.title,
        changeType: changeType,
        editedBy: editedBy,
        isActive: true,
        stats: {
            characterCount: content.length,
            wordCount: content.trim().split(/\s+/).length,
            paragraphCount: content.split('\n\n').length,
            sentenceCount: content.split(/[.!?]+/).length - 1,
        }
    };

    // Deactivate previous versions
    this.versions.forEach(v => v.isActive = false);

    // Add new version
    this.versions.push(newVersion);

    // Update main content
    this.content = content;
    this.title = title || this.title;

    // Limit versions
    if (this.versions.length > this.settings.maxVersions) {
        this.versions = this.versions.slice(-this.settings.maxVersions);
    }

    return this.save();
};

summarySchema.methods.calculateQualityScore = function () {
    const content = this.content || '';
    const title = this.title || '';

    // Grammar score (placeholder - integrate with grammar service)
    this.quality.scores.grammar = Math.min(100, Math.max(0, 100 - (content.match(/\b(the the|and and|or or)\b/gi) || []).length * 10));

    // Readability score (Flesch Reading Ease approximation)
    const sentences = content.split(/[.!?]+/).length - 1;
    const words = content.trim().split(/\s+/).length;
    const syllables = content.toLowerCase().match(/[aeiouy]+/g)?.length || words;

    if (sentences > 0 && words > 0) {
        this.quality.scores.readability = Math.max(0, Math.min(100,
            206.835 - (1.015 * (words / sentences)) - (84.6 * (syllables / words))
        ));
    }

    // Engagement score based on content structure
    const hasCallToAction = /\b(contact|connect|reach|hire|available)\b/i.test(content);
    const hasPersonalTouch = /\b(I|my|me)\b/i.test(content);
    const hasAchievements = /\b(achieved|accomplished|successful|led|managed)\b/i.test(content);

    this.quality.scores.engagement =
        (hasCallToAction ? 30 : 0) +
        (hasPersonalTouch ? 25 : 0) +
        (hasAchievements ? 25 : 0) +
        (Math.min(20, words / 25)); // Length bonus up to 20 points

    // SEO score
    const titleWords = title.toLowerCase().split(/\s+/);
    const contentLower = content.toLowerCase();
    const keywordDensity = titleWords.reduce((acc, word) => {
        if (word.length > 3) {
            const regex = new RegExp(`\\b${word}\\b`, 'gi');
            const matches = contentLower.match(regex);
            return acc + (matches ? matches.length : 0);
        }
        return acc;
    }, 0);

    this.quality.scores.seo = Math.min(100,
        (title.length >= 10 && title.length <= 60 ? 30 : 0) + // Title length
        (content.length >= 150 ? 20 : 0) +                   // Content length
        (this.seo.metaDescription && this.seo.metaDescription.length >= 50 && this.seo.metaDescription.length <= 160 ? 20 : 0) + // Meta description
        (this.seo.keywords && this.seo.keywords.length > 0 ? Math.min(20, this.seo.keywords.length * 5) : 0) + // Keywords
        (keywordDensity >= 2 && keywordDensity <= 10 ? 10 : 0) // Keyword density
    );

    // Uniqueness score (placeholder - integrate with plagiarism checker)
    this.quality.scores.uniqueness = content.length > 0 ? 80 : 0; // Basic check

    // Overall score as weighted average
    this.quality.overallScore = Math.round(
        (this.quality.scores.grammar * 0.25) +
        (this.quality.scores.readability * 0.25) +
        (this.quality.scores.engagement * 0.20) +
        (this.quality.scores.seo * 0.20) +
        (this.quality.scores.uniqueness * 0.10)
    );

    this.quality.lastAnalyzed = new Date();

    return this.save();
};

// Static Methods for Scalability
summarySchema.statics.findByUser = async function (userId, options = {}) {
    const { status = 'active', limit = 20, skip = 0, sort = { createdAt: -1 } } = options;
    return this.find({
        userId,
        status,
        'flags.isDeleted': false
    })
        .select('title slug content status createdAt updatedAt quality.overallScore')
        .sort(sort)
        .skip(skip)
        .limit(limit)
        .lean()
        .cache(3600); // Cache for 1 hour
};

summarySchema.statics.findPublicSummaries = async function (options = {}) {
    const { category, limit = 20, skip = 0, sort = { 'analytics.views.total': -1 } } = options;
    const query = {
        'sharing.isPublic': true,
        status: 'active',
        'flags.isDeleted': false
    };
    if (category) query.category = category;

    return this.find(query)
        .select('title slug content category createdAt analytics.views.total quality.overallScore')
        .sort(sort)
        .skip(skip)
        .limit(limit)
        .lean()
        .cache(3600); // Cache for 1 hour
};

summarySchema.statics.searchSummaries = async function (searchTerm, options = {}) {
    const { limit = 20, skip = 0, status = 'active', isPublic = true } = options;
    return this.find({
        $text: { $search: searchTerm },
        status,
        'sharing.isPublic': isPublic,
        'flags.isDeleted': false
    })
        .select('title slug content category createdAt quality.overallScore')
        .sort({ score: { $meta: "textScore" } })
        .skip(skip)
        .limit(limit)
        .lean()
        .cache(1800); // Cache for 30 minutes
};

summarySchema.statics.getAnalyticsSummary = async function (userId, timeRange = '30d') {
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
        { $match: { userId, 'flags.isDeleted': false, status: 'active' } },
        {
            $lookup: {
                from: 'summaries',
                localField: '_id',
                foreignField: '_id',
                as: 'self'
            }
        },
        { $unwind: '$self' },
        {
            $project: {
                title: 1,
                'analytics.views.total': 1,
                'analytics.views.unique': 1,
                'analytics.interactions': 1,
                'analytics.performance': 1,
                'analytics.traffic': 1,
                timeline: {
                    $filter: {
                        input: '$analytics.timeline',
                        as: 'item',
                        cond: { $gte: ['$$item.date', startDate] }
                    }
                }
            }
        },
        { $sort: { 'analytics.views.total': -1 } },
        { $limit: 10 }
    ]);
};

summarySchema.statics.bulkUpdateStatus = async function (userId, summaryIds, status) {
    return this.updateMany(
        { _id: { $in: summaryIds }, userId, 'flags.isDeleted': false },
        { $set: { status, updatedAt: new Date() } },
        { multi: true }
    );
};

summarySchema.statics.cleanupExpiredShares = async function () {
    const now = new Date();
    return this.updateMany(
        { 'sharing.shareLinks.expiresAt': { $lte: now }, 'flags.isDeleted': false },
        { $pull: { 'sharing.shareLinks': { expiresAt: { $lte: now } } } }
    );
};

summarySchema.statics.getCollaboratedSummaries = async function (userId, options = {}) {
    const { status = 'active', limit = 20, skip = 0 } = options;
    return this.find({
        'sharing.collaborators.userId': userId,
        'sharing.collaborators.status': 'accepted',
        status,
        'flags.isDeleted': false
    })
        .select('title slug content status sharing.collaborators')
        .sort({ updatedAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean()
        .cache(3600); // Cache for 1 hour
};

summarySchema.statics.scheduleSummaries = async function () {
    const now = new Date();
    return this.updateMany(
        {
            'scheduling.isScheduled': true,
            'scheduling.publishAt': { $lte: now },
            status: 'draft',
            'flags.isDeleted': false
        },
        {
            $set: {
                status: 'active',
                'scheduling.isScheduled': false,
                updatedAt: new Date()
            }
        }
    );
};

// Pre-save middleware for slug generation and cache update
summarySchema.pre('save', function (next) {
    if (!this.slug && this.title) {
        this.slug = this.title.toLowerCase()
            .replace(/[^a-z0-9]+/g, '-')
            .replace(/(^-|-$)/g, '');
    }

    this.cache.searchableText = [
        this.title,
        this.content,
        this.tags.join(' '),
        this.metadata.industry,
        this.metadata.jobTitle
    ].filter(Boolean).join(' ').toLowerCase();

    this.cache.lastCached = new Date();

    next();
});

// Pre-update middleware for updating lastModifiedBy
summarySchema.pre(['updateOne', 'updateMany', 'findOneAndUpdate'], function (next) {
    this.set({
        'compliance.audit.lastModifiedBy': {
            userId: this.getOptions().userId || 'system',
            ip: this.getOptions().ip,
            userAgent: this.getOptions().userAgent,
            timestamp: new Date()
        }
    });
    next();
});

// Model
const Summary = mongoose.model('Summary', summarySchema);

export default Summary;