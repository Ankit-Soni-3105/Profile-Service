import mongoose, { Schema } from 'mongoose';
import aggregatePaginate from 'mongoose-aggregate-paginate-v2';
import { v4 as uuidv4 } from 'uuid';
import validator from 'validator';
import crypto from 'crypto';
import redis from 'redis';

// Initialize Redis client (configure with your Redis URL)
const redisClient = redis.createClient({ url: process.env.REDIS_URL || 'redis://localhost:6379' });
redisClient.connect().catch(err => console.error('Redis connection error:', err));

// Custom validation functions
const validateURL = (v) => !v || validator.isURL(v, { require_protocol: true });
const validateEmail = (v) => !v || validator.isEmail(v);
const validatePhone = (v) => !v || validator.isMobilePhone(v, 'any', { strictMode: false });
const validateSlug = (v) => /^[a-z0-9-]+$/.test(v);
const validateHexColor = (v) => !v || /^#([0-9A-F]{3}|[0-9A-F]{6})$/i.test(v);
const validateYear = (v) => !v || (Number.isInteger(v) && v >= 1600 && v <= new Date().getFullYear() + 1);
const validateIP = (v) => !v || validator.isIP(v);

// Sub-schemas for modularity and scalability
const versionSchema = new Schema({
    _id: { type: String, default: () => uuidv4() },
    versionNumber: { type: Number, required: true, min: 1 },
    name: { type: String, required: true, trim: true, maxlength: 200 },
    description: { type: String, trim: true, maxlength: 10000 },
    industry: { type: String, trim: true, maxlength: 100 },
    changeType: { type: String, enum: ['create', 'edit', 'merge', 'ai_enhance', 'admin_update'], required: true },
    editedBy: {
        userId: { type: Schema.Types.ObjectId, ref: 'User' },
        userType: { type: String, enum: ['owner', 'admin', 'ai', 'system'], default: 'admin' }
    },
    stats: {
        employeeCountAtTime: { type: Number, min: 0 },
        followerCountAtTime: { type: Number, min: 0 }
    },
    createdAt: { type: Date, default: Date.now, index: true },
    isActive: { type: Boolean, default: false }
}, { _id: true });

const analyticsSchema = new Schema({
    views: {
        total: { type: Number, default: 0, min: 0 },
        unique: { type: Number, default: 0, min: 0 },
        daily: { type: Number, default: 0, min: 0 },
        weekly: { type: Number, default: 0, min: 0 },
        monthly: { type: Number, default: 0, min: 0 }
    },
    interactions: {
        follows: { type: Number, default: 0, min: 0 },
        unfollows: { type: Number, default: 0, min: 0 },
        shares: { type: Number, default: 0, min: 0 },
        jobApplications: { type: Number, default: 0, min: 0 },
        comments: { type: Number, default: 0, min: 0 },
        reviews: { type: Number, default: 0, min: 0 },
        referrals: { type: Number, default: 0, min: 0 }
    },
    performance: {
        avgSessionDuration: { type: Number, default: 0, min: 0 },
        bounceRate: { type: Number, default: 0, min: 0, max: 100 },
        engagementRate: { type: Number, default: 0, min: 0, max: 100 },
        conversionRate: { type: Number, default: 0, min: 0, max: 100 },
        growthRate: { type: Number, default: 0 }
    },
    trafficSources: [{
        source: { type: String, enum: ['organic', 'direct', 'referral', 'social', 'email', 'paid', 'search', 'internal'] },
        count: { type: Number, default: 0, min: 0 },
        percentage: { type: Number, default: 0, min: 0, max: 100 }
    }],
    deviceBreakdown: [{
        device: { type: String, enum: ['mobile', 'desktop', 'tablet', 'other'] },
        count: { type: Number, default: 0, min: 0 },
        percentage: { type: Number, default: 0, min: 0, max: 100 }
    }],
    locationBreakdown: [{
        country: { type: String, maxlength: 100 },
        city: { type: String, maxlength: 100 },
        count: { type: Number, default: 0, min: 0 },
        percentage: { type: Number, default: 0, min: 0, max: 100 }
    }],
    timeline: [{
        date: { type: Date, required: true },
        views: { type: Number, default: 0, min: 0 },
        interactions: { type: Number, default: 0, min: 0 },
        applications: { type: Number, default: 0, min: 0 },
        growth: { type: Number, default: 0 }
    }],
    lastCalculated: { type: Date, default: Date.now }
}, { _id: false });

const sharingSchema = new Schema({
    isPublic: { type: Boolean, default: true, index: true },
    visibilityLevel: {
        type: String,
        enum: ['public', 'restricted', 'private', 'employees_only'],
        default: 'public',
        index: true
    },
    allowedActions: [{
        type: String,
        enum: ['view', 'comment', 'share', 'follow', 'apply', 'review', 'message']
    }],
    accessControls: {
        requireLogin: { type: Boolean, default: false },
        requireVerification: { type: Boolean, default: false },
        geoRestrictions: [{ country: String, allow: Boolean }],
        ipWhitelist: [{ ip: { type: String, validate: { validator: validateIP, message: 'Invalid IP address' } } }],
        ipBlacklist: [{ ip: { type: String, validate: { validator: validateIP, message: 'Invalid IP address' } } }]
    },
    shareTokens: [{
        token: { type: String, default: () => crypto.randomBytes(16).toString('hex'), unique: true, sparse: true },
        expiresAt: { type: Date },
        usageCount: { type: Number, default: 0, min: 0 },
        maxUses: { type: Number, min: 0 },
        permissions: [{ type: String, enum: ['view', 'edit', 'share'] }],
        createdAt: { type: Date, default: Date.now }
    }]
}, { _id: false });

const seoSchema = new Schema({
    metaTitle: { type: String, trim: true, maxlength: 60 },
    metaDescription: { type: String, trim: true, maxlength: 160 },
    keywords: [{
        keyword: { type: String, trim: true, maxlength: 50 },
        priority: { type: Number, min: 1, max: 10 }
    }],
    canonicalUrl: { type: String, validate: { validator: validateURL, message: 'Invalid canonical URL' } },
    robots: { type: String, enum: ['index,follow', 'noindex,nofollow', 'index,nofollow'], default: 'index,follow' },
    openGraph: {
        title: { type: String, maxlength: 60 },
        description: { type: String, maxlength: 160 },
        image: { type: String, validate: { validator: validateURL, message: 'Invalid OG image URL' } },
        type: { type: String, default: 'website' }
    },
    schemaMarkup: { type: Schema.Types.Mixed },
    lastOptimized: { type: Date, default: Date.now }
}, { _id: false });

const aiSchema = new Schema({
    isAiAssisted: { type: Boolean, default: false, index: true },
    assistedFields: [{
        field: { type: String, enum: ['description', 'benefits', 'culture', 'seo', 'job_listings'] },
        modelUsed: { type: String, maxlength: 100 },
        confidence: { type: Number, min: 0, max: 1 },
        generatedAt: { type: Date, default: Date.now }
    }],
    recommendations: [{
        type: { type: String, enum: ['content_optimization', 'seo_improvement', 'engagement_boost', 'data_enrichment', 'profile_completion'] },
        suggestion: { type: String, maxlength: 2000 },
        priority: { type: String, enum: ['low', 'medium', 'high'], default: 'medium' },
        status: { type: String, enum: ['pending', 'applied', 'dismissed'], default: 'pending' },
        appliedAt: { type: Date }
    }],
    lastAiScan: { type: Date }
}, { _id: false });

const complianceSchema = new Schema({
    dataProtection: {
        gdprCompliant: { type: Boolean, default: false },
        ccpaCompliant: { type: Boolean, default: false },
        dataProcessingAgreement: { type: Boolean, default: false },
        lastAuditDate: { type: Date }
    },
    legal: {
        registrationNumber: { type: String, maxlength: 50, unique: true, sparse: true, index: true },
        taxId: { type: String, maxlength: 50, unique: true, sparse: true, index: true },
        incorporationCountry: { type: String, maxlength: 100 },
        legalStatus: { type: String, enum: ['verified', 'pending', 'rejected'], default: 'pending', index: true }
    },
    auditLogs: [{
        event: { type: String, required: true },
        userId: { type: Schema.Types.ObjectId, ref: 'User' },
        timestamp: { type: Date, default: Date.now, index: true },
        details: { type: Schema.Types.Mixed },
        ip: { type: String, validate: { validator: validateIP, message: 'Invalid IP address' } },
        userAgent: { type: String, maxlength: 500 }
    }],
    dataRetention: {
        period: { type: Number, default: 3650, min: 365 },
        autoDelete: { type: Boolean, default: true }
    },
    consentRecords: [{
        userId: { type: Schema.Types.ObjectId, ref: 'User' },
        consentedTo: [{ type: String, enum: ['analytics', 'marketing', 'data_sharing', 'profile_visibility'] }],
        consentedAt: { type: Date, default: Date.now },
        version: { type: Number, default: 1 }
    }]
}, { _id: false });

// Main Company Schema
const companySchema = new Schema({
    _id: { type: Schema.Types.ObjectId, auto: true },
    companyHandle: {
        type: String,
        required: [true, 'Company handle is required'],
        unique: true,
        trim: true,
        lowercase: true,
        minlength: 2,
        maxlength: 50,
        validate: { validator: validateSlug, message: 'Invalid handle format (a-z, 0-9, - only)' },
        index: { unique: true }
    },
    name: {
        type: String,
        required: [true, 'Company name is required'],
        trim: true,
        minlength: 1,
        maxlength: 200,
        index: 'text'
    },
    displayName: {
        type: String,
        trim: true,
        maxlength: 200
    },
    description: {
        type: String,
        trim: true,
        maxlength: 10000,
        index: 'text'
    },
    missionStatement: {
        type: String,
        trim: true,
        maxlength: 1000
    },
    industry: {
        primary: {
            type: String,
            required: [true, 'Primary industry is required'],
            trim: true,
            maxlength: 100,
            index: true
        },
        secondary: [{ type: String, trim: true, maxlength: 100 }],
        tags: [{ type: String, trim: true, lowercase: true, maxlength: 50, index: true }]
    },
    size: {
        category: {
            type: String,
            enum: ['startup', 'small', 'medium', 'large', 'enterprise', 'government', 'non-profit'],
            index: true
        },
        employeeRange: {
            min: { type: Number, min: 1 },
            max: { type: Number, min: 1 }
        },
        exactCount: { type: Number, min: 0, index: true }
    },
    locations: [{
        type: {
            type: String,
            enum: ['headquarters', 'office', 'remote', 'hybrid', 'branch', 'manufacturing'],
            required: true
        },
        address: {
            street: { type: String, maxlength: 200 },
            city: { type: String, required: true, index: true, maxlength: 100 },
            state: { type: String, maxlength: 100 },
            country: { type: String, required: true, index: true, maxlength: 100 },
            zipCode: { type: String, maxlength: 20 },
            coordinates: {
                type: { type: String, enum: ['Point'], default: 'Point' },
                coordinates: { type: [Number], index: '2dsphere' }
            }
        },
        isPrimary: { type: Boolean, default: false },
        employeeCount: { type: Number, min: 0 },
        timezone: { type: String, maxlength: 50 },
        isActive: { type: Boolean, default: true, index: true }
    }],
    contact: {
        website: { type: String, validate: { validator: validateURL, message: 'Invalid website URL' } },
        email: { type: String, trim: true, lowercase: true, validate: { validator: validateEmail, message: 'Invalid email format' } },
        phone: { type: String, validate: { validator: validatePhone, message: 'Invalid phone number format' } },
        socialMedia: {
            linkedin: { type: String, validate: { validator: validateURL, message: 'Invalid LinkedIn URL' } },
            twitter: { type: String, validate: { validator: validateURL, message: 'Invalid Twitter URL' } },
            facebook: { type: String, validate: { validator: validateURL, message: 'Invalid Facebook URL' } },
            instagram: { type: String, validate: { validator: validateURL, message: 'Invalid Instagram URL' } },
            youtube: { type: String, validate: { validator: validateURL, message: 'Invalid YouTube URL' } },
            tiktok: { type: String, validate: { validator: validateURL, message: 'Invalid TikTok URL' } }
        }
    },
    branding: {
        logo: {
            url: { type: String, validate: { validator: validateURL, message: 'Invalid logo URL' } },
            cloudinaryId: { type: String },
            sizes: {
                small: { type: String, validate: { validator: validateURL, message: 'Invalid small logo URL' } },
                medium: { type: String, validate: { validator: validateURL, message: 'Invalid medium logo URL' } },
                large: { type: String, validate: { validator: validateURL, message: 'Invalid large logo URL' } }
            }
        },
        coverImage: {
            url: { type: String, validate: { validator: validateURL, message: 'Invalid cover image URL' } },
            cloudinaryId: { type: String }
        },
        brandColors: {
            primary: { type: String, validate: { validator: validateHexColor, message: 'Invalid primary color' } },
            secondary: { type: String, validate: { validator: validateHexColor, message: 'Invalid secondary color' } },
            accent: { type: String, validate: { validator: validateHexColor, message: 'Invalid accent color' } }
        },
        fontFamily: { type: String, maxlength: 100 },
        customCss: { type: String, maxlength: 5000 }
    },
    stats: {
        employeeCount: { type: Number, default: 0, min: 0, index: true },
        followersCount: { type: Number, default: 0, min: 0, index: true },
        postsCount: { type: Number, default: 0, min: 0 },
        jobOpeningsCount: { type: Number, default: 0, min: 0, index: true },
        avgRating: { type: Number, min: 0, max: 5, default: 0, index: true },
        totalReviews: { type: Number, default: 0, min: 0 },
        lastActiveAt: { type: Date, default: Date.now, index: true },
        employeeGrowthRate: { type: Number, default: 0 },
        followerGrowthRate: { type: Number, default: 0 }
    },
    verification: {
        isVerified: { type: Boolean, default: false, index: true },
        verifiedAt: { type: Date },
        verificationLevel: { type: String, enum: ['basic', 'premium', 'enterprise', 'certified'], default: 'basic', index: true },
        verificationMethod: { type: String, enum: ['domain', 'document', 'manual', 'api'], index: true },
        verificationScore: { type: Number, min: 0, max: 100, default: 0 },
        badges: [{ type: String, enum: ['top-employer', 'fast-growing', 'remote-friendly', 'diversity-champion', 'green-company', 'innovation-leader', 'best-workplace'], index: true }]
    },
    keyPeople: [{
        name: { type: String, required: true, maxlength: 100 },
        position: { type: String, required: true, maxlength: 100 },
        userId: { type: Schema.Types.ObjectId, ref: 'User', index: true },
        linkedinProfile: { type: String, validate: { validator: validateURL, message: 'Invalid LinkedIn URL' } },
        startDate: { type: Date },
        isActive: { type: Boolean, default: true, index: true }
    }],
    timeline: {
        foundedYear: { type: Number, validate: { validator: validateYear, message: 'Invalid founding year' }, index: true },
        foundedDate: { type: Date },
        registrationDate: { type: Date },
        lastFundingDate: { type: Date },
        ipoDate: { type: Date },
        acquisitionDate: { type: Date },
        events: [{
            type: { type: String, enum: ['founding', 'funding', 'acquisition', 'merger', 'ipo', 'expansion', 'rebranding'] },
            date: { type: Date, required: true },
            description: { type: String, maxlength: 500 },
            participants: [{ type: String, maxlength: 100 }]
        }]
    },
    business: {
        type: {
            type: String,
            enum: ['public', 'private', 'partnership', 'llc', 'non-profit', 'government', 'startup', 'scaleup'],
            index: true
        },
        revenue: {
            range: { type: String, enum: ['under-1m', '1m-10m', '10m-50m', '50m-100m', '100m-500m', '500m-1b', 'over-1b', 'undisclosed'] },
            currency: { type: String, default: 'USD', maxlength: 3 },
            year: { type: Number, validate: { validator: validateYear, message: 'Invalid revenue year' } },
            isPublic: { type: Boolean, default: false }
        },
        stockSymbol: { type: String, maxlength: 10, uppercase: true, sparse: true, index: true },
        marketCap: { type: Number, min: 0 },
        parentCompany: { type: Schema.Types.ObjectId, ref: 'Company', index: true },
        subsidiaries: [{ type: Schema.Types.ObjectId, ref: 'Company', index: true }],
        fundingRounds: [{
            type: { type: String, enum: ['seed', 'series-a', 'series-b', 'series-c', 'series-d+', 'venture', 'private-equity', 'debt'] },
            amount: { type: Number, min: 0 },
            currency: { type: String, default: 'USD' },
            date: { type: Date },
            investors: [{ name: { type: String, maxlength: 100 }, type: { type: String, enum: ['vc', 'angel', 'corporate', 'crowd'] } }],
            valuation: { type: Number, min: 0 },
            isPublic: { type: Boolean, default: false }
        }]
    },
    culture: {
        values: [{ type: String, maxlength: 200 }],
        benefits: [{ type: String, maxlength: 200 }],
        workEnvironment: { type: String, enum: ['remote', 'hybrid', 'office', 'flexible', 'digital-nomad-friendly'] },
        diversity: {
            isEqualOpportunity: { type: Boolean, default: false },
            diversityStatement: { type: String, maxlength: 2000 },
            initiatives: [{ type: String, maxlength: 200 }]
        },
        employeeSatisfaction: {
            score: { type: Number, min: 0, max: 100 },
            surveyDate: { type: Date }
        },
        workLifeBalanceScore: { type: Number, min: 0, max: 5 },
        careerGrowthScore: { type: Number, min: 0, max: 5 }
    },
    seo: seoSchema,
    status: {
        type: String,
        enum: ['active', 'inactive', 'suspended', 'merged', 'acquired', 'closed'],
        default: 'active',
        index: true
    },
    visibility: {
        isPublic: { type: Boolean, default: true, index: true },
        searchable: { type: Boolean, default: true, index: true },
        allowReviews: { type: Boolean, default: true },
        allowEmployeePosts: { type: Boolean, default: true },
        allowJobPostings: { type: Boolean, default: true },
        privacyLevel: { type: String, enum: ['open', 'moderate', 'strict'], default: 'open', index: true }
    },
    admin: {
        createdBy: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
        owners: [{ type: Schema.Types.ObjectId, ref: 'User', index: true }],
        admins: [{
            userId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
            role: { type: String, enum: ['owner', 'admin', 'editor', 'recruiter', 'viewer'], default: 'editor' },
            addedAt: { type: Date, default: Date.now },
            permissions: [{
                type: String,
                enum: [
                    'edit_profile',
                    'post_updates',
                    'manage_jobs',
                    'manage_employees',
                    'view_analytics',
                    'manage_followers',
                    'moderate_content',
                    'handle_verification',
                    'manage_integrations'
                ]
            }],
            status: { type: String, enum: ['active', 'pending', 'revoked'], default: 'active' }
        }],
        lastModifiedBy: { type: Schema.Types.ObjectId, ref: 'User', index: true },
        adminCount: { type: Number, default: 0, min: 0 }
    },
    cache: {
        searchVector: { type: String, index: 'text' },
        popularityScore: { type: Number, default: 0, index: true },
        trendingScore: { type: Number, default: 0, index: true },
        cacheVersion: { type: Number, default: 1 },
        lastCacheUpdate: { type: Date, default: Date.now, index: true }
    },
    audit: {
        version: { type: Number, default: 1, min: 1 },
        changeHistory: [{
            changedBy: { type: Schema.Types.ObjectId, ref: 'User' },
            changedAt: { type: Date, default: Date.now, index: true },
            changes: { type: Schema.Types.Mixed },
            changeType: { type: String, enum: ['create', 'update', 'delete', 'restore', 'merge', 'split'] },
            previousState: { type: Schema.Types.Mixed }
        }],
        accessLogs: [{
            userId: { type: Schema.Types.ObjectId, ref: 'User' },
            action: { type: String, enum: ['view', 'edit', 'follow', 'unfollow', 'apply', 'review', 'report'] },
            timestamp: { type: Date, default: Date.now, index: true },
            ip: { type: String, validate: { validator: validateIP, message: 'Invalid IP address' } },
            userAgent: { type: String, maxlength: 500 },
            success: { type: Boolean, default: true },
            details: { type: Schema.Types.Mixed }
        }]
    },
    ai: aiSchema,
    compliance: complianceSchema,
    versions: [versionSchema],
    integrations: {
        linkedin: {
            connected: { type: Boolean, default: false },
            profileId: { type: String },
            lastSync: { type: Date },
            syncStatus: { type: String, enum: ['active', 'failed', 'pending'], default: 'pending' }
        },
        crunchbase: {
            connected: { type: Boolean, default: false },
            profileId: { type: String },
            lastSync: { type: Date }
        },
        jobBoards: [{
            name: { type: String, maxlength: 100 },
            apiKey: { type: String },
            lastSync: { type: Date },
            isActive: { type: Boolean, default: true }
        }]
    }
}, {
    timestamps: true,
    collection: 'companies',
    autoIndex: process.env.NODE_ENV !== 'production',
    autoCreate: true,
    readPreference: 'secondaryPreferred',
    writeConcern: { w: 'majority', wtimeout: 5000 },
    versionKey: '__v',
    toJSON: {
        virtuals: true,
        transform: (doc, ret) => {
            delete ret.audit.accessLogs;
            delete ret.compliance.consentRecords;
            delete ret.__v;
            return ret;
        }
    },
    toObject: { virtuals: true },
    minimize: false,
    strict: 'throw'
});

// Compound Indexes
companySchema.index({ status: 1, 'visibility.isPublic': 1, 'verification.isVerified': -1, 'stats.followersCount': -1 });
companySchema.index({ 'industry.primary': 1, 'locations.address.city': 1, 'size.category': 1 });
companySchema.index({ 'timeline.foundedYear': 1, 'industry.primary': 1 });
companySchema.index({ 'locations.address.coordinates': '2dsphere' });
companySchema.index({ 'seo.slug': 1 }, { sparse: true, unique: true });
companySchema.index({ 'business.stockSymbol': 1 }, { sparse: true });
companySchema.index({ 'cache.popularityScore': -1, status: 1 });
companySchema.index({ 'cache.trendingScore': -1, 'visibility.isPublic': 1 });
companySchema.index({ 'verification.isVerified': 1, 'verification.verificationLevel': 1 });
companySchema.index({ 'admin.admins.userId': 1 }, { sparse: true });
companySchema.index({ 'business.fundingRounds.date': -1 }, { sparse: true });
companySchema.index({ 'audit.changeHistory.changedAt': -1 }, { partialFilterExpression: { 'audit.changeHistory': { $exists: true } } });
companySchema.index({ 'compliance.legal.taxId': 1, 'compliance.legal.registrationNumber': 1 }, { sparse: true });
companySchema.index({
    name: 'text',
    description: 'text',
    'industry.primary': 'text',
    'industry.tags': 'text',
    'cache.searchVector': 'text'
}, {
    weights: {
        name: 10,
        'industry.primary': 5,
        description: 3,
        'industry.tags': 2,
        'cache.searchVector': 1
    },
    name: 'company_text_search'
});

// TTL Indexes
companySchema.index({ 'audit.accessLogs.timestamp': 1 }, { expireAfterSeconds: 7776000 }); // 90 days
companySchema.index({ 'audit.changeHistory.changedAt': 1 }, { expireAfterSeconds: 31536000 }); // 1 year

// Virtuals
companySchema.virtual('totalFunding').get(function () {
    return this.business.fundingRounds.reduce((sum, round) => sum + (round.amount || 0), 0);
});

companySchema.virtual('isGrowing').get(function () {
    return this.stats.employeeGrowthRate > 10 || this.stats.followerGrowthRate > 15;
});

companySchema.virtual('activeLocations').get(function () {
    return this.locations.filter(loc => loc.isActive).length;
});

companySchema.virtual('currentVersion').get(function () {
    return this.versions.find(v => v.isActive) || this.versions[this.versions.length - 1] || null;
});

// Pre-save Middleware
companySchema.pre('save', async function (next) {
    // Generate unique companyHandle
    if (!this.companyHandle && this.name) {
        this.companyHandle = this.name
            .toLowerCase()
            .replace(/[^a-z0-9]/g, '-')
            .replace(/-+/g, '-')
            .replace(/^-|-$/g, '');
        let suffix = 1;
        let existing = await this.constructor.findOne({ companyHandle: this.companyHandle });
        while (existing && existing._id.toString() !== this._id.toString()) {
            this.companyHandle = `${this.companyHandle}-${suffix++}`;
            existing = await this.constructor.findOne({ companyHandle: this.companyHandle });
        }
    }

    // Generate SEO slug
    if (!this.seo.slug && this.name) {
        this.seo.slug = this.name
            .toLowerCase()
            .replace(/[^a-z0-9]/g, '-')
            .replace(/-+/g, '-')
            .replace(/^-|-$/g, '');
        let suffix = 1;
        let existing = await this.constructor.findOne({ 'seo.slug': this.seo.slug });
        while (existing && existing._id.toString() !== this._id.toString()) {
            this.seo.slug = `${this.seo.slug}-${suffix++}`;
            existing = await this.constructor.findOne({ 'seo.slug': this.seo.slug });
        }
    }

    // Update search vector
    this.cache.searchVector = [
        this.name,
        this.displayName,
        this.description,
        this.missionStatement,
        this.industry.primary,
        ...this.industry.secondary,
        ...this.industry.tags,
        this.culture.diversityStatement,
        this.business.type
    ].filter(Boolean).join(' ').toLowerCase();

    // Update popularity and trending scores
    this.cache.popularityScore = this.calculatePopularityScore();
    this.cache.trendingScore = (this.stats.followerGrowthRate * 0.4) + (this.stats.employeeGrowthRate * 0.3) + (this.stats.jobOpeningsCount * 0.3);

    // Update cache metadata
    this.cache.lastCacheUpdate = new Date();
    this.cache.cacheVersion += 1;

    // Cache in Redis
    await redisClient.setEx(`company:${this._id}`, 300, JSON.stringify(this.toJSON()));

    // Publish score updates
    await redisClient.publish('popularity_updates', JSON.stringify({
        companyId: this._id,
        popularityScore: this.cache.popularityScore,
        trendingScore: this.cache.trendingScore
    }));

    // Versioning for significant changes
    if (this.isModified('name') || this.isModified('description') || this.isModified('industry') || this.isModified('business') || this.isModified('culture')) {
        const newVersion = {
            versionNumber: this.versions.length + 1,
            name: this.name,
            description: this.description,
            industry: this.industry.primary,
            changeType: this.ai.isAiAssisted ? 'ai_enhance' : 'edit',
            editedBy: { userId: this.admin.lastModifiedBy || this.admin.createdBy, userType: 'admin' },
            stats: {
                employeeCountAtTime: this.stats.employeeCount,
                followerCountAtTime: this.stats.followersCount
            },
            isActive: true
        };
        this.versions.forEach(v => v.isActive = false);
        this.versions.push(newVersion);
        if (this.versions.length > 100) this.versions.shift();
    }

    // Update admin count
    this.admin.adminCount = this.admin.admins.length;

    // Encrypt sensitive fields (using CSFLE placeholder)
    if (this.compliance.legal.taxId) {
        this.compliance.legal.taxId = await encryptField(this.compliance.legal.taxId);
    }
    if (this.compliance.legal.registrationNumber) {
        this.compliance.legal.registrationNumber = await encryptField(this.compliance.legal.registrationNumber);
    }

    next();
});

// Pre-update Middleware
companySchema.pre(['updateOne', 'findOneAndUpdate'], async function (next) {
    const update = this.getUpdate();
    if (update) {
        update['admin.lastModifiedAt'] = new Date();
        update['compliance.auditLogs'] = update['compliance.auditLogs'] || [];
        update['compliance.auditLogs'].push({
            event: this.getOptions()?.event || 'update',
            userId: this.getOptions()?.userId || 'system',
            ip: this.getOptions()?.ip,
            userAgent: this.getOptions()?.userAgent,
            timestamp: new Date(),
            details: this.getUpdate()
        });
    }
    // Invalidate Redis cache
    const companyId = this.getQuery()._id;
    if (companyId) {
        await redisClient.del(`company:${companyId}`);
    }
    next();
});

// Instance Methods
companySchema.methods.calculatePopularityScore = function () {
    const weights = {
        followers: 0.35,
        employees: 0.2,
        posts: 0.15,
        jobs: 0.15,
        rating: 0.1,
        verified: 0.05,
        recency: 0.05
    };

    const followerScore = Math.log1p(this.stats.followersCount) / Math.log1p(1000000);
    const employeeScore = Math.log1p(this.stats.employeeCount) / Math.log1p(100000);
    const postScore = Math.log1p(this.stats.postsCount) / Math.log1p(1000);
    const jobScore = Math.log1p(this.stats.jobOpeningsCount) / Math.log1p(500);
    const ratingScore = this.stats.avgRating / 5;
    const verifiedScore = this.verification.isVerified ? 1 : 0;
    const daysSinceActive = (Date.now() - (this.stats.lastActiveAt?.getTime() || Date.now())) / (1000 * 60 * 60 * 24);
    const recencyScore = Math.max(0, 1 - (daysSinceActive / 30));

    return Math.min(100, (
        followerScore * weights.followers +
        employeeScore * weights.employees +
        postScore * weights.posts +
        jobScore * weights.jobs +
        ratingScore * weights.rating +
        verifiedScore * weights.verified +
        recencyScore * weights.recency
    ) * 100);
};

companySchema.methods.addAdmin = async function (userId, role, permissions) {
    this.admin.admins.push({
        userId,
        role,
        permissions,
        addedAt: new Date(),
        status: 'active'
    });
    this.admin.adminCount = this.admin.admins.length;
    await this.save();
};

companySchema.methods.logAccess = async function (userId, action, ip, userAgent, details) {
    this.audit.accessLogs.push({
        userId,
        action,
        ip,
        userAgent,
        timestamp: new Date(),
        success: true,
        details
    });
    if (this.audit.accessLogs.length > 1000) this.audit.accessLogs.shift();
    await this.save();
};

// Static Methods
companySchema.statics.advancedSearch = async function (query, options = {}) {
    const {
        page = 1,
        limit = 20,
        sortBy = 'popularity',
        industry,
        location,
        size,
        verified,
        minRating,
        minEmployees,
        geoNear
    } = options;

    // Check Redis cache
    const cacheKey = `search:${query}:${JSON.stringify(options)}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) {
        return JSON.parse(cached);
    }

    const pipeline = [
        {
            $match: {
                status: 'active',
                'visibility.isPublic': true,
                ...(query && { $text: { $search: query } }),
                ...(industry && { 'industry.primary': new RegExp(industry, 'i') }),
                ...(location && {
                    $or: [
                        { 'locations.address.city': new RegExp(location, 'i') },
                        { 'locations.address.country': new RegExp(location, 'i') }
                    ]
                }),
                ...(size && { 'size.category': size }),
                ...(verified && { 'verification.isVerified': true }),
                ...(minRating && { 'stats.avgRating': { $gte: Number(minRating) } }),
                ...(minEmployees && { 'stats.employeeCount': { $gte: Number(minEmployees) } })
            }
        },
        ...(geoNear ? [{
            $geoNear: {
                near: { type: 'Point', coordinates: geoNear.coordinates },
                distanceField: 'distance',
                maxDistance: geoNear.maxDistance || 100000,
                spherical: true
            }
        }] : []),
        {
            $addFields: {
                relevanceScore: {
                    $add: [
                        { $cond: [{ $eq: ['$verification.isVerified', true] }, 20, 0] },
                        { $cond: [{ $eq: ['$verification.verificationLevel', 'premium'] }, 10, 0] },
                        { $multiply: ['$stats.avgRating', 5] },
                        { $multiply: ['$cache.popularityScore', 0.1] },
                        { $multiply: [{ $ln: { $add: ['$stats.employeeCount', 1] } }, 3] }
                    ]
                }
            }
        },
        {
            $sort: {
                ...(sortBy === 'popularity' && { 'cache.popularityScore': -1 }),
                ...(sortBy === 'trending' && { 'cache.trendingScore': -1 }),
                ...(sortBy === 'followers' && { 'stats.followersCount': -1 }),
                ...(sortBy === 'rating' && { 'stats.avgRating': -1 }),
                ...(sortBy === 'size' && { 'stats.employeeCount': -1 }),
                ...(sortBy === 'name' && { name: 1 }),
                ...(sortBy === 'newest' && { createdAt: -1 }),
                ...(sortBy === 'oldest' && { createdAt: 1 }),
                ...(sortBy === 'relevance' && { relevanceScore: -1 }),
                createdAt: -1
            }
        },
        {
            $project: {
                audit: 0,
                compliance: 0,
                versions: 0,
                'integrations.jobBoards.apiKey': 0
            }
        }
    ];

    const results = await this.aggregatePaginate(this.aggregate(pipeline), { page, limit });
    await redisClient.setEx(cacheKey, 60, JSON.stringify(results));
    return results;
};

companySchema.statics.getTrending = async function (timeframe = '7d', limit = 10, filters = {}) {
    const timeframeMap = {
        '1d': 1 * 24 * 60 * 60 * 1000,
        '7d': 7 * 24 * 60 * 60 * 1000,
        '30d': 30 * 24 * 60 * 60 * 1000,
        '90d': 90 * 24 * 60 * 60 * 1000
    };

    const cacheKey = `trending:${timeframe}:${JSON.stringify(filters)}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) {
        return JSON.parse(cached);
    }

    const since = new Date(Date.now() - (timeframeMap[timeframe] || timeframeMap['7d']));
    const pipeline = [
        {
            $match: {
                status: 'active',
                'visibility.isPublic': true,
                'stats.lastActiveAt': { $gte: since },
                ...(filters.industry && { 'industry.primary': new RegExp(filters.industry, 'i') }),
                ...(filters.location && { 'locations.address.country': new RegExp(filters.location, 'i') }),
                ...(filters.minFollowers && { 'stats.followersCount': { $gte: Number(filters.minFollowers) } })
            }
        },
        {
            $sort: {
                'cache.trendingScore': -1,
                'cache.popularityScore': -1,
                'stats.followersCount': -1
            }
        },
        {
            $limit: limit
        },
        {
            $project: {
                name: 1,
                displayName: 1,
                companyHandle: 1,
                'branding.logo': 1,
                'stats.followersCount': 1,
                'stats.employeeCount': 1,
                'industry.primary': 1,
                'cache.trendingScore': 1,
                'cache.popularityScore': 1
            }
        }
    ];

    const results = await this.aggregate(pipeline);
    await redisClient.setEx(cacheKey, 60, JSON.stringify(results));
    return results;
};

companySchema.statics.bulkUpdateStats = async function (updates) {
    const bulkOps = updates.map(update => ({
        updateOne: {
            filter: { _id: update.companyId },
            update: {
                $set: {
                    'stats.employeeCount': update.employeeCount,
                    'stats.followersCount': update.followersCount,
                    'stats.jobOpeningsCount': update.jobOpeningsCount,
                    'stats.lastActiveAt': new Date(),
                    'cache.lastCacheUpdate': new Date()
                }
            }
        }
    }));
    const result = await this.bulkWrite(bulkOps);
    // Invalidate Redis cache for updated companies
    for (const update of updates) {
        await redisClient.del(`company:${update.companyId}`);
    }
    return result;
};

companySchema.statics.archiveInactive = async function () {
    const cutoff = new Date(Date.now() - 5 * 365 * 24 * 60 * 60 * 1000);
    const inactiveCompanies = await this.find({ status: 'inactive', updatedAt: { $lt: cutoff } }).lean();
    if (inactiveCompanies.length === 0) return { archived: 0 };

    const ArchiveCompany = mongoose.model('ArchiveCompany', companySchema, 'archive_companies');
    await ArchiveCompany.insertMany(inactiveCompanies);
    const deleted = await this.deleteMany({ _id: { $in: inactiveCompanies.map(c => c._id) } });

    // Clear Redis cache for archived companies
    for (const company of inactiveCompanies) {
        await redisClient.del(`company:${company._id}`);
    }

    return { archived: deleted.deletedCount };
};

companySchema.statics.cleanupIndexes = async function () {
    const indexes = await this.collection.indexes();
    const essentialIndexes = [
        '_id_',
        'companyHandle_1',
        'seo.slug_1',
        'business.stockSymbol_1',
        'company_text_search'
        // Add other critical index names
    ];
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

companySchema.statics.findByHandle = async function (handle) {
    const cacheKey = `company:handle:${handle}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) {
        return JSON.parse(cached);
    }
    const company = await this.findOne({ companyHandle: handle }).lean();
    if (company) {
        await redisClient.setEx(cacheKey, 300, JSON.stringify(company));
    }
    return company;
};

companySchema.statics.aggregateStats = async function (companyId, period = 'monthly') {
    const cacheKey = `stats:${companyId}:${period}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) {
        return JSON.parse(cached);
    }

    const match = { _id: new mongoose.Types.ObjectId(companyId) };
    const pipeline = [
        { $match: match },
        {
            $project: {
                name: 1,
                companyHandle: 1,
                growthMetrics: {
                    employeeGrowth: '$stats.employeeGrowthRate',
                    followerGrowth: '$stats.followerGrowthRate',
                    engagement: '$analytics.performance.engagementRate'
                },
                timelineSummary: { $slice: ['$analytics.timeline', -30] },
                recentActivity: {
                    views: '$analytics.views.monthly',
                    interactions: '$analytics.interactions',
                    applications: '$analytics.interactions.jobApplications'
                }
            }
        }
    ];
    const results = await this.aggregate(pipeline);
    await redisClient.setEx(cacheKey, 300, JSON.stringify(results));
    return results;
};

// Change Stream Setup (must be initialized in application)
companySchema.statics.initChangeStream = function () {
    const changeStream = this.watch([
        { $match: { 'operationType': { $in: ['insert', 'update', 'replace'] } } }
    ]);
    changeStream.on('change', async (change) => {
        const companyId = change.documentKey._id.toString();
        // Invalidate cache
        await redisClient.del(`company:${companyId}`);
        // Update analytics or other real-time metrics
        await redisClient.publish('company_updates', JSON.stringify({
            companyId,
            operation: change.operationType,
            updatedFields: change.updateDescription?.updatedFields
        }));
    });
    return changeStream;
};

// Placeholder for CSFLE (MongoDB Client-Side Field Level Encryption)
async function encryptField(value) {
    // Requires MongoDB CSFLE setup with a key vault
    // Example configuration:
    /*
    import { ClientEncryption } from 'mongodb';
    const encryption = new ClientEncryption(mongoose.connection.client, {
      keyVaultNamespace: 'encryption.__keyVault',
      kmsProviders: { local: { key: process.env.ENCRYPTION_KEY } }
    });
    return await encryption.encrypt(value, {
      algorithm: 'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic',
      keyId: process.env.ENCRYPTION_KEY_ID
    });
    */
    // Temporary SHA-256 placeholder
    return crypto.createHash('sha256').update(value).digest('hex');
}

// Plugin for Aggregation Pagination
companySchema.plugin(aggregatePaginate);

// Production-specific indexes
if (process.env.NODE_ENV === 'production') {
    companySchema.index({ 'cache.popularityScore': -1, status: 1, 'visibility.isPublic': 1 }, { background: true });
    companySchema.index({ 'cache.trendingScore': -1, 'visibility.isPublic': 1 }, { background: true });
    companySchema.index({ 'integrations.linkedin.connected': 1, 'integrations.linkedin.lastSync': -1 }, { sparse: true });
}

// Export the model
export default mongoose.model('Company', companySchema);
