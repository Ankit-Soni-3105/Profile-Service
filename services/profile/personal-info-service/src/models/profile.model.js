import mongoose from 'mongoose';
import { createHash } from 'crypto';

// ===========================
// OPTIMIZED SUB-SCHEMAS
// ===========================
const personalInfoSchema = new mongoose.Schema({
    firstName: {
        type: String,
        required: true,
        trim: true,
        maxlength: 50,
        index: true
    },
    middleName: {
        type: String,
        default: '',
        trim: true,
        maxlength: 50
    },
    lastName: {
        type: String,
        required: true,
        trim: true,
        maxlength: 50,
        index: true
    },
    pronouns: {
        type: String,
        enum: ['he/him', 'she/her', 'they/them', 'other', ''],
        default: ''
    },
    tagline: {
        type: String,
        default: '',
        trim: true,
        maxlength: 120,
        index: 'text'
    },
}, { _id: false });

const locationSchema = new mongoose.Schema({
    city: {
        type: String,
        default: '',
        trim: true,
        maxlength: 100,
        index: true
    },
    state: {
        type: String,
        default: '',
        trim: true,
        maxlength: 100,
        index: true
    },
    country: {
        type: String,
        default: '',
        trim: true,
        maxlength: 100,
        index: true
    },
    zipCode: {
        type: String,
        default: '',
        trim: true,
        maxlength: 20
    },
    timeZone: {
        type: String,
        default: 'UTC',
        maxlength: 50
    },
    coordinates: {
        type: [Number], // [longitude, latitude]
        index: '2dsphere'
    }
}, { _id: false });

const contactSchema = new mongoose.Schema({
    primaryEmail: {
        type: String,
        required: true,
        lowercase: true,
        trim: true,
        index: { unique: true, sparse: true }
    },
    secondaryEmail: {
        type: String,
        default: '',
        lowercase: true,
        trim: true,
        sparse: true
    },
    phoneNumber: {
        type: String,
        default: '',
        trim: true,
        index: { sparse: true }
    },
    website: {
        type: String,
        default: '',
        trim: true
    },
    socialLinks: {
        linkedin: { type: String, default: '', trim: true },
        twitter: { type: String, default: '', trim: true },
        github: { type: String, default: '', trim: true },
        instagram: { type: String, default: '', trim: true },
        youtube: { type: String, default: '', trim: true },
        facebook: { type: String, default: '', trim: true }
    }
}, { _id: false });

const mediaSchema = new mongoose.Schema({
    profilePhoto: {
        url: { type: String, default: '' },
        thumbnail: { type: String, default: '' },
        altText: { type: String, default: '' },
        uploadedAt: { type: Date },
        size: { type: Number },
        format: { type: String, enum: ['jpg', 'jpeg', 'png', 'webp'], default: 'jpg' },
        isOptimized: { type: Boolean, default: false }
    },
    coverPhoto: {
        url: { type: String, default: '' },
        thumbnail: { type: String, default: '' },
        templateId: { type: String, default: '' },
        uploadedAt: { type: Date },
        size: { type: Number },
        format: { type: String, enum: ['jpg', 'jpeg', 'png', 'webp'], default: 'jpg' }
    },
    gallery: [{
        url: { type: String, required: true },
        thumbnail: { type: String },
        caption: { type: String, maxlength: 200 },
        type: { type: String, enum: ['image', 'video'], default: 'image' },
        uploadedAt: { type: Date, default: Date.now }
    }]
}, { _id: false });

const experienceSchema = new mongoose.Schema({
    company: {
        type: String,
        required: true,
        trim: true,
        maxlength: 200,
        index: true
    },
    position: {
        type: String,
        required: true,
        trim: true,
        maxlength: 200,
        index: 'text'
    },
    employmentType: {
        type: String,
        enum: ['full-time', 'part-time', 'contract', 'internship', 'freelance', 'volunteer'],
        required: true,
        index: true
    },
    location: {
        city: { type: String, default: '', trim: true },
        state: { type: String, default: '', trim: true },
        country: { type: String, default: '', trim: true },
        isRemote: { type: Boolean, default: false, index: true }
    },
    startDate: {
        type: Date,
        required: true,
        index: true
    },
    endDate: {
        type: Date,
        index: true
    },
    isCurrent: {
        type: Boolean,
        default: false,
        index: true
    },
    duration: {
        type: Number,
        default: 0
    },
    description: {
        type: String,
        default: '',
        maxlength: 2000,
        index: 'text'
    },
    skills: [{
        type: String,
        trim: true,
        maxlength: 50,
        index: true
    }],
    achievements: [{
        type: String,
        trim: true,
        maxlength: 500
    }],
    teamSize: {
        type: Number,
        min: 0
    },
    industry: {
        type: String,
        trim: true,
        index: true
    },
    verified: {
        type: Boolean,
        default: false
    },
    order: {
        type: Number,
        default: 0
    }
});

const educationSchema = new mongoose.Schema({
    institution: {
        type: String,
        required: true,
        trim: true,
        maxlength: 200,
        index: true
    },
    degree: {
        type: String,
        required: true,
        trim: true,
        maxlength: 200,
        index: true
    },
    field: {
        type: String,
        default: '',
        trim: true,
        maxlength: 200,
        index: true
    },
    startDate: { type: Date },
    endDate: { type: Date },
    isCurrent: {
        type: Boolean,
        default: false
    },
    gpa: {
        type: Number,
        min: 0,
        max: 10
    },
    maxGpa: {
        type: Number,
        default: 4.0
    },
    honors: [{
        type: String,
        trim: true,
        maxlength: 100
    }],
    activities: [{
        type: String,
        trim: true,
        maxlength: 100
    }],
    description: {
        type: String,
        default: '',
        maxlength: 1000
    },
    verified: {
        type: Boolean,
        default: false
    },
    order: {
        type: Number,
        default: 0
    }
});

const skillSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true,
        maxlength: 50,
        index: true
    },
    category: {
        type: String,
        enum: ['technical', 'soft', 'language', 'certification', 'tool', 'framework', 'database'],
        default: 'technical',
        index: true
    },
    level: {
        type: String,
        enum: ['beginner', 'intermediate', 'advanced', 'expert'],
        default: 'intermediate',
        index: true
    },
    yearsOfExperience: {
        type: Number,
        min: 0,
        max: 50,
        index: true
    },
    verified: {
        type: Boolean,
        default: false
    },
    endorsements: {
        count: { type: Number, default: 0, index: true },
        lastEndorsedAt: { type: Date },
        endorsers: [{ type: String }], // Added to track unique endorsers
    },
    trending: {
        type: Boolean,
        default: false,
        index: true
    },
    demandScore: {
        type: Number,
        default: 0,
        min: 0,
        max: 100
    }
});

const certificationSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true,
        maxlength: 200,
        index: 'text'
    },
    issuingOrg: {
        type: String,
        required: true,
        trim: true,
        maxlength: 200,
        index: true
    },
    issueDate: {
        type: Date,
        required: true,
        index: true
    },
    expiryDate: {
        type: Date,
        index: true
    },
    credentialId: {
        type: String,
        default: '',
        trim: true,
        index: { sparse: true }
    },
    credentialUrl: {
        type: String,
        default: '',
        trim: true
    },
    verified: {
        type: Boolean,
        default: false,
        index: true
    },
    isActive: {
        type: Boolean,
        default: true
    },
    category: {
        type: String,
        enum: ['technical', 'professional', 'academic', 'language', 'safety'],
        default: 'technical',
        index: true
    }
});

// ===========================
// MAIN PROFILE SCHEMA
// ===========================
const profileSchema = new mongoose.Schema({
    userId: {
        type: String,
        required: true,
        unique: true,
        index: true,
        immutable: true
    },
    personalInfo: {
        type: personalInfoSchema,
        required: true
    },
    location: {
        type: locationSchema,
        default: () => ({})
    },
    contact: {
        type: contactSchema,
        required: true
    },
    media: {
        type: mediaSchema,
        default: () => ({})
    },
    headline: {
        type: String,
        default: '',
        trim: true,
        maxlength: 120,
        index: 'text'
    },
    summary: {
        type: String,
        default: '',
        maxlength: 2600,
        index: 'text'
    },
    experience: [experienceSchema],
    education: [educationSchema],
    skills: [skillSchema],
    certifications: [certificationSchema],
    languages: [{
        name: {
            type: String,
            required: true,
            index: true
        },
        proficiency: {
            type: String,
            enum: ['elementary', 'limited', 'professional', 'full-professional', 'native'],
            required: true,
            index: true
        },
        certifications: [{ type: String }],
        isNative: { type: Boolean, default: false }
    }],
    projects: [{
        title: {
            type: String,
            required: true,
            maxlength: 200,
            index: 'text'
        },
        description: {
            type: String,
            default: '',
            maxlength: 2000
        },
        url: { type: String, default: '' },
        repositoryUrl: { type: String, default: '' },
        demoUrl: { type: String, default: '' },
        startDate: { type: Date },
        endDate: { type: Date },
        isCurrent: { type: Boolean, default: false },
        technologies: [{
            type: String,
            index: true
        }],
        media: [{
            type: String
        }],
        teamSize: {
            type: Number,
            min: 1
        },
        role: {
            type: String,
            maxlength: 100
        },
        featured: {
            type: Boolean,
            default: false
        },
        order: {
            type: Number,
            default: 0
        }
    }],
    publications: [{
        title: {
            type: String,
            required: true,
            maxlength: 300,
            index: 'text'
        },
        publisher: {
            type: String,
            default: '',
            maxlength: 200,
            index: true
        },
        publishDate: {
            type: Date,
            index: true
        },
        url: { type: String, default: '' },
        doi: { type: String, default: '' },
        description: {
            type: String,
            default: '',
            maxlength: 1000
        },
        authors: [{ type: String }],
        type: {
            type: String,
            enum: ['article', 'book', 'paper', 'blog', 'presentation'],
            default: 'article',
            index: true
        },
        citations: {
            type: Number,
            default: 0
        }
    }],
    honors: [{
        title: {
            type: String,
            required: true,
            maxlength: 200,
            index: 'text'
        },
        issuer: {
            type: String,
            required: true,
            maxlength: 200,
            index: true
        },
        issueDate: {
            type: Date,
            required: true,
            index: true
        },
        description: {
            type: String,
            default: '',
            maxlength: 1000
        },
        category: {
            type: String,
            enum: ['academic', 'professional', 'community', 'technical', 'leadership'],
            default: 'professional',
            index: true
        },
        level: {
            type: String,
            enum: ['local', 'regional', 'national', 'international'],
            default: 'local',
            index: true
        }
    }],
    volunteer: [{
        organization: {
            type: String,
            required: true,
            maxlength: 200,
            index: true
        },
        role: {
            type: String,
            required: true,
            maxlength: 200,
            index: true
        },
        cause: {
            type: String,
            default: '',
            maxlength: 100,
            index: true
        },
        startDate: {
            type: Date,
            required: true
        },
        endDate: { type: Date },
        isCurrent: {
            type: Boolean,
            default: false
        },
        description: {
            type: String,
            default: '',
            maxlength: 1000
        },
        hoursPerWeek: {
            type: Number,
            min: 0
        },
        totalHours: {
            type: Number,
            min: 0
        }
    }],
    testScores: [{
        testName: {
            type: String,
            required: true,
            index: true
        },
        score: {
            type: String,
            required: true
        },
        maxScore: { type: String },
        percentile: { type: Number, min: 0, max: 100 },
        testDate: {
            type: Date,
            required: true
        },
        validUntil: { type: Date }
    }],
    organizations: [{
        name: {
            type: String,
            required: true,
            index: true
        },
        membershipType: {
            type: String,
            enum: ['member', 'senior-member', 'fellow', 'board-member'],
            default: 'member'
        },
        joinDate: { type: Date },
        position: { type: String, default: '' },
        isActive: { type: Boolean, default: true },
        description: { type: String, maxlength: 500 }
    }],
    settings: {
        profileSlug: {
            type: String,
            unique: true,
            sparse: true,
            lowercase: true,
            match: /^[a-z0-9-]+$/,
            maxlength: 100,
            index: true
        },
        visibility: {
            type: String,
            enum: ['public', 'connections', 'private'],
            default: 'public',
            index: true
        },
        searchable: {
            type: Boolean,
            default: true,
            index: true
        },
        showEmail: { type: Boolean, default: false },
        showPhone: { type: Boolean, default: false },
        showSalary: { type: Boolean, default: false },
        allowMessages: { type: Boolean, default: true },
        emailNotifications: { type: Boolean, default: true },
        pushNotifications: { type: Boolean, default: true },
        twoFactorEnabled: { type: Boolean, default: false },
        profileTheme: {
            type: String,
            enum: ['default', 'dark', 'colorful', 'minimal'],
            default: 'default'
        },
        dataRetention: { // Added for GDPR/CCPA compliance
            type: String,
            enum: ['standard', 'limited', 'minimal'],
            default: 'standard'
        }
    },
    analytics: {
        profileViews: {
            type: Number,
            default: 0,
            index: true
        },
        uniqueViews: {
            type: Number,
            default: 0
        },
        lastViewedAt: {
            type: Date,
            index: true
        },
        searchAppearances: {
            type: Number,
            default: 0
        },
        completionScore: {
            type: Number,
            default: 0,
            min: 0,
            max: 100,
            index: true
        },
        responseRate: {
            type: Number,
            default: 0,
            min: 0,
            max: 100
        },
        averageRating: {
            type: Number,
            default: 0,
            min: 0,
            max: 5
        },
        totalRatings: {
            type: Number,
            default: 0
        },
        bookmarkCount: {
            type: Number,
            default: 0
        },
        shareCount: {
            type: Number,
            default: 0
        },
        weeklyViews: [{
            week: Date,
            views: Number
        }],
        topSkillsViewed: [{
            skill: String,
            count: Number
        }],
        profileStrength: { // Added for gamification
            type: String,
            enum: ['beginner', 'intermediate', 'advanced', 'expert'],
            default: 'beginner'
        }
    },
    verification: {
        isVerified: {
            type: Boolean,
            default: false,
            index: true
        },
        verifiedAt: { type: Date },
        verifiedBy: { type: String },
        verificationLevel: {
            type: String,
            enum: ['basic', 'premium', 'enterprise'],
            default: 'basic'
        },
        badges: [{
            type: String,
            enum: ['early-adopter', 'top-performer', 'verified-professional', 'mentor', 'thought-leader', 'community-leader']
        }]
    },
    accountType: {
        type: String,
        enum: ['free', 'premium', 'business', 'enterprise'],
        default: 'free',
        index: true
    },
    status: {
        type: String,
        enum: ['active', 'inactive', 'suspended', 'deleted', 'pending'],
        default: 'active',
        index: true
    },
    aiEnhancements: {
        skillsSuggested: [{ type: String }],
        headlineSuggestions: [{ type: String }],
        summarySuggestions: [{ type: String }],
        lastAiUpdate: { type: Date },
        profileScore: { type: Number, min: 0, max: 100 },
        industryMatch: { type: Number, min: 0, max: 100 },
        salaryEstimate: {
            min: { type: Number },
            max: { type: Number },
            currency: { type: String, default: 'USD' },
            lastUpdated: { type: Date }
        },
        recommendationWeight: { // Added for AI-driven recommendations
            type: Number,
            default: 0,
            min: 0,
            max: 100
        }
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
    lastLoginAt: {
        type: Date,
        index: true
    },
    lastProfileEdit: {
        type: Date,
        index: true
    },
    cacheVersion: { // Added for cache invalidation
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
    collection: 'profiles',
    read: 'secondaryPreferred',
    shardKey: { userId: 1, 'location.country': 1 }, // Enhanced sharding
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
profileSchema.index({ userId: 1 }, { unique: true, name: 'idx_userId_unique' });
profileSchema.index({ 'contact.primaryEmail': 1 }, { unique: true, sparse: true, name: 'idx_email_unique' });
profileSchema.index({ 'settings.profileSlug': 1 }, { unique: true, sparse: true, name: 'idx_slug_unique' });
profileSchema.index({ status: 1, 'settings.visibility': 1, 'settings.searchable': 1 }, { name: 'idx_status_visibility' });
profileSchema.index({
    'location.country': 1,
    'location.city': 1,
    status: 1
}, { name: 'idx_location_search' });
profileSchema.index({
    'skills.name': 1,
    'skills.level': 1,
    status: 1
}, { name: 'idx_skills_search' });
profileSchema.index({
    'experience.company': 1,
    'experience.position': 1,
    status: 1
}, { name: 'idx_experience_search' });
profileSchema.index({
    'analytics.profileViews': -1,
    status: 1,
    'settings.visibility': 1
}, { name: 'idx_popular_profiles' });
profileSchema.index({
    'analytics.completionScore': -1,
    status: 1
}, { name: 'idx_quality_profiles' });
profileSchema.index({
    updatedAt: -1,
    status: 1
}, { name: 'idx_recent_updates' });
profileSchema.index({
    lastLoginAt: -1,
    status: 1
}, { name: 'idx_active_users' });
profileSchema.index({ 'location.coordinates': '2dsphere' }, { name: 'idx_geo_location' });
profileSchema.index({
    'personalInfo.firstName': 1,
    'personalInfo.lastName': 1,
    status: 1
}, { name: 'idx_name_search' });
profileSchema.index({
    'verification.isVerified': 1,
    'analytics.completionScore': -1,
    status: 1
}, { name: 'idx_verified_quality' });
profileSchema.index({
    accountType: 1,
    'analytics.profileViews': -1,
    status: 1
}, { name: 'idx_account_type_popularity' });
profileSchema.index({
    createdAt: 1,
    status: 1
}, { name: 'idx_registration_analytics' });
profileSchema.index({
    'lastProfileEdit': -1,
    status: 1
}, { name: 'idx_profile_activity' });
profileSchema.index({
    'experience.industry': 1,
    'experience.isCurrent': 1,
    status: 1
}, { name: 'idx_industry_current' });
profileSchema.index({
    'certifications.issuingOrg': 1,
    'certifications.verified': 1,
    status: 1
}, { name: 'idx_certifications' });
profileSchema.index({
    'education.institution': 1,
    'education.degree': 1,
    status: 1
}, { name: 'idx_education' });
profileSchema.index({
    'personalInfo.firstName': 'text',
    'personalInfo.lastName': 'text',
    'personalInfo.tagline': 'text',
    'headline': 'text',
    'summary': 'text',
    'skills.name': 'text',
    'experience.company': 'text',
    'experience.position': 'text',
    'experience.description': 'text',
    'education.institution': 'text',
    'education.degree': 'text',
    'projects.title': 'text',
    'publications.title': 'text'
}, {
    weights: {
        'personalInfo.firstName': 10,
        'personalInfo.lastName': 10,
        'headline': 8,
        'skills.name': 7,
        'experience.position': 6,
        'experience.company': 5,
        'personalInfo.tagline': 4,
        'summary': 3,
        'education.degree': 3,
        'projects.title': 2,
        'publications.title': 2,
        'experience.description': 1
    },
    name: 'idx_fulltext_search'
});

// ===========================
// PRE/POST HOOKS
// ===========================
profileSchema.pre('save', function (next) {
    if (!this.settings.profileSlug && this.personalInfo?.firstName && this.personalInfo?.lastName) {
        this.settings.profileSlug = this.generateProfileSlug();
    }

    if (this.experience && this.experience.length > 0) {
        this.experience.forEach(exp => {
            if (exp.startDate) {
                const endDate = exp.endDate || new Date();
                const months = (endDate - exp.startDate) / (1000 * 60 * 60 * 24 * 30.44);
                exp.duration = Math.round(months);
            }
        });
    }

    this.calculateCompletionScore();

    if (this.isModified() && !this.isNew) {
        this.lastProfileEdit = new Date();
        this.cacheVersion += 1; // Invalidate cache
    }

    this.updatedAt = new Date();
    next();
});

profileSchema.pre(/^find/, function (next) {
    if (!this.getQuery().status) {
        this.where({ status: { $ne: 'deleted' } });
    }
    next();
});

profileSchema.pre(['findOneAndUpdate', 'updateOne', 'updateMany'], function (next) {
    this.set({ updatedAt: new Date(), cacheVersion: { $inc: 1 } });
    next();
});

// ===========================
// INSTANCE METHODS
// ===========================
profileSchema.methods.generateProfileSlug = function () {
    const baseSlug = `${this.personalInfo.firstName}-${this.personalInfo.lastName}`
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '');

    const timestamp = Date.now().toString(36);
    const randomSuffix = Math.random().toString(36).substring(2, 6);
    return `${baseSlug}-${timestamp}${randomSuffix}`;
};

profileSchema.methods.calculateCompletionScore = function () {
    let score = 0;
    const weights = {
        personalInfo: 15,
        headline: 10,
        summary: 15,
        experience: 25,
        education: 10,
        skills: 15,
        profilePhoto: 5,
        certifications: 3,
        projects: 2
    };

    if (this.personalInfo?.firstName && this.personalInfo?.lastName) {
        score += weights.personalInfo;
    }

    if (this.headline && this.headline.trim().length >= 10) {
        score += weights.headline;
    }

    if (this.summary && this.summary.trim().length >= 100) {
        score += weights.summary;
    }

    if (this.experience && this.experience.length > 0) {
        const hasDetailedExp = this.experience.some(exp =>
            exp.description && exp.description.trim().length >= 50
        );
        score += hasDetailedExp ? weights.experience : weights.experience * 0.6;
    }

    if (this.education && this.education.length > 0) {
        score += weights.education;
    }

    if (this.skills && this.skills.length >= 3) {
        score += weights.skills;
    } else if (this.skills && this.skills.length > 0) {
        score += weights.skills * 0.5;
    }

    if (this.media?.profilePhoto?.url) {
        score += weights.profilePhoto;
    }

    if (this.certifications && this.certifications.length > 0) {
        score += weights.certifications;
    }

    if (this.projects && this.projects.length > 0) {
        score += weights.projects;
    }

    this.analytics.completionScore = Math.min(score, 100);
    this.analytics.profileStrength = this.calculateProfileStrength(score);
    return this.analytics.completionScore;
};

profileSchema.methods.calculateProfileStrength = function (score) {
    if (score >= 90) return 'expert';
    if (score >= 70) return 'advanced';
    if (score >= 50) return 'intermediate';
    return 'beginner';
};

profileSchema.methods.incrementProfileViews = async function (viewerId = null) {
    const now = new Date();
    const hourAgo = new Date(now - 60 * 60 * 1000);

    if (!this.analytics.lastViewedAt || this.analytics.lastViewedAt < hourAgo) {
        this.analytics.profileViews += 1;
        this.analytics.lastViewedAt = now;

        const weekStart = new Date(now);
        weekStart.setDate(weekStart.getDate() - weekStart.getDay());
        weekStart.setHours(0, 0, 0, 0);

        const weeklyView = this.analytics.weeklyViews.find(w =>
            w.week.getTime() === weekStart.getTime()
        );

        if (weeklyView) {
            weeklyView.views += 1;
        } else {
            this.analytics.weeklyViews.push({
                week: weekStart,
                views: 1
            });

            if (this.analytics.weeklyViews.length > 12) {
                this.analytics.weeklyViews = this.analytics.weeklyViews.slice(-12);
            }
        }

        this.cacheVersion += 1;
        return this.save({ validateBeforeSave: false });
    }
};

profileSchema.methods.getPublicProfile = function () {
    const profile = this.toObject();

    if (!this.settings.showEmail) {
        delete profile.contact.primaryEmail;
        delete profile.contact.secondaryEmail;
    }

    if (!this.settings.showPhone) {
        delete profile.contact.phoneNumber;
    }

    delete profile.settings.twoFactorEnabled;
    delete profile.analytics.weeklyViews;
    delete profile.aiEnhancements;

    profile.analytics = {
        profileViews: profile.analytics.profileViews,
        completionScore: profile.analytics.completionScore,
        lastViewedAt: profile.analytics.lastViewedAt,
        profileStrength: profile.analytics.profileStrength
    };

    return profile;
};

profileSchema.methods.getSearchSummary = function () {
    return {
        userId: this.userId,
        personalInfo: this.personalInfo,
        headline: this.headline,
        location: {
            city: this.location.city,
            state: this.location.state,
            country: this.location.country
        },
        media: {
            profilePhoto: this.media.profilePhoto
        },
        settings: {
            profileSlug: this.settings.profileSlug
        },
        analytics: {
            profileViews: this.analytics.profileViews,
            completionScore: this.analytics.completionScore,
            profileStrength: this.analytics.profileStrength
        },
        verification: {
            isVerified: this.verification.isVerified,
            badges: this.verification.badges
        },
        topSkills: this.skills.slice(0, 5).map(skill => skill.name),
        currentPosition: this.experience.find(exp => exp.isCurrent)?.position || '',
        currentCompany: this.experience.find(exp => exp.isCurrent)?.company || '',
        updatedAt: this.updatedAt
    };
};

profileSchema.methods.endorseSkill = function (skillName, endorserId) {
    const skill = this.skills.find(s => s.name.toLowerCase() === skillName.toLowerCase());
    if (skill) {
        if (!skill.endorsers.includes(endorserId)) {
            skill.endorsements.count += 1;
            skill.endorsements.lastEndorsedAt = new Date();
            skill.endorsers.push(endorserId);
            this.cacheVersion += 1;
            return this.save();
        }
        return Promise.resolve(this);
    }
    return Promise.reject(new Error('Skill not found'));
};

profileSchema.methods.getCareerProgression = function () {
    if (!this.experience || this.experience.length === 0) {
        return { totalExperience: 0, positions: 0, companies: 0 };
    }

    const sortedExperience = this.experience.sort((a, b) => new Date(a.startDate) - new Date(b.startDate));
    const totalMonths = sortedExperience.reduce((total, exp) => total + (exp.duration || 0), 0);
    const uniqueCompanies = new Set(sortedExperience.map(exp => exp.company)).size;

    return {
        totalExperience: Math.round(totalMonths / 12 * 10) / 10,
        positions: sortedExperience.length,
        companies: uniqueCompanies,
        careerPath: sortedExperience.map(exp => ({
            company: exp.company,
            position: exp.position,
            duration: exp.duration,
            startDate: exp.startDate,
            endDate: exp.endDate,
            isCurrent: exp.isCurrent
        }))
    };
};

// ===========================
// STATIC METHODS
// ===========================
profileSchema.statics.findBySlug = function (slug) {
    return this.findOne({
        'settings.profileSlug': slug,
        status: 'active',
        'settings.visibility': { $in: ['public'] }
    })
        .cache({ key: `profile:slug:${slug}` }) // Added caching
        .select('-analytics.weeklyViews -settings.twoFactorEnabled -aiEnhancements')
        .lean();
};

profileSchema.statics.searchProfiles = function (searchQuery, options = {}) {
    const {
        page = 1,
        limit = 20,
        location,
        skills,
        experience,
        education,
        sortBy = 'relevance',
        minExperience = 0,
        maxExperience = 50,
        industries,
        employmentTypes,
        verifiedOnly = false,
        accountTypes
    } = options;

    const pipeline = [];

    const matchStage = {
        status: 'active',
        'settings.visibility': 'public',
        'settings.searchable': true
    };

    if (searchQuery && searchQuery.trim()) {
        matchStage.$text = { $search: searchQuery.trim() };
    }

    if (location) {
        matchStage.$or = [
            { 'location.city': { $regex: location, $options: 'i' } },
            { 'location.state': { $regex: location, $options: 'i' } },
            { 'location.country': { $regex: location, $options: 'i' } }
        ];
    }

    if (skills && skills.length > 0) {
        matchStage['skills.name'] = {
            $in: skills.map(skill => new RegExp(skill, 'i'))
        };
    }

    if (experience) {
        matchStage.$or = [
            { 'experience.company': { $regex: experience, $options: 'i' } },
            { 'experience.position': { $regex: experience, $options: 'i' } }
        ];
    }

    if (industries && industries.length > 0) {
        matchStage['experience.industry'] = { $in: industries };
    }

    if (employmentTypes && employmentTypes.length > 0) {
        matchStage['experience.employmentType'] = { $in: employmentTypes };
    }

    if (verifiedOnly) {
        matchStage['verification.isVerified'] = true;
    }

    if (accountTypes && accountTypes.length > 0) {
        matchStage.accountType = { $in: accountTypes };
    }

    pipeline.push({ $match: matchStage });

    pipeline.push({
        $addFields: {
            totalExperience: {
                $sum: '$experience.duration'
            },
            relevanceScore: {
                $add: [
                    { $multiply: ['$analytics.completionScore', 0.3] },
                    { $multiply: ['$analytics.profileViews', 0.0001] },
                    { $multiply: ['$aiEnhancements.recommendationWeight', 0.2] }, // Added AI weight
                    searchQuery && searchQuery.trim() ? { $meta: 'textScore' } : 0
                ]
            },
            hasPhoto: {
                $cond: [{ $ne: ['$media.profilePhoto.url', ''] }, 1, 0]
            }
        }
    });

    if (minExperience > 0 || maxExperience < 50) {
        pipeline.push({
            $match: {
                totalExperience: {
                    $gte: minExperience * 12,
                    $lte: maxExperience * 12
                }
            }
        });
    }

    let sortStage = {};
    switch (sortBy) {
        case 'recent':
            sortStage = { updatedAt: -1 };
            break;
        case 'popular':
            sortStage = { 'analytics.profileViews': -1, 'analytics.completionScore': -1 };
            break;
        case 'experience':
            sortStage = { totalExperience: -1, 'analytics.completionScore': -1 };
            break;
        case 'name':
            sortStage = { 'personalInfo.firstName': 1, 'personalInfo.lastName': 1 };
            break;
        case 'completion':
            sortStage = { 'analytics.completionScore': -1, 'analytics.profileViews': -1 };
            break;
        default:
            sortStage = { relevanceScore: -1, hasPhoto: -1 };
    }

    pipeline.push({ $sort: sortStage });

    const skip = (page - 1) * limit;
    pipeline.push({ $skip: skip });
    pipeline.push({ $limit: limit });

    pipeline.push({
        $project: {
            userId: 1,
            personalInfo: 1,
            headline: 1,
            location: {
                city: 1,
                state: 1,
                country: 1
            },
            media: {
                profilePhoto: 1
            },
            settings: {
                profileSlug: 1
            },
            analytics: {
                profileViews: 1,
                completionScore: 1,
                profileStrength: 1
            },
            verification: {
                isVerified: 1,
                badges: 1
            },
            skills: { $slice: ['$skills.name', 5] },
            currentExperience: {
                $filter: {
                    input: '$experience',
                    cond: { $eq: ['$this.isCurrent', true] }
                }
            },
            totalExperience: 1,
            relevanceScore: 1,
            updatedAt: 1
        }
    });

    return this.aggregate(pipeline).cache({ key: `search:${JSON.stringify(options)}:${searchQuery}` });
};

profileSchema.statics.getTrendingProfiles = function (limit = 10, timeframe = 7) {
    const daysAgo = new Date();
    daysAgo.setDate(daysAgo.getDate() - timeframe);

    return this.find({
        status: 'active',
        'settings.visibility': 'public',
        updatedAt: { $gte: daysAgo },
        'analytics.profileViews': { $gte: 10 }
    })
        .sort({
            'analytics.profileViews': -1,
            updatedAt: -1,
            'analytics.completionScore': -1
        })
        .limit(limit)
        .select('personalInfo headline media.profilePhoto analytics.profileViews settings.profileSlug analytics.profileStrength')
        .cache({ key: `trending:${timeframe}:${limit}` })
        .lean();
};

profileSchema.statics.getProfilesNearLocation = function (longitude, latitude, maxDistance = 50000, limit = 20) {
    return this.find({
        status: 'active',
        'settings.visibility': 'public',
        'location.coordinates': {
            $near: {
                $geometry: {
                    type: 'Point',
                    coordinates: [longitude, latitude]
                },
                $maxDistance: maxDistance
            }
        }
    })
        .limit(limit)
        .select('personalInfo headline location media.profilePhoto settings.profileSlug analytics.profileStrength')
        .cache({ key: `geo:${longitude}:${latitude}:${maxDistance}:${limit}` })
        .lean();
};

profileSchema.statics.getSkillBasedRecommendations = function (userId, userSkills, limit = 10) {
    return this.aggregate([
        {
            $match: {
                status: 'active',
                'settings.visibility': 'public',
                userId: { $ne: userId },
                'skills.name': { $in: userSkills }
            }
        },
        {
            $addFields: {
                skillMatchCount: {
                    $size: {
                        $setIntersection: ['$skills.name', userSkills]
                    }
                }
            }
        },
        {
            $sort: {
                skillMatchCount: -1,
                'analytics.completionScore': -1,
                'analytics.profileViews': -1,
                'aiEnhancements.recommendationWeight': -1
            }
        },
        {
            $limit: limit
        },
        {
            $project: {
                personalInfo: 1,
                headline: 1,
                media: { profilePhoto: 1 },
                settings: { profileSlug: 1 },
                skillMatchCount: 1,
                analytics: {
                    profileViews: 1,
                    completionScore: 1,
                    profileStrength: 1
                }
            }
        }
    ]).cache({ key: `recommend:${userId}:${userSkills.join(',')}:${limit}` });
};

profileSchema.statics.getAnalyticsSummary = function (timeframe = 30) {
    const daysAgo = new Date();
    daysAgo.setDate(daysAgo.getDate() - timeframe);

    return this.aggregate([
        {
            $facet: {
                totalStats: [
                    {
                        $match: { status: { $ne: 'deleted' } }
                    },
                    {
                        $group: {
                            _id: null,
                            totalProfiles: { $sum: 1 },
                            activeProfiles: {
                                $sum: { $cond: [{ $eq: ['$status', 'active'] }, 1, 0] }
                            },
                            verifiedProfiles: {
                                $sum: { $cond: ['$verification.isVerified', 1, 0] }
                            },
                            avgCompletionScore: { $avg: '$analytics.completionScore' },
                            totalViews: { $sum: '$analytics.profileViews' }
                        }
                    }
                ],
                recentActivity: [
                    {
                        $match: {
                            createdAt: { $gte: daysAgo },
                            status: 'active'
                        }
                    },
                    {
                        $group: {
                            _id: {
                                $dateToString: {
                                    format: '%Y-%m-%d',
                                    date: '$createdAt'
                                }
                            },
                            newRegistrations: { $sum: 1 }
                        }
                    },
                    {
                        $sort: { _id: 1 }
                    }
                ],
                topSkills: [
                    {
                        $match: { status: 'active' }
                    },
                    {
                        $unwind: '$skills'
                    },
                    {
                        $group: {
                            _id: '$skills.name',
                            count: { $sum: 1 },
                            avgEndorsements: { $avg: '$skills.endorsements.count' }
                        }
                    },
                    {
                        $sort: { count: -1 }
                    },
                    {
                        $limit: 20
                    }
                ]
            }
        }
    ]).cache({ key: `analytics:${timeframe}` });
};

profileSchema.statics.bulkUpdateCompletionScores = function (batchSize = 1000) {
    const cursor = this.find({ status: 'active' }).cursor();
    let processed = 0;

    return cursor.eachAsync(async (profile) => {
        const completionScore = profile.calculateCompletionScore();
        await this.updateOne(
            { _id: profile._id },
            {
                $set: {
                    'analytics.completionScore': completionScore,
                    'analytics.profileStrength': profile.analytics.profileStrength,
                    updatedAt: new Date(),
                    cacheVersion: { $inc: 1 }
                }
            }
        );

        processed++;
        if (processed % 100 === 0) {
            console.log(`Updated completion scores for ${processed} profiles`);
        }
    });
};

// ===========================
// VALIDATION METHODS
// ===========================
profileSchema.methods.validateEmail = function (email) {
    if (!email) return true;
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
};

profileSchema.methods.validateUrl = function (url) {
    if (!url) return true;
    const urlRegex = /^(https?:\/\/)?([\w-]+\.)+[\w-]+(\/[\w- ./?%&=]*)?$/;
    return urlRegex.test(url);
};

profileSchema.methods.validatePhone = function (phone) {
    if (!phone) return true;
    const cleanPhone = phone.replace(/[\s-()]/g, '');
    const phoneRegex = /^\+?[1-9]\d{1,14}$/;
    return phoneRegex.test(cleanPhone);
};

// ===========================
// CUSTOM VALIDATORS
// ===========================
profileSchema.path('contact.primaryEmail').validate(function (value) {
    if (!value) return false;
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}, 'Invalid email format');

profileSchema.path('contact.website').validate(function (value) {
    if (!value) return true;
    return /^(https?:\/\/)?([\w-]+\.)+[\w-]+(\/[\w- ./?%&=]*)?$/.test(value);
}, 'Invalid website URL');

profileSchema.path('contact.phoneNumber').validate(function (value) {
    if (!value) return true;
    const cleanPhone = value.replace(/[\s-()]/g, '');
    return /^\+?[1-9]\d{1,14}$/.test(cleanPhone);
}, 'Invalid phone number format');

profileSchema.path('skills').validate(function (skills) {
    if (!skills || skills.length === 0) return true;
    const skillNames = skills.map(skill => skill.name.toLowerCase());
    return skillNames.length === new Set(skillNames).size;
}, 'Duplicate skills are not allowed');

// ===========================
// VIRTUAL FIELDS
// ===========================
profileSchema.virtual('fullName').get(function () {
    const { firstName, middleName, lastName } = this.personalInfo || {};
    return [firstName, middleName, lastName].filter(Boolean).join(' ');
});

profileSchema.virtual('totalExperience').get(function () {
    if (!this.experience || this.experience.length === 0) return 0;
    const totalMonths = this.experience.reduce((sum, exp) => sum + (exp.duration || 0), 0);
    return Math.round(totalMonths / 12 * 10) / 10;
});

profileSchema.virtual('isComplete').get(function () {
    return this.analytics.completionScore >= 70;
});

profileSchema.virtual('profileUrl').get(function () {
    return this.settings.profileSlug
        ? `/profile/${this.settings.profileSlug}`
        : `/profile/user/${this.userId}`;
});

// ===========================
// QUERY HELPERS
// ===========================
profileSchema.query.cache = function (options = {}) {
    // Note: Cache implementation depends on your caching solution (e.g., Redis)
    // This is a placeholder for cache middleware
    return this;
};

// ===========================
// EXPORT MODEL
// ===========================
const Profile = mongoose.model('Profile', profileSchema);

Profile.createCollection({
    capped: false,
    size: null,
    max: null,
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: ["userId", "personalInfo", "contact"],
            properties: {
                userId: {
                    bsonType: "string",
                    description: "User ID is required and must be a string"
                },
                personalInfo: {
                    bsonType: "object",
                    required: ["firstName", "lastName"],
                    description: "Personal info with required first and last name"
                },
                contact: {
                    bsonType: "object",
                    required: ["primaryEmail"],
                    description: "Contact info with required email"
                }
            }
        }
    }
}).catch(() => {
    // Collection might already exist
});

export default Profile;