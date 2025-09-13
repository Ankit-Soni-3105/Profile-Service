import mongoose, { Schema } from 'mongoose';
import aggregatePaginate from 'mongoose-aggregate-paginate-v2';
import mongooseAlgolia from 'mongoose-algolia';
import validator from 'validator';
import sanitizeHtml from 'sanitize-html';
import Redis from 'ioredis';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';

// Redis Cluster Configuration for 1M+ Users
const createRedisCluster = () => {
    if (process.env.REDIS_CLUSTER_NODES) {
        return new Redis.Cluster(
            process.env.REDIS_CLUSTER_NODES.split(',').map(node => ({
                host: node.split(':')[0],
                port: parseInt(node.split(':')[1]),
            })),
            {
                redisOptions: {
                    password: process.env.REDIS_PASSWORD,
                    connectTimeout: 10000,
                    maxRetriesPerRequest: 5,
                    retryDelayOnFailover: 100,
                    keepAlive: 1000,
                },
                enableOfflineQueue: false,
                scaleReads: 'slave',
                slotsRefreshTimeout: 10000,
                slotsRefreshInterval: 30000,
            }
        );
    }

    return new Redis({
        host: process.env.REDIS_HOST || 'localhost',
        port: process.env.REDIS_PORT || 6379,
        password: process.env.REDIS_PASSWORD,
        connectTimeout: 10000,
        maxRetriesPerRequest: 5,
        retryDelayOnFailover: 100,
        keepAlive: 1000,
        keyPrefix: 'skills:',
        db: 0,
    });
};

const redis = createRedisCluster();
redis.on('error', err => console.error('Redis error:', err));
redis.connect().catch(err => console.error('Redis connection error:', err));

// Cache TTL Constants
const CACHE_TTL = {
    SHORT: 300,      // 5 minutes
    MEDIUM: 1800,    // 30 minutes
    LONG: 3600,      // 1 hour
    EXTRA_LONG: 86400 // 24 hours
};

// Validation Functions
const validateSkillName = (value) => /^[a-zA-Z0-9\s\-&()#\+\/\.]+$/.test(value);
const validateURL = (value) => !value || validator.isURL(value, { require_protocol: true });
const validateEmail = (value) => !value || validator.isEmail(value);
const validateYearsExperience = (value) => value >= 0 && value <= 50;
const validateProficiencyLevel = (value) => ['beginner', 'intermediate', 'advanced', 'expert'].includes(value);

// Sub-Schemas
const categorySchema = new Schema({
    primary: { type: String, required: true, index: true }, // Changed to String for sharding
    secondary: [{ type: String, index: true }],
    tags: [{ type: String, trim: true, maxlength: 50, index: true }],
    industry: { type: String, enum: ['tech', 'finance', 'healthcare', 'education', 'marketing', 'engineering', 'creative', 'other'], index: true },
    subdomain: { type: String, trim: true, maxlength: 50 },
}, { _id: false });

const proficiencySchema = new Schema({
    level: {
        type: String,
        enum: ['beginner', 'intermediate', 'advanced', 'expert'],
        default: 'intermediate',
        validate: { validator: validateProficiencyLevel, message: 'Invalid proficiency level' },
        index: true
    },
    description: {
        type: String,
        maxlength: 1000,
        trim: true,
        set: v => v ? sanitizeHtml(v, { allowedTags: [], allowedAttributes: {} }) : v
    },
    selfAssessmentScore: {
        type: Number,
        min: 0,
        max: 100,
        default: 50
    },
    assessmentDate: {
        type: Date,
        index: true
    },
    assessmentMethod: {
        type: String,
        enum: ['self', 'peer-review', 'certification', 'project-based', 'quiz'],
        default: 'self'
    },
    progressGoals: [{
        goal: { type: String, maxlength: 200 },
        targetDate: { type: Date },
        status: { type: String, enum: ['pending', 'in-progress', 'completed'] }
    }],
}, { _id: false });

const experienceSchema = new Schema({
    years: {
        type: Number,
        min: 0,
        max: 50,
        default: 0,
        validate: { validator: validateYearsExperience, message: 'Years of experience must be between 0 and 50' }
    },
    lastUsed: {
        type: Date,
        index: true
    },
    frequency: {
        type: String,
        enum: ['daily', 'weekly', 'monthly', 'occasionally', 'rarely'],
        default: 'occasionally'
    },
    projectsCount: {
        type: Number,
        min: 0,
        default: 0
    },
    hoursInvested: {
        type: Number,
        min: 0,
        default: 0
    },
    learningCurve: {
        type: String,
        enum: ['steep', 'moderate', 'gentle'],
        default: 'moderate'
    },
}, { _id: false });

const prioritySchema = new Schema({
    userPriority: {
        type: Number,
        min: 1,
        max: 10,
        default: 5
    },
    aiSuggestedPriority: {
        type: Number,
        min: 1,
        max: 10
    },
    reason: {
        type: String,
        maxlength: 500
    },
    setAt: {
        type: Date,
        default: Date.now,
        index: true
    },
    reviewDate: {
        type: Date
    },
}, { _id: false });

const suggestionSchema = new Schema({
    recommendedByAI: {
        type: Boolean,
        default: false
    },
    suggestionSource: {
        type: String,
        enum: ['job-match', 'career-path', 'peer', 'trend-analysis', 'other'],
        default: 'other'
    },
    confidenceScore: {
        type: Number,
        min: 0,
        max: 100,
        default: 0
    },
    relatedSkills: [{
        type: String
    }],
    learningResources: [{
        title: { type: String, maxlength: 200 },
        url: { type: String, validate: { validator: validateURL, message: 'Invalid resource URL' } },
        type: { type: String, enum: ['course', 'book', 'video', 'article'] }
    }],
}, { _id: false });

const trendSchema = new Schema({
    currentTrend: {
        type: String,
        enum: ['emerging', 'growing', 'stable', 'declining'],
        default: 'stable',
        index: true
    },
    trendScore: {
        type: Number,
        min: 0,
        max: 100,
        default: 50,
        index: true
    },
    lastAnalyzed: {
        type: Date,
        default: Date.now,
        index: true
    },
    sources: [{
        source: { type: String, maxlength: 100 },
        scoreContribution: { type: Number, min: 0, max: 100 }
    }],
    historicalData: [{
        date: { type: Date },
        score: { type: Number, min: 0, max: 100 }
    }],
}, { _id: false });

const analysisSchema = new Schema({
    skillGaps: [{
        gap: { type: String, maxlength: 200 },
        severity: { type: String, enum: ['low', 'medium', 'high'] }
    }],
    strengths: [{
        strength: { type: String, maxlength: 200 },
        impact: { type: String, enum: ['low', 'medium', 'high'] }
    }],
    aiAnalysisDate: {
        type: Date,
        index: true
    },
    analysisScore: {
        type: Number,
        min: 0,
        max: 100
    },
    recommendations: [{
        text: { type: String, maxlength: 500 },
        priority: { type: Number, min: 1, max: 10 }
    }],
}, { _id: false });

const comparisonSchema = new Schema({
    peerComparison: {
        type: Number,
        min: 0,
        max: 100,
        default: 50
    },
    industryAverage: {
        type: Number,
        min: 0,
        max: 100
    },
    benchmarkSource: {
        type: String,
        maxlength: 100
    },
    lastCompared: {
        type: Date,
        index: true
    },
    comparisonMetrics: [{
        metric: { type: String, maxlength: 50 },
        value: { type: Number }
    }],
}, { _id: false });

const certificationSchema = new Schema({
    isCertified: {
        type: Boolean,
        default: false,
        index: true
    },
    certificationName: {
        type: String,
        maxlength: 200
    },
    issuer: {
        type: String,
        maxlength: 100,
        index: true
    },
    issueDate: {
        type: Date,
        index: true
    },
    expiryDate: {
        type: Date,
        index: true
    },
    url: {
        type: String,
        validate: { validator: validateURL, message: 'Invalid certification URL' }
    },
    verificationStatus: {
        type: String,
        enum: ['pending', 'verified', 'expired', 'invalid'],
        default: 'pending',
        index: true
    },
    renewalReminder: {
        type: Boolean,
        default: false
    },
}, { _id: false });

const synonymSchema = new Schema({
    names: [{
        type: String,
        trim: true,
        maxlength: 50,
        validate: { validator: validateSkillName, message: 'Invalid synonym name' }
    }],
    primarySynonym: {
        type: String,
        trim: true,
        maxlength: 50
    },
    languageVariants: [{
        language: { type: String, maxlength: 10 },
        name: { type: String, maxlength: 50 }
    }],
}, { _id: false });

const demandSchema = new Schema({
    marketDemand: {
        type: String,
        enum: ['low', 'medium', 'high', 'very-high'],
        default: 'medium',
        index: true
    },
    jobPostings: {
        type: Number,
        min: 0,
        default: 0
    },
    averageSalaryImpact: {
        type: Number,
        min: 0
    },
    demandGrowth: {
        type: Number,
        min: -100,
        max: 100,
        default: 0
    },
    regionalDemand: [{
        region: { type: String, maxlength: 50 },
        demandLevel: { type: String, enum: ['low', 'medium', 'high'] }
    }],
    lastUpdated: {
        type: Date,
        default: Date.now,
        index: true
    },
}, { _id: false });

const endorsementSchema = new Schema({
    endorserId: {
        type: String,
        required: true,
        index: true
    },
    endorserName: {
        type: String,
        maxlength: 100
    },
    endorserTitle: {
        type: String,
        maxlength: 100
    },
    endorserCompany: {
        type: String,
        maxlength: 100
    },
    relationship: {
        type: String,
        enum: ['manager', 'colleague', 'client', 'mentor', 'other']
    },
    endorsedAt: {
        type: Date,
        default: Date.now,
        index: true
    },
    comment: {
        type: String,
        maxlength: 1000,
        set: v => v ? sanitizeHtml(v, { allowedTags: [], allowedAttributes: {} }) : v
    },
    rating: {
        type: Number,
        min: 1,
        max: 5
    },
    isVerified: {
        type: Boolean,
        default: false,
        index: true
    },
    verificationMethod: {
        type: String,
        enum: ['linkedin', 'email', 'manual']
    },
}, { _id: false });

const verificationSchema = new Schema({
    isVerified: {
        type: Boolean,
        default: false,
        index: true
    },
    verifiedBy: {
        type: String
    },
    verificationDate: {
        type: Date,
        index: true
    },
    method: {
        type: String,
        enum: ['endorsement', 'certification', 'project', 'self', 'admin']
    },
    score: {
        type: Number,
        min: 0,
        max: 100,
        default: 0
    },
    documents: [{
        type: { type: String, enum: ['certificate', 'project-link', 'endorsement-proof'] },
        url: { type: String, validate: { validator: validateURL, message: 'Invalid document URL' } },
        uploadedAt: { type: Date, default: Date.now }
    }],
    contactEmail: {
        type: String,
        validate: { validator: validateEmail, message: 'Invalid contact email' }
    },
    contactVerified: {
        type: Boolean,
        default: false
    },
}, { _id: false });

const privacySchema = new Schema({
    isPublic: {
        type: Boolean,
        default: true,
        index: true
    },
    showProficiency: {
        type: Boolean,
        default: true
    },
    showEndorsements: {
        type: Boolean,
        default: true
    },
    visibleToConnections: {
        type: Boolean,
        default: true
    },
    visibleToRecruiters: {
        type: Boolean,
        default: true,
        index: true
    },
    searchable: {
        type: Boolean,
        default: true,
        index: true
    },
    allowEndorsements: {
        type: Boolean,
        default: true
    },
}, { _id: false });

const performanceSchema = new Schema({
    usageRating: {
        type: Number,
        min: 1,
        max: 5
    },
    feedback: [{
        text: { type: String, maxlength: 500 },
        from: { type: String },
        date: { type: Date }
    }],
    goals: [{
        title: { type: String, maxlength: 200 },
        status: { type: String, enum: ['not-started', 'in-progress', 'completed'] },
        deadline: { type: Date }
    }],
    achievements: [{
        type: String,
        maxlength: 200,
        date: { type: Date }
    }],
}, { _id: false });

const connectionsSchema = new Schema({
    linkedUsers: [{
        userId: { type: String },
        connectionType: { type: String, enum: ['shared-skill', 'endorsed', 'collaborated'] }
    }],
    networkStrength: {
        type: Number,
        min: 0,
        max: 100
    },
}, { _id: false });

const aiInsightsSchema = new Schema({
    recommendedLearningPaths: [{
        path: { type: String, maxlength: 200 },
        estimatedTime: { type: Number, min: 0 }
    }],
    careerImpact: {
        type: String,
        maxlength: 500
    },
    salaryBoostPrediction: {
        type: Number,
        min: 0
    },
    marketDemandForecast: [{
        period: { type: String, enum: ['short-term', 'medium-term', 'long-term'] },
        demand: { type: String, enum: ['low', 'medium', 'high'] }
    }],
    similarSkills: [{
        skillId: { type: String },
        similarityScore: { type: Number, min: 0, max: 100 }
    }],
    industryTrends: [{
        trend: { type: String, maxlength: 100 },
        relevance: { type: Number, min: 0, max: 100 }
    }],
    lastAnalyzed: {
        type: Date,
        index: true
    },
    aiModelVersion: {
        type: String,
        default: '1.0'
    },
}, { _id: false });

const metadataSchema = new Schema({
    source: {
        type: String,
        default: 'manual',
        enum: ['manual', 'linkedin', 'indeed', 'api', 'csv-import', 'ai-suggested'],
        index: true
    },
    importId: {
        type: String,
        maxlength: 100
    },
    templateId: {
        type: String
    },
    lastUpdated: {
        type: Date,
        default: Date.now,
        index: true
    },
    updateCount: {
        type: Number,
        default: 0,
        min: 0
    },
    version: {
        type: Number,
        default: 1,
        min: 1
    },
    isDuplicate: {
        type: Boolean,
        default: false,
        index: true
    },
    duplicateOf: {
        type: String
    },
}, { _id: false });

const analyticsSchema = new Schema({
    profileViews: {
        type: Number,
        default: 0,
        min: 0,
        index: true
    },
    endorsementCount: {
        type: Number,
        default: 0,
        min: 0,
        index: true
    },
    searchAppearances: {
        type: Number,
        default: 0,
        min: 0
    },
    engagementScore: {
        type: Number,
        default: 0,
        min: 0,
        index: true
    },
    lastViewed: {
        type: Date,
        index: true
    },
    clickThroughRate: {
        type: Number,
        default: 0,
        min: 0
    },
    shareCount: {
        type: Number,
        default: 0,
        min: 0
    },
    likesCount: {
        type: Number,
        default: 0,
        min: 0
    },
    commentsCount: {
        type: Number,
        default: 0,
        min: 0
    },
}, { _id: false });

const statusSchema = new Schema({
    isActive: {
        type: Boolean,
        default: true,
        index: true
    },
    isDeleted: {
        type: Boolean,
        default: false,
        index: true
    },
    isFeatured: {
        type: Boolean,
        default: false
    },
    deletedAt: {
        type: Date,
        index: true
    },
    archivedAt: {
        type: Date
    },
    featuredUntil: {
        type: Date
    },
    lastActiveAt: {
        type: Date,
        default: Date.now,
        index: true
    },
    workflow: {
        type: String,
        enum: ['draft', 'pending', 'published', 'archived'],
        default: 'published'
    },
}, { _id: false });

const socialSchema = new Schema({
    likes: [{
        userId: { type: String },
        likedAt: { type: Date }
    }],
    comments: [{
        userId: { type: String },
        comment: { type: String, maxlength: 500 },
        commentedAt: { type: Date }
    }],
    shares: [{
        userId: { type: String },
        platform: { type: String },
        sharedAt: { type: Date }
    }],
    bookmarks: [{
        userId: { type: String },
        bookmarkedAt: { type: Date }
    }],
}, { _id: false });

// Main Skill Schema
const skillSchema = new Schema({
    _id: {
        type: String,
        default: () => uuidv4(),
        index: true
    },
    name: {
        type: String,
        required: [true, 'Skill name is required'],
        trim: true,
        maxlength: 50,
        index: true,
        unique: true,
        validate: { validator: validateSkillName, message: 'Invalid skill name format' }
    },
    normalizedName: {
        type: String,
        index: true
    },
    description: {
        type: String,
        maxlength: 2000,
        trim: true,
        set: v => v ? sanitizeHtml(v, { allowedTags: [], allowedAttributes: {} }) : v
    },
    category: categorySchema,
    proficiency: proficiencySchema,
    experience: experienceSchema,
    priority: prioritySchema,
    suggestion: suggestionSchema,
    trend: trendSchema,
    analysis: analysisSchema,
    comparison: comparisonSchema,
    certification: certificationSchema,
    synonyms: synonymSchema,
    demand: demandSchema,
    endorsements: [endorsementSchema],
    verification: verificationSchema,
    privacy: privacySchema,
    performance: performanceSchema,
    connections: connectionsSchema,
    aiInsights: aiInsightsSchema,
    metadata: metadataSchema,
    analytics: analyticsSchema,
    status: statusSchema,
    social: socialSchema,
    cache: {
        searchVector: { type: String, index: 'text' },
        popularityScore: { type: Number, default: 0, index: true },
        trendingScore: { type: Number, default: 0, index: true },
        cacheVersion: { type: Number, default: 1 },
        lastCacheUpdate: { type: Date, default: Date.now, index: true }
    }
}, {
    timestamps: true,
    collection: 'skills',
    autoIndex: process.env.NODE_ENV !== 'production',
    readPreference: 'secondaryPreferred',
    writeConcern: { w: 1, wtimeout: 5000 },
    toJSON: {
        virtuals: true,
        transform: (doc, ret) => {
            delete ret.social.comments;
            delete ret.verification.documents;
            delete ret.__v;
            delete ret.cache.searchVector;
            return ret;
        }
    },
    toObject: { virtuals: true },
    minimize: false,
    strict: 'throw',
    shardKey: { name: 'hashed' }
});

// Indexes
skillSchema.index({ 'category.primary': 1, 'status.isActive': 1 }, { background: true });
skillSchema.index({ 'demand.marketDemand': 1, 'trend.trendScore': -1 }, { background: true });
skillSchema.index({ 'experience.lastUsed': -1, 'status.isActive': 1 }, { background: true });
skillSchema.index({ 'verification.isVerified': 1, 'verification.score': -1 }, { background: true });
skillSchema.index({ 'analytics.engagementScore': -1, 'status.isActive': 1 }, { background: true });
skillSchema.index({ 'aiInsights.lastAnalyzed': -1 }, { background: true });
skillSchema.index({ 'cache.popularityScore': -1, 'status.isActive': 1 }, { background: true });
skillSchema.index({ 'cache.trendingScore': -1, 'privacy.isPublic': 1 }, { background: true });
skillSchema.index({ 'status.deletedAt': 1 }, { expireAfterSeconds: 7776000, sparse: true });
skillSchema.index({
    name: 'text',
    normalizedName: 'text',
    description: 'text',
    'synonyms.names': 'text',
    'category.tags': 'text',
    'cache.searchVector': 'text'
}, {
    weights: { name: 10, normalizedName: 8, description: 5, 'synonyms.names': 4, 'category.tags': 3, 'cache.searchVector': 1 },
    name: 'skill_text_search',
    background: true
});
skillSchema.index({ 'demand.jobPostings': -1, 'demand.demandGrowth': -1 }, { background: true });
skillSchema.index({ 'proficiency.level': 1, 'experience.years': 1 }, { background: true });
skillSchema.index({ 'certification.isCertified': 1, 'certification.expiryDate': 1 }, { sparse: true });
skillSchema.index({ 'metadata.source': 1, 'metadata.lastUpdated': -1 }, { background: true });
skillSchema.index({ 'category.primary': 1, 'proficiency.level': 1, 'verification.isVerified': 1 }, { background: true });
skillSchema.index({ 'trend.currentTrend': 1, 'demand.marketDemand': 1, 'analytics.engagementScore': -1 }, { background: true });
skillSchema.index({ 'privacy.isPublic': 1, 'status.isActive': 1, 'cache.popularityScore': -1 }, { background: true });

// Virtuals
skillSchema.virtual('endorsementCount').get(function () {
    return this.endorsements?.length || 0;
});
skillSchema.virtual('isHighDemand').get(function () {
    return ['high', 'very-high'].includes(this.demand.marketDemand);
});
skillSchema.virtual('proficiencyProgress').get(function () {
    const levels = { beginner: 25, intermediate: 50, advanced: 75, expert: 100 };
    return levels[this.proficiency.level] || 0;
});
skillSchema.virtual('expirationStatus').get(function () {
    if (!this.certification.expiryDate) return 'no-expiry';
    return this.certification.expiryDate < new Date() ? 'expired' : 'valid';
});
skillSchema.virtual('networkReach').get(function () {
    return this.connections.linkedUsers?.length || 0;
});
skillSchema.virtual('aiRecommendationStrength').get(function () {
    return this.aiInsights.salaryBoostPrediction > 0 ? 'strong' : 'moderate';
});
skillSchema.virtual('trendDirection').get(function () {
    return this.trend.trendScore > 50 ? 'upward' : this.trend.trendScore < 50 ? 'downward' : 'stable';
});
skillSchema.virtual('verificationLevel').get(function () {
    const score = this.verification.score;
    if (score >= 90) return 'platinum';
    if (score >= 70) return 'gold';
    if (score >= 50) return 'silver';
    return 'bronze';
});
skillSchema.virtual('engagementLevel').get(function () {
    const score = this.analytics.engagementScore;
    if (score >= 80) return 'high';
    if (score >= 50) return 'medium';
    return 'low';
});

// Middleware
skillSchema.pre('validate', function (next) {
    if (this.certification.isCertified && !this.certification.issueDate) {
        next(new Error('Issue date is required for certified skills'));
    }
    if (this.experience.years > 0 && !this.experience.lastUsed) {
        this.experience.lastUsed = new Date();
    }
    next();
});

skillSchema.pre('save', async function (next) {
    try {
        // Normalize name
        this.normalizedName = this.name.toLowerCase().trim();

        // Update metadata
        this.metadata.lastUpdated = new Date();
        this.metadata.updateCount += 1;
        this.metadata.version += 1;

        // Generate search vector
        this.cache.searchVector = [
            this.name,
            this.normalizedName,
            this.description,
            ...(this.synonyms.names || []),
            ...(this.category.tags || [])
        ].filter(Boolean).join(' ').toLowerCase();

        // Calculate verification score
        let verScore = 0;
        if (this.verification.isVerified) verScore += 30;
        if (this.certification.isCertified) verScore += 20;
        if (this.endorsementCount > 0) verScore += Math.min(this.endorsementCount * 5, 30);
        if (this.verification.documents?.length > 0) verScore += 10;
        if (this.verification.contactVerified) verScore += 10;
        this.verification.score = Math.min(verScore, 100);

        // Calculate engagement score
        let engScore = 0;
        engScore += (this.analytics.profileViews || 0) * 0.05;
        engScore += this.endorsementCount * 2;
        engScore += (this.analytics.commentsCount || 0) * 3;
        engScore += (this.analytics.shareCount || 0) * 4;
        engScore += this.verification.score * 0.3;
        this.analytics.engagementScore = Math.min(engScore, 1000);

        // Calculate scores
        this.cache.popularityScore = this.calculatePopularityScore();
        this.cache.trendingScore = (this.analytics.engagementScore * 0.35) + (this.trend.trendScore * 0.4) + (this.demand.demandGrowth * 0.25);

        // Update cache
        this.cache.lastCacheUpdate = new Date();
        this.cache.cacheVersion += 1;

        // Redis operations
        const pipeline = redis.pipeline();
        pipeline.setex(`skill:${this._id}`, CACHE_TTL.MEDIUM, JSON.stringify(this.toJSON()));
        pipeline.publish('skill_updates', JSON.stringify({
            skillId: this._id,
            popularityScore: this.cache.popularityScore,
            trendingScore: this.cache.trendingScore
        }));
        await pipeline.exec();

        // AI insights update
        if (!this.aiInsights.lastAnalyzed || (new Date() - this.aiInsights.lastAnalyzed) > 86400000) {
            this.aiInsights.lastAnalyzed = new Date();
            this.aiInsights.salaryBoostPrediction = Math.random() * 20000 + 10000; // Placeholder
        }

        // Encrypt contact email
        if (this.verification.contactEmail) {
            this.verification.contactEmail = await encryptField(this.verification.contactEmail);
        }

        // Update status
        this.status.lastActiveAt = new Date();

        next();
    } catch (error) {
        next(new Error(`Pre-save error: ${error.message}`));
    }
});

skillSchema.pre('remove', async function (next) {
    try {
        this.status.isDeleted = true;
        this.status.deletedAt = new Date();
        this.privacy.isPublic = false;
        this.privacy.searchable = false;
        const pipeline = redis.pipeline();
        pipeline.del(`skill:${this._id}`);
        await pipeline.exec();
        await this.save();
        next();
    } catch (error) {
        next(new Error(`Pre-remove error: ${error.message}`));
    }
});

skillSchema.post('save', async function (doc) {
    try {
        // Invalidate caches
        const pipeline = redis.pipeline();
        pipeline.del(`skills:category:${doc.category.primary}`);
        pipeline.del(`user:skills:${doc.connections.linkedUsers.map(u => u.userId).join(':')}`);
        await pipeline.exec();

        // Sync to Algolia
        if (doc.privacy.searchable && doc.privacy.isPublic && doc.status.isActive) {
            await doc.syncToAlgolia();
        }
    } catch (error) {
        console.error('Post-save error:', error.message);
    }
});

// Instance Methods
skillSchema.methods.calculatePopularityScore = function () {
    const weights = {
        views: 0.3,
        endorsements: 0.25,
        demand: 0.2,
        engagement: 0.15,
        verification: 0.1
    };
    const viewScore = Math.min(Math.log1p(this.analytics.profileViews) / Math.log1p(50000), 1);
    const endorseScore = Math.min(Math.log1p(this.endorsementCount) / Math.log1p(1000), 1);
    const demandScore = this.trend.trendScore / 100;
    const engScore = this.analytics.engagementScore / 1000;
    const verScore = this.verification.score / 100;
    return Math.round((
        viewScore * weights.views +
        endorseScore * weights.endorsements +
        demandScore * weights.demand +
        engScore * weights.engagement +
        verScore * weights.verification
    ) * 100);
};

skillSchema.methods.addEndorsement = async function (endorsementData) {
    this.endorsements.push(endorsementData);
    this.analytics.endorsementCount += 1;
    await this.save();
    return this.endorsements[this.endorsements.length - 1];
};

skillSchema.methods.updateProficiency = async function (newLevel) {
    this.proficiency.level = newLevel;
    this.proficiency.assessmentDate = new Date();
    await this.save();
};

// Static Methods
skillSchema.statics.getSkillsByCategory = async function (categoryId, options = {}) {
    const { page = 1, limit = 50, sortBy = 'name', sortOrder = 1, filters = {} } = options;
    const cacheKey = `skills:category:${categoryId}:${JSON.stringify(options)}`;
    const cached = await redis.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const baseQuery = { 'category.primary': categoryId, 'status.isActive': true, 'status.isDeleted': false };
    Object.assign(baseQuery, filters);

    const results = await this.find(baseQuery)
        .sort({ [sortBy]: sortOrder })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean({ virtuals: true })
        .select('-cache.searchVector -social.comments -verification.documents');

    const response = {
        skills: results,
        pagination: { page, limit, total: results.length }
    };
    await redis.setex(cacheKey, CACHE_TTL.MEDIUM, JSON.stringify(response));
    return response;
};

skillSchema.statics.advancedSearch = async function (searchOptions = {}) {
    const { query = '', category, proficiencyLevel, minYears, isCertified = false, minDemand = 'medium', page = 1, limit = 50, sortBy = 'relevance' } = searchOptions;
    const cacheKey = `search:skills:${JSON.stringify(searchOptions)}`;
    const cached = await redis.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const demandMap = { low: 0, medium: 25, high: 50, 'very-high': 75 };
    const pipeline = [
        {
            $match: {
                'status.isActive': true,
                'status.isDeleted': false,
                'privacy.isPublic': true,
                'privacy.searchable': true,
                ...(category && { 'category.primary': category }),
                ...(proficiencyLevel && { 'proficiency.level': proficiencyLevel }),
                ...(minYears && { 'experience.years': { $gte: minYears } }),
                ...(isCertified && { 'certification.isCertified': true }),
                ...(minDemand && { 'trend.trendScore': { $gte: demandMap[minDemand] || 0 } })
            }
        },
        ...(query ? [{
            $match: { $text: { $search: query, $caseSensitive: false } }
        }, {
            $addFields: { textScore: { $meta: 'textScore' } }
        }] : []),
        {
            $addFields: {
                relevanceScore: {
                    $add: [
                        { $multiply: [{ $ifNull: ['$textScore', 0] }, 0.35] },
                        { $multiply: [{ $divide: ['$trend.trendScore', 100] }, 0.25] },
                        { $multiply: [{ $divide: ['$verification.score', 100] }, 0.15] },
                        { $multiply: [{ $divide: ['$analytics.engagementScore', 1000] }, 0.1] },
                        { $multiply: [{ $cond: ['$certification.isCertified', 1, 0] }, 0.1] },
                        { $multiply: [{ $divide: ['$experience.years', 50] }, 0.05] }
                    ]
                }
            }
        },
        { $sort: this.getSortQuery(sortBy) },
        { $skip: (page - 1) * limit },
        { $limit: limit },
        {
            $project: {
                name: 1,
                description: { $substr: ['$description', 0, 300] },
                category: 1,
                proficiency: 1,
                experience: 1,
                trend: 1,
                demand: 1,
                certification: 1,
                endorsementCount: 1,
                verification: { isVerified: 1, score: 1 },
                analytics: { engagementScore: 1, profileViews: 1 },
                cache: { popularityScore: 1, trendingScore: 1 },
                relevanceScore: 1,
                createdAt: 1,
                updatedAt: 1
            }
        }
    ];

    const results = await this.aggregatePaginate(pipeline, { page, limit });
    await redis.setex(cacheKey, CACHE_TTL.SHORT, JSON.stringify(results));
    return results;
};

skillSchema.statics.getSortQuery = function (sortBy) {
    const sortQueries = {
        relevance: { relevanceScore: -1, 'trend.trendScore': -1 },
        popularity: { 'cache.popularityScore': -1 },
        trending: { 'cache.trendingScore': -1 },
        alphabetical: { name: 1 },
        demand: { 'trend.trendScore': -1 },
        experience: { 'experience.years': -1 }
    };
    return sortQueries[sortBy] || sortQueries.relevance;
};

skillSchema.statics.getTrendingSkills = async function (options = {}) {
    const { timeframe = 30, category, minEndorsements = 0, limit = 50 } = options;
    const cacheKey = `trending:skills:${JSON.stringify(options)}`;
    const cached = await redis.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const startDate = new Date();
    startDate.setDate(startDate.getDate() - timeframe);

    const pipeline = [
        {
            $match: {
                'status.isActive': true,
                'status.isDeleted': false,
                'privacy.isPublic': true,
                updatedAt: { $gte: startDate },
                ...(category && { 'category.primary': category }),
                $expr: { $gte: [{ $size: { $ifNull: ['$endorsements', []] } }, minEndorsements] }
            }
        },
        {
            $group: {
                _id: '$normalizedName',
                count: { $sum: 1 },
                avgTrendScore: { $avg: '$trend.trendScore' },
                totalEndorsements: { $sum: '$analytics.endorsementCount' },
                avgVerificationScore: { $avg: '$verification.score' },
                avgExperienceYears: { $avg: '$experience.years' },
                categories: { $addToSet: '$category.primary' }
            }
        },
        {
            $addFields: {
                trendScore: {
                    $multiply: [
                        { $log10: { $add: ['$count', 1] } },
                        { $divide: ['$avgTrendScore', 100] },
                        { $divide: ['$totalEndorsements', 10] },
                        { $divide: ['$avgVerificationScore', 100] }
                    ]
                }
            }
        },
        { $sort: { trendScore: -1 } },
        { $limit: limit },
        {
            $project: {
                name: '$_id',
                occurrences: '$count',
                avgTrendScore: { $round: ['$avgTrendScore', 1] },
                totalEndorsements: 1,
                avgVerificationScore: { $round: ['$avgVerificationScore', 1] },
                avgExperienceYears: { $round: ['$avgExperienceYears', 1] },
                categoryCount: { $size: '$categories' },
                trendScore: { $round: ['$trendScore', 1] }
            }
        }
    ];

    const results = await this.aggregate(pipeline);
    await redis.setex(cacheKey, CACHE_TTL.LONG, JSON.stringify(results));
    return results;
};

skillSchema.statics.getSkillAnalytics = async function (skillId, options = {}) {
    const { timeframe = 30 } = options;
    const cacheKey = `skill:analytics:${skillId}:${timeframe}`;
    const cached = await redis.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const startDate = new Date();
    startDate.setDate(startDate.getDate() - timeframe);

    const pipeline = [
        {
            $match: { _id: skillId, 'status.isActive': true, 'status.isDeleted': false }
        },
        {
            $addFields: {
                recentEndorsements: {
                    $filter: {
                        input: '$endorsements',
                        as: 'endorsement',
                        cond: { $gte: ['$$endorsement.endorsedAt', startDate] }
                    }
                }
            }
        },
        {
            $project: {
                name: 1,
                summary: {
                    endorsementCount: '$analytics.endorsementCount',
                    recentEndorsementCount: { $size: '$recentEndorsements' },
                    avgRating: { $avg: '$endorsements.rating' },
                    trendScore: '$trend.trendScore',
                    demandLevel: '$demand.marketDemand',
                    engagementScore: '$analytics.engagementScore',
                    verificationScore: '$verification.score',
                    aiSalaryBoost: '$aiInsights.salaryBoostPrediction'
                },
                historicalTrends: '$trend.historicalData'
            }
        }
    ];

    const results = await this.aggregate(pipeline);
    const result = results[0] || null;
    await redis.setex(cacheKey, CACHE_TTL.MEDIUM, JSON.stringify(result));
    return result;
};

skillSchema.statics.getMarketInsights = async function (options = {}) {
    const { skillName, category, region, minExperience = 0, limit = 20 } = options;
    const cacheKey = `market:insights:${JSON.stringify(options)}`;
    const cached = await redis.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const pipeline = [
        {
            $match: {
                'status.isActive': true,
                'status.isDeleted': false,
                'privacy.isPublic': true,
                ...(skillName && { normalizedName: new RegExp(skillName, 'i') }),
                ...(category && { 'category.primary': category }),
                ...(region && { 'demand.regionalDemand.region': region }),
                'experience.years': { $gte: minExperience }
            }
        },
        {
            $group: {
                _id: '$normalizedName',
                count: { $sum: 1 },
                avgTrendScore: { $avg: '$trend.trendScore' },
                avgDemandGrowth: { $avg: '$demand.demandGrowth' },
                avgSalaryImpact: { $avg: '$demand.averageSalaryImpact' },
                totalJobPostings: { $sum: '$demand.jobPostings' },
                avgVerificationScore: { $avg: '$verification.score' },
                categories: { $addToSet: '$category.primary' }
            }
        },
        {
            $addFields: {
                marketScore: {
                    $add: [
                        { $multiply: [{ $log10: { $add: ['$count', 1] } }, 0.3] },
                        { $divide: ['$avgTrendScore', 100] },
                        { $divide: ['$avgDemandGrowth', 100] },
                        { $divide: ['$totalJobPostings', 10000] }
                    ]
                }
            }
        },
        { $sort: { marketScore: -1 } },
        { $limit: limit },
        {
            $project: {
                skillName: '$_id',
                occurrences: '$count',
                avgTrendScore: { $round: ['$avgTrendScore', 1] },
                avgDemandGrowth: { $round: ['$avgDemandGrowth', 1] },
                avgSalaryImpact: { $round: ['$avgSalaryImpact', 0] },
                totalJobPostings: 1,
                categoryCount: { $size: '$categories' },
                marketScore: { $round: ['$marketScore', 2] }
            }
        }
    ];

    const results = await this.aggregate(pipeline);
    await redis.setex(cacheKey, CACHE_TTL.LONG, JSON.stringify(results));
    return results;
};

skillSchema.statics.bulkOperations = {
    updateTrends: async function (skillIds, trendData) {
        const bulkOps = skillIds.map(id => ({
            updateOne: {
                filter: { _id: id, 'status.isActive': true },
                update: {
                    $set: {
                        trend: trendData,
                        'metadata.lastUpdated': new Date(),
                        'cache.lastCacheUpdate': new Date()
                    },
                    $inc: { 'metadata.updateCount': 1, 'cache.cacheVersion': 1 }
                }
            }
        }));
        const result = await this.bulkWrite(bulkOps, { ordered: false, writeConcern: { w: 1 } });
        const pipeline = redis.pipeline();
        skillIds.forEach(id => pipeline.del(`skill:${id}`));
        await pipeline.exec();
        return result;
    },
    verifySkills: async function (skillIds, verificationData) {
        const bulkOps = skillIds.map(id => ({
            updateOne: {
                filter: { _id: id, 'status.isActive': true },
                update: {
                    $set: {
                        verification: verificationData,
                        'metadata.lastUpdated': new Date(),
                        'cache.lastCacheUpdate': new Date()
                    },
                    $inc: { 'metadata.updateCount': 1, 'cache.cacheVersion': 1 }
                }
            }
        }));
        const result = await this.bulkWrite(bulkOps, { ordered: false, writeConcern: { w: 1 } });
        const pipeline = redis.pipeline();
        skillIds.forEach(id => pipeline.del(`skill:${id}`));
        await pipeline.exec();
        return result;
    },
    archiveOldSkills: async function (cutoffDate) {
        const oldSkills = await this.find({
            'metadata.lastUpdated': { $lt: cutoffDate },
            'status.isActive': true,
            'status.isDeleted': false
        }).lean();
        if (oldSkills.length === 0) return { archived: 0 };
        const ArchiveSkill = mongoose.model('ArchiveSkill', skillSchema, 'archive_skills');
        await ArchiveSkill.insertMany(oldSkills, { ordered: false });
        const bulkOps = oldSkills.map(skill => ({
            updateOne: {
                filter: { _id: skill._id },
                update: {
                    $set: {
                        'status.isActive': false,
                        'status.isDeleted': true,
                        'status.archivedAt': new Date(),
                        'cache.lastCacheUpdate': new Date()
                    }
                }
            }
        }));
        const result = await this.bulkWrite(bulkOps, { ordered: false, writeConcern: { w: 1 } });
        const pipeline = redis.pipeline();
        oldSkills.forEach(skill => pipeline.del(`skill:${skill._id}`));
        await pipeline.exec();
        return { archived: result.modifiedCount };
    },
    addEndorsements: async function (skillId, endorsements) {
        const result = await this.updateOne(
            { _id: skillId, 'status.isActive': true },
            {
                $push: { endorsements: { $each: endorsements } },
                $inc: {
                    'analytics.endorsementCount': endorsements.length,
                    'cache.cacheVersion': 1
                },
                $set: { 'cache.lastCacheUpdate': new Date() }
            },
            { writeConcern: { w: 1 } }
        );
        await redis.del(`skill:${skillId}`);
        return result;
    }
};

skillSchema.statics.getAIRecommendations = async function (options = {}) {
    const { category, currentSkills = [], limit = 20 } = options;
    const cacheKey = `ai:recommendations:${JSON.stringify(options)}`;
    const cached = await redis.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const pipeline = [
        {
            $match: {
                'status.isActive': true,
                'status.isDeleted': false,
                'privacy.isPublic': true,
                ...(category && { 'category.primary': category }),
                normalizedName: { $nin: currentSkills }
            }
        },
        {
            $addFields: {
                recommendationScore: {
                    $add: [
                        { $multiply: [{ $divide: ['$trend.trendScore', 100] }, 0.4] },
                        { $multiply: [{ $divide: ['$demand.demandGrowth', 100] }, 0.3] },
                        { $multiply: [{ $cond: ['$certification.isCertified', 1, 0] }, 0.2] },
                        { $multiply: [{ $divide: ['$analytics.engagementScore', 1000] }, 0.1] }
                    ]
                }
            }
        },
        { $sort: { recommendationScore: -1 } },
        { $limit: limit },
        {
            $project: {
                name: 1,
                description: 1,
                trend: 1,
                demand: 1,
                certification: 1,
                recommendationScore: { $round: ['$recommendationScore', 2] }
            }
        }
    ];

    const results = await this.aggregate(pipeline);
    await redis.setex(cacheKey, CACHE_TTL.LONG, JSON.stringify(results));
    return results;
};

skillSchema.statics.getPerformanceMetrics = async function (timeframe = '30d') {
    const cacheKey = `performance:metrics:${timeframe}`;
    const cached = await redis.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const days = parseInt(timeframe.replace('d', ''));
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    const pipeline = [
        {
            $match: {
                updatedAt: { $gte: startDate },
                'status.isActive': true,
                'status.isDeleted': false
            }
        },
        {
            $group: {
                _id: null,
                totalSkills: { $sum: 1 },
                avgTrendScore: { $avg: '$trend.trendScore' },
                avgEngagement: { $avg: '$analytics.engagementScore' },
                verifiedCount: { $sum: { $cond: ['$verification.isVerified', 1, 0] } },
                certifiedCount: { $sum: { $cond: ['$certification.isCertified', 1, 0] } },
                highDemandCount: { $sum: { $cond: [{ $in: ['$demand.marketDemand', ['high', 'very-high']] }, 1, 0] } },
                totalEndorsements: { $sum: '$analytics.endorsementCount' }
            }
        },
        {
            $addFields: {
                verificationRate: { $multiply: [{ $divide: ['$verifiedCount', '$totalSkills'] }, 100] },
                certificationRate: { $multiply: [{ $divide: ['$certifiedCount', '$totalSkills'] }, 100] },
                highDemandRate: { $multiply: [{ $divide: ['$highDemandCount', '$totalSkills'] }, 100] },
                avgEndorsementsPerSkill: { $divide: ['$totalEndorsements', '$totalSkills'] }
            }
        },
        {
            $project: {
                _id: 0,
                totalSkills: 1,
                avgTrendScore: { $round: ['$avgTrendScore', 1] },
                avgEngagement: { $round: ['$avgEngagement', 1] },
                verificationRate: { $round: ['$verificationRate', 1] },
                certificationRate: { $round: ['$certificationRate', 1] },
                highDemandRate: { $round: ['$highDemandRate', 1] },
                avgEndorsementsPerSkill: { $round: ['$avgEndorsementsPerSkill', 1] }
            }
        }
    ];

    const results = await this.aggregate(pipeline);
    const result = results[0] || {
        totalSkills: 0,
        avgTrendScore: 0,
        avgEngagement: 0,
        verificationRate: 0,
        certificationRate: 0,
        highDemandRate: 0,
        avgEndorsementsPerSkill: 0
    };
    await redis.setex(cacheKey, CACHE_TTL.EXTRA_LONG, JSON.stringify(result));
    return result;
};

skillSchema.statics.cleanupIndexes = async function () {
    const indexes = await this.collection.indexes();
    const essentialIndexes = [
        '_id_',
        'skill_text_search',
        'category.primary_1_status.isActive_1',
        'name_1'
    ];
    const unusedIndexes = indexes.filter(idx => !essentialIndexes.includes(idx.name) && !idx.name.includes('hashed'));
    let dropped = 0;
    for (const idx of unusedIndexes) {
        try {
            await this.collection.dropIndex(idx.name);
            dropped++;
        } catch (err) {
            console.error(`Failed to drop index ${idx.name}:`, err.message);
        }
    }
    return { dropped };
};

skillSchema.statics.initChangeStream = function () {
    const changeStream = this.watch([
        { $match: { operationType: { $in: ['insert', 'update', 'delete'] } } }
    ], { fullDocument: 'updateLookup' });
    changeStream.on('change', async (change) => {
        const skillId = change.documentKey._id;
        const pipeline = redis.pipeline();
        pipeline.del(`skill:${skillId}`);
        pipeline.publish('skill_changes', JSON.stringify({
            skillId,
            operation: change.operationType
        }));
        await pipeline.exec();
    });
    changeStream.on('error', err => console.error('Change stream error:', err));
    return changeStream;
};

skillSchema.statics.healthCheck = async function () {
    try {
        const dbCheck = await this.findOne({}, '_id').lean().timeout(5000);
        const redisCheck = await redis.ping();
        return {
            database: dbCheck !== null ? 'healthy' : 'unhealthy',
            redis: redisCheck === 'PONG' ? 'healthy' : 'unhealthy',
            timestamp: new Date()
        };
    } catch (error) {
        return {
            database: 'unhealthy',
            redis: 'unhealthy',
            error: error.message,
            timestamp: new Date()
        };
    }
};

// Encryption Placeholder
async function encryptField(value) {
    return crypto.createHash('sha512').update(value).digest('hex');
}

// Plugins
skillSchema.plugin(aggregatePaginate);
if (process.env.ALGOLIA_APP_ID && process.env.ALGOLIA_ADMIN_KEY) {
    skillSchema.plugin(mongooseAlgolia, {
        appId: process.env.ALGOLIA_APP_ID,
        apiKey: process.env.ALGOLIA_ADMIN_KEY,
        indexName: 'skills',
        selector: 'name normalizedName description category.tags synonyms.names cache.searchVector',
        defaults: { author: 'system' },
        mappings: {
            name: v => v?.toLowerCase() || '',
            normalizedName: v => v || '',
            description: v => v?.slice(0, 500) || '',
            'category.tags': v => v || [],
            'synonyms.names': v => v || [],
            'cache.searchVector': v => v || ''
        },
        debug: process.env.NODE_ENV !== 'production',
        batchSize: 1000
    });
} else {
    console.warn('Algolia not configured: Missing ALGOLIA_APP_ID or ALGOLIA_ADMIN_KEY');
}

// Production Indexes
if (process.env.NODE_ENV === 'production') {
    skillSchema.index({ 'analytics.profileViews': -1 }, { background: true });
    skillSchema.index({ 'trend.currentTrend': 1 }, { background: true });
    skillSchema.index({ 'demand.jobPostings': -1 }, { background: true });
}

export default mongoose.model('Skill', skillSchema);