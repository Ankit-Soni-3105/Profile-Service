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

// Sub-Schemas
const categorySchema = new Schema({
    primary: {
        type: String,
        required: true,
        enum: ['award', 'certification', 'publication', 'project', 'milestone', 'recognition', 'promotion', 'patent', 'competition', 'speaking', 'volunteer', 'education', 'leadership', 'innovation', 'sales', 'performance', 'team', 'client', 'research', 'other'],
        index: true
    },
    subcategory: { type: String, trim: true, maxlength: 100, validate: { validator: validateString, message: 'Invalid subcategory' } },
    tags: [{ type: String, trim: true, lowercase: true, maxlength: 50, validate: { validator: validateString, message: 'Invalid tag' } }],
    industryRelevant: [{ type: String, trim: true, maxlength: 100, validate: { validator: validateString, message: 'Invalid industry' } }]
}, { _id: false });

const scopeSchema = new Schema({
    level: {
        type: String,
        enum: ['individual', 'team', 'department', 'company', 'industry', 'national', 'international', 'global'],
        required: true,
        index: true
    },
    impactArea: [{ type: String, enum: ['revenue', 'cost-saving', 'efficiency', 'innovation', 'customer-satisfaction', 'team-building', 'process-improvement', 'market-expansion', 'product-development', 'sustainability', 'diversity', 'safety', 'quality', 'compliance', 'other'] }],
    teamSize: { type: Number, min: 1, max: 10000 }
}, { _id: false });

const metricsSchema = new Schema({
    financial: {
        value: { type: Number, min: 0 },
        currency: { type: String, default: 'USD', maxlength: 3 },
        type: { type: String, enum: ['revenue-generated', 'cost-saved', 'budget-managed', 'roi', 'other'] }
    },
    performance: {
        percentage: { type: Number, min: -100, max: 10000 },
        metric: { type: String, maxlength: 100, validate: { validator: validateString, message: 'Invalid metric' } },
        baseline: { type: String, maxlength: 200 },
        timeframe: { type: String, maxlength: 50 }
    },
    reach: {
        people: { type: Number, min: 1 },
        geographic: { type: String, maxlength: 100 }
    },
    custom: [{
        metric: { type: String, required: true, maxlength: 100, validate: { validator: validateString, message: 'Invalid custom metric' } },
        value: { type: String, required: true, maxlength: 200, validate: { validator: validateString, message: 'Invalid custom value' } },
        unit: { type: String, maxlength: 50 }
    }]
}, { _id: false });

const timelineSchema = new Schema({
    startDate: { type: Date, required: true, index: true },
    endDate: { type: Date, index: true },
    duration: { type: Number, min: 1 },
    isOngoing: { type: Boolean, default: false, index: true },
    milestones: [{
        date: { type: Date, required: true },
        description: { type: String, required: true, maxlength: 500, validate: { validator: validateString, message: 'Invalid milestone description' } },
        importance: { type: String, enum: ['low', 'medium', 'high', 'critical'], default: 'medium' }
    }]
}, { _id: false });

const sourceSchema = new Schema({
    issuer: {
        name: { type: String, trim: true, maxlength: 200, validate: { validator: validateString, message: 'Invalid issuer name' } },
        type: { type: String, enum: ['company', 'organization', 'institution', 'government', 'industry-body', 'client', 'peer', 'self'], index: true },
        website: { type: String, validate: { validator: validateURL, message: 'Invalid website URL' } },
        logo: { type: String, validate: { validator: validateURL, message: 'Invalid logo URL' } }
    },
    verificationStatus: { type: String, enum: ['unverified', 'pending', 'verified', 'disputed'], default: 'unverified', index: true },
    verificationDetails: {
        verifiedBy: { type: Schema.Types.ObjectId, ref: 'User' },
        verifiedAt: { type: Date },
        verificationMethod: { type: String, enum: ['document', 'email', 'phone', 'third-party', 'witness', 'system'] },
        verificationNotes: { type: String, maxlength: 500 }
    },
    credibilityScore: { type: Number, min: 0, max: 100, default: 50, index: true }
}, { _id: false });

const skillsSchema = new Schema({
    technical: [{
        skill: { type: String, required: true, trim: true, maxlength: 100, validate: { validator: validateString, message: 'Invalid technical skill' } },
        proficiency: { type: String, enum: ['beginner', 'intermediate', 'advanced', 'expert'], default: 'intermediate' },
        yearsUsed: { type: Number, min: 0, max: 50 }
    }],
    soft: [{
        skill: { type: String, required: true, trim: true, maxlength: 100, validate: { validator: validateString, message: 'Invalid soft skill' } },
        level: { type: String, enum: ['developing', 'competent', 'proficient', 'expert'], default: 'competent' }
    }],
    tools: [{
        name: { type: String, required: true, trim: true, maxlength: 100, validate: { validator: validateString, message: 'Invalid tool name' } },
        version: { type: String, maxlength: 50 },
        category: { type: String, maxlength: 50 }
    }]
}, { _id: false });

const mediaSchema = new Schema({
    documents: [{
        type: { type: String, enum: ['certificate', 'award', 'screenshot', 'report', 'presentation', 'video', 'article', 'other'], required: true },
        url: { type: String, required: true, validate: { validator: validateURL, message: 'Invalid document URL' } },
        cloudinaryId: { type: String, maxlength: 100 },
        filename: { type: String, maxlength: 200 },
        size: { type: Number, min: 0 },
        mimeType: { type: String, maxlength: 50 },
        description: { type: String, maxlength: 500 },
        isPublic: { type: Boolean, default: true }
    }],
    links: [{
        title: { type: String, maxlength: 100 },
        url: { type: String, required: true, validate: { validator: validateURL, message: 'Invalid link URL' } },
        type: { type: String, enum: ['article', 'video', 'website', 'portfolio', 'demo', 'code', 'other'] },
        description: { type: String, maxlength: 500 }
    }],
    testimonials: [{
        from: {
            name: { type: String, required: true, maxlength: 100 },
            position: { type: String, maxlength: 100 },
            company: { type: String, maxlength: 100 },
            userId: { type: Schema.Types.ObjectId, ref: 'User' },
            linkedinProfile: { type: String, validate: { validator: validateURL, message: 'Invalid LinkedIn URL' } }
        },
        content: { type: String, required: true, maxlength: 1000, set: v => v ? sanitizeHtml(v, { allowedTags: [], allowedAttributes: {} }) : v },
        date: { type: Date, default: Date.now },
        isPublic: { type: Boolean, default: false },
        verified: { type: Boolean, default: false }
    }]
}, { _id: false });

const visibilitySchema = new Schema({
    isPublic: { type: Boolean, default: true, index: true },
    searchable: { type: Boolean, default: true, index: true },
    showInProfile: { type: Boolean, default: true },
    allowEndorsements: { type: Boolean, default: true },
    visibleTo: { type: String, enum: ['public', 'connections', 'company', 'private'], default: 'public' }
}, { _id: false });

const engagementSchema = new Schema({
    views: {
        count: { type: Number, default: 0, min: 0 },
        uniqueViews: { type: Number, default: 0, min: 0 },
        lastViewed: { type: Date }
    },
    endorsements: {
        count: { type: Number, default: 0, min: 0, index: true },
        users: [{
            userId: { type: Schema.Types.ObjectId, ref: 'User' },
            endorsedAt: { type: Date, default: Date.now },
            relationship: { type: String, enum: ['colleague', 'manager', 'client', 'peer', 'other'] }
        }]
    },
    shares: {
        count: { type: Number, default: 0, min: 0 },
        platforms: [{
            platform: { type: String, enum: ['linkedin', 'twitter', 'facebook', 'email', 'other'] },
            count: { type: Number, default: 0, min: 0 }
        }]
    },
    comments: {
        count: { type: Number, default: 0, min: 0 },
        items: [{
            userId: { type: Schema.Types.ObjectId, ref: 'User' },
            content: { type: String, maxlength: 500, set: v => v ? sanitizeHtml(v, { allowedTags: [], allowedAttributes: {} }) : v },
            commentedAt: { type: Date, default: Date.now },
            isPublic: { type: Boolean, default: true }
        }]
    }
}, { _id: false });

const prioritySchema = new Schema({
    userRating: { type: Number, min: 1, max: 5, default: 3 },
    profileWeight: { type: Number, min: 0, max: 100, default: 50 },
    isHighlight: { type: Boolean, default: false, index: true },
    displayOrder: { type: Number, default: 0, index: true }
}, { _id: false });

const analyticsSchema = new Schema({
    popularityScore: { type: Number, default: 0, index: true },
    relevanceScore: { type: Number, default: 0, index: true },
    searchScore: { type: Number, default: 0 },
    lastScoreUpdate: { type: Date, default: Date.now },
    trendingPeriod: [{
        period: { type: String, enum: ['day', 'week', 'month', 'quarter', 'year'] },
        score: { type: Number },
        timestamp: { type: Date, default: Date.now }
    }]
}, { _id: false });

const flagsSchema = new Schema({
    isFlagged: { type: Boolean, default: false, index: true },
    flagReasons: [{ type: String, enum: ['spam', 'inappropriate', 'fake', 'duplicate', 'copyright', 'other'] }],
    flaggedBy: [{
        userId: { type: Schema.Types.ObjectId, ref: 'User' },
        reason: { type: String, maxlength: 200 },
        flaggedAt: { type: Date, default: Date.now }
    }],
    moderationStatus: { type: String, enum: ['pending', 'approved', 'rejected', 'needs-review'], default: 'approved' }
}, { _id: false });

const auditSchema = new Schema({
    version: { type: Number, default: 1 },
    lastModifiedBy: { type: Schema.Types.ObjectId, ref: 'User' },
    modificationHistory: [{
        modifiedBy: { type: Schema.Types.ObjectId, ref: 'User' },
        modifiedAt: { type: Date, default: Date.now },
        changes: Schema.Types.Mixed,
        changeType: { type: String, enum: ['create', 'update', 'verify', 'endorse', 'flag', 'archive'] },
        ipAddress: { type: String, maxlength: 45 },
        userAgent: { type: String, maxlength: 500 }
    }]
}, { _id: false });

// Main Achievement Schema
const achievementSchema = new Schema({
    _id: { type: Schema.Types.ObjectId, auto: true },
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: [true, 'User ID is required'], index: true },
    experienceId: { type: Schema.Types.ObjectId, ref: 'Experience', index: true },
    companyId: { type: Schema.Types.ObjectId, ref: 'Company', index: true },
    title: { type: String, required: [true, 'Title is required'], trim: true, minlength: 2, maxlength: 200, index: 'text' },
    description: { type: String, required: [true, 'Description is required'], trim: true, minlength: 10, maxlength: 2000, set: v => v ? sanitizeHtml(v, { allowedTags: [], allowedAttributes: {} }) : v, index: 'text' },
    category: categorySchema,
    scope: scopeSchema,
    metrics: metricsSchema,
    timeline: timelineSchema,
    source: sourceSchema,
    skills: skillsSchema,
    media: mediaSchema,
    visibility: visibilitySchema,
    engagement: engagementSchema,
    priority: prioritySchema,
    analytics: analyticsSchema,
    status: { type: String, enum: ['active', 'draft', 'archived', 'suspended', 'disputed'], default: 'active', index: true },
    flags: flagsSchema,
    audit: auditSchema,
    cache: {
        searchVector: { type: String, index: 'text' },
        lastCacheUpdate: { type: Date, default: Date.now, index: true }
    }
}, {
    timestamps: true,
    collection: 'achievements',
    read: 'secondaryPreferred',
    writeConcern: { w: 'majority', wtimeout: 5000 },
    autoIndex: process.env.NODE_ENV !== 'production',
    toJSON: {
        virtuals: true,
        transform: (doc, ret) => {
            delete ret.audit;
            delete ret.flags;
            delete ret.__v;
            return ret;
        }
    },
    toObject: { virtuals: true },
    minimize: false,
    strict: 'throw'
});

// Indexes
achievementSchema.index({ userId: 1, status: 1, 'visibility.isPublic': 1, 'priority.displayOrder': 1 });
achievementSchema.index({ userId: 1, 'category.primary': 1, 'timeline.startDate': -1 });
achievementSchema.index({ companyId: 1, 'source.verificationStatus': 1, 'engagement.endorsements.count': -1 });
achievementSchema.index({ 'category.primary': 1, 'analytics.popularityScore': -1, 'timeline.startDate': -1 });
achievementSchema.index({ 'analytics.popularityScore': -1, 'timeline.startDate': -1 });
achievementSchema.index({ 'priority.isHighlight': 1, 'analytics.relevanceScore': -1 });
achievementSchema.index({ createdAt: -1, 'engagement.endorsements.count': -1 });
achievementSchema.index({ 'timeline.startDate': -1, 'scope.level': 1 });
achievementSchema.index({ experienceId: 1 }, { sparse: true });
achievementSchema.index({ 'source.credibilityScore': -1 }, { sparse: true });
achievementSchema.index({ 'status': 1, 'flags.isFlagged': 1 });
achievementSchema.index({ 'timeline.startDate': 1, 'status': 1 }, { expireAfterSeconds: 31536000 * 5, sparse: true }); // 5 years for archived
achievementSchema.index({
    title: 'text',
    description: 'text',
    'skills.technical.skill': 'text',
    'category.tags': 'text',
    'cache.searchVector': 'text'
}, {
    weights: { title: 10, 'skills.technical.skill': 8, 'category.tags': 5, description: 3, 'cache.searchVector': 1 },
    name: 'achievement_search_index'
});

// Virtuals
achievementSchema.virtual('durationFormatted').get(function () {
    if (!this.timeline.duration) return 'N/A';
    const days = this.timeline.duration;
    if (days < 30) return `${days} day${days !== 1 ? 's' : ''}`;
    const months = Math.floor(days / 30.44);
    if (months < 12) return `${months} month${months !== 1 ? 's' : ''}`;
    const years = Math.floor(months / 12);
    const remainingMonths = months % 12;
    return years > 0
        ? `${years} year${years !== 1 ? 's' : ''}${remainingMonths > 0 ? ` ${remainingMonths} month${remainingMonths !== 1 ? 's' : ''}` : ''}`
        : `${months} month${months !== 1 ? 's' : ''}`;
});
achievementSchema.virtual('skillCount').get(function () {
    return (this.skills.technical?.length || 0) + (this.skills.soft?.length || 0) + (this.skills.tools?.length || 0);
});
achievementSchema.virtual('mediaCount').get(function () {
    return (this.media.documents?.length || 0) + (this.media.links?.length || 0) + (this.media.testimonials?.length || 0);
});
achievementSchema.virtual('isRecent').get(function () {
    const oneYearAgo = new Date();
    oneYearAgo.setFullYear(oneYearAgo.getFullYear() - 1);
    return this.timeline.startDate >= oneYearAgo;
});
achievementSchema.virtual('credibilityLevel').get(function () {
    const score = this.source.credibilityScore;
    if (score >= 90) return 'platinum';
    if (score >= 75) return 'gold';
    if (score >= 60) return 'silver';
    if (score >= 40) return 'bronze';
    return 'unverified';
});

// Middleware
achievementSchema.pre('save', async function (next) {
    try {
        // Calculate duration
        if (this.timeline.startDate && this.timeline.endDate && !this.timeline.duration) {
            const diffTime = Math.abs(this.timeline.endDate - this.timeline.startDate);
            this.timeline.duration = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
        }

        // Generate search vector
        this.cache.searchVector = [
            this.title,
            this.description,
            ...this.skills.technical.map(s => s.skill),
            ...this.skills.soft.map(s => s.skill),
            ...this.skills.tools.map(t => t.name),
            ...this.category.tags
        ].filter(Boolean).join(' ').toLowerCase();

        // Update analytics scores
        await this.calculateAnalyticsScores();

        // Update audit trail
        if (!this.isNew) {
            this.audit.version += 1;
            this.audit.modificationHistory.push({
                modifiedBy: this.audit.lastModifiedBy || this.userId,
                modifiedAt: new Date(),
                changeType: 'update',
                changes: this.getChanges()
            });
        } else {
            this.audit.modificationHistory.push({
                modifiedBy: this.userId,
                modifiedAt: new Date(),
                changeType: 'create'
            });
        }

        // Cache in Redis
        await redisClient.setEx(`achievement:${this._id}`, 300, JSON.stringify(this.toJSON()));

        // Publish updates
        await redisClient.publish('achievement_updates', JSON.stringify({
            achievementId: this._id,
            popularityScore: this.analytics.popularityScore,
            relevanceScore: this.analytics.relevanceScore
        }));

        next();
    } catch (error) {
        next(new Error(`Pre-save middleware error: ${error.message}`));
    }
});

achievementSchema.pre('remove', async function (next) {
    try {
        this.status = 'archived';
        this.flags.isFlagged = false;
        this.visibility.isPublic = false;
        this.visibility.searchable = false;
        await redisClient.del(`achievement:${this._id}`);
        await this.save();
        next();
    } catch (error) {
        next(new Error(`Pre-remove middleware error: ${error.message}`));
    }
});

achievementSchema.post('save', async function (doc) {
    try {
        // Update User profile
        const User = mongoose.model('User');
        await User.updateOne(
            { _id: doc.userId },
            { $set: { 'profile.lastUpdated': new Date() }, $inc: { 'analytics.achievementCount': 1 } }
        );

        // Update Company stats
        if (doc.companyId) {
            const Company = mongoose.model('Company');
            await Company.updateOne(
                { _id: doc.companyId },
                { $inc: { 'stats.achievementCount': 1 }, $set: { 'analytics.lastCalculated': new Date() } }
            );
        }

        // Sync to Algolia
        if (doc.visibility.searchable && doc.visibility.isPublic && doc.status === 'active') {
            try {
                await doc.syncToAlgolia();
            } catch (error) {
                console.error('Algolia sync error:', error.message);
            }
        }

        // Invalidate related caches
        await redisClient.del(`user:achievements:${doc.userId}`);
        if (doc.companyId) await redisClient.del(`company:achievements:${doc.companyId}`);
    } catch (error) {
        console.error('Post-save middleware error:', error.message);
    }
});

// Instance Methods
achievementSchema.methods.calculateAnalyticsScores = async function () {
    const weights = {
        endorsements: 0.3,
        views: 0.2,
        verification: 0.15,
        recency: 0.15,
        scope: 0.1,
        engagement: 0.1,
        media: 0.05,
        skills: 0.05
    };

    const endorsementScore = Math.min(this.engagement.endorsements.count / 50, 1);
    const viewScore = Math.min(this.engagement.views.count / 1000, 1);
    const verificationScore = this.source.verificationStatus === 'verified' ? 1 : this.source.verificationStatus === 'pending' ? 0.5 : 0.3;
    const daysSinceAchievement = (Date.now() - this.timeline.startDate) / (1000 * 60 * 60 * 24);
    const recencyScore = Math.max(0, 1 - (daysSinceAchievement / 1095)); // 3-year decay
    const scopeWeights = { individual: 0.3, team: 0.5, department: 0.6, company: 0.8, industry: 0.9, national: 0.95, international: 1, global: 1 };
    const scopeScore = scopeWeights[this.scope.level] || 0.5;
    const totalEngagement = (this.engagement.shares.count * 2) + (this.engagement.comments.count * 1.5) + this.engagement.endorsements.count;
    const engagementScore = Math.min(totalEngagement / 100, 1);
    const mediaScore = Math.min(this.mediaCount / 10, 1);
    const skillScore = Math.min(this.skillCount / 20, 1);

    this.analytics.popularityScore = Math.min(100, (
        endorsementScore * weights.endorsements +
        viewScore * weights.views +
        verificationScore * weights.verification +
        recencyScore * weights.recency +
        scopeScore * weights.scope +
        engagementScore * weights.engagement +
        mediaScore * weights.media +
        skillScore * weights.skills
    ) * 100);

    this.analytics.relevanceScore = this.calculateRelevanceScore();
    this.analytics.searchScore = this.calculateSearchScore();
    this.analytics.lastScoreUpdate = new Date();

    // Update trending period
    const periods = ['day', 'week', 'month', 'quarter', 'year'];
    for (const period of periods) {
        this.analytics.trendingPeriod.push({
            period,
            score: this.analytics.popularityScore,
            timestamp: new Date()
        });
    }
    this.analytics.trendingPeriod = this.analytics.trendingPeriod.slice(-5); // Keep last 5 periods
};

achievementSchema.methods.calculateRelevanceScore = function () {
    const trendingSkills = ['ai', 'machine-learning', 'cloud', 'devops', 'data-science', 'blockchain', 'cybersecurity'];
    let relevanceBonus = 0;

    this.skills.technical.forEach(skill => {
        if (trendingSkills.some(trending => skill.skill.toLowerCase().includes(trending))) {
            relevanceBonus += 10 * (skill.proficiency === 'expert' ? 1.5 : skill.proficiency === 'advanced' ? 1.2 : 1);
        }
    });

    this.skills.tools.forEach(tool => {
        if (trendingSkills.some(trending => tool.name.toLowerCase().includes(trending))) {
            relevanceBonus += 5;
        }
    });

    relevanceBonus += this.source.verificationStatus === 'verified' ? 20 : 0;
    relevanceBonus += this.category.industryRelevant?.length ? this.category.industryRelevant.length * 5 : 0;
    return Math.min(this.analytics.popularityScore + relevanceBonus, 100);
};

achievementSchema.methods.calculateSearchScore = function () {
    let searchScore = 0;
    if (this.title?.length > 10) searchScore += 20;
    if (this.description?.length > 100) searchScore += 15;
    searchScore += Math.min(this.skillCount * 5, 25);
    searchScore += this.source.verificationStatus === 'verified' ? 20 : 0;
    searchScore += Math.min(this.mediaCount * 5, 20);
    searchScore += this.priority.isHighlight ? 10 : 0;
    return Math.min(searchScore, 100);
};

// Static Methods
achievementSchema.statics.getTrending = async function (options = {}) {
    const { timeframe = '30d', category, limit = 20, minEngagement = 5 } = options;
    const cacheKey = `trending:achievements:${JSON.stringify(options)}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const timeframeMap = { '7d': 7, '30d': 30, '90d': 90, '1y': 365 };
    const days = timeframeMap[timeframe] || 30;
    const since = new Date(Date.now() - (days * 24 * 60 * 60 * 1000));

    const pipeline = [
        {
            $match: {
                status: 'active',
                'visibility.isPublic': true,
                'timeline.startDate': { $gte: since },
                'engagement.endorsements.count': { $gte: minEngagement },
                ...(category && { 'category.primary': category })
            }
        },
        { $lookup: { from: 'users', localField: 'userId', foreignField: '_id', as: 'user', pipeline: [{ $project: { name: 1, profilePicture: 1, headline: 1, verification: 1 } }] } },
        { $unwind: { path: '$user', preserveNullAndEmptyArrays: true } },
        { $lookup: { from: 'companies', localField: 'companyId', foreignField: '_id', as: 'company', pipeline: [{ $project: { name: 1, 'branding.logo': 1, 'industry.primary': 1 } }] } },
        { $unwind: { path: '$company', preserveNullAndEmptyArrays: true } },
        { $sort: { 'analytics.popularityScore': -1, 'engagement.endorsements.count': -1 } },
        { $limit: limit },
        {
            $project: {
                title: 1,
                description: { $substr: ['$description', 0, 200] },
                category: 1,
                scope: 1,
                timeline: { startDate: 1, isOngoing: 1 },
                source: { verificationStatus: 1, credibilityScore: 1 },
                skills: { technical: { $slice: ['$skills.technical', 5] }, soft: { $slice: ['$skills.soft', 5] } },
                user: 1,
                company: 1,
                engagement: { endorsements: { count: 1 }, views: { count: 1 }, shares: { count: 1 } },
                analytics: { popularityScore: 1, relevanceScore: 1 },
                createdAt: 1,
                durationFormatted: 1,
                credibilityLevel: 1
            }
        }
    ];

    const results = await this.aggregatePaginate(pipeline, { page: 1, limit });
    await redisClient.setEx(cacheKey, 3600, JSON.stringify(results));
    return results;
};

achievementSchema.statics.searchAchievements = async function (searchQuery, filters = {}, options = {}) {
    const { page = 1, limit = 20, sortBy = 'relevance', userId, companyId, category, verified, dateRange, skills } = options;
    const cacheKey = `search:achievements:${JSON.stringify({ searchQuery, filters, options })}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const pipeline = [
        {
            $match: {
                status: 'active',
                'visibility.searchable': true,
                'visibility.isPublic': true,
                ...(searchQuery && { $text: { $search: searchQuery, $caseSensitive: false } }),
                ...(userId && { userId: new mongoose.Types.ObjectId(userId) }),
                ...(companyId && { companyId: new mongoose.Types.ObjectId(companyId) }),
                ...(category && { 'category.primary': category }),
                ...(verified && { 'source.verificationStatus': 'verified' }),
                ...(dateRange && { 'timeline.startDate': { $gte: new Date(dateRange.from), $lte: new Date(dateRange.to) } }),
                ...(skills?.length > 0 && { 'skills.technical.skill': { $in: skills.map(skill => new RegExp(skill, 'i')) } })
            }
        },
        { $addFields: { textScore: { $meta: 'textScore' } } },
        { $lookup: { from: 'users', localField: 'userId', foreignField: '_id', as: 'user', pipeline: [{ $project: { name: 1, profilePicture: 1, headline: 1, verification: 1 } }] } },
        { $unwind: { path: '$user', preserveNullAndEmptyArrays: true } },
        { $lookup: { from: 'companies', localField: 'companyId', foreignField: '_id', as: 'company', pipeline: [{ $project: { name: 1, 'branding.logo': 1, 'industry.primary': 1 } }] } },
        { $unwind: { path: '$company', preserveNullAndEmptyArrays: true } },
        {
            $addFields: {
                relevanceScore: {
                    $add: [
                        { $multiply: [{ $ifNull: ['$textScore', 0] }, 0.4] },
                        { $multiply: [{ $divide: ['$source.credibilityScore', 100] }, 0.2] },
                        { $multiply: [{ $divide: ['$analytics.popularityScore', 100] }, 0.2] },
                        { $multiply: [{ $cond: ['$priority.isHighlight', 1, 0] }, 0.1] },
                        { $multiply: [{ $divide: [{ $size: { $ifNull: ['$skills.technical', []] } }, 20] }, 0.1] }
                    ]
                }
            }
        },
        { $sort: this.getSortQuery(sortBy) },
        {
            $project: {
                title: 1,
                description: { $substr: ['$description', 0, 200] },
                category: 1,
                scope: 1,
                timeline: { startDate: 1, isOngoing: 1, durationFormatted: 1 },
                source: { verificationStatus: 1, credibilityScore: 1, credibilityLevel: 1 },
                skills: { technical: { $slice: ['$skills.technical', 5] }, soft: { $slice: ['$skills.soft', 5] } },
                user: 1,
                company: 1,
                engagement: { endorsements: { count: 1 }, views: { count: 1 }, shares: { count: 1 } },
                analytics: { popularityScore: 1, relevanceScore: 1 },
                createdAt: 1
            }
        }
    ];

    const results = await this.aggregatePaginate(pipeline, { page, limit, customLabels: { totalDocs: 'totalResults', docs: 'achievements' } });
    await redisClient.setEx(cacheKey, 60, JSON.stringify(results));
    return results;
};

achievementSchema.statics.getSortQuery = function (sortBy) {
    const sortQueries = {
        relevance: { relevanceScore: -1, 'analytics.relevanceScore': -1 },
        popularity: { 'analytics.popularityScore': -1, 'engagement.endorsements.count': -1 },
        recent: { 'timeline.startDate': -1, createdAt: -1 },
        endorsed: { 'engagement.endorsements.count': -1 },
        verified: { 'source.credibilityScore': -1, 'source.verificationStatus': 1 }
    };
    return sortQueries[sortBy] || sortQueries.relevance;
};

achievementSchema.statics.getUserSummary = async function (userId) {
    const cacheKey = `user:achievements:summary:${userId}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const pipeline = [
        { $match: { userId: new mongoose.Types.ObjectId(userId), status: 'active', 'visibility.isPublic': true } },
        {
            $group: {
                _id: '$category.primary',
                count: { $sum: 1 },
                totalEndorsements: { $sum: '$engagement.endorsements.count' },
                avgPopularityScore: { $avg: '$analytics.popularityScore' },
                avgRelevanceScore: { $avg: '$analytics.relevanceScore' },
                latestAchievement: { $max: '$timeline.startDate' },
                highlightedCount: { $sum: { $cond: ['$priority.isHighlight', 1, 0] } }
            }
        },
        {
            $addFields: {
                category: '$_id',
                engagementRate: { $multiply: [{ $divide: ['$totalEndorsements', '$count'] }, 100] }
            }
        },
        { $sort: { count: -1 } },
        { $project: { _id: 0, category: 1, count: 1, totalEndorsements: 1, avgPopularityScore: { $round: ['$avgPopularityScore', 1] }, avgRelevanceScore: { $round: ['$avgRelevanceScore', 1] }, latestAchievement: 1, highlightedCount: 1, engagementRate: { $round: ['$engagementRate', 2] } } }
    ];

    const results = await this.aggregate(pipeline);
    await redisClient.setEx(cacheKey, 43200, JSON.stringify(results));
    return results;
};

achievementSchema.statics.bulkOperations = {
    verifyAchievements: async function (achievementIds, verificationData) {
        try {
            const bulkOps = achievementIds.map(id => ({
                updateOne: {
                    filter: { _id: new mongoose.Types.ObjectId(id), status: 'active' },
                    update: {
                        $set: {
                            'source.verificationStatus': verificationData.status,
                            'source.verificationDetails': {
                                verifiedBy: verificationData.verifiedBy,
                                verifiedAt: new Date(),
                                verificationMethod: verificationData.method,
                                verificationNotes: verificationData.notes
                            },
                            'audit.modificationHistory': {
                                $push: {
                                    modifiedBy: verificationData.verifiedBy,
                                    modifiedAt: new Date(),
                                    changeType: 'verify',
                                    changes: { verificationStatus: verificationData.status }
                                }
                            }
                        }
                    }
                }
            }));
            const result = await this.bulkWrite(bulkOps);
            for (const id of achievementIds) await redisClient.del(`achievement:${id}`);
            return result;
        } catch (error) {
            throw new Error(`Bulk verification error: ${error.message}`);
        }
    },
    archiveAchievements: async function (cutoffDate) {
        try {
            const oldAchievements = await this.find({ 'timeline.startDate': { $lt: cutoffDate }, status: 'active', 'flags.isFlagged': false }).lean();
            if (oldAchievements.length === 0) return { archived: 0 };
            const ArchiveAchievement = mongoose.model('ArchiveAchievement', achievementSchema, 'archive_achievements');
            await ArchiveAchievement.insertMany(oldAchievements);
            const result = await this.updateMany(
                { _id: { $in: oldAchievements.map(a => a._id) } },
                { $set: { status: 'archived', 'visibility.isPublic': false, 'visibility.searchable': false, 'audit.modificationHistory': { $push: { modifiedAt: new Date(), changeType: 'archive' } } } }
            );
            for (const ach of oldAchievements) await redisClient.del(`achievement:${ach._id}`);
            return { archived: result.modifiedCount };
        } catch (error) {
            throw new Error(`Archive achievements error: ${error.message}`);
        }
    },
    updateVisibility: async function (userId, visibilitySettings) {
        try {
            const result = await this.updateMany(
                { userId: new mongoose.Types.ObjectId(userId), status: 'active' },
                { $set: { visibility: visibilitySettings, 'audit.modificationHistory': { $push: { modifiedAt: new Date(), changeType: 'update', changes: { visibility: visibilitySettings } } } } }
            );
            await redisClient.del(`user:achievements:${userId}`);
            return result;
        } catch (error) {
            throw new Error(`Bulk visibility update error: ${error.message}`);
        }
    }
};

achievementSchema.statics.cleanupIndexes = async function () {
    const indexes = await this.collection.indexes();
    const essentialIndexes = ['_id_', 'achievement_search_index', 'userId_1_status_1_visibility.isPublic_1_priority.displayOrder_1', 'companyId_1_source.verificationStatus_1_engagement.endorsements.count_-1'];
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

achievementSchema.statics.initChangeStream = function () {
    const changeStream = this.watch([{ $match: { 'operationType': { $in: ['insert', 'update', 'replace'] } } }]);
    changeStream.on('change', async (change) => {
        const achievementId = change.documentKey._id.toString();
        await redisClient.del(`achievement:${achievementId}`);
        await redisClient.publish('achievement_updates', JSON.stringify({
            achievementId,
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
achievementSchema.plugin(aggregatePaginate);
if (process.env.ALGOLIA_APP_ID && process.env.ALGOLIA_ADMIN_KEY) {
    achievementSchema.plugin(mongooseAlgolia, {
        appId: process.env.ALGOLIA_APP_ID,
        apiKey: process.env.ALGOLIA_ADMIN_KEY,
        indexName: 'achievements',
        selector: 'title description skills.technical.skill category.tags cache.searchVector userId companyId',
        defaults: { author: 'unknown' },
        mappings: {
            title: v => v || '',
            description: v => v || '',
            'skills.technical.skill': v => v || [],
            'category.tags': v => v || [],
            'cache.searchVector': v => v || '',
            userId: v => v?.toString() || '',
            companyId: v => v?.toString() || ''
        },
        debug: process.env.NODE_ENV === 'development'
    });
} else {
    console.warn('Algolia plugin not initialized: Missing ALGOLIA_APP_ID or ALGOLIA_ADMIN_KEY');
}

// Production Indexes
if (process.env.NODE_ENV === 'production') {
    achievementSchema.index({ 'cache.lastCacheUpdate': -1 }, { background: true });
    achievementSchema.index({ 'engagement.endorsements.count': -1, 'visibility.isPublic': 1 }, { background: true });
}

export default mongoose.model('Achievement', achievementSchema);