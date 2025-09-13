import mongoose, { Schema } from 'mongoose';
import aggregatePaginate from 'mongoose-aggregate-paginate-v2';
import mongooseAlgolia from 'mongoose-algolia';
import validator from 'validator';
import sanitizeHtml from 'sanitize-html';
import redis from 'redis';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';

// Initialize Redis client
const redisClient = redis.createClient({ url: process.env.REDIS_URL || 'redis://localhost:6379' });
redisClient.connect().catch(err => console.error('Redis connection error:', err));

// Validation Functions
const validateHonorTitle = (value) => value && value.trim().length > 0 && value.trim().length <= 200;
const validateDateReceived = (value) => !value || (value instanceof Date && !isNaN(value.getTime()));
const validateIssuerName = (value) => /^[a-zA-Z0-9\s\-&().,'"]+$/.test(value);
const validatePrestigeLevel = (value) => ['local', 'regional', 'national', 'international'].includes(value);
const validateGPARequirement = (value) => !value || (typeof value === 'number' && value >= 0 && value <= 4.0);
const validateVerificationURL = (value) => !value || validator.isURL(value, { require_protocol: true });
const validateEmail = (value) => !value || validator.isEmail(value);

// Sub-Schemas
const issuerSchema = new Schema({
    name: { type: String, required: [true, 'Issuer name is required'], maxlength: 100, validate: { validator: validateIssuerName, message: 'Invalid issuer name format' } },
    type: { type: String, enum: ['university', 'organization', 'government', 'professional-body', 'other'], required: true },
    location: {
        city: { type: String, trim: true, maxlength: 50 },
        state: { type: String, trim: true, maxlength: 50 },
        country: { type: String, trim: true, maxlength: 50, index: true },
        coordinates: { type: { type: String, enum: ['Point'], default: 'Point' }, coordinates: { type: [Number], index: '2dsphere' } }
    },
    contact: {
        email: { type: String, validate: { validator: validateEmail, message: 'Invalid issuer email' } },
        website: { type: String, validate: { validator: value => !value || validator.isURL(value, { require_protocol: true }), message: 'Invalid issuer website' } },
        phone: { type: String, maxlength: 20 }
    },
    verificationStatus: { type: String, enum: ['verified', 'pending', 'unverified'], default: 'unverified' }
}, { _id: false });

const criteriaSchema = new Schema({
    gpaMin: { type: Number, validate: { validator: validateGPARequirement, message: 'GPA minimum must be between 0 and 4.0' } },
    requirements: [{ type: { type: String, enum: ['academic-performance', 'leadership', 'community-service', 'research', 'athletics', 'arts'] }, description: { type: String, maxlength: 500 } }],
    applicationProcess: { type: String, maxlength: 1000, set: v => v ? sanitizeHtml(v, { allowedTags: [], allowedAttributes: {} }) : v },
    deadline: { type: Date },
    isCompetitive: { type: Boolean, default: false },
    selectionCommittee: { type: Boolean, default: false }
}, { _id: false });

const mediaAttachmentSchema = new Schema({
    type: { type: String, enum: ['certificate', 'photo', 'video', 'document', 'other'], required: true },
    url: { type: String, required: true, validate: { validator: validateVerificationURL, message: 'Invalid media URL' } },
    title: { type: String, maxlength: 100 },
    description: { type: String, maxlength: 500 },
    uploadedAt: { type: Date, default: Date.now },
    size: { type: Number, min: 0 },
    hash: { type: String } // For integrity check
}, { _id: false });

const endorsementSchema = new Schema({
    endorserId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    endorserName: { type: String, maxlength: 100 },
    endorserTitle: { type: String, maxlength: 100 },
    relationship: { type: String, enum: ['faculty', 'peer', 'alumni', 'employer', 'mentor'], required: true },
    endorsedAt: { type: Date, default: Date.now },
    comment: { type: String, maxlength: 1000, set: v => v ? sanitizeHtml(v, { allowedTags: [], allowedAttributes: {} }) : v },
    rating: { type: Number, min: 1, max: 5 },
    isVerified: { type: Boolean, default: false }
}, { _id: false });

const verificationSchema = new Schema({
    isVerified: { type: Boolean, default: false, index: true },
    verifiedBy: { type: Schema.Types.ObjectId, ref: 'User' },
    verificationDate: { type: Date },
    method: { type: String, enum: ['document-upload', 'issuer-contact', 'database-check', 'peer-endorsement', 'api-sync'], required: true },
    score: { type: Number, min: 0, max: 100, default: 0 },
    documents: [mediaAttachmentSchema],
    issuerContactEmail: { type: String, validate: { validator: validateEmail, message: 'Invalid issuer contact email' } },
    issuerContactVerified: { type: Boolean, default: false },
    lastVerified: { type: Date }
}, { _id: false });

const impactSchema = new Schema({
    description: { type: String, maxlength: 1000 },
    metrics: [{ type: { type: String, enum: ['funding-awarded', 'scholarship-value', 'recognition-count', 'project-impact'] }, value: { type: Number, min: 0 }, unit: { type: String, maxlength: 20 } }],
    beneficiaries: { type: Number, min: 0 },
    duration: { type: String, maxlength: 50 } // e.g., 'ongoing', 'one-year'
}, { _id: false });

const privacySchema = new Schema({
    isPublic: { type: Boolean, default: true, index: true },
    showDetails: { type: Boolean, default: true },
    showEndorsements: { type: Boolean, default: true },
    showVerification: { type: Boolean, default: true },
    searchable: { type: Boolean, default: true, index: true },
    visibleToConnections: { type: Boolean, default: true },
    visibleToAlumni: { type: Boolean, default: true },
    allowContactFromIssuers: { type: Boolean, default: true }
}, { _id: false });

const analyticsSchema = new Schema({
    profileViews: { type: Number, default: 0, min: 0 },
    endorsementCount: { type: Number, default: 0, min: 0 },
    shareCount: { type: Number, default: 0, min: 0 },
    lastViewed: { type: Date },
    viewersCount: { type: Number, default: 0, min: 0 },
    engagementScore: { type: Number, default: 0, min: 0 },
    clickThroughRate: { type: Number, default: 0, min: 0, max: 100 }
}, { _id: false });

const statusSchema = new Schema({
    isActive: { type: Boolean, default: true, index: true },
    isDeleted: { type: Boolean, default: false, index: true },
    isFeatured: { type: Boolean, default: false },
    isPromoted: { type: Boolean, default: false },
    deletedAt: { type: Date },
    archivedAt: { type: Date },
    featuredUntil: { type: Date },
    lastActiveAt: { type: Date, default: Date.now },
    workflow: { type: String, enum: ['draft', 'pending-review', 'published', 'archived'], default: 'published' }
}, { _id: false });

const socialSchema = new Schema({
    likes: [{ userId: { type: Schema.Types.ObjectId, ref: 'User' }, likedAt: { type: Date, default: Date.now } }],
    comments: [{ userId: { type: Schema.Types.ObjectId, ref: 'User' }, comment: { type: String, maxlength: 500, set: v => v ? sanitizeHtml(v, { allowedTags: [], allowedAttributes: {} }) : v }, commentedAt: { type: Date, default: Date.now }, isPublic: { type: Boolean, default: true } }],
    shares: [{ userId: { type: Schema.Types.ObjectId, ref: 'User' }, platform: { type: String, enum: ['linkedin', 'twitter', 'facebook', 'email', 'internal'] }, sharedAt: { type: Date, default: Date.now } }],
    bookmarks: [{ userId: { type: Schema.Types.ObjectId, ref: 'User' }, bookmarkedAt: { type: Date, default: Date.now } }]
}, { _id: false });

const aiInsightsSchema = new Schema({
    prestigeScore: { type: Number, min: 0, max: 100 },
    careerImpact: { type: String, maxlength: 200 },
    marketValue: { type: Number, min: 0, max: 100 },
    similarHonors: [{ type: Schema.Types.ObjectId, ref: 'Honor' }],
    recommendedApplications: [{ type: String, maxlength: 100 }],
    trendScore: { type: Number, min: 0, max: 100 },
    lastAnalyzed: { type: Date }
}, { _id: false });

const metadataSchema = new Schema({
    source: { type: String, default: 'manual', index: true },
    importSource: { type: String, enum: ['university-portal', 'linkedin', 'manual', 'api', 'csv-import'] },
    importId: { type: String },
    templateId: { type: Schema.Types.ObjectId },
    lastUpdated: { type: Date, default: Date.now },
    updateCount: { type: Number, default: 0, min: 0 },
    version: { type: Number, default: 1, min: 1 },
    duplicateOf: { type: Schema.Types.ObjectId },
    isDuplicate: { type: Boolean, default: false }
}, { _id: false });

// Main Honor Schema
const honorSchema = new Schema({
    _id: { type: Schema.Types.ObjectId, auto: true },
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: [true, 'User ID is required'], index: true },
    title: { type: String, required: [true, 'Honor title is required'], trim: true, maxlength: 200, index: true, validate: { validator: validateHonorTitle, message: 'Honor title must be 1-200 characters' } },
    description: { type: String, maxlength: 1000, trim: true, set: v => v ? sanitizeHtml(v, { allowedTags: [], allowedAttributes: {} }) : v },
    type: { type: String, enum: ['deans-list', 'presidents-list', 'scholarship', 'fellowship', 'award', 'grant', 'honor-society', 'research-grant', 'leadership-award', 'academic-excellence'], required: [true, 'Honor type is required'], index: true },
    dateReceived: { type: Date, required: [true, 'Date received is required'], index: true, validate: { validator: validateDateReceived, message: 'Invalid date received' } },
    issuer: issuerSchema,
    criteria: criteriaSchema,
    prestigeLevel: { type: String, validate: { validator: validatePrestigeLevel, message: 'Invalid prestige level' }, default: 'local', index: true },
    gpaRequirement: { type: Number, validate: { validator: validateGPARequirement, message: 'GPA requirement must be between 0 and 4.0' } },
    mediaAttachments: [mediaAttachmentSchema],
    endorsements: [endorsementSchema],
    verification: verificationSchema,
    impact: impactSchema,
    privacy: privacySchema,
    analytics: analyticsSchema,
    status: statusSchema,
    social: socialSchema,
    aiInsights: aiInsightsSchema,
    metadata: metadataSchema,
    cache: {
        searchVector: { type: String, index: 'text' },
        popularityScore: { type: Number, default: 0, index: true },
        trendingScore: { type: Number, default: 0, index: true },
        cacheVersion: { type: Number, default: 1 },
        lastCacheUpdate: { type: Date, default: Date.now, index: true }
    }
}, {
    timestamps: true,
    collection: 'honors',
    autoIndex: process.env.NODE_ENV !== 'production',
    readPreference: 'secondaryPreferred',
    writeConcern: { w: 'majority', wtimeout: 5000 },
    toJSON: {
        virtuals: true,
        transform: (doc, ret) => {
            delete ret.verification.documents;
            delete ret.social.comments;
            delete ret.__v;
            return ret;
        }
    },
    toObject: { virtuals: true },
    minimize: false,
    strict: 'throw'
});

// Indexes
honorSchema.index({ userId: 1, 'dateReceived': -1, 'status.isActive': 1 });
honorSchema.index({ 'type': 1, 'prestigeLevel': 1, 'status.isActive': 1 });
honorSchema.index({ 'issuer.country': 1, 'issuer.type': 1 });
honorSchema.index({ title: 1, type: 1, 'verification.isVerified': 1 });
honorSchema.index({ 'endorsements.endorserId': 1, 'verification.isVerified': 1, 'privacy.searchable': 1 });
honorSchema.index({ 'privacy.isPublic': 1, 'status.isActive': 1, 'analytics.engagementScore': -1, updatedAt: -1 });
honorSchema.index({ 'dateReceived': 1, userId: 1, 'status.workflow': 1 });
honorSchema.index({ 'aiInsights.marketValue': 1, 'aiInsights.lastAnalyzed': -1 });
honorSchema.index({ 'issuer.coordinates': '2dsphere' }, { sparse: true });
honorSchema.index({ 'status.deletedAt': 1 }, { expireAfterSeconds: 7776000, sparse: true }); // 90 days
honorSchema.index({
    title: 'text',
    description: 'text',
    type: 'text',
    'criteria.requirements.description': 'text',
    'impact.description': 'text',
    'cache.searchVector': 'text'
}, {
    weights: { title: 10, type: 8, description: 6, 'criteria.requirements.description': 4, 'impact.description': 2, 'cache.searchVector': 1 },
    name: 'honor_text_search'
});
honorSchema.index({ 'gpaRequirement': 1, 'issuer.country': 1, prestigeLevel: 1 }, { sparse: true });
honorSchema.index({ 'prestigeLevel': 1, 'dateReceived': -1 });
honorSchema.index({ 'cache.popularityScore': -1, 'status.isActive': 1 }, { background: true });
honorSchema.index({ 'cache.trendingScore': -1, 'privacy.isPublic': 1 }, { background: true });

// Virtuals
honorSchema.virtual('endorsementCount').get(function () {
    return this.endorsements?.length || 0;
});
honorSchema.virtual('mediaCount').get(function () {
    return this.mediaAttachments?.length || 0;
});
honorSchema.virtual('isRecent').get(function () {
    const twoYearsAgo = new Date();
    twoYearsAgo.setFullYear(twoYearsAgo.getFullYear() - 2);
    return this.dateReceived >= twoYearsAgo;
});
honorSchema.virtual('verificationLevel').get(function () {
    const score = this.verification.score;
    if (score >= 90) return 'platinum';
    if (score >= 75) return 'gold';
    if (score >= 60) return 'silver';
    if (score >= 40) return 'bronze';
    return 'unverified';
});
honorSchema.virtual('engagementLevel').get(function () {
    const score = this.analytics.engagementScore;
    if (score >= 80) return 'viral';
    if (score >= 60) return 'high';
    if (score >= 40) return 'medium';
    if (score >= 20) return 'low';
    return 'minimal';
});
honorSchema.virtual('prestigeCategory').get(function () {
    const level = this.prestigeLevel;
    if (level === 'international') return 'elite';
    if (level === 'national') return 'high';
    if (level === 'regional') return 'medium';
    return 'local';
});

// Middleware
honorSchema.pre('save', async function (next) {
    try {
        // Update metadata
        this.metadata.lastUpdated = new Date();
        this.metadata.updateCount += 1;
        this.metadata.version += 1;

        // Generate search vector
        this.cache.searchVector = [
            this.title,
            this.description,
            this.type,
            ...this.criteria.requirements.map(r => r.description),
            ...this.endorsements.map(e => e.comment),
            ...this.impact.metrics.map(m => m.type)
        ].filter(Boolean).join(' ').toLowerCase();

        // Calculate verification score
        if (this.verification.isVerified) {
            let score = 30;
            const methodScores = { 'document-upload': 20, 'issuer-contact': 25, 'database-check': 30, 'peer-endorsement': 15, 'api-sync': 10 };
            score += methodScores[this.verification.method] || 0;
            if (this.verification.documents?.length > 0) score += 15;
            if (this.verification.issuerContactVerified) score += 10;
            if (this.endorsements?.length > 0) score += Math.min(this.endorsements.length * 2, 20);
            if (this.mediaAttachments?.length > 0) score += 5;
            if (this.prestigeLevel === 'international') score += 20;
            this.verification.score = Math.min(score, 100);
        }

        // Calculate engagement score
        let engagementScore = 0;
        engagementScore += (this.analytics.profileViews || 0) * 0.1;
        engagementScore += (this.social.likes?.length || 0) * 2;
        engagementScore += (this.social.comments?.length || 0) * 3;
        engagementScore += (this.social.shares?.length || 0) * 5;
        engagementScore += (this.endorsementCount || 0) * 4;
        engagementScore += (this.verification.score || 0) * 0.2;
        this.analytics.engagementScore = Math.min(engagementScore, 1000);

        this.cache.popularityScore = this.calculatePopularityScore();
        this.cache.trendingScore = (this.analytics.engagementScore * 0.4) + (this.verification.score * 0.3) + (this.endorsementCount * 0.3);

        // Update cache
        this.cache.lastCacheUpdate = new Date();
        this.cache.cacheVersion += 1;

        // Cache in Redis
        await redisClient.setEx(`honor:${this._id}`, 300, JSON.stringify(this.toJSON()));

        // Publish updates
        await redisClient.publish('honor_updates', JSON.stringify({
            honorId: this._id,
            popularityScore: this.cache.popularityScore,
            trendingScore: this.cache.trendingScore
        }));

        // AI Insights
        if (!this.aiInsights.lastAnalyzed || (new Date() - this.aiInsights.lastAnalyzed) > 7 * 24 * 60 * 60 * 1000) {
            this.aiInsights.lastAnalyzed = new Date();
            let prestige = 20;
            if (this.prestigeLevel === 'international') prestige += 40;
            else if (this.prestigeLevel === 'national') prestige += 30;
            else if (this.prestigeLevel === 'regional') prestige += 20;
            if (this.endorsements.length > 3) prestige += 20;
            if (this.verification.score >= 80) prestige += 10;
            this.aiInsights.prestigeScore = Math.min(prestige, 100);
            this.aiInsights.recommendedApplications = this.type === 'scholarship' ? ['fellowship', 'grant'] : ['award', 'recognition'];
        }

        // Update last active
        this.status.lastActiveAt = new Date();

        // Encrypt sensitive fields if private
        if (this.criteria.gpaMin && !this.privacy.showDetails) {
            this.criteria.gpaMin = await encryptField(this.criteria.gpaMin.toString());
        }

        next();
    } catch (error) {
        next(new Error(`Pre-save middleware error: ${error.message}`));
    }
});

honorSchema.pre('remove', async function (next) {
    try {
        this.status.isDeleted = true;
        this.status.deletedAt = new Date();
        this.privacy.isPublic = false;
        this.privacy.searchable = false;
        await redisClient.del(`honor:${this._id}`);
        await this.save();
        next();
    } catch (error) {
        next(new Error(`Pre-remove middleware error: ${error.message}`));
    }
});

honorSchema.post('save', async function (doc) {
    try {
        // Update User profile
        const User = mongoose.model('User');
        await User.updateOne(
            { _id: doc.userId },
            { $set: { 'profile.lastUpdated': new Date() }, $inc: { 'analytics.achievementsCount': 1 } }
        );

        // Sync to Algolia
        if (doc.privacy.searchable && doc.privacy.isPublic && doc.status.isActive) {
            try {
                await doc.syncToAlgolia();
            } catch (error) {
                console.error('Algolia sync error:', error.message);
            }
        }

        // Invalidate related caches
        await redisClient.del(`user:honors:${doc.userId}`);
    } catch (error) {
        console.error('Post-save middleware error:', error.message);
    }
});

// Instance Methods
honorSchema.methods.calculatePopularityScore = function () {
    const weights = { views: 0.3, likes: 0.2, comments: 0.2, shares: 0.2, endorsements: 0.1 };
    const viewScore = Math.log1p(this.analytics.profileViews) / Math.log1p(10000);
    const likeScore = Math.log1p(this.social.likes?.length || 0) / Math.log1p(1000);
    const commentScore = Math.log1p(this.social.comments?.length || 0) / Math.log1p(500);
    const shareScore = Math.log1p(this.social.shares?.length || 0) / Math.log1p(500);
    const endorsementScore = Math.log1p(this.endorsementCount) / Math.log1p(100);
    return Math.min(100, (
        viewScore * weights.views +
        likeScore * weights.likes +
        commentScore * weights.comments +
        shareScore * weights.shares +
        endorsementScore * weights.endorsements
    ) * 100);
};

honorSchema.methods.syncToAlgolia = async function () {
    // Implementation for Algolia sync
    return Promise.resolve();
};

// Static Methods
honorSchema.statics.getUserHonors = async function (userId, options = {}) {
    const { page = 1, limit = 10, sortBy = 'dateReceived', sortOrder = -1, includeDeleted = false, filters = {}, includePrivate = false } = options;
    const cacheKey = `user:honors:${userId}:${JSON.stringify(options)}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const baseQuery = { userId: new mongoose.Types.ObjectId(userId), 'status.isActive': true };
    if (!includeDeleted) baseQuery['status.isDeleted'] = false;
    if (!includePrivate) baseQuery['privacy.isPublic'] = true;
    Object.entries(filters).forEach(([key, value]) => { if (value !== undefined && value !== null && value !== '') baseQuery[key] = value; });

    const results = await this.find(baseQuery)
        .sort({ [sortBy]: sortOrder })
        .skip((page - 1) * limit)
        .limit(limit)
        .populate({ path: 'issuer', select: 'name type location.country' })
        .populate({ path: 'endorsements.endorserId', select: 'name profilePic headline' })
        .populate({ path: 'mediaAttachments', select: 'url type title' })
        .select('-impact.metrics -metadata.importId')
        .lean({ virtuals: true });

    await redisClient.setEx(cacheKey, 3600, JSON.stringify(results));
    return results;
};

honorSchema.statics.advancedSearch = async function (searchOptions = {}) {
    const { query = '', issuerType, prestigeMin, type, verified = false, hasEndorsements = false, dateRange = {}, page = 1, limit = 20, sortBy = 'relevance', userId = null } = searchOptions;
    const cacheKey = `search:honors:${JSON.stringify(searchOptions)}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const pipeline = [
        {
            $match: {
                'status.isActive': true,
                'status.isDeleted': false,
                'privacy.isPublic': true,
                'privacy.searchable': true,
                'status.workflow': 'published',
                ...(verified && { 'verification.isVerified': true }),
                ...(type && { type }),
                ...(issuerType && { 'issuer.type': issuerType }),
                ...(prestigeMin && { prestigeLevel: { $in: ['national', 'international'] } }), // Assuming higher levels
                ...(dateRange.start && { dateReceived: { $gte: new Date(dateRange.start) } }),
                ...(dateRange.end && { dateReceived: { $lte: new Date(dateRange.end) } }),
                ...(hasEndorsements && { 'endorsements.0': { $exists: true } })
            }
        },
        ...(query ? [{ $match: { $text: { $search: query, $caseSensitive: false } } }, { $addFields: { textScore: { $meta: 'textScore' } } }] : []),
        { $lookup: { from: 'users', localField: 'userId', foreignField: '_id', as: 'userProfile', pipeline: [{ $project: { name: 1, profilePic: 1, headline: 1, verification: 1, premium: 1 } }] } },
        { $unwind: { path: '$userProfile', preserveNullAndEmptyArrays: true } },
        ...(userId ? [{
            $addFields: {
                networkBoost: {
                    $cond: [{ $eq: ['$userId', new mongoose.Types.ObjectId(userId)] }, 0.3, 0]
                }
            },
        },] : []),
        {
            $addFields: {
                relevanceScore: {
                    $add: [
                        { $multiply: [{ $ifNull: ['$textScore', 0] }, 0.3] },
                        { $multiply: [{ $divide: ['$verification.score', 100] }, 0.15] },
                        { $multiply: [{ $divide: [{ $min: ['$analytics.engagementScore', 100] }, 100] }, 0.1] },
                        { $multiply: [{ $size: { $ifNull: ['$endorsements', []] } }, 0.1] },
                        { $multiply: [{ $cond: [{ $eq: ['$prestigeLevel', 'international'] }, 1, 0.5] }, 0.2] },
                        { $ifNull: ['$networkBoost', 0] }
                    ]
                },
                popularityScore: this.calculatePopularityScore()
            }
        },
        { $sort: this.getSortQuery(sortBy) },
        {
            $project: {
                userId: 1,
                title: 1,
                type: 1,
                prestigeLevel: 1,
                dateReceived: 1,
                issuer: { name: 1, type: 1, country: '$issuer.location.country' },
                description: { $substr: ['$description', 0, 200] },
                endorsements: { $size: { $ifNull: ['$endorsements', []] } },
                verification: { isVerified: 1, level: '$verification.score' },
                userProfile: { name: '$userProfile.name', profilePic: '$userProfile.profilePic', verified: '$userProfile.verification' },
                relevanceScore: 1,
                popularityScore: 1,
                createdAt: 1,
                updatedAt: 1
            }
        }
    ];

    const results = await this.aggregatePaginate(pipeline, { page, limit, customLabels: { totalDocs: 'totalResults', docs: 'honors' } });
    await redisClient.setEx(cacheKey, 60, JSON.stringify(results));
    return results;
};

honorSchema.statics.getSortQuery = function (sortBy) {
    const sortQueries = {
        'relevance': { relevanceScore: -1, 'verification.score': -1 },
        'recent': { dateReceived: -1, updatedAt: -1 },
        'popular': { 'cache.popularityScore': -1, 'analytics.profileViews': -1 },
        'prestige': { prestigeLevel: -1 },
        'alphabetical': { title: 1 }
    };
    return sortQueries[sortBy] || sortQueries['relevance'];
};

honorSchema.statics.getTrendingInsights = async function (options = {}) {
    const { timeframe = 30, type, prestigeLevel, limit = 25 } = options;
    const cacheKey = `trending:insights:${JSON.stringify(options)}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const startDate = new Date();
    startDate.setDate(startDate.getDate() - timeframe);
    const pipeline = [
        {
            $match: {
                'status.isActive': true,
                'status.isDeleted': false,
                'privacy.isPublic': true,
                createdAt: { $gte: startDate },
                ...(type && { type }),
                ...(prestigeLevel && { prestigeLevel })
            }
        },
        {
            $facet: {
                trendingTypes: [
                    { $group: { _id: '$type', count: { $sum: 1 }, avgPrestige: { $avg: { $switch: { branches: [{ case: { $eq: ['$prestigeLevel', 'local'] }, then: 1 }, { case: { $eq: ['$prestigeLevel', 'regional'] }, then: 2 }, { case: { $eq: ['$prestigeLevel', 'national'] }, then: 3 }, { case: { $eq: ['$prestigeLevel', 'international'] }, then: 4 }], default: 1 } } }, totalEndorsements: { $sum: { $size: { $ifNull: ['$endorsements', []] } } } } },
                    { $addFields: { trendScore: { $multiply: ['$count', { $add: ['$avgPrestige', 1] }, { $add: [{ $divide: ['$totalEndorsements', 10] }, 1] }] } } },
                    { $sort: { trendScore: -1 } },
                    { $limit: limit },
                    { $project: { type: '$_id', occurrences: '$count', avgPrestige: { $round: ['$avgPrestige', 1] }, totalEndorsements: 1, trendScore: 1 } }
                ],
                prestigeTrends: [
                    { $group: { _id: '$prestigeLevel', count: { $sum: 1 }, avgEndorsements: { $avg: { $size: { $ifNull: ['$endorsements', []] } } } } },
                    { $sort: { count: -1 } },
                    { $project: { level: '$_id', count: 1, avgEndorsements: { $round: ['$avgEndorsements', 1] }, percentage: { $multiply: [{ $divide: ['$count', { $sum: '$count' }] }, 100] } } }
                ]
            }
        }
    ];

    const results = await this.aggregate(pipeline);
    await redisClient.setEx(cacheKey, 86400, JSON.stringify(results));
    return results;
};

honorSchema.statics.getAchievementAnalytics = async function (userId, options = {}) {
    const cacheKey = `achievement:analytics:${userId}:${JSON.stringify(options)}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const pipeline = [
        { $match: { userId: new mongoose.Types.ObjectId(userId), 'status.isActive': true, 'status.isDeleted': false } },
        { $sort: { dateReceived: 1 } },
        {
            $group: {
                _id: null,
                honors: {
                    $push: {
                        title: '$title',
                        type: '$type',
                        prestigeLevel: '$prestigeLevel',
                        dateReceived: '$dateReceived',
                        endorsements: { $size: { $ifNull: ['$endorsements', []] } },
                        verificationScore: '$verification.score'
                    }
                },
                totalHonors: { $sum: 1 },
                avgPrestige: { $avg: { $switch: { branches: [{ case: { $eq: ['$prestigeLevel', 'local'] }, then: 1 }, { case: { $eq: ['$prestigeLevel', 'regional'] }, then: 2 }, { case: { $eq: ['$prestigeLevel', 'national'] }, then: 3 }, { case: { $eq: ['$prestigeLevel', 'international'] }, then: 4 }], default: 1 } } },
                totalEndorsements: { $sum: { $size: { $ifNull: ['$endorsements', []] } } },
                uniqueTypes: { $addToSet: '$type' },
                uniqueIssuers: { $addToSet: '$issuer.name' },
                progression: { $push: { date: '$dateReceived', prestige: '$prestigeLevel' } }
            }
        },
        {
            $addFields: {
                typeCount: { $size: '$uniqueTypes' },
                issuerCount: { $size: '$uniqueIssuers' },
                avgEndorsements: { $divide: ['$totalEndorsements', '$totalHonors'] },
                prestigeProgress: '$progression'
            }
        },
        {
            $project: {
                _id: 0,
                summary: { totalHonors: '$totalHonors', avgPrestige: { $round: ['$avgPrestige', 1] }, totalEndorsements: '$totalEndorsements', typeDiversity: '$typeCount', issuerDiversity: '$issuerCount', avgEndorsements: { $round: ['$avgEndorsements', 1] } },
                honors: '$honors',
                progression: '$prestigeProgress'
            }
        }
    ];

    const results = await this.aggregate(pipeline);
    await redisClient.setEx(cacheKey, 43200, JSON.stringify(results));
    return results;
};

honorSchema.statics.getMarketInsights = async function (options = {}) {
    const { type, prestigeLevel, issuerCountry, gpaMin, gpaMax = {}, limit = 20 } = options;
    const cacheKey = `market:insights:${JSON.stringify(options)}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const pipeline = [
        { $match: { 'status.isActive': true, 'status.isDeleted': false, 'privacy.isPublic': true, ...(type && { type }), ...(prestigeLevel && { prestigeLevel }), ...(issuerCountry && { 'issuer.location.country': issuerCountry }), ...(gpaMin || gpaMax ? { gpaRequirement: { $gte: gpaMin || 0, $lte: gpaMax || 4.0 } } : {}) } },
        {
            $group: {
                _id: { type: '$type', prestige: '$prestigeLevel', country: '$issuer.location.country' },
                avgScore: { $avg: '$verification.score' },
                count: { $sum: 1 },
                totalEndorsements: { $sum: { $size: { $ifNull: ['$endorsements', []] } } },
                topIssuers: { $addToSet: '$issuer.name' },
                samples: { $push: { title: '$title', score: '$verification.score', endorsements: { $size: { $ifNull: ['$endorsements', []] } } } }
            }
        },
        {
            $addFields: {
                issuerCount: { $size: '$topIssuers' },
                avgEndorsements: { $divide: ['$totalEndorsements', '$count'] },
                topSamples: { $slice: ['$samples', 5] }
            }
        },
        { $sort: { count: -1 } },
        { $limit: limit },
        { $project: { type: '$_id.type', prestige: '$_id.prestige', country: '$_id.country', avgScore: { $round: ['$avgScore', 1] }, count: 1, issuerCount: 1, avgEndorsements: { $round: ['$avgEndorsements', 1] }, samples: '$topSamples' } }
    ];

    const results = await this.aggregate(pipeline);
    await redisClient.setEx(cacheKey, 86400, JSON.stringify(results));
    return results;
};

honorSchema.statics.bulkOperations = {
    updateVerification: async function (honorIds, verificationData) {
        try {
            const bulkOps = honorIds.map(id => ({
                updateOne: {
                    filter: { _id: new mongoose.Types.ObjectId(id), 'status.isActive': true },
                    update: { $set: { 'verification.isVerified': verificationData.isVerified, 'verification.verificationDate': new Date(), 'verification.verifiedBy': verificationData.verifiedBy, 'verification.method': verificationData.method, 'metadata.lastUpdated': new Date() } }
                }
            }));
            const result = await this.bulkWrite(bulkOps);
            for (const id of honorIds) await redisClient.del(`honor:${id}`);
            return result;
        } catch (error) {
            throw new Error(`Bulk verification update error: ${error.message}`);
        }
    },
    updatePrivacy: async function (userId, privacySettings) {
        try {
            const result = await this.updateMany(
                { userId: new mongoose.Types.ObjectId(userId) },
                { $set: { privacy: { ...privacySettings, 'metadata.lastUpdated': new Date() } } }
            );
            await redisClient.del(`user:honors:${userId}`);
            return result;
        } catch (error) {
            throw new Error(`Bulk privacy update error: ${error.message}`);
        }
    },
    archiveOldHonors: async function (cutoffDate) {
        try {
            const oldHonors = await this.find({ dateReceived: { $lt: cutoffDate }, 'status.isActive': true, 'status.isDeleted': false }).lean();
            if (oldHonors.length === 0) return { archived: 0 };
            const ArchiveHonor = mongoose.model('ArchiveHonor', honorSchema, 'archive_honors');
            await ArchiveHonor.insertMany(oldHonors);
            const result = await this.updateMany(
                { _id: { $in: oldHonors.map(h => h._id) } },
                { $set: { 'status.isActive': false, 'status.archivedAt': new Date(), 'metadata.lastUpdated': new Date() } }
            );
            for (const honor of oldHonors) await redisClient.del(`honor:${honor._id}`);
            return { archived: result.modifiedCount };
        } catch (error) {
            throw new Error(`Archive old honors error: ${error.message}`);
        }
    },
    addEndorsement: async function (honorIds, endorsementData) {
        try {
            const bulkOps = honorIds.map(id => ({
                updateOne: {
                    filter: { _id: new mongoose.Types.ObjectId(id) },
                    update: { $push: { endorsements: endorsementData }, $inc: { 'analytics.endorsementCount': 1 } }
                }
            }));
            const result = await this.bulkWrite(bulkOps);
            for (const id of honorIds) await redisClient.del(`honor:${id}`);
            return result;
        } catch (error) {
            throw new Error(`Bulk endorsement add error: ${error.message}`);
        }
    }
};

honorSchema.statics.getAIRecommendations = async function (userId, options = {}) {
    const { type = 'prestige-boost', limit = 10 } = options;
    const cacheKey = `ai:recommendations:${userId}:${type}:${limit}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const pipeline = [
        { $match: { userId: new mongoose.Types.ObjectId(userId), 'status.isActive': true } },
        { $group: { _id: null, currentTypes: { $addToSet: '$type' }, currentPrestige: { $max: { $switch: { branches: [{ case: { $eq: ['$prestigeLevel', 'local'] }, then: 1 }, { case: { $eq: ['$prestigeLevel', 'regional'] }, then: 2 }, { case: { $eq: ['$prestigeLevel', 'national'] }, then: 3 }, { case: { $eq: ['$prestigeLevel', 'international'] }, then: 4 }], default: 1 } } }, totalEndorsements: { $sum: { $size: { $ifNull: ['$endorsements', []] } } } } },
        { $lookup: { from: 'honors', pipeline: [{ $match: { 'status.isActive': true, 'privacy.isPublic': true, userId: { $ne: new mongoose.Types.ObjectId(userId) } } }, { $sample: { size: 1000 } }], as: 'marketData' } },
        {
            $project: {
                recommendations: {
                    $switch: {
                        branches: [
                            { case: { $eq: [type, 'prestige-boost'] }, then: { nextLevels: { $cond: [{ $eq: [{ $max: '$currentPrestige' }, 1] }, ['regional', 'national'], { $eq: [{ $max: '$currentPrestige' }, 2] }, ['national', 'international'], ['elite-opportunities']] }, suggestedTypes: { $slice: [{ $setDifference: [{ $reduce: { input: '$marketData.type', initialValue: [], in: { $setUnion: ['$value', ['$this']] } } }, '$currentTypes'] }, limit] } } },
                            { case: { $eq: [type, 'endorsement-build'] }, then: { highEndorsementHonors: { $slice: [{ $filter: { input: '$marketData', cond: { $gt: [{ $size: { $ifNull: ['$$this.endorsements', []] } }, 5] } } }, limit] } } }
                        ],
                        default: { message: 'Invalid recommendation type' }
                    }
                }
            }
        }
    ];

    const results = await this.aggregate(pipeline);
    await redisClient.setEx(cacheKey, 43200, JSON.stringify(results));
    return results;
};

honorSchema.statics.getPerformanceMetrics = async function (timeframe = '30d') {
    const cacheKey = `performance:metrics:${timeframe}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const startDate = new Date();
    const days = parseInt(timeframe.replace('d', ''));
    startDate.setDate(startDate.getDate() - days);
    const pipeline = [
        {
            $facet: {
                queryStats: [{ $match: { 'metadata.lastUpdated': { $gte: startDate } } }, { $group: { _id: null, totalQueries: { $sum: 1 }, avgResponseTime: { $avg: '$analytics.responseTime' }, errorRate: { $avg: { $cond: ['$analytics.hasError', 1, 0] } } } }],
                indexStats: [{ $group: { _id: '$metadata.source', count: { $sum: 1 }, avgVerificationScore: { $avg: '$verification.score' } } }],
                dataQuality: [
                    {
                        $group: {
                            _id: null,
                            totalRecords: { $sum: 1 },
                            completeProfiles: { $sum: { $cond: [{ $and: [{ $ne: ['$title', ''] }, { $ne: ['$description', ''] }, { $gt: [{ $size: { $ifNull: ['$mediaAttachments', []] } }, 0] }] }, 1, 0] } },
                            verifiedRecords: { $sum: { $cond: ['$verification.isVerified', 1, 0] } },
                            withEndorsements: { $sum: { $cond: [{ $gt: [{ $size: { $ifNull: ['$endorsements', []] } }, 0] }, 1, 0] } }
                        }
                    },
                    { $addFields: { completenessRate: { $multiply: [{ $divide: ['$completeProfiles', '$totalRecords'] }, 100] }, verificationRate: { $multiply: [{ $divide: ['$verifiedRecords', '$totalRecords'] }, 100] }, endorsementRate: { $multiply: [{ $divide: ['$withEndorsements', '$totalRecords'] }, 100] } } }
                ]
            }
        }
    ];

    const results = await this.aggregate(pipeline);
    await redisClient.setEx(cacheKey, 86400, JSON.stringify(results));
    return results;
};

honorSchema.statics.cleanupIndexes = async function () {
    const indexes = await this.collection.indexes();
    const essentialIndexes = ['_id_', 'honor_text_search', 'userId_1_dateReceived_-1_status.isActive_1', 'type_1_prestigeLevel_1_status.isActive_1'];
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

honorSchema.statics.initChangeStream = function () {
    const changeStream = this.watch([{ $match: { 'operationType': { $in: ['insert', 'update', 'replace'] } } }]);
    changeStream.on('change', async (change) => {
        const honorId = change.documentKey._id.toString();
        await redisClient.del(`honor:${honorId}`);
        await redisClient.publish('honor_updates', JSON.stringify({
            honorId,
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
honorSchema.plugin(aggregatePaginate);
if (process.env.ALGOLIA_APP_ID && process.env.ALGOLIA_ADMIN_KEY) {
    honorSchema.plugin(mongooseAlgolia, {
        appId: process.env.ALGOLIA_APP_ID,
        apiKey: process.env.ALGOLIA_ADMIN_KEY,
        indexName: 'honors',
        selector: 'title description type criteria.requirements.description issuer.name cache.searchVector',
        defaults: { author: 'unknown' },
        mappings: { title: v => v || '', description: v => v || '', type: v => v || '', 'criteria.requirements.description': v => v || [], 'issuer.name': v => v || '', 'cache.searchVector': v => v || '' },
        debug: process.env.NODE_ENV === 'development'
    });
} else {
    console.warn('Algolia plugin not initialized: Missing ALGOLIA_APP_ID or ALGOLIA_ADMIN_KEY');
}

// Production Indexes
if (process.env.NODE_ENV === 'production') {
    honorSchema.index({ 'cache.popularityScore': -1, 'status.isActive': 1 }, { background: true });
    honorSchema.index({ 'cache.trendingScore': -1, 'privacy.isPublic': 1 }, { background: true });
}

export default mongoose.model('Honor', honorSchema);