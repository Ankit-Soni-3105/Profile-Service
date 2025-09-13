import mongoose, { Schema } from 'mongoose';
import aggregatePaginate from 'mongoose-aggregate-paginate-v2';
import mongooseAlgolia from 'mongoose-algolia';
import validator from 'validator';
import sanitizeHtml from 'sanitize-html';
import redis from 'redis';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';

// Initialize Redis client with enhanced configuration
const redisClient = redis.createClient({
    url: process.env.REDIS_URL || 'redis://localhost:6379',
    socket: { reconnectStrategy: retries => Math.min(retries * 100, 3000) },
    maxRetriesPerRequest: 20
});
redisClient.connect().catch(err => console.error('Redis connection error:', err));

// Validation Functions
const validateURL = (value) => !value || validator.isURL(value, { require_protocol: true });
const validateEmail = (value) => !value || validator.isEmail(value);
const validateOrgName = (value) => /^[a-zA-Z0-9\s\-&().,]+$/.test(value);
const validateISODate = (value) => !value || validator.isISO8601(value.toString());

// Sub-Schemas
const contactSchema = new Schema({
    email: { type: String, validate: { validator: validateEmail, message: 'Invalid contact email' }, required: true, index: true },
    phone: { type: String, trim: true, maxlength: 20 },
    address: {
        street: { type: String, maxlength: 200 },
        city: { type: String, maxlength: 100 },
        state: { type: String, maxlength: 100 },
        country: { type: String, maxlength: 2, index: true },
        postalCode: { type: String, maxlength: 20 }
    },
    website: { type: String, validate: { validator: validateURL, message: 'Invalid website URL' } },
    supportEmail: { type: String, validate: { validator: validateEmail, message: 'Invalid support email' } },
    supportPhone: { type: String, trim: true, maxlength: 20 }
}, { _id: false });

const verificationSchema = new Schema({
    status: { type: String, enum: ['pending', 'verified', 'rejected', 'suspended'], default: 'pending', index: true },
    verifiedBy: { type: Schema.Types.ObjectId, ref: 'User' },
    verificationDate: { type: Date, validate: { validator: validateISODate, message: 'Invalid verification date format' } },
    verificationMethod: { type: String, enum: ['automatic', 'manual', 'third-party', 'blockchain', 'api', 'document'], default: 'manual' },
    verificationScore: { type: Number, min: 0, max: 100, default: 0 },
    trustLevel: { type: String, enum: ['unverified', 'basic', 'standard', 'premium', 'enterprise'], default: 'unverified', index: true },
    lastVerificationCheck: { type: Date, default: Date.now },
    verificationHistory: [{
        date: { type: Date, default: Date.now },
        status: { type: String, enum: ['verified', 'rejected', 'suspended'] },
        verifiedBy: { type: Schema.Types.ObjectId, ref: 'User' },
        reason: { type: String, maxlength: 500 },
        evidence: [{ type: String, validate: { validator: validateURL, message: 'Invalid evidence URL' } }]
    }],
    externalVerifications: [{
        provider: { type: String, enum: ['linkedin', 'credly', 'accredible', 'government', 'blockchain', 'other'], required: true },
        verificationId: { type: String, maxlength: 200 },
        verificationUrl: { type: String, validate: { validator: validateURL, message: 'Invalid verification URL' } },
        status: { type: String, enum: ['active', 'inactive', 'expired'] },
        lastChecked: { type: Date, default: Date.now }
    }],
    documents: [{
        type: { type: String, enum: ['registration', 'accreditation', 'certificate', 'license', 'other'] },
        url: { type: String, validate: { validator: validateURL, message: 'Invalid document URL' } },
        hash: { type: String, maxlength: 128 },
        uploadedAt: { type: Date, default: Date.now },
        verifiedAt: { type: Date },
        isPublic: { type: Boolean, default: false }
    }],
    apiValidation: {
        endpoint: { type: String, validate: { validator: validateURL, message: 'Invalid API endpoint' } },
        lastChecked: { type: Date },
        response: { type: Schema.Types.Mixed },
        isValid: { type: Boolean, default: false }
    }
}, { _id: false });

const complianceSchema = new Schema({
    regulatoryStandards: [{
        standard: { type: String, enum: ['ISO', 'GDPR', 'HIPAA', 'SOX', 'PCI-DSS', 'other'], required: true },
        complianceStatus: { type: String, enum: ['compliant', 'non-compliant', 'pending', 'exempt'], default: 'pending' },
        lastAudited: { type: Date },
        auditReport: { type: String, validate: { validator: validateURL, message: 'Invalid audit report URL' } }
    }],
    legalJurisdiction: { type: String, maxlength: 100, index: true },
    dataRetentionPolicy: {
        duration: { type: Number, min: 0, max: 50 },
        deletionDate: { type: Date },
        isPermanent: { type: Boolean, default: false }
    },
    exportControl: {
        isRestricted: { type: Boolean, default: false },
        restrictedCountries: [{ type: String, maxlength: 2 }],
        exportLicense: { type: String, maxlength: 100 }
    },
    taxId: { type: String, maxlength: 50, index: true },
    registrationNumber: { type: String, maxlength: 100, index: true }
}, { _id: false });

const analyticsSchema = new Schema({
    views: { type: Number, default: 0, min: 0, index: true },
    profileViews: { type: Number, default: 0, min: 0 },
    searchAppearances: { type: Number, default: 0, min: 0 },
    verificationRequests: { type: Number, default: 0, min: 0 },
    shareCount: { type: Number, default: 0, min: 0 },
    clickThroughRate: { type: Number, default: 0, min: 0 },
    engagementScore: { type: Number, default: 0, min: 0, index: true },
    popularityRank: { type: Number, default: 0 },
    trendingScore: { type: Number, default: 0, index: true },
    lastViewed: { type: Date },
    viewHistory: [{
        viewedAt: { type: Date, default: Date.now },
        viewerType: { type: String, enum: ['user', 'recruiter', 'organization', 'system', 'anonymous'] },
        viewerId: { type: Schema.Types.ObjectId, ref: 'User' },
        source: { type: String, enum: ['profile', 'search', 'direct', 'share', 'api'] },
        duration: { type: Number, min: 0 }
    }],
    weeklyStats: [{
        week: { type: Date },
        views: { type: Number, default: 0 },
        shares: { type: Number, default: 0 },
        verificationChecks: { type: Number, default: 0 }
    }],
    geographicData: [{
        country: { type: String, maxlength: 2 },
        views: { type: Number, default: 0 },
        lastActivity: { type: Date }
    }],
    certificationCount: { type: Number, default: 0, min: 0 },
    licenseCount: { type: Number, default: 0, min: 0 },
    badgeCount: { type: Number, default: 0, min: 0 }
}, { _id: false });

const socialSchema = new Schema({
    likes: [{
        userId: { type: Schema.Types.ObjectId, ref: 'User' },
        likedAt: { type: Date, default: Date.now }
    }],
    comments: [{
        userId: { type: Schema.Types.ObjectId, ref: 'User' },
        comment: { type: String, maxlength: 1000, set: v => v ? sanitizeHtml(v, { allowedTags: [], allowedAttributes: {} }) : v },
        commentedAt: { type: Date, default: Date.now },
        isPublic: { type: Boolean, default: true },
        replies: [{
            userId: { type: Schema.Types.ObjectId, ref: 'User' },
            reply: { type: String, maxlength: 500 },
            repliedAt: { type: Date, default: Date.now }
        }]
    }],
    shares: [{
        userId: { type: Schema.Types.ObjectId, ref: 'User' },
        platform: { type: String, enum: ['linkedin', 'twitter', 'facebook', 'email', 'internal', 'whatsapp', 'other'] },
        sharedAt: { type: Date, default: Date.now },
        audience: { type: String, enum: ['public', 'connections', 'followers', 'private'] }
    }],
    followers: [{ type: Schema.Types.ObjectId, ref: 'User' }],
    following: [{ type: Schema.Types.ObjectId, ref: 'Organization' }]
}, { _id: false });

const metadataSchema = new Schema({
    source: { type: String, default: 'manual', index: true },
    importSource: { type: String, enum: ['manual', 'linkedin', 'credly', 'api', 'bulk-upload', 'third-party'] },
    importId: { type: String, trim: true },
    externalId: { type: String, trim: true, index: true },
    lastUpdated: { type: Date, default: Date.now },
    updateCount: { type: Number, default: 0, min: 0 },
    version: { type: Number, default: 1, min: 1 },
    createdBy: { type: Schema.Types.ObjectId, ref: 'User' },
    lastModifiedBy: { type: Schema.Types.ObjectId, ref: 'User' },
    changeLog: [{
        timestamp: { type: Date, default: Date.now },
        changedBy: { type: Schema.Types.ObjectId, ref: 'User' },
        changes: { type: Schema.Types.Mixed },
        reason: { type: String, maxlength: 200 }
    }],
    syncStatus: { type: String, enum: ['synced', 'out-of-sync', 'sync-error', 'manual-override'], default: 'synced' },
    dataQuality: {
        completenessScore: { type: Number, min: 0, max: 100, default: 0 },
        accuracyScore: { type: Number, min: 0, max: 100, default: 0 },
        freshnessScore: { type: Number, min: 0, max: 100, default: 100 },
        overallQuality: { type: String, enum: ['poor', 'fair', 'good', 'excellent'], default: 'fair' }
    }
}, { _id: false });

const statusSchema = new Schema({
    isActive: { type: Boolean, default: true, index: true },
    isDeleted: { type: Boolean, default: false, index: true },
    isFeatured: { type: Boolean, default: false, index: true },
    isPromoted: { type: Boolean, default: false },
    isPinned: { type: Boolean, default: false },
    workflow: { type: String, enum: ['draft', 'pending-verification', 'verified', 'published', 'archived', 'suspended'], default: 'pending-verification', index: true },
    moderationStatus: { type: String, enum: ['approved', 'flagged', 'under-review', 'rejected'], default: 'approved' },
    qualityScore: { type: Number, min: 0, max: 100, default: 50 },
    flaggedReasons: [{ type: String, enum: ['inappropriate-content', 'false-information', 'spam', 'duplicate', 'other'] }],
    lastActiveAt: { type: Date, default: Date.now },
    archivedAt: { type: Date },
    deletedAt: { type: Date },
    featuredUntil: { type: Date },
    suspensionDetails: {
        suspendedAt: { type: Date },
        suspendedBy: { type: Schema.Types.ObjectId, ref: 'User' },
        reason: { type: String, maxlength: 500 },
        appealStatus: { type: String, enum: ['none', 'submitted', 'under-review', 'approved', 'rejected'] }
    }
}, { _id: false });

const blockchainSchema = new Schema({
    isOnBlockchain: { type: Boolean, default: false, index: true },
    network: { type: String, enum: ['ethereum', 'polygon', 'hyperledger', 'solana', 'custom'], default: 'ethereum' },
    contractAddress: { type: String, trim: true, maxlength: 42 },
    tokenId: { type: String, trim: true },
    transactionHash: { type: String, trim: true, maxlength: 66 },
    blockNumber: { type: Number, min: 0 },
    timestamp: { type: Date },
    gasUsed: { type: Number, min: 0 },
    metadata: { type: Schema.Types.Mixed },
    ipfsHash: { type: String, trim: true },
    nftStandard: { type: String, enum: ['ERC-721', 'ERC-1155', 'custom'] },
    verificationOnChain: { type: Boolean, default: false }
}, { _id: false });

const cacheSchema = new Schema({
    searchVector: { type: String, index: 'text' },
    popularityScore: { type: Number, default: 0, index: true },
    trendingScore: { type: Number, default: 0, index: true },
    verificationStrength: { type: Number, default: 0, index: true },
    marketRelevance: { type: Number, default: 0, index: true },
    cacheVersion: { type: Number, default: 1 },
    lastCacheUpdate: { type: Date, default: Date.now, index: true },
    precomputedStats: {
        totalCertifications: { type: Number, default: 0 },
        totalLicenses: { type: Number, default: 0 },
        totalBadges: { type: Number, default: 0 },
        verificationRate: { type: Number, default: 0 }
    }
}, { _id: false });

// Main Organization Schema
const organizationSchema = new Schema({
    _id: { type: Schema.Types.ObjectId, auto: true },
    name: { type: String, required: [true, 'Organization name is required'], trim: true, maxlength: 200, index: true, validate: { validator: validateOrgName, message: 'Invalid organization name format' } },
    description: { type: String, maxlength: 2000, trim: true, set: v => v ? sanitizeHtml(v, { allowedTags: ['p', 'br', 'strong', 'em', 'ul', 'ol', 'li'], allowedAttributes: {} }) : v },
    logo: { type: String, validate: { validator: validateURL, message: 'Invalid logo URL' } },
    industry: { type: String, enum: ['education', 'technology', 'healthcare', 'finance', 'government', 'non-profit', 'manufacturing', 'other'], required: true, index: true },
    type: { type: String, enum: ['company', 'university', 'government', 'non-profit', 'association', 'regulatory', 'other'], required: true, index: true },
    size: { type: String, enum: ['small', 'medium', 'large', 'enterprise'], default: 'medium', index: true },
    foundedYear: { type: Number, min: 1800, max: new Date().getFullYear() },
    contact: contactSchema,
    verification: verificationSchema,
    compliance: complianceSchema,
    analytics: analyticsSchema,
    social: socialSchema,
    metadata: metadataSchema,
    status: statusSchema,
    blockchain: blockchainSchema,
    cache: cacheSchema
}, {
    timestamps: true,
    collection: 'organizations',
    autoIndex: process.env.NODE_ENV !== 'production',
    readPreference: 'secondaryPreferred',
    writeConcern: { w: 'majority', wtimeout: 10000 },
    toJSON: {
        virtuals: true,
        transform: (doc, ret) => {
            delete ret.social.comments;
            delete ret.verification.documents;
            delete ret.__v;
            return ret;
        }
    },
    toObject: { virtuals: true },
    minimize: false,
    strict: 'throw',
    shardKey: { name: 1 }
});

// Indexes for Scalability
organizationSchema.index({ name: 1 }, { unique: true });
organizationSchema.index({ 'contact.email': 1 });
organizationSchema.index({ 'contact.country': 1, 'status.isActive': 1 });
organizationSchema.index({ 'verification.status': 1, 'status.isActive': 1 });
organizationSchema.index({ 'analytics.engagementScore': -1, updatedAt: -1 });
organizationSchema.index({
    name: 'text',
    description: 'text',
    'contact.city': 'text',
    'contact.country': 'text',
    'cache.searchVector': 'text'
}, {
    weights: { name: 10, description: 5, 'contact.city': 3, 'contact.country': 3, 'cache.searchVector': 1 },
    name: 'organization_text_search'
});
organizationSchema.index({ 'cache.popularityScore': -1, 'status.isActive': 1 }, { background: true });
organizationSchema.index({ 'cache.trendingScore': -1 }, { background: true });
organizationSchema.index({ 'status.deletedAt': 1 }, { expireAfterSeconds: 7776000, sparse: true }); // 90 days
organizationSchema.index({ 'compliance.legalJurisdiction': 1, 'status.isActive': 1 });
organizationSchema.index({ 'blockchain.isOnBlockchain': 1, 'blockchain.network': 1 });

// Virtuals
organizationSchema.virtual('isVerified').get(function () {
    return this.verification.status === 'verified';
});
organizationSchema.virtual('credentialCount').get(function () {
    return (this.analytics.certificationCount || 0) + (this.analytics.licenseCount || 0) + (this.analytics.badgeCount || 0);
});
organizationSchema.virtual('verificationLevel').get(function () {
    const score = this.verification.verificationScore;
    if (score >= 90) return 'platinum';
    if (score >= 75) return 'gold';
    if (score >= 60) return 'silver';
    if (score >= 40) return 'bronze';
    return 'unverified';
});
organizationSchema.virtual('engagementLevel').get(function () {
    const score = this.analytics.engagementScore;
    if (score >= 80) return 'viral';
    if (score >= 60) return 'high';
    if (score >= 40) return 'medium';
    if (score >= 20) return 'low';
    return 'minimal';
});

// Middleware
organizationSchema.pre('save', async function (next) {
    try {
        // Update metadata
        this.metadata.lastUpdated = new Date();
        this.metadata.updateCount += 1;
        this.metadata.version += 1;

        // Generate search vector
        this.cache.searchVector = [
            this.name,
            this.description,
            this.contact.city,
            this.contact.country
        ].filter(Boolean).join(' ').toLowerCase();

        // Calculate verification score
        if (this.verification.status === 'verified') {
            let score = 30;
            const methodScores = { 'document': 25, 'third-party': 20, 'api': 30, 'blockchain': 30, 'registration': 20, 'manual': 10 };
            score += methodScores[this.verification.verificationMethod] || 0;
            if (this.verification.documents?.length > 0) score += 15;
            if (this.verification.externalVerifications?.length > 0) score += 10;
            if (this.blockchain.isOnBlockchain) score += 15;
            this.verification.verificationScore = Math.min(score, 100);
        }

        // Calculate engagement and popularity scores
        let engagementScore = 0;
        engagementScore += (this.analytics.views || 0) * 0.1;
        engagementScore += (this.analytics.shareCount || 0) * 5;
        engagementScore += (this.social.comments?.length || 0) * 3;
        engagementScore += (this.social.followers?.length || 0) * 2;
        this.analytics.engagementScore = Math.min(engagementScore, 1000);

        this.cache.popularityScore = this.calculatePopularityScore();
        this.cache.trendingScore = (this.analytics.engagementScore * 0.4) + (this.verification.verificationScore * 0.3) + (this.social.followers?.length || 0) * 0.3;
        this.cache.verificationStrength = this.verification.verificationScore * 0.6 + (this.blockchain.isOnBlockchain ? 40 : 0);
        this.cache.marketRelevance = (this.industry === 'education' ? 90 : this.industry === 'healthcare' ? 85 : 70);

        // Update cache metadata
        this.cache.lastCacheUpdate = new Date();
        this.cache.cacheVersion += 1;
        this.cache.precomputedStats = {
            totalCertifications: this.analytics.certificationCount,
            totalLicenses: this.analytics.licenseCount,
            totalBadges: this.analytics.badgeCount,
            verificationRate: this.verification.verificationScore
        };

        // Cache in Redis with sharding
        const shardKey = this.name;
        await redisClient.setEx(`org:${shardKey}`, 300, JSON.stringify(this.toJSON()));

        // Publish updates
        await redisClient.publish('organization_updates', JSON.stringify({
            organizationId: this._id,
            shardKey,
            popularityScore: this.cache.popularityScore,
            trendingScore: this.cache.trendingScore
        }));

        // Compliance checks
        if (this.compliance.regulatoryStandards.length > 0) {
            this.compliance.regulatoryStandards.forEach(std => {
                if (!std.lastAudited || (new Date() - std.lastAudited) > 365 * 24 * 60 * 60 * 1000) {
                    std.complianceStatus = 'pending';
                }
            });
        }

        // Update status
        this.status.lastActiveAt = new Date();

        next();
    } catch (error) {
        next(new Error(`Pre-save middleware error: ${error.message}`));
    }
});

organizationSchema.pre('remove', async function (next) {
    try {
        this.status.isDeleted = true;
        this.status.deletedAt = new Date();
        const shardKey = this.name;
        await redisClient.del(`org:${shardKey}`);
        await this.save();
        next();
    } catch (error) {
        next(new Error(`Pre-remove middleware error: ${error.message}`));
    }
});

organizationSchema.post('save', async function (doc) {
    try {
        // Sync to Algolia
        if (doc.status.isActive) {
            try {
                await doc.syncToAlgolia();
            } catch (error) {
                console.error('Algolia sync error:', error.message);
            }
        }

        // Invalidate related caches
        await redisClient.del(`org:certs:${doc._id}`);
        await redisClient.del(`org:licenses:${doc._id}`);
        await redisClient.del(`org:badges:${doc._id}`);
    } catch (error) {
        console.error('Post-save middleware error:', error.message);
    }
});

// Instance Methods
organizationSchema.methods.calculatePopularityScore = function () {
    const weights = { views: 0.3, shares: 0.2, comments: 0.2, followers: 0.2, verified: 0.1, credentials: 0.2 };
    const viewScore = Math.log1p(this.analytics.views) / Math.log1p(10000);
    const shareScore = Math.log1p(this.analytics.shareCount) / Math.log1p(500);
    const commentScore = Math.log1p(this.social.comments?.length || 0) / Math.log1p(500);
    const followerScore = Math.log1p(this.social.followers?.length || 0) / Math.log1p(1000);
    const verifiedScore = this.verification.status === 'verified' ? 1 : 0;
    const credentialScore = Math.log1p(this.credentialCount) / Math.log1p(1000);
    return Math.min(100, (
        viewScore * weights.views +
        shareScore * weights.shares +
        commentScore * weights.comments +
        followerScore * weights.followers +
        verifiedScore * weights.verified +
        credentialScore * weights.credentials
    ) * 100);
};

organizationSchema.methods.calculateCompletionScore = function () {
    let score = 0;
    if (this.name) score += 20;
    if (this.description) score += 10;
    if (this.contact.email) score += 10;
    if (this.contact.website) score += 10;
    if (this.verification.status === 'verified') score += 20;
    if (this.compliance.regulatoryStandards.length > 0) score += 10;
    if (this.analytics.certificationCount > 0 || this.analytics.licenseCount > 0 || this.analytics.badgeCount > 0) score += 20;
    return score;
};

// Static Methods
organizationSchema.statics.getOrganizations = async function (options = {}) {
    const { page = 1, limit = 10, sortBy = 'name', sortOrder = 1, includeDeleted = false, filters = {} } = options;
    const cacheKey = `orgs:${JSON.stringify(options)}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const baseQuery = { 'status.isActive': true };
    if (!includeDeleted) baseQuery['status.isDeleted'] = false;
    Object.entries(filters).forEach(([key, value]) => { if (value !== undefined && value !== null && value !== '') baseQuery[key] = value; });

    const results = await this.find(baseQuery)
        .sort({ [sortBy]: sortOrder })
        .skip((page - 1) * limit)
        .limit(limit)
        .select('-social.comments -verification.documents')
        .lean({ virtuals: true });

    await redisClient.setEx(cacheKey, 3600, JSON.stringify(results));
    return results;
};

organizationSchema.statics.advancedSearch = async function (searchOptions = {}) {
    const { query = '', industry, country, verificationStatus, page = 1, limit = 20, sortBy = 'relevance' } = searchOptions;
    const cacheKey = `search:orgs:${JSON.stringify(searchOptions)}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const pipeline = [
        {
            $match: {
                'status.isActive': true,
                'status.isDeleted': false,
                'status.workflow': 'verified',
                ...(verificationStatus && { 'verification.status': verificationStatus }),
                ...(industry && { industry }),
                ...(country && { 'contact.country': country })
            }
        },
        ...(query ? [{ $match: { $text: { $search: query, $caseSensitive: false } } }, { $addFields: { textScore: { $meta: 'textScore' } } }] : []),
        {
            $addFields: {
                relevanceScore: {
                    $add: [
                        { $multiply: [{ $ifNull: ['$textScore', 0] }, 0.4] },
                        { $multiply: [{ $divide: ['$verification.verificationScore', 100] }, 0.3] },
                        { $multiply: [{ $divide: [{ $min: ['$analytics.engagementScore', 100] }, 100] }, 0.2] },
                        { $multiply: [{ $divide: [{ $sum: ['$analytics.certificationCount', '$analytics.licenseCount', '$analytics.badgeCount'] }, 1000] }, 0.1] }
                    ]
                }
            }
        },
        { $sort: this.getSortQuery(sortBy) },
        {
            $project: {
                name: 1,
                description: 1,
                industry: 1,
                type: 1,
                contact: { email: 1, website: 1, country: 1 },
                verification: { status: 1, verificationScore: 1 },
                analytics: { certificationCount: 1, licenseCount: 1, badgeCount: 1, engagementScore: 1 },
                relevanceScore: 1,
                createdAt: 1,
                updatedAt: 1
            }
        }
    ];

    const results = await this.aggregatePaginate(pipeline, { page, limit, customLabels: { totalDocs: 'totalResults', docs: 'organizations' } });
    await redisClient.setEx(cacheKey, 60, JSON.stringify(results));
    return results;
};

organizationSchema.statics.getSortQuery = function (sortBy) {
    const sortQueries = {
        'relevance': { relevanceScore: -1, 'verification.verificationScore': -1 },
        'name': { name: 1 },
        'popular': { 'cache.popularityScore': -1, 'analytics.views': -1 },
        'verified': { 'verification.verificationScore': -1, 'verification.status': -1 },
        'credentialCount': { 'analytics.certificationCount': -1, 'analytics.licenseCount': -1 }
    };
    return sortQueries[sortBy] || sortQueries['relevance'];
};

// Plugins
organizationSchema.plugin(aggregatePaginate);
if (process.env.ALGOLIA_APP_ID && process.env.ALGOLIA_ADMIN_KEY) {
    organizationSchema.plugin(mongooseAlgolia, {
        appId: process.env.ALGOLIA_APP_ID,
        apiKey: process.env.ALGOLIA_ADMIN_KEY,
        indexName: 'organizations',
        selector: 'name description contact.city contact.country cache.searchVector',
        defaults: { author: 'unknown' },
        mappings: {
            name: v => v || '',
            description: v => v || '',
            'contact.city': v => v || '',
            'contact.country': v => v || '',
            'cache.searchVector': v => v || ''
        },
        debug: process.env.NODE_ENV === 'development'
    });
} else {
    console.warn('Algolia plugin not initialized: Missing ALGOLIA_APP_ID or ALGOLIA_ADMIN_KEY');
}

// Production Optimizations
if (process.env.NODE_ENV === 'production') {
    organizationSchema.index({ 'cache.popularityScore': -1, 'status.isActive': 1 }, { background: true });
    organizationSchema.index({ 'cache.trendingScore': -1 }, { background: true });
    organizationSchema.index({ 'blockchain.transactionHash': 1 }, { sparse: true });
}

export default mongoose.model('Organization', organizationSchema);