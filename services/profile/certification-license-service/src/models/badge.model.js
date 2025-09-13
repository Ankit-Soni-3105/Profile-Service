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
const validateBadgeId = (value) => /^[A-Z0-9\-_]{6,50}$/.test(value);
const validateISODate = (value) => !value || validator.isISO8601(value.toString());
const validateBadgeName = (value) => /^[a-zA-Z0-9\s\-&():]+$/.test(value);
const validateHexColor = (value) => !value || /^#[0-9A-Fa-f]{6}$/.test(value);

// Sub-Schemas
const organizationSchema = new Schema({
    organizationId: { type: Schema.Types.ObjectId, ref: 'Organization', required: true, index: true },
    name: { type: String, required: true, maxlength: 200, index: true },
    logo: { type: String, validate: { validator: validateURL, message: 'Invalid organization logo URL' } },
    website: { type: String, validate: { validator: validateURL, message: 'Invalid organization website URL' } },
    accreditationLevel: { type: String, enum: ['unaccredited', 'regional', 'national', 'international', 'government'], default: 'unaccredited', index: true },
    trustScore: { type: Number, min: 0, max: 100, default: 50 },
    isVerified: { type: Boolean, default: false, index: true },
    verificationDate: { type: Date },
    contact: {
        email: { type: String, validate: { validator: validateEmail, message: 'Invalid contact email' } },
        phone: { type: String, trim: true, maxlength: 20 },
        address: { type: String, maxlength: 500 }
    }
}, { _id: false });

const badgeDetailsSchema = new Schema({
    title: { type: String, required: [true, 'Badge title is required'], trim: true, maxlength: 300, index: true, validate: { validator: validateBadgeName, message: 'Invalid badge title format' } },
    description: { type: String, maxlength: 2000, trim: true, set: v => v ? sanitizeHtml(v, { allowedTags: ['p', 'br', 'strong', 'em', 'ul', 'ol', 'li'], allowedAttributes: {} }) : v },
    category: { type: String, enum: ['achievement', 'skill', 'event', 'recognition', 'milestone', 'certification', 'other'], required: true, index: true },
    subcategory: { type: String, trim: true, maxlength: 100, index: true },
    level: { type: String, enum: ['beginner', 'intermediate', 'advanced', 'expert'], default: 'beginner', index: true },
    field: { type: String, trim: true, maxlength: 100, index: true },
    specialization: { type: String, trim: true, maxlength: 150 },
    prerequisites: [{ type: String, maxlength: 200 }],
    scope: { type: String, enum: ['local', 'regional', 'national', 'international'], default: 'local' },
    language: { type: String, trim: true, maxlength: 10, default: 'en' },
    design: {
        icon: { type: String, validate: { validator: validateURL, message: 'Invalid icon URL' } },
        color: { type: String, validate: { validator: validateHexColor, message: 'Invalid color format' } },
        shape: { type: String, enum: ['circle', 'square', 'shield', 'star', 'custom'], default: 'circle' },
        badgeUrl: { type: String, validate: { validator: validateURL, message: 'Invalid badge URL' } }
    },
    gamification: {
        points: { type: Number, min: 0, default: 0 },
        tier: { type: String, enum: ['bronze', 'silver', 'gold', 'platinum', 'diamond'], default: 'bronze' },
        progress: { type: Number, min: 0, max: 100, default: 0 },
        milestones: [{
            name: { type: String, maxlength: 100 },
            pointsRequired: { type: Number, min: 0 },
            achievedAt: { type: Date }
        }]
    }
}, { _id: false });

const credentialSchema = new Schema({
    badgeId: { type: String, required: [true, 'Badge ID is required'], unique: true, validate: { validator: validateBadgeId, message: 'Invalid badge ID format' }, index: true },
    documentUrl: { type: String, validate: { validator: validateURL, message: 'Invalid document URL' } },
    digitalBadgeUrl: { type: String, validate: { validator: validateURL, message: 'Invalid digital badge URL' } },
    blockchainHash: { type: String, trim: true, maxlength: 128 },
    qrCode: { type: String },
    serialNumber: { type: String, trim: true, maxlength: 100 },
    issueLocation: { type: String, trim: true, maxlength: 100 },
    format: { type: String, enum: ['digital', 'physical', 'hybrid'], default: 'digital' },
    templateVersion: { type: String, trim: true, maxlength: 20 }
}, { _id: false });

const durationSchema = new Schema({
    issueDate: { type: Date, required: [true, 'Issue date is required'], index: true, validate: { validator: validateISODate, message: 'Invalid issue date format' } },
    expirationDate: { type: Date, index: true, validate: { validator: validateISODate, message: 'Invalid expiration date format' } },
    validityPeriod: { type: Number, min: 0, max: 100 },
    isLifetime: { type: Boolean, default: false, index: true },
    gracePeriod: { type: Number, default: 30, min: 0, max: 365 },
    renewalRequired: { type: Boolean, default: false },
    maintenanceRequired: { type: Boolean, default: false },
    ceuRequired: { type: Number, default: 0, min: 0 },
    warningDate: { type: Date, index: true },
    isExpired: { type: Boolean, default: false, index: true },
    daysUntilExpiration: { type: Number }
}, { _id: false });

const verificationSchema = new Schema({
    status: { type: String, enum: ['pending', 'verified', 'rejected', 'expired', 'revoked', 'suspended'], default: 'pending', index: true },
    verifiedBy: { type: Schema.Types.ObjectId, ref: 'User' },
    verificationDate: { type: Date },
    verificationMethod: { type: String, enum: ['automatic', 'manual', 'third-party', 'blockchain', 'api', 'document'], default: 'automatic' },
    verificationScore: { type: Number, min: 0, max: 100, default: 0 },
    trustLevel: { type: String, enum: ['unverified', 'basic', 'standard', 'premium', 'enterprise'], default: 'unverified', index: true },
    lastVerificationCheck: { type: Date, default: Date.now },
    verificationHistory: [{
        date: { type: Date, default: Date.now },
        status: { type: String, enum: ['verified', 'rejected', 'expired', 'revoked', 'suspended'] },
        verifiedBy: { type: Schema.Types.ObjectId, ref: 'User' },
        reason: { type: String, maxlength: 500 },
        evidence: [{ type: String, validate: { validator: validateURL, message: 'Invalid evidence URL' } }]
    }],
    externalVerifications: [{
        provider: { type: String, enum: ['linkedin', 'credly', 'accredible', 'badgelist', 'blockchain', 'other'], required: true },
        verificationId: { type: String, maxlength: 200 },
        verificationUrl: { type: String, validate: { validator: validateURL, message: 'Invalid verification URL' } },
        status: { type: String, enum: ['active', 'inactive', 'expired'] },
        lastChecked: { type: Date, default: Date.now }
    }],
    documents: [{
        type: { type: String, enum: ['badge', 'certificate', 'transcript', 'evidence', 'other'] },
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
    }
}, { _id: false });

const analyticsSchema = new Schema({
    views: { type: Number, default: 0, min: 0, index: true },
    profileViews: { type: Number, default: 0, min: 0 },
    searchAppearances: { type: Number, default: 0, min: 0 },
    verificationRequests: { type: Number, default: 0, min: 0 },
    shareCount: { type: Number, default: 0, min: 0 },
    downloadCount: { type: Number, default: 0, min: 0 },
    linkedProfiles: { type: Number, default: 0, min: 0 },
    endorsementCount: { type: Number, default: 0, min: 0 },
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
    engagementMetrics: {
        likes: { type: Number, default: 0, min: 0 },
        comments: { type: Number, default: 0, min: 0 },
        shares: { type: Number, default: 0, min: 0 },
        endorsements: [{
            userId: { type: Schema.Types.ObjectId, ref: 'User' },
            endorsedAt: { type: Date, default: Date.now },
            comment: { type: String, maxlength: 500 }
        }]
    }
}, { _id: false });

const renewalSchema = new Schema({
    isEligible: { type: Boolean, default: true },
    renewalDate: { type: Date, index: true },
    applicationDeadline: { type: Date },
    status: { type: String, enum: ['not-started', 'in-progress', 'submitted', 'approved', 'rejected', 'expired'], default: 'not-started', index: true },
    renewalHistory: [{
        renewalDate: { type: Date },
        status: { type: String, enum: ['approved', 'rejected', 'expired'] },
        fee: { amount: { type: Number, min: 0 }, currency: { type: String, maxlength: 3, default: 'USD' } },
        ceuCompleted: { type: Number, min: 0 },
        notes: { type: String, maxlength: 1000 }
    }],
    requirements: {
        ceuNeeded: { type: Number, min: 0 },
        ceuCompleted: { type: Number, min: 0 },
        activitiesCompleted: [{
            type: { type: String, enum: ['course', 'conference', 'workshop', 'project', 'volunteering', 'other'] },
            title: { type: String, maxlength: 200 },
            provider: { type: String, maxlength: 150 },
            completionDate: { type: Date },
            ceuValue: { type: Number, min: 0 },
            certificate: { type: String, validate: { validator: validateURL } }
        }],
        paymentStatus: { type: String, enum: ['pending', 'paid', 'failed', 'refunded'], default: 'pending' },
        paymentDate: { type: Date }
    },
    reminders: [{
        type: { type: String, enum: ['90-days', '60-days', '30-days', '7-days', 'expired'] },
        sentAt: { type: Date },
        status: { type: String, enum: ['sent', 'opened', 'clicked', 'ignored'] }
    }],
    autoRenewal: {
        enabled: { type: Boolean, default: false },
        paymentMethod: { type: String, enum: ['credit-card', 'bank-transfer', 'paypal', 'other'] },
        billingAddress: { type: String, maxlength: 500 }
    }
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
    endorsements: [{
        userId: { type: Schema.Types.ObjectId, ref: 'User' },
        endorsedAt: { type: Date, default: Date.now },
        comment: { type: String, maxlength: 500 }
    }]
}, { _id: false });

const metadataSchema = new Schema({
    source: { type: String, default: 'manual', index: true },
    importSource: { type: String, enum: ['manual', 'linkedin', 'credly', 'accredible', 'api', 'bulk-upload', 'third-party'] },
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
    flaggedReasons: [{ type: String, enum: ['inappropriate-content', 'false-information', 'spam', 'duplicate', 'expired', 'other'] }],
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
    royaltyInfo: {
        percentage: { type: Number, min: 0, max: 100 },
        recipient: { type: String, trim: true, maxlength: 42 }
    },
    transferHistory: [{
        from: { type: String, trim: true, maxlength: 42 },
        to: { type: String, trim: true, maxlength: 42 },
        transactionHash: { type: String, trim: true, maxlength: 66 },
        timestamp: { type: Date },
        gasPrice: { type: String, trim: true }
    }],
    smartContractEvents: [{ type: Schema.Types.Mixed }],
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
        totalEndorsements: { type: Number, default: 0 },
        avgRating: { type: Number, default: 0 },
        verificationRate: { type: Number, default: 0 },
        completionScore: { type: Number, default: 0 }
    }
}, { _id: false });

const gamificationSchema = new Schema({
    pointsEarned: { type: Number, default: 0, min: 0 },
    level: { type: Number, default: 1, min: 1 },
    achievements: [{
        achievementId: { type: String, maxlength: 100 },
        title: { type: String, maxlength: 200 },
        description: { type: String, maxlength: 500 },
        earnedAt: { type: Date, default: Date.now },
        points: { type: Number, min: 0 }
    }],
    progress: {
        current: { type: Number, min: 0, default: 0 },
        nextLevel: { type: Number, min: 0 },
        percentage: { type: Number, min: 0, max: 100 }
    },
    leaderboardRank: { type: Number, default: 0, index: true },
    badgesEarned: { type: Number, default: 0 },
    streak: {
        current: { type: Number, default: 0, min: 0 },
        longest: { type: Number, default: 0, min: 0 },
        lastActive: { type: Date }
    }
}, { _id: false });

// Main Badge Schema
const badgeSchema = new Schema({
    _id: { type: Schema.Types.ObjectId, auto: true },
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: [true, 'User ID is required'], index: true },
    organization: organizationSchema,
    badgeDetails: badgeDetailsSchema,
    credential: credentialSchema,
    duration: durationSchema,
    verification: verificationSchema,
    compliance: complianceSchema,
    analytics: analyticsSchema,
    renewal: renewalSchema,
    social: socialSchema,
    metadata: metadataSchema,
    status: statusSchema,
    blockchain: blockchainSchema,
    cache: cacheSchema,
    gamification: gamificationSchema
}, {
    timestamps: true,
    collection: 'badges',
    autoIndex: process.env.NODE_ENV !== 'production',
    readPreference: 'secondaryPreferred',
    writeConcern: { w: 'majority', wtimeout: 10000 },
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
    strict: 'throw',
    shardKey: { userId: 1, 'credential.badgeId': 1 }
});

// Indexes for Scalability
badgeSchema.index({ userId: 1, 'duration.issueDate': -1, 'status.isActive': 1 });
badgeSchema.index({ 'credential.badgeId': 1 }, { unique: true });
badgeSchema.index({ 'badgeDetails.title': 1, 'organization.organizationId': 1, 'status.isActive': 1 });
badgeSchema.index({ 'verification.status': 1 });
badgeSchema.index({ 'status.isPublic': 1, 'status.isActive': 1, 'analytics.engagementScore': -1, updatedAt: -1 });
badgeSchema.index({ 'duration.isLifetime': 1, 'duration.expirationDate': 1 });
badgeSchema.index({ 'status.workflow': 1, 'renewal.status': 1 });
badgeSchema.index({
    'badgeDetails.title': 'text',
    'badgeDetails.description': 'text',
    'organization.name': 'text',
    'cache.searchVector': 'text'
}, {
    weights: { 'badgeDetails.title': 10, 'organization.name': 6, 'badgeDetails.description': 4, 'cache.searchVector': 1 },
    name: 'badge_text_search'
});
badgeSchema.index({ 'cache.popularityScore': -1, 'status.isActive': 1 }, { background: true });
badgeSchema.index({ 'cache.trendingScore': -1 }, { background: true });
badgeSchema.index({ 'status.deletedAt': 1 }, { expireAfterSeconds: 7776000, sparse: true }); // 90 days
badgeSchema.index({ 'compliance.legalJurisdiction': 1, 'status.isActive': 1 });
badgeSchema.index({ 'blockchain.isOnBlockchain': 1, 'blockchain.network': 1 });
badgeSchema.index({ 'gamification.leaderboardRank': -1, 'status.isActive': 1 });
badgeSchema.index({ 'badgeDetails.category': 1, 'badgeDetails.level': 1 });

// Virtuals
badgeSchema.virtual('isExpired').get(function () {
    if (this.duration.isLifetime) return false;
    return this.duration.expirationDate && this.duration.expirationDate < new Date();
});
badgeSchema.virtual('daysUntilExpiry').get(function () {
    if (this.duration.isLifetime || !this.duration.expirationDate) return null;
    return Math.ceil((this.duration.expirationDate - new Date()) / (1000 * 60 * 60 * 24));
});
badgeSchema.virtual('verificationLevel').get(function () {
    const score = this.verification.verificationScore;
    if (score >= 90) return 'platinum';
    if (score >= 75) return 'gold';
    if (score >= 60) return 'silver';
    if (score >= 40) return 'bronze';
    return 'unverified';
});
badgeSchema.virtual('engagementLevel').get(function () {
    const score = this.analytics.engagementScore;
    if (score >= 80) return 'viral';
    if (score >= 60) return 'high';
    if (score >= 40) return 'medium';
    if (score >= 20) return 'low';
    return 'minimal';
});
badgeSchema.virtual('gamificationLevel').get(function () {
    const points = this.gamification.pointsEarned;
    if (points >= 1000) return 'master';
    if (points >= 500) return 'expert';
    if (points >= 200) return 'pro';
    if (points >= 50) return 'beginner';
    return 'novice';
});

// Middleware
badgeSchema.pre('save', async function (next) {
    try {
        // Auto-set duration fields
        if (this.duration.isLifetime) {
            this.duration.isExpired = false;
            this.duration.renewalRequired = false;
        } else if (this.duration.expirationDate && this.duration.expirationDate < new Date()) {
            this.duration.isExpired = true;
            this.renewal.status = 'expired';
        } else if (this.renewal.renewalDate && this.renewal.renewalDate < new Date()) {
            this.renewal.status = 'in-progress';
        }
        this.duration.daysUntilExpiration = this.daysUntilExpiry;

        // Update metadata
        this.metadata.lastUpdated = new Date();
        this.metadata.updateCount += 1;
        this.metadata.version += 1;

        // Generate search vector
        this.cache.searchVector = [
            this.badgeDetails.title,
            this.badgeDetails.description,
            this.organization.name
        ].filter(Boolean).join(' ').toLowerCase();

        // Calculate verification score
        if (this.verification.status === 'verified') {
            let score = 30;
            const methodScores = { 'document': 25, 'third-party': 20, 'api': 30, 'blockchain': 30, 'certificate': 20, 'manual': 10 };
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
        engagementScore += (this.analytics.downloadCount || 0) * 2;
        engagementScore += (this.social.likes?.length || 0) * 3;
        engagementScore += (this.social.comments?.length || 0) * 4;
        engagementScore += (this.gamification.pointsEarned || 0) * 0.05;
        this.analytics.engagementScore = Math.min(engagementScore, 1000);

        this.cache.popularityScore = this.calculatePopularityScore();
        this.cache.trendingScore = (this.analytics.engagementScore * 0.5) + (this.verification.verificationScore * 0.3) + (this.gamification.pointsEarned * 0.2);
        this.cache.verificationStrength = this.verification.verificationScore * 0.6 + (this.blockchain.isOnBlockchain ? 40 : 0);
        this.cache.marketRelevance = (this.badgeDetails.category === 'achievement' ? 90 : this.badgeDetails.category === 'skill' ? 85 : 70);

        // Update cache metadata
        this.cache.lastCacheUpdate = new Date();
        this.cache.cacheVersion += 1;
        this.cache.precomputedStats = {
            totalEndorsements: this.analytics.engagementMetrics.endorsements?.length || 0,
            avgRating: this.calculateAvgRating(),
            verificationRate: this.verification.verificationScore,
            completionScore: this.calculateCompletionScore()
        };

        // Update gamification
        this.gamification.badgesEarned = (this.gamification.achievements?.length || 0) + 1;
        this.gamification.progress.percentage = this.calculateProgressPercentage();
        if (this.gamification.streak.lastActive && (new Date() - this.gamification.streak.lastActive) < 24 * 60 * 60 * 1000) {
            this.gamification.streak.current += 1;
            this.gamification.streak.longest = Math.max(this.gamification.streak.current, this.gamification.streak.longest);
        } else {
            this.gamification.streak.current = 1;
        }
        this.gamification.streak.lastActive = new Date();

        // Cache in Redis with sharding
        const shardKey = `${this.userId}_${this.credential.badgeId}`;
        await redisClient.setEx(`badge:${shardKey}`, 300, JSON.stringify(this.toJSON()));

        // Publish updates
        await redisClient.publish('badge_updates', JSON.stringify({
            badgeId: this._id,
            shardKey,
            popularityScore: this.cache.popularityScore,
            trendingScore: this.cache.trendingScore,
            gamificationScore: this.gamification.pointsEarned
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

badgeSchema.pre('remove', async function (next) {
    try {
        this.status.isDeleted = true;
        this.status.deletedAt = new Date();
        const shardKey = `${this.userId}_${this.credential.badgeId}`;
        await redisClient.del(`badge:${shardKey}`);
        await this.save();
        next();
    } catch (error) {
        next(new Error(`Pre-remove middleware error: ${error.message}`));
    }
});

badgeSchema.post('save', async function (doc) {
    try {
        // Update User profile
        const User = mongoose.model('User');
        await User.updateOne(
            { _id: doc.userId },
            { $set: { 'profile.lastUpdated': new Date() }, $inc: { 'analytics.profileUpdates': 1, 'gamification.badgesEarned': 1 } }
        );

        // Update Organization stats
        if (doc.organization.organizationId) {
            const Organization = mongoose.model('Organization');
            await Organization.updateOne(
                { _id: doc.organization.organizationId },
                { $inc: { 'analytics.badgeCount': 1 }, $set: { 'analytics.lastCalculated': new Date() } }
            );
        }

        // Sync to Algolia
        if (doc.status.isActive) {
            try {
                await doc.syncToAlgolia();
            } catch (error) {
                console.error('Algolia sync error:', error.message);
            }
        }

        // Invalidate related caches
        await redisClient.del(`user:badges:${doc.userId}`);
        await redisClient.del(`org:badges:${doc.organization.organizationId}`);
    } catch (error) {
        console.error('Post-save middleware error:', error.message);
    }
});

// Instance Methods
badgeSchema.methods.calculatePopularityScore = function () {
    const weights = { views: 0.3, shares: 0.2, downloads: 0.2, likes: 0.1, comments: 0.1, verified: 0.1, points: 0.1 };
    const viewScore = Math.log1p(this.analytics.views) / Math.log1p(10000);
    const shareScore = Math.log1p(this.analytics.shareCount) / Math.log1p(500);
    const downloadScore = Math.log1p(this.analytics.downloadCount) / Math.log1p(500);
    const likeScore = Math.log1p(this.social.likes?.length || 0) / Math.log1p(500);
    const commentScore = Math.log1p(this.social.comments?.length || 0) / Math.log1p(500);
    const verifiedScore = this.verification.status === 'verified' ? 1 : 0;
    const pointsScore = Math.log1p(this.gamification.pointsEarned) / Math.log1p(1000);
    return Math.min(100, (
        viewScore * weights.views +
        shareScore * weights.shares +
        downloadScore * weights.downloads +
        likeScore * weights.likes +
        commentScore * weights.comments +
        verifiedScore * weights.verified +
        pointsScore * weights.points
    ) * 100);
};

badgeSchema.methods.calculateCompletionScore = function () {
    let score = 0;
    if (this.badgeDetails.title) score += 20;
    if (this.badgeDetails.description) score += 10;
    if (this.verification.status === 'verified') score += 20;
    if (this.credential.documentUrl) score += 10;
    if (this.blockchain.isOnBlockchain) score += 10;
    if (this.compliance.regulatoryStandards.length > 0) score += 10;
    if (this.gamification.pointsEarned > 0) score += 20;
    return score;
};

badgeSchema.methods.calculateAvgRating = function () {
    const endorsements = this.analytics.engagementMetrics.endorsements || [];
    if (endorsements.length === 0) return 0;
    const totalRating = endorsements.reduce((sum, e) => sum + (e.rating || 0), 0);
    return totalRating / endorsements.length;
};

badgeSchema.methods.calculateProgressPercentage = function () {
    if (!this.gamification.progress.nextLevel) return 0;
    return Math.min(100, (this.gamification.progress.current / this.gamification.progress.nextLevel) * 100);
};

// Static Methods
badgeSchema.statics.getUserBadges = async function (userId, options = {}) {
    const { page = 1, limit = 10, sortBy = 'issueDate', sortOrder = -1, includeDeleted = false, filters = {} } = options;
    const cacheKey = `user:badges:${userId}:${JSON.stringify(options)}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const baseQuery = { userId: new mongoose.Types.ObjectId(userId), 'status.isActive': true };
    if (!includeDeleted) baseQuery['status.isDeleted'] = false;
    Object.entries(filters).forEach(([key, value]) => { if (value !== undefined && value !== null && value !== '') baseQuery[key] = value; });

    const results = await this.find(baseQuery)
        .sort({ [`duration.${sortBy}`]: sortOrder })
        .skip((page - 1) * limit)
        .limit(limit)
        .populate({ path: 'organization.organizationId', select: 'name logo industry verification.isVerified' })
        .select('-verification.documents -social.comments')
        .lean({ virtuals: true });

    await redisClient.setEx(cacheKey, 3600, JSON.stringify(results));
    return results;
};

badgeSchema.statics.advancedSearch = async function (searchOptions = {}) {
    const { query = '', issuer = {}, category, verificationStatus, page = 1, limit = 20, sortBy = 'relevance' } = searchOptions;
    const cacheKey = `search:badges:${JSON.stringify(searchOptions)}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const pipeline = [
        {
            $match: {
                'status.isActive': true,
                'status.isDeleted': false,
                'status.workflow': 'verified',
                ...(verificationStatus && { 'verification.status': verificationStatus }),
                ...(issuer.name && { 'organization.name': new RegExp(issuer.name, 'i') }),
                ...(issuer.organizationId && { 'organization.organizationId': new mongoose.Types.ObjectId(issuer.organizationId) }),
                ...(category && { 'badgeDetails.category': category })
            }
        },
        ...(query ? [{ $match: { $text: { $search: query, $caseSensitive: false } } }, { $addFields: { textScore: { $meta: 'textScore' } } }] : []),
        { $lookup: { from: 'organizations', localField: 'organization.organizationId', foreignField: '_id', as: 'organization', pipeline: [{ $project: { name: 1, logo: 1, industry: 1, verification: 1 } }] } },
        { $unwind: { path: '$organization', preserveNullAndEmptyArrays: true } },
        {
            $addFields: {
                relevanceScore: {
                    $add: [
                        { $multiply: [{ $ifNull: ['$textScore', 0] }, 0.4] },
                        { $multiply: [{ $divide: ['$verification.verificationScore', 100] }, 0.3] },
                        { $multiply: [{ $divide: [{ $min: ['$analytics.engagementScore', 100] }, 100] }, 0.2] },
                        { $multiply: [{ $cond: ['$organization.verification.isVerified', 1, 0] }, 0.1] },
                        { $multiply: [{ $divide: ['$gamification.pointsEarned', 1000] }, 0.1] }
                    ]
                }
            }
        },
        { $sort: this.getSortQuery(sortBy) },
        {
            $project: {
                userId: 1,
                badgeDetails: { title: 1, category: 1, level: 1, design: 1 },
                credential: { badgeId: 1, digitalBadgeUrl: 1 },
                organization: 1,
                duration: { issueDate: 1, expirationDate: 1, isLifetime: 1 },
                verification: { status: 1, verificationScore: 1 },
                compliance: { regulatoryStandards: 1 },
                gamification: { pointsEarned: 1, level: 1, leaderboardRank: 1 },
                relevanceScore: 1,
                createdAt: 1,
                updatedAt: 1
            }
        }
    ];

    const results = await this.aggregatePaginate(pipeline, { page, limit, customLabels: { totalDocs: 'totalResults', docs: 'badges' } });
    await redisClient.setEx(cacheKey, 60, JSON.stringify(results));
    return results;
};

badgeSchema.statics.getSortQuery = function (sortBy) {
    const sortQueries = {
        'relevance': { relevanceScore: -1, 'verification.verificationScore': -1 },
        'recent': { 'duration.issueDate': -1, updatedAt: -1 },
        'popular': { 'cache.popularityScore': -1, 'analytics.views': -1 },
        'verified': { 'verification.verificationScore': -1, 'verification.status': -1 },
        'points': { 'gamification.pointsEarned': -1, 'gamification.leaderboardRank': -1 },
        'alphabetical': { 'badgeDetails.title': 1, 'organization.name': 1 }
    };
    return sortQueries[sortBy] || sortQueries['relevance'];
};

badgeSchema.statics.getLeaderboard = async function (options = {}) {
    const { page = 1, limit = 50, category, minPoints = 0 } = options;
    const cacheKey = `leaderboard:badges:${JSON.stringify(options)}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const pipeline = [
        {
            $match: {
                'status.isActive': true,
                'status.isDeleted': false,
                'status.workflow': 'verified',
                'gamification.pointsEarned': { $gte: minPoints },
                ...(category && { 'badgeDetails.category': category })
            }
        },
        {
            $lookup: {
                from: 'users',
                localField: 'userId',
                foreignField: '_id',
                as: 'user',
                pipeline: [{ $project: { firstName: 1, lastName: 1, profilePicture: 1 } }]
            }
        },
        { $unwind: { path: '$user', preserveNullAndEmptyArrays: true } },
        {
            $project: {
                userId: 1,
                user: { firstName: 1, lastName: 1, profilePicture: 1 },
                badgeDetails: { title: 1, category: 1, level: 1 },
                gamification: { pointsEarned: 1, level: 1, leaderboardRank: 1 },
                createdAt: 1
            }
        },
        { $sort: { 'gamification.pointsEarned': -1, 'gamification.leaderboardRank': -1 } },
        { $skip: (page - 1) * limit },
        { $limit: limit }
    ];

    const results = await this.aggregate(pipeline);
    await redisClient.setEx(cacheKey, 3600, JSON.stringify(results));
    return results;
};

// Plugins
badgeSchema.plugin(aggregatePaginate);
if (process.env.ALGOLIA_APP_ID && process.env.ALGOLIA_ADMIN_KEY) {
    badgeSchema.plugin(mongooseAlgolia, {
        appId: process.env.ALGOLIA_APP_ID,
        apiKey: process.env.ALGOLIA_ADMIN_KEY,
        indexName: 'badges',
        selector: 'badgeDetails.title badgeDetails.description organization.name cache.searchVector',
        defaults: { author: 'unknown' },
        mappings: {
            'badgeDetails.title': v => v || '',
            'badgeDetails.description': v => v || '',
            'organization.name': v => v || '',
            'cache.searchVector': v => v || ''
        },
        debug: process.env.NODE_ENV === 'development'
    });
} else {
    console.warn('Algolia plugin not initialized: Missing ALGOLIA_APP_ID or ALGOLIA_ADMIN_KEY');
}

// Production Optimizations
if (process.env.NODE_ENV === 'production') {
    badgeSchema.index({ 'cache.popularityScore': -1, 'status.isActive': 1 }, { background: true });
    badgeSchema.index({ 'cache.trendingScore': -1 }, { background: true });
    badgeSchema.index({ 'blockchain.transactionHash': 1 }, { sparse: true });
    badgeSchema.index({ 'gamification.pointsEarned': -1, 'status.isActive': 1 }, { background: true });
}

export default mongoose.model('Badge', badgeSchema);