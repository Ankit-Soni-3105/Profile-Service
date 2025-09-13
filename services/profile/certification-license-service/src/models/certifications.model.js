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
const validateCertificationNumber = (value) => /^[A-Z0-9\-_]{6,50}$/.test(value);
const validateISODate = (value) => !value || validator.isISO8601(value.toString());
const validateCertificationName = (value) => /^[a-zA-Z0-9\s\-&():]+$/.test(value);

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

const certificationDetailsSchema = new Schema({
    title: { type: String, required: [true, 'Certification title is required'], trim: true, maxlength: 300, index: true, validate: { validator: validateCertificationName, message: 'Invalid certification title format' } },
    description: { type: String, maxlength: 2000, trim: true, set: v => v ? sanitizeHtml(v, { allowedTags: ['p', 'br', 'strong', 'em', 'ul', 'ol', 'li'], allowedAttributes: {} }) : v },
    category: { type: String, enum: ['technical', 'professional', 'academic', 'vocational', 'safety', 'compliance', 'language', 'creative', 'leadership', 'other'], required: true, index: true },
    subcategory: { type: String, trim: true, maxlength: 100, index: true },
    level: { type: String, enum: ['foundation', 'associate', 'professional', 'expert', 'master', 'specialist'], default: 'professional', index: true },
    difficulty: { type: String, enum: ['beginner', 'intermediate', 'advanced', 'expert'], default: 'intermediate' },
    field: { type: String, trim: true, maxlength: 100, index: true },
    specialization: { type: String, trim: true, maxlength: 150 },
    prerequisites: [{ type: String, maxlength: 200 }],
    learningOutcomes: [{ type: String, maxlength: 300 }],
    competencies: [{ type: String, maxlength: 150 }],
    language: { type: String, trim: true, maxlength: 10, default: 'en' }
}, { _id: false });

const credentialSchema = new Schema({
    certificationNumber: { type: String, required: [true, 'Certification number is required'], unique: true, validate: { validator: validateCertificationNumber, message: 'Invalid certification number format' }, index: true },
    certificateUrl: { type: String, validate: { validator: validateURL, message: 'Invalid certificate URL' } },
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
    renewalRequired: { type: Boolean, default: true },
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
        type: { type: String, enum: ['certificate', 'transcript', 'badge', 'license', 'diploma', 'other'] },
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

const skillsSchema = new Schema({
    primarySkills: [{
        name: { type: String, trim: true, maxlength: 100, required: true, index: true },
        proficiencyLevel: { type: String, enum: ['novice', 'beginner', 'intermediate', 'advanced', 'expert'], default: 'intermediate' },
        category: { type: String, enum: ['technical', 'soft', 'language', 'domain', 'tool', 'framework', 'methodology'] },
        weight: { type: Number, min: 0, max: 100, default: 50 },
        isCore: { type: Boolean, default: true }
    }],
    secondarySkills: [{
        name: { type: String, trim: true, maxlength: 100, index: true },
        proficiencyLevel: { type: String, enum: ['novice', 'beginner', 'intermediate', 'advanced', 'expert'] },
        category: { type: String, enum: ['technical', 'soft', 'language', 'domain', 'tool', 'framework', 'methodology'] }
    }],
    industryRelevance: [{
        industry: { type: String, trim: true, maxlength: 100, index: true },
        relevanceScore: { type: Number, min: 0, max: 100 },
        demandLevel: { type: String, enum: ['low', 'medium', 'high', 'critical'] }
    }],
    marketValue: {
        salaryImpact: { type: Number, min: 0, max: 200 },
        demandScore: { type: Number, min: 0, max: 100 },
        trendDirection: { type: String, enum: ['declining', 'stable', 'growing', 'emerging'] },
        lastUpdated: { type: Date, default: Date.now }
    }
}, { _id: false });

const requirementsSchema = new Schema({
    examDetails: {
        isRequired: { type: Boolean, default: false },
        examCode: { type: String, trim: true, maxlength: 50 },
        passingScore: { type: Number, min: 0, max: 100 },
        duration: { type: Number, min: 0 },
        format: { type: String, enum: ['online', 'offline', 'proctored', 'open-book', 'practical'] },
        retakePolicy: { type: String, maxlength: 500 },
        cost: { amount: { type: Number, min: 0 }, currency: { type: String, maxlength: 3, default: 'USD' } }
    },
    trainingDetails: {
        isRequired: { type: Boolean, default: false },
        provider: { type: String, trim: true, maxlength: 200 },
        duration: { type: Number, min: 0 },
        format: { type: String, enum: ['online', 'classroom', 'hybrid', 'self-paced', 'instructor-led'] },
        cost: { amount: { type: Number, min: 0 }, currency: { type: String, maxlength: 3, default: 'USD' } },
        materials: [{ type: String, maxlength: 200 }]
    },
    experienceRequirements: {
        minimumYears: { type: Number, min: 0, max: 50, default: 0 },
        relevantFields: [{ type: String, maxlength: 100 }],
        specificRoles: [{ type: String, maxlength: 150 }],
        portfolioRequired: { type: Boolean, default: false }
    },
    educationRequirements: {
        minimumDegree: { type: String, enum: ['none', 'high-school', 'associate', 'bachelor', 'master', 'doctorate'], default: 'none' },
        relevantFields: [{ type: String, maxlength: 100 }],
        gpaRequirement: { type: Number, min: 0, max: 4 }
    },
    maintenanceRequirements: {
        ceuRequired: { type: Number, min: 0, default: 0 },
        renewalFee: { amount: { type: Number, min: 0 }, currency: { type: String, maxlength: 3, default: 'USD' } },
        renewalPeriod: { type: Number, min: 1, max: 10 },
        activitiesRequired: [{ type: String, maxlength: 200 }]
    }
}, { _id: false });

const recognitionSchema = new Schema({
    industryRecognition: {
        level: { type: String, enum: ['unknown', 'niche', 'regional', 'national', 'international'], default: 'unknown', index: true },
        adoptionRate: { type: Number, min: 0, max: 100 },
        employerRecognition: { type: Number, min: 0, max: 100 },
        peerRecognition: { type: Number, min: 0, max: 100 }
    },
    accreditations: [{
        body: { type: String, trim: true, maxlength: 200, required: true },
        accreditationNumber: { type: String, trim: true, maxlength: 100 },
        level: { type: String, enum: ['candidate', 'accredited', 'premium', 'gold'] },
        validUntil: { type: Date },
        isActive: { type: Boolean, default: true }
    }],
    endorsements: [{
        endorserId: { type: Schema.Types.ObjectId, ref: 'User' },
        endorserType: { type: String, enum: ['peer', 'manager', 'expert', 'organization', 'client'] },
        endorserName: { type: String, maxlength: 100 },
        endorserTitle: { type: String, maxlength: 100 },
        endorserOrganization: { type: String, maxlength: 100 },
        comment: { type: String, maxlength: 1000, set: v => v ? sanitizeHtml(v, { allowedTags: [], allowedAttributes: {} }) : v },
        rating: { type: Number, min: 1, max: 5 },
        endorsedAt: { type: Date, default: Date.now },
        isVerified: { type: Boolean, default: false },
        isPublic: { type: Boolean, default: true },
        relevanceScore: { type: Number, min: 0, max: 100 }
    }],
    awards: [{
        title: { type: String, maxlength: 200 },
        issuedBy: { type: String, maxlength: 200 },
        dateReceived: { type: Date },
        description: { type: String, maxlength: 500 },
        category: { type: String, enum: ['excellence', 'innovation', 'leadership', 'contribution', 'achievement'] }
    }],
    mediaPresence: {
        articles: [{ title: String, url: { type: String, validate: { validator: validateURL } }, publishedAt: Date }],
        interviews: [{ title: String, url: { type: String, validate: { validator: validateURL } }, publishedAt: Date }],
        presentations: [{ title: String, event: String, date: Date, url: { type: String, validate: { validator: validateURL } } }]
    }
}, { _id: false });

const privacySchema = new Schema({
    isPublic: { type: Boolean, default: true, index: true },
    showInProfile: { type: Boolean, default: true },
    showDetails: { type: Boolean, default: true },
    showEndorsements: { type: Boolean, default: true },
    showVerificationStatus: { type: Boolean, default: true },
    allowContactFromRecruiters: { type: Boolean, default: true },
    searchable: { type: Boolean, default: true, index: true },
    shareableLink: { type: Boolean, default: true },
    visibilityLevel: { type: String, enum: ['private', 'connections', 'network', 'public'], default: 'public', index: true },
    restrictedCountries: [{ type: String, maxlength: 2 }],
    allowAnalytics: { type: Boolean, default: true }
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
    }]
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
    bookmarks: [{
        userId: { type: Schema.Types.ObjectId, ref: 'User' },
        bookmarkedAt: { type: Date, default: Date.now },
        tags: [{ type: String, maxlength: 50 }],
        notes: { type: String, maxlength: 500 }
    }]
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

const aiInsightsSchema = new Schema({
    marketDemand: { type: String, enum: ['very-low', 'low', 'medium', 'high', 'very-high'], index: true },
    salaryImpact: { type: Number, min: -50, max: 200 },
    careerProgression: [{ type: String, maxlength: 100 }],
    relatedCertifications: [{
        certificationId: { type: Schema.Types.ObjectId, ref: 'Certification' },
        relationshipType: { type: String, enum: ['prerequisite', 'complementary', 'alternative', 'advanced'] },
        relevanceScore: { type: Number, min: 0, max: 100 }
    }],
    recommendedFor: [{
        jobTitle: { type: String, maxlength: 100 },
        industry: { type: String, maxlength: 100 },
        experienceLevel: { type: String, enum: ['entry', 'mid', 'senior', 'executive'] },
        relevanceScore: { type: Number, min: 0, max: 100 }
    }],
    trendAnalysis: {
        trendDirection: { type: String, enum: ['declining', 'stable', 'growing', 'emerging'] },
        trendStrength: { type: Number, min: 0, max: 100 },
        peakDemandPeriods: [{ month: Number, year: Number, demand: Number }],
        seasonalityIndex: { type: Number, min: 0, max: 100 }
    },
    competitorAnalysis: [{
        competitorCertification: { type: Schema.Types.ObjectId, ref: 'Certification' },
        similarityScore: { type: Number, min: 0, max: 100 },
        advantagePoints: [{ type: String, maxlength: 200 }],
        disadvantagePoints: [{ type: String, maxlength: 200 }]
    }],
    lastAnalyzed: { type: Date, default: Date.now },
    analysisVersion: { type: String, default: '1.0' },
    confidenceLevel: { type: Number, min: 0, max: 100, default: 50 }
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

const complianceSchema = new Schema({
    regulatoryStandards: [{
        standard: { type: String, enum: ['ISO', 'GDPR', 'HIPAA', 'SOX', 'PCI-DSS', 'other'], required: true },
        complianceStatus: { type: String, enum: ['compliant', 'non-compliant', 'pending', 'exempt'], default: 'pending' },
        lastAudited: { type: Date },
        auditReport: { type: String, validate: { validator: validateURL, message: 'Invalid audit report URL' } }
    }],
    legalJurisdiction: { type: String, maxlength: 100, index: true },
    dataRetentionPolicy: {
        duration: { type: Number, min: 0, max: 50 }, // years
        deletionDate: { type: Date },
        isPermanent: { type: Boolean, default: false }
    },
    exportControl: {
        isRestricted: { type: Boolean, default: false },
        restrictedCountries: [{ type: String, maxlength: 2 }],
        exportLicense: { type: String, maxlength: 100 }
    }
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

// Main Certification Schema
const certificationSchema = new Schema({
    _id: { type: Schema.Types.ObjectId, auto: true },
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: [true, 'User ID is required'], index: true },
    organization: organizationSchema,
    certificationDetails: certificationDetailsSchema,
    credential: credentialSchema,
    duration: durationSchema,
    verification: verificationSchema,
    skills: skillsSchema,
    requirements: requirementsSchema,
    recognition: recognitionSchema,
    privacy: privacySchema,
    analytics: analyticsSchema,
    renewal: renewalSchema,
    social: socialSchema,
    metadata: metadataSchema,
    status: statusSchema,
    aiInsights: aiInsightsSchema,
    blockchain: blockchainSchema,
    compliance: complianceSchema,
    cache: cacheSchema
}, {
    timestamps: true,
    collection: 'certifications',
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
    shardKey: { userId: 1, 'credential.certificationNumber': 1 }
});

// Indexes for Scalability
certificationSchema.index({ userId: 1, 'duration.issueDate': -1, 'status.isActive': 1 });
certificationSchema.index({ 'credential.certificationNumber': 1 }, { unique: true });
certificationSchema.index({ 'certificationDetails.title': 1, 'organization.organizationId': 1, 'status.isActive': 1 });
certificationSchema.index({ 'skills.primarySkills.name': 1, 'verification.status': 1 });
certificationSchema.index({ 'privacy.isPublic': 1, 'status.isActive': 1, 'analytics.engagementScore': -1, updatedAt: -1 });
certificationSchema.index({ 'duration.isLifetime': 1, 'duration.expirationDate': 1 });
certificationSchema.index({ 'status.workflow': 1, 'renewal.status': 1 });
certificationSchema.index({
    'certificationDetails.title': 'text',
    'certificationDetails.description': 'text',
    'organization.name': 'text',
    'skills.primarySkills.name': 'text',
    'cache.searchVector': 'text'
}, {
    weights: { 'certificationDetails.title': 10, 'skills.primarySkills.name': 8, 'organization.name': 6, 'certificationDetails.description': 4, 'cache.searchVector': 1 },
    name: 'certification_text_search'
});
certificationSchema.index({ 'cache.popularityScore': -1, 'status.isActive': 1 }, { background: true });
certificationSchema.index({ 'cache.trendingScore': -1, 'privacy.isPublic': 1 }, { background: true });
certificationSchema.index({ 'status.deletedAt': 1 }, { expireAfterSeconds: 7776000, sparse: true }); // 90 days
certificationSchema.index({ 'compliance.legalJurisdiction': 1, 'status.isActive': 1 });
certificationSchema.index({ 'blockchain.isOnBlockchain': 1, 'blockchain.network': 1 });

// Virtuals
certificationSchema.virtual('isExpired').get(function () {
    if (this.duration.isLifetime) return false;
    return this.duration.expirationDate && this.duration.expirationDate < new Date();
});
certificationSchema.virtual('daysUntilExpiry').get(function () {
    if (this.duration.isLifetime || !this.duration.expirationDate) return null;
    return Math.ceil((this.duration.expirationDate - new Date()) / (1000 * 60 * 60 * 24));
});
certificationSchema.virtual('skillsCount').get(function () {
    return (this.skills.primarySkills?.length || 0) + (this.skills.secondarySkills?.length || 0);
});
certificationSchema.virtual('endorsementCount').get(function () {
    return this.recognition.endorsements?.length || 0;
});
certificationSchema.virtual('verificationLevel').get(function () {
    const score = this.verification.verificationScore;
    if (score >= 90) return 'platinum';
    if (score >= 75) return 'gold';
    if (score >= 60) return 'silver';
    if (score >= 40) return 'bronze';
    return 'unverified';
});
certificationSchema.virtual('engagementLevel').get(function () {
    const score = this.analytics.engagementScore;
    if (score >= 80) return 'viral';
    if (score >= 60) return 'high';
    if (score >= 40) return 'medium';
    if (score >= 20) return 'low';
    return 'minimal';
});

// Middleware
certificationSchema.pre('save', async function (next) {
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
            this.certificationDetails.title,
            this.certificationDetails.description,
            this.organization.name,
            ...this.skills.primarySkills.map(s => s.name),
            ...this.skills.secondarySkills.map(s => s.name)
        ].filter(Boolean).join(' ').toLowerCase();

        // Calculate verification score
        if (this.verification.status === 'verified') {
            let score = 30;
            const methodScores = { 'document': 25, 'third-party': 20, 'api': 30, 'blockchain': 30, 'certificate': 20, 'manual': 10 };
            score += methodScores[this.verification.verificationMethod] || 0;
            if (this.verification.documents?.length > 0) score += 15;
            if (this.verification.externalVerifications?.length > 0) score += 10;
            if (this.recognition.endorsements?.length > 0) score += Math.min(this.recognition.endorsements.length * 2, 20);
            if (this.blockchain.isOnBlockchain) score += 10;
            this.verification.verificationScore = Math.min(score, 100);
        }

        // Calculate engagement and popularity scores
        let engagementScore = 0;
        engagementScore += (this.analytics.views || 0) * 0.1;
        engagementScore += (this.analytics.shareCount || 0) * 5;
        engagementScore += (this.analytics.comments?.length || 0) * 3;
        engagementScore += (this.analytics.downloadCount || 0) * 2;
        engagementScore += (this.endorsementCount || 0) * 4;
        engagementScore += (this.verification.verificationScore || 0) * 0.2;
        this.analytics.engagementScore = Math.min(engagementScore, 1000);

        this.cache.popularityScore = this.calculatePopularityScore();
        this.cache.trendingScore = (this.analytics.engagementScore * 0.4) + (this.verification.verificationScore * 0.3) + (this.endorsementCount * 0.3);
        this.cache.verificationStrength = this.verification.verificationScore * 0.6 + (this.blockchain.isOnBlockchain ? 40 : 0);
        this.cache.marketRelevance = (this.aiInsights.marketDemand === 'very-high' ? 100 : this.aiInsights.marketDemand === 'high' ? 80 : this.aiInsights.marketDemand === 'medium' ? 60 : 40);

        // Update cache metadata
        this.cache.lastCacheUpdate = new Date();
        this.cache.cacheVersion += 1;
        this.cache.precomputedStats = {
            totalEndorsements: this.endorsementCount,
            avgRating: this.recognition.endorsements.reduce((sum, e) => sum + (e.rating || 0), 0) / (this.endorsementCount || 1),
            verificationRate: this.verification.verificationScore,
            completionScore: this.calculateCompletionScore()
        };

        // Cache in Redis with sharding
        const shardKey = `${this.userId}_${this.credential.certificationNumber}`;
        await redisClient.setEx(`cert:${shardKey}`, 300, JSON.stringify(this.toJSON()));

        // Publish updates
        await redisClient.publish('certification_updates', JSON.stringify({
            certificationId: this._id,
            shardKey,
            popularityScore: this.cache.popularityScore,
            trendingScore: this.cache.trendingScore
        }));

        // AI Insights
        if (!this.aiInsights.lastAnalyzed || (new Date() - this.aiInsights.lastAnalyzed) > 7 * 24 * 60 * 60 * 1000) {
            this.aiInsights.lastAnalyzed = new Date();
            this.aiInsights.recommendedFor = this.skills.primarySkills.map(skill => ({
                jobTitle: skill.name,
                industry: this.certificationDetails.field,
                experienceLevel: skill.proficiencyLevel,
                relevanceScore: skill.weight
            }));
        }

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

certificationSchema.pre('remove', async function (next) {
    try {
        this.status.isDeleted = true;
        this.status.deletedAt = new Date();
        this.privacy.isPublic = false;
        this.privacy.searchable = false;
        const shardKey = `${this.userId}_${this.credential.certificationNumber}`;
        await redisClient.del(`cert:${shardKey}`);
        await this.save();
        next();
    } catch (error) {
        next(new Error(`Pre-remove middleware error: ${error.message}`));
    }
});

certificationSchema.post('save', async function (doc) {
    try {
        // Update User profile
        const User = mongoose.model('User');
        await User.updateOne(
            { _id: doc.userId },
            { $set: { 'profile.lastUpdated': new Date() }, $inc: { 'analytics.profileUpdates': 1 } }
        );

        // Update Organization stats
        if (doc.organization.organizationId) {
            const Organization = mongoose.model('Organization');
            await Organization.updateOne(
                { _id: doc.organization.organizationId },
                { $inc: { 'stats.certificationCount': 1 }, $set: { 'analytics.lastCalculated': new Date() } }
            );
        }

        // Sync to Algolia
        if (doc.privacy.searchable && doc.privacy.isPublic && doc.status.isActive) {
            try {
                await doc.syncToAlgolia();
            } catch (error) {
                console.error('Algolia sync error:', error.message);
            }
        }

        // Invalidate related caches
        await redisClient.del(`user:certs:${doc.userId}`);
    } catch (error) {
        console.error('Post-save middleware error:', error.message);
    }
});

// Instance Methods
certificationSchema.methods.calculatePopularityScore = function () {
    const weights = { views: 0.3, likes: 0.2, comments: 0.2, shares: 0.2, endorsements: 0.2, verified: 0.1 };
    const viewScore = Math.log1p(this.analytics.views) / Math.log1p(10000);
    const likeScore = Math.log1p(this.analytics.shareCount) / Math.log1p(1000);
    const commentScore = Math.log1p(this.social.comments?.length || 0) / Math.log1p(500);
    const shareScore = Math.log1p(this.analytics.shareCount) / Math.log1p(500);
    const endorsementScore = Math.log1p(this.endorsementCount) / Math.log1p(100);
    const verifiedScore = this.verification.status === 'verified' ? 1 : 0;
    return Math.min(100, (
        viewScore * weights.views +
        likeScore * weights.likes +
        commentScore * weights.comments +
        shareScore * weights.shares +
        endorsementScore * weights.endorsements +
        verifiedScore * weights.verified
    ) * 100);
};

certificationSchema.methods.calculateCompletionScore = function () {
    let score = 0;
    if (this.certificationDetails.title) score += 20;
    if (this.certificationDetails.description) score += 10;
    if (this.skills.primarySkills?.length > 0) score += 20;
    if (this.verification.status === 'verified') score += 20;
    if (this.recognition.endorsements?.length > 0) score += 10;
    if (this.credential.certificateUrl) score += 10;
    if (this.blockchain.isOnBlockchain) score += 10;
    return score;
};

// Static Methods
certificationSchema.statics.getUserCertifications = async function (userId, options = {}) {
    const { page = 1, limit = 10, sortBy = 'issueDate', sortOrder = -1, includeDeleted = false, filters = {}, includePrivate = false } = options;
    const cacheKey = `user:certs:${userId}:${JSON.stringify(options)}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const baseQuery = { userId: new mongoose.Types.ObjectId(userId), 'status.isActive': true };
    if (!includeDeleted) baseQuery['status.isDeleted'] = false;
    if (!includePrivate) baseQuery['privacy.isPublic'] = true;
    Object.entries(filters).forEach(([key, value]) => { if (value !== undefined && value !== null && value !== '') baseQuery[key] = value; });

    const results = await this.find(baseQuery)
        .sort({ [`duration.${sortBy}`]: sortOrder })
        .skip((page - 1) * limit)
        .limit(limit)
        .populate({ path: 'organization.organizationId', select: 'name logo industry verification.isVerified' })
        .select('-social.comments -verification.documents')
        .lean({ virtuals: true });

    await redisClient.setEx(cacheKey, 3600, JSON.stringify(results));
    return results;
};

certificationSchema.statics.advancedSearch = async function (searchOptions = {}) {
    const { query = '', issuer = {}, skills = [], verificationStatus, page = 1, limit = 20, sortBy = 'relevance', userId = null } = searchOptions;
    const cacheKey = `search:certs:${JSON.stringify(searchOptions)}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const pipeline = [
        {
            $match: {
                'status.isActive': true,
                'status.isDeleted': false,
                'privacy.isPublic': true,
                'privacy.searchable': true,
                'status.workflow': 'verified',
                ...(verificationStatus && { 'verification.status': verificationStatus }),
                ...(issuer.name && { 'organization.name': new RegExp(issuer.name, 'i') }),
                ...(issuer.organizationId && { 'organization.organizationId': new mongoose.Types.ObjectId(issuer.organizationId) })
            }
        },
        ...(query ? [{ $match: { $text: { $search: query, $caseSensitive: false } } }, { $addFields: { textScore: { $meta: 'textScore' } } }] : []),
        ...(skills.length > 0 ? [
            { $addFields: { skillMatchScore: { $divide: [{ $size: { $setIntersection: [skills, { $concatArrays: [{ $map: { input: '$skills.primarySkills', as: 'skill', in: '$$skill.name' } }, { $map: { input: '$skills.secondarySkills', as: 'skill', in: '$$skill.name' } }] }] } }, skills.length] } } },
            { $match: { skillMatchScore: { $gt: 0 } } }
        ] : []),
        { $lookup: { from: 'organizations', localField: 'organization.organizationId', foreignField: '_id', as: 'organization', pipeline: [{ $project: { name: 1, logo: 1, industry: 1, verification: 1 } }] } },
        { $unwind: { path: '$organization', preserveNullAndEmptyArrays: true } },
        { $lookup: { from: 'users', localField: 'userId', foreignField: '_id', as: 'userProfile', pipeline: [{ $project: { name: 1, profilePic: 1, headline: 1, verification: 1 } }] } },
        { $unwind: { path: '$userProfile', preserveNullAndEmptyArrays: true } },
        ...(userId ? [{ $addFields: { networkBoost: { $cond: [{ $in: [new mongoose.Types.ObjectId(userId), '$userProfile.connections'] }, 0.3, { $cond: [{ $in: [new mongoose.Types.ObjectId(userId), '$userProfile.followers'] }, 0.1, 0] }] } } }] : []),
        {
            $addFields: {
                relevanceScore: {
                    $add: [
                        { $multiply: [{ $ifNull: ['$textScore', 0] }, 0.3] },
                        { $multiply: [{ $ifNull: ['$skillMatchScore', 0] }, 0.25] },
                        { $multiply: [{ $divide: ['$verification.verificationScore', 100] }, 0.15] },
                        { $multiply: [{ $divide: [{ $min: ['$analytics.engagementScore', 100] }, 100] }, 0.1] },
                        { $multiply: [{ $cond: ['$organization.verification.isVerified', 1, 0] }, 0.1] },
                        { $ifNull: ['$networkBoost', 0] },
                        { $multiply: [{ $cond: ['$blockchain.isOnBlockchain', 1, 0] }, 0.1] }
                    ]
                },
                popularityScore: this.calculatePopularityScore()
            }
        },
        { $sort: this.getSortQuery(sortBy) },
        {
            $project: {
                userId: 1,
                certificationDetails: { title: 1, category: 1, level: 1 },
                credential: { certificationNumber: 1, certificateUrl: 1 },
                organization: { $cond: ['$privacy.showDetails', '$organization', { name: '$organization.name' }] },
                duration: { $cond: ['$privacy.showDetails', '$duration', { isLifetime: '$duration.isLifetime' }] },
                skills: { $slice: [{ $concatArrays: ['$skills.primarySkills', '$skills.secondarySkills'] }, 10] },
                verification: { status: '$verification.status', level: '$verification.verificationScore' },
                recognition: { endorsements: { $size: { $ifNull: ['$recognition.endorsements', []] } } },
                organization: 1,
                userProfile: { name: '$userProfile.name', profilePic: '$userProfile.profilePic', headline: '$userProfile.headline' },
                relevanceScore: 1,
                popularityScore: 1,
                createdAt: 1,
                updatedAt: 1
            }
        }
    ];

    const results = await this.aggregatePaginate(pipeline, { page, limit, customLabels: { totalDocs: 'totalResults', docs: 'certifications' } });
    await redisClient.setEx(cacheKey, 60, JSON.stringify(results));
    return results;
};

certificationSchema.statics.getSortQuery = function (sortBy) {
    const sortQueries = {
        'relevance': { relevanceScore: -1, 'verification.verificationScore': -1 },
        'recent': { 'duration.issueDate': -1, updatedAt: -1 },
        'popular': { 'cache.popularityScore': -1, 'analytics.views': -1 },
        'verified': { 'verification.verificationScore': -1, 'verification.status': -1 },
        'alphabetical': { 'certificationDetails.title': 1, 'organization.name': 1 }
    };
    return sortQueries[sortBy] || sortQueries['relevance'];
};

certificationSchema.statics.getTrendingCertifications = async function (options = {}) {
    const { timeframe = 30, issuer, skills, limit = 25 } = options;
    const cacheKey = `trending:certs:${JSON.stringify(options)}`;
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
                ...(issuer && { 'organization.name': new RegExp(issuer, 'i') })
            }
        },
        ...(skills.length > 0 ? [{ $match: { 'skills.primarySkills.name': { $in: skills } } }] : []),
        { $lookup: { from: 'organizations', localField: 'organization.organizationId', foreignField: '_id', as: 'organization' } },
        { $unwind: { path: '$organization', preserveNullAndEmptyArrays: true } },
        {
            $facet: {
                trendingCertifications: [
                    { $group: { _id: { title: '$certificationDetails.title', issuer: '$organization.name' }, count: { $sum: 1 }, avgVerificationScore: { $avg: '$verification.verificationScore' }, totalEndorsements: { $sum: { $size: { $ifNull: ['$recognition.endorsements', []] } } }, uniqueUsers: { $addToSet: '$userId' } } },
                    { $addFields: { userCount: { $size: '$uniqueUsers' }, trendScore: { $multiply: ['$count', { $add: [{ $size: '$uniqueUsers' }, 1] }, { $add: [{ $divide: ['$totalEndorsements', 10] }, 1] }] } } },
                    { $sort: { trendScore: -1 } },
                    { $limit: limit },
                    { $project: { title: '$_id.title', issuer: '$_id.issuer', occurrences: '$count', userCount: 1, trendScore: 1, avgVerificationScore: { $round: ['$avgVerificationScore', 1] } } }
                ],
                trendingSkills: [
                    { $unwind: '$skills.primarySkills' },
                    { $group: { _id: '$skills.primarySkills.name', count: { $sum: 1 }, avgLevel: { $avg: { $switch: { branches: [{ case: { $eq: ['$skills.primarySkills.proficiencyLevel', 'novice'] }, then: 1 }, { case: { $eq: ['$skills.primarySkills.proficiencyLevel', 'beginner'] }, then: 2 }, { case: { $eq: ['$skills.primarySkills.proficiencyLevel', 'intermediate'] }, then: 3 }, { case: { $eq: ['$skills.primarySkills.proficiencyLevel', 'advanced'] }, then: 4 }, { case: { $eq: ['$skills.primarySkills.proficiencyLevel', 'expert'] }, then: 5 }], default: 3 } } }, endorsements: { $sum: { $cond: ['$skills.primarySkills.isCore', 1, 0] } } } },
                    { $addFields: { endorsementRate: { $divide: ['$endorsements', '$count'] } } },
                    { $sort: { count: -1 } },
                    { $limit: limit },
                    { $project: { skill: '$_id', frequency: '$count', averageLevel: { $round: ['$avgLevel', 1] }, endorsementRate: { $round: ['$endorsementRate', 2] } } }
                ]
            }
        }
    ];

    const results = await this.aggregate(pipeline);
    await redisClient.setEx(cacheKey, 86400, JSON.stringify(results));
    return results;
};

certificationSchema.statics.getCertificationAnalytics = async function (userId, options = {}) {
    const cacheKey = `cert:analytics:${userId}:${JSON.stringify(options)}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const pipeline = [
        { $match: { userId: new mongoose.Types.ObjectId(userId), 'status.isActive': true, 'status.isDeleted': false } },
        { $sort: { 'duration.issueDate': 1 } },
        { $lookup: { from: 'organizations', localField: 'organization.organizationId', foreignField: '_id', as: 'organization' } },
        { $unwind: { path: '$organization', preserveNullAndEmptyArrays: true } },
        {
            $group: {
                _id: null,
                certifications: {
                    $push: {
                        title: '$certificationDetails.title',
                        issuer: '$organization.name',
                        industry: '$organization.industry',
                        issueDate: '$duration.issueDate',
                        expirationDate: '$duration.expirationDate',
                        isLifetime: '$duration.isLifetime',
                        renewalStatus: '$renewal.status',
                        skills: { $concatArrays: ['$skills.primarySkills', '$skills.secondarySkills'] },
                        endorsements: { $size: { $ifNull: ['$recognition.endorsements', []] } },
                        verificationScore: '$verification.verificationScore'
                    }
                },
                totalCertifications: { $sum: 1 },
                activeCertifications: { $sum: { $cond: [{ $or: ['$duration.isLifetime', { $gt: ['$duration.expirationDate', new Date()] }] }, 1, 0] } },
                verifiedCertifications: { $sum: { $cond: ['$verification.status', 'verified', 1, 0] } },
                uniqueIssuers: { $addToSet: '$organization.organizationId' },
                allSkills: { $push: { $concatArrays: ['$skills.primarySkills', '$skills.secondarySkills'] } },
                totalEndorsements: { $sum: { $size: { $ifNull: ['$recognition.endorsements', []] } } }
            }
        },
        {
            $addFields: {
                issuerCount: { $size: '$uniqueIssuers' },
                skillEvolution: { $reduce: { input: '$allSkills', initialValue: [], in: { $setUnion: ['$value', { $map: { input: '$this', as: 'skill', in: '$skill.name' } }] } } },
                avgVerificationScore: { $avg: '$certifications.verificationScore' }
            }
        },
        {
            $project: {
                _id: 0,
                summary: { totalCertifications: '$totalCertifications', activeCertifications: '$activeCertifications', verifiedCertifications: '$verifiedCertifications', issuerCount: '$issuerCount', totalEndorsements: '$totalEndorsements', avgVerificationScore: { $round: ['$avgVerificationScore', 1] } },
                certifications: '$certifications',
                skills: { total: { $size: '$skillEvolution' }, evolution: '$skillEvolution' }
            }
        }
    ];

    const results = await this.aggregate(pipeline);
    await redisClient.setEx(cacheKey, 43200, JSON.stringify(results));
    return results;
};

certificationSchema.statics.bulkOperations = {
    updateVerification: async function (certificationIds, verificationData) {
        try {
            const bulkOps = certificationIds.map(id => ({
                updateOne: {
                    filter: { _id: new mongoose.Types.ObjectId(id), 'status.isActive': true },
                    update: { $set: { verification: verificationData, 'metadata.lastUpdated': new Date() } }
                }
            }));
            const result = await this.bulkWrite(bulkOps);
            for (const id of certificationIds) {
                const cert = await this.findById(id).lean();
                await redisClient.del(`cert:${cert.userId}_${cert.credential.certificationNumber}`);
            }
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
            await redisClient.del(`user:certs:${userId}`);
            return result;
        } catch (error) {
            throw new Error(`Bulk privacy update error: ${error.message}`);
        }
    },
    archiveExpiredCertifications: async function (cutoffDate) {
        try {
            const expiredCertifications = await this.find({ 'duration.expirationDate': { $lt: cutoffDate }, 'status.isActive': true, 'status.isDeleted': false, 'duration.isLifetime': false }).lean();
            if (expiredCertifications.length === 0) return { archived: 0 };
            const ArchiveCertification = mongoose.model('ArchiveCertification', certificationSchema, 'archive_certifications');
            await ArchiveCertification.insertMany(expiredCertifications);
            const result = await this.updateMany(
                { _id: { $in: expiredCertifications.map(c => c._id) } },
                { $set: { 'status.isActive': false, 'status.archivedAt': new Date(), 'metadata.lastUpdated': new Date() } }
            );
            for (const cert of expiredCertifications) await redisClient.del(`cert:${cert.userId}_${cert.credential.certificationNumber}`);
            return { archived: result.modifiedCount };
        } catch (error) {
            throw new Error(`Archive expired certifications error: ${error.message}`);
        }
    },
    addEndorsement: async function (certificationIds, endorsementData) {
        try {
            const bulkOps = certificationIds.map(id => ({
                updateOne: {
                    filter: { _id: new mongoose.Types.ObjectId(id) },
                    update: { $push: { 'recognition.endorsements': endorsementData }, $inc: { 'analytics.endorsementCount': 1 } }
                }
            }));
            const result = await this.bulkWrite(bulkOps);
            for (const id of certificationIds) {
                const cert = await this.findById(id).lean();
                await redisClient.del(`cert:${cert.userId}_${cert.credential.certificationNumber}`);
            }
            return result;
        } catch (error) {
            throw new Error(`Bulk endorsement add error: ${error.message}`);
        }
    }
};

certificationSchema.statics.getAIRecommendations = async function (userId, options = {}) {
    const { type = 'certification-growth', limit = 10 } = options;
    const cacheKey = `ai:cert-recommendations:${userId}:${type}:${limit}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const pipeline = [
        { $match: { userId: new mongoose.Types.ObjectId(userId), 'status.isActive': true } },
        { $group: { _id: null, currentSkills: { $push: { $concatArrays: [{ $map: { input: '$skills.primarySkills', as: 'skill', in: '$skill.name' } }, { $map: { input: '$skills.secondarySkills', as: 'skill', in: '$skill.name' } }] } }, currentCertifications: { $push: '$certificationDetails.title' } } },
        { $lookup: { from: 'certifications', pipeline: [{ $match: { 'status.isActive': true, 'privacy.isPublic': true, userId: { $ne: new mongoose.Types.ObjectId(userId) } } }, { $sample: { size: 1000 } }], as: 'marketData' } },
        {
            $project: {
                recommendations: {
                    $switch: {
                        branches: [
                            { case: { $eq: [type, 'certification-growth'] }, then: { recommendedCertifications: { $slice: [{ $setDifference: [{ $reduce: { input: '$marketData.certificationDetails.title', initialValue: [], in: { $setUnion: ['$value', '$this'] } } }, '$currentCertifications'] }, limit] }, skillsToLearn: { $slice: [{ $setDifference: [{ $reduce: { input: '$marketData.skills.primarySkills', initialValue: [], in: { $setUnion: ['$value', '$this.name'] } } }, '$currentSkills'] }, limit] } } },
                            { case: { $eq: [type, 'skill-development'] }, then: { trendingSkills: { $slice: [{ $reduce: { input: '$marketData.skills.primarySkills', initialValue: [], in: { $setUnion: ['$value', '$this.name'] } } }, limit] } } }
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

certificationSchema.statics.getPerformanceMetrics = async function (timeframe = '30d') {
    const cacheKey = `performance:cert-metrics:${timeframe}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const startDate = new Date();
    const days = parseInt(timeframe.replace('d', ''));
    startDate.setDate(startDate.getDate() - days);
    const pipeline = [
        {
            $facet: {
                queryStats: [{ $match: { 'metadata.lastUpdated': { $gte: startDate } } }, { $group: { _id: null, totalQueries: { $sum: 1 }, avgResponseTime: { $avg: '$analytics.responseTime' }, errorRate: { $avg: { $cond: ['$analytics.hasError', 1, 0] } } } }],
                indexStats: [{ $group: { _id: '$metadata.source', count: { $sum: 1 }, avgVerificationScore: { $avg: '$verification.verificationScore' } } }],
                dataQuality: [
                    {
                        $group: {
                            _id: null,
                            totalRecords: { $sum: 1 },
                            completeProfiles: { $sum: { $cond: [{ $and: [{ $ne: ['$certificationDetails.title', ''] }, { $ne: ['$credential.certificationNumber', ''] }, { $gt: [{ $size: { $ifNull: ['$skills.primarySkills', []] } }, 0] }] }, 1, 0] } },
                            verifiedRecords: { $sum: { $cond: ['$verification.status', 'verified', 1, 0] } },
                            withEndorsements: { $sum: { $cond: [{ $gt: [{ $size: { $ifNull: ['$recognition.endorsements', []] } }, 0] }, 1, 0] } }
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

certificationSchema.statics.cleanupIndexes = async function () {
    const indexes = await this.collection.indexes();
    const essentialIndexes = ['_id_', 'certification_text_search', 'userId_1_duration.issueDate_-1_status.isActive_1', 'credential.certificationNumber_1'];
    const unusedIndexes = indexes.filter(idx => !essentialIndexes.includes(idx.name));
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

certificationSchema.statics.initChangeStream = function () {
    const changeStream = this.watch([{ $match: { 'operationType': { $in: ['insert', 'update', 'replace'] } } }]);
    changeStream.on('change', async (change) => {
        const certificationId = change.documentKey._id.toString();
        const cert = await this.findById(certificationId).lean();
        if (cert) {
            const shardKey = `${cert.userId}_${cert.credential.certificationNumber}`;
            await redisClient.del(`cert:${shardKey}`);
            await redisClient.publish('certification_updates', JSON.stringify({
                certificationId,
                operation: change.operationType,
                updatedFields: change.updateDescription?.updatedFields
            }));
        }
    });
    return changeStream;
};

// Placeholder for CSFLE
async function encryptField(value) {
    return crypto.createHash('sha256').update(value).digest('hex');
}

// Plugins
certificationSchema.plugin(aggregatePaginate);
if (process.env.ALGOLIA_APP_ID && process.env.ALGOLIA_ADMIN_KEY) {
    certificationSchema.plugin(mongooseAlgolia, {
        appId: process.env.ALGOLIA_APP_ID,
        apiKey: process.env.ALGOLIA_ADMIN_KEY,
        indexName: 'certifications',
        selector: 'certificationDetails.title certificationDetails.description skills.primarySkills.name organization.name cache.searchVector',
        defaults: { author: 'unknown' },
        mappings: {
            'certificationDetails.title': v => v || '',
            'certificationDetails.description': v => v || '',
            'skills.primarySkills.name': v => v || [],
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
    certificationSchema.index({ 'cache.popularityScore': -1, 'status.isActive': 1 }, { background: true });
    certificationSchema.index({ 'cache.trendingScore': -1, 'privacy.isPublic': 1 }, { background: true });
    certificationSchema.index({ 'blockchain.transactionHash': 1 }, { sparse: true });
}

export default mongoose.model('Certification', certificationSchema);