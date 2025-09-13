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
const validateSchoolName = (value) => /^[a-zA-Z0-9\s\-&().,'"]+$/.test(value);
const validateWebsiteURL = (value) => !value || validator.isURL(value, { require_protocol: true });
const validateEmail = (value) => !value || validator.isEmail(value);
const validateAccreditationCode = (value) => /^[A-Z]{2,5}-[0-9]{4,6}$/.test(value) || !value;
const validateEnrollmentNumber = (value) => typeof value === 'number' && value >= 0 && value <= 1000000;
const validateRankingScore = (value) => typeof value === 'number' && value >= 0 && value <= 100;

// Sub-Schemas
const addressSchema = new Schema({
    street: { type: String, trim: true, maxlength: 200 },
    city: { type: String, trim: true, maxlength: 50, index: true },
    state: { type: String, trim: true, maxlength: 50 },
    country: { type: String, trim: true, maxlength: 50, index: true },
    zipCode: { type: String, trim: true, maxlength: 10, validate: { validator: value => !value || /^[0-9]{5}(-[0-9]{4})?$/.test(value), message: 'Invalid zip code format' } },
    timezone: { type: String, trim: true, maxlength: 50 },
    coordinates: { type: { type: String, enum: ['Point'], default: 'Point' }, coordinates: { type: [Number], index: '2dsphere' } }
}, { _id: false });

const contactSchema = new Schema({
    generalEmail: { type: String, validate: { validator: validateEmail, message: 'Invalid general email' } },
    admissionsEmail: { type: String, validate: { validator: validateEmail, message: 'Invalid admissions email' } },
    phone: { type: String, maxlength: 20 },
    website: { type: String, validate: { validator: validateWebsiteURL, message: 'Invalid website URL' } },
    socialMedia: {
        twitter: { type: String, validate: { validator: value => !value || validator.isURL(value), message: 'Invalid Twitter URL' } },
        linkedin: { type: String, validate: { validator: value => !value || validator.isURL(value), message: 'Invalid LinkedIn URL' } },
        facebook: { type: String, validate: { validator: value => !value || validator.isURL(value), message: 'Invalid Facebook URL' } }
    }
}, { _id: false });

const typeSchema = new Schema({
    primary: { type: String, enum: ['university', 'college', 'community-college', 'high-school', 'vocational', 'online', 'other'], required: true, index: true },
    secondary: [{ type: String, enum: ['public', 'private', 'non-profit', 'for-profit', 'liberal-arts', 'technical', 'research'] }],
    level: { type: String, enum: ['undergraduate', 'graduate', 'postgraduate', 'k-12', 'vocational'], default: 'undergraduate', index: true }
}, { _id: false });

const sizeSchema = new Schema({
    undergraduateEnrollment: { type: Number, min: 0, max: 100000, validate: { validator: validateEnrollmentNumber, message: 'Invalid undergraduate enrollment' } },
    graduateEnrollment: { type: Number, min: 0, max: 50000, validate: { validator: validateEnrollmentNumber, message: 'Invalid graduate enrollment' } },
    totalEnrollment: { type: Number, min: 0, max: 150000, validate: { validator: validateEnrollmentNumber, message: 'Invalid total enrollment' } },
    facultyCount: { type: Number, min: 0, max: 50000 },
    studentFacultyRatio: { type: Number, min: 0, max: 50, default: 15 },
    category: { type: String, enum: ['small', 'medium', 'large', 'very-large'], index: true }
}, { _id: false });

const accreditationSchema = new Schema({
    bodies: [{ name: { type: String, maxlength: 100 }, code: { type: String, validate: { validator: validateAccreditationCode, message: 'Invalid accreditation code' } }, status: { type: String, enum: ['accredited', 'candidate', 'probation', 'withdrawn'], default: 'accredited' }, expires: { type: Date } }],
    regional: { type: Boolean, default: false },
    national: { type: Boolean, default: false },
    international: { type: Boolean, default: false },
    lastReviewed: { type: Date },
    nextReview: { type: Date }
}, { _id: false });

const departmentSchema = new Schema({
    name: { type: String, maxlength: 100, required: true },
    description: { type: String, maxlength: 1000, set: v => v ? sanitizeHtml(v, { allowedTags: [], allowedAttributes: {} }) : v },
    head: { type: Schema.Types.ObjectId, ref: 'User' },
    facultyCount: { type: Number, min: 0 },
    programsOffered: [{ type: String, maxlength: 100 }],
    researchFocus: [{ type: String, maxlength: 100 }],
    facilities: { type: String, maxlength: 500 },
    contactEmail: { type: String, validate: { validator: validateEmail, message: 'Invalid department email' } }
}, { _id: false });

const programSchema = new Schema({
    name: { type: String, maxlength: 200, required: true },
    degreeLevel: { type: String, enum: ['associate', 'bachelor', 'master', 'doctorate', 'certificate'], required: true },
    fieldOfStudy: { type: String, maxlength: 100, required: true },
    durationYears: { type: Number, min: 0.5, max: 8 },
    creditsRequired: { type: Number, min: 0, max: 200 },
    tuitionAnnual: { type: Number, min: 0 },
    currency: { type: String, maxlength: 3, default: 'USD' },
    admissionRate: { type: Number, min: 0, max: 100 },
    avgGPARequired: { type: Number, min: 0, max: 4.0 },
    satActRequired: { type: Boolean, default: false },
    description: { type: String, maxlength: 2000 },
    department: { type: Schema.Types.ObjectId, ref: 'Department' }, // Assuming Department model
    outcomes: {
        employmentRate: { type: Number, min: 0, max: 100 },
        avgSalary: { type: Number, min: 0 },
        topEmployers: [{ type: String, maxlength: 100 }]
    }
}, { _id: false });

const statsSchema = new Schema({
    avgRating: { type: Number, min: 0, max: 5, default: 0 },
    alumniCount: { type: Number, min: 0 },
    retentionRate: { type: Number, min: 0, max: 100 },
    graduationRate: { type: Number, min: 0, max: 100 },
    researchOutput: { type: Number, min: 0 }, // Publications per year
    endowment: { type: Number, min: 0 },
    diversity: {
        genderRatio: { female: { type: Number, min: 0, max: 100 }, male: { type: Number, min: 0, max: 100 }, other: { type: Number, min: 0, max: 100 } },
        ethnicBreakdown: [{ group: { type: String }, percentage: { type: Number, min: 0, max: 100 } }]
    },
    internationalStudents: { type: Number, min: 0 },
    lastCalculated: { type: Date, default: Date.now }
}, { _id: false });

const rankingSchema = new Schema({
    sources: [{
        name: { type: String, maxlength: 100 }, // e.g., US News, QS
        rank: { type: Number },
        year: { type: Number },
        category: { type: String, maxlength: 50 },
        score: { type: Number, validate: { validator: validateRankingScore, message: 'Ranking score must be 0-100' } },
        methodology: { type: String, maxlength: 500 }
    }],
    overallRank: { type: Number },
    globalRank: { type: Number },
    nationalRank: { type: Number }
}, { _id: false });

const facilitySchema = new Schema({
    name: { type: String, maxlength: 100 },
    type: { type: String, enum: ['library', 'lab', 'dormitory', 'sports', 'auditorium', 'research-center'] },
    capacity: { type: Number, min: 0 },
    description: { type: String, maxlength: 500 },
    url: { type: String, validate: { validator: validateWebsiteURL, message: 'Invalid facility URL' } },
    media: [{ type: Schema.Types.ObjectId, ref: 'Media' }]
}, { _id: false });

const eventSchema = new Schema({
    name: { type: String, maxlength: 200 },
    description: { type: String, maxlength: 1000 },
    date: { type: Date },
    type: { type: String, enum: ['admission-open-house', 'career-fair', 'seminar', 'graduation', 'research-conference'] },
    location: addressSchema,
    attendance: { type: Number, min: 0 },
    virtual: { type: Boolean, default: false },
    registrationUrl: { type: String, validate: { validator: validateWebsiteURL, message: 'Invalid registration URL' } }
}, { _id: false });

const alumniSchema = new Schema({
    notable: [{ name: { type: String, maxlength: 100 }, achievement: { type: String, maxlength: 200 }, yearGraduated: { type: Number } }],
    networkSize: { type: Number, min: 0 },
    chapters: [{ name: { type: String, maxlength: 100 }, location: { type: String }, members: { type: Number, min: 0 } }],
    successRate: { type: Number, min: 0, max: 100 } // Employment or further education
}, { _id: false });

const facultySchema = new Schema({
    total: { type: Number, min: 0 },
    phdPercentage: { type: Number, min: 0, max: 100 },
    avgExperience: { type: Number, min: 0 },
    publicationsPerFaculty: { type: Number, min: 0 },
    grantsPerFaculty: { type: Number, min: 0 },
    diversity: {
        gender: { female: { type: Number, min: 0, max: 100 }, male: { type: Number, min: 0, max: 100 } },
        ethnic: [{ group: { type: String }, percentage: { type: Number, min: 0, max: 100 } }]
    }
}, { _id: false });

const verificationSchema = new Schema({
    isVerified: { type: Boolean, default: false, index: true },
    verifiedBy: { type: Schema.Types.ObjectId, ref: 'User' },
    verificationDate: { type: Date },
    method: { type: String, enum: ['official-website', 'government-database', 'accreditation-body', 'alumni-verification', 'api-sync'], required: true },
    score: { type: Number, min: 0, max: 100, default: 0 },
    documents: [{
        type: { type: String, enum: ['charter', 'accreditation-certificate', 'enrollment-report', 'financial-statement'] },
        url: { type: String, validate: { validator: validateWebsiteURL, message: 'Invalid document URL' } },
        uploadedAt: { type: Date, default: Date.now },
        hash: { type: String }
    }],
    lastVerified: { type: Date },
    issues: [{ type: { type: String }, description: { type: String, maxlength: 500 }, resolved: { type: Boolean, default: false } }]
}, { _id: false });

const brandingSchema = new Schema({
    logo: { type: String, validate: { validator: validateWebsiteURL, message: 'Invalid logo URL' } },
    colors: { primary: { type: String }, secondary: { type: String } },
    mascot: { type: String, maxlength: 50 },
    slogan: { type: String, maxlength: 200 },
    missionStatement: { type: String, maxlength: 1000, set: v => v ? sanitizeHtml(v, { allowedTags: [], allowedAttributes: {} }) : v }
}, { _id: false });

const privacySchema = new Schema({
    isPublic: { type: Boolean, default: true, index: true },
    showContacts: { type: Boolean, default: true },
    showStats: { type: Boolean, default: true },
    showPrograms: { type: Boolean, default: true },
    searchable: { type: Boolean, default: true, index: true },
    visibleToAlumni: { type: Boolean, default: true },
    allowAlumniContact: { type: Boolean, default: true }
}, { _id: false });

const aiInsightsSchema = new Schema({
    reputationScore: { type: Number, min: 0, max: 100 },
    growthPotential: { type: String, enum: ['declining', 'stable', 'growing', 'expanding'] },
    marketPosition: { type: String, maxlength: 200 },
    competitorAnalysis: [{ schoolId: { type: Schema.Types.ObjectId, ref: 'School' }, similarity: { type: Number, min: 0, max: 100 } }],
    trendInsights: [{ metric: { type: String }, value: { type: Number }, period: { type: String } }],
    recommendedPrograms: [{ type: String, maxlength: 100 }],
    lastAnalyzed: { type: Date }
}, { _id: false });

const metadataSchema = new Schema({
    source: { type: String, default: 'manual', index: true },
    importSource: { type: String, enum: ['wikipedia', 'government-db', 'api', 'csv', 'user-submission'] },
    importId: { type: String },
    lastUpdated: { type: Date, default: Date.now },
    updateCount: { type: Number, default: 0, min: 0 },
    version: { type: Number, default: 1, min: 1 },
    duplicateOf: { type: Schema.Types.ObjectId },
    isDuplicate: { type: Boolean, default: false }
}, { _id: false });

const analyticsSchema = new Schema({
    profileViews: { type: Number, default: 0, min: 0 },
    searchAppearances: { type: Number, default: 0, min: 0 },
    applicationSubmissions: { type: Number, default: 0, min: 0 },
    lastViewed: { type: Date },
    engagementScore: { type: Number, default: 0, min: 0 },
    clickThroughRate: { type: Number, default: 0, min: 0, max: 100 },
    bounceRate: { type: Number, default: 0, min: 0, max: 100 }
}, { _id: false });

const statusSchema = new Schema({
    isActive: { type: Boolean, default: true, index: true },
    isDeleted: { type: Boolean, default: false, index: true },
    isFeatured: { type: Boolean, default: false },
    isPromoted: { type: Boolean, default: false },
    deletedAt: { type: Date },
    lastActiveAt: { type: Date, default: Date.now },
    workflow: { type: String, enum: ['draft', 'pending-review', 'published', 'archived'], default: 'published' }
}, { _id: false });

const socialSchema = new Schema({
    followers: [{ type: Schema.Types.ObjectId, ref: 'User' }],
    likes: [{ userId: { type: Schema.Types.ObjectId, ref: 'User' }, likedAt: { type: Date, default: Date.now } }],
    comments: [{ userId: { type: Schema.Types.ObjectId, ref: 'User' }, comment: { type: String, maxlength: 500, set: v => v ? sanitizeHtml(v, { allowedTags: [], allowedAttributes: {} }) : v }, commentedAt: { type: Date, default: Date.now } }],
    shares: [{ userId: { type: Schema.Types.ObjectId, ref: 'User' }, platform: { type: String }, sharedAt: { type: Date, default: Date.now } }]
}, { _id: false });

// Main School Schema
const schoolSchema = new Schema({
    _id: { type: Schema.Types.ObjectId, auto: true },
    name: { type: String, required: [true, 'School name is required'], trim: true, maxlength: 200, index: true, validate: { validator: validateSchoolName, message: 'Invalid school name format' } },
    abbreviation: { type: String, trim: true, maxlength: 10, uppercase: true, index: true },
    foundedYear: { type: Number, min: 1000, max: 2025 },
    description: { type: String, maxlength: 5000, trim: true, set: v => v ? sanitizeHtml(v, { allowedTags: [], allowedAttributes: {} }) : v, required: true },
    type: typeSchema,
    size: sizeSchema,
    location: addressSchema,
    accreditation: accreditationSchema,
    departments: [departmentSchema],
    programs: [programSchema],
    stats: statsSchema,
    ranking: rankingSchema,
    facilities: [facilitySchema],
    events: [eventSchema],
    alumni: alumniSchema,
    faculty: facultySchema,
    contact: contactSchema,
    verification: verificationSchema,
    branding: brandingSchema,
    privacy: privacySchema,
    aiInsights: aiInsightsSchema,
    metadata: metadataSchema,
    analytics: analyticsSchema,
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
    collection: 'schools',
    autoIndex: process.env.NODE_ENV !== 'production',
    readPreference: 'secondaryPreferred',
    writeConcern: { w: 'majority', wtimeout: 5000 },
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
    strict: 'throw'
});

// Indexes
schoolSchema.index({ name: 1, 'type.primary': 1, 'status.isActive': 1 });
schoolSchema.index({ 'location.country': 1, 'location.city': 1, 'type.level': 1 });
schoolSchema.index({ 'accreditation.bodies.status': 1, 'ranking.overallRank': 1 });
schoolSchema.index({ 'programs.fieldOfStudy': 1, 'type.primary': 1, 'verification.isVerified': 1 });
schoolSchema.index({ 'privacy.isPublic': 1, 'status.isActive': 1, 'analytics.engagementScore': -1, updatedAt: -1 });
schoolSchema.index({ 'size.category': 1, 'stats.avgRating': -1 });
schoolSchema.index({ 'aiInsights.reputationScore': 1, 'aiInsights.lastAnalyzed': -1 });
schoolSchema.index({ 'location.coordinates': '2dsphere' }, { sparse: true });
schoolSchema.index({ 'status.deletedAt': 1 }, { expireAfterSeconds: 7776000, sparse: true }); // 90 days
schoolSchema.index({
    name: 'text',
    description: 'text',
    abbreviation: 'text',
    'programs.name': 'text',
    'departments.name': 'text',
    'facilities.name': 'text',
    'cache.searchVector': 'text'
}, {
    weights: { name: 10, abbreviation: 8, description: 6, 'programs.name': 4, 'departments.name': 3, 'facilities.name': 2, 'cache.searchVector': 1 },
    name: 'school_text_search'
});
schoolSchema.index({ 'ranking.overallRank': 1, 'location.country': 1, 'type.primary': 1 }, { sparse: true });
schoolSchema.index({ 'size.totalEnrollment': -1, 'stats.graduationRate': -1 });
schoolSchema.index({ 'cache.popularityScore': -1, 'status.isActive': 1 }, { background: true });
schoolSchema.index({ 'cache.trendingScore': -1, 'privacy.isPublic': 1 }, { background: true });

// Virtuals
schoolSchema.virtual('totalPrograms').get(function () {
    return this.programs?.length || 0;
});
schoolSchema.virtual('totalDepartments').get(function () {
    return this.departments?.length || 0;
});
schoolSchema.virtual('totalFacilities').get(function () {
    return this.facilities?.length || 0;
});
schoolSchema.virtual('isTopRanked').get(function () {
    return this.ranking?.overallRank <= 100;
});
schoolSchema.virtual('verificationLevel').get(function () {
    const score = this.verification.score;
    if (score >= 90) return 'platinum';
    if (score >= 75) return 'gold';
    if (score >= 60) return 'silver';
    if (score >= 40) return 'bronze';
    return 'unverified';
});
schoolSchema.virtual('engagementLevel').get(function () {
    const score = this.analytics.engagementScore;
    if (score >= 80) return 'high';
    if (score >= 60) return 'medium';
    if (score >= 40) return 'low';
    return 'minimal';
});
schoolSchema.virtual('sizeCategory').get(function () {
    const total = this.size.totalEnrollment;
    if (total < 5000) return 'small';
    if (total < 20000) return 'medium';
    if (total < 50000) return 'large';
    return 'very-large';
});

// Middleware
schoolSchema.pre('save', async function (next) {
    try {
        // Update metadata
        this.metadata.lastUpdated = new Date();
        this.metadata.updateCount += 1;
        this.metadata.version += 1;

        // Generate search vector
        this.cache.searchVector = [
            this.name,
            this.abbreviation,
            this.description,
            ...this.programs.map(p => p.name),
            ...this.departments.map(d => d.name),
            ...this.facilities.map(f => f.name)
        ].filter(Boolean).join(' ').toLowerCase();

        // Calculate verification score
        if (this.verification.isVerified) {
            let score = 30;
            const methodScores = { 'official-website': 20, 'government-database': 30, 'accreditation-body': 25, 'api-sync': 15, 'alumni-verification': 10 };
            score += methodScores[this.verification.method] || 0;
            if (this.verification.documents?.length > 0) score += 20;
            if (this.accreditation.bodies?.length > 0 && this.accreditation.bodies.every(b => b.status === 'accredited')) score += 25;
            if (this.ranking.overallRank <= 500) score += 15;
            if (this.stats.avgRating >= 4.0) score += 10;
            this.verification.score = Math.min(score, 100);
        }

        // Calculate engagement score
        let engagementScore = 0;
        engagementScore += (this.analytics.profileViews || 0) * 0.1;
        engagementScore += (this.social.likes?.length || 0) * 2;
        engagementScore += (this.social.comments?.length || 0) * 3;
        engagementScore += (this.analytics.applicationSubmissions || 0) * 5;
        engagementScore += (this.verification.score || 0) * 0.2;
        this.analytics.engagementScore = Math.min(engagementScore, 1000);

        this.cache.popularityScore = this.calculatePopularityScore();
        this.cache.trendingScore = (this.analytics.engagementScore * 0.4) + (this.verification.score * 0.3) + (this.stats.avgRating * 20);

        // Update cache
        this.cache.lastCacheUpdate = new Date();
        this.cache.cacheVersion += 1;

        // Cache in Redis
        await redisClient.setEx(`school:${this._id}`, 300, JSON.stringify(this.toJSON()));

        // Publish updates
        await redisClient.publish('school_updates', JSON.stringify({
            schoolId: this._id,
            popularityScore: this.cache.popularityScore,
            trendingScore: this.cache.trendingScore
        }));

        // AI Insights
        if (!this.aiInsights.lastAnalyzed || (new Date() - this.aiInsights.lastAnalyzed) > 7 * 24 * 60 * 60 * 1000) {
            this.aiInsights.lastAnalyzed = new Date();
            this.aiInsights.reputationScore = (this.stats.avgRating * 20) + (this.ranking.overallRank ? (100 - this.ranking.overallRank / 10) : 0);
            this.aiInsights.growthPotential = this.stats.retentionRate > 80 ? 'growing' : 'stable';
        }

        // Update last active
        this.status.lastActiveAt = new Date();

        // Encrypt sensitive data if needed
        if (this.contact.generalEmail) {
            this.contact.generalEmail = await encryptField(this.contact.generalEmail);
        }

        next();
    } catch (error) {
        next(new Error(`Pre-save middleware error: ${error.message}`));
    }
});

schoolSchema.pre('remove', async function (next) {
    try {
        this.status.isDeleted = true;
        this.status.deletedAt = new Date();
        this.privacy.isPublic = false;
        this.privacy.searchable = false;
        await redisClient.del(`school:${this._id}`);
        await this.save();
        next();
    } catch (error) {
        next(new Error(`Pre-remove middleware error: ${error.message}`));
    }
});

schoolSchema.post('save', async function (doc) {
    try {
        // Update related educations or users if needed
        // For example, update school stats in educations
        const Education = mongoose.model('Education');
        await Education.updateMany(
            { schoolId: doc._id },
            { $set: { 'school.verification.isVerified': doc.verification.isVerified } }
        );

        // Sync to Algolia
        if (doc.privacy.searchable && doc.privacy.isPublic && doc.status.isActive) {
            try {
                await doc.syncToAlgolia();
            } catch (error) {
                console.error('Algolia sync error:', error.message);
            }
        }

        // Invalidate caches
        await redisClient.del(`schools:search:*`);
    } catch (error) {
        console.error('Post-save middleware error:', error.message);
    }
});

// Instance Methods
schoolSchema.methods.calculatePopularityScore = function () {
    const weights = { views: 0.3, likes: 0.2, comments: 0.2, applications: 0.2, verified: 0.1 };
    const viewScore = Math.log1p(this.analytics.profileViews) / Math.log1p(100000);
    const likeScore = Math.log1p(this.social.likes?.length || 0) / Math.log1p(10000);
    const commentScore = Math.log1p(this.social.comments?.length || 0) / Math.log1p(5000);
    const appScore = Math.log1p(this.analytics.applicationSubmissions) / Math.log1p(10000);
    const verifiedScore = this.verification.isVerified ? 1 : 0;
    return Math.min(100, (
        viewScore * weights.views +
        likeScore * weights.likes +
        commentScore * weights.comments +
        appScore * weights.applications +
        verifiedScore * weights.verified
    ) * 100);
};

schoolSchema.methods.syncToAlgolia = async function () {
    // Implementation for Algolia sync
    return Promise.resolve();
};

// Static Methods
schoolSchema.statics.getSchoolById = async function (schoolId, options = {}) {
    const { includePrivate = false } = options;
    const cacheKey = `school:${schoolId}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const query = { _id: new mongoose.Types.ObjectId(schoolId), 'status.isActive': true };
    if (!includePrivate) query['privacy.isPublic'] = true;

    const school = await this.findOne(query)
        .populate({ path: 'programs', select: 'name degreeLevel fieldOfStudy' })
        .populate({ path: 'departments', select: 'name programsOffered' })
        .populate({ path: 'alumni.notable', select: 'name achievement' })
        .lean({ virtuals: true });

    if (school) await redisClient.setEx(cacheKey, 3600, JSON.stringify(school));
    return school;
};

schoolSchema.statics.advancedSearch = async function (searchOptions = {}) {
    const { query = '', location = {}, types = [], accreditationStatus, minEnrollment, maxEnrollment = {}, minRating, rankingCategory, verified = false, hasPrograms = false, page = 1, limit = 20, sortBy = 'relevance' } = searchOptions;
    const cacheKey = `search:schools:${JSON.stringify(searchOptions)}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const pipeline = [
        {
            $match: {
                'status.isActive': true,
                'status.isDeleted': false,
                'privacy.isPublic': true,
                'privacy.searchable': true,
                ...(verified && { 'verification.isVerified': true }),
                ...(types.length > 0 && { 'type.primary': { $in: types } }),
                ...(accreditationStatus && { 'accreditation.bodies.status': accreditationStatus }),
                ...(location.country && { 'location.country': new RegExp(location.country, 'i') }),
                ...(location.city && { 'location.city': new RegExp(location.city, 'i') }),
                ...(hasPrograms && { 'programs.0': { $exists: true } }),
                ...(minEnrollment && { 'size.totalEnrollment': { $gte: minEnrollment } }),
                ...(maxEnrollment && { 'size.totalEnrollment': { $lte: maxEnrollment } }),
                ...(minRating && { 'stats.avgRating': { $gte: minRating } })
            }
        },
        ...(query ? [{ $match: { $text: { $search: query, $caseSensitive: false } } }, { $addFields: { textScore: { $meta: 'textScore' } } }] : []),
        { $lookup: { from: 'users', localField: 'social.followers', foreignField: '_id', as: 'followersData', pipeline: [{ $project: { name: 1, verified: 1 } }] } },
        {
            $addFields: {
                followerCount: { $size: '$social.followers' },
                relevanceScore: {
                    $add: [
                        { $multiply: [{ $ifNull: ['$textScore', 0] }, 0.3] },
                        { $multiply: [{ $divide: ['$stats.avgRating', 5] }, 0.25] },
                        { $multiply: [{ $divide: ['$verification.score', 100] }, 0.15] },
                        { $multiply: [{ $divide: [{ $min: ['$analytics.engagementScore', 100] }, 100] }, 0.1] },
                        { $multiply: [{ $size: { $ifNull: ['$programs', []] } }, 0.05] },
                        { $multiply: [{ $cond: [{ $gt: ['$ranking.overallRank', 0] }, { $subtract: [100, { $divide: ['$ranking.overallRank', 10] }] }, 0] }, 0.1] }
                    ]
                }
            }
        },
        { $sort: this.getSortQuery(sortBy) },
        {
            $project: {
                name: 1,
                abbreviation: 1,
                type: 1,
                location: { city: 1, state: 1, country: 1 },
                size: { totalEnrollment: 1, category: 1 },
                stats: { avgRating: 1, graduationRate: 1 },
                ranking: { overallRank: 1 },
                verification: { isVerified: 1, score: 1 },
                programs: { $slice: ['$programs', 5] },
                departments: { $size: { $ifNull: ['$departments', []] } },
                followerCount: 1,
                relevanceScore: 1,
                createdAt: 1,
                updatedAt: 1
            }
        }
    ];

    const results = await this.aggregatePaginate(pipeline, { page, limit, customLabels: { totalDocs: 'totalResults', docs: 'schools' } });
    await redisClient.setEx(cacheKey, 300, JSON.stringify(results)); // Shorter cache for search
    return results;
};

schoolSchema.statics.getSortQuery = function (sortBy) {
    const sortQueries = {
        'relevance': { relevanceScore: -1, 'verification.score': -1 },
        'rating': { 'stats.avgRating': -1, 'analytics.engagementScore': -1 },
        'enrollment': { 'size.totalEnrollment': -1 },
        'ranking': { 'ranking.overallRank': 1 },
        'popular': { 'cache.popularityScore': -1, 'analytics.profileViews': -1 },
        'alphabetical': { name: 1 }
    };
    return sortQueries[sortBy] || sortQueries['relevance'];
};

schoolSchema.statics.getTrendingSchools = async function (options = {}) {
    const { location, type, timeframe = 30, limit = 25 } = options;
    const cacheKey = `trending:schools:${JSON.stringify(options)}`;
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
                updatedAt: { $gte: startDate },
                ...(location && { 'location.country': location }),
                ...(type && { 'type.primary': type })
            }
        },
        {
            $facet: {
                trendingByViews: [
                    { $group: { _id: null, topSchools: { $push: { _id: '$_id', views: '$analytics.profileViews' } } } },
                    { $addFields: { topSchools: { $sortArray: { input: '$topSchools', sortBy: { views: -1 } } } } },
                    { $project: { schools: { $slice: ['$topSchools', limit] } } }
                ],
                trendingPrograms: [
                    { $unwind: '$programs' },
                    { $group: { _id: '$programs.fieldOfStudy', count: { $sum: 1 }, avgAdmissionRate: { $avg: '$programs.admissionRate' } } },
                    { $sort: { count: -1 } },
                    { $limit: limit },
                    { $project: { field: '$_id', programsOffered: '$count', avgAdmission: { $round: ['$avgAdmissionRate', 1] } } }
                ],
                enrollmentTrends: [
                    { $group: { _id: '$size.category', count: { $sum: 1 }, avgEnrollment: { $avg: '$size.totalEnrollment' } } },
                    { $sort: { count: -1 } }
                ]
            }
        }
    ];

    const results = await this.aggregate(pipeline);
    await redisClient.setEx(cacheKey, 86400, JSON.stringify(results));
    return results;
};

schoolSchema.statics.getAnalytics = async function (schoolId, options = {}) {
    const cacheKey = `analytics:school:${schoolId}:${JSON.stringify(options)}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const pipeline = [
        { $match: { _id: new mongoose.Types.ObjectId(schoolId), 'status.isActive': true } },
        {
            $group: {
                _id: null,
                totalPrograms: { $sum: { $size: '$programs' } },
                totalDepartments: { $sum: { $size: '$departments' } },
                avgAdmissionRate: { $avg: { $ifNull: ['$programs.admissionRate', 0] } },
                alumniSuccess: { $avg: '$alumni.successRate' },
                engagementMetrics: {
                    totalViews: { $sum: '$analytics.profileViews' },
                    totalApplications: { $sum: '$analytics.applicationSubmissions' },
                    avgEngagement: { $avg: '$analytics.engagementScore' }
                },
                diversityMetrics: { $push: '$stats.diversity' }
            }
        },
        {
            $project: {
                _id: 0,
                summary: {
                    programs: '$totalPrograms',
                    departments: '$totalDepartments',
                    avgAdmission: { $round: ['$avgAdmissionRate', 2] },
                    alumniSuccess: { $round: ['$alumniSuccess', 2] },
                    totalViews: '$engagementMetrics.totalViews',
                    totalApplications: '$engagementMetrics.totalApplications',
                    avgEngagement: { $round: ['$engagementMetrics.avgEngagement', 1] }
                },
                diversity: { $reduce: { input: '$diversityMetrics', initialValue: { gender: { female: 0, male: 0 }, ethnic: [] }, in: { /* complex reduction for averages */ } } }
            }
        }
    ];

    const results = await this.aggregate(pipeline);
    await redisClient.setEx(cacheKey, 43200, JSON.stringify(results[0] || {}));
    return results[0] || {};
};

schoolSchema.statics.bulkOperations = {
    updateVerification: async function (schoolIds, verificationData) {
        try {
            const bulkOps = schoolIds.map(id => ({
                updateOne: {
                    filter: { _id: new mongoose.Types.ObjectId(id), 'status.isActive': true },
                    update: { $set: { 'verification.isVerified': verificationData.isVerified, 'verification.verificationDate': new Date(), 'verification.score': verificationData.score, 'metadata.lastUpdated': new Date() } }
                }
            }));
            const result = await this.bulkWrite(bulkOps);
            for (const id of schoolIds) await redisClient.del(`school:${id}`);
            return result;
        } catch (error) {
            throw new Error(`Bulk verification update error: ${error.message}`);
        }
    },
    updateStats: async function (schoolIds, statsUpdates) {
        try {
            const bulkOps = schoolIds.map(id => ({
                updateOne: {
                    filter: { _id: new mongoose.Types.ObjectId(id) },
                    update: { $set: { stats: statsUpdates, 'metadata.lastUpdated': new Date() } }
                }
            }));
            const result = await this.bulkWrite(bulkOps);
            for (const id of schoolIds) await redisClient.del(`school:${id}`);
            return result;
        } catch (error) {
            throw new Error(`Bulk stats update error: ${error.message}`);
        }
    },
    archiveInactive: async function (cutoffDate) {
        try {
            const inactiveSchools = await this.find({ lastActiveAt: { $lt: cutoffDate }, 'status.isActive': true }).lean();
            if (inactiveSchools.length === 0) return { archived: 0 };
            const ArchiveSchool = mongoose.model('ArchiveSchool', schoolSchema, 'archive_schools');
            await ArchiveSchool.insertMany(inactiveSchools);
            const result = await this.updateMany(
                { _id: { $in: inactiveSchools.map(s => s._id) } },
                { $set: { 'status.isActive': false, 'status.archivedAt': new Date() } }
            );
            for (const sch of inactiveSchools) await redisClient.del(`school:${sch._id}`);
            return { archived: result.modifiedCount };
        } catch (error) {
            throw new Error(`Archive inactive schools error: ${error.message}`);
        }
    }
};

schoolSchema.statics.getAIInsights = async function (options = {}) {
    const { type = 'reputation', limit = 10 } = options;
    const cacheKey = `ai:insights:schools:${type}:${limit}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const pipeline = [
        { $match: { 'status.isActive': true, 'privacy.isPublic': true } },
        {
            $group: {
                _id: null,
                topSchools: { $push: { _id: '$_id', reputation: { $multiply: [{ $add: [{ $divide: ['$stats.avgRating', 5] }, { $cond: [{ $lt: [{ $ifNull: ['$ranking.overallRank', 1000] }, 1000] }, { $subtract: [1, { $divide: [{ $ifNull: ['$ranking.overallRank', 1000] }, 1000] }] }, 0] }] }, 100] } } },
                marketTrends: { $push: { enrollment: '$size.totalEnrollment', rating: '$stats.avgRating' } }
            }
        },
        {
            $addFields: {
                insights: {
                    $switch: {
                        branches: [
                            { case: { $eq: [type, 'reputation'] }, then: { topRanked: { $slice: [{ $sortArray: { input: '$topSchools', sortBy: { reputation: -1 } } }, limit] } } },
                            { case: { $eq: [type, 'growth'] }, then: { growingSchools: { $filter: { input: '$topSchools', cond: { $gt: [{ $size: { $ifNull: ['$programs', []] } }, 10] } } } } }
                        ],
                        default: { message: 'Invalid insight type' }
                    }
                }
            }
        },
        { $project: { _id: 0, insights: 1 } }
    ];

    const results = await this.aggregate(pipeline);
    await redisClient.setEx(cacheKey, 43200, JSON.stringify(results[0]));
    return results[0];
};

schoolSchema.statics.getPerformanceMetrics = async function (timeframe = '30d') {
    const cacheKey = `performance:metrics:schools:${timeframe}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const startDate = new Date();
    const days = parseInt(timeframe.replace('d', ''));
    startDate.setDate(startDate.getDate() - days);
    const pipeline = [
        {
            $match: { 'metadata.lastUpdated': { $gte: startDate } }
        },
        {
            $facet: {
                queryStats: [{ $group: { _id: null, totalQueries: { $sum: 1 }, avgEngagement: { $avg: '$analytics.engagementScore' } } }],
                dataQuality: [
                    {
                        $group: {
                            _id: null,
                            totalRecords: { $sum: 1 },
                            verifiedRecords: { $sum: { $cond: ['$verification.isVerified', 1, 0] } },
                            completeProfiles: { $sum: { $cond: [{ $and: [{ $ne: ['$name', ''] }, { $gt: [{ $size: { $ifNull: ['$programs', []] } }, 0] }] }, 1, 0] } }
                        }
                    },
                    { $addFields: { verificationRate: { $multiply: [{ $divide: ['$verifiedRecords', '$totalRecords'] }, 100] }, completenessRate: { $multiply: [{ $divide: ['$completeRecords', '$totalRecords'] }, 100] } } }
                ]
            }
        }
    ];

    const results = await this.aggregate(pipeline);
    await redisClient.setEx(cacheKey, 86400, JSON.stringify(results[0]));
    return results[0];
};

schoolSchema.statics.cleanupIndexes = async function () {
    const indexes = await this.collection.indexes();
    const essentialIndexes = ['_id_', 'school_text_search', 'name_1_type.primary_1_status.isActive_1'];
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

schoolSchema.statics.initChangeStream = function () {
    const changeStream = this.watch([{ $match: { 'operationType': { $in: ['insert', 'update', 'replace'] } } }]);
    changeStream.on('change', async (change) => {
        const schoolId = change.documentKey._id.toString();
        await redisClient.del(`school:${schoolId}`);
        await redisClient.publish('school_updates', JSON.stringify({
            schoolId,
            operation: change.operationType,
            updatedFields: change.updateDescription?.updatedFields
        }));
    });
    return changeStream;
};

// Placeholder for encryption
async function encryptField(value) {
    return crypto.createHash('sha256').update(value).digest('hex');
}

// Plugins
schoolSchema.plugin(aggregatePaginate);
if (process.env.ALGOLIA_APP_ID && process.env.ALGOLIA_ADMIN_KEY) {
    schoolSchema.plugin(mongooseAlgolia, {
        appId: process.env.ALGOLIA_APP_ID,
        apiKey: process.env.ALGOLIA_ADMIN_KEY,
        indexName: 'schools',
        selector: 'name description programs.name location.city location.country cache.searchVector',
        defaults: { author: 'unknown' },
        mappings: { name: v => v || '', description: v => v || '', 'programs.name': v => v || [], 'location.city': v => v || '', 'location.country': v => v || '', 'cache.searchVector': v => v || '' },
        debug: process.env.NODE_ENV === 'development'
    });
} else {
    console.warn('Algolia plugin not initialized: Missing env vars');
}

// Production Indexes
if (process.env.NODE_ENV === 'production') {
    schoolSchema.index({ 'cache.popularityScore': -1, 'status.isActive': 1 }, { background: true });
    schoolSchema.index({ 'cache.trendingScore': -1, 'privacy.isPublic': 1 }, { background: true });
}

export default mongoose.model('School', schoolSchema);