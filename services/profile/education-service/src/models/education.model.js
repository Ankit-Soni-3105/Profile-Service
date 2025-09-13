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
const validateGPA = (value) => !value || (typeof value === 'number' && value >= 0 && value <= 4.0);
const validateTranscriptURL = (value) => !value || validator.isURL(value, { require_protocol: true });
const validateSchoolName = (value) => /^[a-zA-Z0-9\s\-&().,]+$/.test(value);
const validateCourseCode = (value) => /^[A-Z]{2,4}\s?\d{3,4}[A-Z]?$/.test(value);
const validateCreditHours = (value) => typeof value === 'number' && value > 0 && value <= 20;
const validateThesisTitle = (value) => value && value.trim().length > 0 && value.trim().length <= 200;

// Sub-Schemas
const locationSchema = new Schema({
    city: { type: String, trim: true, maxlength: 50, index: true },
    state: { type: String, trim: true, maxlength: 50 },
    country: { type: String, trim: true, maxlength: 50, index: true },
    zipCode: { type: String, trim: true, maxlength: 10, validate: { validator: value => !value || /^[0-9]{5}(-[0-9]{4})?$/.test(value), message: 'Invalid zip code format' } },
    timezone: { type: String, trim: true, maxlength: 50 },
    coordinates: { type: { type: String, enum: ['Point'], default: 'Point' }, coordinates: { type: [Number], index: '2dsphere' } },
    isOnline: { type: Boolean, default: false, index: true }
}, { _id: false });

const academicDurationSchema = new Schema({
    startDate: { type: Date, required: [true, 'Start date is required'], index: true },
    endDate: { type: Date, index: true },
    isCurrent: { type: Boolean, default: false, index: true },
    expectedEndDate: { type: Date },
    enrollmentStatus: { type: String, enum: ['enrolled', 'on-leave', 'withdrawn', 'graduated'], default: 'enrolled', index: true }
}, { _id: false });

const gpaSchema = new Schema({
    overall: { type: Number, min: 0, max: 4.0, validate: { validator: validateGPA, message: 'GPA must be between 0 and 4.0' } },
    major: { type: Number, min: 0, max: 4.0, validate: { validator: validateGPA, message: 'Major GPA must be between 0 and 4.0' } },
    semesterBreakdown: [{
        semester: { type: String, maxlength: 20 },
        gpa: { type: Number, min: 0, max: 4.0, validate: { validator: validateGPA, message: 'Semester GPA must be between 0 and 4.0' } },
        credits: { type: Number, min: 0, max: 200 }
    }],
    isCumulative: { type: Boolean, default: true },
    scale: { type: String, enum: ['4.0', '5.0', '10.0', 'percentage'], default: '4.0' }
}, { _id: false });

const courseSchema = new Schema({
    code: { type: String, trim: true, maxlength: 20, required: true, validate: { validator: validateCourseCode, message: 'Invalid course code format' } },
    title: { type: String, trim: true, maxlength: 200, required: true },
    credits: { type: Number, required: true, validate: { validator: validateCreditHours, message: 'Credits must be between 0 and 20' } },
    grade: { type: String, enum: ['A', 'A-', 'B+', 'B', 'B-', 'C+', 'C', 'C-', 'D+', 'D', 'D-', 'F', 'P', 'W'], required: true },
    semester: { type: String, maxlength: 20 },
    instructor: { type: String, maxlength: 100 },
    description: { type: String, maxlength: 1000, set: v => v ? sanitizeHtml(v, { allowedTags: [], allowedAttributes: {} }) : v },
    isCore: { type: Boolean, default: false },
    difficultyLevel: { type: String, enum: ['easy', 'medium', 'hard', 'very-hard'], default: 'medium' },
    skillsGained: [{ type: String, maxlength: 50 }],
    performance: { type: Number, min: 0, max: 100, default: 0 } // Percentage or score
}, { _id: false });

const honorSchema = new Schema({
    title: { type: String, maxlength: 200, required: true },
    description: { type: String, maxlength: 500 },
    type: { type: String, enum: ['deans-list', 'presidents-list', 'scholarship', 'fellowship', 'award', 'grant', 'recognition', 'honor-society'], required: true },
    dateReceived: { type: Date, required: true },
    issuedBy: { type: String, maxlength: 100, required: true },
    gpaRequirement: { type: Number, min: 0, max: 4.0 },
    verificationUrl: { type: String, validate: { validator: value => !value || validator.isURL(value, { require_protocol: true }), message: 'Invalid verification URL' } },
    mediaAttachments: [{ type: Schema.Types.ObjectId, ref: 'Media' }],
    isPublic: { type: Boolean, default: true },
    prestigeLevel: { type: String, enum: ['local', 'regional', 'national', 'international'], default: 'local' }
}, { _id: false });

const thesisSchema = new Schema({
    title: { type: String, maxlength: 200, required: true, validate: { validator: validateThesisTitle, message: 'Thesis title is required and must be 1-200 characters' } },
    abstract: { type: String, maxlength: 2000 },
    supervisor: { type: Schema.Types.ObjectId, ref: 'User', required: true }, // Advisor
    committee: [{ type: Schema.Types.ObjectId, ref: 'User' }],
    defenseDate: { type: Date },
    grade: { type: String, enum: ['pass', 'pass-with-distinction', 'fail', 'revised'], default: 'pass' },
    publicationStatus: { type: String, enum: ['draft', 'submitted', 'published', 'under-review'], default: 'draft' },
    url: { type: String, validate: { validator: value => !value || validator.isURL(value, { require_protocol: true }), message: 'Invalid thesis URL' } },
    citations: { type: Number, default: 0, min: 0 },
    impactFactor: { type: Number, min: 0, max: 100 },
    mediaAttachments: [{ type: Schema.Types.ObjectId, ref: 'Media' }],
    isPublic: { type: Boolean, default: true }
}, { _id: false });

const advisorSchema = new Schema({
    advisorId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    advisorName: { type: String, maxlength: 100 },
    role: { type: String, enum: ['thesis-supervisor', 'academic-advisor', 'research-mentor', 'career-counselor'], required: true },
    relationshipStart: { type: Date, required: true },
    relationshipEnd: { type: Date },
    feedback: { type: String, maxlength: 1000, set: v => v ? sanitizeHtml(v, { allowedTags: [], allowedAttributes: {} }) : v },
    recommendation: { type: String, enum: ['strong', 'positive', 'neutral', 'cautious'], default: 'positive' },
    isCurrent: { type: Boolean, default: true }
}, { _id: false });

const studyAbroadSchema = new Schema({
    hostInstitution: { type: Schema.Types.ObjectId, ref: 'School', required: true },
    programName: { type: String, maxlength: 200, required: true },
    location: locationSchema,
    duration: academicDurationSchema,
    creditsTransferred: { type: Number, min: 0, max: 60 },
    coursesTaken: [courseSchema],
    culturalExperiences: { type: String, maxlength: 1000 },
    languageLearned: { type: String, maxlength: 50 },
    isExchange: { type: Boolean, default: false },
    fundingSource: { type: String, maxlength: 100 },
    mediaAttachments: [{ type: Schema.Types.ObjectId, ref: 'Media' }]
}, { _id: false });

const academicProjectSchema = new Schema({
    name: { type: String, maxlength: 100, required: true },
    description: { type: String, maxlength: 1000, required: true },
    role: { type: String, maxlength: 100 },
    subjects: [{ type: String, maxlength: 50 }],
    startDate: { type: Date, required: true },
    endDate: { type: Date },
    url: { type: String, validate: { validator: value => !value || validator.isURL(value, { require_protocol: true }), message: 'Invalid project URL' } },
    teamSize: { type: Number, min: 1, max: 100 },
    budget: { type: Number, min: 0 },
    impact: { type: String, maxlength: 300 },
    isOngoing: { type: Boolean, default: false },
    grade: { type: String, enum: ['A', 'B', 'C', 'D', 'F'], default: 'A' },
    mediaAttachments: [{ type: Schema.Types.ObjectId, ref: 'Media' }],
    presentationCount: { type: Number, default: 0, min: 0 },
    publicationCount: { type: Number, default: 0, min: 0 }
}, { _id: false });

const recommendationSchema = new Schema({
    recommenderId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    recommenderName: { type: String, maxlength: 100 },
    recommenderTitle: { type: String, maxlength: 100 },
    recommenderInstitution: { type: String, maxlength: 100 },
    relationship: { type: String, enum: ['professor', 'advisor', 'peer', 'ta', 'alumni', 'other'], required: true },
    recommendedAt: { type: Date, default: Date.now },
    comment: { type: String, maxlength: 1000, set: v => v ? sanitizeHtml(v, { allowedTags: [], allowedAttributes: {} }) : v, required: true },
    rating: { type: Number, min: 1, max: 5, required: true },
    strengths: [{ type: String, maxlength: 50 }],
    isVerified: { type: Boolean, default: false },
    isPublic: { type: Boolean, default: true },
    verificationUrl: { type: String, validate: { validator: value => !value || validator.isURL(value, { require_protocol: true }), message: 'Invalid verification URL' } }
}, { _id: false });

const academicVerificationSchema = new Schema({
    isVerified: { type: Boolean, default: false, index: true },
    verifiedBy: { type: Schema.Types.ObjectId, ref: 'User' },
    verificationDate: { type: Date },
    verificationMethod: { type: String, enum: ['transcript', 'diploma', 'registrar-contact', 'professor', 'alumni-association', 'national-database', 'self-report'], required: true },
    verificationScore: { type: Number, min: 0, max: 100, default: 0 },
    documents: [{
        type: { type: String, enum: ['transcript', 'diploma', 'enrollment-certificate', 'degree-certificate', 'recommendation-letter'] },
        url: { type: String, validate: { validator: validateTranscriptURL, message: 'Invalid document URL' } },
        uploadedAt: { type: Date, default: Date.now },
        hash: { type: String } // For integrity
    }],
    registrarEmail: { type: String, validate: { validator: validator.isEmail, message: 'Invalid registrar email' } },
    registrarVerified: { type: Boolean, default: false },
    degreeConferred: { type: Boolean, default: false },
    conferredDate: { type: Date }
}, { _id: false });

const privacySchema = new Schema({
    isPublic: { type: Boolean, default: true, index: true },
    showDuration: { type: Boolean, default: true },
    showGPA: { type: Boolean, default: false },
    showGrades: { type: Boolean, default: false },
    showRecommendations: { type: Boolean, default: true },
    visibleToConnections: { type: Boolean, default: true },
    visibleToAlumni: { type: Boolean, default: true },
    visibleToRecruiters: { type: Boolean, default: true },
    searchable: { type: Boolean, default: true, index: true },
    allowContactFromAlumni: { type: Boolean, default: true },
    showExtracurriculars: { type: Boolean, default: true }
}, { _id: false });

const fundingSchema = new Schema({
    amount: { type: Number, min: 0 },
    currency: { type: String, maxlength: 3, default: 'USD' },
    type: { type: String, enum: ['scholarship', 'grant', 'fellowship', 'loan', 'tuition-waiver', 'work-study'], default: 'scholarship' },
    isEstimate: { type: Boolean, default: false },
    duration: { type: String, enum: ['one-time', 'semester', 'annual', 'full-program'] },
    benefits: [{ type: { type: String, enum: ['tuition-coverage', 'stipend', 'housing', 'books', 'research-funding', 'other'] }, value: { type: String, maxlength: 100 } }],
    renewalCriteria: { type: String, maxlength: 500 }
}, { _id: false });

const academicPerformanceSchema = new Schema({
    overallGPA: gpaSchema,
    classRank: { type: Number, min: 1 },
    totalCredits: { type: Number, min: 0, max: 200 },
    creditsCompleted: { type: Number, min: 0, max: 200 },
    thesisGrade: { type: String, enum: ['pass', 'pass-with-distinction', 'fail'] },
    comprehensiveExam: { type: String, enum: ['passed', 'failed', 'pending'], default: 'pending' },
    publications: [{ title: { type: String, maxlength: 200 }, journal: { type: String, maxlength: 100 }, date: { type: Date }, impactFactor: { type: Number, min: 0 } }],
    presentations: [{ title: { type: String, maxlength: 200 }, venue: { type: String, maxlength: 100 }, date: { type: Date } }],
    extracurriculars: [{ name: { type: String, maxlength: 100 }, role: { type: String, maxlength: 100 }, duration: academicDurationSchema, achievements: { type: String, maxlength: 500 } }],
    awardsCount: { type: Number, default: 0, min: 0 },
    recognitions: [{ type: String, maxlength: 200, date: { type: Date } }]
}, { _id: false });

const academicConnectionsSchema = new Schema({
    peers: [{ userId: { type: Schema.Types.ObjectId, ref: 'User' }, relationship: { type: String, enum: ['classmate', 'study-group', 'project-partner'] }, connectedAt: { type: Date, default: Date.now } }],
    professors: [{ userId: { type: Schema.Types.ObjectId, ref: 'User' }, startDate: { type: Date }, endDate: { type: Date }, courses: [{ type: String }] }],
    alumni: [{ userId: { type: Schema.Types.ObjectId, ref: 'User' }, graduationYear: { type: Number }, major: { type: String } }],
    mentors: [{ userId: { type: Schema.Types.ObjectId, ref: 'User' }, relationship: { type: String, enum: ['academic-mentor', 'career-mentor', 'research-mentor'] }, startDate: { type: Date } }]
}, { _id: false });

const aiInsightsSchema = new Schema({
    skillGaps: [{ type: String, maxlength: 50 }],
    careerAlignment: { type: String, maxlength: 200 },
    employabilityScore: { type: Number, min: 0, max: 100, default: 0 },
    marketDemand: { type: String, enum: ['low', 'medium', 'high', 'very-high'] },
    similarPrograms: [{ type: String, maxlength: 100 }],
    industryTrends: [{ type: String, maxlength: 100 }],
    recommendedCourses: [{ type: String, maxlength: 50 }],
    alumniOutcomes: { avgSalary: { type: Number, min: 0 }, employmentRate: { type: Number, min: 0, max: 100 } },
    lastAnalyzed: { type: Date }
}, { _id: false });

const metadataSchema = new Schema({
    source: { type: String, default: 'manual', index: true },
    importSource: { type: String, enum: ['linkedin', 'university-portal', 'manual', 'api', 'csv-import', 'transcript-scan'] },
    importId: { type: String },
    templateId: { type: Schema.Types.ObjectId },
    lastUpdated: { type: Date, default: Date.now },
    updateCount: { type: Number, default: 0, min: 0 },
    version: { type: Number, default: 1, min: 1 },
    duplicateOf: { type: Schema.Types.ObjectId },
    isDuplicate: { type: Boolean, default: false },
    transcriptHash: { type: String } // For deduplication
}, { _id: false });

const analyticsSchema = new Schema({
    profileViews: { type: Number, default: 0, min: 0 },
    connectionRequests: { type: Number, default: 0, min: 0 },
    lastViewed: { type: Date },
    viewersCount: { type: Number, default: 0, min: 0 },
    shareCount: { type: Number, default: 0, min: 0 },
    likesCount: { type: Number, default: 0, min: 0 },
    commentsCount: { type: Number, default: 0, min: 0 },
    searchAppearances: { type: Number, default: 0, min: 0 },
    clickThroughRate: { type: Number, default: 0, min: 0, max: 100 },
    engagementScore: { type: Number, default: 0, min: 0 }
}, { _id: false });

const statusSchema = new Schema({
    isActive: { type: Boolean, default: true, index: true },
    isDeleted: { type: Boolean, default: false, index: true },
    isFeatured: { type: Boolean, default: false },
    isPromoted: { type: Boolean, default: false },
    isPremium: { type: Boolean, default: false },
    isSponsored: { type: Boolean, default: false },
    deletedAt: { type: Date },
    archivedAt: { type: Date },
    featuredUntil: { type: Date },
    lastActiveAt: { type: Date, default: Date.now },
    workflow: { type: String, enum: ['draft', 'pending-review', 'published', 'archived'], default: 'published' },
    verificationStatus: { type: String, enum: ['pending', 'verified', 'rejected', 'expired'], default: 'pending' }
}, { _id: false });

const socialSchema = new Schema({
    likes: [{ userId: { type: Schema.Types.ObjectId, ref: 'User' }, likedAt: { type: Date, default: Date.now } }],
    comments: [{ userId: { type: Schema.Types.ObjectId, ref: 'User' }, comment: { type: String, maxlength: 500, set: v => v ? sanitizeHtml(v, { allowedTags: [], allowedAttributes: {} }) : v }, commentedAt: { type: Date, default: Date.now }, isPublic: { type: Boolean, default: true } }],
    shares: [{ userId: { type: Schema.Types.ObjectId, ref: 'User' }, platform: { type: String, enum: ['linkedin', 'twitter', 'facebook', 'email', 'internal'] }, sharedAt: { type: Date, default: Date.now } }],
    bookmarks: [{ userId: { type: Schema.Types.ObjectId, ref: 'User' }, bookmarkedAt: { type: Date, default: Date.now } }]
}, { _id: false });

// Main Education Schema
const educationSchema = new Schema({
    _id: { type: Schema.Types.ObjectId, auto: true },
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: [true, 'User ID is required'], index: true },
    schoolId: { type: Schema.Types.ObjectId, ref: 'School', required: [true, 'School ID is required'], index: true },
    degree: { type: String, required: [true, 'Degree is required'], trim: true, maxlength: 100, index: true, enum: ['associate', 'bachelor', 'master', 'doctorate', 'certificate', 'diploma', 'postdoc'] },
    fieldOfStudy: { type: String, required: [true, 'Field of study is required'], trim: true, maxlength: 100, index: true },
    specialization: { type: String, trim: true, maxlength: 100 },
    accreditation: { type: String, enum: ['accredited', 'unaccredited', 'pending'], default: 'accredited', index: true },
    location: locationSchema,
    duration: academicDurationSchema,
    description: { type: String, maxlength: 5000, trim: true, set: v => v ? sanitizeHtml(v, { allowedTags: [], allowedAttributes: {} }) : v },
    gpa: gpaSchema,
    courses: [courseSchema],
    honors: [honorSchema],
    thesis: thesisSchema,
    advisors: [advisorSchema],
    studyAbroad: [studyAbroadSchema],
    projects: [academicProjectSchema],
    recommendations: [recommendationSchema],
    verification: academicVerificationSchema,
    privacy: privacySchema,
    funding: [fundingSchema],
    performance: academicPerformanceSchema,
    connections: academicConnectionsSchema,
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
    collection: 'educations',
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
educationSchema.index({ userId: 1, 'duration.startDate': -1, 'status.isActive': 1 });
educationSchema.index({ schoolId: 1, degree: 1, 'status.isActive': 1 });
educationSchema.index({ 'location.country': 1, 'location.city': 1, accreditation: 1 });
educationSchema.index({ fieldOfStudy: 1, degree: 1, 'verification.isVerified': 1 });
educationSchema.index({ 'courses.code': 1, degree: 1, 'verification.isVerified': 1, 'privacy.searchable': 1 });
educationSchema.index({ 'privacy.isPublic': 1, 'status.isActive': 1, 'analytics.engagementScore': -1, updatedAt: -1 });
educationSchema.index({ 'duration.isCurrent': 1, userId: 1, 'status.workflow': 1 });
educationSchema.index({ 'aiInsights.marketDemand': 1, 'aiInsights.lastAnalyzed': -1 });
educationSchema.index({ 'location.coordinates': '2dsphere' }, { sparse: true });
educationSchema.index({ 'status.deletedAt': 1 }, { expireAfterSeconds: 7776000, sparse: true }); // 90 days
educationSchema.index({
    degree: 'text',
    fieldOfStudy: 'text',
    specialization: 'text',
    description: 'text',
    'courses.title': 'text',
    'honors.title': 'text',
    'projects.name': 'text',
    'cache.searchVector': 'text'
}, {
    weights: { degree: 10, fieldOfStudy: 8, specialization: 6, description: 4, 'courses.title': 3, 'honors.title': 2, 'projects.name': 1, 'cache.searchVector': 1 },
    name: 'education_text_search'
});
educationSchema.index({ 'gpa.overall': 1, 'location.country': 1, degree: 1 }, { sparse: true });
educationSchema.index({ accreditation: 1, 'location.isOnline': 1, 'duration.isCurrent': 1 });
educationSchema.index({ 'cache.popularityScore': -1, 'status.isActive': 1 }, { background: true });
educationSchema.index({ 'cache.trendingScore': -1, 'privacy.isPublic': 1 }, { background: true });

// Virtuals
educationSchema.virtual('durationInSemesters').get(function () {
    const endDate = this.duration.endDate || new Date();
    const startDate = this.duration.startDate;
    const months = Math.ceil(Math.abs(endDate - startDate) / (1000 * 60 * 60 * 24 * 30.44));
    return Math.ceil(months / 4.33); // Approx semester length
});
educationSchema.virtual('durationInYears').get(function () {
    return Math.floor(this.durationInSemesters / 2);
});
educationSchema.virtual('durationFormatted').get(function () {
    const years = this.durationInYears;
    const semesters = this.durationInSemesters % 2;
    if (years === 0) return `${semesters} semester${semesters !== 1 ? 's' : ''}`;
    if (semesters === 0) return `${years} year${years !== 1 ? 's' : ''}`;
    return `${years} year${years !== 1 ? 's' : ''} ${semesters} semester${semesters !== 1 ? 's' : ''}`;
});
educationSchema.virtual('coursesCount').get(function () {
    return this.courses?.length || 0;
});
educationSchema.virtual('recommendationCount').get(function () {
    return this.recommendations?.length || 0;
});
educationSchema.virtual('honorCount').get(function () {
    return this.honors?.length || 0;
});
educationSchema.virtual('projectCount').get(function () {
    return this.projects?.length || 0;
});
educationSchema.virtual('isRecent').get(function () {
    const fiveYearsAgo = new Date();
    fiveYearsAgo.setFullYear(fiveYearsAgo.getFullYear() - 5);
    return this.duration.startDate >= fiveYearsAgo;
});
educationSchema.virtual('verificationLevel').get(function () {
    const score = this.verification.verificationScore;
    if (score >= 90) return 'platinum';
    if (score >= 75) return 'gold';
    if (score >= 60) return 'silver';
    if (score >= 40) return 'bronze';
    return 'unverified';
});
educationSchema.virtual('engagementLevel').get(function () {
    const score = this.analytics.engagementScore;
    if (score >= 80) return 'viral';
    if (score >= 60) return 'high';
    if (score >= 40) return 'medium';
    if (score >= 20) return 'low';
    return 'minimal';
});
educationSchema.virtual('gpaRange').get(function () {
    if (!this.gpa.overall) return null;
    const gpa = this.gpa.overall;
    if (gpa < 2.0) return 'low';
    if (gpa < 3.0) return 'average';
    if (gpa < 3.7) return 'good';
    return 'excellent';
});

// Middleware
educationSchema.pre('save', async function (next) {
    try {
        // Auto-set isCurrent flag
        if (this.duration.endDate && this.duration.isCurrent) this.duration.isCurrent = false;
        else if (!this.duration.endDate && !this.duration.isCurrent) this.duration.isCurrent = true;

        // Update metadata
        this.metadata.lastUpdated = new Date();
        this.metadata.updateCount += 1;
        this.metadata.version += 1;

        // Generate search vector
        this.cache.searchVector = [
            this.degree,
            this.fieldOfStudy,
            this.description,
            this.specialization,
            ...this.courses.map(c => c.title),
            ...this.honors.map(h => h.title),
            ...this.projects.map(p => p.name)
        ].filter(Boolean).join(' ').toLowerCase();

        // Calculate verification score
        if (this.verification.isVerified) {
            let score = 30;
            const methodScores = { 'transcript': 25, 'diploma': 25, 'registrar-contact': 20, 'national-database': 30, 'professor': 15, 'alumni-association': 15, 'self-report': 5 };
            score += methodScores[this.verification.verificationMethod] || 0;
            if (this.verification.documents?.length > 0) score += 15;
            if (this.verification.registrarVerified) score += 10;
            if (this.recommendations?.length > 0) score += Math.min(this.recommendations.length * 2, 20);
            if (this.honors?.length > 0) score += Math.min(this.honors.length * 3, 15);
            if (this.thesis) score += 10;
            this.verification.verificationScore = Math.min(score, 100);
        }

        // Calculate engagement and popularity scores
        let engagementScore = 0;
        engagementScore += (this.analytics.profileViews || 0) * 0.1;
        engagementScore += (this.analytics.likesCount || 0) * 2;
        engagementScore += (this.analytics.commentsCount || 0) * 3;
        engagementScore += (this.analytics.shareCount || 0) * 5;
        engagementScore += (this.recommendationCount || 0) * 4;
        engagementScore += (this.verification.verificationScore || 0) * 0.2;
        this.analytics.engagementScore = Math.min(engagementScore, 1000);

        this.cache.popularityScore = this.calculatePopularityScore();
        this.cache.trendingScore = (this.analytics.engagementScore * 0.4) + (this.verification.verificationScore * 0.3) + (this.recommendationCount * 0.3);

        // Update cache metadata
        this.cache.lastCacheUpdate = new Date();
        this.cache.cacheVersion += 1;

        // Cache in Redis
        await redisClient.setEx(`education:${this._id}`, 300, JSON.stringify(this.toJSON()));

        // Publish score updates
        await redisClient.publish('education_updates', JSON.stringify({
            educationId: this._id,
            popularityScore: this.cache.popularityScore,
            trendingScore: this.cache.trendingScore
        }));

        // AI Insights
        if (!this.aiInsights.lastAnalyzed || (new Date() - this.aiInsights.lastAnalyzed) > 7 * 24 * 60 * 60 * 1000) {
            this.aiInsights.lastAnalyzed = new Date();
            this.aiInsights.recommendedCourses = this.courses?.map(course => course.title) || [];
            // Simulate employability score based on GPA, honors, etc.
            let employability = 50;
            if (this.gpa.overall >= 3.5) employability += 20;
            if (this.honors.length > 2) employability += 15;
            if (this.projects.length > 0) employability += 10;
            if (this.thesis) employability += 5;
            this.aiInsights.employabilityScore = Math.min(employability, 100);
        }

        // Update last active
        this.status.lastActiveAt = new Date();

        // Encrypt sensitive fields (e.g., GPA if private)
        if (this.gpa.overall && !this.privacy.showGPA) {
            this.gpa.overall = await encryptField(this.gpa.overall.toString());
            this.gpa.major = await encryptField(this.gpa.major?.toString() || '');
        }

        next();
    } catch (error) {
        next(new Error(`Pre-save middleware error: ${error.message}`));
    }
});

educationSchema.pre('remove', async function (next) {
    try {
        this.status.isDeleted = true;
        this.status.deletedAt = new Date();
        this.privacy.isPublic = false;
        this.privacy.searchable = false;
        await redisClient.del(`education:${this._id}`);
        await this.save();
        next();
    } catch (error) {
        next(new Error(`Pre-remove middleware error: ${error.message}`));
    }
});

educationSchema.post('save', async function (doc) {
    try {
        // Update User profile
        const User = mongoose.model('User');
        await User.updateOne(
            { _id: doc.userId },
            { $set: { 'profile.lastUpdated': new Date() }, $inc: { 'analytics.profileUpdates': 1 } }
        );

        // Update School stats
        const School = mongoose.model('School');
        await School.updateOne(
            { _id: doc.schoolId },
            { $inc: { 'stats.alumniCount': doc.duration.enrollmentStatus === 'graduated' ? 1 : 0 }, $set: { 'analytics.lastCalculated': new Date() } }
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
        await redisClient.del(`user:educations:${doc.userId}`);
    } catch (error) {
        console.error('Post-save middleware error:', error.message);
    }
});

// Instance Methods
educationSchema.methods.calculatePopularityScore = function () {
    const weights = { views: 0.3, likes: 0.2, comments: 0.2, shares: 0.2, recommendations: 0.2, verified: 0.1 };
    const viewScore = Math.log1p(this.analytics.profileViews) / Math.log1p(10000);
    const likeScore = Math.log1p(this.analytics.likesCount) / Math.log1p(1000);
    const commentScore = Math.log1p(this.analytics.commentsCount) / Math.log1p(500);
    const shareScore = Math.log1p(this.analytics.shareCount) / Math.log1p(500);
    const recommendationScore = Math.log1p(this.recommendationCount) / Math.log1p(100);
    const verifiedScore = this.verification.isVerified ? 1 : 0;
    return Math.min(100, (
        viewScore * weights.views +
        likeScore * weights.likes +
        commentScore * weights.comments +
        shareScore * weights.shares +
        recommendationScore * weights.recommendations +
        verifiedScore * weights.verified
    ) * 100);
};

educationSchema.methods.syncToAlgolia = async function () {
    // Implementation for Algolia sync (assuming plugin handles it)
    return Promise.resolve();
};

// Static Methods
educationSchema.statics.getUserEducations = async function (userId, options = {}) {
    const { page = 1, limit = 10, sortBy = 'startDate', sortOrder = -1, includeDeleted = false, filters = {}, includePrivate = false } = options;
    const cacheKey = `user:educations:${userId}:${JSON.stringify(options)}`;
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
        .populate({ path: 'schoolId', select: 'name branding.logo type size location stats.avgRating verification.isVerified' })
        .populate({ path: 'honors', select: 'title type dateReceived isPublic' })
        .populate({ path: 'recommendations.recommenderId', select: 'name profilePic headline verification.isVerified' })
        .populate({ path: 'media', select: 'url type title' })
        .select('-connections.peers -metadata.importId')
        .lean({ virtuals: true });

    await redisClient.setEx(cacheKey, 3600, JSON.stringify(results));
    return results;
};

educationSchema.statics.advancedSearch = async function (searchOptions = {}) {
    const { query = '', location = {}, fieldsOfStudy = [], degree, accreditation, gpaMin, gpaMax = {}, schoolType, verified = false, hasThesis = false, hasHonors = false, enrollmentStatus = {}, page = 1, limit = 20, sortBy = 'relevance', userId = null } = searchOptions;
    const cacheKey = `search:educations:${JSON.stringify(searchOptions)}`;
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
                ...(degree && { degree }),
                ...(accreditation && { accreditation }),
                ...(location.country && { 'location.country': new RegExp(location.country, 'i') }),
                ...(location.city && { 'location.city': new RegExp(location.city, 'i') }),
                ...(location.isOnline !== undefined && { 'location.isOnline': location.isOnline }),
                ...(hasThesis && { thesis: { $exists: true, $ne: {} } }),
                ...(hasHonors && { 'honors.0': { $exists: true } }),
                ...(enrollmentStatus && { 'duration.enrollmentStatus': enrollmentStatus })
            }
        },
        ...(query ? [{ $match: { $text: { $search: query, $caseSensitive: false } } }, { $addFields: { textScore: { $meta: 'textScore' } } }] : []),
        ...(fieldsOfStudy.length > 0 ? [
            { $addFields: { fieldMatchScore: { $divide: [{ $size: { $setIntersection: [fieldsOfStudy, { $map: { input: '$courses', as: 'course', in: '$$course.skillsGained' } }] } }, fieldsOfStudy.length] } } },
            { $match: { fieldMatchScore: { $gt: 0 } } }
        ] : []),
        ...(gpaMin || gpaMax ? [
            { $addFields: { totalGPAMatch: { $and: [{ $gte: [{ $ifNull: ['$gpa.overall', 0] }, gpaMin || 0] }, { $lte: [{ $ifNull: ['$gpa.overall', 4.0] }, gpaMax || 4.0] }] } } },
            { $match: { totalGPAMatch: true } }
        ] : []),
        { $lookup: { from: 'schools', localField: 'schoolId', foreignField: '_id', as: 'school', pipeline: [{ $project: { name: 1, 'branding.logo': 1, 'type.primary': 1, 'size.category': 1, 'stats.avgRating': 1, 'verification.isVerified': 1, 'locations.address': 1, contact: 1, description: 1 } }] } },
        { $unwind: { path: '$school', preserveNullAndEmptyArrays: true } },
        ...(schoolType ? [{ $match: { 'school.type.primary': schoolType } }] : []),
        { $lookup: { from: 'users', localField: 'userId', foreignField: '_id', as: 'userProfile', pipeline: [{ $project: { name: 1, profilePic: 1, headline: 1, location: 1, 'verification.isVerified': 1, premium: 1, connectionCount: { $size: { $ifNull: ['$connections', []] } }, followerCount: { $size: { $ifNull: ['$followers', []] } } } }] } },
        { $unwind: { path: '$userProfile', preserveNullAndEmptyArrays: true } },
        ...(userId ? [{ $addFields: { networkBoost: { $cond: [{ $in: [new mongoose.Types.ObjectId(userId), '$userProfile.connections'] }, 0.3, { $cond: [{ $in: [new mongoose.Types.ObjectId(userId), '$userProfile.followers'] }, 0.1, 0] }] } } }] : []),
        {
            $addFields: {
                relevanceScore: {
                    $add: [
                        { $multiply: [{ $ifNull: ['$textScore', 0] }, 0.3] },
                        { $multiply: [{ $ifNull: ['$fieldMatchScore', 0] }, 0.25] },
                        { $multiply: [{ $divide: ['$verification.verificationScore', 100] }, 0.15] },
                        { $multiply: [{ $divide: [{ $min: ['$analytics.engagementScore', 100] }, 100] }, 0.1] },
                        { $multiply: [{ $ifNull: ['$school.stats.avgRating', 0] }, 0.05] },
                        { $multiply: [{ $cond: ['$userProfile.premium', 1, 0] }, 0.05] },
                        { $ifNull: ['$networkBoost', 0] },
                        { $multiply: [{ $divide: [{ $subtract: [new Date(), '$duration.startDate'] }, 1000 * 60 * 60 * 24 * 365 * 5] }, -0.05] },
                        { $multiply: [{ $add: [{ $cond: [{ $gt: [{ $size: { $ifNull: ['$honors', []] } }, 0] }, 0.02, 0] }, { $cond: [{ $gt: [{ $size: { $ifNull: ['$projects', []] } }, 0] }, 0.02, 0] }, { $cond: [{ $gt: [{ $size: { $ifNull: ['$recommendations', []] } }, 0] }, 0.01, 0] }] }, 10] }
                    ]
                },
                popularityScore: this.calculatePopularityScore()
            }
        },
        { $sort: this.getSortQuery(sortBy) },
        {
            $project: {
                userId: 1,
                degree: 1,
                fieldOfStudy: 1,
                specialization: 1,
                accreditation: 1,
                location: { $cond: ['$privacy.showLocation', '$location', { country: '$location.country', isOnline: '$location.isOnline' }] },
                duration: { $cond: ['$privacy.showDuration', '$duration', { isCurrent: '$duration.isCurrent' }] },
                description: { $cond: ['$privacy.showExtracurriculars', { $substr: ['$description', 0, 200] }, null] },
                courses: { $slice: [{ $filter: { input: '$courses', cond: { $ne: ['$this.title', ''] } } }, 10] },
                honors: { $cond: ['$privacy.showHonors', { $size: { $ifNull: ['$honors', []] } }, 0] },
                projects: { $cond: ['$privacy.showProjects', { $size: { $ifNull: ['$projects', []] } }, 0] },
                verification: { isVerified: '$verification.isVerified', level: '$verification.verificationScore' },
                gpa: { $cond: ['$privacy.showGPA', { overall: '$gpa.overall', range: '$gpaRange' }, null] },
                school: 1,
                userProfile: { name: '$userProfile.name', profilePic: '$userProfile.profilePic', headline: '$userProfile.headline', verified: '$userProfile.verified', premium: '$userProfile.premium' },
                recommendationCount: { $size: { $ifNull: ['$recommendations', []] } },
                relevanceScore: 1,
                popularityScore: 1,
                createdAt: 1,
                updatedAt: 1,
                durationSemesters: { $divide: [{ $subtract: [{ $ifNull: ['$duration.endDate', new Date()] }, '$duration.startDate'] }, 1000 * 60 * 60 * 24 * 30.44 * 2] } // Approx per semester
            }
        }
    ];

    const results = await this.aggregatePaginate(pipeline, { page, limit, customLabels: { totalDocs: 'totalResults', docs: 'educations' } });
    await redisClient.setEx(cacheKey, 60, JSON.stringify(results));
    return results;
};

educationSchema.statics.getSortQuery = function (sortBy) {
    const sortQueries = {
        'relevance': { relevanceScore: -1, 'verification.verificationScore': -1 },
        'recent': { 'duration.startDate': -1, updatedAt: -1 },
        'popular': { 'cache.popularityScore': -1, 'analytics.profileViews': -1 },
        'gpa-high': { 'gpa.overall': -1 },
        'gpa-low': { 'gpa.overall': 1 },
        'duration': { durationSemesters: -1 },
        'verified': { 'verification.verificationScore': -1, 'verification.isVerified': -1 },
        'alphabetical': { fieldOfStudy: 1, 'school.name': 1 }
    };
    return sortQueries[sortBy] || sortQueries['relevance'];
};

educationSchema.statics.getTrendingInsights = async function (options = {}) {
    const { location, timeframe = 30, fieldOfStudy, limit = 25 } = options;
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
                ...(location && { 'location.country': location })
            }
        },
        { $lookup: { from: 'schools', localField: 'schoolId', foreignField: '_id', as: 'school' } },
        { $unwind: { path: '$school', preserveNullAndEmptyArrays: true } },
        ...(fieldOfStudy ? [{ $match: { fieldOfStudy: new RegExp(fieldOfStudy, 'i') } }] : []),
        {
            $facet: {
                trendingDegrees: [
                    { $group: { _id: { degree: '$degree', fieldOfStudy: '$fieldOfStudy' }, count: { $sum: 1 }, avgGPA: { $avg: '$gpa.overall' }, uniqueSchools: { $addToSet: '$schoolId' }, totalRecommendations: { $sum: { $size: { $ifNull: ['$recommendations', []] } } }, avgVerificationScore: { $avg: '$verification.verificationScore' } } },
                    { $addFields: { schoolCount: { $size: '$uniqueSchools' }, trendScore: { $multiply: ['$count', { $add: [{ $size: '$uniqueSchools' }, 1] }, { $add: [{ $divide: ['$totalRecommendations', 10] }, 1] }] } } },
                    { $sort: { trendScore: -1 } },
                    { $limit: limit },
                    { $project: { degree: '$_id.degree', fieldOfStudy: '$_id.fieldOfStudy', occurrences: '$count', avgGPA: { $round: ['$avgGPA', 2] }, schoolCount: 1, trendScore: 1, avgVerificationScore: { $round: ['$avgVerificationScore', 1] } } }
                ],
                trendingCourses: [
                    { $unwind: '$courses' },
                    { $group: { _id: '$courses.title', count: { $sum: 1 }, avgGrade: { $avg: { $switch: { branches: [{ case: { $eq: ['$courses.grade', 'A'] }, then: 4.0 }, { case: { $eq: ['$courses.grade', 'A-'] }, then: 3.7 }, { case: { $eq: ['$courses.grade', 'B+'] }, then: 3.3 }, { case: { $eq: ['$courses.grade', 'B'] }, then: 3.0 }, { case: { $eq: ['$courses.grade', 'B-'] }, then: 2.7 }, { case: { $eq: ['$courses.grade', 'C+'] }, then: 2.3 }, { case: { $eq: ['$courses.grade', 'C'] }, then: 2.0 }, { case: { $eq: ['$courses.grade', 'C-'] }, then: 1.7 }, { case: { $eq: ['$courses.grade', 'D+'] }, then: 1.3 }, { case: { $eq: ['$courses.grade', 'D'] }, then: 1.0 }, { case: { $eq: ['$courses.grade', 'D-'] }, then: 0.7 }, { case: { $eq: ['$courses.grade', 'F'] }, then: 0.0 }], default: 0.0 } } }, endorsements: { $sum: { $cond: ['$courses.isCore', 1, 0] } }, associatedGPAs: { $push: '$gpa.overall' } } },
                    { $addFields: { avgGPA: { $avg: { $filter: { input: '$associatedGPAs', cond: { $gt: ['$this', 0] } } } }, coreRate: { $divide: ['$endorsements', '$count'] } } },
                    { $sort: { count: -1 } },
                    { $limit: limit },
                    { $project: { course: '$_id', frequency: '$count', averageGrade: { $round: ['$avgGrade', 2] }, coreRate: { $round: ['$coreRate', 2] }, averageGPA: { $round: ['$avgGPA', 2] } } }
                ],
                enrollmentTrends: [
                    { $group: { _id: '$duration.enrollmentStatus', count: { $sum: 1 }, avgGPA: { $avg: '$gpa.overall' } } },
                    { $sort: { count: -1 } },
                    { $project: { status: '$_id', count: 1, avgGPA: { $round: ['$avgGPA', 2] }, percentage: { $multiply: [{ $divide: ['$count', { $sum: '$count' }] }, 100] } } }
                ],
                accreditationTrends: [
                    { $group: { _id: '$accreditation', count: { $sum: 1 } } },
                    { $sort: { count: -1 } }
                ]
            }
        }
    ];

    const results = await this.aggregate(pipeline);
    await redisClient.setEx(cacheKey, 86400, JSON.stringify(results));
    return results;
};

educationSchema.statics.getAcademicAnalytics = async function (userId, options = {}) {
    const cacheKey = `academic:analytics:${userId}:${JSON.stringify(options)}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const pipeline = [
        { $match: { userId: new mongoose.Types.ObjectId(userId), 'status.isActive': true, 'status.isDeleted': false } },
        { $sort: { 'duration.startDate': 1 } },
        { $lookup: { from: 'schools', localField: 'schoolId', foreignField: '_id', as: 'school' } },
        { $unwind: { path: '$school', preserveNullAndEmptyArrays: true } },
        {
            $group: {
                _id: null,
                educations: {
                    $push: {
                        degree: '$degree',
                        fieldOfStudy: '$fieldOfStudy',
                        school: '$school.name',
                        type: '$school.type.primary',
                        schoolSize: '$school.size.category',
                        startDate: '$duration.startDate',
                        endDate: '$duration.endDate',
                        isCurrent: '$duration.isCurrent',
                        enrollmentStatus: '$duration.enrollmentStatus',
                        gpa: '$gpa.overall',
                        courses: { $size: '$courses' },
                        honors: { $size: { $ifNull: ['$honors', []] } },
                        projects: { $size: { $ifNull: ['$projects', []] } },
                        recommendations: { $size: { $ifNull: ['$recommendations', []] } },
                        verificationScore: '$verification.verificationScore',
                        funding: { $size: { $ifNull: ['$funding', []] } }
                    }
                },
                totalCredits: { $sum: { $sum: '$courses.credits' } },
                avgGPA: { $avg: '$gpa.overall' },
                degreeChanges: { $sum: 1 },
                uniqueSchools: { $addToSet: '$schoolId' },
                uniqueFields: { $addToSet: '$fieldOfStudy' },
                allCourses: { $push: '$courses' },
                totalRecommendations: { $sum: { $size: { $ifNull: ['$recommendations', []] } } },
                totalHonors: { $sum: { $size: { $ifNull: ['$honors', []] } } },
                totalProjects: { $sum: { $size: { $ifNull: ['$projects', []] } } },
                gpaProgression: { $push: { $cond: [{ $gt: ['$gpa.overall', 0] }, { date: '$duration.startDate', gpa: '$gpa.overall', degree: '$degree' }, null] } },
                accreditationProgression: { $push: '$accreditation' }
            }
        },
        {
            $addFields: {
                schoolCount: { $size: '$uniqueSchools' },
                fieldCount: { $size: '$uniqueFields' },
                courseEvolution: { $reduce: { input: '$allCourses', initialValue: [], in: { $setUnion: ['$value', { $map: { input: '$this', as: 'course', in: '$course.title' } }] } } },
                cleanGPAProgression: { $filter: { input: '$gpaProgression', cond: { $ne: ['$this', null] } } },
                avgGPAYears: { $round: ['$avgGPA', 2] },
                totalDurationYears: { $divide: [{ $subtract: [{ $ifNull: [{ $max: '$educations.endDate' }, new Date()] }, { $min: '$educations.startDate' }] }, 1000 * 60 * 60 * 24 * 365.25] },
                academicVelocity: { $cond: [{ $gt: ['$totalDurationYears', 0] }, { $divide: ['$degreeChanges', '$totalDurationYears'] }, 0] }
            }
        },
        {
            $project: {
                _id: 0,
                summary: { totalCredits: { $round: ['$totalCredits', 0] }, avgGPA: '$avgGPAYears', degreeChanges: '$degreeChanges', schoolCount: '$schoolCount', fieldCount: '$fieldCount', totalRecommendations: '$totalRecommendations', totalHonors: '$totalHonors', totalProjects: '$totalProjects', academicVelocity: { $round: ['$academicVelocity', 2] } },
                educations: '$educations',
                progression: { gpa: '$cleanGPAProgression', accreditation: '$accreditationProgression' },
                courses: { total: { $size: '$courseEvolution' }, evolution: '$courseEvolution' },
                diversity: { schools: '$schoolCount', fields: '$fieldCount' }
            }
        }
    ];

    const results = await this.aggregate(pipeline);
    await redisClient.setEx(cacheKey, 43200, JSON.stringify(results));
    return results;
};

educationSchema.statics.getMarketInsights = async function (options = {}) {
    const { degree, location, fieldOfStudy, gpaMin, gpaMax = {}, schoolType, yearsEnrolled } = options;
    const cacheKey = `market:insights:${JSON.stringify(options)}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const pipeline = [
        { $match: { 'status.isActive': true, 'status.isDeleted': false, 'privacy.isPublic': true, 'gpa.overall': { $gt: 0 }, ...(degree && { degree: new RegExp(degree, 'i') }), ...(location && { 'location.country': location }), ...(fieldOfStudy && { fieldOfStudy: new RegExp(fieldOfStudy, 'i') }) } },
        { $lookup: { from: 'schools', localField: 'schoolId', foreignField: '_id', as: 'school' } },
        { $unwind: { path: '$school', preserveNullAndEmptyArrays: true } },
        ...(schoolType ? [{ $match: { 'school.type.primary': schoolType } }] : []),
        { $addFields: { enrollmentYears: { $divide: [{ $subtract: [{ $ifNull: ['$duration.endDate', new Date()] }, '$duration.startDate'] }, 1000 * 60 * 60 * 24 * 365.25] } } },
        ...(yearsEnrolled ? [{ $match: { enrollmentYears: { $gte: yearsEnrolled.min || 0, $lte: yearsEnrolled.max || 10 } } }] : []),
        ...(gpaMin || gpaMax ? [{ $match: { 'gpa.overall': { $gte: gpaMin || 0, $lte: gpaMax || 4.0 } } }] : []),
        {
            $group: {
                _id: { degree: '$degree', fieldOfStudy: '$fieldOfStudy', country: '$location.country' },
                avgGPA: { $avg: '$gpa.overall' },
                medianGPA: { $push: '$gpa.overall' },
                minGPA: { $min: '$gpa.overall' },
                maxGPA: { $max: '$gpa.overall' },
                gpaCount: { $sum: 1 },
                avgEnrollment: { $avg: '$enrollmentYears' },
                totalRecommendations: { $sum: { $size: { $ifNull: ['$recommendations', []] } } },
                schoolsAttended: { $addToSet: '$schoolId' },
                commonCourses: { $push: '$courses' },
                enrollmentStatuses: { $push: '$duration.enrollmentStatus' },
                samples: { $push: { school: '$school.name', gpa: '$gpa.overall', enrollment: '$enrollmentYears', verified: '$verification.isVerified' } }
            }
        },
        {
            $addFields: {
                medianGPA: { $let: { vars: { sortedGPAs: { $sortArray: { input: '$medianGPA', sortBy: 1 } } }, in: { $arrayElemAt: ['$sortedGPAs', { $floor: { $divide: [{ $size: '$sortedGPAs' }, 2] } }] } } },
                gpaP25: { $let: { vars: { sortedGPAs: { $sortArray: { input: '$medianGPA', sortBy: 1 } } }, in: { $arrayElemAt: ['$sortedGPAs', { $floor: { $multiply: [{ $size: '$sortedGPAs' }, 0.25] } }] } } },
                gpaP75: { $let: { vars: { sortedGPAs: { $sortArray: { input: '$medianGPA', sortBy: 1 } } }, in: { $arrayElemAt: ['$sortedGPAs', { $floor: { $multiply: [{ $size: '$sortedGPAs' }, 0.75] } }] } } },
                attendingSchoolCount: { $size: '$schoolsAttended' },
                topCourses: { $slice: [{ $map: { input: { $setUnion: [{ $reduce: { input: '$commonCourses', initialValue: [], in: { $concatArrays: ['$value', '$this'] } } }] }, as: 'course', in: '$course.title' } }, 10] }
            }
        },
        { $sort: { gpaCount: -1 } },
        { $limit: 20 },
        { $project: { degree: '$_id.degree', fieldOfStudy: '$_id.fieldOfStudy', location: '$_id.country', gpaInsights: { average: { $round: ['$avgGPA', 2] }, median: { $round: ['$medianGPA', 2] }, min: '$minGPA', max: '$maxGPA', percentile25: { $round: ['$gpaP25', 2] }, percentile75: { $round: ['$gpaP75', 2] }, sampleSize: '$gpaCount' }, marketMetrics: { avgEnrollment: { $round: ['$avgEnrollment', 1] }, attendingSchoolCount: '$attendingSchoolCount', totalRecommendations: '$totalRecommendations' }, topCourses: '$topCourses', sampleData: { $slice: ['$samples', 5] } } }
    ];

    const results = await this.aggregate(pipeline);
    await redisClient.setEx(cacheKey, 86400, JSON.stringify(results));
    return results;
};

educationSchema.statics.bulkOperations = {
    updateVerification: async function (educationIds, verificationData) {
        try {
            const bulkOps = educationIds.map(id => ({
                updateOne: {
                    filter: { _id: new mongoose.Types.ObjectId(id), 'status.isActive': true },
                    update: { $set: { 'verification.isVerified': verificationData.isVerified, 'verification.verificationDate': new Date(), 'verification.verifiedBy': verificationData.verifiedBy, 'verification.verificationMethod': verificationData.method, 'metadata.lastUpdated': new Date() } }
                }
            }));
            const result = await this.bulkWrite(bulkOps);
            for (const id of educationIds) await redisClient.del(`education:${id}`);
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
            await redisClient.del(`user:educations:${userId}`);
            return result;
        } catch (error) {
            throw new Error(`Bulk privacy update error: ${error.message}`);
        }
    },
    archiveOldEducations: async function (cutoffDate) {
        try {
            const oldEducations = await this.find({ 'duration.endDate': { $lt: cutoffDate }, 'status.isActive': true, 'status.isDeleted': false }).lean();
            if (oldEducations.length === 0) return { archived: 0 };
            const ArchiveEducation = mongoose.model('ArchiveEducation', educationSchema, 'archive_educations');
            await ArchiveEducation.insertMany(oldEducations);
            const result = await this.updateMany(
                { _id: { $in: oldEducations.map(e => e._id) } },
                { $set: { 'status.isActive': false, 'status.archivedAt': new Date(), 'metadata.lastUpdated': new Date() } }
            );
            for (const edu of oldEducations) await redisClient.del(`education:${edu._id}`);
            return { archived: result.modifiedCount };
        } catch (error) {
            throw new Error(`Archive old educations error: ${error.message}`);
        }
    },
    updateCourses: async function (educationIds, courseUpdates) {
        try {
            const bulkOps = educationIds.map(id => ({
                updateOne: {
                    filter: { _id: new mongoose.Types.ObjectId(id) },
                    update: { $set: { courses: courseUpdates, 'metadata.lastUpdated': new Date(), 'metadata.updateCount': { $inc: 1 } } }
                }
            }));
            const result = await this.bulkWrite(bulkOps);
            for (const id of educationIds) await redisClient.del(`education:${id}`);
            return result;
        } catch (error) {
            throw new Error(`Bulk courses update error: ${error.message}`);
        }
    },
    addRecommendation: async function (educationIds, recommendationData) {
        try {
            const bulkOps = educationIds.map(id => ({
                updateOne: {
                    filter: { _id: new mongoose.Types.ObjectId(id) },
                    update: { $push: { recommendations: recommendationData }, $inc: { 'analytics.recommendationCount': 1 } }
                }
            }));
            const result = await this.bulkWrite(bulkOps);
            for (const id of educationIds) await redisClient.del(`education:${id}`);
            return result;
        } catch (error) {
            throw new Error(`Bulk recommendation add error: ${error.message}`);
        }
    }
};

educationSchema.statics.getAIRecommendations = async function (userId, options = {}) {
    const { type = 'career-growth', limit = 10 } = options;
    const cacheKey = `ai:recommendations:${userId}:${type}:${limit}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const pipeline = [
        { $match: { userId: new mongoose.Types.ObjectId(userId), 'status.isActive': true } },
        { $group: { _id: null, currentFields: { $push: '$fieldOfStudy' }, degrees: { $addToSet: '$degree' }, currentGPA: { $last: '$gpa.overall' }, totalEnrollment: { $sum: { $divide: [{ $subtract: [{ $ifNull: ['$duration.endDate', new Date()] }, '$duration.startDate'] }, 1000 * 60 * 60 * 24 * 365.25] } } } },
        { $lookup: { from: 'educations', pipeline: [{ $match: { 'status.isActive': true, 'privacy.isPublic': true, userId: { $ne: new mongoose.Types.ObjectId(userId) } } }, { $sample: { size: 1000 } }], as: 'marketData' } },
        {
            $project: {
                recommendations: {
                    $switch: {
                        branches: [
                            { case: { $eq: [type, 'career-growth'] }, then: { nextDegrees: { $cond: [{ $eq: [{ $last: '$degrees' }, 'bachelor'] }, ['master', 'doctorate'], { $eq: [{ $last: '$degrees' }, 'master'] }, ['doctorate', 'postdoc'], ['advanced-certification']] }, fieldsToExplore: { $slice: [{ $setDifference: [{ $reduce: { input: '$marketData.fieldOfStudy', initialValue: [], in: { $setUnion: ['$value', ['$this']] } } }, '$currentFields'] }, limit] }, targetEmployability: { min: { $add: ['$currentGPA', 0.5] }, max: 4.0 } } },
                            { case: { $eq: [type, 'skill-development'] }, then: { trendingFields: { $slice: [{ $reduce: { input: '$marketData.fieldOfStudy', initialValue: [], in: { $setUnion: ['$value', ['$this']] } } }, limit] }, fieldGaps: { $slice: [{ $setDifference: [{ $reduce: { input: '$marketData.fieldOfStudy', initialValue: [], in: { $setUnion: ['$value', ['$this']] } } }, '$currentFields'] }, limit] } } },
                            { case: { $eq: [type, 'networking'] }, then: { recommendedConnections: { $slice: [{ $reduce: { input: '$marketData.userId', initialValue: [], in: { $setUnion: ['$value', '$this'] } } }, limit] } } }
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

educationSchema.statics.getPerformanceMetrics = async function (timeframe = '30d') {
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
                indexStats: [{ $group: { _id: '$metadata.source', count: { $sum: 1 }, avgVerificationScore: { $avg: '$verification.verificationScore' } } }],
                dataQuality: [
                    {
                        $group: {
                            _id: null,
                            totalRecords: { $sum: 1 },
                            completeProfiles: { $sum: { $cond: [{ $and: [{ $ne: ['$degree', ''] }, { $ne: ['$fieldOfStudy', ''] }, { $gt: [{ $size: { $ifNull: ['$courses', []] } }, 0] }] }, 1, 0] } },
                            verifiedRecords: { $sum: { $cond: ['$verification.isVerified', 1, 0] } },
                            withGPAInfo: { $sum: { $cond: [{ $gt: ['$gpa.overall', 0] }, 1, 0] } },
                            withRecommendations: { $sum: { $cond: [{ $gt: [{ $size: { $ifNull: ['$recommendations', []] } }, 0] }, 1, 0] } }
                        }
                    },
                    { $addFields: { completenessRate: { $multiply: [{ $divide: ['$completeProfiles', '$totalRecords'] }, 100] }, verificationRate: { $multiply: [{ $divide: ['$verifiedRecords', '$totalRecords'] }, 100] }, gpaTransparency: { $multiply: [{ $divide: ['$withGPAInfo', '$totalRecords'] }, 100] }, recommendationRate: { $multiply: [{ $divide: ['$withRecommendations', '$totalRecords'] }, 100] } } }
                ]
            }
        }
    ];

    const results = await this.aggregate(pipeline);
    await redisClient.setEx(cacheKey, 86400, JSON.stringify(results));
    return results;
};

educationSchema.statics.cleanupIndexes = async function () {
    const indexes = await this.collection.indexes();
    const essentialIndexes = ['_id_', 'education_text_search', 'userId_1_duration.startDate_-1_status.isActive_1', 'schoolId_1_degree_1_status.isActive_1'];
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

educationSchema.statics.initChangeStream = function () {
    const changeStream = this.watch([{ $match: { 'operationType': { $in: ['insert', 'update', 'replace'] } } }]);
    changeStream.on('change', async (change) => {
        const educationId = change.documentKey._id.toString();
        await redisClient.del(`education:${educationId}`);
        await redisClient.publish('education_updates', JSON.stringify({
            educationId,
            operation: change.operationType,
            updatedFields: change.updateDescription?.updatedFields
        }));
    });
    return changeStream;
};

// Placeholder for CSFLE
async function encryptField(value) {
    // Requires MongoDB CSFLE setup
    // Example similar to experience model
    return crypto.createHash('sha256').update(value).digest('hex');
}

// Plugins
educationSchema.plugin(aggregatePaginate);
if (process.env.ALGOLIA_APP_ID && process.env.ALGOLIA_ADMIN_KEY) {
    educationSchema.plugin(mongooseAlgolia, {
        appId: process.env.ALGOLIA_APP_ID,
        apiKey: process.env.ALGOLIA_ADMIN_KEY,
        indexName: 'educations',
        selector: 'degree fieldOfStudy courses.title location.city location.country schoolId cache.searchVector',
        defaults: { author: 'unknown' },
        mappings: { degree: v => v || '', fieldOfStudy: v => v || '', 'courses.title': v => v || [], 'location.city': v => v || '', 'location.country': v => v || '', 'cache.searchVector': v => v || '' },
        debug: process.env.NODE_ENV === 'development'
    });
} else {
    console.warn('Algolia plugin not initialized: Missing ALGOLIA_APP_ID or ALGOLIA_ADMIN_KEY');
}

// Production Indexes
if (process.env.NODE_ENV === 'production') {
    educationSchema.index({ 'cache.popularityScore': -1, 'status.isActive': 1 }, { background: true });
    educationSchema.index({ 'cache.trendingScore': -1, 'privacy.isPublic': 1 }, { background: true });
}

export default mongoose.model('Education', educationSchema);