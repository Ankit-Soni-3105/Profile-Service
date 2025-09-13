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
const validateCourseCode = (value) => /^[A-Z]{2,4}\s?\d{3,4}[A-Z]?$/.test(value);
const validateCourseTitle = (value) => value && value.trim().length > 0 && value.trim().length <= 200;
const validateCreditHours = (value) => typeof value === 'number' && value > 0 && value <= 20;
const validateURL = (value) => !value || validator.isURL(value, { require_protocol: true });
const validateEmail = (value) => !value || validator.isEmail(value);
const validateGrade = (value) => ['A', 'A-', 'B+', 'B', 'B-', 'C+', 'C', 'C-', 'D+', 'D', 'D-', 'F', 'P', 'W', 'I'].includes(value);
const validateDifficultyLevel = (value) => ['easy', 'medium', 'hard', 'very-hard'].includes(value);

// Sub-Schemas
const instructorSchema = new Schema({
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    name: { type: String, maxlength: 100, required: true },
    email: { type: String, validate: { validator: validateEmail, message: 'Invalid instructor email' } },
    department: { type: String, maxlength: 100 },
    role: { type: String, enum: ['professor', 'adjunct', 'lecturer', 'ta'], default: 'professor' },
    rating: { type: Number, min: 0, max: 5 },
    officeHours: { type: String, maxlength: 100 },
    verificationStatus: { type: String, enum: ['verified', 'pending', 'unverified'], default: 'unverified' }
}, { _id: false });

const scheduleSchema = new Schema({
    days: [{ type: String, enum: ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'] }],
    startTime: { type: String, match: /^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/ },
    endTime: { type: String, match: /^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/ },
    location: { type: String, maxlength: 100 },
    room: { type: String, maxlength: 50 },
    isOnline: { type: Boolean, default: false },
    timezone: { type: String, maxlength: 50 }
}, { _id: false });

const prerequisiteSchema = new Schema({
    courseId: { type: Schema.Types.ObjectId, ref: 'Course' },
    code: { type: String, validate: { validator: validateCourseCode, message: 'Invalid prerequisite course code' } },
    minimumGrade: { type: String, validate: { validator: validateGrade, message: 'Invalid prerequisite grade' } },
    isMandatory: { type: Boolean, default: true }
}, { _id: false });

const learningOutcomeSchema = new Schema({
    description: { type: String, maxlength: 500, required: true },
    category: { type: String, enum: ['knowledge', 'skill', 'application', 'analysis', 'synthesis'], required: true },
    bloomLevel: { type: String, enum: ['remember', 'understand', 'apply', 'analyze', 'evaluate', 'create'], required: true },
    assessmentCriteria: { type: String, maxlength: 500 }
}, { _id: false });

const resourceSchema = new Schema({
    type: { type: String, enum: ['textbook', 'article', 'video', 'website', 'lab-material', 'other'], required: true },
    title: { type: String, maxlength: 200, required: true },
    url: { type: String, validate: { validator: validateURL, message: 'Invalid resource URL' } },
    isbn: { type: String, maxlength: 13, match: /^[0-9]{10,13}$/ },
    required: { type: Boolean, default: false },
    cost: { type: Number, min: 0 },
    format: { type: String, enum: ['pdf', 'physical', 'digital', 'video', 'audio'] }
}, { _id: false });

const assignmentSchema = new Schema({
    title: { type: String, maxlength: 200, required: true },
    description: { type: String, maxlength: 1000, set: v => v ? sanitizeHtml(v, { allowedTags: [], allowedAttributes: {} }) : v },
    type: { type: String, enum: ['homework', 'project', 'exam', 'quiz', 'paper', 'presentation'], required: true },
    dueDate: { type: Date, required: true },
    weight: { type: Number, min: 0, max: 100, required: true },
    maxScore: { type: Number, min: 0, default: 100 },
    submissionFormat: { type: String, enum: ['online', 'in-person', 'email', 'platform'], default: 'online' },
    isGroup: { type: Boolean, default: false }
}, { _id: false });

const gradeSchema = new Schema({
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    grade: { type: String, validate: { validator: validateGrade, message: 'Invalid grade' } },
    score: { type: Number, min: 0, max: 100 },
    feedback: { type: String, maxlength: 1000, set: v => v ? sanitizeHtml(v, { allowedTags: [], allowedAttributes: {} }) : v },
    submittedAt: { type: Date, default: Date.now },
    isFinal: { type: Boolean, default: false }
}, { _id: false });

const reviewSchema = new Schema({
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    rating: { type: Number, min: 1, max: 5, required: true },
    comment: { type: String, maxlength: 1000, set: v => v ? sanitizeHtml(v, { allowedTags: [], allowedAttributes: {} }) : v },
    difficulty: { type: String, validate: { validator: validateDifficultyLevel, message: 'Invalid difficulty level' } },
    workload: { type: Number, min: 1, max: 5 },
    createdAt: { type: Date, default: Date.now },
    isAnonymous: { type: Boolean, default: false },
    isVerified: { type: Boolean, default: false }
}, { _id: false });

const verificationSchema = new Schema({
    isVerified: { type: Boolean, default: false, index: true },
    verifiedBy: { type: Schema.Types.ObjectId, ref: 'User' },
    verificationDate: { type: Date },
    method: { type: String, enum: ['registrar', 'syllabus', 'instructor', 'department', 'api-sync'], required: true },
    score: { type: Number, min: 0, max: 100, default: 0 },
    documents: [{
        type: { type: String, enum: ['syllabus', 'transcript', 'certificate', 'roster'] },
        url: { type: String, validate: { validator: validateURL, message: 'Invalid document URL' } },
        uploadedAt: { type: Date, default: Date.now },
        hash: { type: String }
    }],
    lastVerified: { type: Date }
}, { _id: false });

const privacySchema = new Schema({
    isPublic: { type: Boolean, default: true, index: true },
    showGrades: { type: Boolean, default: false },
    showReviews: { type: Boolean, default: true },
    showResources: { type: Boolean, default: true },
    searchable: { type: Boolean, default: true, index: true },
    visibleToStudents: { type: Boolean, default: true },
    allowComments: { type: Boolean, default: true }
}, { _id: false });

const analyticsSchema = new Schema({
    profileViews: { type: Number, default: 0, min: 0 },
    searchAppearances: { type: Number, default: 0, min: 0 },
    completionRate: { type: Number, min: 0, max: 100 },
    avgGradeScore: { type: Number, min: 0, max: 100 },
    reviewCount: { type: Number, default: 0, min: 0 },
    engagementScore: { type: Number, default: 0, min: 0 },
    lastViewed: { type: Date }
}, { _id: false });

const socialSchema = new Schema({
    likes: [{ userId: { type: Schema.Types.ObjectId, ref: 'User' }, likedAt: { type: Date, default: Date.now } }],
    comments: [{ userId: { type: Schema.Types.ObjectId, ref: 'User' }, comment: { type: String, maxlength: 500, set: v => v ? sanitizeHtml(v, { allowedTags: [], allowedAttributes: {} }) : v }, commentedAt: { type: Date, default: Date.now } }],
    shares: [{ 
        userId: { type: Schema.Types.ObjectId, ref: 'User' }, platform: { type: String, enum: ['linkedin', 'twitter', 'facebook', 'email'] }, sharedAt: { type: Date, default: Date.now }
    }],
    bookmarks: [{ userId: { type: Schema.Types.ObjectId, ref: 'User' }, bookmarkedAt: { type: Date, default: Date.now } }]
}, { _id: false });

const aiInsightsSchema = new Schema({
    demandScore: { type: Number, min: 0, max: 100 },
    skillRelevance: [{ skill: { type: String, maxlength: 50 }, relevance: { type: Number, min: 0, max: 100 } }],
    industryAlignment: { type: String, maxlength: 200 },
    completionTrend: { type: Number, min: -100, max: 100 },
    recommendedFor: [{ role: { type: String, maxlength: 100 }, confidence: { type: Number, min: 0, max: 100 } }],
    lastAnalyzed: { type: Date }
}, { _id: false });

const metadataSchema = new Schema({
    source: { type: String, default: 'manual', index: true },
    importSource: { type: String, enum: ['university-portal', 'api', 'csv', 'manual'] },
    importId: { type: String },
    lastUpdated: { type: Date, default: Date.now },
    updateCount: { type: Number, default: 0, min: 0 },
    version: { type: Number, default: 1, min: 1 },
    duplicateOf: { type: Schema.Types.ObjectId },
    isDuplicate: { type: Boolean, default: false }
}, { _id: false });

// Main Course Schema
const courseSchema = new Schema({
    _id: { type: Schema.Types.ObjectId, auto: true },
    code: { type: String, required: [true, 'Course code is required'], trim: true, maxlength: 20, index: true, validate: { validator: validateCourseCode, message: 'Invalid course code format' } },
    title: { type: String, required: [true, 'Course title is required'], trim: true, maxlength: 200, index: true, validate: { validator: validateCourseTitle, message: 'Course title must be 1-200 characters' } },
    schoolId: { type: Schema.Types.ObjectId, ref: 'School', required: [true, 'School ID is required'], index: true },
    departmentId: { type: Schema.Types.ObjectId, ref: 'Department', required: [true, 'Department ID is required'], index: true },
    credits: { type: Number, required: [true, 'Credits are required'], validate: { validator: validateCreditHours, message: 'Credits must be between 0 and 20' } },
    description: { type: String, maxlength: 2000, set: v => v ? sanitizeHtml(v, { allowedTags: [], allowedAttributes: {} }) : v },
    level: { type: String, enum: ['undergraduate', 'graduate', 'certificate', 'continuing-education'], required: true, index: true },
    isCore: { type: Boolean, default: false, index: true },
    difficultyLevel: { type: String, validate: { validator: validateDifficultyLevel, message: 'Invalid difficulty level' }, default: 'medium' },
    syllabusUrl: { type: String, validate: { validator: validateURL, message: 'Invalid syllabus URL' } },
    instructors: [instructorSchema],
    schedule: scheduleSchema,
    prerequisites: [prerequisiteSchema],
    learningOutcomes: [learningOutcomeSchema],
    resources: [resourceSchema],
    assignments: [assignmentSchema],
    grades: [gradeSchema],
    reviews: [reviewSchema],
    verification: verificationSchema,
    privacy: privacySchema,
    analytics: analyticsSchema,
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
    collection: 'courses',
    autoIndex: process.env.NODE_ENV !== 'production',
    readPreference: 'secondaryPreferred',
    writeConcern: { w: 'majority', wtimeout: 5000 },
    toJSON: {
        virtuals: true,
        transform: (doc, ret) => {
            delete ret.grades;
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
courseSchema.index({ code: 1, schoolId: 1, 'status.isActive': 1 });
courseSchema.index({ schoolId: 1, departmentId: 1, level: 1 });
courseSchema.index({ 'instructors.userId': 1, 'verification.isVerified': 1 });
courseSchema.index({ 'privacy.isPublic': 1, 'analytics.engagementScore': -1, updatedAt: -1 });
courseSchema.index({ 'aiInsights.demandScore': 1, 'aiInsights.lastAnalyzed': -1 });
courseSchema.index({ 'schedule.isOnline': 1, 'isCore': 1 });
courseSchema.index({
    code: 'text',
    title: 'text',
    description: 'text',
    'learningOutcomes.description': 'text',
    'resources.title': 'text',
    'cache.searchVector': 'text'
}, {
    weights: { code: 10, title: 8, description: 6, 'learningOutcomes.description': 4, 'resources.title': 2, 'cache.searchVector': 1 },
    name: 'course_text_search'
});
courseSchema.index({ 'analytics.popularityScore': -1, 'status.isActive': 1 }, { background: true });
courseSchema.index({ 'cache.trendingScore': -1, 'privacy.isPublic': 1 }, { background: true });
courseSchema.index({ 'status.deletedAt': 1 }, { expireAfterSeconds: 7776000, sparse: true }); // 90 days

// Virtuals
courseSchema.virtual('totalAssignments').get(function () {
    return this.assignments?.length || 0;
});
courseSchema.virtual('totalReviews').get(function () {
    return this.reviews?.length || 0;
});
courseSchema.virtual('averageRating').get(function () {
    return this.reviews?.length > 0 ? (this.reviews.reduce((sum, review) => sum + review.rating, 0) / this.reviews.length).toFixed(1) : null;
});
courseSchema.virtual('isPopular').get(function () {
    return this.analytics.popularityScore >= 50;
});
courseSchema.virtual('verificationLevel').get(function () {
    const score = this.verification.score;
    if (score >= 90) return 'platinum';
    if (score >= 75) return 'gold';
    if (score >= 60) return 'silver';
    if (score >= 40) return 'bronze';
    return 'unverified';
});
courseSchema.virtual('engagementLevel').get(function () {
    const score = this.analytics.engagementScore;
    if (score >= 80) return 'high';
    if (score >= 60) return 'medium';
    if (score >= 40) return 'low';
    return 'minimal';
});
courseSchema.virtual('isActiveSemester').get(function () {
    const now = new Date();
    return this.schedule?.startTime && new Date().getMonth() >= 8 && new Date().getMonth() <= 12; // Fall semester example
});

// Middleware
courseSchema.pre('save', async function (next) {
    try {
        // Update metadata
        this.metadata.lastUpdated = new Date();
        this.metadata.updateCount += 1;
        this.metadata.version += 1;

        // Generate search vector
        this.cache.searchVector = [
            this.code,
            this.title,
            this.description,
            ...this.learningOutcomes.map(lo => lo.description),
            ...this.resources.map(r => r.title)
        ].filter(Boolean).join(' ').toLowerCase();

        // Calculate verification score
        if (this.verification.isVerified) {
            let score = 30;
            const methodScores = { 'registrar': 25, 'syllabus': 20, 'instructor': 15, 'department': 15, 'api-sync': 10 };
            score += methodScores[this.verification.method] || 0;
            if (this.verification.documents?.length > 0) score += 20;
            if (this.reviews?.length > 0) score += Math.min(this.reviews.length * 2, 10);
            if (this.instructors?.length > 0 && this.instructors.every(i => i.verificationStatus === 'verified')) score += 15;
            this.verification.score = Math.min(score, 100);
        }

        // Calculate engagement score
        let engagementScore = 0;
        engagementScore += (this.analytics.profileViews || 0) * 0.1;
        engagementScore += (this.social.likes?.length || 0) * 2;
        engagementScore += (this.social.comments?.length || 0) * 3;
        engagementScore += (this.social.shares?.length || 0) * 5;
        engagementScore += (this.totalReviews || 0) * 4;
        engagementScore += (this.verification.score || 0) * 0.2;
        this.analytics.engagementScore = Math.min(engagementScore, 1000);

        this.cache.popularityScore = this.calculatePopularityScore();
        this.cache.trendingScore = (this.analytics.engagementScore * 0.4) + (this.verification.score * 0.3) + (this.averageRating * 20);

        // Update cache
        this.cache.lastCacheUpdate = new Date();
        this.cache.cacheVersion += 1;

        // Cache in Redis
        await redisClient.setEx(`course:${this._id}`, 300, JSON.stringify(this.toJSON()));

        // Publish updates
        await redisClient.publish('course_updates', JSON.stringify({
            courseId: this._id,
            popularityScore: this.cache.popularityScore,
            trendingScore: this.cache.trendingScore
        }));

        // AI Insights
        if (!this.aiInsights.lastAnalyzed || (new Date() - this.aiInsights.lastAnalyzed) > 7 * 24 * 60 * 60 * 1000) {
            this.aiInsights.lastAnalyzed = new Date();
            this.aiInsights.demandScore = (this.analytics.completionRate * 0.5) + (this.averageRating * 10) + (this.totalReviews * 2);
            this.aiInsights.skillRelevance = this.learningOutcomes.map(lo => ({
                skill: lo.description.slice(0, 50),
                relevance: lo.bloomLevel === 'create' ? 90 : lo.bloomLevel === 'evaluate' ? 80 : 70
            }));
        }

        // Encrypt sensitive fields
        if (this.grades?.length > 0 && !this.privacy.showGrades) {
            this.grades = await Promise.all(this.grades.map(async g => ({
                ...g,
                grade: await encryptField(g.grade),
                score: await encryptField(g.score.toString())
            })));
        }

        next();
    } catch (error) {
        next(new Error(`Pre-save middleware error: ${error.message}`));
    }
});

courseSchema.pre('remove', async function (next) {
    try {
        this.status.isDeleted = true;
        this.status.deletedAt = new Date();
        this.privacy.isPublic = false;
        this.privacy.searchable = false;
        await redisClient.del(`course:${this._id}`);
        await this.save();
        next();
    } catch (error) {
        next(new Error(`Pre-remove middleware error: ${error.message}`));
    }
});

courseSchema.post('save', async function (doc) {
    try {
        // Update related school or department
        const School = mongoose.model('School');
        await School.updateOne(
            { _id: doc.schoolId },
            { $set: { 'stats.lastCalculated': new Date() } }
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
        await redisClient.del(`courses:school:${doc.schoolId}`);
    } catch (error) {
        console.error('Post-save middleware error:', error.message);
    }
});

// Instance Methods
courseSchema.methods.calculatePopularityScore = function () {
    const weights = { views: 0.3, likes: 0.2, comments: 0.2, shares: 0.2, reviews: 0.2 };
    const viewScore = Math.log1p(this.analytics.profileViews) / Math.log1p(10000);
    const likeScore = Math.log1p(this.social.likes?.length || 0) / Math.log1p(1000);
    const commentScore = Math.log1p(this.social.comments?.length || 0) / Math.log1p(500);
    const shareScore = Math.log1p(this.social.shares?.length || 0) / Math.log1p(500);
    const reviewScore = Math.log1p(this.totalReviews) / Math.log1p(100);
    return Math.min(100, (
        viewScore * weights.views +
        likeScore * weights.likes +
        commentScore * weights.comments +
        shareScore * weights.shares +
        reviewScore * weights.reviews
    ) * 100);
};

courseSchema.methods.syncToAlgolia = async function () {
    return Promise.resolve();
};

// Static Methods
courseSchema.statics.getCoursesBySchool = async function (schoolId, options = {}) {
    const { page = 1, limit = 10, sortBy = 'code', sortOrder = 1, includePrivate = false, filters = {} } = options;
    const cacheKey = `courses:school:${schoolId}:${JSON.stringify(options)}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const query = { schoolId: new mongoose.Types.ObjectId(schoolId), 'status.isActive': true };
    if (!includePrivate) query['privacy.isPublic'] = true;
    Object.entries(filters).forEach(([key, value]) => {
        if (value !== undefined && value !== null && value !== '') query[key] = value;
    });

    const results = await this.find(query)
        .sort({ [sortBy]: sortOrder })
        .skip((page - 1) * limit)
        .limit(limit)
        .populate({ path: 'instructors.userId', select: 'name profilePic verificationStatus' })
        .populate({ path: 'schoolId', select: 'name branding.logo' })
        .select('-grades -verification.documents')
        .lean({ virtuals: true });

    await redisClient.setEx(cacheKey, 3600, JSON.stringify(results));
    return results;
};

courseSchema.statics.advancedSearch = async function (searchOptions = {}) {
    const { query = '', schoolId, departmentId, level, isCore, minCredits, maxCredits, verified = false, hasReviews = false, page = 1, limit = 20, sortBy = 'relevance' } = searchOptions;
    const cacheKey = `search:courses:${JSON.stringify(searchOptions)}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const pipeline = [
        {
            $match: {
                'status.isActive': true,
                'status.isDeleted': false,
                'privacy.isPublic': true,
                'privacy.searchable': true,
                ...(schoolId && { schoolId: new mongoose.Types.ObjectId(schoolId) }),
                ...(departmentId && { departmentId: new mongoose.Types.ObjectId(departmentId) }),
                ...(level && { level }),
                ...(isCore !== undefined && { isCore }),
                ...(verified && { 'verification.isVerified': true }),
                ...(hasReviews && { 'reviews.0': { $exists: true } }),
                ...(minCredits || maxCredits ? { credits: { $gte: minCredits || 0, $lte: maxCredits || 20 } } : {})
            }
        },
        ...(query ? [{ $match: { $text: { $search: query, $caseSensitive: false } } }, { $addFields: { textScore: { $meta: 'textScore' } } }] : []),
        { $lookup: { from: 'schools', localField: 'schoolId', foreignField: '_id', as: 'school', pipeline: [{ $project: { name: 1, 'branding.logo': 1 } }] } },
        { $unwind: { path: '$school', preserveNullAndEmptyArrays: true } },
        {
            $addFields: {
                relevanceScore: {
                    $add: [
                        { $multiply: [{ $ifNull: ['$textScore', 0] }, 0.3] },
                        { $multiply: [{ $divide: ['$verification.score', 100] }, 0.2] },
                        { $multiply: [{ $divide: [{ $min: ['$analytics.engagementScore', 100] }, 100] }, 0.2] },
                        { $multiply: [{ $size: { $ifNull: ['$reviews', []] } }, 0.1] },
                        { $multiply: [{ $avg: '$reviews.rating' }, 0.2] }
                    ]
                }
            }
        },
        { $sort: this.getSortQuery(sortBy) },
        {
            $project: {
                code: 1,
                title: 1,
                credits: 1,
                level: 1,
                isCore: 1,
                school: 1,
                description: { $substr: ['$description', 0, 200] },
                instructors: { $slice: ['$instructors', 3] },
                reviews: { $size: { $ifNull: ['$reviews', []] } },
                verification: { isVerified: 1, score: 1 },
                relevanceScore: 1,
                createdAt: 1,
                updatedAt: 1
            }
        }
    ];

    const results = await this.aggregatePaginate(pipeline, { page, limit, customLabels: { totalDocs: 'totalResults', docs: 'courses' } });
    await redisClient.setEx(cacheKey, 300, JSON.stringify(results));
    return results;
};

courseSchema.statics.getSortQuery = function (sortBy) {
    const sortQueries = {
        'relevance': { relevanceScore: -1, 'verification.score': -1 },
        'credits': { credits: -1 },
        'rating': { 'analytics.avgGradeScore': -1 },
        'popular': { 'cache.popularityScore': -1, 'analytics.profileViews': -1 },
        'alphabetical': { code: 1 }
    };
    return sortQueries[sortBy] || sortQueries['relevance'];
};

courseSchema.statics.getTrendingCourses = async function (options = {}) {
    const { schoolId, timeframe = 30, limit = 25 } = options;
    const cacheKey = `trending:courses:${JSON.stringify(options)}`;
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
                ...(schoolId && { schoolId: new mongoose.Types.ObjectId(schoolId) })
            }
        },
        {
            $facet: {
                trendingByViews: [
                    { $group: { _id: null, topCourses: { $push: { _id: '$_id', code: '$code', title: '$title', views: '$analytics.profileViews' } } } },
                    { $addFields: { topCourses: { $sortArray: { input: '$topCourses', sortBy: { views: -1 } } } } },
                    { $project: { courses: { $slice: ['$topCourses', limit] } } }
                ],
                trendingByReviews: [
                    { $group: { _id: { code: '$code', title: '$title' }, reviewCount: { $sum: { $size: { $ifNull: ['$reviews', []] } } }, avgRating: { $avg: '$reviews.rating' } } },
                    { $sort: { reviewCount: -1 } },
                    { $limit: limit },
                    { $project: { code: '$_id.code', title: '$_id.title', reviews: '$reviewCount', avgRating: { $round: ['$avgRating', 1] } } }
                ]
            }
        }
    ];

    const results = await this.aggregate(pipeline);
    await redisClient.setEx(cacheKey, 86400, JSON.stringify(results));
    return results;
};

courseSchema.statics.getAnalytics = async function (courseId, options = {}) {
    const cacheKey = `analytics:course:${courseId}:${JSON.stringify(options)}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const pipeline = [
        { $match: { _id: new mongoose.Types.ObjectId(courseId), 'status.isActive': true } },
        {
            $group: {
                _id: null,
                totalReviews: { $sum: { $size: { $ifNull: ['$reviews', []] } } },
                avgRating: { $avg: '$reviews.rating' },
                completionRate: { $avg: '$analytics.completionRate' },
                engagementMetrics: {
                    views: { $sum: '$analytics.profileViews' },
                    shares: { $sum: { $size: { $ifNull: ['$social.shares', []] } } },
                    comments: { $sum: { $size: { $ifNull: ['$social.comments', []] } } }
                },
                gradeDistribution: { $push: '$grades.grade' }
            }
        },
        {
            $project: {
                _id: 0,
                summary: {
                    reviews: '$totalReviews',
                    avgRating: { $round: ['$avgRating', 1] },
                    completionRate: { $round: ['$completionRate', 1] },
                    views: '$engagementMetrics.views',
                    shares: '$engagementMetrics.shares',
                    comments: '$engagementMetrics.comments'
                },
                grades: {
                    distribution: {
                        $arrayToObject: {
                            $map: {
                                input: { $setUnion: ['$gradeDistribution'] },
                                as: 'grade',
                                in: { k: '$$grade', v: { $size: { $filter: { input: '$gradeDistribution', cond: { $eq: ['$$this', '$$grade'] } } } } }
                            }
                        }
                    }
                }
            }
        }
    ];

    const results = await this.aggregate(pipeline);
    await redisClient.setEx(cacheKey, 43200, JSON.stringify(results[0] || {}));
    return results[0] || {};
};

courseSchema.statics.bulkOperations = {
    updateVerification: async function (courseIds, verificationData) {
        try {
            const bulkOps = courseIds.map(id => ({
                updateOne: {
                    filter: { _id: new mongoose.Types.ObjectId(id), 'status.isActive': true },
                    update: { $set: { 'verification.isVerified': verificationData.isVerified, 'verification.verificationDate': new Date(), 'verification.score': verificationData.score, 'metadata.lastUpdated': new Date() } }
                }
            }));
            const result = await this.bulkWrite(bulkOps);
            for (const id of courseIds) await redisClient.del(`course:${id}`);
            return result;
        } catch (error) {
            throw new Error(`Bulk verification update error: ${error.message}`);
        }
    },
    updateAssignments: async function (courseIds, assignments) {
        try {
            const bulkOps = courseIds.map(id => ({
                updateOne: {
                    filter: { _id: new mongoose.Types.ObjectId(id) },
                    update: { $set: { assignments, 'metadata.lastUpdated': new Date() } }
                }
            }));
            const result = await this.bulkWrite(bulkOps);
            for (const id of courseIds) await redisClient.del(`course:${id}`);
            return result;
        } catch (error) {
            throw new Error(`Bulk assignments update error: ${error.message}`);
        }
    },
    archiveOldCourses: async function (cutoffDate) {
        try {
            const oldCourses = await this.find({ 'schedule.endTime': { $lt: cutoffDate }, 'status.isActive': true }).lean();
            if (oldCourses.length === 0) return { archived: 0 };
            const ArchiveCourse = mongoose.model('ArchiveCourse', courseSchema, 'archive_courses');
            await ArchiveCourse.insertMany(oldCourses);
            const result = await this.updateMany(
                { _id: { $in: oldCourses.map(c => c._id) } },
                { $set: { 'status.isActive': false, 'status.archivedAt': new Date() } }
            );
            for (const course of oldCourses) await redisClient.del(`course:${course._id}`);
            return { archived: result.modifiedCount };
        } catch (error) {
            throw new Error(`Archive old courses error: ${error.message}`);
        }
    }
};

courseSchema.statics.getAIRecommendations = async function (userId, options = {}) {
    const { type = 'skill-development', limit = 10 } = options;
    const cacheKey = `ai:recommendations:courses:${userId}:${type}:${limit}`;
    const cached = await redisClient.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const pipeline = [
        { $match: { 'status.isActive': true, 'privacy.isPublic': true } },
        { $lookup: { from: 'educations', localField: '_id', foreignField: 'courses._id', as: 'educationData', pipeline: [{ $match: { userId: new mongoose.Types.ObjectId(userId) } }] } },
        {
            $project: {
                recommendations: {
                    $switch: {
                        branches: [
                            { case: { $eq: [type, 'skill-development'] }, then: { skills: { $slice: ['$learningOutcomes', limit] } } },
                            { case: { $eq: [type, 'career-alignment'] }, then: { roles: { $slice: ['$aiInsights.recommendedFor', limit] } } }
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

courseSchema.statics.getPerformanceMetrics = async function (timeframe = '30d') {
    const cacheKey = `performance:metrics:courses:${timeframe}`;
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
                            completeProfiles: { $sum: { $cond: [{ $and: [{ $ne: ['$code', ''] }, { $ne: ['$title', ''] }, { $gt: [{ $size: { $ifNull: ['$learningOutcomes', []] } }, 0] }] }, 1, 0] } }
                        }
                    },
                    { $addFields: { verificationRate: { $multiply: [{ $divide: ['$verifiedRecords', '$totalRecords'] }, 100] }, completenessRate: { $multiply: [{ $divide: ['$completeProfiles', '$totalRecords'] }, 100] } } }
                ]
            }
        }
    ];

    const results = await this.aggregate(pipeline);
    await redisClient.setEx(cacheKey, 86400, JSON.stringify(results[0]));
    return results[0];
};

courseSchema.statics.cleanupIndexes = async function () {
    const indexes = await this.collection.indexes();
    const essentialIndexes = ['_id_', 'course_text_search', 'code_1_schoolId_1_status.isActive_1'];
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

courseSchema.statics.initChangeStream = function () {
    const changeStream = this.watch([{ $match: { 'operationType': { $in: ['insert', 'update', 'replace'] } } }]);
    changeStream.on('change', async (change) => {
        const courseId = change.documentKey._id.toString();
        await redisClient.del(`course:${courseId}`);
        await redisClient.publish('course_updates', JSON.stringify({
            courseId,
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
courseSchema.plugin(aggregatePaginate);
if (process.env.ALGOLIA_APP_ID && process.env.ALGOLIA_ADMIN_KEY) {
    courseSchema.plugin(mongooseAlgolia, {
        appId: process.env.ALGOLIA_APP_ID,
        apiKey: process.env.ALGOLIA_ADMIN_KEY,
        indexName: 'courses',
        selector: 'code title description learningOutcomes.description resources.title cache.searchVector',
        defaults: { author: 'unknown' },
        mappings: {
            code: v => v || '',
            title: v => v || '',
            description: v => v || '',
            'learningOutcomes.description': v => v || [],
            'resources.title': v => v || [],
            'cache.searchVector': v => v || ''
        },
        debug: process.env.NODE_ENV === 'development'
    });
} else {
    console.warn('Algolia plugin not initialized: Missing env vars');
}

// Production Indexes
if (process.env.NODE_ENV === 'production') {
    courseSchema.index({ 'cache.popularityScore': -1, 'status.isActive': 1 }, { background: true });
    courseSchema.index({ 'cache.trendingScore': -1, 'privacy.isPublic': 1 }, { background: true });
}

export default mongoose.model('Course', courseSchema);