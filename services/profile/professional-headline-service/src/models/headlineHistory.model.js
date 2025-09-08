import mongoose from 'mongoose';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';

const accessControlSchema = new mongoose.Schema({
    visibility: {
        type: String,
        enum: ['public', 'private', 'team', 'organization'],
        default: 'private',
        index: true
    },
    teamId: { type: String, index: true },
    organizationId: { type: String, index: true },
    collaborators: [{
        userId: {
            type: String,
            required: true,
            validate: {
                validator: v => /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(v),
                message: 'Invalid collaborator UUID'
            }
        },
        role: {
            type: String,
            enum: ['owner', 'editor', 'viewer', 'coach', 'admin', 'contributor'],
            required: true
        }
    }],
    shareSettings: {
        allowPublicView: { type: Boolean, default: false },
        allowCopy: { type: Boolean, default: false },
        allowSuggestions: { type: Boolean, default: true },
        trackViews: { type: Boolean, default: true }
    }
}, { _id: false });

const metadataSchema = new mongoose.Schema({
    characterCount: { type: Number, required: true },
    wordCount: { type: Number, required: true },
    language: { type: String, default: 'en' },
    tone: { type: String, default: 'professional' },
    formality: { type: String, default: 'semi-formal' },
    targetAudience: { type: String, default: 'recruiters' },
    industry: { type: String, default: 'general' },
    keywords: [{ type: String, maxlength: 50 }],
    readabilityScore: { type: Number, min: 0, max: 100, default: 70 },
    sentimentScore: {
        positive: { type: Number, min: 0, max: 1, default: 0.7 },
        negative: { type: Number, min: 0, max: 1, default: 0.1 },
        neutral: { type: Number, min: 0, max: 1, default: 0.2 }
    },
    uniquenessScore: { type: Number, min: 0, max: 100, default: 80 },
    seoScore: { type: Number, min: 0, max: 100, default: 60 },
    lastAnalyzedAt: { type: Date }
}, { _id: false });

const optimizationSchema = new mongoose.Schema({
    overallScore: { type: Number, min: 0, max: 100, default: 70 },
    categoryScores: {
        grammar: { type: Number, min: 0, max: 100, default: 85 },
        clarity: { type: Number, min: 0, max: 100, default: 75 },
        impact: { type: Number, min: 0, max: 100, default: 70 },
        relevance: { type: Number, min: 0, max: 100, default: 80 },
        professionalism: { type: Number, min: 0, max: 100, default: 85 }
    },
    suggestions: [{
        suggestionId: { type: String, required: true },
        text: { type: String, required: true },
        reason: { type: String, maxlength: 500 },
        category: {
            type: String,
            enum: ['grammar', 'clarity', 'tone', 'seo', 'performance', 'branding'],
            default: 'clarity'
        },
        confidence: { type: Number, min: 0, max: 1, default: 0.8 }
    }]
}, { _id: false });

const performanceSchema = new mongoose.Schema({
    profileViews: {
        total: { type: Number, default: 0, index: true },
        thisWeek: { type: Number, default: 0 },
        thisMonth: { type: Number, default: 0 }
    },
    engagement: {
        connectionRequests: { type: Number, default: 0 },
        messagesSent: { type: Number, default: 0 },
        profileClicks: { type: Number, default: 0 }
    },
    conversionRates: {
        clickThroughRate: { type: Number, min: 0, max: 100, default: 0 },
        engagementRate: { type: Number, min: 0, max: 100, default: 0 }
    }
}, { _id: false });

const aiAnalysisSchema = new mongoose.Schema({
    emotionalTone: { type: String, default: 'neutral' },
    personalityTraits: [{ type: String, maxlength: 50 }],
    careerStage: { type: String, default: 'mid-level' },
    skillsIdentified: [{ type: String, maxlength: 100 }],
    valueProposition: { type: String, default: 'general' }
}, { _id: false });

const versionSchema = new mongoose.Schema({
    versionId: { type: String, required: true },
    text: { type: String, required: true },
    reason: { type: String, maxlength: 500 },
    createdBy: {
        type: String,
        validate: {
            validator: v => /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(v),
            message: 'Invalid user UUID'
        }
    },
    createdAt: { type: Date, default: Date.now },
    scores: {
        overall: { type: Number, min: 0, max: 100, default: 70 },
        grammar: { type: Number, min: 0, max: 100, default: 85 },
        clarity: { type: Number, min: 0, max: 100, default: 75 },
        impact: { type: Number, min: 0, max: 100, default: 70 },
        relevance: { type: Number, min: 0, max: 100, default: 80 },
        professionalism: { type: Number, min: 0, max: 100, default: 85 }
    }
}, { _id: false });

const moderationSchema = new mongoose.Schema({
    status: {
        type: String,
        enum: ['pending', 'approved', 'rejected', 'flagged'],
        default: 'pending',
        index: true
    },
    flagReason: { type: String, maxlength: 500 },
    flaggedBy: { type: String },
    flaggedAt: { type: Date },
    reviewedBy: { type: String },
    reviewedAt: { type: Date }
}, { _id: false });

const headlineSchema = new mongoose.Schema({
    headlineId: {
        type: String,
        required: true,
        unique: true,
        index: true,
        default: () => `hl_${uuidv4().replace(/-/g, '')}`
    },
    userId: {
        type: String,
        required: true,
        index: true,
        validate: {
            validator: v => /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(v),
            message: 'Invalid user UUID'
        }
    },
    text: {
        type: String,
        required: true,
        maxlength: 160,
        trim: true
    },
    originalText: {
        type: String,
        required: true,
        maxlength: 160,
        trim: true
    },
    title: {
        type: String,
        required: true,
        maxlength: 100,
        default: 'Untitled Headline'
    },
    description: {
        type: String,
        maxlength: 500,
        default: ''
    },
    category: {
        type: String,
        enum: ['specialist', 'executive', 'technical', 'creative', 'general'],
        default: 'specialist',
        index: true
    },
    tags: [{
        type: String,
        maxlength: 30,
        lowercase: true,
        trim: true
    }],
    source: {
        type: String,
        enum: ['manual', 'api', 'ai-generated', 'import', 'test-variant'],
        default: 'manual',
        index: true
    },
    status: {
        type: String,
        enum: ['draft', 'processing', 'active', 'failed', 'deleted', 'archived'],
        default: 'draft',
        index: true
    },
    metadata: {
        type: metadataSchema,
        default: () => ({})
    },
    optimization: {
        type: optimizationSchema,
        default: () => ({})
    },
    performance: {
        type: performanceSchema,
        default: () => ({})
    },
    aiAnalysis: {
        type: aiAnalysisSchema,
        default: () => ({})
    },
    versions: [versionSchema],
    accessControl: {
        type: accessControlSchema,
        default: () => ({})
    },
    moderation: {
        type: moderationSchema,
        default: () => ({})
    },
    cacheVersion: {
        type: Number,
        default: 0,
        index: true
    },
    schemaVersion: {
        type: String,
        default: '1.0.0'
    }
}, {
    timestamps: true,
    collection: 'headlines',
    read: 'secondaryPreferred',
    shardKey: { userId: 1, headlineId: 1 },
    toJSON: {
        transform: (doc, ret) => {
            ret.id = ret._id;
            delete ret._id;
            delete ret.__v;
            return ret;
        }
    },
    toObject: {
        transform: (doc, ret) => {
            ret.id = ret._id;
            delete ret._id;
            delete ret.__v;
            return ret;
        }
    }
});

// Indexes
headlineSchema.index({ headlineId: 1 }, { unique: true, name: 'idx_headlineId_unique' });
headlineSchema.index({ userId: 1, status: 1, createdAt: -1 }, { name: 'idx_user_status' });
headlineSchema.index({ category: 1, status: 1 }, { name: 'idx_category_status' });
headlineSchema.index({ tags: 1 }, { name: 'idx_tags' });
headlineSchema.index({ 'metadata.keywords': 1 }, { name: 'idx_keywords' });
headlineSchema.index({ 'performance.profileViews.total': -1 }, { name: 'idx_profile_views' });
headlineSchema.index({ 'optimization.overallScore': -1 }, { name: 'idx_optimization_score' });
headlineSchema.index({ text: 'text', title: 'text', description: 'text' }, {
    weights: { text: 10, title: 5, description: 3 },
    name: 'idx_text_search'
});

// Pre-save hooks
headlineSchema.pre('save', async function (next) {
    try {
        // Update metadata
        if (this.isModified('text')) {
            this.metadata.characterCount = this.text.length;
            this.metadata.wordCount = this.text.trim().split(/\s+/).length;
        }

        // Validate tags
        if (this.isModified('tags')) {
            this.tags = [...new Set(this.tags)].slice(0, 10); // Limit to 10 unique tags
        }

        // Update cache version
        if (this.isModified() && !this.isNew) {
            this.cacheVersion += 1;
        }

        // Ensure history record
        await this.createHistoryRecord('updated');

        next();
    } catch (error) {
        logger.error(`Pre-save error for headline ${this.headlineId}:`, error);
        next(new AppError('Failed to save headline', 500));
    }
});

// Pre-find hook to exclude deleted records
headlineSchema.pre(/^find/, function (next) {
    if (!this.getQuery().includeDeleted) {
        this.where({ status: { $ne: 'deleted' } });
    }
    next();
});

// Instance methods
headlineSchema.methods.createVersion = async function (newText, reason, userId) {
    this.versions.push({
        versionId: `ver_${uuidv4().replace(/-/g, '')}`,
        text: newText,
        reason,
        createdBy: userId,
        scores: {
            overall: this.optimization.overallScore,
            grammar: this.optimization.categoryScores.grammar,
            clarity: this.optimization.categoryScores.clarity,
            impact: this.optimization.categoryScores.impact,
            relevance: this.optimization.categoryScores.relevance,
            professionalism: this.optimization.categoryScores.professionalism
        }
    });

    // Keep only last 50 versions
    if (this.versions.length > 50) {
        this.versions = this.versions.slice(-50);
    }

    await this.createHistoryRecord('versioned', {
        changes: [{
            field: 'text',
            oldValue: this.text,
            newValue: newText,
            changeType: 'update',
            impact: 'major',
            automated: false,
            confidence: 1
        }]
    });
};

headlineSchema.methods.recordPerformanceMetrics = async function (metrics) {
    if (metrics.profileViews) {
        this.performance.profileViews.total += metrics.profileViews;
        this.performance.profileViews.thisWeek += metrics.profileViews;
        this.performance.profileViews.thisMonth += metrics.profileViews;
    }

    if (metrics.engagement) {
        Object.keys(metrics.engagement).forEach(key => {
            if (this.performance.engagement[key]) {
                this.performance.engagement[key] += metrics.engagement[key];
            }
        });
    }

    // Recalculate conversion rates
    const totalViews = this.performance.profileViews.total || 1;
    this.performance.conversionRates.engagementRate =
        (this.performance.engagement.profileClicks / totalViews) * 100;

    await this.createHistoryRecord('performance_updated', {
        changes: [{
            field: 'performance',
            oldValue: { ...this.performance.toObject() },
            newValue: { ...this.performance.toObject(), ...metrics },
            changeType: 'update',
            impact: 'moderate'
        }]
    });
};

headlineSchema.methods.createHistoryRecord = async function (eventType, details = {}) {
    const HeadlineHistory = mongoose.model('HeadlineHistory');

    const changes = details.changes || [{
        field: 'text',
        oldValue: this.originalText,
        newValue: this.text,
        changeType: eventType === 'created' ? 'create' : 'update',
        impact: eventType === 'created' ? 'major' : 'moderate'
    }];

    const historyRecord = new HeadlineHistory({
        historyId: `hist_${uuidv4().replace(/-/g, '')}`,
        headlineId: this.headlineId,
        userId: this.userId,
        version: this.versions.length + 1,
        eventType,
        eventCategory: details.eventCategory || 'content',
        priority: details.priority || 'medium',
        summary: details.summary || `Headline ${eventType}`,
        description: details.description || '',
        changes,
        snapshot: {
            text: this.text,
            metadata: { ...this.metadata.toObject() },
            category: this.category,
            tags: this.tags,
            status: this.status,
            optimizationScore: this.optimization.overallScore,
            visibility: this.accessControl.visibility,
            targeting: {
                industries: this.metadata.industry ? [this.metadata.industry] : [],
                roles: [],
                seniority: [],
                locations: []
            }
        },
        performanceSnapshot: { ...this.performance.toObject() },
        trigger: {
            source: details.source || 'system',
            triggeredBy: this.userId,
            automatic: details.automatic || false,
            reason: details.reason || `Headline ${eventType}`
        },
        collaboration: details.collaboration || [],
        experiments: details.experiments || [],
        analytics: details.analytics || []
    });

    try {
        await historyRecord.save();
    } catch (error) {
        logger.error(`Failed to create history record for headline ${this.headlineId}:`, error);
        throw new AppError('Failed to create history record', 500);
    }
};

headlineSchema.methods.getPublicData = function () {
    const publicFields = {
        headlineId: this.headlineId,
        text: this.text,
        title: this.title,
        description: this.description,
        category: this.category,
        tags: this.tags,
        metadata: {
            language: this.metadata.language,
            tone: this.metadata.tone,
            industry: this.metadata.industry,
            keywords: this.metadata.keywords,
            readabilityScore: this.metadata.readabilityScore,
            seoScore: this.metadata.seoScore
        },
        optimization: {
            overallScore: this.optimization.overallScore,
            categoryScores: this.optimization.categoryScores
        },
        performance: {
            profileViews: { total: this.performance.profileViews.total },
            conversionRates: this.performance.conversionRates
        },
        createdAt: this.createdAt,
        updatedAt: this.updatedAt
    };

    return publicFields;
};

// Static methods
headlineSchema.statics.findByUser = async function (userId, options = {}) {
    const {
        page = 1,
        limit = 20,
        status,
        category,
        sortBy = 'createdAt',
        search
    } = options;

    const query = { userId };
    if (status && status !== 'all') query.status = status;
    if (category) query.category = category;
    if (search) query.$text = { $search: search };

    const sortOptions = {};
    switch (sortBy) {
        case 'createdAt': sortOptions.createdAt = -1; break;
        case 'optimization': sortOptions['optimization.overallScore'] = -1; break;
        case 'views': sortOptions['performance.profileViews.total'] = -1; break;
        case 'title': sortOptions.title = 1; break;
        default: sortOptions.createdAt = -1;
    }

    const skip = (page - 1) * limit;
    const headlines = await this.find(query)
        .sort(sortOptions)
        .skip(skip)
        .limit(parseInt(limit))
        .select('headlineId text title category status metadata optimization performance createdAt updatedAt')
        .lean();

    const totalCount = await this.countDocuments(query);
    return {
        headlines,
        pagination: {
            page: parseInt(page),
            limit: parseInt(limit),
            totalCount,
            totalPages: Math.ceil(totalCount / limit)
        }
    };
};

// Register the model
const Headline = mongoose.model('Headline', headlineSchema);

export default Headline;