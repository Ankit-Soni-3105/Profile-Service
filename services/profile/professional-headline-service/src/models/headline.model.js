import mongoose from 'mongoose';
import { createHash } from 'crypto';

// ===========================
// OPTIMIZED SUB-SCHEMAS
// ===========================
const metadataSchema = new mongoose.Schema({
    characterCount: {
        type: Number,
        required: true,
        min: 10,
        max: 220,
        index: true
    },
    wordCount: {
        type: Number,
        required: true,
        min: 2,
        max: 40,
        index: true
    },
    language: {
        type: String,
        required: true,
        enum: ['en', 'es', 'fr', 'de', 'it', 'pt', 'nl', 'ru', 'zh', 'ja', 'ko', 'ar', 'hi'],
        default: 'en',
        index: true
    },
    tone: {
        type: String,
        enum: ['professional', 'casual', 'confident', 'friendly', 'authoritative', 'creative', 'corporate', 'personal'],
        required: true,
        index: true
    },
    formality: {
        type: String,
        enum: ['formal', 'semi-formal', 'informal'],
        default: 'semi-formal',
        index: true
    },
    targetAudience: {
        type: String,
        enum: ['recruiters', 'employers', 'peers', 'clients', 'investors', 'general'],
        default: 'recruiters',
        index: true
    },
    industry: {
        type: String,
        required: true,
        maxlength: 50,
        index: true
    },
    keywords: [{
        keyword: { type: String, required: true, maxlength: 30 },
        relevance: { type: Number, min: 0, max: 1, default: 0.5 },
        density: { type: Number, min: 0, max: 100, default: 0 }
    }],
    readabilityScore: {
        type: Number,
        min: 0,
        max: 100,
        default: 75,
        index: true
    },
    sentimentScore: {
        positive: { type: Number, min: 0, max: 1, default: 0.7 },
        negative: { type: Number, min: 0, max: 1, default: 0.1 },
        neutral: { type: Number, min: 0, max: 1, default: 0.2 }
    },
    uniquenessScore: {
        type: Number,
        min: 0,
        max: 100,
        default: 80,
        index: true
    },
    seoScore: {
        type: Number,
        min: 0,
        max: 100,
        default: 60,
        index: true
    }
}, { _id: false });

const optimizationSchema = new mongoose.Schema({
    suggestions: [{
        type: {
            type: String,
            enum: ['grammar', 'tone', 'keywords', 'length', 'clarity', 'impact', 'industry-specific'],
            required: true
        },
        priority: {
            type: String,
            enum: ['high', 'medium', 'low'],
            required: true
        },
        description: { type: String, required: true, maxlength: 200 },
        originalText: { type: String, maxlength: 50 },
        suggestedText: { type: String, maxlength: 50 },
        confidence: { type: Number, min: 0, max: 1, default: 0.8 },
        applied: { type: Boolean, default: false },
        appliedAt: { type: Date }
    }],
    overallScore: {
        type: Number,
        min: 0,
        max: 100,
        default: 70,
        index: true
    },
    categoryScores: {
        grammar: { type: Number, min: 0, max: 100, default: 85 },
        clarity: { type: Number, min: 0, max: 100, default: 75 },
        impact: { type: Number, min: 0, max: 100, default: 70 },
        relevance: { type: Number, min: 0, max: 100, default: 80 },
        professionalism: { type: Number, min: 0, max: 100, default: 85 }
    },
    lastOptimizedAt: { type: Date },
    optimizationVersion: { type: String, default: '1.0' },
    autoOptimizations: [{
        type: { type: String, required: true },
        beforeText: { type: String, required: true },
        afterText: { type: String, required: true },
        confidence: { type: Number, min: 0, max: 1 },
        appliedAt: { type: Date, default: Date.now }
    }]
}, { _id: false });

const performanceSchema = new mongoose.Schema({
    profileViews: {
        total: { type: Number, default: 0, index: true },
        thisWeek: { type: Number, default: 0 },
        thisMonth: { type: Number, default: 0 },
        previousWeek: { type: Number, default: 0 },
        previousMonth: { type: Number, default: 0 }
    },
    searchAppearances: {
        total: { type: Number, default: 0, index: true },
        recruiterSearches: { type: Number, default: 0 },
        peerSearches: { type: Number, default: 0 },
        impressionRate: { type: Number, min: 0, max: 100, default: 0 }
    },
    engagement: {
        profileClicks: { type: Number, default: 0 },
        messagesSent: { type: Number, default: 0 },
        connectionRequests: { type: Number, default: 0 },
        saves: { type: Number, default: 0 },
        shares: { type: Number, default: 0 }
    },
    conversionMetrics: {
        clickThroughRate: { type: Number, min: 0, max: 100, default: 0 },
        engagementRate: { type: Number, min: 0, max: 100, default: 0 },
        conversionRate: { type: Number, min: 0, max: 100, default: 0 }
    },
    industryBenchmarks: {
        viewsPercentile: { type: Number, min: 0, max: 100, default: 50 },
        engagementPercentile: { type: Number, min: 0, max: 100, default: 50 },
        searchPercentile: { type: Number, min: 0, max: 100, default: 50 }
    },
    weeklyAnalytics: [{
        week: { type: Date, required: true },
        profileViews: { type: Number, default: 0 },
        searchAppearances: { type: Number, default: 0 },
        engagement: { type: Number, default: 0 }
    }],
    lastTrackedAt: { type: Date, index: true }
}, { _id: false });

const aiAnalysisSchema = new mongoose.Schema({
    emotionalTone: {
        dominant: {
            type: String,
            enum: ['confident', 'enthusiastic', 'professional', 'innovative', 'collaborative', 'results-driven', 'strategic'],
            index: true
        },
        secondary: [{
            tone: { type: String, required: true },
            strength: { type: Number, min: 0, max: 1 }
        }],
        authenticity: { type: Number, min: 0, max: 1, default: 0.8 }
    },
    personalityTraits: [{
        trait: {
            type: String,
            enum: ['leadership', 'creativity', 'analytical', 'communication', 'innovation', 'teamwork', 'results-oriented', 'strategic']
        },
        confidence: { type: Number, min: 0, max: 1 },
        evidence: [{ type: String, maxlength: 100 }]
    }],
    careerStage: {
        level: {
            type: String,
            enum: ['entry-level', 'mid-level', 'senior', 'executive', 'c-suite', 'entrepreneur', 'consultant'],
            index: true
        },
        confidence: { type: Number, min: 0, max: 1, default: 0.8 },
        indicators: [{ type: String, maxlength: 50 }]
    },
    skillsIdentified: [{
        skill: { type: String, required: true, maxlength: 30 },
        category: {
            type: String,
            enum: ['technical', 'soft', 'industry', 'leadership', 'language'],
            required: true
        },
        confidence: { type: Number, min: 0, max: 1 },
        mentioned: { type: Boolean, default: true }
    }],
    valueProposition: {
        strength: { type: Number, min: 0, max: 100, default: 70 },
        clarity: { type: Number, min: 0, max: 100, default: 75 },
        uniqueness: { type: Number, min: 0, max: 100, default: 60 },
        marketability: { type: Number, min: 0, max: 100, default: 65 }
    },
    competitorAnalysis: {
        similarProfiles: { type: Number, default: 0 },
        averageViews: { type: Number, default: 0 },
        differentiationScore: { type: Number, min: 0, max: 100, default: 50 }
    },
    trendAlignment: {
        currentTrends: [{
            trend: { type: String, required: true },
            alignment: { type: Number, min: 0, max: 1 },
            impact: { type: String, enum: ['high', 'medium', 'low'] }
        }],
        industryRelevance: { type: Number, min: 0, max: 100, default: 70 },
        futureProofScore: { type: Number, min: 0, max: 100, default: 75 }
    },
    analysisVersion: { type: String, default: '1.0' },
    analyzedAt: { type: Date, index: true }
}, { _id: false });

const accessControlSchema = new mongoose.Schema({
    visibility: {
        type: String,
        enum: ['public', 'private', 'team', 'organization'],
        default: 'private',
        index: true
    },
    teamId: {
        type: String,
        index: true,
        validate: {
            validator: function (v) {
                return !v || /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(v);
            },
            message: 'Invalid team UUID'
        }
    },
    organizationId: {
        type: String,
        index: true,
        validate: {
            validator: function (v) {
                return !v || /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(v);
            },
            message: 'Invalid organization UUID'
        }
    },
    collaborators: [{
        userId: {
            type: String,
            required: true,
            validate: {
                validator: function (v) {
                    return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(v);
                },
                message: 'Invalid user UUID'
            }
        },
        role: {
            type: String,
            enum: ['viewer', 'editor', 'admin'],
            default: 'viewer'
        },
        permissions: [{
            type: String,
            enum: ['read', 'edit', 'suggest', 'analyze', 'share']
        }],
        addedAt: { type: Date, default: Date.now }
    }],
    shareSettings: {
        allowPublicView: { type: Boolean, default: false },
        allowCopy: { type: Boolean, default: false },
        allowSuggestions: { type: Boolean, default: true },
        trackViews: { type: Boolean, default: true }
    },
    coachAccess: {
        enabled: { type: Boolean, default: false },
        coachId: { type: String },
        permissions: [{
            type: String,
            enum: ['view', 'suggest', 'edit', 'analyze']
        }],
        grantedAt: { type: Date }
    }
}, { _id: false });

// ===========================
// MAIN HEADLINE SCHEMA
// ===========================
const headlineSchema = new mongoose.Schema({
    headlineId: {
        type: String,
        required: true,
        unique: true,
        index: true,
        immutable: true
    },
    userId: {
        type: String,
        required: true,
        index: true,
        validate: {
            validator: function (v) {
                return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(v);
            },
            message: 'Invalid user UUID'
        }
    },
    text: {
        type: String,
        required: true,
        trim: true,
        minlength: 10,
        maxlength: 220,
        index: 'text'
    },
    originalText: {
        type: String,
        required: true,
        trim: true,
        maxlength: 220
    },
    title: {
        type: String,
        default: '',
        maxlength: 100,
        index: 'text'
    },
    description: {
        type: String,
        default: '',
        maxlength: 500,
        index: 'text'
    },
    category: {
        type: String,
        enum: [
            'executive', 'manager', 'specialist', 'consultant', 'entrepreneur', 
            'freelancer', 'student', 'recent-graduate', 'career-changer', 'returning-professional'
        ],
        required: true,
        index: true
    },
    subCategory: {
        type: String,
        maxlength: 50,
        index: true
    },
    metadata: {
        type: metadataSchema,
        required: true
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
    accessControl: {
        type: accessControlSchema,
        default: () => ({})
    },
    source: {
        type: String,
        enum: ['manual', 'ai-generated', 'template', 'imported', 'collaborative'],
        required: true,
        default: 'manual',
        index: true
    },
    sourceReference: {
        templateId: { type: String, default: '' },
        importSource: { type: String, default: '' },
        aiPrompt: { type: String, default: '', maxlength: 500 },
        aiModel: { type: String, default: '' },
        collaborationId: { type: String, default: '' }
    },
    versions: [{
        versionId: { type: String, required: true },
        text: { type: String, required: true },
        changes: { type: String, maxlength: 500 },
        createdAt: { type: Date, default: Date.now },
        createdBy: { type: String, required: true },
        isActive: { type: Boolean, default: false },
        metadata: { type: metadataSchema, default: () => ({}) },
        optimization: { type: optimizationSchema, default: () => ({}) }
    }],
    tags: [{
        type: String,
        trim: true,
        maxlength: 30,
        index: true
    }],
    customFields: [{
        name: { type: String, required: true, maxlength: 50 },
        value: { type: String, required: true, maxlength: 200 },
        type: {
            type: String,
            enum: ['text', 'number', 'boolean', 'date', 'select'],
            default: 'text'
        }
    }],
    coaching: {
        hasCoachInput: { type: Boolean, default: false },
        coachNotes: [{ type: String, maxlength: 500 }],
        coachRating: { type: Number, min: 1, max: 5 },
        improvementAreas: [{
            area: { type: String, required: true },
            priority: { type: String, enum: ['high', 'medium', 'low'] },
            suggestions: [{ type: String, maxlength: 200 }]
        }],
        lastCoachReview: { type: Date }
    },
    testing: {
        isInTest: { type: Boolean, default: false },
        currentTestId: { type: String, default: '', index: true },
        testHistory: [{
            testId: { type: String, required: true },
            startDate: { type: Date, required: true },
            endDate: { type: Date },
            status: {
                type: String,
                enum: ['running', 'completed', 'stopped'],
                default: 'running'
            },
            performance: {
                views: { type: Number, default: 0 },
                clicks: { type: Number, default: 0 },
                conversions: { type: Number, default: 0 },
                score: { type: Number, default: 0 }
            }
        }]
    },
    integrations: {
        linkedin: {
            connected: { type: Boolean, default: false },
            lastSynced: { type: Date },
            syncStatus: { type: String, enum: ['pending', 'synced', 'failed'], default: 'pending' },
            profileUrl: { type: String, default: '' }
        },
        resume: {
            connected: { type: Boolean, default: false },
            resumeId: { type: String, default: '' },
            lastSynced: { type: Date }
        },
        portfolio: {
            connected: { type: Boolean, default: false },
            portfolioUrl: { type: String, default: '' },
            lastSynced: { type: Date }
        }
    },
    backup: {
        isBackedUp: { type: Boolean, default: false },
        backupUrl: { type: String, default: '' },
        backupDate: { type: Date },
        backupProvider: { type: String, enum: ['s3', 'gcs', 'azure'], default: 's3' },
        encryptionKey: { type: String, default: '' }
    },
    moderation: {
        status: {
            type: String,
            enum: ['pending', 'approved', 'flagged', 'rejected'],
            default: 'pending',
            index: true
        },
        reviewedBy: { type: String },
        reviewedAt: { type: Date },
        flagReason: { type: String, default: '' },
        autoModeration: {
            toxicityScore: { type: Number, min: 0, max: 1, default: 0 },
            profanityScore: { type: Number, min: 0, max: 1, default: 0 },
            spamScore: { type: Number, min: 0, max: 1, default: 0 }
        }
    },
    status: {
        type: String,
        enum: ['draft', 'active', 'inactive', 'archived', 'deleted'],
        default: 'draft',
        index: true
    },
    priority: {
        type: String,
        enum: ['low', 'medium', 'high', 'urgent'],
        default: 'medium',
        index: true
    },
    isTemplate: {
        type: Boolean,
        default: false,
        index: true
    },
    templateMetadata: {
        name: { type: String, default: '', maxlength: 100 },
        description: { type: String, default: '', maxlength: 500 },
        category: { type: String, default: '' },
        usageCount: { type: Number, default: 0 },
        rating: { type: Number, min: 0, max: 5, default: 0 },
        isPublic: { type: Boolean, default: false }
    },
    createdAt: {
        type: Date,
        default: Date.now,
        index: true
    },
    updatedAt: {
        type: Date,
        default: Date.now,
        index: true
    },
    lastUsedAt: {
        type: Date,
        index: true
    },
    lastAnalyzedAt: {
        type: Date,
        index: true
    },
    cacheVersion: {
        type: Number,
        default: 0
    }
}, {
    timestamps: {
        createdAt: 'createdAt',
        updatedAt: 'updatedAt'
    },
    versionKey: 'version',
    strict: true,
    collection: 'headlines',
    read: 'secondaryPreferred',
    shardKey: { userId: 1, category: 1 },
    toJSON: {
        transform: function (doc, ret) {
            ret.id = ret._id;
            delete ret._id;
            delete ret.__v;
            return ret;
        }
    },
    toObject: {
        transform: function (doc, ret) {
            ret.id = ret._id;
            delete ret._id;
            delete ret.__v;
            return ret;
        }
    }
});

// ===========================
// OPTIMIZED INDEXES
// ===========================
headlineSchema.index({ headlineId: 1 }, { unique: true, name: 'idx_headlineId_unique' });
headlineSchema.index({ userId: 1, status: 1 }, { name: 'idx_user_status' });
headlineSchema.index({ category: 1, status: 1 }, { name: 'idx_category_active' });
headlineSchema.index({ 'optimization.overallScore': -1, status: 1 }, { name: 'idx_optimization_score' });
headlineSchema.index({ 'performance.profileViews.total': -1, status: 1 }, { name: 'idx_performance' });
headlineSchema.index({ 'metadata.industry': 1, category: 1, status: 1 }, { name: 'idx_industry_category' });
headlineSchema.index({ 'aiAnalysis.careerStage.level': 1, status: 1 }, { name: 'idx_career_stage' });
headlineSchema.index({ 'metadata.tone': 1, 'metadata.formality': 1, status: 1 }, { name: 'idx_tone_formality' });
headlineSchema.index({ 'accessControl.organizationId': 1, status: 1 }, { name: 'idx_organization' });
headlineSchema.index({ 'accessControl.teamId': 1, status: 1 }, { name: 'idx_team' });
headlineSchema.index({ 'testing.currentTestId': 1, 'testing.isInTest': 1 }, { name: 'idx_ab_testing' });
headlineSchema.index({ isTemplate: 1, 'templateMetadata.isPublic': 1, status: 1 }, { name: 'idx_public_templates' });
headlineSchema.index({ source: 1, createdAt: -1 }, { name: 'idx_source_created' });
headlineSchema.index({ lastUsedAt: -1, userId: 1 }, { name: 'idx_recent_usage' });
headlineSchema.index({ 'moderation.status': 1, createdAt: -1 }, { name: 'idx_moderation_queue' });
headlineSchema.index({ priority: 1, status: 1, updatedAt: -1 }, { name: 'idx_priority_status' });
headlineSchema.index({
    text: 'text',
    title: 'text',
    description: 'text',
    tags: 'text',
    'metadata.keywords.keyword': 'text'
}, {
    weights: {
        text: 10,
        title: 8,
        tags: 6,
        description: 4,
        'metadata.keywords.keyword': 5
    },
    name: 'idx_fulltext_search'
});

// ===========================
// PRE/POST HOOKS
// ===========================
headlineSchema.pre('save', function (next) {
    if (!this.headlineId) {
        this.headlineId = this.generateHeadlineId();
    }

    // Update metadata based on current text
    this.updateMetadata();
    
    // Calculate optimization scores
    this.calculateOptimizationScore();
    
    // Update cache version
    if (this.isModified() && !this.isNew) {
        this.cacheVersion += 1;
    }

    this.updatedAt = new Date();
    next();
});

headlineSchema.pre(/^find/, function (next) {
    // Exclude deleted headlines by default
    if (!this.getQuery().status) {
        this.where({ status: { $ne: 'deleted' } });
    }
    next();
});

headlineSchema.pre(['findOneAndUpdate', 'updateOne', 'updateMany'], function (next) {
    this.set({ 
        updatedAt: new Date(), 
        cacheVersion: { $inc: 1 } 
    });
    next();
});

// ===========================
// INSTANCE METHODS
// ===========================
headlineSchema.methods.generateHeadlineId = function () {
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substring(2, 8);
    return `hl_${timestamp}${random}`;
};

headlineSchema.methods.updateMetadata = function () {
    const text = this.text || '';
    
    // Update character and word counts
    this.metadata.characterCount = text.length;
    this.metadata.wordCount = text.trim().split(/\s+/).length;
    
    // Extract and analyze keywords
    this.extractKeywords();
    
    // Calculate readability score
    this.calculateReadabilityScore();
    
    // Analyze sentiment
    this.analyzeSentiment();
    
    return this;
};

headlineSchema.methods.extractKeywords = function () {
    const text = this.text.toLowerCase();
    const commonWords = ['the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by'];
    const words = text.split(/\W+/).filter(word => 
        word.length > 2 && !commonWords.includes(word)
    );
    
    const wordCount = {};
    words.forEach(word => {
        wordCount[word] = (wordCount[word] || 0) + 1;
    });
    
    const totalWords = words.length;
    this.metadata.keywords = Object.entries(wordCount)
        .sort(([,a], [,b]) => b - a)
        .slice(0, 10)
        .map(([keyword, count]) => ({
            keyword,
            relevance: Math.min(1, count / Math.max(1, totalWords * 0.1)),
            density: Math.round((count / totalWords) * 100)
        }));
    
    return this;
};

headlineSchema.methods.calculateReadabilityScore = function () {
    const text = this.text;
    const sentences = text.split(/[.!?]+/).length;
    const words = text.split(/\s+/).length;
    const characters = text.length;
    
    // Simplified readability calculation
    const avgWordsPerSentence = words / Math.max(1, sentences);
    const avgCharsPerWord = characters / Math.max(1, words);
    
    // Professional headlines should be concise and clear
    let score = 100;
    if (avgWordsPerSentence > 15) score -= 20;
    if (avgCharsPerWord > 6) score -= 15;
    if (words > 20) score -= 10;
    
    this.metadata.readabilityScore = Math.max(0, Math.min(100, score));
    return this;
};

headlineSchema.methods.analyzeSentiment = function () {
    const text = this.text.toLowerCase();
    const positiveWords = ['expert', 'leader', 'innovative', 'successful', 'professional', 'experienced', 'skilled', 'proven', 'accomplished'];
    const negativeWords = ['seeking', 'entry-level', 'junior', 'looking', 'hoping'];
    
    let positive = 0;
    let negative = 0;
    
    positiveWords.forEach(word => {
        if (text.includes(word)) positive++;
    });
    
    negativeWords.forEach(word => {
        if (text.includes(word)) negative++;
    });
    
    const total = Math.max(1, positive + negative);
    this.metadata.sentimentScore = {
        positive: positive / total,
        negative: negative / total,
        neutral: Math.max(0, 1 - (positive + negative) / total)
    };
    
    return this;
};

headlineSchema.methods.calculateOptimizationScore = function () {
    const scores = {
        grammar: 85, // Default - would be calculated by grammar checker
        clarity: this.calculateClarityScore(),
        impact: this.calculateImpactScore(),
        relevance: this.calculateRelevanceScore(),
        professionalism: this.calculateProfessionalismScore()
    };
    
    this.optimization.categoryScores = scores;
    this.optimization.overallScore = Math.round(
        Object.values(scores).reduce((sum, score) => sum + score, 0) / Object.keys(scores).length
    );
    
    return this;
};

headlineSchema.methods.calculateClarityScore = function () {
    const text = this.text;
    let score = 80;
    
    // Penalize overly long headlines
    if (text.length > 120) score -= 20;
    if (this.metadata.wordCount > 15) score -= 15;
    
    // Reward clear structure
    if (text.includes('|') || text.includes('-') || text.includes('•')) score += 10;
    
    return Math.max(0, Math.min(100, score));
};

headlineSchema.methods.calculateImpactScore = function () {
    const text = this.text.toLowerCase();
    const impactWords = ['leader', 'expert', 'innovator', 'strategist', 'results-driven', 'accomplished', 'award-winning'];
    const weakWords = ['responsible for', 'involved in', 'participated', 'helped'];
    
    let score = 60;
    
    impactWords.forEach(word => {
        if (text.includes(word)) score += 8;
    });
    
    weakWords.forEach(word => {
        if (text.includes(word)) score -= 10;
    });
    
    // Numbers and metrics add impact
    if (/\d+[%+]/.test(text)) score += 15;
    if (/\$\d+/.test(text)) score += 12;
    
    return Math.max(0, Math.min(100, score));
};

headlineSchema.methods.calculateRelevanceScore = function () {
    let score = 70;
    
    // Check if industry keywords are present
    const industryKeywords = this.metadata.keywords.filter(k => k.relevance > 0.6);
    score += Math.min(20, industryKeywords.length * 5);
    
    // Check target audience alignment
    if (this.metadata.targetAudience === 'recruiters' && 
        (this.text.toLowerCase().includes('experience') || this.text.toLowerCase().includes('professional'))) {
        score += 10;
    }
    
    return Math.max(0, Math.min(100, score));
};

headlineSchema.methods.calculateProfessionalismScore = function () {
    const text = this.text;
    let score = 85;
    
    // Check for casual language
    const casualWords = ['awesome', 'cool', 'super', 'amazing', 'love'];
    casualWords.forEach(word => {
        if (text.toLowerCase().includes(word)) score -= 15;
    });
    
    // Check for proper capitalization
    const words = text.split(' ');
    const properlyCapitalized = words.filter(word => 
        word.length > 3 && word[0] === word[0].toUpperCase()
    ).length;
    
    if (properlyCapitalized < words.length * 0.3) score -= 10;
    
    return Math.max(0, Math.min(100, score));
};

headlineSchema.methods.createVersion = function (newText, changes = '', userId = null) {
    const versionId = `v${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    
    // Mark current versions as inactive
    this.versions.forEach(v => v.isActive = false);
    
    // Create metadata for new version
    const tempHeadline = {
        text: newText,
        metadata: { ...this.metadata.toObject() }
    };
    
    // Update metadata for new text
    tempHeadline.metadata.characterCount = newText.length;
    tempHeadline.metadata.wordCount = newText.trim().split(/\s+/).length;
    
    this.versions.push({
        versionId,
        text: newText,
        changes,
        createdBy: userId || this.userId,
        isActive: true,
        metadata: tempHeadline.metadata,
        optimization: { ...this.optimization.toObject() },
        createdAt: new Date()
    });
    
    // Keep only last 20 versions
    if (this.versions.length > 20) {
        this.versions = this.versions.slice(-20);
    }
    
    // Update main text
    this.text = newText;
    this.updateMetadata();
    this.calculateOptimizationScore();
    
    return versionId;
};

headlineSchema.methods.addOptimizationSuggestion = function (suggestion) {
    this.optimization.suggestions.push({
        ...suggestion,
        confidence: suggestion.confidence || 0.8,
        applied: false
    });
    
    // Keep only last 50 suggestions
    if (this.optimization.suggestions.length > 50) {
        this.optimization.suggestions = this.optimization.suggestions.slice(-50);
    }
    
    this.optimization.lastOptimizedAt = new Date();
    return this;
};

headlineSchema.methods.applyOptimizationSuggestion = function (suggestionIndex, userId = null) {
    if (suggestionIndex < 0 || suggestionIndex >= this.optimization.suggestions.length) {
        throw new Error('Invalid suggestion index');
    }
    
    const suggestion = this.optimization.suggestions[suggestionIndex];
    if (suggestion.applied) {
        throw new Error('Suggestion already applied');
    }
    
    // Apply the suggestion
    const oldText = this.text;
    if (suggestion.originalText && suggestion.suggestedText) {
        this.text = this.text.replace(suggestion.originalText, suggestion.suggestedText);
    }
    
    // Mark as applied
    suggestion.applied = true;
    suggestion.appliedAt = new Date();
    
    // Create version
    this.createVersion(this.text, `Applied ${suggestion.type} suggestion`, userId);
    
    return this;
};

headlineSchema.methods.recordPerformanceMetrics = function (metrics) {
    const { profileViews, searchAppearances, engagement, period = 'total' } = metrics;
    
    if (period === 'week') {
        this.performance.profileViews.thisWeek += profileViews || 0;
        this.performance.searchAppearances.total += searchAppearances || 0;
        this.performance.engagement.profileClicks += engagement?.profileClicks || 0;
    } else {
        this.performance.profileViews.total += profileViews || 0;
        this.performance.searchAppearances.total += searchAppearances || 0;
        this.performance.engagement.profileClicks += engagement?.profileClicks || 0;
        this.performance.engagement.connectionRequests += engagement?.connectionRequests || 0;
    }
    
    // Update weekly analytics
    const now = new Date();
    const weekStart = new Date(now);
    weekStart.setDate(weekStart.getDate() - weekStart.getDay());
    weekStart.setHours(0, 0, 0, 0);
    
    let weeklyRecord = this.performance.weeklyAnalytics.find(w => 
        w.week.getTime() === weekStart.getTime()
    );
    
    if (!weeklyRecord) {
        weeklyRecord = {
            week: weekStart,
            profileViews: 0,
            searchAppearances: 0,
            engagement: 0
        };
        this.performance.weeklyAnalytics.push(weeklyRecord);
    }
    
    weeklyRecord.profileViews += profileViews || 0;
    weeklyRecord.searchAppearances += searchAppearances || 0;
    weeklyRecord.engagement += (engagement?.profileClicks || 0) + (engagement?.connectionRequests || 0);
    
    // Keep only last 12 weeks
    if (this.performance.weeklyAnalytics.length > 12) {
        this.performance.weeklyAnalytics = this.performance.weeklyAnalytics
            .sort((a, b) => b.week - a.week)
            .slice(0, 12);
    }
    
    this.performance.lastTrackedAt = new Date();
    this.lastUsedAt = new Date();
    
    return this;
};

headlineSchema.methods.getPublicData = function () {
    const headline = this.toObject();
    
    // Remove sensitive data
    delete headline.optimization.suggestions;
    delete headline.performance.weeklyAnalytics;
    delete headline.accessControl.collaborators;
    delete headline.coaching.coachNotes;
    delete headline.backup;
    delete headline.moderation.autoModeration;
    
    // Simplify for public view
    headline.performance = {
        profileViews: headline.performance.profileViews.total,
        overallScore: headline.optimization.overallScore
    };
    
    return headline;
};

headlineSchema.methods.generateAISuggestions = async function (type = 'general') {
    const suggestions = [];
    const currentText = this.text;
    const industry = this.metadata.industry;
    const careerLevel = this.aiAnalysis.careerStage?.level || 'mid-level';
    
    // Generate suggestions based on type
    switch (type) {
        case 'impact':
            suggestions.push({
                type: 'impact',
                priority: 'high',
                description: 'Add quantifiable achievements to increase impact',
                originalText: currentText,
                suggestedText: currentText.replace(/professional/i, 'results-driven professional'),
                confidence: 0.85
            });
            break;
            
        case 'keywords':
            const industryKeywords = this.getIndustryKeywords(industry);
            if (industryKeywords.length > 0) {
                suggestions.push({
                    type: 'keywords',
                    priority: 'medium',
                    description: `Include ${industry} industry keywords`,
                    originalText: currentText,
                    suggestedText: currentText + ` | ${industryKeywords[0]}`,
                    confidence: 0.80
                });
            }
            break;
            
        case 'tone':
            if (this.metadata.tone === 'casual') {
                suggestions.push({
                    type: 'tone',
                    priority: 'medium',
                    description: 'Make tone more professional',
                    originalText: currentText,
                    suggestedText: currentText.replace(/awesome|cool|super/gi, 'exceptional'),
                    confidence: 0.90
                });
            }
            break;
    }
    
    // Add suggestions to the headline
    suggestions.forEach(suggestion => {
        this.addOptimizationSuggestion(suggestion);
    });
    
    return suggestions;
};

headlineSchema.methods.getIndustryKeywords = function (industry) {
    const keywordMap = {
        'technology': ['Software Development', 'Digital Innovation', 'Tech Leadership'],
        'healthcare': ['Patient Care', 'Healthcare Innovation', 'Medical Excellence'],
        'finance': ['Financial Strategy', 'Risk Management', 'Investment Banking'],
        'marketing': ['Digital Marketing', 'Brand Strategy', 'Growth Marketing'],
        'sales': ['Revenue Growth', 'Business Development', 'Client Relations']
    };
    
    return keywordMap[industry.toLowerCase()] || ['Professional Excellence', 'Industry Expertise'];
};

// ===========================
// STATIC METHODS
// ===========================
headlineSchema.statics.findByUser = function (userId, options = {}) {
    const {
        status = 'active',
        category,
        sortBy = 'recent',
        limit = 20,
        page = 1
    } = options;
    
    const query = { userId };
    
    if (status !== 'all') {
        query.status = status;
    }
    
    if (category) {
        query.category = category;
    }
    
    let sortOption = {};
    switch (sortBy) {
        case 'recent':
            sortOption = { updatedAt: -1 };
            break;
        case 'performance':
            sortOption = { 'performance.profileViews.total': -1, updatedAt: -1 };
            break;
        case 'optimization':
            sortOption = { 'optimization.overallScore': -1 };
            break;
        default:
            sortOption = { updatedAt: -1 };
    }
    
    const skip = (page - 1) * limit;
    
    return this.find(query)
        .sort(sortOption)
        .skip(skip)
        .limit(limit)
        .populate({
            path: 'testing.currentTestId',
            model: 'HeadlineTest',
            select: 'testName status performance'
        })
        .lean();
};

headlineSchema.statics.searchHeadlines = function (searchQuery, filters = {}) {
    const {
        categories = [],
        industries = [],
        careerLevels = [],
        tones = [],
        minScore = 0,
        userId,
        organizationId,
        isPublic = false,
        page = 1,
        limit = 20
    } = filters;
    
    const pipeline = [];
    
    // Match stage
    const matchStage = {
        status: 'active',
        'moderation.status': 'approved'
    };
    
    if (searchQuery && searchQuery.trim()) {
        matchStage.$text = { $search: searchQuery.trim() };
    }
    
    if (categories.length > 0) {
        matchStage.category = { $in: categories };
    }
    
    if (industries.length > 0) {
        matchStage['metadata.industry'] = { $in: industries };
    }
    
    if (careerLevels.length > 0) {
        matchStage['aiAnalysis.careerStage.level'] = { $in: careerLevels };
    }
    
    if (tones.length > 0) {
        matchStage['metadata.tone'] = { $in: tones };
    }
    
    if (minScore > 0) {
        matchStage['optimization.overallScore'] = { $gte: minScore };
    }
    
    // Access control
    if (isPublic) {
        matchStage['accessControl.visibility'] = 'public';
        matchStage.isTemplate = true;
        matchStage['templateMetadata.isPublic'] = true;
    } else if (userId) {
        matchStage.$or = [
            { userId },
            { 'accessControl.visibility': 'public' },
            { 'accessControl.collaborators.userId': userId },
            { 'accessControl.organizationId': organizationId }
        ];
    }
    
    pipeline.push({ $match: matchStage });
    
    // Add relevance scoring
    pipeline.push({
        $addFields: {
            relevanceScore: {
                $add: [
                    { $multiply: ['$optimization.overallScore', 0.4] },
                    { $multiply: ['$performance.profileViews.total', 0.0001] },
                    { $multiply: ['$templateMetadata.usageCount', 0.1] },
                    searchQuery && searchQuery.trim() ? { $meta: 'textScore' } : 0
                ]
            }
        }
    });
    
    // Sort by relevance
    pipeline.push({
        $sort: {
            relevanceScore: -1,
            'performance.profileViews.total': -1,
            updatedAt: -1
        }
    });
    
    // Pagination
    const skip = (page - 1) * limit;
    pipeline.push({ $skip: skip });
    pipeline.push({ $limit: limit });
    
    // Project fields
    pipeline.push({
        $project: {
            headlineId: 1,
            userId: 1,
            text: 1,
            title: 1,
            category: 1,
            'metadata.industry': 1,
            'metadata.tone': 1,
            'metadata.characterCount': 1,
            'optimization.overallScore': 1,
            'performance.profileViews.total': 1,
            'aiAnalysis.careerStage.level': 1,
            'templateMetadata.name': 1,
            'templateMetadata.usageCount': 1,
            tags: { $slice: ['$tags', 5] },
            createdAt: 1,
            relevanceScore: 1
        }
    });
    
    return this.aggregate(pipeline);
};

headlineSchema.statics.getTopPerforming = function (timeframe = 30, category = null, limit = 10) {
    const daysAgo = new Date();
    daysAgo.setDate(daysAgo.getDate() - timeframe);
    
    const query = {
        status: 'active',
        'moderation.status': 'approved',
        'accessControl.visibility': 'public',
        'performance.lastTrackedAt': { $gte: daysAgo },
        'performance.profileViews.total': { $gte: 10 }
    };
    
    if (category) {
        query.category = category;
    }
    
    return this.find(query)
        .sort({
            'performance.profileViews.total': -1,
            'optimization.overallScore': -1,
            'performance.conversionMetrics.engagementRate': -1
        })
        .limit(limit)
        .select(`
            headlineId text title category 
            metadata.industry metadata.tone 
            optimization.overallScore 
            performance.profileViews.total 
            performance.conversionMetrics.engagementRate
            aiAnalysis.careerStage.level
        `)
        .lean();
};

headlineSchema.statics.getTemplates = function (category = null, industry = null, limit = 20) {
    const query = {
        isTemplate: true,
        'templateMetadata.isPublic': true,
        status: 'active',
        'moderation.status': 'approved'
    };
    
    if (category) {
        query.category = category;
    }
    
    if (industry) {
        query['metadata.industry'] = industry;
    }
    
    return this.find(query)
        .sort({
            'templateMetadata.usageCount': -1,
            'templateMetadata.rating': -1,
            'optimization.overallScore': -1
        })
        .limit(limit)
        .select(`
            headlineId text 
            templateMetadata.name templateMetadata.description 
            templateMetadata.usageCount templateMetadata.rating
            category metadata.industry metadata.tone
            optimization.overallScore
        `)
        .lean();
};

headlineSchema.statics.getAnalytics = function (userId, timeframe = 30) {
    const daysAgo = new Date();
    daysAgo.setDate(daysAgo.getDate() - timeframe);
    
    return this.aggregate([
        {
            $match: {
                userId,
                status: 'active',
                updatedAt: { $gte: daysAgo }
            }
        },
        {
            $group: {
                _id: null,
                totalHeadlines: { $sum: 1 },
                avgOptimizationScore: { $avg: '$optimization.overallScore' },
                totalViews: { $sum: '$performance.profileViews.total' },
                totalEngagement: { $sum: '$performance.engagement.profileClicks' },
                topCategory: { $push: '$category' },
                topIndustry: { $push: '$metadata.industry' },
                topTone: { $push: '$metadata.tone' }
            }
        },
        {
            $project: {
                totalHeadlines: 1,
                avgOptimizationScore: { $round: ['$avgOptimizationScore', 1] },
                totalViews: 1,
                totalEngagement: 1,
                engagementRate: {
                    $cond: [
                        { $gt: ['$totalViews', 0] },
                        { $round: [{ $multiply: [{ $divide: ['$totalEngagement', '$totalViews'] }, 100] }, 1] },
                        0
                    ]
                }
            }
        }
    ]);
};

// Export model
const Headline = mongoose.model('Headline', headlineSchema);

// Create collection with validation
Headline.createCollection({
    capped: false,
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: ["headlineId", "userId", "text", "category", "metadata"],
            properties: {
                headlineId: {
                    bsonType: "string",
                    description: "Headline ID is required and must be a string"
                },
                userId: {
                    bsonType: "string",
                    pattern: "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
                    description: "User ID must be a valid UUID"
                },
                text: {
                    bsonType: "string",
                    minLength: 10,
                    maxLength: 220,
                    description: "Headline text must be between 10-220 characters"
                },
                category: {
                    bsonType: "string",
                    enum: ['executive', 'manager', 'specialist', 'consultant', 'entrepreneur', 'freelancer', 'student', 'recent-graduate', 'career-changer', 'returning-professional'],
                    description: "Category must be from predefined list"
                }
            }
        }
    }
}).catch(() => {
    // Collection might already exist
});

export default Headline;