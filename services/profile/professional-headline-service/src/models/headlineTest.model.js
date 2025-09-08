import mongoose from 'mongoose';

// ===========================
// OPTIMIZED SUB-SCHEMAS
// ===========================
const testVariantSchema = new mongoose.Schema({
    variantId: {
        type: String,
        required: true,
        index: true
    },
    headlineId: {
        type: String,
        required: true,
        index: true
    },
    text: {
        type: String,
        required: true,
        trim: true,
        maxlength: 220
    },
    name: {
        type: String,
        required: true,
        maxlength: 100
    },
    description: {
        type: String,
        default: '',
        maxlength: 500
    },
    trafficAllocation: {
        type: Number,
        required: true,
        min: 0,
        max: 100,
        default: 50
    },
    isControl: {
        type: Boolean,
        default: false,
        index: true
    },
    status: {
        type: String,
        enum: ['active', 'paused', 'stopped', 'winner'],
        default: 'active',
        index: true
    },
    metadata: {
        characterCount: { type: Number, required: true },
        wordCount: { type: Number, required: true },
        tone: { type: String, required: true },
        optimizationScore: { type: Number, min: 0, max: 100, default: 70 }
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
}, { _id: false });

const performanceMetricsSchema = new mongoose.Schema({
    impressions: {
        type: Number,
        default: 0,
        index: true
    },
    profileViews: {
        type: Number,
        default: 0,
        index: true
    },
    clicks: {
        type: Number,
        default: 0
    },
    conversions: {
        type: Number,
        default: 0
    },
    engagements: {
        connectionRequests: { type: Number, default: 0 },
        messagesSent: { type: Number, default: 0 },
        profileSaves: { type: Number, default: 0 },
        shares: { type: Number, default: 0 }
    },
    searchMetrics: {
        searchAppearances: { type: Number, default: 0 },
        searchClicks: { type: Number, default: 0 },
        searchImpressions: { type: Number, default: 0 },
        averagePosition: { type: Number, default: 0 }
    },
    conversionRates: {
        clickThroughRate: { type: Number, min: 0, max: 100, default: 0 },
        engagementRate: { type: Number, min: 0, max: 100, default: 0 },
        conversionRate: { type: Number, min: 0, max: 100, default: 0 },
        profileCompletionRate: { type: Number, min: 0, max: 100, default: 0 }
    },
    audienceMetrics: {
        recruiterViews: { type: Number, default: 0 },
        peerViews: { type: Number, default: 0 },
        clientViews: { type: Number, default: 0 },
        uniqueVisitors: { type: Number, default: 0 }
    },
    timeMetrics: {
        averageTimeOnProfile: { type: Number, default: 0 }, // seconds
        bounceRate: { type: Number, min: 0, max: 100, default: 0 },
        returnVisitorRate: { type: Number, min: 0, max: 100, default: 0 }
    },
    geographicData: [{
        country: { type: String, required: true },
        region: { type: String, default: '' },
        views: { type: Number, required: true },
        clicks: { type: Number, default: 0 },
        conversions: { type: Number, default: 0 }
    }],
    deviceBreakdown: {
        desktop: {
            views: { type: Number, default: 0 },
            clicks: { type: Number, default: 0 },
            conversions: { type: Number, default: 0 }
        },
        mobile: {
            views: { type: Number, default: 0 },
            clicks: { type: Number, default: 0 },
            conversions: { type: Number, default: 0 }
        },
        tablet: {
            views: { type: Number, default: 0 },
            clicks: { type: Number, default: 0 },
            conversions: { type: Number, default: 0 }
        }
    },
    hourlyData: [{
        hour: { type: Number, min: 0, max: 23, required: true },
        views: { type: Number, default: 0 },
        clicks: { type: Number, default: 0 },
        conversions: { type: Number, default: 0 }
    }],
    lastUpdated: {
        type: Date,
        default: Date.now,
        index: true
    }
}, { _id: false });

const statisticalAnalysisSchema = new mongoose.Schema({
    sampleSize: {
        current: { type: Number, default: 0 },
        required: { type: Number, default: 100 },
        isAdequate: { type: Boolean, default: false }
    },
    confidenceLevel: {
        type: Number,
        min: 80,
        max: 99,
        default: 95
    },
    significance: {
        isSignificant: { type: Boolean, default: false, index: true },
        pValue: { type: Number, min: 0, max: 1, default: 1 },
        confidenceInterval: {
            lower: { type: Number, default: 0 },
            upper: { type: Number, default: 0 }
        },
        effectSize: { type: Number, default: 0 }
    },
    winnerProbability: [{
        variantId: { type: String, required: true },
        probability: { type: Number, min: 0, max: 1, required: true }
    }],
    minimumDetectableEffect: {
        type: Number,
        min: 1,
        max: 50,
        default: 5
    },
    powerAnalysis: {
        statisticalPower: { type: Number, min: 0, max: 1, default: 0.8 },
        betaError: { type: Number, min: 0, max: 1, default: 0.2 },
        alphaError: { type: Number, min: 0, max: 1, default: 0.05 }
    },
    bayesianAnalysis: {
        posteriorProbability: [{
            variantId: { type: String, required: true },
            probability: { type: Number, min: 0, max: 1 }
        }],
        credibilityInterval: {
            lower: { type: Number },
            upper: { type: Number }
        }
    },
    testDuration: {
        plannedDays: { type: Number, min: 7, max: 90, default: 14 },
        actualDays: { type: Number, default: 0 },
        recommendedDays: { type: Number, default: 14 }
    },
    lastCalculated: {
        type: Date,
        default: Date.now
    }
}, { _id: false });

const testConfigurationSchema = new mongoose.Schema({
    testType: {
        type: String,
        enum: ['ab', 'multivariate', 'split-url', 'redirect'],
        default: 'ab',
        required: true
    },
    hypothesis: {
        type: String,
        required: true,
        maxlength: 1000
    },
    primaryMetric: {
        type: String,
        enum: ['profileViews', 'clicks', 'conversions', 'engagementRate', 'searchAppearances'],
        required: true,
        index: true
    },
    secondaryMetrics: [{
        metric: {
            type: String,
            enum: ['profileViews', 'clicks', 'conversions', 'engagementRate', 'searchAppearances', 'timeOnProfile', 'bounceRate'],
            required: true
        },
        weight: { type: Number, min: 0, max: 1, default: 0.1 }
    }],
    targetAudience: {
        industries: [{ type: String, maxlength: 50 }],
        careerLevels: [{
            type: String,
            enum: ['entry-level', 'mid-level', 'senior', 'executive', 'c-suite']
        }],
        geographic: {
            countries: [{ type: String, maxlength: 50 }],
            regions: [{ type: String, maxlength: 50 }],
            excludeCountries: [{ type: String, maxlength: 50 }]
        },
        demographics: {
            ageRanges: [{
                min: { type: Number, min: 18, max: 65 },
                max: { type: Number, min: 18, max: 65 }
            }],
            experienceYears: {
                min: { type: Number, min: 0, max: 50 },
                max: { type: Number, min: 0, max: 50 }
            }
        },
        behavioral: {
            profileCompleteness: { type: Number, min: 0, max: 100 },
            activityLevel: {
                type: String,
                enum: ['low', 'medium', 'high'],
                default: 'medium'
            },
            lastLoginDays: { type: Number, min: 0, max: 365, default: 30 }
        }
    },
    trafficSplit: {
        type: String,
        enum: ['equal', 'weighted', 'adaptive', 'winner-takes-all'],
        default: 'equal'
    },
    adaptiveRules: {
        enabled: { type: Boolean, default: false },
        minSampleSize: { type: Number, min: 50, default: 100 },
        maxTrafficShift: { type: Number, min: 10, max: 90, default: 70 },
        reallocationInterval: { type: Number, min: 24, max: 168, default: 48 } // hours
    },
    stoppingRules: {
        autoStop: { type: Boolean, default: true },
        significanceThreshold: { type: Number, min: 0.01, max: 0.1, default: 0.05 },
        minimumSampleSize: { type: Number, min: 100, default: 1000 },
        maximumDuration: { type: Number, min: 7, max: 90, default: 30 }, // days
        lossThreshold: { type: Number, min: 5, max: 50, default: 10 } // percentage
    }
}, { _id: false });

// ===========================
// MAIN HEADLINE TEST SCHEMA
// ===========================
const headlineTestSchema = new mongoose.Schema({
    testId: {
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
    testName: {
        type: String,
        required: true,
        trim: true,
        maxlength: 200,
        index: 'text'
    },
    description: {
        type: String,
        default: '',
        maxlength: 1000,
        index: 'text'
    },
    category: {
        type: String,
        enum: [
            'tone-optimization', 'keyword-testing', 'length-variation',
            'format-testing', 'industry-focus', 'call-to-action',
            'personalization', 'seasonal', 'competitive-analysis'
        ],
        required: true,
        index: true
    },
    status: {
        type: String,
        enum: ['draft', 'scheduled', 'running', 'paused', 'completed', 'stopped', 'failed'],
        default: 'draft',
        index: true
    },
    priority: {
        type: String,
        enum: ['low', 'medium', 'high', 'urgent'],
        default: 'medium',
        index: true
    },
    variants: {
        type: [testVariantSchema],
        required: true,
        validate: {
            validator: function (variants) {
                return variants && variants.length >= 2 && variants.length <= 10;
            },
            message: 'Test must have between 2 and 10 variants'
        }
    },
    configuration: {
        type: testConfigurationSchema,
        required: true
    },
    performance: {
        overall: { type: performanceMetricsSchema, default: () => ({}) },
        byVariant: [{
            variantId: { type: String, required: true },
            metrics: { type: performanceMetricsSchema, default: () => ({}) }
        }]
    },
    statisticalAnalysis: {
        type: statisticalAnalysisSchema,
        default: () => ({})
    },
    timeline: {
        createdAt: {
            type: Date,
            default: Date.now,
            index: true
        },
        scheduledStartAt: {
            type: Date,
            index: true
        },
        actualStartAt: {
            type: Date,
            index: true
        },
        scheduledEndAt: {
            type: Date,
            index: true
        },
        actualEndAt: {
            type: Date,
            index: true
        },
        pausedAt: { type: Date },
        resumedAt: { type: Date },
        lastUpdatedAt: {
            type: Date,
            default: Date.now,
            index: true
        }
    },
    results: {
        winner: {
            variantId: { type: String, default: '', index: true },
            confidence: { type: Number, min: 0, max: 100, default: 0 },
            improvement: { type: Number, default: 0 },
            significanceLevel: { type: Number, min: 0, max: 1, default: 0 }
        },
        insights: [{
            type: {
                type: String,
                enum: ['performance', 'audience', 'timing', 'demographic', 'behavioral'],
                required: true
            },
            insight: { type: String, required: true, maxlength: 500 },
            confidence: { type: Number, min: 0, max: 1, default: 0.8 },
            actionable: { type: Boolean, default: true },
            impact: {
                type: String,
                enum: ['high', 'medium', 'low'],
                default: 'medium'
            }
        }],
        recommendations: [{
            recommendation: { type: String, required: true, maxlength: 500 },
            priority: {
                type: String,
                enum: ['immediate', 'short-term', 'long-term'],
                default: 'short-term'
            },
            expectedImpact: { type: Number, min: 0, max: 100 },
            effort: {
                type: String,
                enum: ['low', 'medium', 'high'],
                default: 'medium'
            }
        }],
        summary: {
            totalImpressions: { type: Number, default: 0 },
            totalConversions: { type: Number, default: 0 },
            bestPerformingVariant: { type: String, default: '' },
            worstPerformingVariant: { type: String, default: '' },
            overallImprovement: { type: Number, default: 0 },
            statisticalSignificance: { type: Boolean, default: false }
        }
    },
    alerts: [{
        type: {
            type: String,
            enum: ['significance-reached', 'sample-size-met', 'poor-performance', 'test-duration-exceeded', 'error-occurred'],
            required: true
        },
        message: { type: String, required: true, maxlength: 200 },
        severity: {
            type: String,
            enum: ['info', 'warning', 'error', 'critical'],
            default: 'info'
        },
        acknowledged: { type: Boolean, default: false },
        createdAt: { type: Date, default: Date.now },
        acknowledgedAt: { type: Date },
        acknowledgedBy: { type: String }
    }],
    collaboration: {
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
                enum: ['viewer', 'editor', 'analyst', 'admin'],
                default: 'viewer'
            },
            permissions: [{
                type: String,
                enum: ['view', 'edit', 'start', 'stop', 'analyze', 'export']
            }],
            addedAt: { type: Date, default: Date.now }
        }],
        shareSettings: {
            isPublic: { type: Boolean, default: false },
            allowComments: { type: Boolean, default: true },
            allowDataExport: { type: Boolean, default: false }
        }
    },
    integrations: {
        analytics: {
            googleAnalytics: {
                enabled: { type: Boolean, default: false },
                trackingId: { type: String, default: '' },
                goalId: { type: String, default: '' }
            },
            linkedin: {
                enabled: { type: Boolean, default: false },
                campaignId: { type: String, default: '' }
            },
            customTracking: {
                enabled: { type: Boolean, default: false },
                trackingCode: { type: String, default: '' },
                conversionEvents: [{ type: String, maxlength: 100 }]
            }
        },
        notifications: {
            email: {
                enabled: { type: Boolean, default: true },
                recipients: [{ type: String, maxlength: 100 }],
                frequency: {
                    type: String,
                    enum: ['immediate', 'daily', 'weekly', 'milestone'],
                    default: 'milestone'
                }
            },
            slack: {
                enabled: { type: Boolean, default: false },
                webhookUrl: { type: String, default: '' },
                channel: { type: String, default: '' }
            },
            webhook: {
                enabled: { type: Boolean, default: false },
                url: { type: String, default: '' },
                events: [{
                    type: String,
                    enum: ['test-started', 'test-completed', 'significance-reached', 'error-occurred']
                }]
            }
        }
    },
    metadata: {
        source: {
            type: String,
            enum: ['manual', 'automated', 'ai-suggested', 'template'],
            default: 'manual',
            index: true
        },
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
                enum: ['text', 'number', 'boolean', 'date'],
                default: 'text'
            }
        }],
        industry: { type: String, maxlength: 50, index: true },
        targetRole: { type: String, maxlength: 100 },
        budget: { type: Number, min: 0 },
        expectedROI: { type: Number, min: 0 }
    },
    audit: {
        createdBy: {
            type: String,
            required: true,
            validate: {
                validator: function (v) {
                    return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(v);
                },
                message: 'Invalid user UUID'
            }
        },
        modifiedBy: [{
            userId: { type: String, required: true },
            action: { type: String, required: true, maxlength: 100 },
            timestamp: { type: Date, default: Date.now },
            changes: { type: String, maxlength: 500 }
        }],
        approvals: [{
            approvedBy: { type: String, required: true },
            approvedAt: { type: Date, default: Date.now },
            status: {
                type: String,
                enum: ['approved', 'rejected', 'pending'],
                default: 'pending'
            },
            comments: { type: String, maxlength: 500 }
        }]
    },
    cacheVersion: {
        type: Number,
        default: 0
    }
}, {
    timestamps: {
        createdAt: 'timeline.createdAt',
        updatedAt: 'timeline.lastUpdatedAt'
    },
    versionKey: 'version',
    strict: true,
    collection: 'headline_tests',
    read: 'secondaryPreferred',
    shardKey: { userId: 1, status: 1 },
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
headlineTestSchema.index({ testId: 1 }, { unique: true, name: 'idx_testId_unique' });
headlineTestSchema.index({ userId: 1, status: 1 }, { name: 'idx_user_status' });
headlineTestSchema.index({ status: 1, 'timeline.scheduledStartAt': 1 }, { name: 'idx_scheduled_tests' });
headlineTestSchema.index({ status: 1, 'timeline.actualStartAt': 1 }, { name: 'idx_running_tests' });
headlineTestSchema.index({ category: 1, status: 1 }, { name: 'idx_category_status' });
headlineTestSchema.index({ 'configuration.primaryMetric': 1, status: 1 }, { name: 'idx_primary_metric' });
headlineTestSchema.index({ 'collaboration.organizationId': 1, status: 1 }, { name: 'idx_organization_tests' });
headlineTestSchema.index({ 'collaboration.teamId': 1, status: 1 }, { name: 'idx_team_tests' });
headlineTestSchema.index({ 'variants.variantId': 1, status: 1 }, { name: 'idx_variant_lookup' });
headlineTestSchema.index({ 'variants.headlineId': 1 }, { name: 'idx_headline_tests' });
headlineTestSchema.index({ 'statisticalAnalysis.significance.isSignificant': 1, status: 1 }, { name: 'idx_significant_tests' });
headlineTestSchema.index({ 'results.winner.variantId': 1, status: 1 }, { name: 'idx_test_winners' });
headlineTestSchema.index({ priority: 1, status: 1, 'timeline.createdAt': -1 }, { name: 'idx_priority_queue' });
headlineTestSchema.index({ 'metadata.source': 1, 'timeline.createdAt': -1 }, { name: 'idx_source_analytics' });
headlineTestSchema.index({ 'metadata.industry': 1, category: 1, status: 1 }, { name: 'idx_industry_category' });

// Full-text search index
headlineTestSchema.index({
    testName: 'text',
    description: 'text',
    'metadata.tags': 'text',
    'variants.text': 'text'
}, {
    weights: {
        testName: 10,
        'variants.text': 8,
        'metadata.tags': 6,
        description: 4
    },
    name: 'idx_fulltext_search'
});

// ===========================
// PRE/POST HOOKS
// ===========================
headlineTestSchema.pre('save', function (next) {
    if (!this.testId) {
        this.testId = this.generateTestId();
    }

    // Validate traffic allocation
    this.validateTrafficAllocation();

    // Update statistical analysis
    if (this.status === 'running') {
        this.updateStatisticalAnalysis();
    }

    // Update cache version
    if (this.isModified() && !this.isNew) {
        this.cacheVersion += 1;
    }

    this.timeline.lastUpdatedAt = new Date();
    next();
});

headlineTestSchema.pre(/^find/, function (next) {
    // Exclude deleted tests by default
    if (!this.getQuery().status) {
        this.where({ status: { $ne: 'deleted' } });
    }
    next();
});

// ===========================
// INSTANCE METHODS
// ===========================
headlineTestSchema.methods.generateTestId = function () {
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substring(2, 8);
    return `test_${timestamp}${random}`;
};

headlineTestSchema.methods.validateTrafficAllocation = function () {
    const totalAllocation = this.variants.reduce((sum, variant) => sum + variant.trafficAllocation, 0);

    if (Math.abs(totalAllocation - 100) > 0.01) {
        throw new Error(`Traffic allocation must sum to 100%. Current total: ${totalAllocation}%`);
    }

    // Ensure only one control variant
    const controlVariants = this.variants.filter(v => v.isControl);
    if (controlVariants.length !== 1) {
        throw new Error('Test must have exactly one control variant');
    }

    return true;
};

headlineTestSchema.methods.startTest = function () {
    if (this.status !== 'draft' && this.status !== 'scheduled') {
        throw new Error(`Cannot start test with status: ${this.status}`);
    }

    this.status = 'running';
    this.timeline.actualStartAt = new Date();

    // Calculate planned end date
    const plannedDuration = this.statisticalAnalysis.testDuration.plannedDays || 14;
    const endDate = new Date();
    endDate.setDate(endDate.getDate() + plannedDuration);
    this.timeline.scheduledEndAt = endDate;

    // Initialize variant performance
    this.variants.forEach(variant => {
        variant.status = 'active';

        // Find or create performance entry
        let variantPerformance = this.performance.byVariant.find(p => p.variantId === variant.variantId);
        if (!variantPerformance) {
            variantPerformance = {
                variantId: variant.variantId,
                metrics: {}
            };
            this.performance.byVariant.push(variantPerformance);
        }
    });

    // Add audit entry
    this.audit.modifiedBy.push({
        userId: this.userId,
        action: 'test_started',
        timestamp: new Date(),
        changes: `Test started with ${this.variants.length} variants`
    });

    return this;
};

headlineTestSchema.methods.pauseTest = function (reason = '') {
    if (this.status !== 'running') {
        throw new Error(`Cannot pause test with status: ${this.status}`);
    }

    this.status = 'paused';
    this.timeline.pausedAt = new Date();

    // Add audit entry
    this.audit.modifiedBy.push({
        userId: this.userId,
        action: 'test_paused',
        timestamp: new Date(),
        changes: reason || 'Test paused'
    });

    return this;
};

headlineTestSchema.methods.resumeTest = function () {
    if (this.status !== 'paused') {
        throw new Error(`Cannot resume test with status: ${this.status}`);
    }

    this.status = 'running';
    this.timeline.resumedAt = new Date();

    // Add audit entry
    this.audit.modifiedBy.push({
        userId: this.userId,
        action: 'test_resumed',
        timestamp: new Date(),
        changes: 'Test resumed'
    });

    return this;
};

headlineTestSchema.methods.stopTest = function (reason = 'Manual stop') {
    if (this.status !== 'running' && this.status !== 'paused') {
        throw new Error(`Cannot stop test with status: ${this.status}`);
    }

    this.status = 'completed';
    this.timeline.actualEndAt = new Date();

    // Calculate actual duration
    if (this.timeline.actualStartAt) {
        const durationMs = this.timeline.actualEndAt - this.timeline.actualStartAt;
        this.statisticalAnalysis.testDuration.actualDays = Math.ceil(durationMs / (1000 * 60 * 60 * 24));
    }

    // Determine winner
    this.determineWinner();

    // Generate insights and recommendations
    this.generateInsights();

    // Add audit entry
    this.audit.modifiedBy.push({
        userId: this.userId,
        action: 'test_stopped',
        timestamp: new Date(),
        changes: reason
    });

    return this;
};

headlineTestSchema.methods.updateStatisticalAnalysis = function () {
    // Calculate sample sizes
    const totalSampleSize = this.performance.overall.impressions || 0;
    this.statisticalAnalysis.sampleSize.current = totalSampleSize;
    this.statisticalAnalysis.sampleSize.isAdequate = totalSampleSize >= this.statisticalAnalysis.sampleSize.required;

    // Calculate significance for each metric
    if (this.variants.length >= 2 && totalSampleSize > 100) {
        this.calculateStatisticalSignificance();
    }

    // Update winner probabilities
    this.calculateWinnerProbabilities();

    this.statisticalAnalysis.lastCalculated = new Date();
    return this;
};

headlineTestSchema.methods.calculateStatisticalSignificance = function () {
    const primaryMetric = this.configuration.primaryMetric;
    const controlVariant = this.variants.find(v => v.isControl);

    if (!controlVariant) return;

    const controlPerformance = this.performance.byVariant.find(p => p.variantId === controlVariant.variantId);
    if (!controlPerformance) return;

    let maxSignificance = false;
    let minPValue = 1;

    this.variants.filter(v => !v.isControl).forEach(variant => {
        const variantPerformance = this.performance.byVariant.find(p => p.variantId === variant.variantId);
        if (!variantPerformance) return;

        // Simplified z-test calculation (in reality, you'd use proper statistical libraries)
        const controlRate = this.getConversionRate(controlPerformance.metrics, primaryMetric);
        const variantRate = this.getConversionRate(variantPerformance.metrics, primaryMetric);

        const controlSample = controlPerformance.metrics.impressions || 1;
        const variantSample = variantPerformance.metrics.impressions || 1;

        if (controlSample > 30 && variantSample > 30) {
            // Simplified p-value calculation (use proper statistical library in production)
            const pooledRate = ((controlRate * controlSample) + (variantRate * variantSample)) / (controlSample + variantSample);
            const standardError = Math.sqrt(pooledRate * (1 - pooledRate) * (1 / controlSample + 1 / variantSample));

            if (standardError > 0) {
                const zScore = Math.abs(controlRate - variantRate) / standardError;
                const pValue = 2 * (1 - this.normalCDF(Math.abs(zScore)));

                if (pValue < minPValue) {
                    minPValue = pValue;
                }

                if (pValue < this.statisticalAnalysis.powerAnalysis.alphaError) {
                    maxSignificance = true;
                }
            }
        }
    });

    this.statisticalAnalysis.significance.isSignificant = maxSignificance;
    this.statisticalAnalysis.significance.pValue = minPValue;

    return this;
};

headlineTestSchema.methods.getConversionRate = function (metrics, metricType) {
    switch (metricType) {
        case 'profileViews':
            return metrics.impressions > 0 ? metrics.profileViews / metrics.impressions : 0;
        case 'clicks':
            return metrics.profileViews > 0 ? metrics.clicks / metrics.profileViews : 0;
        case 'conversions':
            return metrics.profileViews > 0 ? metrics.conversions / metrics.profileViews : 0;
        case 'engagementRate':
            return metrics.conversionRates ? metrics.conversionRates.engagementRate / 100 : 0;
        default:
            return 0;
    }
};

headlineTestSchema.methods.normalCDF = function (x) {
    // Approximation of the cumulative distribution function of the standard normal distribution
    return 0.5 * (1 + this.erf(x / Math.sqrt(2)));
};

headlineTestSchema.methods.erf = function (x) {
    // Approximation of the error function
    const a1 = 0.254829592;
    const a2 = -0.284496736;
    const a3 = 1.421413741;
    const a4 = -1.453152027;
    const a5 = 1.061405429;
    const p = 0.3275911;

    const sign = x < 0 ? -1 : 1;
    x = Math.abs(x);

    const t = 1.0 / (1.0 + p * x);
    const y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * Math.exp(-x * x);

    return sign * y;
};

headlineTestSchema.methods.calculateWinnerProbabilities = function () {
    const primaryMetric = this.configuration.primaryMetric;
    const probabilities = [];

    this.variants.forEach(variant => {
        const variantPerformance = this.performance.byVariant.find(p => p.variantId === variant.variantId);
        if (variantPerformance) {
            const rate = this.getConversionRate(variantPerformance.metrics, primaryMetric);
            probabilities.push({
                variantId: variant.variantId,
                rate: rate,
                sampleSize: variantPerformance.metrics.impressions || 0
            });
        }
    });

    // Simple winner probability calculation (in production, use Bayesian analysis)
    const totalRate = probabilities.reduce((sum, p) => sum + p.rate, 0);

    this.statisticalAnalysis.winnerProbability = probabilities.map(p => ({
        variantId: p.variantId,
        probability: totalRate > 0 ? p.rate / totalRate : 1 / probabilities.length
    }));

    return this;
};

headlineTestSchema.methods.determineWinner = function () {
    if (this.statisticalAnalysis.winnerProbability.length === 0) {
        this.calculateWinnerProbabilities();
    }

    // Find variant with highest probability
    const winner = this.statisticalAnalysis.winnerProbability.reduce((best, current) =>
        current.probability > best.probability ? current : best
    );

    if (winner) {
        this.results.winner.variantId = winner.variantId;
        this.results.winner.confidence = Math.round(winner.probability * 100);

        // Calculate improvement over control
        const controlVariant = this.variants.find(v => v.isControl);
        const winnerVariant = this.variants.find(v => v.variantId === winner.variantId);

        if (controlVariant && winnerVariant && controlVariant.variantId !== winner.variantId) {
            const controlPerformance = this.performance.byVariant.find(p => p.variantId === controlVariant.variantId);
            const winnerPerformance = this.performance.byVariant.find(p => p.variantId === winner.variantId);

            if (controlPerformance && winnerPerformance) {
                const controlRate = this.getConversionRate(controlPerformance.metrics, this.configuration.primaryMetric);
                const winnerRate = this.getConversionRate(winnerPerformance.metrics, this.configuration.primaryMetric);

                this.results.winner.improvement = controlRate > 0 ?
                    Math.round(((winnerRate - controlRate) / controlRate) * 100) : 0;
            }
        }

        // Update variant status
        this.variants.forEach(variant => {
            variant.status = variant.variantId === winner.variantId ? 'winner' : 'stopped';
        });
    }

    return this;
};

headlineTestSchema.methods.generateInsights = function () {
    const insights = [];
    const recommendations = [];

    // Performance insights
    if (this.results.winner.improvement > 10) {
        insights.push({
            type: 'performance',
            insight: `The winning variant showed a ${this.results.winner.improvement}% improvement over the control`,
            confidence: 0.9,
            impact: 'high'
        });

        recommendations.push({
            recommendation: 'Implement the winning variant as your primary headline',
            priority: 'immediate',
            expectedImpact: this.results.winner.improvement,
            effort: 'low'
        });
    }

    // Audience insights
    const deviceData = this.performance.overall.deviceBreakdown;
    if (deviceData) {
        const totalViews = deviceData.desktop.views + deviceData.mobile.views + deviceData.tablet.views;
        if (totalViews > 0) {
            const mobilePercentage = Math.round((deviceData.mobile.views / totalViews) * 100);

            if (mobilePercentage > 70) {
                insights.push({
                    type: 'audience',
                    insight: `${mobilePercentage}% of views came from mobile devices`,
                    confidence: 0.95,
                    impact: 'medium'
                });

                recommendations.push({
                    recommendation: 'Optimize headlines specifically for mobile viewing',
                    priority: 'short-term',
                    expectedImpact: 15,
                    effort: 'medium'
                });
            }
        }
    }

    // Statistical significance insights
    if (this.statisticalAnalysis.significance.isSignificant) {
        insights.push({
            type: 'performance',
            insight: `Results are statistically significant (p < ${this.statisticalAnalysis.significance.pValue.toFixed(3)})`,
            confidence: 1 - this.statisticalAnalysis.significance.pValue,
            impact: 'high'
        });
    } else {
        recommendations.push({
            recommendation: 'Consider running the test longer to reach statistical significance',
            priority: 'long-term',
            expectedImpact: 10,
            effort: 'low'
        });
    }

    this.results.insights = insights;
    this.results.recommendations = recommendations;

    // Update summary
    this.results.summary = {
        totalImpressions: this.performance.overall.impressions || 0,
        totalConversions: this.performance.overall.conversions || 0,
        bestPerformingVariant: this.results.winner.variantId || '',
        worstPerformingVariant: this.getWorstPerformingVariant(),
        overallImprovement: this.results.winner.improvement || 0,
        statisticalSignificance: this.statisticalAnalysis.significance.isSignificant
    };

    return this;
};

headlineTestSchema.methods.getWorstPerformingVariant = function () {
    const primaryMetric = this.configuration.primaryMetric;
    let worstVariant = '';
    let worstRate = Infinity;

    this.variants.forEach(variant => {
        const performance = this.performance.byVariant.find(p => p.variantId === variant.variantId);
        if (performance) {
            const rate = this.getConversionRate(performance.metrics, primaryMetric);
            if (rate < worstRate) {
                worstRate = rate;
                worstVariant = variant.variantId;
            }
        }
    });

    return worstVariant;
};

headlineTestSchema.methods.addAlert = function (type, message, severity = 'info') {
    this.alerts.push({
        type,
        message,
        severity,
        acknowledged: false,
        createdAt: new Date()
    });

    // Keep only last 50 alerts
    if (this.alerts.length > 50) {
        this.alerts = this.alerts.slice(-50);
    }

    return this;
};

headlineTestSchema.methods.acknowledgeAlert = function (alertIndex, userId) {
    if (alertIndex >= 0 && alertIndex < this.alerts.length) {
        this.alerts[alertIndex].acknowledged = true;
        this.alerts[alertIndex].acknowledgedAt = new Date();
        this.alerts[alertIndex].acknowledgedBy = userId;
    }
    return this;
};

headlineTestSchema.methods.recordMetrics = function (variantId, metrics) {
    let variantPerformance = this.performance.byVariant.find(p => p.variantId === variantId);

    if (!variantPerformance) {
        variantPerformance = {
            variantId,
            metrics: {}
        };
        this.performance.byVariant.push(variantPerformance);
    }

    // Update variant metrics
    Object.keys(metrics).forEach(key => {
        if (typeof metrics[key] === 'number') {
            variantPerformance.metrics[key] = (variantPerformance.metrics[key] || 0) + metrics[key];
        } else if (typeof metrics[key] === 'object') {
            variantPerformance.metrics[key] = variantPerformance.metrics[key] || {};
            Object.keys(metrics[key]).forEach(subKey => {
                if (typeof metrics[key][subKey] === 'number') {
                    variantPerformance.metrics[key][subKey] =
                        (variantPerformance.metrics[key][subKey] || 0) + metrics[key][subKey];
                }
            });
        }
    });

    // Update overall metrics
    Object.keys(metrics).forEach(key => {
        if (typeof metrics[key] === 'number') {
            this.performance.overall[key] = (this.performance.overall[key] || 0) + metrics[key];
        } else if (typeof metrics[key] === 'object') {
            this.performance.overall[key] = this.performance.overall[key] || {};
            Object.keys(metrics[key]).forEach(subKey => {
                if (typeof metrics[key][subKey] === 'number') {
                    this.performance.overall[key][subKey] =
                        (this.performance.overall[key][subKey] || 0) + metrics[key][subKey];
                }
            });
        }
    });

    // Update conversion rates
    this.updateConversionRates(variantId);

    // Update statistical analysis
    this.updateStatisticalAnalysis();

    // Check for automatic stopping conditions
    this.checkStoppingConditions();

    variantPerformance.metrics.lastUpdated = new Date();
    this.timeline.lastUpdatedAt = new Date();

    return this;
};

headlineTestSchema.methods.updateConversionRates = function (variantId) {
    const variantPerformance = this.performance.byVariant.find(p => p.variantId === variantId);
    if (!variantPerformance) return;

    const metrics = variantPerformance.metrics;

    // Calculate conversion rates
    if (metrics.impressions > 0) {
        metrics.conversionRates = metrics.conversionRates || {};

        metrics.conversionRates.clickThroughRate =
            Math.round((metrics.profileViews / metrics.impressions) * 100 * 100) / 100;

        if (metrics.profileViews > 0) {
            metrics.conversionRates.engagementRate =
                Math.round(((metrics.engagements?.connectionRequests || 0) / metrics.profileViews) * 100 * 100) / 100;

            metrics.conversionRates.conversionRate =
                Math.round((metrics.conversions / metrics.profileViews) * 100 * 100) / 100;
        }
    }

    return this;
};

headlineTestSchema.methods.checkStoppingConditions = function () {
    if (!this.configuration.stoppingRules.autoStop) return;

    const rules = this.configuration.stoppingRules;

    // Check maximum duration
    if (this.timeline.actualStartAt) {
        const daysSinceStart = (Date.now() - this.timeline.actualStartAt) / (1000 * 60 * 60 * 24);
        if (daysSinceStart >= rules.maximumDuration) {
            this.addAlert('test-duration-exceeded',
                `Test has been running for ${Math.round(daysSinceStart)} days, exceeding maximum duration of ${rules.maximumDuration} days`,
                'warning'
            );
        }
    }

    // Check statistical significance
    if (this.statisticalAnalysis.significance.isSignificant &&
        this.statisticalAnalysis.sampleSize.current >= rules.minimumSampleSize) {

        this.addAlert('significance-reached',
            `Test has reached statistical significance with ${this.statisticalAnalysis.sampleSize.current} samples`,
            'info'
        );
    }

    // Check for poor performance (significant loss)
    const controlVariant = this.variants.find(v => v.isControl);
    if (controlVariant) {
        const controlPerformance = this.performance.byVariant.find(p => p.variantId === controlVariant.variantId);

        this.variants.filter(v => !v.isControl).forEach(variant => {
            const variantPerformance = this.performance.byVariant.find(p => p.variantId === variant.variantId);

            if (controlPerformance && variantPerformance &&
                variantPerformance.metrics.impressions >= 100) {

                const controlRate = this.getConversionRate(controlPerformance.metrics, this.configuration.primaryMetric);
                const variantRate = this.getConversionRate(variantPerformance.metrics, this.configuration.primaryMetric);

                if (controlRate > 0) {
                    const lossPercentage = ((controlRate - variantRate) / controlRate) * 100;
                    if (lossPercentage >= rules.lossThreshold) {
                        this.addAlert('poor-performance',
                            `Variant ${variant.name} is performing ${Math.round(lossPercentage)}% worse than control`,
                            'warning'
                        );
                    }
                }
            }
        });
    }

    return this;
};

// ===========================
// STATIC METHODS
// ===========================
headlineTestSchema.statics.findByUser = function (userId, options = {}) {
    const {
        status,
        category,
        sortBy = 'recent',
        limit = 20,
        page = 1
    } = options;

    const query = { userId };

    if (status && status !== 'all') {
        query.status = status;
    }

    if (category) {
        query.category = category;
    }

    let sortOption = {};
    switch (sortBy) {
        case 'recent':
            sortOption = { 'timeline.createdAt': -1 };
            break;
        case 'performance':
            sortOption = { 'performance.overall.conversions': -1, 'timeline.createdAt': -1 };
            break;
        case 'significance':
            sortOption = { 'statisticalAnalysis.significance.isSignificant': -1, 'statisticalAnalysis.significance.pValue': 1 };
            break;
        default:
            sortOption = { 'timeline.lastUpdatedAt': -1 };
    }

    const skip = (page - 1) * limit;

    return this.find(query)
        .sort(sortOption)
        .skip(skip)
        .limit(limit)
        .populate({
            path: 'variants.headlineId',
            model: 'Headline',
            select: 'text title category'
        })
        .select('-performance.byVariant.metrics.hourlyData -performance.byVariant.metrics.geographicData')
        .lean();
};

headlineTestSchema.statics.getRunningTests = function () {
    return this.find({
        status: 'running',
        'timeline.actualStartAt': { $exists: true }
    })
        .populate({
            path: 'variants.headlineId',
            model: 'Headline',
            select: 'text userId'
        })
        .select('testId testName userId variants.variantId variants.headlineId variants.trafficAllocation timeline.actualStartAt configuration.stoppingRules')
        .lean();
};

headlineTestSchema.statics.getScheduledTests = function () {
    const now = new Date();

    return this.find({
        status: 'scheduled',
        'timeline.scheduledStartAt': { $lte: now }
    })
        .populate({
            path: 'variants.headlineId',
            model: 'Headline',
            select: 'text userId status'
        })
        .lean();
};

headlineTestSchema.statics.getTestAnalytics = function (userId, timeframe = 30) {
    const daysAgo = new Date();
    daysAgo.setDate(daysAgo.getDate() - timeframe);

    return this.aggregate([
        {
            $match: {
                userId,
                'timeline.createdAt': { $gte: daysAgo }
            }
        },
        {
            $group: {
                _id: null,
                totalTests: { $sum: 1 },
                runningTests: {
                    $sum: { $cond: [{ $eq: ['$status', 'running'] }, 1, 0] }
                },
                completedTests: {
                    $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] }
                },
                significantTests: {
                    $sum: { $cond: ['$statisticalAnalysis.significance.isSignificant', 1, 0] }
                },
                totalImpressions: { $sum: '$performance.overall.impressions' },
                totalConversions: { $sum: '$performance.overall.conversions' },
                avgTestDuration: { $avg: '$statisticalAnalysis.testDuration.actualDays' },
                categories: { $push: '$category' }
            }
        },
        {
            $project: {
                totalTests: 1,
                runningTests: 1,
                completedTests: 1,
                significantTests: 1,
                totalImpressions: 1,
                totalConversions: 1,
                avgTestDuration: { $round: ['$avgTestDuration', 1] },
                successRate: {
                    $cond: [
                        { $gt: ['$completedTests', 0] },
                        { $round: [{ $multiply: [{ $divide: ['$significantTests', '$completedTests'] }, 100] }, 1] },
                        0
                    ]
                },
                overallConversionRate: {
                    $cond: [
                        { $gt: ['$totalImpressions', 0] },
                        { $round: [{ $multiply: [{ $divide: ['$totalConversions', '$totalImpressions'] }, 100] }, 2] },
                        0
                    ]
                }
            }
        }
    ]);
};

headlineTestSchema.statics.getTopPerformingTests = function (timeframe = 30, limit = 10) {
    const daysAgo = new Date();
    daysAgo.setDate(daysAgo.getDate() - timeframe);

    return this.find({
        status: 'completed',
        'timeline.actualEndAt': { $gte: daysAgo },
        'statisticalAnalysis.significance.isSignificant': true,
        'results.winner.improvement': { $gt: 0 }
    })
        .sort({
            'results.winner.improvement': -1,
            'results.winner.confidence': -1,
            'performance.overall.conversions': -1
        })
        .limit(limit)
        .select(`
        testId testName category
        results.winner.improvement results.winner.confidence
        performance.overall.impressions performance.overall.conversions
        statisticalAnalysis.significance.pValue
        timeline.actualStartAt timeline.actualEndAt
    `)
        .lean();
};

// Export model
const HeadlineTest = mongoose.model('HeadlineTest', headlineTestSchema);

// Create collection with validation
HeadlineTest.createCollection({
    capped: false,
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: ["testId", "userId", "testName", "category", "variants", "configuration"],
            properties: {
                testId: {
                    bsonType: "string",
                    description: "Test ID is required and must be a string"
                },
                userId: {
                    bsonType: "string",
                    pattern: "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
                    description: "User ID must be a valid UUID"
                },
                testName: {
                    bsonType: "string",
                    minLength: 1,
                    maxLength: 200,
                    description: "Test name must be between 1-200 characters"
                },
                variants: {
                    bsonType: "array",
                    minItems: 2,
                    maxItems: 10,
                    description: "Test must have between 2 and 10 variants"
                }
            }
        }
    }
}).catch(() => {
    // Collection might already exist
});

export default HeadlineTest;