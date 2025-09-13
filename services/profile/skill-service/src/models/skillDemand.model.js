import mongoose, { Schema } from 'mongoose';
import aggregatePaginate from 'mongoose-aggregate-paginate-v2';
import mongooseAlgolia from 'mongoose-algolia';
import validator from 'validator';
import sanitizeHtml from 'sanitize-html';
import Redis from 'ioredis';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';

// Redis Cluster Configuration
const createRedisCluster = () => {
    if (process.env.REDIS_CLUSTER_NODES) {
        return new Redis.Cluster(
            process.env.REDIS_CLUSTER_NODES.split(',').map(node => ({
                host: node.split(':')[0],
                port: parseInt(node.split(':')[1]),
            })),
            {
                redisOptions: {
                    password: process.env.REDIS_PASSWORD,
                    connectTimeout: 10000,
                    maxRetriesPerRequest: 5,
                    retryDelayOnFailover: 100,
                    keepAlive: 1000,
                },
                enableOfflineQueue: false,
                scaleReads: 'slave',
                slotsRefreshTimeout: 10000,
                slotsRefreshInterval: 30000,
            }
        );
    }

    return new Redis({
        host: process.env.REDIS_HOST || 'localhost',
        port: process.env.REDIS_PORT || 6379,
        password: process.env.REDIS_PASSWORD,
        connectTimeout: 10000,
        maxRetriesPerRequest: 5,
        retryDelayOnFailover: 100,
        keepAlive: 1000,
        keyPrefix: 'skill_demand:',
        db: 1,
    });
};

const redis = createRedisCluster();
redis.on('error', err => console.error('Redis error:', err));
redis.connect().catch(err => console.error('Redis connection error:', err));

// Cache TTL Constants
const CACHE_TTL = {
    SHORT: 300,      // 5 minutes
    MEDIUM: 1800,    // 30 minutes
    LONG: 3600,      // 1 hour
    EXTRA_LONG: 86400 // 24 hours
};

// Validation Functions
const validateSkillName = (value) => /^[a-zA-Z0-9\s\-&()#\+\/\.]+$/.test(value);
const validateCountryCode = (value) => /^[A-Z]{2,3}$/.test(value);

// Sub-Schemas
const metadataSchema = new Schema({
    source: {
        type: String,
        default: 'system',
        enum: ['system', 'job-board', 'api', 'external-analysis', 'manual', 'ml-prediction'],
        index: true
    },
    dataProvider: {
        type: String,
        maxlength: 50,
        index: true
    },
    confidence: {
        type: Number,
        min: 0,
        max: 100,
        default: 70
    },
    lastUpdated: {
        type: Date,
        default: Date.now,
        index: true
    },
    version: {
        type: Number,
        default: 1,
        min: 1
    },
    refreshInterval: {
        type: Number,
        default: 86400,
        min: 3600
    },
}, { _id: false });

const analyticsSchema = new Schema({
    viewCount: {
        type: Number,
        default: 0,
        min: 0,
        index: true
    },
    queryCount: {
        type: Number,
        default: 0,
        min: 0
    },
    engagementScore: {
        type: Number,
        default: 0,
        min: 0,
        max: 1000,
        index: true
    },
    lastViewed: {
        type: Date,
        index: true
    },
    avgResponseTime: {
        type: Number,
        default: 0,
        min: 0
    },
    errorRate: {
        type: Number,
        default: 0,
        min: 0,
        max: 100
    },
}, { _id: false });

const statusSchema = new Schema({
    isActive: {
        type: Boolean,
        default: true,
        index: true
    },
    isStale: {
        type: Boolean,
        default: false,
        index: true
    },
    isDeleted: {
        type: Boolean,
        default: false,
        index: true
    },
    deletedAt: {
        type: Date,
        index: true,
        sparse: true
    },
    lastAnalyzed: {
        type: Date,
        default: Date.now,
        index: true
    },
    nextAnalysis: {
        type: Date,
        index: true
    },
}, { _id: false });

const trendDataPointSchema = new Schema({
    timestamp: {
        type: Date,
        required: true,
        index: true
    },
    trendScore: {
        type: Number,
        min: 0,
        max: 100,
        required: true,
        index: true
    },
    growthRate: {
        type: Number,
        min: -100,
        max: 100,
        default: 0
    },
    jobPostingsCount: {
        type: Number,
        min: 0,
        default: 0,
        index: true
    },
    userAdoptionRate: {
        type: Number,
        min: 0,
        max: 100,
        default: 0
    },
    averageSalary: {
        type: Number,
        min: 0,
        sparse: true
    },
    demandLevel: {
        type: String,
        enum: ['very-low', 'low', 'medium', 'high', 'very-high'],
        default: 'medium',
        index: true
    },
    meta: {
        sources: { type: Number, default: 1, min: 1 },
        reliability: { type: Number, default: 70, min: 0, max: 100 }
    },
}, { _id: false });

const regionalDataSchema = new Schema({
    countryCode: {
        type: String,
        maxlength: 3,
        required: true,
        index: true,
        validate: { validator: validateCountryCode, message: 'Invalid country code' },
        uppercase: true
    },
    regionCode: {
        type: String,
        maxlength: 10,
        index: true
    },
    trendScore: {
        type: Number,
        min: 0,
        max: 100,
        default: 0,
        index: true
    },
    jobPostingsCount: {
        type: Number,
        min: 0,
        default: 0
    },
    userAdoptionRate: {
        type: Number,
        min: 0,
        max: 100,
        default: 0
    },
    lastUpdated: {
        type: Date,
        default: Date.now
    },
}, { _id: false });

const marketSegmentSchema = new Schema({
    industry: {
        type: String,
        maxlength: 50,
        index: true
    },
    companySize: {
        type: String,
        enum: ['startup', 'small', 'medium', 'large', 'enterprise'],
        index: true
    },
    demandScore: {
        type: Number,
        min: 0,
        max: 100,
        default: 0
    },
    salaryRange: {
        min: { type: Number, min: 0 },
        max: { type: Number, min: 0 }
    },
}, { _id: false });

// Main SkillDemand Schema
const skillDemandSchema = new Schema({
    _id: {
        type: String,
        default: () => uuidv4(),
        index: true
    },
    skillId: {
        type: String,
        index: true,
        sparse: true
    },
    categoryId: {
        type: String,
        index: true,
        sparse: true
    },
    skillName: {
        type: String,
        required: [true, 'Skill name is required'],
        trim: true,
        maxlength: 50,
        index: true,
        validate: { validator: validateSkillName, message: 'Invalid skill name format' }
    },
    normalizedSkillName: {
        type: String,
        index: true,
        lowercase: true
    },
    categoryName: {
        type: String,
        trim: true,
        maxlength: 50,
        index: true
    },
    trendData: {
        daily: [trendDataPointSchema],
        weekly: [trendDataPointSchema],
        monthly: [trendDataPointSchema],
        quarterly: [trendDataPointSchema],
    },
    regionalData: [regionalDataSchema],
    marketSegments: [marketSegmentSchema],
    currentSnapshot: {
        trendScore: { type: Number, min: 0, max: 100, default: 0, index: true },
        demandLevel: { type: String, enum: ['very-low', 'low', 'medium', 'high', 'very-high'], default: 'medium', index: true },
        jobPostingsCount: { type: Number, min: 0, default: 0, index: true },
        averageSalary: { type: Number, min: 0, sparse: true },
        growthRate: { type: Number, min: -100, max: 100, default: 0 },
        lastCalculated: { type: Date, default: Date.now, index: true },
    },
    analytics: analyticsSchema,
    metadata: metadataSchema,
    status: statusSchema,
    compositeTrendScore: { type: Number, default: 0, index: true },
    volatilityScore: { type: Number, min: 0, max: 100, default: 0 },
    searchVector: { type: String, index: 'text' },
    cache: {
        version: { type: Number, default: 1 },
        lastUpdate: { type: Date, default: Date.now, index: true },
        hash: { type: String, index: true },
    },
}, {
    timestamps: true,
    collection: 'skill_demands',
    readPreference: 'secondaryPreferred',
    writeConcern: { w: 1, wtimeout: 5000 },
    toJSON: {
        virtuals: true,
        transform: (doc, ret) => {
            delete ret.__v;
            delete ret.searchVector;
            delete ret.cache.hash;
            return ret;
        },
    },
    toObject: { virtuals: true },
    minimize: false,
    strict: 'throw',
    shardKey: { normalizedSkillName: 'hashed' },
});

// Indexes
skillDemandSchema.index({ normalizedSkillName: 1, 'status.isActive': 1, 'status.isStale': 1 }, { background: true });
skillDemandSchema.index({ skillId: 1, 'metadata.lastUpdated': -1 }, { background: true, sparse: true });
skillDemandSchema.index({ compositeTrendScore: -1, 'status.isActive': 1, 'currentSnapshot.demandLevel': 1 }, { background: true });
skillDemandSchema.index({ 'regionalData.countryCode': 1, 'regionalData.trendScore': -1, 'status.isActive': 1 }, { background: true });
skillDemandSchema.index({ categoryName: 1, 'currentSnapshot.trendScore': -1, 'status.lastAnalyzed': -1 }, { background: true });
skillDemandSchema.index({ 'currentSnapshot.lastCalculated': -1, 'status.isActive': 1 }, { background: true });
skillDemandSchema.index({
    skillName: 'text',
    normalizedSkillName: 'text',
    categoryName: 'text',
    searchVector: 'text',
}, {
    weights: { skillName: 10, normalizedSkillName: 8, categoryName: 5, searchVector: 1 },
    name: 'demand_text_search',
    background: true,
});
skillDemandSchema.index({ 'status.nextAnalysis': 1 }, { partialFilterExpression: { 'status.isActive': true, 'status.isStale': false }, background: true });
skillDemandSchema.index({ 'marketSegments.industry': 1, 'marketSegments.companySize': 1, compositeTrendScore: -1 }, { background: true, sparse: true });
skillDemandSchema.index({ 'status.deletedAt': 1 }, { expireAfterSeconds: 7776000, sparse: true });

// Virtuals
skillDemandSchema.virtual('latestTrend').get(function () {
    const daily = this.trendData?.daily || [];
    if (daily.length > 0) return daily[daily.length - 1];
    const weekly = this.trendData?.weekly || [];
    if (weekly.length > 0) return weekly[weekly.length - 1];
    return this.currentSnapshot || null;
});

skillDemandSchema.virtual('isHighDemand').get(function () {
    return ['high', 'very-high'].includes(this.currentSnapshot?.demandLevel);
});

skillDemandSchema.virtual('isTrending').get(function () {
    return this.compositeTrendScore >= 75;
});

skillDemandSchema.virtual('isVolatile').get(function () {
    return this.volatilityScore >= 60;
});

skillDemandSchema.virtual('dataFreshness').get(function () {
    if (!this.metadata?.lastUpdated) return 'unknown';
    const hoursOld = (Date.now() - this.metadata.lastUpdated) / (1000 * 60 * 60);
    if (hoursOld < 1) return 'fresh';
    if (hoursOld < 24) return 'recent';
    if (hoursOld < 168) return 'week-old';
    return 'stale';
});

skillDemandSchema.virtual('regionalHotspots').get(function () {
    return (this.regionalData || [])
        .filter(region => region.trendScore >= 70)
        .sort((a, b) => b.trendScore - a.trendScore)
        .slice(0, 5);
});

// Middleware
skillDemandSchema.pre('validate', function (next) {
    if (this.trendData?.daily?.length > 30) this.trendData.daily = this.trendData.daily.slice(-30);
    if (this.trendData?.weekly?.length > 52) this.trendData.weekly = this.trendData.weekly.slice(-52);
    if (this.trendData?.monthly?.length > 24) this.trendData.monthly = this.trendData.monthly.slice(-24);
    if (this.trendData?.quarterly?.length > 8) this.trendData.quarterly = this.trendData.quarterly.slice(-8);
    next();
});

skillDemandSchema.pre('save', async function (next) {
    try {
        this.normalizedSkillName = this.skillName.toLowerCase().trim();
        this.metadata.lastUpdated = new Date();
        this.metadata.version += 1;

        const contentStr = JSON.stringify({
            skill: this.normalizedSkillName,
            category: this.categoryName,
            current: this.currentSnapshot,
            regional: this.regionalData,
        });
        this.cache.hash = crypto.createHash('md5').update(contentStr).digest('hex');

        this.searchVector = [
            this.skillName,
            this.normalizedSkillName,
            this.categoryName,
            ...(this.marketSegments?.map(s => s.industry) || []),
        ].filter(Boolean).join(' ').toLowerCase();

        this.compositeTrendScore = this.calculateCompositeTrendScore();
        this.volatilityScore = this.calculateVolatilityScore();

        if (!this.status.nextAnalysis) {
            const nextAnalysis = new Date();
            nextAnalysis.setSeconds(nextAnalysis.getSeconds() + this.metadata.refreshInterval);
            this.status.nextAnalysis = nextAnalysis;
        }

        this.status.lastAnalyzed = new Date();
        this.status.isStale = false;
        this.cache.lastUpdate = new Date();
        this.cache.version += 1;

        const pipeline = redis.pipeline();
        pipeline.setex(`demand:${this._id}`, CACHE_TTL.MEDIUM, JSON.stringify(this.toJSON()));
        pipeline.publish('skill_demand_updates', JSON.stringify({
            demandId: this._id,
            skillId: this.skillId,
            skillName: this.skillName,
            action: 'updated',
            compositeTrendScore: this.compositeTrendScore,
            demandLevel: this.currentSnapshot?.demandLevel,
        }));
        await pipeline.exec();

        next();
    } catch (error) {
        next(new Error(`Pre-save error: ${error.message}`));
    }
});

skillDemandSchema.pre('remove', async function (next) {
    try {
        this.status.isDeleted = true;
        this.status.deletedAt = new Date();
        this.status.isActive = false;
        const pipeline = redis.pipeline();
        pipeline.del(`demand:${this._id}`);
        await pipeline.exec();
        await this.save();
        next();
    } catch (error) {
        next(new Error(`Pre-remove error: ${error.message}`));
    }
});

skillDemandSchema.post('save', async function (doc) {
    try {
        const pipeline = redis.pipeline();
        pipeline.del(`skill:trends:${doc.skillId}`);
        pipeline.del(`category:trends:${doc.categoryId}`);
        pipeline.del(`trending:${doc.normalizedSkillName}`);
        pipeline.del(`regional:${doc._id}`);
        if (doc.status.isActive && !doc.status.isStale) {
            await doc.syncToAlgolia();
        }
        await pipeline.exec();
    } catch (error) {
        console.error('Post-save error:', error.message);
    }
});

// Instance Methods
skillDemandSchema.methods.calculateCompositeTrendScore = function () {
    const current = this.currentSnapshot || {};
    const weights = {
        trend: 0.4,
        jobs: 0.3,
        growth: 0.2,
        adoption: 0.1,
    };
    const jobScore = current.jobPostingsCount > 0 ? Math.min(100, (Math.log10(current.jobPostingsCount + 1) / Math.log10(10000)) * 100) : 0;
    const growthScore = Math.max(0, (current.growthRate + 100) / 2);
    const regionalCount = this.regionalData?.length || 0;
    const score =
        (current.trendScore * weights.trend) +
        (jobScore * weights.jobs) +
        (growthScore * weights.growth) +
        (regionalCount * 10 * weights.adoption);
    return Math.min(100, Math.round(score));
};

skillDemandSchema.methods.calculateVolatilityScore = function () {
    const daily = this.trendData?.daily || [];
    if (daily.length < 7) return 0;
    const scores = daily.slice(-7).map(d => d.trendScore);
    const mean = scores.reduce((a, b) => a + b, 0) / scores.length;
    const variance = scores.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / scores.length;
    const stdDev = Math.sqrt(variance);
    return Math.min(100, Math.round((stdDev / mean) * 100));
};

skillDemandSchema.methods.addTrendDataPoint = async function (timeframe, dataPoint) {
    if (!this.trendData) this.trendData = {};
    if (!this.trendData[timeframe]) this.trendData[timeframe] = [];
    this.trendData[timeframe].push(dataPoint);
    const limits = { daily: 30, weekly: 52, monthly: 24, quarterly: 8 };
    const limit = limits[timeframe] || 100;
    if (this.trendData[timeframe].length > limit) {
        this.trendData[timeframe] = this.trendData[timeframe].slice(-limit);
    }
    if (timeframe === 'daily' || (timeframe === 'weekly' && !this.trendData.daily?.length)) {
        this.currentSnapshot = {
            ...this.currentSnapshot,
            trendScore: dataPoint.trendScore,
            demandLevel: dataPoint.demandLevel,
            jobPostingsCount: dataPoint.jobPostingsCount,
            growthRate: dataPoint.growthRate,
            lastCalculated: new Date(),
        };
    }
    await this.save();
};

skillDemandSchema.methods.getRecentTrend = function (days = 30) {
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - days);
    const allTrends = [
        ...(this.trendData?.daily || []),
        ...(this.trendData?.weekly || []),
        ...(this.trendData?.monthly || []),
        ...(this.trendData?.quarterly || []),
    ].filter(trend => trend.timestamp >= cutoff)
        .sort((a, b) => a.timestamp - b.timestamp);
    return allTrends;
};

// Static Methods
skillDemandSchema.statics.getDemandTrends = async function (options = {}) {
    const { page = 1, limit = 50, sortBy = 'compositeTrendScore', sortOrder = -1, category, demandLevel, countryCode, minTrendScore = 0, includeStale = false } = options;
    const cacheKey = `trends:${JSON.stringify(options)}`;
    const cached = await redis.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const query = {
        'status.isActive': true,
        'status.isDeleted': false,
        ...(category && { categoryName: new RegExp(category, 'i') }),
        ...(demandLevel && { 'currentSnapshot.demandLevel': demandLevel }),
        ...(minTrendScore && { compositeTrendScore: { $gte: minTrendScore } }),
        ...(countryCode && { 'regionalData.countryCode': countryCode.toUpperCase() }),
        ...(!includeStale && { 'status.isStale': false }),
    };

    const results = await this.find(query)
        .sort({ [sortBy]: sortOrder })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean({ virtuals: true })
        .select('-trendData -searchVector -cache.hash');

    const response = {
        trends: results,
        pagination: { page, limit, hasNext: results.length === limit },
    };
    await redis.setex(cacheKey, CACHE_TTL.MEDIUM, JSON.stringify(response));
    return response;
};

skillDemandSchema.statics.searchDemands = async function (searchOptions = {}) {
    const { query = '', category, demandLevel, minTrendScore = 0, countryCode, page = 1, limit = 20, sortBy = 'relevance' } = searchOptions;
    const cacheKey = `search:demands:${JSON.stringify(searchOptions)}`;
    const cached = await redis.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const pipeline = [
        {
            $match: {
                'status.isActive': true,
                'status.isDeleted': false,
                'status.isStale': false,
                ...(category && { categoryName: new RegExp(category, 'i') }),
                ...(demandLevel && { 'currentSnapshot.demandLevel': demandLevel }),
                ...(minTrendScore && { compositeTrendScore: { $gte: minTrendScore } }),
                ...(countryCode && { 'regionalData.countryCode': countryCode.toUpperCase() }),
            },
        },
        ...(query ? [{
            $match: { $text: { $search: query, $caseSensitive: false } },
        }, {
            $addFields: { textScore: { $meta: 'textScore' } },
        }] : []),
        {
            $addFields: {
                relevanceScore: {
                    $add: [
                        { $multiply: [{ $ifNull: ['$textScore', 0] }, 0.5] },
                        { $multiply: [{ $divide: ['$compositeTrendScore', 100] }, 0.3] },
                        { $multiply: [{ $divide: ['$analytics.engagementScore', 1000] }, 0.2] },
                    ],
                },
            },
        },
        { $sort: this.getSortQuery(sortBy) },
        { $skip: (page - 1) * limit },
        { $limit: limit },
        {
            $project: {
                skillName: 1,
                categoryName: 1,
                currentSnapshot: 1,
                compositeTrendScore: 1,
                volatilityScore: 1,
                regionalHotspots: { $slice: [{ $filter: { input: '$regionalData', cond: { $gte: ['$$this.trendScore', 70] } } }, 3] },
                metadata: { source: 1, lastUpdated: 1, confidence: 1 },
                createdAt: 1,
                updatedAt: 1,
                relevanceScore: 1,
            },
        },
    ];

    const results = await this.aggregatePaginate(pipeline, { page, limit });
    await redis.setex(cacheKey, CACHE_TTL.SHORT, JSON.stringify(results));
    return results;
};

skillDemandSchema.statics.getSortQuery = function (sortBy) {
    const sortQueries = {
        relevance: { relevanceScore: -1, compositeTrendScore: -1 },
        trendScore: { compositeTrendScore: -1 },
        volatility: { volatilityScore: -1 },
        jobPostings: { 'currentSnapshot.jobPostingsCount': -1 },
        alphabetical: { skillName: 1 },
    };
    return sortQueries[sortBy] || sortQueries.relevance;
};

skillDemandSchema.statics.getTrendingSkills = async function (options = {}) {
    const { timeframe = 'weekly', countryCode, category, limit = 25 } = options;
    const cacheKey = `trending:skills:${JSON.stringify(options)}`;
    const cached = await redis.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const pipeline = [
        {
            $match: {
                'status.isActive': true,
                'status.isDeleted': false,
                'status.isStale': false,
                compositeTrendScore: { $gte: 50 },
                ...(category && { categoryName: new RegExp(category, 'i') }),
                ...(countryCode && { 'regionalData.countryCode': countryCode.toUpperCase() }),
            },
        },
        {
            $addFields: {
                trendingScore: {
                    $add: [
                        { $multiply: ['$compositeTrendScore', 0.6] },
                        { $multiply: ['$volatilityScore', 0.2] },
                        { $multiply: [{ $size: { $ifNull: ['$regionalData', []] } }, 5] },
                        { $cond: [{ $gte: ['$analytics.engagementScore', 500] }, 10, 0] },
                    ],
                },
            },
        },
        { $sort: { trendingScore: -1, compositeTrendScore: -1 } },
        { $limit: limit },
        {
            $project: {
                skillName: 1,
                categoryName: 1,
                compositeTrendScore: 1,
                trendingScore: { $round: ['$trendingScore', 1] },
                currentSnapshot: 1,
                regionalHotspots: 1,
                metadata: { source: 1, lastUpdated: 1, confidence: 1 },
            },
        },
    ];

    const results = await this.aggregate(pipeline);
    await redis.setex(cacheKey, CACHE_TTL.LONG, JSON.stringify(results));
    return results;
};

skillDemandSchema.statics.getRegionalInsights = async function (options = {}) {
    const { countryCode, category, minTrendScore = 0, limit = 20 } = options;
    const cacheKey = `regional:insights:${JSON.stringify(options)}`;
    const cached = await redis.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const pipeline = [
        {
            $match: {
                'status.isActive': true,
                'status.isDeleted': false,
                'status.isStale': false,
                ...(category && { categoryName: new RegExp(category, 'i') }),
                ...(countryCode && { 'regionalData.countryCode': countryCode.toUpperCase() }),
                ...(minTrendScore && { compositeTrendScore: { $gte: minTrendScore } }),
            },
        },
        { $unwind: '$regionalData' },
        { $match: { ...(countryCode && { 'regionalData.countryCode': countryCode.toUpperCase() }) } },
        {
            $group: {
                _id: { skillName: '$skillName', countryCode: '$regionalData.countryCode' },
                trendScore: { $avg: '$regionalData.trendScore' },
                jobPostingsCount: { $sum: '$regionalData.jobPostingsCount' },
                userAdoptionRate: { $avg: '$regionalData.userAdoptionRate' },
                lastUpdated: { $max: '$regionalData.lastUpdated' },
                compositeTrendScore: { $avg: '$compositeTrendScore' },
                categoryName: { $first: '$categoryName' },
            },
        },
        { $sort: { trendScore: -1, compositeTrendScore: -1 } },
        { $limit: limit },
        {
            $project: {
                skillName: '$_id.skillName',
                countryCode: '$_id.countryCode',
                trendScore: { $round: ['$trendScore', 1] },
                jobPostingsCount: 1,
                userAdoptionRate: { $round: ['$userAdoptionRate', 1] },
                lastUpdated: 1,
                compositeTrendScore: { $round: ['$compositeTrendScore', 1] },
                categoryName: 1,
            },
        },
    ];

    const results = await this.aggregate(pipeline);
    await redis.setex(cacheKey, CACHE_TTL.LONG, JSON.stringify(results));
    return results;
};

skillDemandSchema.statics.getPerformanceMetrics = async function (timeframe = '30d') {
    const cacheKey = `performance:demands:${timeframe}`;
    const cached = await redis.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const days = parseInt(timeframe.replace('d', ''));
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    const pipeline = [
        {
            $match: {
                updatedAt: { $gte: startDate },
                'status.isActive': true,
                'status.isDeleted': false,
                'status.isStale': false,
            },
        },
        {
            $group: {
                _id: null,
                totalDemands: { $sum: 1 },
                avgTrendScore: { $avg: '$compositeTrendScore' },
                avgEngagement: { $avg: '$analytics.engagementScore' },
                avgJobPostings: { $avg: '$currentSnapshot.jobPostingsCount' },
                highDemandCount: { $sum: { $cond: [{ $in: ['$currentSnapshot.demandLevel', ['high', 'very-high']] }, 1, 0] } },
                volatileCount: { $sum: { $cond: [{ $gte: ['$volatilityScore', 60] }, 1, 0] } },
            },
        },
        {
            $project: {
                _id: 0,
                totalDemands: 1,
                avgTrendScore: { $round: ['$avgTrendScore', 1] },
                avgEngagement: { $round: ['$avgEngagement', 1] },
                avgJobPostings: { $round: ['$avgJobPostings', 0] },
                highDemandRate: { $multiply: [{ $divide: ['$highDemandCount', '$totalDemands'] }, 100] },
                volatileRate: { $multiply: [{ $divide: ['$volatileCount', '$totalDemands'] }, 100] },
            },
        },
    ];

    const results = await this.aggregate(pipeline);
    const result = results[0] || {
        totalDemands: 0,
        avgTrendScore: 0,
        avgEngagement: 0,
        avgJobPostings: 0,
        highDemandRate: 0,
        volatileRate: 0,
    };
    await redis.setex(cacheKey, CACHE_TTL.EXTRA_LONG, JSON.stringify(result));
    return result;
};

skillDemandSchema.statics.bulkOperations = {
    updateTrends: async function (demandIds, trendData) {
        const bulkOps = demandIds.map(id => ({
            updateOne: {
                filter: { _id: id, 'status.isActive': true },
                update: {
                    $set: {
                        'currentSnapshot.trendScore': trendData.trendScore,
                        'currentSnapshot.demandLevel': trendData.demandLevel,
                        'currentSnapshot.jobPostingsCount': trendData.jobPostingsCount,
                        'currentSnapshot.growthRate': trendData.growthRate,
                        'currentSnapshot.lastCalculated': new Date(),
                        'metadata.lastUpdated': new Date(),
                        'cache.lastUpdate': new Date(),
                    },
                    $inc: { 'metadata.version': 1, 'cache.version': 1 },
                },
            },
        }));
        const result = await this.bulkWrite(bulkOps, { ordered: false, writeConcern: { w: 1 } });
        const pipeline = redis.pipeline();
        demandIds.forEach(id => pipeline.del(`demand:${id}`));
        await pipeline.exec();
        return result;
    },
    archiveStaleDemands: async function (cutoffDate) {
        const staleDemands = await this.find({
            'metadata.lastUpdated': { $lt: cutoffDate },
            'status.isActive': true,
            'status.isDeleted': false,
        }).lean();
        if (staleDemands.length === 0) return { archived: 0 };
        const ArchiveDemand = mongoose.model('ArchiveDemand', skillDemandSchema, 'archive_skill_demands');
        await ArchiveDemand.insertMany(staleDemands, { ordered: false });
        const bulkOps = staleDemands.map(demand => ({
            updateOne: {
                filter: { _id: demand._id },
                update: {
                    $set: {
                        'status.isActive': false,
                        'status.isDeleted': true,
                        'status.archivedAt': new Date(),
                        'cache.lastUpdate': new Date(),
                    },
                },
            },
        }));
        const result = await this.bulkWrite(bulkOps, { ordered: false, writeConcern: { w: 1 } });
        const pipeline = redis.pipeline();
        staleDemands.forEach(demand => pipeline.del(`demand:${demand._id}`));
        await pipeline.exec();
        return { archived: result.modifiedCount };
    },
    addTrendDataPoints: async function (demandId, timeframe, dataPoints) {
        const result = await this.updateOne(
            { _id: demandId, 'status.isActive': true },
            {
                $push: { [`trendData.${timeframe}`]: { $each: dataPoints, $slice: -30 } },
                $set: { 'cache.lastUpdate': new Date() },
                $inc: { 'cache.version': 1 },
            },
            { writeConcern: { w: 1 } }
        );
        await redis.del(`demand:${demandId}`);
        return result;
    },
};

skillDemandSchema.statics.cleanupIndexes = async function () {
    const indexes = await this.collection.indexes();
    const essentialIndexes = [
        '_id_',
        'demand_text_search',
        'normalizedSkillName_1_status.isActive_1_status.isStale_1',
        'skillId_1_metadata.lastUpdated_-1',
    ];
    const unusedIndexes = indexes.filter(idx => !essentialIndexes.includes(idx.name) && !idx.name.includes('hashed'));
    let dropped = 0;
    for (const idx of unusedIndexes) {
        try {
            await this.collection.dropIndex(idx.name);
            dropped++;
        } catch (err) {
            console.error(`Failed to drop index ${idx.name}:`, err.message);
        }
    }
    return { dropped };
};

skillDemandSchema.statics.initChangeStream = function () {
    const changeStream = this.watch([
        { $match: { operationType: { $in: ['insert', 'update', 'delete'] } } },
    ], { fullDocument: 'updateLookup' });
    changeStream.on('change', async (change) => {
        const demandId = change.documentKey._id;
        const pipeline = redis.pipeline();
        pipeline.del(`demand:${demandId}`);
        pipeline.publish('skill_demand_changes', JSON.stringify({
            demandId,
            operation: change.operationType,
        }));
        await pipeline.exec();
    });
    changeStream.on('error', err => console.error('Change stream error:', err));
    return changeStream;
};

skillDemandSchema.statics.healthCheck = async function () {
    try {
        const dbCheck = await this.findOne({}, '_id').lean().timeout(5000);
        const redisCheck = await redis.ping();
        return {
            database: dbCheck !== null ? 'healthy' : 'unhealthy',
            redis: redisCheck === 'PONG' ? 'healthy' : 'unhealthy',
            timestamp: new Date(),
        };
    } catch (error) {
        return {
            database: 'unhealthy',
            redis: 'unhealthy',
            error: error.message,
            timestamp: new Date(),
        };
    }
};

// Encryption Placeholder
async function encryptField(value) {
    return crypto.createHash('sha512').update(value).digest('hex');
}

// Plugins
skillDemandSchema.plugin(aggregatePaginate);
if (process.env.ALGOLIA_APP_ID && process.env.ALGOLIA_ADMIN_KEY) {
    skillDemandSchema.plugin(mongooseAlgolia, {
        appId: process.env.ALGOLIA_APP_ID,
        apiKey: process.env.ALGOLIA_ADMIN_KEY,
        indexName: 'skill_demands',
        selector: 'skillName normalizedSkillName categoryName searchVector',
        defaults: { author: 'system' },
        mappings: {
            skillName: v => v?.toLowerCase() || '',
            normalizedSkillName: v => v || '',
            categoryName: v => v || '',
            searchVector: v => v || '',
        },
        debug: process.env.NODE_ENV !== 'production',
        batchSize: 1000,
    });
} else {
    console.warn('Algolia not configured: Missing ALGOLIA_APP_ID or ALGOLIA_ADMIN_KEY');
}

// Production Indexes
if (process.env.NODE_ENV === 'production') {
    skillDemandSchema.index({ 'analytics.viewCount': -1 }, { background: true });
    skillDemandSchema.index({ 'currentSnapshot.demandLevel': 1 }, { background: true });
    skillDemandSchema.index({ 'analytics.engagementScore': -1 }, { background: true });
}

export default mongoose.model('SkillDemand', skillDemandSchema);