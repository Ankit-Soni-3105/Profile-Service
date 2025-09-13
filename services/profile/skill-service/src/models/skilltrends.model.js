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
        keyPrefix: 'skill_trend:',
        db: 2,
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
    importId: {
        type: String,
        maxlength: 100
    },
    lastUpdated: {
        type: Date,
        default: Date.now,
        index: true
    },
    updateCount: {
        type: Number,
        default: 0,
        min: 0
    },
    version: {
        type: Number,
        default: 1,
        min: 1
    },
}, { _id: false });

const analyticsSchema = new Schema({
    viewCount: {
        type: Number,
        default: 0,
        min: 0,
        index: true
    },
    searchAppearances: {
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
    clickThroughRate: {
        type: Number,
        default: 0,
        min: 0,
        max: 100
    },
    userInteractions: {
        type: Number,
        default: 0,
        min: 0
    },
}, { _id: false });

const statusSchema = new Schema({
    isActive: {
        type: Boolean,
        default: true,
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
}, { _id: false });

const trendDataSchema = new Schema({
    timeframe: {
        type: String,
        enum: ['daily', 'weekly', 'monthly', 'quarterly'],
        required: true,
        index: true
    },
    trendScore: {
        type: Number,
        min: 0,
        max: 100,
        default: 0,
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
    analysisDate: {
        type: Date,
        default: Date.now,
        index: true
    },
    sources: [{
        source: { type: String, maxlength: 50 },
        weight: { type: Number, min: 0, max: 1 }
    }],
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
}, { _id: false });

// Main SkillTrend Schema
const skillTrendSchema = new Schema({
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
    trendData: [trendDataSchema],
    regionalData: [regionalDataSchema],
    analytics: analyticsSchema,
    metadata: metadataSchema,
    status: statusSchema,
    cache: {
        compositeTrendScore: { type: Number, default: 0, index: true },
        cacheVersion: { type: Number, default: 1 },
        lastCacheUpdate: { type: Date, default: Date.now, index: true },
        searchVector: { type: String, index: 'text' },
    },
}, {
    timestamps: true,
    collection: 'skill_trends',
    readPreference: 'secondaryPreferred',
    writeConcern: { w: 1, wtimeout: 5000 },
    toJSON: {
        virtuals: true,
        transform: (doc, ret) => {
            delete ret.__v;
            delete ret.cache.searchVector;
            return ret;
        },
    },
    toObject: { virtuals: true },
    minimize: false,
    strict: 'throw',
    shardKey: { normalizedSkillName: 'hashed' },
});

// Indexes
skillTrendSchema.index({ normalizedSkillName: 1, 'trendData.timeframe': 1 }, { unique: true, background: true });
skillTrendSchema.index({ skillId: 1, 'trendData.analysisDate': -1 }, { background: true, sparse: true });
skillTrendSchema.index({ categoryId: 1, 'trendData.timeframe': 1 }, { background: true, sparse: true });
skillTrendSchema.index({ 'cache.compositeTrendScore': -1, 'status.isActive': 1 }, { background: true });
skillTrendSchema.index({ 'regionalData.countryCode': 1, 'trendData.timeframe': 1 }, { background: true });
skillTrendSchema.index({ 'trendData.demandLevel': 1, 'trendData.analysisDate': -1 }, { background: true });
skillTrendSchema.index({
    skillName: 'text',
    normalizedSkillName: 'text',
    categoryName: 'text',
    'cache.searchVector': 'text',
}, {
    weights: { skillName: 10, normalizedSkillName: 8, categoryName: 5, 'cache.searchVector': 1 },
    name: 'trend_text_search',
    background: true,
});
skillTrendSchema.index({ 'status.deletedAt': 1 }, { expireAfterSeconds: 7776000, sparse: true });

// Virtuals
skillTrendSchema.virtual('latestTrend').get(function () {
    return this.trendData.sort((a, b) => b.analysisDate - a.analysisDate)[0] || null;
});

skillTrendSchema.virtual('isTrending').get(function () {
    const latest = this.latestTrend;
    return latest && latest.trendScore >= 75;
});

skillTrendSchema.virtual('regionalHotspots').get(function () {
    return (this.regionalData || [])
        .filter(region => region.trendScore >= 75)
        .sort((a, b) => b.trendScore - a.trendScore)
        .slice(0, 5);
});

skillTrendSchema.virtual('isHighDemand').get(function () {
    const latest = this.latestTrend;
    return latest && ['high', 'very-high'].includes(latest.demandLevel);
});

// Middleware
skillTrendSchema.pre('validate', function (next) {
    if (this.trendData?.length > 0) {
        const limits = { daily: 30, weekly: 52, monthly: 24, quarterly: 8 };
        this.trendData = this.trendData.filter(data => {
            const limit = limits[data.timeframe] || 100;
            return this.trendData.filter(d => d.timeframe === data.timeframe).length <= limit;
        });
    }
    next();
});

skillTrendSchema.pre('save', async function (next) {
    try {
        this.normalizedSkillName = this.skillName.toLowerCase().trim();
        this.metadata.lastUpdated = new Date();
        this.metadata.updateCount += 1;
        this.metadata.version += 1;

        const latestTrend = this.trendData.sort((a, b) => b.analysisDate - a.analysisDate)[0];
        if (latestTrend) {
            this.cache.compositeTrendScore = this.calculateCompositeTrendScore();
        }

        this.cache.searchVector = [
            this.skillName,
            this.normalizedSkillName,
            this.categoryName,
        ].filter(Boolean).join(' ').toLowerCase();

        this.cache.lastCacheUpdate = new Date();
        this.cache.cacheVersion += 1;

        const pipeline = redis.pipeline();
        pipeline.setex(`skill_trend:${this._id}`, CACHE_TTL.MEDIUM, JSON.stringify(this.toJSON()));
        pipeline.publish('skill_trend_updates', JSON.stringify({
            trendId: this._id,
            skillId: this.skillId,
            skillName: this.skillName,
            compositeTrendScore: this.cache.compositeTrendScore,
            action: 'updated',
        }));
        await pipeline.exec();

        this.status.lastAnalyzed = new Date();
        next();
    } catch (error) {
        next(new Error(`Pre-save error: ${error.message}`));
    }
});

skillTrendSchema.pre('remove', async function (next) {
    try {
        this.status.isDeleted = true;
        this.status.deletedAt = new Date();
        this.status.isActive = false;
        const pipeline = redis.pipeline();
        pipeline.del(`skill_trend:${this._id}`);
        await pipeline.exec();
        await this.save();
        next();
    } catch (error) {
        next(new Error(`Pre-remove error: ${error.message}`));
    }
});

skillTrendSchema.post('save', async function (doc) {
    try {
        const pipeline = redis.pipeline();
        pipeline.del(`skill:trends:${doc.skillId}`);
        pipeline.del(`category:trends:${doc.categoryId}`);
        pipeline.del(`trending:${doc.normalizedSkillName}`);
        if (doc.status.isActive && !doc.status.isDeleted) {
            await doc.syncToAlgolia();
        }
        await pipeline.exec();
    } catch (error) {
        console.error('Post-save error:', error.message);
    }
});

// Instance Methods
skillTrendSchema.methods.calculateCompositeTrendScore = function () {
    const latestTrend = this.trendData.sort((a, b) => b.analysisDate - a.analysisDate)[0];
    if (!latestTrend) return 0;
    const weights = { trendScore: 0.5, adoptionRate: 0.3, jobPostings: 0.2 };
    const trendScore = latestTrend.trendScore / 100;
    const adoptionScore = latestTrend.userAdoptionRate / 100;
    const jobScore = Math.log1p(latestTrend.jobPostingsCount) / Math.log1p(10000);
    return Math.min(100, Math.round((
        trendScore * weights.trendScore +
        adoptionScore * weights.adoptionRate +
        jobScore * weights.jobPostings
    ) * 100));
};

skillTrendSchema.methods.addTrendDataPoint = async function (timeframe, dataPoint) {
    if (!this.trendData) this.trendData = [];
    this.trendData.push({ ...dataPoint, timeframe });
    const limits = { daily: 30, weekly: 52, monthly: 24, quarterly: 8 };
    const limit = limits[timeframe] || 100;
    this.trendData = this.trendData
        .filter(d => d.timeframe === timeframe)
        .slice(-limit)
        .concat(this.trendData.filter(d => d.timeframe !== timeframe));
    await this.save();
};

// Static Methods
skillTrendSchema.statics.getTrends = async function (options = {}) {
    const { page = 1, limit = 50, sortBy = 'compositeTrendScore', sortOrder = -1, filters = {}, timeframe = 'monthly' } = options;
    const cacheKey = `skill_trends:${JSON.stringify(options)}`;
    const cached = await redis.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const baseQuery = { 'status.isActive': true, 'status.isDeleted': false, 'trendData.timeframe': timeframe };
    Object.entries(filters).forEach(([key, value]) => {
        if (value !== undefined && value !== null && value !== '') baseQuery[key] = value;
    });

    const results = await this.find(baseQuery)
        .sort({ [sortBy]: sortOrder })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean({ virtuals: true })
        .select('-trendData.sources -cache.searchVector');

    const response = {
        trends: results,
        pagination: { page, limit, hasNext: results.length === limit },
    };
    await redis.setex(cacheKey, CACHE_TTL.LONG, JSON.stringify(response));
    return response;
};

skillTrendSchema.statics.advancedSearch = async function (searchOptions = {}) {
    const { query = '', timeframe = 'monthly', demandLevel, minTrendScore = 0, countryCode, page = 1, limit = 50, sortBy = 'relevance' } = searchOptions;
    const cacheKey = `search:skill_trends:${JSON.stringify(searchOptions)}`;
    const cached = await redis.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const pipeline = [
        {
            $match: {
                'status.isActive': true,
                'status.isDeleted': false,
                'trendData.timeframe': timeframe,
                ...(demandLevel && { 'trendData.demandLevel': demandLevel }),
                ...(minTrendScore && { 'trendData.trendScore': { $gte: minTrendScore } }),
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
                        { $multiply: [{ $ifNull: ['$textScore', 0] }, 0.4] },
                        { $multiply: [{ $divide: [{ $arrayElemAt: ['$trendData.trendScore', 0] }, 100] }, 0.3] },
                        { $multiply: [{ $divide: ['$analytics.engagementScore', 1000] }, 0.2] },
                        { $multiply: [{ $divide: [{ $arrayElemAt: ['$trendData.jobPostingsCount', 0] }, 10000] }, 0.1] },
                    ],
                },
            },
        },
        { $sort: this.getSortQuery(sortBy) },
        {
            $project: {
                skillName: 1,
                categoryName: 1,
                trendData: { $slice: ['$trendData', 1] },
                regionalData: { $slice: ['$regionalData', 5] },
                analytics: 1,
                compositeTrendScore: '$cache.compositeTrendScore',
                relevanceScore: 1,
                createdAt: 1,
                updatedAt: 1,
            },
        },
    ];

    const results = await this.aggregatePaginate(pipeline, { page, limit, customLabels: { totalDocs: 'totalResults', docs: 'trends' } });
    await redis.setex(cacheKey, CACHE_TTL.SHORT, JSON.stringify(results));
    return results;
};

skillTrendSchema.statics.getSortQuery = function (sortBy) {
    const sortQueries = {
        relevance: { relevanceScore: -1, 'cache.compositeTrendScore': -1 },
        trendScore: { 'cache.compositeTrendScore': -1 },
        jobPostings: { 'trendData.jobPostingsCount': -1 },
        adoptionRate: { 'trendData.userAdoptionRate': -1 },
        alphabetical: { skillName: 1 },
    };
    return sortQueries[sortBy] || sortQueries.relevance;
};

skillTrendSchema.statics.getTrendingSkills = async function (options = {}) {
    const { timeframe = 'monthly', countryCode, minTrendScore = 50, limit = 100 } = options;
    const cacheKey = `trending:skills:${JSON.stringify(options)}`;
    const cached = await redis.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const startDate = new Date();
    startDate.setDate(startDate.getDate() - (timeframe === 'daily' ? 1 : timeframe === 'weekly' ? 7 : timeframe === 'monthly' ? 30 : timeframe === 'quarterly' ? 90 : 365));

    const pipeline = [
        {
            $match: {
                'status.isActive': true,
                'status.isDeleted': false,
                'trendData.timeframe': timeframe,
                'trendData.trendScore': { $gte: minTrendScore },
                'trendData.analysisDate': { $gte: startDate },
                ...(countryCode && { 'regionalData.countryCode': countryCode.toUpperCase() }),
            },
        },
        {
            $group: {
                _id: { skillId: '$skillId', skillName: '$skillName', categoryId: '$categoryId', categoryName: '$categoryName' },
                latestTrend: { $max: '$trendData.trendScore' },
                totalJobPostings: { $sum: { $arrayElemAt: ['$trendData.jobPostingsCount', 0] } },
                avgAdoptionRate: { $avg: { $arrayElemAt: ['$trendData.userAdoptionRate', 0] } },
                totalInteractions: { $sum: '$analytics.userInteractions' },
            },
        },
        {
            $addFields: {
                trendScore: {
                    $multiply: [
                        { $divide: ['$latestTrend', 100] },
                        { $add: [{ $divide: ['$totalJobPostings', 10000] }, 1] },
                        { $add: [{ $divide: ['$totalInteractions', 1000] }, 1] },
                    ],
                },
            },
        },
        { $sort: { trendScore: -1 } },
        { $limit: limit },
        {
            $project: {
                skillId: '$_id.skillId',
                skillName: '$_id.skillName',
                categoryId: '$_id.categoryId',
                categoryName: '$_id.categoryName',
                trendScore: { $round: ['$trendScore', 1] },
                jobPostings: '$totalJobPostings',
                adoptionRate: { $round: ['$avgAdoptionRate', 1] },
                interactions: '$totalInteractions',
            },
        },
    ];

    const results = await this.aggregate(pipeline);
    await redis.setex(cacheKey, CACHE_TTL.LONG, JSON.stringify(results));
    return results;
};

skillTrendSchema.statics.getRegionalTrends = async function (options = {}) {
    const { timeframe = 'monthly', countryCode, minTrendScore = 0, limit = 100 } = options;
    const cacheKey = `regional:trends:${JSON.stringify(options)}`;
    const cached = await redis.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const pipeline = [
        {
            $match: {
                'status.isActive': true,
                'status.isDeleted': false,
                'trendData.timeframe': timeframe,
                'regionalData.trendScore': { $gte: minTrendScore },
                ...(countryCode && { 'regionalData.countryCode': countryCode.toUpperCase() }),
            },
        },
        { $unwind: '$regionalData' },
        {
            $match: { ...(countryCode && { 'regionalData.countryCode': countryCode.toUpperCase() }) },
        },
        {
            $group: {
                _id: { skillId: '$skillId', skillName: '$skillName', countryCode: '$regionalData.countryCode' },
                latestTrend: { $max: '$regionalData.trendScore' },
                totalJobPostings: { $sum: '$regionalData.jobPostingsCount' },
                avgAdoptionRate: { $avg: '$regionalData.userAdoptionRate' },
            },
        },
        {
            $addFields: {
                trendScore: {
                    $multiply: [
                        { $divide: ['$latestTrend', 100] },
                        { $add: [{ $divide: ['$totalJobPostings', 10000] }, 1] },
                    ],
                },
            },
        },
        { $sort: { trendScore: -1 } },
        { $limit: limit },
        {
            $project: {
                skillId: '$_id.skillId',
                skillName: '$_id.skillName',
                countryCode: '$_id.countryCode',
                trendScore: { $round: ['$trendScore', 1] },
                jobPostings: '$totalJobPostings',
                adoptionRate: { $round: ['$avgAdoptionRate', 1] },
            },
        },
    ];

    const results = await this.aggregate(pipeline);
    await redis.setex(cacheKey, CACHE_TTL.LONG, JSON.stringify(results));
    return results;
};

skillTrendSchema.statics.getPerformanceMetrics = async function (timeframe = '30d') {
    const cacheKey = `performance:trends:${timeframe}`;
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
            },
        },
        {
            $group: {
                _id: null,
                totalTrends: { $sum: 1 },
                avgTrendScore: { $avg: '$cache.compositeTrendScore' },
                avgEngagement: { $avg: '$analytics.engagementScore' },
                avgJobPostings: { $avg: { $arrayElemAt: ['$trendData.jobPostingsCount', 0] } },
                highDemandCount: { $sum: { $cond: [{ $in: [{ $arrayElemAt: ['$trendData.demandLevel', 0] }, ['high', 'very-high']] }, 1, 0] } },
            },
        },
        {
            $project: {
                _id: 0,
                totalTrends: 1,
                avgTrendScore: { $round: ['$avgTrendScore', 1] },
                avgEngagement: { $round: ['$avgEngagement', 1] },
                avgJobPostings: { $round: ['$avgJobPostings', 0] },
                highDemandRate: { $multiply: [{ $divide: ['$highDemandCount', '$totalTrends'] }, 100] },
            },
        },
    ];

    const results = await this.aggregate(pipeline);
    const result = results[0] || {
        totalTrends: 0,
        avgTrendScore: 0,
        avgEngagement: 0,
        avgJobPostings: 0,
        highDemandRate: 0,
    };
    await redis.setex(cacheKey, CACHE_TTL.EXTRA_LONG, JSON.stringify(result));
    return result;
};

skillTrendSchema.statics.bulkOperations = {
    updateTrendData: async function (trendIds, trendData) {
        const bulkOps = trendIds.map(id => ({
            updateOne: {
                filter: { _id: id, 'status.isActive': true },
                update: {
                    $push: { trendData: { $each: [trendData], $slice: -30 } },
                    $set: {
                        'metadata.lastUpdated': new Date(),
                        'cache.lastCacheUpdate': new Date(),
                    },
                    $inc: { 'metadata.updateCount': 1, 'cache.cacheVersion': 1 },
                },
            },
        }));
        const result = await this.bulkWrite(bulkOps, { ordered: false, writeConcern: { w: 1 } });
        const pipeline = redis.pipeline();
        trendIds.forEach(id => pipeline.del(`skill_trend:${id}`));
        await pipeline.exec();
        return result;
    },
    archiveOldTrends: async function (cutoffDate) {
        const oldTrends = await this.find({
            'metadata.lastUpdated': { $lt: cutoffDate },
            'status.isActive': true,
            'status.isDeleted': false,
        }).lean();
        if (oldTrends.length === 0) return { archived: 0 };
        const ArchiveSkillTrend = mongoose.model('ArchiveSkillTrend', skillTrendSchema, 'archive_skill_trends');
        await ArchiveSkillTrend.insertMany(oldTrends, { ordered: false });
        const bulkOps = oldTrends.map(trend => ({
            updateOne: {
                filter: { _id: trend._id },
                update: {
                    $set: {
                        'status.isActive': false,
                        'status.isDeleted': true,
                        'status.deletedAt': new Date(),
                        'cache.lastCacheUpdate': new Date(),
                    },
                },
            },
        }));
        const result = await this.bulkWrite(bulkOps, { ordered: false, writeConcern: { w: 1 } });
        const pipeline = redis.pipeline();
        oldTrends.forEach(trend => pipeline.del(`skill_trend:${trend._id}`));
        await pipeline.exec();
        return { archived: result.modifiedCount };
    },
};

skillTrendSchema.statics.cleanupIndexes = async function () {
    const indexes = await this.collection.indexes();
    const essentialIndexes = [
        '_id_',
        'trend_text_search',
        'normalizedSkillName_1_trendData.timeframe_1',
        'cache.compositeTrendScore_-1_status.isActive_1',
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

skillTrendSchema.statics.initChangeStream = function () {
    const changeStream = this.watch([
        { $match: { operationType: { $in: ['insert', 'update', 'delete'] } } },
    ], { fullDocument: 'updateLookup' });
    changeStream.on('change', async (change) => {
        const trendId = change.documentKey._id;
        const pipeline = redis.pipeline();
        pipeline.del(`skill_trend:${trendId}`);
        pipeline.publish('skill_trend_changes', JSON.stringify({
            trendId,
            operation: change.operationType,
        }));
        await pipeline.exec();
    });
    changeStream.on('error', err => console.error('Change stream error:', err));
    return changeStream;
};

skillTrendSchema.statics.healthCheck = async function () {
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
skillTrendSchema.plugin(aggregatePaginate);
if (process.env.ALGOLIA_APP_ID && process.env.ALGOLIA_ADMIN_KEY) {
    skillTrendSchema.plugin(mongooseAlgolia, {
        appId: process.env.ALGOLIA_APP_ID,
        apiKey: process.env.ALGOLIA_ADMIN_KEY,
        indexName: 'skill_trends',
        selector: 'skillName normalizedSkillName categoryName cache.searchVector',
        defaults: { author: 'system' },
        mappings: {
            skillName: v => v?.toLowerCase() || '',
            normalizedSkillName: v => v || '',
            categoryName: v => v || '',
            'cache.searchVector': v => v || '',
        },
        debug: process.env.NODE_ENV !== 'production',
        batchSize: 1000,
    });
} else {
    console.warn('Algolia not configured: Missing ALGOLIA_APP_ID or ALGOLIA_ADMIN_KEY');
}

// Production Indexes
if (process.env.NODE_ENV === 'production') {
    skillTrendSchema.index({ 'analytics.userInteractions': -1 }, { background: true });
    skillTrendSchema.index({ 'trendData.analysisDate': -1 }, { background: true });
    skillTrendSchema.index({ 'analytics.engagementScore': -1 }, { background: true });
}

export default mongoose.model('SkillTrend', skillTrendSchema);