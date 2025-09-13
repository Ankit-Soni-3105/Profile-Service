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
        keyPrefix: 'skillCategories:',
        db: 0,
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
const validateCategoryName = (value) => /^[a-zA-Z0-9\s\-&()#\+\/\.]+$/.test(value);
const validateURL = (value) => !value || validator.isURL(value, { require_protocol: true });

// Sub-Schemas
const metadataSchema = new Schema({
    source: {
        type: String,
        default: 'manual',
        enum: ['manual', 'api', 'csv-import', 'ai-suggested'],
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
    isDuplicate: {
        type: Boolean,
        default: false,
        index: true
    },
    duplicateOf: {
        type: String
    },
}, { _id: false });

const analyticsSchema = new Schema({
    profileViews: {
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
        index: true
    },
    lastViewed: {
        type: Date,
        index: true
    },
    clickThroughRate: {
        type: Number,
        default: 0,
        min: 0
    },
    associatedSkillsCount: {
        type: Number,
        default: 0,
        min: 0,
        index: true
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
        index: true
    },
    archivedAt: {
        type: Date
    },
    lastActiveAt: {
        type: Date,
        default: Date.now,
        index: true
    },
    workflow: {
        type: String,
        enum: ['draft', 'pending', 'published', 'archived'],
        default: 'published'
    },
}, { _id: false });

const trendSchema = new Schema({
    currentTrend: {
        type: String,
        enum: ['emerging', 'growing', 'stable', 'declining'],
        default: 'stable',
        index: true
    },
    trendScore: {
        type: Number,
        min: 0,
        max: 100,
        default: 50,
        index: true
    },
    lastAnalyzed: {
        type: Date,
        default: Date.now,
        index: true
    },
    sources: [{
        source: { type: String, maxlength: 100 },
        scoreContribution: { type: Number, min: 0, max: 100 }
    }],
    historicalData: [{
        date: { type: Date },
        score: { type: Number, min: 0, max: 100 }
    }],
}, { _id: false });

// Main SkillCategory Schema
const skillCategorySchema = new Schema({
    _id: {
        type: String,
        default: () => uuidv4(),
        index: true
    },
    name: {
        type: String,
        required: [true, 'Category name is required'],
        trim: true,
        maxlength: 50,
        index: true,
        unique: true,
        validate: { validator: validateCategoryName, message: 'Invalid category name format' }
    },
    normalizedName: {
        type: String,
        index: true
    },
    description: {
        type: String,
        maxlength: 1000,
        trim: true,
        set: v => v ? sanitizeHtml(v, { allowedTags: [], allowedAttributes: {} }) : v
    },
    parentCategory: {
        type: String,
        index: true
    },
    subCategories: [{
        type: String,
        index: true
    }],
    tags: [{
        type: String,
        trim: true,
        maxlength: 50,
        index: true
    }],
    industry: {
        type: String,
        enum: ['tech', 'finance', 'healthcare', 'education', 'marketing', 'engineering', 'creative', 'other'],
        index: true
    },
    metadata: metadataSchema,
    analytics: analyticsSchema,
    status: statusSchema,
    trend: trendSchema,
    cache: {
        searchVector: { type: String, index: 'text' },
        popularityScore: { type: Number, default: 0, index: true },
        trendingScore: { type: Number, default: 0, index: true },
        cacheVersion: { type: Number, default: 1 },
        lastCacheUpdate: { type: Date, default: Date.now, index: true }
    }
}, {
    timestamps: true,
    collection: 'skill_categories',
    autoIndex: process.env.NODE_ENV !== 'production',
    readPreference: 'secondaryPreferred',
    writeConcern: { w: 1, wtimeout: 5000 },
    toJSON: {
        virtuals: true,
        transform: (doc, ret) => {
            delete ret.cache.searchVector;
            delete ret.__v;
            return ret;
        }
    },
    toObject: { virtuals: true },
    minimize: false,
    strict: 'throw',
    shardKey: { name: 'hashed' }
});

// Indexes
skillCategorySchema.index({ 'status.isActive': 1, 'analytics.popularityScore': -1 }, { background: true });
skillCategorySchema.index({ 'trend.trendScore': -1, 'status.isActive': 1 }, { background: true });
skillCategorySchema.index({ 'industry': 1, 'status.isActive': 1 }, { background: true });
skillCategorySchema.index({ 'status.deletedAt': 1 }, { expireAfterSeconds: 7776000, sparse: true });
skillCategorySchema.index({
    name: 'text',
    normalizedName: 'text',
    description: 'text',
    tags: 'text',
    'cache.searchVector': 'text'
}, {
    weights: { name: 10, normalizedName: 8, description: 5, tags: 3, 'cache.searchVector': 1 },
    name: 'category_text_search',
    background: true
});
skillCategorySchema.index({ 'metadata.source': 1, 'metadata.lastUpdated': -1 }, { background: true });
skillCategorySchema.index({ 'parentCategory': 1, 'status.isActive': 1 }, { background: true });
skillCategorySchema.index({ 'analytics.engagementScore': -1, 'status.isActive': 1 }, { background: true });

// Virtuals
skillCategorySchema.virtual('subCategoryCount').get(function () {
    return this.subCategories?.length || 0;
});
skillCategorySchema.virtual('isTrending').get(function () {
    return this.trend.trendScore > 50;
});
skillCategorySchema.virtual('engagementLevel').get(function () {
    const score = this.analytics.engagementScore;
    if (score >= 80) return 'high';
    if (score >= 50) return 'medium';
    return 'low';
});
skillCategorySchema.virtual('trendDirection').get(function () {
    return this.trend.trendScore > 50 ? 'upward' : this.trend.trendScore < 50 ? 'downward' : 'stable';
});

// Middleware
skillCategorySchema.pre('validate', function (next) {
    if (this.parentCategory && this.subCategories.includes(this.parentCategory)) {
        next(new Error('Parent category cannot be included in sub-categories'));
    }
    next();
});

skillCategorySchema.pre('save', async function (next) {
    try {
        // Normalize name
        this.normalizedName = this.name.toLowerCase().trim();

        // Update metadata
        this.metadata.lastUpdated = new Date();
        this.metadata.updateCount += 1;
        this.metadata.version += 1;

        // Generate search vector
        this.cache.searchVector = [
            this.name,
            this.normalizedName,
            this.description,
            ...(this.tags || [])
        ].filter(Boolean).join(' ').toLowerCase();

        // Calculate engagement score
        let engScore = 0;
        engScore += (this.analytics.profileViews || 0) * 0.05;
        engScore += (this.analytics.associatedSkillsCount || 0) * 2;
        engScore += (this.analytics.searchAppearances || 0) * 0.1;
        this.analytics.engagementScore = Math.min(engScore, 1000);

        // Calculate scores
        this.cache.popularityScore = this.calculatePopularityScore();
        this.cache.trendingScore = (this.analytics.engagementScore * 0.4) + (this.trend.trendScore * 0.6);

        // Update cache
        this.cache.lastCacheUpdate = new Date();
        this.cache.cacheVersion += 1;

        // Redis operations
        const pipeline = redis.pipeline();
        pipeline.setex(`category:${this._id}`, CACHE_TTL.MEDIUM, JSON.stringify(this.toJSON()));
        pipeline.publish('category_updates', JSON.stringify({
            categoryId: this._id,
            popularityScore: this.cache.popularityScore,
            trendingScore: this.cache.trendingScore
        }));
        await pipeline.exec();

        // Update status
        this.status.lastActiveAt = new Date();

        next();
    } catch (error) {
        next(new Error(`Pre-save error: ${error.message}`));
    }
});

skillCategorySchema.pre('remove', async function (next) {
    try {
        this.status.isDeleted = true;
        this.status.deletedAt = new Date();
        this.status.isActive = false;
        const pipeline = redis.pipeline();
        pipeline.del(`category:${this._id}`);
        await pipeline.exec();
        await this.save();
        next();
    } catch (error) {
        next(new Error(`Pre-remove error: ${error.message}`));
    }
});

skillCategorySchema.post('save', async function (doc) {
    try {
        // Invalidate caches
        const pipeline = redis.pipeline();
        pipeline.del(`categories:parent:${doc.parentCategory || 'root'}`);
        pipeline.del(`categories:industry:${doc.industry}`);
        await pipeline.exec();

        // Sync to Algolia
        if (doc.status.isActive && !doc.status.isDeleted) {
            await doc.syncToAlgolia();
        }
    } catch (error) {
        console.error('Post-save error:', error.message);
    }
});

// Instance Methods
skillCategorySchema.methods.calculatePopularityScore = function () {
    const weights = {
        views: 0.4,
        skills: 0.3,
        engagement: 0.2,
        trend: 0.1
    };
    const viewScore = Math.min(Math.log1p(this.analytics.profileViews) / Math.log1p(50000), 1);
    const skillScore = Math.min(Math.log1p(this.analytics.associatedSkillsCount) / Math.log1p(1000), 1);
    const engScore = this.analytics.engagementScore / 1000;
    const trendScore = this.trend.trendScore / 100;
    return Math.round((
        viewScore * weights.views +
        skillScore * weights.skills +
        engScore * weights.engagement +
        trendScore * weights.trend
    ) * 100);
};

// Static Methods
skillCategorySchema.statics.getCategoriesByIndustry = async function (industry, options = {}) {
    const { page = 1, limit = 50, sortBy = 'name', sortOrder = 1, filters = {} } = options;
    const cacheKey = `categories:industry:${industry}:${JSON.stringify(options)}`;
    const cached = await redis.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const baseQuery = { industry, 'status.isActive': true, 'status.isDeleted': false };
    Object.assign(baseQuery, filters);

    const results = await this.find(baseQuery)
        .sort({ [sortBy]: sortOrder })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean({ virtuals: true })
        .select('-cache.searchVector');

    const response = {
        categories: results,
        pagination: { page, limit, total: results.length }
    };
    await redis.setex(cacheKey, CACHE_TTL.MEDIUM, JSON.stringify(response));
    return response;
};

skillCategorySchema.statics.advancedSearch = async function (searchOptions = {}) {
    const { query = '', industry, parentCategory, minSkills = 0, page = 1, limit = 50, sortBy = 'relevance' } = searchOptions;
    const cacheKey = `search:categories:${JSON.stringify(searchOptions)}`;
    const cached = await redis.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const pipeline = [
        {
            $match: {
                'status.isActive': true,
                'status.isDeleted': false,
                ...(industry && { industry }),
                ...(parentCategory && { parentCategory }),
                ...(minSkills && { 'analytics.associatedSkillsCount': { $gte: minSkills } })
            }
        },
        ...(query ? [{
            $match: { $text: { $search: query, $caseSensitive: false } }
        }, {
            $addFields: { textScore: { $meta: 'textScore' } }
        }] : []),
        {
            $addFields: {
                relevanceScore: {
                    $add: [
                        { $multiply: [{ $ifNull: ['$textScore', 0] }, 0.4] },
                        { $multiply: [{ $divide: ['$trend.trendScore', 100] }, 0.3] },
                        { $multiply: [{ $divide: ['$analytics.engagementScore', 1000] }, 0.2] },
                        { $multiply: [{ $divide: ['$analytics.associatedSkillsCount', 1000] }, 0.1] }
                    ]
                }
            }
        },
        { $sort: this.getSortQuery(sortBy) },
        { $skip: (page - 1) * limit },
        { $limit: limit },
        {
            $project: {
                name: 1,
                description: { $substr: ['$description', 0, 300] },
                industry: 1,
                parentCategory: 1,
                subCategories: 1,
                tags: 1,
                trend: 1,
                analytics: { engagementScore: 1, profileViews: 1, associatedSkillsCount: 1 },
                cache: { popularityScore: 1, trendingScore: 1 },
                relevanceScore: 1,
                createdAt: 1,
                updatedAt: 1
            }
        }
    ];

    const results = await this.aggregatePaginate(pipeline, { page, limit });
    await redis.setex(cacheKey, CACHE_TTL.SHORT, JSON.stringify(results));
    return results;
};

skillCategorySchema.statics.getSortQuery = function (sortBy) {
    const sortQueries = {
        relevance: { relevanceScore: -1, 'trend.trendScore': -1 },
        popularity: { 'cache.popularityScore': -1 },
        trending: { 'cache.trendingScore': -1 },
        alphabetical: { name: 1 },
        skillsCount: { 'analytics.associatedSkillsCount': -1 }
    };
    return sortQueries[sortBy] || sortQueries.relevance;
};

skillCategorySchema.statics.getTrendingCategories = async function (options = {}) {
    const { timeframe = 30, industry, minSkills = 0, limit = 50 } = options;
    const cacheKey = `trending:categories:${JSON.stringify(options)}`;
    const cached = await redis.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const startDate = new Date();
    startDate.setDate(startDate.getDate() - timeframe);

    const pipeline = [
        {
            $match: {
                'status.isActive': true,
                'status.isDeleted': false,
                updatedAt: { $gte: startDate },
                ...(industry && { industry }),
                ...(minSkills && { 'analytics.associatedSkillsCount': { $gte: minSkills } })
            }
        },
        {
            $group: {
                _id: '$normalizedName',
                count: { $sum: 1 },
                avgTrendScore: { $avg: '$trend.trendScore' },
                totalSkills: { $sum: '$analytics.associatedSkillsCount' },
                avgEngagementScore: { $avg: '$analytics.engagementScore' },
                industries: { $addToSet: '$industry' }
            }
        },
        {
            $addFields: {
                trendScore: {
                    $multiply: [
                        { $log10: { $add: ['$count', 1] } },
                        { $divide: ['$avgTrendScore', 100] },
                        { $divide: ['$totalSkills', 1000] },
                        { $divide: ['$avgEngagementScore', 1000] }
                    ]
                }
            }
        },
        { $sort: { trendScore: -1 } },
        { $limit: limit },
        {
            $project: {
                name: '$_id',
                occurrences: '$count',
                avgTrendScore: { $round: ['$avgTrendScore', 1] },
                totalSkills: 1,
                avgEngagementScore: { $round: ['$avgEngagementScore', 1] },
                industryCount: { $size: '$industries' },
                trendScore: { $round: ['$trendScore', 1] }
            }
        }
    ];

    const results = await this.aggregate(pipeline);
    await redis.setex(cacheKey, CACHE_TTL.LONG, JSON.stringify(results));
    return results;
};

skillCategorySchema.statics.getCategoryAnalytics = async function (categoryId, options = {}) {
    const { timeframe = 30 } = options;
    const cacheKey = `category:analytics:${categoryId}:${timeframe}`;
    const cached = await redis.get(cacheKey);
    if (cached) return JSON.parse(cached);

    const startDate = new Date();
    startDate.setDate(startDate.getDate() - timeframe);

    const pipeline = [
        {
            $match: { _id: categoryId, 'status.isActive': true, 'status.isDeleted': false }
        },
        {
            $lookup: {
                from: 'skills',
                localField: '_id',
                foreignField: 'category.primary',
                as: 'skills'
            }
        },
        {
            $addFields: {
                recentSkills: {
                    $filter: {
                        input: '$skills',
                        as: 'skill',
                        cond: { $gte: ['$$skill.createdAt', startDate] }
                    }
                }
            }
        },
        {
            $project: {
                name: 1,
                summary: {
                    totalSkills: { $size: '$skills' },
                    recentSkillsCount: { $size: '$recentSkills' },
                    avgTrendScore: '$trend.trendScore',
                    engagementScore: '$analytics.engagementScore',
                    profileViews: '$analytics.profileViews',
                    associatedSkillsCount: '$analytics.associatedSkillsCount'
                },
                historicalTrends: '$trend.historicalData'
            }
        }
    ];

    const results = await this.aggregate(pipeline);
    const result = results[0] || null;
    await redis.setex(cacheKey, CACHE_TTL.MEDIUM, JSON.stringify(result));
    return result;
};

skillCategorySchema.statics.bulkOperations = {
    updateTrends: async function (categoryIds, trendData) {
        const bulkOps = categoryIds.map(id => ({
            updateOne: {
                filter: { _id: id, 'status.isActive': true },
                update: {
                    $set: {
                        trend: trendData,
                        'metadata.lastUpdated': new Date(),
                        'cache.lastCacheUpdate': new Date()
                    },
                    $inc: { 'metadata.updateCount': 1, 'cache.cacheVersion': 1 }
                }
            }
        }));
        const result = await this.bulkWrite(bulkOps, { ordered: false, writeConcern: { w: 1 } });
        const pipeline = redis.pipeline();
        categoryIds.forEach(id => pipeline.del(`category:${id}`));
        await pipeline.exec();
        return result;
    },
    archiveOldCategories: async function (cutoffDate) {
        const oldCategories = await this.find({
            'metadata.lastUpdated': { $lt: cutoffDate },
            'status.isActive': true,
            'status.isDeleted': false
        }).lean();
        if (oldCategories.length === 0) return { archived: 0 };
        const ArchiveCategory = mongoose.model('ArchiveCategory', skillCategorySchema, 'archive_skill_categories');
        await ArchiveCategory.insertMany(oldCategories, { ordered: false });
        const bulkOps = oldCategories.map(category => ({
            updateOne: {
                filter: { _id: category._id },
                update: {
                    $set: {
                        'status.isActive': false,
                        'status.isDeleted': true,
                        'status.archivedAt': new Date(),
                        'cache.lastCacheUpdate': new Date()
                    }
                }
            }
        }));
        const result = await this.bulkWrite(bulkOps, { ordered: false, writeConcern: { w: 1 } });
        const pipeline = redis.pipeline();
        oldCategories.forEach(category => pipeline.del(`category:${category._id}`));
        await pipeline.exec();
        return { archived: result.modifiedCount };
    },
    updateSkillCounts: async function (categoryId, increment) {
        const result = await this.updateOne(
            { _id: categoryId, 'status.isActive': true },
            {
                $inc: { 'analytics.associatedSkillsCount': increment, 'cache.cacheVersion': 1 },
                $set: { 'cache.lastCacheUpdate': new Date() }
            },
            { writeConcern: { w: 1 } }
        );
        await redis.del(`category:${categoryId}`);
        return result;
    }
};

skillCategorySchema.statics.getPerformanceMetrics = async function (timeframe = '30d') {
    const cacheKey = `performance:categories:${timeframe}`;
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
                'status.isDeleted': false
            }
        },
        {
            $group: {
                _id: null,
                totalCategories: { $sum: 1 },
                avgTrendScore: { $avg: '$trend.trendScore' },
                avgEngagement: { $avg: '$analytics.engagementScore' },
                avgSkillsCount: { $avg: '$analytics.associatedSkillsCount' },
                trendingCount: { $sum: { $cond: [{ $gt: ['$trend.trendScore', 50] }, 1, 0] } }
            }
        },
        {
            $addFields: {
                trendingRate: { $multiply: [{ $divide: ['$trendingCount', '$totalCategories'] }, 100] }
            }
        },
        {
            $project: {
                _id: 0,
                totalCategories: 1,
                avgTrendScore: { $round: ['$avgTrendScore', 1] },
                avgEngagement: { $round: ['$avgEngagement', 1] },
                avgSkillsCount: { $round: ['$avgSkillsCount', 1] },
                trendingRate: { $round: ['$trendingRate', 1] }
            }
        }
    ];

    const results = await this.aggregate(pipeline);
    const result = results[0] || {
        totalCategories: 0,
        avgTrendScore: 0,
        avgEngagement: 0,
        avgSkillsCount: 0,
        trendingRate: 0
    };
    await redis.setex(cacheKey, CACHE_TTL.EXTRA_LONG, JSON.stringify(result));
    return result;
};

skillCategorySchema.statics.cleanupIndexes = async function () {
    const indexes = await this.collection.indexes();
    const essentialIndexes = [
        '_id_',
        'category_text_search',
        'name_1',
        'status.isActive_1_analytics.popularityScore_-1'
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

skillCategorySchema.statics.initChangeStream = function () {
    const changeStream = this.watch([
        { $match: { operationType: { $in: ['insert', 'update', 'delete'] } } }
    ], { fullDocument: 'updateLookup' });
    changeStream.on('change', async (change) => {
        const categoryId = change.documentKey._id;
        const pipeline = redis.pipeline();
        pipeline.del(`category:${categoryId}`);
        pipeline.publish('category_changes', JSON.stringify({
            categoryId,
            operation: change.operationType
        }));
        await pipeline.exec();
    });
    changeStream.on('error', err => console.error('Change stream error:', err));
    return changeStream;
};

skillCategorySchema.statics.healthCheck = async function () {
    try {
        const dbCheck = await this.findOne({}, '_id').lean().timeout(5000);
        const redisCheck = await redis.ping();
        return {
            database: dbCheck !== null ? 'healthy' : 'unhealthy',
            redis: redisCheck === 'PONG' ? 'healthy' : 'unhealthy',
            timestamp: new Date()
        };
    } catch (error) {
        return {
            database: 'unhealthy',
            redis: 'unhealthy',
            error: error.message,
            timestamp: new Date()
        };
    }
};

// Encryption Placeholder
async function encryptField(value) {
    return crypto.createHash('sha512').update(value).digest('hex');
}

// Plugins
skillCategorySchema.plugin(aggregatePaginate);
if (process.env.ALGOLIA_APP_ID && process.env.ALGOLIA_ADMIN_KEY) {
    skillCategorySchema.plugin(mongooseAlgolia, {
        appId: process.env.ALGOLIA_APP_ID,
        apiKey: process.env.ALGOLIA_ADMIN_KEY,
        indexName: 'skill_categories',
        selector: 'name normalizedName description tags cache.searchVector',
        defaults: { author: 'system' },
        mappings: {
            name: v => v?.toLowerCase() || '',
            normalizedName: v => v || '',
            description: v => v?.slice(0, 500) || '',
            tags: v => v || [],
            'cache.searchVector': v => v || ''
        },
        debug: process.env.NODE_ENV !== 'production',
        batchSize: 1000
    });
} else {
    console.warn('Algolia not configured: Missing ALGOLIA_APP_ID or ALGOLIA_ADMIN_KEY');
}

// Production Indexes
if (process.env.NODE_ENV === 'production') {
    skillCategorySchema.index({ 'analytics.profileViews': -1 }, { background: true });
    skillCategorySchema.index({ 'trend.currentTrend': 1 }, { background: true });
    skillCategorySchema.index({ 'analytics.associatedSkillsCount': -1 }, { background: true });
}

export default mongoose.model('SkillCategory', skillCategorySchema);