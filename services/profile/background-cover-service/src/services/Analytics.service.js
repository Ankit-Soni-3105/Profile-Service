import { AppError } from '../errors/app.error.js';
import { logger } from '../utils/logger.js';
import CoverPhoto from '../models/CoverPhoto.js';
import Design from '../models/Design.model.js';
import { analyzeWithAI } from './cover.service.js';
import { v4 as uuidv4 } from 'uuid';

export class AnalyticsService {
    static async getCoverAnalyticsSummary(userId, timeframe, category, groups = []) {
        let daysAgo = 30;
        switch (timeframe) {
            case '7d': daysAgo = 7; break;
            case '30d': daysAgo = 30; break;
            case '90d': daysAgo = 90; break;
            case '1y': daysAgo = 365; break;
        }

        const query = {
            userId,
            status: { $ne: 'deleted' },
            createdAt: { $gte: new Date(Date.now() - daysAgo * 24 * 60 * 60 * 1000) }
        };
        if (category !== 'all') {
            query.category = category;
        }

        const summary = await CoverPhoto.aggregate([
            { $match: query },
            {
                $group: {
                    _id: null,
                    totalCovers: { $sum: 1 },
                    activeCovers: { $sum: { $cond: [{ $eq: ['$status', 'active'] }, 1, 0] } },
                    totalViews: { $sum: '$usage.totalViews' },
                    totalLikes: { $sum: '$usage.likes' },
                    totalDownloads: { $sum: '$usage.downloads' },
                    totalShares: { $sum: '$usage.shares' },
                    avgQuality: { $avg: '$quality.qualityScore.overall' },
                    categories: { $addToSet: '$category' },
                    trendingScore: { $avg: '$usage.trendingScore' }
                }
            },
            {
                $project: {
                    _id: 0,
                    totalCovers: 1,
                    activeCovers: 1,
                    completionRate: {
                        $multiply: [
                            { $divide: ['$activeCovers', { $max: ['$totalCovers', 1] }] },
                            100
                        ]
                    },
                    totalViews: 1,
                    totalLikes: 1,
                    totalDownloads: 1,
                    totalShares: 1,
                    avgQuality: { $round: ['$avgQuality', 1] },
                    categories: 1,
                    trendingScore: { $round: ['$trendingScore', 1] }
                }
            }
        ]).cache({ key: `analytics:covers:${userId}:${timeframe}:${category}` });

        return summary[0] || {};
    }

    static async getDesignAnalyticsSummary(userId, timeframe, category, groups = []) {
        let daysAgo = 30;
        switch (timeframe) {
            case '7d': daysAgo = 7; break;
            case '30d': daysAgo = 30; break;
            case '90d': daysAgo = 90; break;
            case '1y': daysAgo = 365; break;
        }

        const query = {
            userId,
            status: { $ne: 'deleted' },
            createdAt: { $gte: new Date(Date.now() - daysAgo * 24 * 60 * 60 * 1000) }
        };
        if (category !== 'all') {
            query.category = category;
        }

        const summary = await Design.aggregate([
            { $match: query },
            {
                $group: {
                    _id: null,
                    totalDesigns: { $sum: 1 },
                    activeDesigns: { $sum: { $cond: [{ $eq: ['$status', 'active'] }, 1, 0] } },
                    totalViews: { $sum: '$analytics.views' },
                    totalLikes: { $sum: '$analytics.likes' },
                    totalDownloads: { $sum: '$analytics.downloads' },
                    totalShares: { $sum: '$analytics.shares' },
                    totalComments: { $sum: '$analytics.comments' },
                    avgQuality: { $avg: '$quality.overall' },
                    categories: { $addToSet: '$category' },
                    popularityScore: { $avg: '$analytics.popularityScore' }
                }
            },
            {
                $project: {
                    _id: 0,
                    totalDesigns: 1,
                    activeDesigns: 1,
                    completionRate: {
                        $multiply: [
                            { $divide: ['$activeDesigns', { $max: ['$totalDesigns', 1] }] },
                            100
                        ]
                    },
                    totalViews: 1,
                    totalLikes: 1,
                    totalDownloads: 1,
                    totalShares: 1,
                    totalComments: 1,
                    avgQuality: { $round: ['$avgQuality', 1] },
                    categories: 1,
                    popularityScore: { $round: ['$popularityScore', 1] }
                }
            }
        ]).cache({ key: `analytics:designs:${userId}:${timeframe}:${category}` });

        return summary[0] || {};
    }

    static async getTrendingCovers(timeframe, limit, category, userId, groups = []) {
        let daysAgo = 7;
        switch (timeframe) {
            case '7d': daysAgo = 7; break;
            case '30d': daysAgo = 30; break;
            case '90d': daysAgo = 90; break;
            case '1y': daysAgo = 365; break;
        }

        const query = {
            $or: [
                { userId },
                { 'accessControl.allowedUsers': userId },
                { 'accessControl.allowedGroups': { $in: groups } },
                { 'accessControl.visibility': 'public' }
            ],
            status: 'active',
            createdAt: { $gte: new Date(Date.now() - daysAgo * 24 * 60 * 60 * 1000) }
        };
        if (category !== 'all') {
            query.category = category;
        }

        return await CoverPhoto.find(query)
            .sort({ 'usage.trendingScore': -1, 'usage.totalViews': -1 })
            .limit(parseInt(limit))
            .select('coverId name category usage processing.thumbnails.medium.url')
            .cache({ key: `trending:covers:${userId}:${timeframe}:${category}:${limit}` })
            .lean();
    }

    static async getTrendingDesigns(timeframe, limit, category, userId, groups = []) {
        let daysAgo = 7;
        switch (timeframe) {
            case '7d': daysAgo = 7; break;
            case '30d': daysAgo = 30; break;
            case '90d': daysAgo = 90; break;
            case '1y': daysAgo = 365; break;
        }

        const query = {
            $or: [
                { userId },
                { 'accessControl.allowedUsers': userId },
                { 'accessControl.allowedGroups': { $in: groups } },
                { 'accessControl.visibility': 'public' }
            ],
            status: 'active',
            createdAt: { $gte: new Date(Date.now() - daysAgo * 24 * 60 * 60 * 1000) }
        };
        if (category !== 'all') {
            query.category = category;
        }

        return await Design.find(query)
            .sort({ 'analytics.popularityScore': -1, 'analytics.views': -1 })
            .limit(parseInt(limit))
            .select('designId name category analytics processing.thumbnails.medium.url')
            .cache({ key: `trending:designs:${userId}:${timeframe}:${category}:${limit}` })
            .lean();
    }

    static async getCoverAnalytics(coverId, timeframe, userId, groups = []) {
        let daysAgo = 30;
        switch (timeframe) {
            case '7d': daysAgo = 7; break;
            case '30d': daysAgo = 30; break;
            case '90d': daysAgo = 90; break;
            case '1y': daysAgo = 365; break;
        }

        const cover = await CoverPhoto.findOne({
            coverId,
            $or: [
                { userId },
                { 'accessControl.allowedUsers': userId },
                { 'accessControl.allowedGroups': { $in: groups } }
            ]
        }).cache({ key: `analytics:cover:${coverId}:${userId}:${timeframe}` });

        if (!cover) {
            throw new AppError('Cover not found or access denied', 404);
        }

        const startDate = new Date(Date.now() - daysAgo * 24 * 60 * 60 * 1000);
        const analytics = await CoverPhoto.aggregate([
            {
                $match: {
                    coverId,
                    'usage.activityLog.timestamp': { $gte: startDate }
                }
            },
            {
                $unwind: '$usage.activityLog'
            },
            {
                $match: {
                    'usage.activityLog.timestamp': { $gte: startDate }
                }
            },
            {
                $group: {
                    _id: {
                        $dateToString: { format: '%Y-%m-%d', date: '$usage.activityLog.timestamp' }
                    },
                    views: { $sum: { $cond: [{ $eq: ['$usage.activityLog.action', 'view'] }, 1, 0] } },
                    likes: { $sum: { $cond: [{ $eq: ['$usage.activityLog.action', 'like'] }, 1, 0] } },
                    downloads: { $sum: { $cond: [{ $eq: ['$usage.activityLog.action', 'download'] }, 1, 0] } },
                    shares: { $sum: { $cond: [{ $eq: ['$usage.activityLog.action', 'share'] }, 1, 0] } }
                }
            },
            {
                $sort: { _id: 1 }
            }
        ]);

        return {
            summary: {
                totalViews: cover.usage.totalViews,
                totalLikes: cover.usage.likes,
                totalDownloads: cover.usage.downloads,
                totalShares: cover.usage.shares,
                trendingScore: cover.usage.trendingScore,
                qualityScore: cover.quality.qualityScore
            },
            trends: analytics.map(a => ({
                date: a._id,
                views: a.views,
                likes: a.likes,
                downloads: a.downloads,
                shares: a.shares
            })),
            thumbnail: cover.processing.thumbnails.medium?.url || ''
        };
    }

    static async getDesignAnalytics(designId, timeframe, userId, groups = []) {
        let daysAgo = 30;
        switch (timeframe) {
            case '7d': daysAgo = 7; break;
            case '30d': daysAgo = 30; break;
            case '90d': daysAgo = 90; break;
            case '1y': daysAgo = 365; break;
        }

        const design = await Design.findOne({
            designId,
            $or: [
                { userId },
                { 'accessControl.allowedUsers': userId },
                { 'accessControl.allowedGroups': { $in: groups } },
                { 'collaboration.collaborators': { $elemMatch: { userId, status: 'accepted' } } }
            ]
        }).cache({ key: `analytics:design:${designId}:${userId}:${timeframe}` });

        if (!design) {
            throw new AppError('Design not found or access denied', 404);
        }

        const startDate = new Date(Date.now() - daysAgo * 24 * 60 * 60 * 1000);
        const analytics = await Design.aggregate([
            {
                $match: {
                    designId,
                    'analytics.activityLog.timestamp': { $gte: startDate }
                }
            },
            {
                $unwind: '$analytics.activityLog'
            },
            {
                $match: {
                    'analytics.activityLog.timestamp': { $gte: startDate }
                }
            },
            {
                $group: {
                    _id: {
                        $dateToString: { format: '%Y-%m-%d', date: '$analytics.activityLog.timestamp' }
                    },
                    views: { $sum: { $cond: [{ $eq: ['$analytics.activityLog.action', 'view'] }, 1, 0] } },
                    likes: { $sum: { $cond: [{ $eq: ['$analytics.activityLog.action', 'like'] }, 1, 0] } },
                    downloads: { $sum: { $cond: [{ $eq: ['$analytics.activityLog.action', 'download'] }, 1, 0] } },
                    shares: { $sum: { $cond: [{ $eq: ['$analytics.activityLog.action', 'share'] }, 1, 0] } },
                    comments: { $sum: { $cond: [{ $eq: ['$analytics.activityLog.action', 'comment'] }, 1, 0] } }
                }
            },
            {
                $sort: { _id: 1 }
            }
        ]);

        return {
            summary: {
                totalViews: design.analytics.views,
                totalLikes: design.analytics.likes,
                totalDownloads: design.analytics.downloads,
                totalShares: design.analytics.shares,
                totalComments: design.analytics.comments,
                popularityScore: design.analytics.popularityScore,
                quality: design.quality
            },
            trends: analytics.map(a => ({
                date: a._id,
                views: a.views,
                likes: a.likes,
                downloads: a.downloads,
                shares: a.shares,
                comments: a.comments
            })),
            thumbnail: design.processing.thumbnails.medium?.url || ''
        };
    }

    static async generateAnalyticsInsights(id, type, timeframe, userId, groups = []) {
        const Model = type === 'cover' ? CoverPhoto : Design;
        const field = type === 'cover' ? 'coverId' : 'designId';

        const resource = await Model.findOne({
            [field]: id,
            $or: [
                { userId },
                { 'accessControl.allowedUsers': userId },
                { 'accessControl.allowedGroups': { $in: groups } },
                type === 'design' ? { 'collaboration.collaborators': { $elemMatch: { userId, status: 'accepted' } } } : {}
            ]
        });

        if (!resource) {
            throw new AppError(`${type} not found or access denied`, 404);
        }

        const analytics = type === 'cover'
            ? await this.getCoverAnalytics(id, timeframe, userId, groups)
            : await this.getDesignAnalytics(id, timeframe, userId, groups);

        const aiAnalysis = await analyzeWithAI(resource.processing.original.url, {
            analyzePerformance: true,
            generateInsights: true
        });

        const insights = [
            {
                insightId: `ins_${uuidv4()}`,
                type: 'performance',
                description: `Engagement rate is ${analytics.summary.totalLikes / Math.max(analytics.summary.totalViews, 1) * 100}%`,
                confidence: 0.9,
                createdAt: new Date()
            },
            {
                insightId: `ins_${uuidv4()}`,
                type: 'visual',
                description: aiAnalysis.insights?.visual || 'No visual insights available',
                confidence: aiAnalysis.insights?.confidence || 0.8,
                createdAt: new Date()
            }
        ];

        resource.analytics.insights = [...(resource.analytics.insights || []), ...insights].slice(-50);
        resource.cacheVersion += 1;
        await resource.save();

        logger.info(`Generated analytics insights for ${type} ${id} by user ${userId}`);
        return insights;
    }

    static async getPlatformAnalytics(id, type, timeframe, platform, userId, groups = []) {
        let daysAgo = 30;
        switch (timeframe) {
            case '7d': daysAgo = 7; break;
            case '30d': daysAgo = 30; break;
            case '90d': daysAgo = 90; break;
            case '1y': daysAgo = 365; break;
        }

        const Model = type === 'cover' ? CoverPhoto : Design;
        const field = type === 'cover' ? 'coverId' : 'designId';
        const analyticsField = type === 'cover' ? 'usage.activityLog' : 'analytics.activityLog';

        const resource = await Model.findOne({
            [field]: id,
            $or: [
                { userId },
                { 'accessControl.allowedUsers': userId },
                { 'accessControl.allowedGroups': { $in: groups } },
                type === 'design' ? { 'collaboration.collaborators': { $elemMatch: { userId, status: 'accepted' } } } : {}
            ]
        });

        if (!resource) {
            throw new AppError(`${type} not found or access denied`, 404);
        }

        const startDate = new Date(Date.now() - daysAgo * 24 * 60 * 60 * 1000);
        const analytics = await Model.aggregate([
            {
                $match: {
                    [field]: id,
                    [`${analyticsField}.timestamp`]: { $gte: startDate },
                    [`${analyticsField}.platform`]: platform
                }
            },
            {
                $unwind: `$${analyticsField}`
            },
            {
                $match: {
                    [`${analyticsField}.timestamp`]: { $gte: startDate },
                    [`${analyticsField}.platform`]: platform
                }
            },
            {
                $group: {
                    _id: {
                        $dateToString: { format: '%Y-%m-%d', date: `$${analyticsField}.timestamp` }
                    },
                    views: { $sum: { $cond: [{ $eq: [`$${analyticsField}.action`, 'view'] }, 1, 0] } },
                    likes: { $sum: { $cond: [{ $eq: [`$${analyticsField}.action`, 'like'] }, 1, 0] } },
                    downloads: { $sum: { $cond: [{ $eq: [`$${analyticsField}.action`, 'download'] }, 1, 0] } },
                    shares: { $sum: { $cond: [{ $eq: [`$${analyticsField}.action`, 'share'] }, 1, 0] } },
                    comments: { $sum: { $cond: [{ $eq: [`$${analyticsField}.action`, 'comment'] }, 1, 0] } }
                }
            },
            {
                $sort: { _id: 1 }
            }
        ]);

        logger.info(`Retrieved platform analytics for ${type} ${id} on ${platform} by user ${userId}`);
        return {
            platform,
            trends: analytics.map(a => ({
                date: a._id,
                views: a.views,
                likes: a.likes,
                downloads: a.downloads,
                shares: a.shares,
                comments: a.comments || 0
            }))
        };
    }

    static async updateAnalyticsMetrics(id, type, metrics, userId, groups = []) {
        const Model = type === 'cover' ? CoverPhoto : Design;
        const field = type === 'cover' ? 'coverId' : 'designId';
        const analyticsField = type === 'cover' ? 'usage' : 'analytics';

        const resource = await Model.findOne({
            [field]: id,
            $or: [
                { userId },
                { 'accessControl.allowedUsers': userId },
                { 'accessControl.allowedGroups': { $in: groups } },
                type === 'design' ? { 'collaboration.collaborators': { $elemMatch: { userId, status: 'accepted', role: { $in: ['editor', 'admin'] } } } } : {}
            ]
        });

        if (!resource) {
            throw new AppError(`${type} not found or access denied`, 404);
        }

        const allowedMetrics = ['views', 'likes', 'downloads', 'shares', 'comments'];
        for (const [metric, value] of Object.entries(metrics)) {
            if (allowedMetrics.includes(metric) && Number.isInteger(value) && value >= 0) {
                resource[analyticsField][metric] += value;
                resource[analyticsField].activityLog.push({
                    action: metric,
                    timestamp: new Date(),
                    userId,
                    platform: metrics.platform || 'unknown'
                });
            }
        }

        if (type === 'cover') {
            resource.usage.trendingScore = (
                resource.usage.views * 0.1 +
                resource.usage.likes * 0.5 +
                resource.usage.downloads * 2 +
                resource.usage.shares * 1
            );
        } else {
            resource.analytics.popularityScore = (
                resource.analytics.views * 0.1 +
                resource.analytics.likes * 0.5 +
                resource.analytics.downloads * 2 +
                resource.analytics.shares * 1 +
                resource.analytics.comments * 0.5
            );
        }

        resource.cacheVersion += 1;
        await resource.save();

        logger.info(`Updated analytics metrics for ${type} ${id} by user ${userId}`);
        return {
            [field]: id,
            [analyticsField]: resource[analyticsField]
        };
    }

    static async bulkUpdateAnalyticsMetrics(ids, type, metrics, userId, groups = []) {
        const Model = type === 'cover' ? CoverPhoto : Design;
        const field = type === 'cover' ? 'coverId' : 'designId';
        const analyticsField = type === 'cover' ? 'usage' : 'analytics';

        const resources = await Model.find({
            [field]: { $in: ids },
            $or: [
                { userId },
                { 'accessControl.allowedUsers': userId },
                { 'accessControl.allowedGroups': { $in: groups } },
                type === 'design' ? { 'collaboration.collaborators': { $elemMatch: { userId, status: 'accepted', role: { $in: ['editor', 'admin'] } } } } : {}
            ]
        });

        const updated = [];
        const failed = [];

        const allowedMetrics = ['views', 'likes', 'downloads', 'shares', 'comments'];
        for (const resource of resources) {
            try {
                for (const [metric, value] of Object.entries(metrics)) {
                    if (allowedMetrics.includes(metric) && Number.isInteger(value) && value >= 0) {
                        resource[analyticsField][metric] += value;
                        resource[analyticsField].activityLog.push({
                            action: metric,
                            timestamp: new Date(),
                            userId,
                            platform: metrics.platform || 'unknown'
                        });
                    }
                }

                if (type === 'cover') {
                    resource.usage.trendingScore = (
                        resource.usage.views * 0.1 +
                        resource.usage.likes * 0.5 +
                        resource.usage.downloads * 2 +
                        resource.usage.shares * 1
                    );
                } else {
                    resource.analytics.popularityScore = (
                        resource.analytics.views * 0.1 +
                        resource.analytics.likes * 0.5 +
                        resource.analytics.downloads * 2 +
                        resource.analytics.shares * 1 +
                        resource.analytics.comments * 0.5
                    );
                }

                resource.cacheVersion += 1;
                updated.push(await resource.save());
            } catch (error) {
                failed.push({ [field]: resource[field], error: error.message });
            }
        }

        logger.info(`Bulk updated analytics metrics for ${ids.length} ${type}s by user ${userId}`);
        return { updated, failed };
    }

    static async getEngagementTrends(id, type, timeframe, userId, groups = []) {
        let daysAgo = 30;
        switch (timeframe) {
            case '7d': daysAgo = 7; break;
            case '30d': daysAgo = 30; break;
            case '90d': daysAgo = 90; break;
            case '1y': daysAgo = 365; break;
        }

        const Model = type === 'cover' ? CoverPhoto : Design;
        const field = type === 'cover' ? 'coverId' : 'designId';
        const analyticsField = type === 'cover' ? 'usage.activityLog' : 'analytics.activityLog';

        const resource = await Model.findOne({
            [field]: id,
            $or: [
                { userId },
                { 'accessControl.allowedUsers': userId },
                { 'accessControl.allowedGroups': { $in: groups } },
                type === 'design' ? { 'collaboration.collaborators': { $elemMatch: { userId, status: 'accepted' } } } : {}
            ]
        });

        if (!resource) {
            throw new AppError(`${type} not found or access denied`, 404);
        }

        const startDate = new Date(Date.now() - daysAgo * 24 * 60 * 60 * 1000);
        const trends = await Model.aggregate([
            {
                $match: {
                    [field]: id,
                    [`${analyticsField}.timestamp`]: { $gte: startDate }
                }
            },
            {
                $unwind: `$${analyticsField}`
            },
            {
                $match: {
                    [`${analyticsField}.timestamp`]: { $gte: startDate }
                }
            },
            {
                $group: {
                    _id: {
                        $dateToString: { format: '%Y-%m-%d', date: `$${analyticsField}.timestamp` }
                    },
                    engagement: {
                        $sum: {
                            $switch: {
                                branches: [
                                    { case: { $eq: [`$${analyticsField}.action`, 'view'] }, then: 0.1 },
                                    { case: { $eq: [`$${analyticsField}.action`, 'like'] }, then: 0.5 },
                                    { case: { $eq: [`$${analyticsField}.action`, 'download'] }, then: 2 },
                                    { case: { $eq: [`$${analyticsField}.action`, 'share'] }, then: 1 },
                                    { case: { $eq: [`$${analyticsField}.action`, 'comment'] }, then: 0.5 }
                                ],
                                default: 0
                            }
                        }
                    }
                }
            },
            {
                $sort: { _id: 1 }
            }
        ]).cache({ key: `trends:${type}:${id}:${userId}:${timeframe}` });

        logger.info(`Retrieved engagement trends for ${type} ${id} by user ${userId}`);
        return trends.map(t => ({
            date: t._id,
            engagement: t.engagement
        }));
    }
}