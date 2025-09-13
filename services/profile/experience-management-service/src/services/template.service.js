import { Template } from '../models/Template.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { cacheService } from '../services/cache.service.js';
import { metricsCollector } from '../utils/metrics.js';
import mongoose from 'mongoose';
import sanitizeHtml from 'sanitize-html';
import { eventEmitter } from '../events/events.js';
import natural from 'natural';

class TemplateService {
    /**
     * Create a new template
     */
    async createTemplate(data, options = {}) {
        const { userId, metadata, ...templateData } = data;

        try {
            const template = new Template({
                ...templateData,
                userId,
                metadata: {
                    ...metadata,
                    createdAt: new Date(),
                },
                analytics: {
                    views: { total: 0, unique: 0, byDate: [] },
                    shares: { total: 0, byPlatform: {} },
                },
                status: 'draft',
                visibility: 'private',
            });

            await template.save(options);
            logger.info(`Template created: ${template._id} for user ${userId}`);
            metricsCollector.increment('template.created', { userId });

            return template;
        } catch (error) {
            logger.error(`Failed to create template for user ${userId}:`, error);
            metricsCollector.increment('template.create_failed', { userId });
            throw new AppError('Failed to create template', 500);
        }
    }

    /**
     * Index template for search
     */
    async indexForSearch(template) {
        try {
            const searchableFields = {
                name: template.name,
                content: template.content,
                category: template.category,
                tags: template.tags || [],
                keywords: template.keywords || [],
            };

            await Template.findByIdAndUpdate(
                template._id,
                { $set: { searchableFields } },
                { new: true }
            );

            logger.info(`Template ${template._id} indexed for search`);
            metricsCollector.increment('template.indexed', { templateId: template._id });
        } catch (error) {
            logger.error(`Failed to index template ${template._id}:`, error);
            metricsCollector.increment('template.index_failed', { templateId: template._id });
        }
    }

    /**
     * Extract keywords from content
     */
    async extractKeywords(content) {
        try {
            const tokenizer = new natural.WordTokenizer();
            const words = tokenizer.tokenize(sanitizeHtml(content).toLowerCase());
            const tfidf = new natural.TfIdf();
            tfidf.addDocument(words);

            const keywords = [];
            tfidf.listTerms(0).forEach((item) => {
                if (item.tfidf > 1) {
                    keywords.push(item.term);
                }
            });

            return keywords.slice(0, 20);
        } catch (error) {
            logger.error(`Failed to extract keywords:`, error);
            return [];
        }
    }

    /**
     * Update user stats
     */
    async updateUserStats(userId, options = {}) {
        try {
            const stats = await Template.aggregate([
                { $match: { userId, status: { $ne: 'deleted' } } },
                {
                    $group: {
                        _id: null,
                        totalTemplates: { $sum: 1 },
                        totalViews: { $sum: '$analytics.views.total' },
                        totalShares: { $sum: '$analytics.shares.total' },
                    },
                },
            ]);

            const userStats = stats[0] || {
                totalTemplates: 0,
                totalViews: 0,
                totalShares: 0,
            };

            await cacheService.set(`user_stats:${userId}`, userStats, 3600);
            logger.info(`Updated stats for user ${userId}`);
            metricsCollector.increment('template.user_stats_updated', { userId });
        } catch (error) {
            logger.error(`Failed to update user stats for ${userId}:`, error);
            metricsCollector.increment('template.user_stats_failed', { userId });
        }
    }

    /**
     * Get trending templates
     */
    async getTrendingTemplates(timeframe, category, limit) {
        try {
            const timeframeDate = new Date();
            switch (timeframe) {
                case '7d':
                    timeframeDate.setDate(timeframeDate.getDate() - 7);
                    break;
                case '30d':
                    timeframeDate.setDate(timeframeDate.getDate() - 30);
                    break;
                case '90d':
                    timeframeDate.setDate(timeframeDate.getDate() - 90);
                    break;
                default:
                    timeframeDate.setDate(timeframeDate.getDate() - 30);
            }

            const query = {
                status: 'active',
                visibility: 'public',
                createdAt: { $gte: timeframeDate },
            };

            if (category && category !== 'all') {
                query.category = category;
            }

            const templates = await Template.find(query)
                .sort({ 'analytics.views.total': -1 })
                .limit(limit)
                .lean();

            logger.info(`Fetched ${templates.length} trending templates`);
            return templates;
        } catch (error) {
            logger.error(`Failed to fetch trending templates:`, error);
            throw new AppError('Failed to fetch trending templates', 500);
        }
    }

    /**
     * Search templates
     */
    async searchTemplates(query, filters, options) {
        try {
            const { page = 1, limit = 20 } = options;
            const skip = (page - 1) * limit;

            const searchQuery = {
                status: { $ne: 'deleted' },
                visibility: 'public',
                $text: { $search: query },
            };

            Object.assign(searchQuery, filters);

            const [results, total] = await Promise.all([
                Template.find(searchQuery)
                    .skip(skip)
                    .limit(limit)
                    .lean(),
                Template.countDocuments(searchQuery),
            ]);

            return { hits: results, total };
        } catch (error) {
            logger.error(`Search failed for templates: ${query}`, error);
            throw new AppError('Failed to search templates', 500);
        }
    }
}

export default new TemplateService();