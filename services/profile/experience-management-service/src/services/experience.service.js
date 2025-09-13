import { Experience } from '../models/Experience.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { cacheService } from '../services/cache.service.js';
import { metricsCollector } from '../utils/metrics.js';
import mongoose from 'mongoose';
import sanitizeHtml from 'sanitize-html';
import { eventEmitter } from '../events/events.js';
import natural from 'natural';

class ExperienceService {
    /**
     * Create a new experience
     */
    async createExperience(data, options = {}) {
        const { userId, metadata, ...experienceData } = data;

        try {
            const experience = new Experience({
                ...experienceData,
                userId,
                metadata: {
                    ...metadata,
                    createdAt: new Date(),
                },
                analytics: {
                    views: { total: 0, unique: 0, byDate: [] },
                    shares: { total: 0, byPlatform: {} },
                    endorsements: [],
                },
                status: 'draft',
                visibility: 'private',
            });

            await experience.save(options);
            logger.info(`Experience created: ${experience._id} for user ${userId}`);
            metricsCollector.increment('experience.created', { userId });

            return experience;
        } catch (error) {
            logger.error(`Failed to create experience for user ${userId}:`, error);
            metricsCollector.increment('experience.create_failed', { userId });
            throw new AppError('Failed to create experience', 500);
        }
    }

    /**
     * Index experience for search
     */
    async indexForSearch(experience) {
        try {
            const searchableFields = {
                title: experience.title,
                description: experience.description,
                tags: experience.tags || [],
                keywords: experience.keywords || [],
            };

            // Simulate indexing (e.g., to Elasticsearch or MongoDB text index)
            await Experience.findByIdAndUpdate(
                experience._id,
                { $set: { searchableFields } },
                { new: true }
            );

            logger.info(`Experience ${experience._id} indexed for search`);
            metricsCollector.increment('experience.indexed', { experienceId: experience._id });
        } catch (error) {
            logger.error(`Failed to index experience ${experience._id}:`, error);
            metricsCollector.increment('experience.index_failed', { experienceId: experience._id });
        }
    }

    /**
     * Extract keywords from description
     */
    async extractKeywords(description) {
        try {
            const tokenizer = new natural.WordTokenizer();
            const words = tokenizer.tokenize(sanitizeHtml(description).toLowerCase());
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
            const stats = await Experience.aggregate([
                { $match: { userId, status: { $ne: 'deleted' } } },
                {
                    $group: {
                        _id: null,
                        totalExperiences: { $sum: 1 },
                        totalViews: { $sum: '$analytics.views.total' },
                        totalShares: { $sum: '$analytics.shares.total' },
                    },
                },
            ]);

            const userStats = stats[0] || {
                totalExperiences: 0,
                totalViews: 0,
                totalShares: 0,
            };

            await cacheService.set(`user_stats:${userId}`, userStats, 3600);
            logger.info(`Updated stats for user ${userId}`);
            metricsCollector.increment('experience.user_stats_updated', { userId });
        } catch (error) {
            logger.error(`Failed to update user stats for ${userId}:`, error);
            metricsCollector.increment('experience.user_stats_failed', { userId });
        }
    }

    /**
     * Calculate quality score
     */
    async calculateQualityScore(experienceId, options = {}) {
        try {
            const experience = await Experience.findById(experienceId, null, options);
            if (!experience) {
                throw new AppError('Experience not found', 404);
            }

            const completeness = this.calculateCompleteness(experience);
            const engagement = this.calculateEngagement(experience);
            const qualityScore = (completeness * 0.6) + (engagement * 0.4);

            experience.qualityScore = Math.min(100, Math.max(0, qualityScore));
            await experience.save(options);

            logger.info(`Calculated quality score for experience ${experienceId}: ${experience.qualityScore}`);
            metricsCollector.gauge('experience.quality_score', qualityScore, { experienceId });

            return experience.qualityScore;
        } catch (error) {
            logger.error(`Failed to calculate quality score for experience ${experienceId}:`, error);
            throw error;
        }
    }

    /**
     * Calculate completeness score
     */
    calculateCompleteness(experience) {
        let score = 0;
        if (experience.title) score += 20;
        if (experience.description && experience.description.length > 100) score += 30;
        if (experience.tags && experience.tags.length > 0) score += 20;
        if (experience.achievements && experience.achievements.length > 0) score += 20;
        if (experience.mediaAttachments && experience.mediaAttachments.length > 0) score += 10;
        return score;
    }

    /**
     * Calculate engagement score
     */
    calculateEngagement(experience) {
        const views = experience.analytics?.views?.total || 0;
        const shares = experience.analytics?.shares?.total || 0;
        const endorsements = experience.endorsements?.length || 0;

        return Math.min(100, (views * 0.4) + (shares * 0.3) + (endorsements * 0.3));
    }

    /**
     * Get trending experiences
     */
    async getTrendingExperiences(timeframe, category, limit) {
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

            const experiences = await Experience.find(query)
                .sort({ 'analytics.views.total': -1, qualityScore: -1 })
                .limit(limit)
                .lean();

            logger.info(`Fetched ${experiences.length} trending experiences`);
            return experiences;
        } catch (error) {
            logger.error(`Failed to fetch trending experiences:`, error);
            throw new AppError('Failed to fetch trending experiences', 500);
        }
    }

    /**
     * Search experiences
     */
    async searchExperiences(query, filters, options) {
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
                Experience.find(searchQuery)
                    .skip(skip)
                    .limit(limit)
                    .lean(),
                Experience.countDocuments(searchQuery),
            ]);

            return { hits: results, total };
        } catch (error) {
            logger.error(`Search failed for experiences: ${query}`, error);
            throw new AppError('Failed to search experiences', 500);
        }
    }
}

export default new ExperienceService();