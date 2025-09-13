import { Company } from '../models/Company.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { cacheService } from '../services/cache.service.js';
import { metricsCollector } from '../utils/metrics.js';
import mongoose from 'mongoose';
import sanitizeHtml from 'sanitize-html';
import { eventEmitter } from '../events/events.js';
import natural from 'natural';
import axios from 'axios';

class CompanyService {
    /**
     * Create a new company
     */
    async createCompany(data, options = {}) {
        const { userId, metadata, ...companyData } = data;

        try {
            const company = new Company({
                ...companyData,
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
                verification: {
                    status: 'pending',
                    confidence: 0,
                },
            });

            await company.save(options);
            logger.info(`Company created: ${company._id} for user ${userId}`);
            metricsCollector.increment('company.created', { userId });

            return company;
        } catch (error) {
            logger.error(`Failed to create company for user ${userId}:`, error);
            metricsCollector.increment('company.create_failed', { userId });
            throw new AppError('Failed to create company', 500);
        }
    }

    /**
     * Create backup for company
     */
    async createBackup(companyId, action, userId, options = {}) {
        try {
            const company = await Company.findById(companyId, null, options);
            if (!company) {
                throw new AppError('Company not found', 404);
            }

            const backup = {
                companyId,
                action,
                userId,
                data: company.toObject(),
                createdAt: new Date(),
            };

            // Simulate backup storage (e.g., to S3 or another collection)
            await cacheService.set(`backup:company:${companyId}:${Date.now()}`, backup, 30 * 24 * 60 * 60); // 30 days
            logger.info(`Backup created for company ${companyId}`);
            metricsCollector.increment('company.backup_created', { companyId });
        } catch (error) {
            logger.error(`Failed to create backup for company ${companyId}:`, error);
            metricsCollector.increment('company.backup_failed', { companyId });
        }
    }

    /**
     * Delete all backups for a company
     */
    async deleteAllBackups(companyId) {
        try {
            await cacheService.deletePattern(`backup:company:${companyId}:*`);
            logger.info(`Deleted all backups for company ${companyId}`);
            metricsCollector.increment('company.backups_deleted', { companyId });
        } catch (error) {
            logger.error(`Failed to delete backups for company ${companyId}:`, error);
            metricsCollector.increment('company.backups_delete_failed', { companyId });
        }
    }

    /**
     * Index company for search
     */
    async indexForSearch(company) {
        try {
            const searchableFields = {
                name: company.name,
                description: company.description,
                industry: company.industry,
                tags: company.tags || [],
                keywords: company.keywords || [],
            };

            await Company.findByIdAndUpdate(
                company._id,
                { $set: { searchableFields } },
                { new: true }
            );

            logger.info(`Company ${company._id} indexed for search`);
            metricsCollector.increment('company.indexed', { companyId: company._id });
        } catch (error) {
            logger.error(`Failed to index company ${company._id}:`, error);
            metricsCollector.increment('company.index_failed', { companyId: company._id });
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
            const stats = await Company.aggregate([
                { $match: { userId, status: { $ne: 'deleted' } } },
                {
                    $group: {
                        _id: null,
                        totalCompanies: { $sum: 1 },
                        totalViews: { $sum: '$analytics.views.total' },
                        totalShares: { $sum: '$analytics.shares.total' },
                        totalEndorsements: { $sum: { $size: '$endorsements' } },
                    },
                },
            ]);

            const userStats = stats[0] || {
                totalCompanies: 0,
                totalViews: 0,
                totalShares: 0,
                totalEndorsements: 0,
            };

            await cacheService.set(`user_stats:${userId}`, userStats, 3600);
            logger.info(`Updated stats for user ${userId}`);
            metricsCollector.increment('company.user_stats_updated', { userId });
        } catch (error) {
            logger.error(`Failed to update user stats for ${userId}:`, error);
            metricsCollector.increment('company.user_stats_failed', { userId });
        }
    }

    /**
     * Verify company with external API
     */
    async verifyCompany({ companyId, userId, name, website, location }) {
        try {
            // Simulate external verification API call
            const response = await axios.post('https://api.verification-service.com/verify', {
                name,
                website,
                location,
            });

            const result = {
                success: response.data.success,
                status: response.data.status || 'pending',
                confidence: response.data.confidence || 0,
                verifiedBy: 'external-service',
                details: response.data.details || {},
            };

            await Company.findByIdAndUpdate(
                companyId,
                { verification: result },
                { new: true }
            );

            logger.info(`Company ${companyId} verified with status ${result.status}`);
            metricsCollector.increment('company.verified', { companyId, status: result.status });
            return result;
        } catch (error) {
            logger.error(`Verification failed for company ${companyId}:`, error);
            metricsCollector.increment('company.verify_failed', { companyId });
            return { success: false, message: error.message };
        }
    }

    /**
     * Check connection level between users
     */
    async checkConnectionLevel(userId, requestingUserId) {
        try {
            // Simulate connection check (e.g., via a User model or external service)
            const isConnected = true; // Placeholder
            return isConnected;
        } catch (error) {
            logger.error(`Failed to check connection level for users ${userId} and ${requestingUserId}:`, error);
            return false;
        }
    }

    /**
     * Get trending companies
     */
    async getTrendingCompanies(timeframe, industry, limit) {
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

            if (industry && industry !== 'all') {
                query.industry = industry;
            }

            const companies = await Company.find(query)
                .sort({ 'analytics.views.total': -1, qualityScore: -1 })
                .limit(limit)
                .lean();

            logger.info(`Fetched ${companies.length} trending companies`);
            return companies;
        } catch (error) {
            logger.error(`Failed to fetch trending companies:`, error);
            throw new AppError('Failed to fetch trending companies', 500);
        }
    }

    /**
     * Search companies
     */
    async searchCompanies(query, filters, options) {
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
                Company.find(searchQuery)
                    .skip(skip)
                    .limit(limit)
                    .lean(),
                Company.countDocuments(searchQuery),
            ]);

            return { hits: results, total };
        } catch (error) {
            logger.error(`Search failed for companies: ${query}`, error);
            throw new AppError('Failed to search companies', 500);
        }
    }
}

export default new CompanyService();