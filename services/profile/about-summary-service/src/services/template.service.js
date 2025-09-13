import SummaryTemplate from '../models/SummaryTemplate.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { cacheService } from '../services/cache.service.js';
import { metricsCollector } from '../utils/metrics.js';
import { eventEmitter } from '../events/events.js';
import { slugify } from '../utils/string.js';
import { generateId } from '../utils/id.js';
import mongoose from 'mongoose';

class TemplateService {
    constructor() {
        this.model = SummaryTemplate;
        this.defaultCacheTTL = 1800; // 30 minutes
    }

    /**
     * Create a new template
     */
    async createTemplate(data) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            // Generate unique ID
            const templateId = generateId('tpl');

            // Prepare template data
            const templateData = {
                ...data,
                _id: templateId,
                slug: await this.generateUniqueSlug(slugify(data.name)),
                analytics: this.initializeAnalytics(),
                settings: this.getDefaultSettings(data.userId),
                metadata: {
                    ...data.metadata,
                    variableCount: (data.content.match(/\{\{[^}]+\}\}/g) || []).length,
                },
            };

            // Create template
            const [template] = await this.model.create([templateData], { session });

            // Update user stats
            await this.updateUserStats(data.userId, 'create', session);

            await session.commitTransaction();

            // Clear cache
            await this.clearTemplateCache(templateId);

            // Schedule async processing
            this.scheduleAsyncProcessing(templateId);

            logger.info(`Template created: ${template._id} by user ${data.userId}`);
            return template;
        } catch (error) {
            await session.abortTransaction();
            logger.error('Template creation failed:', error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    /**
     * Get template by ID with caching
     */
    async getTemplateById(templateId, userId, options = {}) {
        try {
            const cacheKey = `template:${templateId}:${userId || 'public'}:${JSON.stringify(options)}`;

            // Try cache first
            if (!options.skipCache) {
                const cached = await cacheService.get(cacheKey);
                if (cached) {
                    metricsCollector.increment('template.cache_hit');
                    return cached;
                }
            }

            const query = this.model.findById(templateId);
            if (options.fields) {
                query.select(options.fields);
            }

            const template = await query.lean();
            if (!template) {
                return null;
            }

            // Check access
            const hasAccess = this.checkAccess(template, userId);
            if (!hasAccess && !options.skipAccessCheck) {
                throw new AppError('Access denied', 403);
            }

            // Process template data
            const processedTemplate = this.processTemplateResponse(template, userId);

            // Cache result
            if (!options.skipCache) {
                await cacheService.set(cacheKey, processedTemplate, this.defaultCacheTTL);
                metricsCollector.increment('template.cache_miss');
            }

            return processedTemplate;
        } catch (error) {
            logger.error(`Failed to get template ${templateId}:`, error);
            throw error;
        }
    }

    /**
     * Get templates with filtering and pagination
     */
    async getTemplates(query, options = {}) {
        try {
            const { skip = 0, limit = 20 } = options;
            return await this.model
                .find(query)
                .skip(skip)
                .limit(limit)
                .lean();
        } catch (error) {
            logger.error('Template fetch failed:', error);
            throw error;
        }
    }

    /**
     * Count templates
     */
    async countTemplates(query) {
        try {
            return await this.model.countDocuments(query);
        } catch (error) {
            logger.error('Template count failed:', error);
            throw error;
        }
    }

    /**
     * Update a template
     */
    async updateTemplate(templateId, updates, userId) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const template = await this.model.findById(templateId).session(session);
            if (!template) {
                throw new AppError('Template not found', 404);
            }

            // Check permissions
            if (template.userId !== userId) {
                throw new AppError('Access denied', 403);
            }

            // Apply updates
            Object.assign(template, updates);

            // Update metadata
            if (updates.content) {
                template.metadata.variableCount = (updates.content.match(/\{\{[^}]+\}\}/g) || []).length;
            }

            // Regenerate slug if name changed
            if (updates.name && updates.name !== template.name) {
                template.slug = await this.generateUniqueSlug(slugify(updates.name), templateId);
            }

            const updatedTemplate = await template.save({ session });

            // Update user stats
            await this.updateUserStats(userId, 'update', session);

            await session.commitTransaction();

            // Clear cache
            await this.clearTemplateCache(templateId);

            return updatedTemplate;
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Template update failed for ${templateId}:`, error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    /**
     * Delete a template (soft or hard)
     */
    async deleteTemplate(templateId, userId, permanent = false) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const template = await this.model.findById(templateId).session(session);
            if (!template) {
                throw new AppError('Template not found', 404);
            }

            // Check permissions
            if (template.userId !== userId) {
                throw new AppError('Access denied', 403);
            }

            if (permanent) {
                await this.model.findByIdAndDelete(templateId).session(session);
            } else {
                template.flags.isDeleted = true;
                template.status = 'deleted';
                template.deletedAt = new Date();
                await template.save({ session });
            }

            // Update user stats
            await this.updateUserStats(userId, permanent ? 'permanent_delete' : 'soft_delete', session);

            await session.commitTransaction();

            // Clear cache
            await this.clearTemplateCache(templateId);

            logger.info(`Template ${permanent ? 'permanently' : 'soft'} deleted: ${templateId} by user ${userId}`);
            return { deleted: true, permanent };
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Template deletion failed for ${templateId}:`, error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    /**
     * Bulk update templates
     */
    async bulkUpdate(templateIds, operation, data, userId) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const query = { _id: { $in: templateIds }, userId, 'flags.isDeleted': false };
            const templates = await this.model.find(query).session(session);

            if (templates.length === 0) {
                throw new AppError('No templates found', 404);
            }

            if (templates.length !== templateIds.length) {
                throw new AppError('Some templates not found or access denied', 403);
            }

            let updateData = {};
            switch (operation) {
                case 'delete':
                    updateData = {
                        'flags.isDeleted': true,
                        status: 'deleted',
                        deletedAt: new Date(),
                        'metadata.lastModifiedBy': { userId, timestamp: new Date() },
                    };
                    break;
                case 'updateCategory':
                    if (!data.category) throw new AppError('Category is required', 400);
                    updateData = { category: data.category, updatedAt: new Date() };
                    break;
                case 'updateVisibility':
                    if (!data.visibility) throw new AppError('Visibility is required', 400);
                    updateData = { visibility: data.visibility, updatedAt: new Date() };
                    break;
                case 'updateTags':
                    if (!Array.isArray(data.tags)) throw new AppError('Tags array is required', 400);
                    updateData = {
                        $addToSet: { tags: { $each: data.tags.map(tag => tag.trim().toLowerCase()).slice(0, 10) } },
                        updatedAt: new Date(),
                    };
                    break;
                default:
                    throw new AppError('Invalid operation', 400);
            }

            const result = await this.model.updateMany(query, updateData).session(session);

            // Update user stats
            await this.updateUserStats(userId, 'bulk_update', session);

            await session.commitTransaction();

            // Clear cache
            await Promise.all(templateIds.map(id => this.clearTemplateCache(id)));

            return {
                requested: templateIds.length,
                matched: result.matchedCount,
                modified: result.modifiedCount,
            };
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk update failed for user ${userId}:`, error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    /**
     * Get template analytics
     */
    async getAnalytics(templateId, timeframe, metrics) {
        try {
            const template = await this.model.findById(templateId).select('analytics').lean();
            if (!template) {
                throw new AppError('Template not found', 404);
            }

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

            const analytics = template.analytics || {};
            const filteredAnalytics = {
                usage: {
                    total: analytics.usage?.total || 0,
                    byDate: (analytics.usage?.byDate || []).filter(u => new Date(u.date) >= timeframeDate),
                },
                views: {
                    total: analytics.views?.total || 0,
                    unique: analytics.views?.unique || 0,
                },
            };

            if (metrics === 'detailed') {
                filteredAnalytics.performance = analytics.performance || {};
            }

            return filteredAnalytics;
        } catch (error) {
            logger.error(`Analytics fetch failed for template ${templateId}:`, error);
            throw error;
        }
    }

    /**
     * Duplicate a template
     */
    async duplicateTemplate(templateId, userId, options = {}) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const original = await this.model.findById(templateId).session(session);
            if (!original) {
                throw new AppError('Template not found', 404);
            }

            // Prepare duplicate data
            const duplicateData = original.toObject();
            delete duplicateData._id;
            delete duplicateData.createdAt;
            delete duplicateData.updatedAt;
            delete duplicateData.analytics;

            // Update identifiers
            duplicateData._id = generateId('tpl');
            duplicateData.name = options.name || `${original.name} (Copy)`;
            duplicateData.slug = await this.generateUniqueSlug(slugify(duplicateData.name));
            duplicateData.userId = userId;
            duplicateData.analytics = this.initializeAnalytics();

            const [duplicate] = await this.model.create([duplicateData], { session });

            // Update user stats
            await this.updateUserStats(userId, 'duplicate', session);

            await session.commitTransaction();

            // Clear cache
            await this.clearTemplateCache(duplicate._id);

            logger.info(`Template duplicated: ${templateId} -> ${duplicate._id} by user ${userId}`);
            return duplicate;
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Template duplication failed for ${templateId}:`, error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    /**
     * Increment view count
     */
    async incrementViews(templateId) {
        try {
            await this.model.findByIdAndUpdate(templateId, {
                $inc: { 'analytics.views.total': 1, 'analytics.views.unique': 1 },
            });
        } catch (error) {
            logger.error(`View increment failed for template ${templateId}:`, error);
        }
    }

    // Helper Methods

    async generateUniqueSlug(baseSlug, excludeId = null) {
        let slug = baseSlug;
        let counter = 1;

        while (true) {
            const query = { slug };
            if (excludeId) {
                query._id = { $ne: excludeId };
            }

            const existing = await this.model.findOne(query).select('_id').lean();
            if (!existing) {
                return slug;
            }

            slug = `${baseSlug}-${counter}`;
            counter++;

            if (counter > 100) {
                slug = `${baseSlug}-${crypto.randomBytes(4).toString('hex')}`;
                break;
            }
        }

        return slug;
    }

    initializeAnalytics() {
        return {
            usage: {
                total: 0,
                byDate: [],
            },
            views: {
                total: 0,
                unique: 0,
            },
            performance: {
                adoptionRate: 0,
                successRate: 0,
            },
        };
    }

    getDefaultSettings(userId) {
        return {
            autoApply: false,
            notifications: {
                usage: true,
                updates: false,
            },
        };
    }

    async updateUserStats(userId, action, session) {
        try {
            metricsCollector.increment(`template.${action}`, { userId });
        } catch (error) {
            logger.error(`Failed to update user stats for ${userId}:`, error);
        }
    }

    checkAccess(template, userId) {
        if (template.visibility === 'public') return true;
        if (template.userId === userId) return true;
        return false;
    }

    processTemplateResponse(template, userId) {
        const processed = {
            ...template,
            isOwner: template.userId === userId,
            variableCount: template.metadata?.variableCount || 0,
        };

        if (template.userId !== userId) {
            delete processed.metadata?.createdBy;
        }

        return processed;
    }

    async clearTemplateCache(templateId) {
        try {
            const patterns = [
                `template:${templateId}:*`,
                'templates:*',
            ];
            await Promise.all(patterns.map(pattern => cacheService.deletePattern(pattern)));
        } catch (error) {
            logger.error(`Cache clearing failed for template ${templateId}:`, error);
        }
    }

    scheduleAsyncProcessing(templateId) {
        setTimeout(async () => {
            try {
                // Placeholder for async tasks (e.g., validate variables, update analytics)
                logger.info(`Async processing completed for template ${templateId}`);
            } catch (error) {
                logger.error(`Async processing failed for template ${templateId}:`, error);
            }
        }, 1000);
    }
}

export default new TemplateService();