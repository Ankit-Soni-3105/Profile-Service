import Summary from '../models/Summary.js';
import SummaryTemplate from '../models/SummaryTemplate.js';
import GrammarService from './GrammarService.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { cacheService } from './cache.service.js';
import { eventEmitter } from '../events/events.js';
import { metricsCollector } from '../utils/metrics.js';
import { aiService } from './ai.service.js';
import { searchService } from './search.service.js';
import { notificationService } from './notification.service.js';
import { slugify } from '../utils/string.js';
import { generateId } from '../utils/id.js';
import crypto from 'crypto';
import mongoose from 'mongoose';

class SummaryService {
    constructor() {
        this.model = Summary;
        this.templateModel = SummaryTemplate;
        this.grammarService = new GrammarService();
        this.defaultCacheTTL = 600; // 10 minutes
    }

    /**
     * Create a new summary
     */
    async createSummary(data) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            // Generate unique slug
            const baseSlug = slugify(data.title);
            const slug = await this.generateUniqueSlug(baseSlug);

            // Prepare summary data
            const summaryData = {
                ...data,
                _id: generateId('sum'),
                slug,
                metadata: {
                    ...data.metadata,
                    wordCount: data.content ? data.content.trim().split(/\s+/).length : 0,
                    characterCount: data.content ? data.content.length : 0,
                    createdBy: data.metadata.createdBy || { userId: data.userId },
                },
                versions: [{
                    versionNumber: 1,
                    content: data.content,
                    title: data.title,
                    changeType: 'create',
                    isActive: true,
                    createdAt: new Date(),
                    stats: {
                        characterCount: data.content ? data.content.length : 0,
                        wordCount: data.content ? data.content.trim().split(/\s+/).length : 0,
                        paragraphCount: data.content ? data.content.split('\n\n').length : 0,
                        sentenceCount: data.content ? data.content.split(/[.!?]+/).length - 1 : 0,
                    }
                }],
                analytics: this.initializeAnalytics(),
                quality: this.initializeQuality(),
                settings: this.getDefaultSettings(data.userId),
                flags: {
                    isDeleted: false,
                    isBlocked: false,
                    isFeatured: false,
                    isPremium: data.isPremium || false,
                    needsReview: false
                }
            };

            // Apply template if provided
            if (data.templateId) {
                const template = await this.getTemplateById(data.templateId, { session });
                if (!template) {
                    throw new AppError('Template not found', 404);
                }
                summaryData.templateData = this.applyTemplate(template, data.variables || {});
                summaryData.category = summaryData.category || template.category;
                summaryData.tags = [...new Set([...(summaryData.tags || []), ...(template.tags || [])])];
            }

            // Create summary
            const [summary] = await this.model.create([summaryData], { session });

            // Update user stats
            await this.updateUserStats(data.userId, 'create', session);

            // Update template usage
            if (data.templateId) {
                await this.updateTemplateUsage(data.templateId, session);
            }

            // Index in search service
            await searchService.indexDocument('summaries', {
                id: summary._id,
                title: summary.title,
                content: summary.content,
                category: summary.category,
                tags: summary.tags,
                userId: summary.userId,
                visibility: summary.sharing.visibility
            });

            await session.commitTransaction();

            // Schedule async processing
            this.scheduleAsyncProcessing(summary._id, summary.userId);

            logger.info(`Summary created: ${summary._id} by user ${data.userId}`);
            metricsCollector.increment('summary.created', { userId: data.userId });
            eventEmitter.emit('summary.created', { summaryId: summary._id, userId: data.userId });

            return summary;

        } catch (error) {
            await session.abortTransaction();
            logger.error(`Summary creation failed for user ${data.userId}:`, error);
            metricsCollector.increment('summary.create_failed', { userId: data.userId });
            throw error.name === 'AppError' ? error : new AppError('Failed to create summary', 500);
        } finally {
            session.endSession();
        }
    }

    /**
     * Update summary content (real-time editing)
     */
    async updateContent(summaryId, userId, content, requestingUserId) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const summary = await this.model.findOne({ _id: summaryId, userId }).session(session);
            if (!summary) {
                throw new AppError('Summary not found', 404);
            }

            if (summary.flags.isBlocked) {
                throw new AppError('Summary is locked and cannot be edited', 423);
            }

            if (content !== summary.content) {
                await summary.createVersion(content, summary.title, 'edit', { userId: requestingUserId });
                summary.content = content;
                summary.metadata.wordCount = content.trim().split(/\s+/).length;
                summary.metadata.characterCount = content.length;
                summary.compliance.audit.lastModifiedBy = {
                    userId: requestingUserId,
                    ip: null,
                    userAgent: null,
                    timestamp: new Date()
                };
                await summary.save({ session });

                // Update search index
                await searchService.updateDocument('summaries', summaryId, {
                    title: summary.title,
                    content,
                    category: summary.category,
                    tags: summary.tags
                });

                // Clear cache
                await this.clearSummaryCache(summaryId, userId);

                // Schedule quality update
                this.scheduleQualityUpdate(summaryId);
            }

            await session.commitTransaction();
            logger.info(`Content updated for summary ${summaryId} by user ${requestingUserId}`);
            metricsCollector.increment('summary.content_updated', { userId });
            return summary;

        } catch (error) {
            await session.abortTransaction();
            logger.error(`Content update failed for summary ${summaryId}:`, error);
            metricsCollector.increment('summary.content_update_failed', { userId });
            throw error.name === 'AppError' ? error : new AppError('Failed to update content', 500);
        } finally {
            session.endSession();
        }
    }

    /**
     * Save editor state (cursor position, selection)
     */
    async saveEditorState(summaryId, userId, state) {
        try {
            const summary = await this.model.findOne({ _id: summaryId, userId });
            if (!summary) {
                throw new AppError('Summary not found', 404);
            }

            summary.editorState = {
                ...summary.editorState,
                ...state,
                lastUpdated: new Date()
            };
            await summary.save();

            await this.clearSummaryCache(summaryId, userId);
            logger.info(`Editor state saved for summary ${summaryId}`);
            metricsCollector.increment('summary.editor_state_saved', { userId });
            return summary;

        } catch (error) {
            logger.error(`Editor state save failed for summary ${summaryId}:`, error);
            metricsCollector.increment('summary.editor_state_save_failed', { userId });
            throw error.name === 'AppError' ? error : new AppError('Failed to save editor state', 500);
        }
    }

    /**
     * Apply formatting to summary content
     */
    async applyFormatting(summaryId, userId, { formatType, range, value }) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const summary = await this.model.findOne({ _id: summaryId, userId }).session(session);
            if (!summary) {
                throw new AppError('Summary not found', 404);
            }

            // Apply formatting (e.g., markdown or HTML)
            const formattedContent = this.applyFormatToContent(summary.content, formatType, range, value);
            if (formattedContent !== summary.content) {
                await summary.createVersion(formattedContent, summary.title, 'format', { userId });
                summary.content = formattedContent;
                summary.metadata.wordCount = formattedContent.trim().split(/\s+/).length;
                summary.metadata.characterCount = formattedContent.length;
                await summary.save({ session });

                // Update search index
                await searchService.updateDocument('summaries', summaryId, {
                    title: summary.title,
                    content: formattedContent,
                    category: summary.category,
                    tags: summary.tags
                });

                await this.clearSummaryCache(summaryId, userId);
                this.scheduleQualityUpdate(summaryId);
            }

            await session.commitTransaction();
            logger.info(`Formatting ${formatType} applied to summary ${summaryId}`);
            metricsCollector.increment('summary.formatting_applied', { userId, formatType });
            return summary;

        } catch (error) {
            await session.abortTransaction();
            logger.error(`Formatting failed for summary ${summaryId}:`, error);
            metricsCollector.increment('summary.formatting_failed', { userId });
            throw error.name === 'AppError' ? error : new AppError('Failed to apply formatting', 500);
        } finally {
            session.endSession();
        }
    }

    /**
     * Generate AI suggestions
     */
    async generateSuggestions(summaryId, userId) {
        try {
            const summary = await this.model.findOne({ _id: summaryId, userId });
            if (!summary) {
                throw new AppError('Summary not found', 404);
            }

            const suggestions = await aiService.generateSuggestions({
                content: summary.content,
                title: summary.title,
                category: summary.category,
                industry: summary.metadata.industry,
                experienceLevel: summary.metadata.experienceLevel
            });

            summary.ai.suggestions = suggestions.map((s, index) => ({
                id: generateId('sug'),
                text: s.text,
                type: s.type,
                confidence: s.confidence,
                createdAt: new Date(),
                index
            }));
            summary.ai.lastAnalyzed = new Date();
            await summary.save();

            await this.clearSummaryCache(summaryId, userId);
            logger.info(`Suggestions generated for summary ${summaryId}`);
            metricsCollector.increment('summary.suggestions_generated', { userId });
            return summary.ai.suggestions;

        } catch (error) {
            logger.error(`Suggestions generation failed for summary ${summaryId}:`, error);
            metricsCollector.increment('summary.suggestions_failed', { userId });
            throw error.name === 'AppError' ? error : new AppError('Failed to generate suggestions', 500);
        }
    }

    /**
     * Apply a suggestion to summary
     */
    async applySuggestion(summaryId, userId, suggestionId, content, requestingUserId) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const summary = await this.model.findOne({ _id: summaryId, userId }).session(session);
            if (!summary) {
                throw new AppError('Summary not found', 404);
            }

            const suggestion = summary.ai.suggestions.find(s => s.id === suggestionId);
            if (!suggestion) {
                throw new AppError('Suggestion not found', 404);
            }

            summary.content = content;
            await summary.createVersion(content, summary.title, 'suggestion', { userId: requestingUserId });
            summary.ai.suggestions = summary.ai.suggestions.filter(s => s.id !== suggestionId);
            summary.metadata.wordCount = content.trim().split(/\s+/).length;
            summary.metadata.characterCount = content.length;
            await summary.save({ session });

            // Update search index
            await searchService.updateDocument('summaries', summaryId, {
                title: summary.title,
                content,
                category: summary.category,
                tags: summary.tags
            });

            await this.clearSummaryCache(summaryId, userId);
            this.scheduleQualityUpdate(summaryId);

            await session.commitTransaction();
            logger.info(`Suggestion ${suggestionId} applied to summary ${summaryId}`);
            metricsCollector.increment('summary.suggestion_applied', { userId });
            return summary;

        } catch (error) {
            await session.abortTransaction();
            logger.error(`Suggestion application failed for summary ${summaryId}:`, error);
            metricsCollector.increment('summary.suggestion_apply_failed', { userId });
            throw error.name === 'AppError' ? error : new AppError('Failed to apply suggestion', 500);
        } finally {
            session.endSession();
        }
    }

    /**
     * Process voice input to create or update summary
     */
    async processVoiceInput(summaryId, userId, audioData, language, requestingUserId) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const summary = await this.model.findOne({ _id: summaryId, userId }).session(session);
            if (!summary) {
                throw new AppError('Summary not found', 404);
            }

            const transcribedText = await aiService.transcribeAudio(audioData, language);
            if (!transcribedText) {
                throw new AppError('Failed to transcribe audio', 500);
            }

            summary.content = transcribedText;
            await summary.createVersion(transcribedText, summary.title, 'voice', { userId: requestingUserId });
            summary.metadata.wordCount = transcribedText.trim().split(/\s+/).length;
            summary.metadata.characterCount = transcribedText.length;
            await summary.save({ session });

            // Update search index
            await searchService.updateDocument('summaries', summaryId, {
                title: summary.title,
                content: transcribedText,
                category: summary.category,
                tags: summary.tags
            });

            await this.clearSummaryCache(summaryId, userId);
            this.scheduleQualityUpdate(summaryId);

            await session.commitTransaction();
            logger.info(`Voice input processed for summary ${summaryId}`);
            metricsCollector.increment('summary.voice_processed', { userId, language });
            return summary;

        } catch (error) {
            await session.abortTransaction();
            logger.error(`Voice input processing failed for summary ${summaryId}:`, error);
            metricsCollector.increment('summary.voice_failed', { userId });
            throw error.name === 'AppError' ? error : new AppError('Failed to process voice input', 500);
        } finally {
            session.endSession();
        }
    }

    /**
     * Create summary from voice input
     */
    async createFromVoiceInput(userId, audioData, language, requestingUserId) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const transcribedText = await aiService.transcribeAudio(audioData, language);
            if (!transcribedText) {
                throw new AppError('Failed to transcribe audio', 500);
            }

            const title = transcribedText.substring(0, 50) + (transcribedText.length > 50 ? '...' : '');
            const baseSlug = slugify(title);
            const slug = await this.generateUniqueSlug(baseSlug);

            const summaryData = {
                userId,
                title,
                content: transcribedText,
                slug,
                _id: generateId('sum'),
                metadata: {
                    wordCount: transcribedText.trim().split(/\s+/).length,
                    characterCount: transcribedText.length,
                    createdBy: { userId: requestingUserId },
                },
                versions: [{
                    versionNumber: 1,
                    content: transcribedText,
                    title,
                    changeType: 'create',
                    isActive: true,
                    createdAt: new Date(),
                    stats: {
                        characterCount: transcribedText.length,
                        wordCount: transcribedText.trim().split(/\s+/).length,
                        paragraphCount: transcribedText.split('\n\n').length,
                        sentenceCount: transcribedText.split(/[.!?]+/).length - 1,
                    }
                }],
                analytics: this.initializeAnalytics(),
                quality: this.initializeQuality(),
                settings: this.getDefaultSettings(userId),
                flags: {
                    isDeleted: false,
                    isBlocked: false,
                    isFeatured: false,
                    isPremium: false,
                    needsReview: false
                }
            };

            const [summary] = await this.model.create([summaryData], { session });

            // Index in search service
            await searchService.indexDocument('summaries', {
                id: summary._id,
                title: summary.title,
                content: summary.content,
                category: summary.category,
                tags: summary.tags,
                userId: summary.userId,
                visibility: summary.sharing.visibility
            });

            await this.updateUserStats(userId, 'create', session);
            await session.commitTransaction();

            this.scheduleAsyncProcessing(summary._id, userId);
            logger.info(`Summary created from voice input: ${summary._id}`);
            metricsCollector.increment('summary.created_from_voice', { userId });
            return summary;

        } catch (error) {
            await session.abortTransaction();
            logger.error(`Summary creation from voice failed for user ${userId}:`, error);
            metricsCollector.increment('summary.create_from_voice_failed', { userId });
            throw error.name === 'AppError' ? error : new AppError('Failed to create summary from voice', 500);
        } finally {
            session.endSession();
        }
    }

    /**
     * Update summary with version control
     */
    async updateSummary(summaryId, updates, userId) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const summary = await this.model.findOne({ _id: summaryId, userId }).session(session);
            if (!summary) {
                throw new AppError('Summary not found', 404);
            }

            if (summary.flags.isBlocked) {
                throw new AppError('Summary is locked and cannot be edited', 423);
            }

            // Create new version if content changed
            if (updates.content && updates.content !== summary.content) {
                await summary.createVersion(updates.content, updates.title || summary.title, 'edit', { userId });
                summary.content = updates.content;
                summary.metadata.wordCount = updates.content.trim().split(/\s+/).length;
                summary.metadata.characterCount = updates.content.length;
            }

            // Apply other updates
            const allowedFields = [
                'title', 'category', 'tags', 'status', 'sharing.visibility',
                'settings.autoBackup', 'settings.aiEnhancements', 'templateId'
            ];
            allowedFields.forEach(field => {
                if (updates[field] !== undefined) {
                    if (field.includes('.')) {
                        const [parent, child] = field.split('.');
                        summary[parent][child] = updates[field];
                    } else {
                        summary[field] = updates[field];
                    }
                }
            });

            // Regenerate slug if title changed
            if (updates.title && updates.title !== summary.title) {
                const baseSlug = slugify(updates.title);
                summary.slug = await this.generateUniqueSlug(baseSlug, summaryId);
            }

            // Update audit trail
            summary.compliance.audit.lastModifiedBy = {
                userId,
                ip: null,
                userAgent: null,
                timestamp: new Date()
            };

            await summary.save({ session });

            // Update search index
            if (updates.content || updates.title || updates.category || updates.tags) {
                await searchService.updateDocument('summaries', summaryId, {
                    title: summary.title,
                    content: summary.content,
                    category: summary.category,
                    tags: summary.tags
                });
            }

            await this.updateUserStats(userId, 'update', session);
            await this.clearSummaryCache(summaryId, userId);
            if (updates.content) {
                this.scheduleQualityUpdate(summaryId);
            }

            await session.commitTransaction();
            logger.info(`Summary updated: ${summaryId}`);
            metricsCollector.increment('summary.updated', { userId });
            return summary;

        } catch (error) {
            await session.abortTransaction();
            logger.error(`Summary update failed for ${summaryId}:`, error);
            metricsCollector.increment('summary.update_failed', { userId });
            throw error.name === 'AppError' ? error : new AppError('Failed to update summary', 500);
        } finally {
            session.endSession();
        }
    }

    /**
     * Get summary by ID with caching
     */
    async getSummaryById(summaryId, userId, options = {}) {
        try {
            const cacheKey = `summary:${summaryId}:${userId || 'public'}:${JSON.stringify(options)}`;
            if (!options.skipCache) {
                const cached = await cacheService.get(cacheKey);
                if (cached) {
                    metricsCollector.increment('summary.cache_hit', { userId });
                    return cached;
                }
            }

            const query = this.model.findById(summaryId);
            if (options.includeTemplate) {
                query.populate('templateId', 'name category description');
            }
            if (options.fields) {
                query.select(options.fields);
            }

            const summary = await query.lean();
            if (!summary) {
                throw new AppError('Summary not found', 404);
            }

            // Check access permissions
            if (!options.skipAccessCheck && !this.checkAccess(summary, userId)) {
                throw new AppError('Access denied', 403);
            }

            const processedSummary = this.processSummaryResponse(summary, userId, options);
            if (!options.skipCache) {
                await cacheService.set(cacheKey, processedSummary, this.defaultCacheTTL);
                metricsCollector.increment('summary.cache_miss', { userId });
            }

            logger.info(`Fetched summary ${summaryId} for user ${userId || 'public'}`);
            return processedSummary;

        } catch (error) {
            logger.error(`Failed to get summary ${summaryId}:`, error);
            metricsCollector.increment('summary.get_failed', { userId });
            throw error.name === 'AppError' ? error : new AppError('Failed to fetch summary', 500);
        }
    }

    /**
     * Search summaries with advanced filtering
     */
    async searchSummaries(filters, pagination, userId) {
        try {
            const { page = 1, limit = 20, sortBy = 'recent' } = pagination;
            const skip = (page - 1) * limit;

            const pipeline = this.buildSearchPipeline(filters, sortBy, skip, limit, userId);
            const [results] = await this.model.aggregate([
                ...pipeline,
                {
                    $facet: {
                        data: [{ $skip: skip }, { $limit: limit }],
                        totalCount: [{ $count: 'count' }]
                    }
                }
            ]);

            const summaries = results.data || [];
            const totalCount = results.totalCount[0]?.count || 0;
            const totalPages = Math.ceil(totalCount / limit);

            const processedSummaries = summaries.map(summary =>
                this.processSummaryResponse(summary, userId, { minimal: true })
            );

            logger.info(`Fetched ${summaries.length} summaries for user ${userId}`);
            metricsCollector.increment('summary.search', { userId, count: summaries.length });
            return {
                summaries: processedSummaries,
                pagination: {
                    page,
                    limit,
                    totalCount,
                    totalPages,
                    hasNext: page < totalPages,
                    hasPrev: page > 1
                }
            };

        } catch (error) {
            logger.error(`Summary search failed for user ${userId}:`, error);
            metricsCollector.increment('summary.search_failed', { userId });
            throw new AppError('Failed to search summaries', 500);
        }
    }

    /**
     * Get user statistics
     */
    async getUserStats(userId, timeframe = '30d') {
        try {
            const cacheKey = `user_stats:${userId}:${timeframe}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('user_stats.cache_hit', { userId });
                return cached;
            }

            const endDate = new Date();
            const startDate = new Date();
            switch (timeframe) {
                case '7d': startDate.setDate(endDate.getDate() - 7); break;
                case '30d': startDate.setDate(endDate.getDate() - 30); break;
                case '90d': startDate.setDate(endDate.getDate() - 90); break;
                case '1y': startDate.setFullYear(endDate.getFullYear() - 1); break;
                default: startDate.setDate(endDate.getDate() - 30);
            }

            const pipeline = [
                {
                    $match: {
                        userId,
                        'flags.isDeleted': false,
                        createdAt: { $gte: startDate, $lte: endDate }
                    }
                },
                {
                    $group: {
                        _id: null,
                        totalSummaries: { $sum: 1 },
                        totalViews: { $sum: '$analytics.views.total' },
                        totalWords: { $sum: '$metadata.wordCount' },
                        avgQuality: { $avg: '$quality.overallScore' },
                        categories: { $addToSet: '$category' },
                        statuses: {
                            $push: {
                                status: '$status',
                                count: 1
                            }
                        }
                    }
                },
                {
                    $project: {
                        _id: 0,
                        totalSummaries: 1,
                        totalViews: 1,
                        totalWords: 1,
                        avgQuality: { $round: ['$avgQuality', 2] },
                        uniqueCategories: { $size: '$categories' },
                        statusBreakdown: '$statuses'
                    }
                }
            ];

            const [stats] = await this.model.aggregate(pipeline);
            const result = stats || {
                totalSummaries: 0,
                totalViews: 0,
                totalWords: 0,
                avgQuality: 0,
                uniqueCategories: 0,
                statusBreakdown: []
            };

            await cacheService.set(cacheKey, result, 3600);
            logger.info(`Fetched user stats for ${userId}`);
            metricsCollector.increment('user_stats.fetched', { userId });
            return result;

        } catch (error) {
            logger.error(`Failed to get user stats for ${userId}:`, error);
            metricsCollector.increment('user_stats.fetch_failed', { userId });
            throw new AppError('Failed to fetch user stats', 500);
        }
    }

    /**
     * Duplicate summary
     */
    async duplicateSummary(summaryId, userId, options = {}) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const original = await this.model.findOne({ _id: summaryId, userId }).session(session);
            if (!original) {
                throw new AppError('Summary not found', 404);
            }

            const duplicateData = original.toObject();
            delete duplicateData._id;
            delete duplicateData.createdAt;
            delete duplicateData.updatedAt;
            delete duplicateData.analytics;
            delete duplicateData.sharing.collaborators;

            duplicateData._id = generateId('sum');
            duplicateData.title = options.title || `${original.title} (Copy)`;
            duplicateData.slug = await this.generateUniqueSlug(slugify(duplicateData.title));
            duplicateData.status = 'draft';
            duplicateData.analytics = this.initializeAnalytics();
            duplicateData.compliance.audit.createdBy = { userId, timestamp: new Date() };

            if (!options.includeVersions) {
                duplicateData.versions = [{
                    versionNumber: 1,
                    content: duplicateData.content,
                    title: duplicateData.title,
                    changeType: 'create',
                    isActive: true,
                    createdAt: new Date(),
                    stats: {
                        characterCount: duplicateData.content.length,
                        wordCount: duplicateData.content.trim().split(/\s+/).length,
                        paragraphCount: duplicateData.content.split('\n\n').length,
                        sentenceCount: duplicateData.content.split(/[.!?]+/).length - 1,
                    }
                }];
            }

            const [duplicate] = await this.model.create([duplicateData], { session });
            await searchService.indexDocument('summaries', {
                id: duplicate._id,
                title: duplicate.title,
                content: duplicate.content,
                category: duplicate.category,
                tags: duplicate.tags,
                userId: duplicate.userId,
                visibility: duplicate.sharing.visibility
            });

            await this.updateUserStats(userId, 'duplicate', session);
            await session.commitTransaction();

            await this.clearSummaryCache(duplicate._id, userId);
            this.scheduleAsyncProcessing(duplicate._id, userId);

            logger.info(`Summary duplicated: ${summaryId} -> ${duplicate._id}`);
            metricsCollector.increment('summary.duplicated', { userId });
            return duplicate;

        } catch (error) {
            await session.abortTransaction();
            logger.error(`Summary duplication failed for ${summaryId}:`, error);
            metricsCollector.increment('summary.duplicate_failed', { userId });
            throw error.name === 'AppError' ? error : new AppError('Failed to duplicate summary', 500);
        } finally {
            session.endSession();
        }
    }

    /**
     * Bulk update summaries
     */
    async bulkUpdate(summaryIds, updates, userId) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const query = {
                _id: { $in: summaryIds },
                userId,
                'flags.isDeleted': false
            };

            const summaries = await this.model.find(query).session(session);
            if (summaries.length === 0) {
                throw new AppError('No summaries found', 404);
            }

            const updateData = {
                ...updates,
                updatedAt: new Date(),
                'compliance.audit.lastModifiedBy': { userId, timestamp: new Date() }
            };

            const result = await this.model.updateMany(query, updateData).session(session);
            await Promise.all(summaries.map(summary =>
                searchService.updateDocument('summaries', summary._id, {
                    title: summary.title,
                    content: summary.content,
                    category: updates.category || summary.category,
                    tags: updates.tags ? [...new Set([...summary.tags, ...updates.tags])] : summary.tags
                })
            ));

            await this.updateUserStats(userId, 'bulk_update', session);
            await Promise.all(summaryIds.map(id => this.clearSummaryCache(id, userId)));

            await session.commitTransaction();
            logger.info(`Bulk update completed: ${result.modifiedCount}/${summaryIds.length} summaries`);
            metricsCollector.increment('summary.bulk_updated', { userId, count: result.modifiedCount });
            return {
                requested: summaryIds.length,
                matched: result.matchedCount,
                modified: result.modifiedCount
            };

        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk update failed for user ${userId}:`, error);
            metricsCollector.increment('summary.bulk_update_failed', { userId });
            throw error.name === 'AppError' ? error : new AppError('Failed to perform bulk update', 500);
        } finally {
            session.endSession();
        }
    }

    /**
     * Delete summary (soft or hard)
     */
    async deleteSummary(summaryId, userId, permanent = false) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const summary = await this.model.findOne({ _id: summaryId, userId }).session(session);
            if (!summary) {
                throw new AppError('Summary not found', 404);
            }

            if (permanent) {
                await this.model.findByIdAndDelete(summaryId).session(session);
                await searchService.deleteDocument('summaries', summaryId);
            } else {
                summary.flags.isDeleted = true;
                summary.status = 'deleted';
                summary.deletedAt = new Date();
                summary.compliance.audit.lastModifiedBy = { userId, timestamp: new Date() };
                await summary.save({ session });
                await searchService.updateDocument('summaries', summaryId, { status: 'deleted' });
            }

            await this.updateUserStats(userId, permanent ? 'permanent_delete' : 'soft_delete', session);
            await this.clearSummaryCache(summaryId, userId);

            await session.commitTransaction();
            logger.info(`Summary ${permanent ? 'permanently' : 'soft'} deleted: ${summaryId}`);
            metricsCollector.increment(`summary.${permanent ? 'permanently_deleted' : 'soft_deleted'}`, { userId });
            return { deleted: true, permanent };

        } catch (error) {
            await session.abortTransaction();
            logger.error(`Summary deletion failed for ${summaryId}:`, error);
            metricsCollector.increment('summary.delete_failed', { userId });
            throw error.name === 'AppError' ? error : new AppError('Failed to delete summary', 500);
        } finally {
            session.endSession();
        }
    }

    /**
     * Get trending summaries
     */
    async getTrendingSummaries(limit = 10, timeframe = '7d') {
        try {
            const cacheKey = `trending_summaries:${limit}:${timeframe}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('trending_summaries.cache_hit');
                return cached;
            }

            const endDate = new Date();
            const startDate = new Date();
            switch (timeframe) {
                case '7d': startDate.setDate(endDate.getDate() - 7); break;
                case '30d': startDate.setDate(endDate.getDate() - 30); break;
                case '90d': startDate.setDate(endDate.getDate() - 90); break;
                default: startDate.setDate(endDate.getDate() - 7);
            }

            const pipeline = [
                {
                    $match: {
                        'sharing.visibility': 'public',
                        'flags.isDeleted': false,
                        status: 'active',
                        updatedAt: { $gte: startDate }
                    }
                },
                {
                    $addFields: {
                        trendingScore: {
                            $add: [
                                { $multiply: ['$analytics.views.total', 1] },
                                { $multiply: ['$analytics.interactions.likes', 5] },
                                { $multiply: ['$analytics.interactions.shares', 10] },
                                { $multiply: ['$analytics.interactions.comments', 3] },
                                { $multiply: ['$quality.overallScore', 0.1] }
                            ]
                        }
                    }
                },
                { $sort: { trendingScore: -1 } },
                { $limit: limit },
                {
                    $project: {
                        title: 1,
                        slug: 1,
                        category: 1,
                        'metadata.industry': 1,
                        'metadata.experienceLevel': 1,
                        'quality.overallScore': 1,
                        'analytics.views.total': 1,
                        'analytics.interactions': 1,
                        trendingScore: 1,
                        createdAt: 1,
                        updatedAt: 1
                    }
                }
            ];

            const trending = await this.model.aggregate(pipeline);
            await cacheService.set(cacheKey, trending, 3600);
            logger.info(`Fetched ${trending.length} trending summaries`);
            metricsCollector.increment('trending_summaries.fetched', { count: trending.length });
            return trending;

        } catch (error) {
            logger.error('Failed to get trending summaries:', error);
            metricsCollector.increment('trending_summaries.failed');
            throw new AppError('Failed to fetch trending summaries', 500);
        }
    }

    /**
     * Schedule async processing (grammar, suggestions, quality)
     */
    async scheduleAsyncProcessing(summaryId, userId) {
        try {
            // Use a queue system or setTimeout for async processing
            setImmediate(async () => {
                try {
                    const summary = await this.model.findById(summaryId);
                    if (!summary) {
                        logger.warn(`Summary ${summaryId} not found for async processing`);
                        return;
                    }

                    // Run grammar check
                    const grammarResult = await this.grammarService.checkGrammar(summary.content);
                    summary.ai.grammar = grammarResult;
                    summary.quality.grammarScore = grammarResult.score;

                    // Generate AI suggestions
                    const suggestions = await this.generateSuggestions(summaryId, userId);
                    summary.ai.suggestions = suggestions;

                    // Update quality scores
                    await this.updateQualityScores(summaryId);

                    await summary.save();
                    await this.clearSummaryCache(summaryId, userId);

                    // Notify user of processing completion
                    await notificationService.notify({
                        userId,
                        type: 'summary_processed',
                        message: `Summary ${summary.title} processing completed`,
                        data: { summaryId }
                    });

                    logger.info(`Async processing completed for summary ${summaryId}`);
                    metricsCollector.increment('summary.async_processed', { userId });
                } catch (error) {
                    logger.error(`Async processing failed for summary ${summaryId}:`, error);
                    metricsCollector.increment('summary.async_process_failed', { userId });
                }
            });
        } catch (error) {
            logger.error(`Failed to schedule async processing for summary ${summaryId}:`, error);
        }
    }

    /**
     * Calculate and update quality scores
     */
    async updateQualityScores(summaryId) {
        try {
            const summary = await this.model.findById(summaryId);
            if (!summary) {
                return;
            }

            const qualityScores = await this.calculateQualityScores(summary);
            summary.quality = {
                ...qualityScores,
                lastAnalyzed: new Date()
            };
            await summary.save();

            await this.clearSummaryCache(summaryId, summary.userId);
            logger.info(`Quality scores updated for summary ${summaryId}`);
            metricsCollector.increment('summary.quality_updated', { userId: summary.userId });
            return qualityScores;

        } catch (error) {
            logger.error(`Quality score update failed for ${summaryId}:`, error);
            metricsCollector.increment('summary.quality_update_failed', { userId: summary.userId });
        }
    }

    /**
     * Schedule quality update
     */
    async scheduleQualityUpdate(summaryId) {
        setImmediate(async () => {
            try {
                await this.updateQualityScores(summaryId);
            } catch (error) {
                logger.error(`Scheduled quality update failed for ${summaryId}:`, error);
            }
        });
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
            views: { total: 0, unique: 0, today: 0, thisWeek: 0, thisMonth: 0 },
            interactions: { likes: 0, shares: 0, comments: 0, bookmarks: 0 },
            performance: { averageReadTime: 0, bounceRate: 0, completionRate: 0, engagementRate: 0 },
            timeline: [],
            lastCalculated: new Date()
        };
    }

    initializeQuality() {
        return {
            overallScore: 0,
            scores: { grammar: 0, readability: 0, engagement: 0, seo: 0, uniqueness: 0 },
            issues: [],
            lastAnalyzed: new Date()
        };
    }

    getDefaultSettings(userId) {
        return {
            autoSave: true,
            autoBackup: true,
            versionControl: true,
            maxVersions: 20,
            notifications: { email: true, push: false, sms: false },
            privacy: { showInSearch: false, allowIndexing: false, requirePassword: false }
        };
    }

    async getTemplateById(templateId, options = {}) {
        try {
            const cacheKey = `template:${templateId}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                return cached;
            }

            const query = this.templateModel.findById(templateId);
            if (options.session) {
                query.session(options.session);
            }
            const template = await query.lean();
            if (template) {
                await cacheService.set(cacheKey, template, 1800);
            }
            return template;

        } catch (error) {
            logger.error(`Failed to get template ${templateId}:`, error);
            return null;
        }
    }

    applyTemplate(template, variables) {
        let content = template.content;
        let title = template.title;

        Object.keys(variables).forEach(key => {
            const placeholder = new RegExp(`\\{\\{${key}\\}\\}`, 'g');
            content = content.replace(placeholder, variables[key] || '');
            title = title.replace(placeholder, variables[key] || '');
        });

        return {
            originalTemplate: template._id,
            processedContent: content,
            processedTitle: title,
            variables,
            appliedAt: new Date()
        };
    }

    async updateUserStats(userId, action, session) {
        try {
            metricsCollector.increment(`user.${action}`, { userId });
            // Placeholder for updating user stats collection if needed
        } catch (error) {
            logger.error(`Failed to update user stats for ${userId}:`, error);
        }
    }

    async updateTemplateUsage(templateId, session) {
        try {
            await this.templateModel.findByIdAndUpdate(templateId, {
                $inc: { 'analytics.usage.totalUses': 1 }
            }).session(session);
        } catch (error) {
            logger.error(`Failed to update template usage for ${templateId}:`, error);
        }
    }

    checkAccess(summary, userId) {
        if (summary.sharing?.visibility === 'public') return true;
        if (summary.userId === userId) return true;
        if (summary.sharing?.collaborators?.some(c => c.userId === userId && c.status === 'accepted')) return true;
        return false;
    }

    processSummaryResponse(summary, userId, options = {}) {
        const processed = { ...summary };
        processed.wordCount = summary.content ? summary.content.trim().split(/\s+/).length : 0;
        processed.readingTime = Math.ceil(processed.wordCount / 200);
        processed.url = `/summary/${summary.slug || summary._id}`;
        processed.isOwner = summary.userId === userId;

        if (summary.userId !== userId && !options.includePrivate) {
            delete processed.compliance;
            delete processed.ai?.feedback;
            delete processed.sharing?.collaborators;
            if (!options.includeVersions) {
                delete processed.versions;
            }
        }

        if (options.minimal) {
            const minimalFields = [
                '_id', 'title', 'slug', 'category', 'status', 'tags',
                'quality', 'analytics', 'createdAt', 'updatedAt',
                'wordCount', 'readingTime', 'url', 'isOwner'
            ];
            const minimal = {};
            minimalFields.forEach(field => {
                if (processed[field] !== undefined) {
                    minimal[field] = processed[field];
                }
            });
            return minimal;
        }

        return processed;
    }

    buildSearchPipeline(filters, sortBy, skip, limit, userId) {
        const pipeline = [];
        const matchStage = { 'flags.isDeleted': false };

        if (filters.userId) {
            matchStage.userId = filters.userId;
        } else if (!filters.includePrivate) {
            matchStage['sharing.visibility'] = 'public';
            matchStage.status = 'active';
        }

        if (filters.status && filters.status !== 'all') {
            matchStage.status = filters.status;
        }

        if (filters.category && filters.category !== 'all') {
            matchStage.category = filters.category;
        }

        if (filters.startDate || filters.endDate) {
            matchStage.createdAt = {};
            if (filters.startDate) matchStage.createdAt.$gte = new Date(filters.startDate);
            if (filters.endDate) matchStage.createdAt.$lte = new Date(filters.endDate);
        }

        if (filters.search) {
            matchStage.$text = { $search: filters.search };
        }

        if (filters.tags && filters.tags.length > 0) {
            matchStage.tags = { $in: filters.tags };
        }

        pipeline.push({ $match: matchStage });

        if (filters.search) {
            pipeline.push({
                $addFields: { textScore: { $meta: 'textScore' } }
            });
        }

        const sortOptions = {
            recent: { updatedAt: -1 },
            oldest: { createdAt: 1 },
            popular: { 'analytics.views.total': -1 },
            quality: { 'quality.overallScore': -1 },
            title: { title: 1 },
            relevance: filters.search ? { textScore: { $meta: 'textScore' } } : { updatedAt: -1 }
        };

        pipeline.push({ $sort: sortOptions[sortBy] || sortOptions.recent });
        return pipeline;
    }

    async clearSummaryCache(summaryId, userId) {
        try {
            const patterns = [
                `summary:${summaryId}:*`,
                `summaries:${userId}:*`,
                `user_stats:${userId}:*`,
                'trending_summaries:*'
            ];
            await Promise.all(patterns.map(pattern => cacheService.deletePattern(pattern)));
        } catch (error) {
            logger.error(`Cache clearing failed for summary ${summaryId}:`, error);
        }
    }

    applyFormatToContent(content, formatType, range, value) {
        // Placeholder for formatting logic
        // Implement based on specific formatting requirements (e.g., markdown)
        let formattedContent = content;
        switch (formatType) {
            case 'bold':
                formattedContent = `${content.slice(0, range.start)}**${content.slice(range.start, range.end)}**${content.slice(range.end)}`;
                break;
            case 'italic':
                formattedContent = `${content.slice(0, range.start)}*${content.slice(range.start, range.end)}*${content.slice(range.end)}`;
                break;
            case 'underline':
                formattedContent = `${content.slice(0, range.start)}<u>${content.slice(range.start, range.end)}</u>${content.slice(range.end)}`;
                break;
            case 'list':
                formattedContent = `${content.slice(0, range.start)}- ${content.slice(range.start, range.end)}\n${content.slice(range.end)}`;
                break;
            case 'heading':
                formattedContent = `${content.slice(0, range.start)}# ${content.slice(range.start, range.end)}\n${content.slice(range.end)}`;
                break;
            case 'link':
                formattedContent = `${content.slice(0, range.start)}[${content.slice(range.start, range.end)}](${value})${content.slice(range.end)}`;
                break;
        }
        return formattedContent;
    }

    async calculateQualityScores(summary) {
        try {
            const grammarResult = await this.grammarService.checkGrammar(summary.content);
            const readability = await aiService.calculateReadability(summary.content);
            const engagement = await aiService.calculateEngagement(summary.content);
            const seo = await aiService.calculateSEO(summary.content);
            const uniqueness = await aiService.calculateUniqueness(summary.content);

            return {
                overallScore: (grammarResult.score * 0.3 + readability * 0.2 + engagement * 0.2 + seo * 0.2 + uniqueness * 0.1).toFixed(2),
                scores: {
                    grammar: grammarResult.score,
                    readability,
                    engagement,
                    seo,
                    uniqueness
                },
                issues: grammarResult.issues || [],
                lastAnalyzed: new Date()
            };
        } catch (error) {
            logger.error(`Quality score calculation failed for summary ${summary._id}:`, error);
            return this.initializeQuality();
        }
    }
}

export default new SummaryService();