import Summary from '../models/summary.model.js';
import { AppError } from '../errors/app.error.js';
import { eventEmitter } from '../events/events.js';
import SummaryService from '../services/summary.service.js';
import GrammarService from '../services/grammar.service.js';
import TemplateService from '../services/template.service.js';
import BackupService from '../services/backup.service.js';
import { ApiResponse } from '../services/apiresponse.service.js';
import { cacheService } from '../services/redis.service.js';
import { catchAsync } from '../handler/catchAsync.js';
import { logger } from '../utils/logger.js';
import { createRateLimiter } from '../utils/rateLimiter.js';
import { metricsCollector } from '../utils/metrics.js';
import { validateSummary, sanitizeInput } from '../validations/summary.validation.js';

// Rate limiters for different operations
const createSummaryLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // 10 creates per 15 minutes for free users
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_summary_${req.user.id}`,
});

const updateSummaryLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 20, // 20 updates per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_summary_${req.user.id}`,
});

const bulkOperationsLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5, // 5 bulk operations per hour
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_operations_${req.user.id}`,
});

class SummaryController {
    constructor() {
        this.summaryService = SummaryService;
        this.grammarService = GrammarService;
        this.templateService = TemplateService;
        this.backupService = BackupService;
    }

    /**
     * Create a new summary
     * POST /api/v1/summary/:userId
     */
    createSummary = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const summaryData = req.body;
        const requestingUserId = req.user.id;

        // Validate access permissions
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied: Cannot create summary for another user', 403));
        }

        // Apply rate limiting
        await createSummaryLimiter(req, res, () => { });

        // Validate input data
        const validation = validateSummary(summaryData);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        // Sanitize input
        const sanitizedData = sanitizeInput(summaryData);

        // Check user limits
        const userSummaryCount = await Summary.countDocuments({
            userId,
            'flags.isDeleted': false
        }).cache({ ttl: 300, key: `user_summary_count_${userId}` });

        const limits = this.getUserLimits(req.user.accountType);
        if (userSummaryCount >= limits.maxSummaries) {
            return next(new AppError(`Summary limit reached (${limits.maxSummaries})`, 403));
        }

        try {
            // Create summary with service
            const summary = await this.summaryService.createSummary({
                ...sanitizedData,
                userId,
                metadata: {
                    ...sanitizedData.metadata,
                    createdBy: {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        location: req.geoip,
                    }
                }
            });

            // Start async processing
            this.processNewSummaryAsync(summary._id, requestingUserId)
                .catch(err => logger.error(`Async processing failed for summary ${summary._id}:`, err));

            // Log metrics
            metricsCollector.increment('summary.created', {
                userId,
                category: summary.category,
                templateUsed: !!summary.templateId
            });

            // Emit event
            eventEmitter.emit('summary.created', {
                summaryId: summary._id,
                userId,
                templateId: summary.templateId
            });

            // Create backup if enabled
            if (summary.settings.autoBackup) {
                this.backupService.createBackup(summary._id, 'create', requestingUserId)
                    .catch(err => logger.error(`Auto backup failed for summary ${summary._id}:`, err));
            }

            const responseTime = Date.now() - startTime;
            logger.info(`Summary created successfully: ${summary._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Summary created successfully',
                data: {
                    id: summary._id,
                    userId: summary.userId,
                    title: summary.title,
                    status: summary.status,
                    slug: summary.slug,
                    createdAt: summary.createdAt,
                    processingStatus: 'started'
                }
            }, 201);

        } catch (error) {
            logger.error(`Summary creation failed for user ${userId}:`, error);
            metricsCollector.increment('summary.create_failed', { userId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.code === 11000) {
                return next(new AppError('Summary with this title already exists', 409));
            }

            return next(new AppError('Failed to create summary', 500));
        }
    });

    /**
     * Get user's summaries with filtering and pagination
     * GET /api/v1/summary/:userId
     */
    getSummaries = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;

        // Validate access permissions
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const {
            page = 1,
            limit = 20,
            status,
            category,
            search,
            sortBy = 'recent',
            templateId,
            tags,
            startDate,
            endDate,
            includeAnalytics = 'false'
        } = req.query;

        // Build query
        const query = this.buildSummaryQuery({
            userId,
            status,
            category,
            search,
            templateId,
            tags,
            startDate,
            endDate
        });

        // Build sort option
        const sortOption = this.buildSortOption(sortBy);

        // Pagination
        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit))); // Max 100 items per page
        const skip = (pageNum - 1) * limitNum;

        // Cache key
        const cacheKey = `summaries:${userId}:${JSON.stringify({
            page: pageNum, limit: limitNum, status, category, search, sortBy, templateId, tags, startDate, endDate
        })}`;

        try {
            // Try cache first
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('summary.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            // Query database
            const [summaries, totalCount] = await Promise.all([
                Summary.find(query)
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select(this.getSelectFields(includeAnalytics === 'true'))
                    .populate('templateId', 'name category')
                    .lean(),
                Summary.countDocuments(query)
            ]);

            // Process summaries data
            const processedSummaries = await Promise.all(
                summaries.map(summary => this.processSummaryData(summary, includeAnalytics === 'true'))
            );

            const totalPages = Math.ceil(totalCount / limitNum);
            const hasNext = pageNum < totalPages;
            const hasPrev = pageNum > 1;

            const result = {
                summaries: processedSummaries,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages,
                    hasNext,
                    hasPrev,
                    nextPage: hasNext ? pageNum + 1 : null,
                    prevPage: hasPrev ? pageNum - 1 : null
                },
                filters: {
                    status: status || 'all',
                    category: category || 'all',
                    sortBy,
                    search: search || null
                }
            };

            // Cache result
            await cacheService.set(cacheKey, result, 300); // 5 minutes

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('summary.fetched', {
                userId,
                count: summaries.length,
                cached: false
            });
            logger.info(`Fetched ${summaries.length} summaries for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, result);

        } catch (error) {
            logger.error(`Failed to fetch summaries for user ${userId}:`, error);
            metricsCollector.increment('summary.fetch_failed', { userId });
            return next(new AppError('Failed to fetch summaries', 500));
        }
    });

    /**
     * Get single summary by ID
     * GET /api/v1/summary/:userId/:summaryId
     */
    getSummaryById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, summaryId } = req.params;
        const requestingUserId = req.user.id;
        const { includeVersions = 'false', includeAnalytics = 'false' } = req.query;

        try {
            const summary = await Summary.findOne({
                _id: summaryId,
                userId
            })
                .populate('templateId', 'name category description')
                .cache({ ttl: 600, key: `summary:${summaryId}:${userId}` });

            if (!summary) {
                return next(new AppError('Summary not found', 404));
            }

            // Check access permissions
            const hasAccess = this.checkSummaryAccess(summary, requestingUserId, req.user.isAdmin);
            if (!hasAccess) {
                return next(new AppError('Access denied', 403));
            }

            // Increment view count (async)
            if (requestingUserId !== userId) {
                summary.incrementViews(true).catch(err =>
                    logger.error(`View increment failed for summary ${summaryId}:`, err)
                );
            }

            // Process response data
            const responseData = {
                ...summary.toObject(),
                currentVersion: summary.currentVersion,
                wordCount: summary.wordCount,
                readingTime: summary.readingTime,
                url: summary.url
            };

            // Add versions if requested
            if (includeVersions === 'true' && summary.userId === requestingUserId) {
                responseData.versions = summary.versions;
            } else {
                delete responseData.versions;
            }

            // Add analytics if requested and authorized
            if (includeAnalytics === 'true' && summary.userId === requestingUserId) {
                responseData.analytics = summary.analytics;
            } else {
                delete responseData.analytics;
            }

            // Remove sensitive data for non-owners
            if (summary.userId !== requestingUserId) {
                delete responseData.compliance;
                delete responseData.ai.feedback;
                delete responseData.sharing.collaborators;
            }

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('summary.viewed', {
                userId: summary.userId,
                viewerId: requestingUserId,
                isOwner: summary.userId === requestingUserId
            });
            logger.info(`Fetched summary ${summaryId} for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                data: responseData
            });

        } catch (error) {
            logger.error(`Failed to fetch summary ${summaryId}:`, error);
            metricsCollector.increment('summary.view_failed', { userId });
            return next(new AppError('Failed to fetch summary', 500));
        }
    });

    /**
     * Update summary
     * PUT /api/v1/summary/:userId/:summaryId
     */
    updateSummary = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, summaryId } = req.params;
        const requestingUserId = req.user.id;
        const updates = req.body;

        // Apply rate limiting
        await updateSummaryLimiter(req, res, () => { });

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        try {
            const summary = await Summary.findOne({ _id: summaryId, userId });

            if (!summary) {
                return next(new AppError('Summary not found', 404));
            }

            // Check if summary is locked
            if (summary.flags.isBlocked) {
                return next(new AppError('Summary is locked and cannot be edited', 423));
            }

            // Validate updates
            const allowedUpdates = this.getAllowedUpdateFields();
            const sanitizedUpdates = this.sanitizeUpdates(updates, allowedUpdates);

            if (Object.keys(sanitizedUpdates).length === 0) {
                return next(new AppError('No valid update fields provided', 400));
            }

            // Create version if content changed
            let versionCreated = false;
            if (sanitizedUpdates.content && sanitizedUpdates.content !== summary.content) {
                await summary.createVersion(
                    sanitizedUpdates.content,
                    sanitizedUpdates.title || summary.title,
                    'edit',
                    { userId: requestingUserId }
                );
                versionCreated = true;
            }

            // Update summary
            Object.assign(summary, sanitizedUpdates);

            // Update metadata
            summary.compliance.audit.lastModifiedBy = {
                userId: requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date()
            };

            await summary.save();

            // Recalculate quality scores if content changed
            if (sanitizedUpdates.content) {
                await summary.calculateQualityScore();
            }

            // Create backup if enabled
            if (summary.settings.autoBackup) {
                this.backupService.createBackup(summary._id, 'update', requestingUserId)
                    .catch(err => logger.error(`Auto backup failed for summary ${summary._id}:`, err));
            }

            // Clear cache
            await cacheService.deletePattern(`summary:${summaryId}:*`);
            await cacheService.deletePattern(`summaries:${userId}:*`);

            // Log metrics
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('summary.updated', {
                userId,
                versionCreated,
                fieldsUpdated: Object.keys(sanitizedUpdates).length
            });

            // Emit event
            eventEmitter.emit('summary.updated', {
                summaryId: summary._id,
                userId,
                changes: Object.keys(sanitizedUpdates),
                versionCreated
            });

            logger.info(`Summary updated successfully: ${summary._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Summary updated successfully',
                data: {
                    id: summary._id,
                    title: summary.title,
                    status: summary.status,
                    updatedAt: summary.updatedAt,
                    versionCreated,
                    currentVersion: summary.currentVersion?.versionNumber
                }
            });

        } catch (error) {
            logger.error(`Summary update failed for ${summaryId}:`, error);
            metricsCollector.increment('summary.update_failed', { userId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }

            return next(new AppError('Failed to update summary', 500));
        }
    });

    /**
     * Delete summary (soft delete)
     * DELETE /api/v1/summary/:userId/:summaryId
     */
    deleteSummary = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, summaryId } = req.params;
        const requestingUserId = req.user.id;
        const { permanent = 'false' } = req.query;

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        try {
            const summary = await Summary.findOne({ _id: summaryId, userId });

            if (!summary) {
                return next(new AppError('Summary not found', 404));
            }

            if (permanent === 'true') {
                // Permanent deletion
                await Summary.findByIdAndDelete(summary._id);

                // Delete all backups
                this.backupService.deleteAllBackups(summaryId)
                    .catch(err => logger.error(`Failed to delete backups for ${summaryId}:`, err));

                metricsCollector.increment('summary.permanently_deleted', { userId });

                return ApiResponse.success(res, {
                    message: 'Summary permanently deleted'
                });
            } else {
                // Soft delete
                summary.flags.isDeleted = true;
                summary.status = 'deleted';
                summary.compliance.audit.lastModifiedBy = {
                    userId: requestingUserId,
                    ip: req.ip,
                    userAgent: req.get('User-Agent'),
                    timestamp: new Date()
                };

                await summary.save();

                metricsCollector.increment('summary.soft_deleted', { userId });
            }

            // Clear cache
            await cacheService.deletePattern(`summary:${summaryId}:*`);
            await cacheService.deletePattern(`summaries:${userId}:*`);

            // Emit event
            eventEmitter.emit('summary.deleted', {
                summaryId: summary._id,
                userId,
                permanent: permanent === 'true'
            });

            const responseTime = Date.now() - startTime;
            logger.info(`Summary ${summaryId} deleted (permanent: ${permanent}) in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Summary moved to trash'
            });

        } catch (error) {
            logger.error(`Summary deletion failed for ${summaryId}:`, error);
            metricsCollector.increment('summary.delete_failed', { userId });
            return next(new AppError('Failed to delete summary', 500));
        }
    });

    /**
     * Bulk operations on summaries
     * POST /api/v1/summary/:userId/bulk
     */
    bulkOperations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { operation, summaryIds, data = {} } = req.body;

        // Apply rate limiting
        await bulkOperationsLimiter(req, res, () => { });

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        // Validate input
        if (!Array.isArray(summaryIds) || summaryIds.length === 0) {
            return next(new AppError('Summary IDs array is required', 400));
        }

        if (summaryIds.length > 100) {
            return next(new AppError('Maximum 100 summaries can be processed at once', 400));
        }

        const allowedOperations = ['delete', 'archive', 'publish', 'updateCategory', 'updateTags', 'updateVisibility'];
        if (!allowedOperations.includes(operation)) {
            return next(new AppError('Invalid operation', 400));
        }

        try {
            const query = { _id: { $in: summaryIds }, userId };
            let updateData = {};
            let message = '';

            switch (operation) {
                case 'delete':
                    updateData = {
                        'flags.isDeleted': true,
                        status: 'deleted',
                        updatedAt: new Date(),
                        'compliance.audit.lastModifiedBy': {
                            userId: requestingUserId,
                            ip: req.ip,
                            userAgent: req.get('User-Agent'),
                            timestamp: new Date()
                        }
                    };
                    message = 'Summaries moved to trash';
                    break;

                case 'archive':
                    updateData = {
                        status: 'archived',
                        updatedAt: new Date(),
                        'compliance.audit.lastModifiedBy': {
                            userId: requestingUserId,
                            ip: req.ip,
                            userAgent: req.get('User-Agent'),
                            timestamp: new Date()
                        }
                    };
                    message = 'Summaries archived';
                    break;

                case 'publish':
                    updateData = {
                        status: 'active',
                        'sharing.visibility': 'public',
                        updatedAt: new Date(),
                        'compliance.audit.lastModifiedBy': {
                            userId: requestingUserId,
                            ip: req.ip,
                            userAgent: req.get('User-Agent'),
                            timestamp: new Date()
                        }
                    };
                    message = 'Summaries published';
                    break;

                case 'updateCategory':
                    if (!data.category) {
                        return next(new AppError('Category is required', 400));
                    }
                    updateData = {
                        category: data.category,
                        updatedAt: new Date(),
                        'compliance.audit.lastModifiedBy': {
                            userId: requestingUserId,
                            ip: req.ip,
                            userAgent: req.get('User-Agent'),
                            timestamp: new Date()
                        }
                    };
                    message = `Category updated to ${data.category}`;
                    break;

                case 'updateTags':
                    if (!Array.isArray(data.tags)) {
                        return next(new AppError('Tags array is required', 400));
                    }
                    updateData = {
                        $addToSet: {
                            tags: { $each: data.tags.map(tag => tag.trim().toLowerCase()).slice(0, 10) }
                        },
                        updatedAt: new Date(),
                        'compliance.audit.lastModifiedBy': {
                            userId: requestingUserId,
                            ip: req.ip,
                            userAgent: req.get('User-Agent'),
                            timestamp: new Date()
                        }
                    };
                    message = 'Tags updated';
                    break;

                case 'updateVisibility':
                    if (!data.visibility) {
                        return next(new AppError('Visibility is required', 400));
                    }
                    updateData = {
                        'sharing.visibility': data.visibility,
                        updatedAt: new Date(),
                        'compliance.audit.lastModifiedBy': {
                            userId: requestingUserId,
                            ip: req.ip,
                            userAgent: req.get('User-Agent'),
                            timestamp: new Date()
                        }
                    };
                    message = `Visibility updated to ${data.visibility}`;
                    break;
            }

            const result = await Summary.updateMany(query, updateData);

            // Clear cache for affected summaries
            await Promise.all([
                cacheService.deletePattern(`summaries:${userId}:*`),
                ...summaryIds.map(id => cacheService.deletePattern(`summary:${id}:*`))
            ]);

            // Log metrics
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('summary.bulk_operation', {
                userId,
                operation,
                count: result.modifiedCount
            });
            logger.info(`Bulk operation ${operation} completed for ${result.modifiedCount} summaries in ${responseTime}ms`);

            // Emit event
            eventEmitter.emit('summary.bulk_updated', {
                userId,
                operation,
                summaryIds,
                modifiedCount: result.modifiedCount
            });

            return ApiResponse.success(res, {
                message,
                data: {
                    operation,
                    requested: summaryIds.length,
                    matched: result.matchedCount,
                    modified: result.modifiedCount
                }
            });

        } catch (error) {
            logger.error(`Bulk operation failed for user ${userId}:`, error);
            metricsCollector.increment('summary.bulk_operation_failed', { userId, operation });
            return next(new AppError('Bulk operation failed', 500));
        }
    });

    /**
     * Get summary analytics
     * GET /api/v1/summary/:userId/:summaryId/analytics
     */
    getAnalytics = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, summaryId } = req.params;
        const requestingUserId = req.user.id;
        const { timeframe = '30d', metrics = 'basic' } = req.query;

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        try {
            const summary = await Summary.findOne({ _id: summaryId, userId })
                .select('analytics quality sharing status createdAt')
                .cache({ ttl: 300, key: `analytics:${summaryId}:${timeframe}:${metrics}` });

            if (!summary) {
                return next(new AppError('Summary not found', 404));
            }

            const analytics = this.processAnalyticsData(summary, timeframe, metrics);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('summary.analytics_viewed', { userId });
            logger.info(`Fetched analytics for summary ${summaryId} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                data: analytics
            });

        } catch (error) {
            logger.error(`Analytics fetch failed for ${summaryId}:`, error);
            metricsCollector.increment('summary.analytics_fetch_failed', { userId });
            return next(new AppError('Failed to fetch analytics', 500));
        }
    });

    /**
     * Duplicate summary
     * POST /api/v1/summary/:userId/:summaryId/duplicate
     */
    duplicateSummary = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, summaryId } = req.params;
        const requestingUserId = req.user.id;
        const { title, includeVersions = 'false' } = req.body;

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        try {
            const originalSummary = await Summary.findOne({ _id: summaryId, userId });

            if (!originalSummary) {
                return next(new AppError('Summary not found', 404));
            }

            // Check user limits
            const userSummaryCount = await Summary.countDocuments({
                userId,
                'flags.isDeleted': false
            }).cache({ ttl: 300, key: `user_summary_count_${userId}` });

            const limits = this.getUserLimits(req.user.accountType);
            if (userSummaryCount >= limits.maxSummaries) {
                return next(new AppError(`Summary limit reached (${limits.maxSummaries})`, 403));
            }

            // Create duplicate
            const duplicateData = originalSummary.toObject();
            delete duplicateData._id;
            delete duplicateData.createdAt;
            delete duplicateData.updatedAt;
            delete duplicateData.slug;
            delete duplicateData.analytics;
            delete duplicateData.sharing.collaborators;

            // Update title and status
            duplicateData.title = title || `${originalSummary.title} (Copy)`;
            duplicateData.status = 'draft';
            duplicateData.compliance.audit.createdBy = {
                userId: requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date()
            };

            // Handle versions
            if (includeVersions !== 'true') {
                duplicateData.versions = [{
                    versionNumber: 1,
                    content: duplicateData.content,
                    title: duplicateData.title,
                    changeType: 'create',
                    isActive: true,
                    stats: {
                        characterCount: duplicateData.content.length,
                        wordCount: duplicateData.content.trim().split(/\s+/).length,
                        paragraphCount: duplicateData.content.split('\n\n').length,
                        sentenceCount: duplicateData.content.split(/[.!?]+/).length - 1,
                    }
                }];
            }

            const duplicate = new Summary(duplicateData);
            await duplicate.save();

            // Create backup
            if (duplicate.settings.autoBackup) {
                this.backupService.createBackup(duplicate._id, 'duplicate', requestingUserId)
                    .catch(err => logger.error(`Auto backup failed for duplicate ${duplicate._id}:`, err));
            }

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('summary.duplicated', { userId });
            logger.info(`Summary ${summaryId} duplicated as ${duplicate._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Summary duplicated successfully',
                data: {
                    originalId: summaryId,
                    duplicateId: duplicate._id,
                    title: duplicate.title,
                    slug: duplicate.slug
                }
            }, 201);

        } catch (error) {
            logger.error(`Summary duplication failed for ${summaryId}:`, error);
            metricsCollector.increment('summary.duplicate_failed', { userId });
            return next(new AppError('Failed to duplicate summary', 500));
        }
    });

    /**
     * Process new summary asynchronously (grammar check, suggestions, etc.)
     */
    async processNewSummaryAsync(summaryId, userId) {
        try {
            const summary = await Summary.findById(summaryId);
            if (!summary) return;

            // Run grammar check
            const grammarResult = await this.grammarService.checkGrammar(summary.content);
            summary.ai.grammar = grammarResult;
            summary.quality.grammarScore = grammarResult.score;

            // Generate suggestions
            const suggestions = await this.summaryService.generateSuggestions(summary.content);
            summary.ai.suggestions = suggestions;

            // Update quality score
            await summary.calculateQualityScore();

            // Save updates
            await summary.save();

            logger.info(`Async processing completed for summary ${summaryId}`);
        } catch (error) {
            logger.error(`Async processing failed for summary ${summaryId}:`, error);
        }
    }

    /**
     * Check access permissions for a summary
     */
    checkSummaryAccess(summary, requestingUserId, isAdmin) {
        if (isAdmin) return true;
        if (summary.userId === requestingUserId) return true;
        if (summary.sharing.visibility === 'public') return true;
        if (summary.sharing.collaborators.some(c => c.userId === requestingUserId && c.accessLevel !== 'none')) return true;
        return false;
    }

    /**
     * Get allowed fields for update
     */
    getAllowedUpdateFields() {
        return [
            'title',
            'content',
            'category',
            'tags',
            'status',
            'sharing.visibility',
            'settings.autoBackup',
            'settings.aiEnhancements',
            'templateId'
        ];
    }

    /**
     * Sanitize update fields
     */
    sanitizeUpdates(updates, allowedFields) {
        const sanitized = {};
        allowedFields.forEach(field => {
            if (updates[field] !== undefined) {
                sanitized[field] = sanitizeInput(updates[field]);
            }
        });
        return sanitized;
    }

    /**
     * Process analytics data
     */
    processAnalyticsData(summary, timeframe, metrics) {
        const analytics = summary.analytics || {};
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

        const filteredAnalytics = {
            views: {
                total: analytics.views?.total || 0,
                unique: analytics.views?.unique || 0,
                byDate: (analytics.views?.byDate || []).filter(v => new Date(v.date) >= timeframeDate)
            },
            shares: {
                total: analytics.shares?.total || 0,
                byPlatform: analytics.shares?.byPlatform || {}
            }
        };

        if (metrics === 'detailed') {
            filteredAnalytics.quality = summary.quality;
            filteredAnalytics.engagement = analytics.engagement || {};
        }

        return filteredAnalytics;
    }

    /**
     * Get user limits based on account type
     */
    getUserLimits(accountType) {
        const limits = {
            free: { maxSummaries: 10, maxVersions: 5 },
            premium: { maxSummaries: 100, maxVersions: 20 },
            enterprise: { maxSummaries: 1000, maxVersions: 50 }
        };
        return limits[accountType] || limits.free;
    }

    /**
     * Build query for fetching summaries
     */
    buildSummaryQuery({ userId, status, category, search, templateId, tags, startDate, endDate }) {
        const query = { userId };

        // Status filter
        if (status && status !== 'all') {
            if (status === 'deleted') {
                query['flags.isDeleted'] = true;
            } else {
                query['flags.isDeleted'] = false;
                query.status = status;
            }
        } else {
            query['flags.isDeleted'] = false;
        }

        // Category filter
        if (category && category !== 'all') {
            query.category = category;
        }

        // Template filter
        if (templateId) {
            query.templateId = templateId;
        }

        // Tags filter
        if (tags) {
            const tagArray = tags.split(',').map(tag => tag.trim().toLowerCase());
            query.tags = { $in: tagArray };
        }

        // Date range filter
        if (startDate || endDate) {
            query.createdAt = {};
            if (startDate) query.createdAt.$gte = new Date(startDate);
            if (endDate) query.createdAt.$lte = new Date(endDate);
        }

        // Search filter
        if (search) {
            query.$text = { $search: search };
        }

        return query;
    }

    /**
     * Build sort option for queries
     */
    buildSortOption(sortBy) {
        const sortOptions = {
            recent: { updatedAt: -1 },
            oldest: { createdAt: 1 },
            title: { title: 1 },
            popular: { 'analytics.views.total': -1 },
            quality: { 'quality.overallScore': -1 },
            status: { status: 1, updatedAt: -1 }
        };
        return sortOptions[sortBy] || sortOptions.recent;
    }

    /**
     * Get fields to select in queries
     */
    getSelectFields(includeAnalytics) {
        const baseFields = 'title content status category tags templateId quality createdAt updatedAt slug sharing.visibility flags.isPremium flags.isFeatured';
        return includeAnalytics ? baseFields + ' analytics' : baseFields;
    }

    /**
     * Process summary data for response
     */
    async processSummaryData(summary, includeAnalytics) {
        const processed = {
            ...summary,
            wordCount: summary.content ? summary.content.trim().split(/\s+/).length : 0,
            readingTime: summary.content ? Math.ceil(summary.content.trim().split(/\s+/).length / 200) : 0
        };

        if (!includeAnalytics) {
            delete processed.analytics;
        }

        return processed;
    }
}

export default new SummaryController();