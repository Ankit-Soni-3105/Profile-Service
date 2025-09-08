import { v4 as uuidv4 } from 'uuid';
import Headline from '../models/headline.model.js';
import HeadlineHistory from '../models/headlineHistory.model.js';
import HeadlineService from '../services/headline.service.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { catchAsync } from '../handler/catchAsync.js';
import { validateOptimizationRequest } from '../validations/optimization.validation.js';

class OptimizationController {
    // Trigger headline optimization
    optimizeHeadline = catchAsync(async (req, res, next) => {
        const { headlineId, tone, industry, audience } = req.body;
        const userId = req.user.id;

        const headline = await Headline.findOne({ headlineId, status: { $ne: 'deleted' } });
        if (!headline) {
            return next(new AppError('Headline not found', 404));
        }

        // Check access permissions
        const hasAccess = headline.userId === userId ||
            headline.accessControl.collaborators.some(c => c.userId === userId && ['editor', 'admin'].includes(c.role));
        if (!hasAccess) {
            return next(new AppError('Access denied', 403));
        }

        // Validate optimization request
        const validation = validateOptimizationRequest({ tone, industry, audience });
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        try {
            headline.status = 'processing';
            headline.cacheVersion += 1;
            await headline.save();

            // Start async optimization
            this.processOptimizationAsync(headline, { tone, industry, audience }, userId);

            res.json({
                success: true,
                message: 'Optimization started',
                data: {
                    headlineId,
                    status: 'processing',
                    estimatedTime: '15-30 seconds'
                }
            });
        } catch (error) {
            logger.error(`Optimization initiation error for headlineId ${headlineId}:`, error);
            return next(new AppError('Optimization initiation failed', 500));
        }
    });

    // Get optimization history
    getOptimizationHistory = catchAsync(async (req, res, next) => {
        const { headlineId } = req.params;
        const userId = req.user.id;
        const { page = 1, limit = 20 } = req.query;

        const headline = await Headline.findOne({ headlineId })
            .select('userId accessControl')
            .cache({ key: `headline:access:${headlineId}:${userId}` });

        if (!headline) {
            return next(new AppError('Headline not found', 404));
        }

        // Check access permissions
        const hasAccess = headline.userId === userId ||
            headline.accessControl.visibility === 'public' ||
            headline.accessControl.collaborators.some(c => c.userId === userId);
        if (!hasAccess) {
            return next(new AppError('Access denied', 403));
        }

        const skip = (page - 1) * limit;
        const historyRecords = await HeadlineHistory.find({
            headlineId,
            eventType: { $in: ['optimized', 'analyzed', 'versioned'] }
        })
            .sort({ timestamp: -1 })
            .skip(skip)
            .limit(parseInt(limit))
            .select('eventType changes snapshot optimization performance timestamp')
            .cache({ key: `headline:optimization_history:${headlineId}:${page}:${limit}` })
            .lean();

        const totalCount = await HeadlineHistory.countDocuments({
            headlineId,
            eventType: { $in: ['optimized', 'analyzed', 'versioned'] }
        });

        res.json({
            success: true,
            data: {
                headlineId,
                history: historyRecords,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    totalCount,
                    totalPages: Math.ceil(totalCount / limit)
                }
            }
        });
    });

    // Apply optimization suggestion
    applyOptimization = catchAsync(async (req, res, next) => {
        const { headlineId, suggestionId } = req.params;
        const userId = req.user.id;

        const headline = await Headline.findOne({ headlineId, status: { $ne: 'deleted' } });
        if (!headline) {
            return next(new AppError('Headline not found', 404));
        }

        // Check access permissions
        const hasAccess = headline.userId === userId ||
            headline.accessControl.collaborators.some(c => c.userId === userId && ['editor', 'admin'].includes(c.role));
        if (!hasAccess) {
            return next(new AppError('Access denied', 403));
        }

        const suggestion = headline.optimization.suggestions.find(s => s.suggestionId === suggestionId);
        if (!suggestion) {
            return next(new AppError('Suggestion not found', 404));
        }

        try {
            const oldText = headline.text;
            headline.text = suggestion.text;
            suggestion.accepted = true;
            suggestion.acceptedAt = new Date();
            suggestion.acceptedBy = userId;
            headline.cacheVersion += 1;

            // Create new version
            await headline.createVersion(suggestion.text, `Applied optimization suggestion ${suggestionId}`, userId);

            // Create history record
            await headline.createHistoryRecord('optimized', {
                eventCategory: 'system',
                summary: `Applied optimization suggestion ${suggestionId} for headline ${headlineId}`,
                changes: [{
                    field: 'text',
                    oldValue: oldText,
                    newValue: suggestion.text,
                    changeType: 'update',
                    impact: 'major',
                    automated: true
                }, {
                    field: 'optimization.suggestions',
                    path: `optimization.suggestions.${suggestionId}.accepted`,
                    oldValue: false,
                    newValue: true,
                    changeType: 'update',
                    impact: 'moderate',
                    automated: true
                }]
            });

            // Start async AI analysis
            this.processOptimizationAsync(headline, { suggestionId }, userId);

            await headline.save();

            res.json({
                success: true,
                message: 'Optimization applied successfully',
                data: { suggestionId, newText: headline.text }
            });
        } catch (error) {
            logger.error(`Optimization application error for suggestionId ${suggestionId}:`, error);
            return next(new AppError('Optimization application failed', 500));
        }
    });

    // Async processing for optimization
    processOptimizationAsync = async (headline, options, userId) => {
        try {
            const headlineService = new HeadlineService();
            const optimizedHeadline = await headlineService.optimizeHeadline(headline.headlineId, options);

            // Update history with optimization results
            await headline.createHistoryRecord('optimized', {
                eventCategory: 'system',
                summary: `Optimization completed for headline ${headline.headlineId}`,
                changes: [{
                    field: 'text',
                    oldValue: headline.originalText,
                    newValue: optimizedHeadline.text,
                    changeType: 'update',
                    impact: 'major',
                    automated: true
                }, {
                    field: 'optimization',
                    oldValue: { ...headline.optimization.toObject() },
                    newValue: optimizedHeadline.optimization,
                    changeType: 'update',
                    impact: 'moderate',
                    automated: true
                }],
                analytics: [{
                    period: 'daily',
                    startDate: new Date(),
                    endDate: new Date(),
                    metrics: {
                        optimizationScore: optimizedHeadline.optimization.overallScore
                    }
                }]
            });

            logger.info(`Optimization processed successfully for headline: ${headline.headlineId}`);
        } catch (error) {
            logger.error(`Optimization processing failed for headlineId ${headline.headlineId}:`, error);
            headline.status = 'failed';
            headline.moderation.status = 'flagged';
            headline.moderation.flagReason = error.message;
            await headline.save();
        }
    };
}

export default new OptimizationController();