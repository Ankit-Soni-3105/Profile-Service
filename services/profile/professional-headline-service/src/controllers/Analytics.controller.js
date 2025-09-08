import Headline from '../models/Headline.model.js';
import HeadlineHistory from '../models/HeadlineHistory.model.js';
import AnalyticsService from '../services/AnalyticsService.js';
import { validateAnalyticsRequest } from '../validations/analytics.validation.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { catchAsync } from '../handler/catchAsync.js';

class AnalyticsController {
    // Get headline analytics
    getHeadlineAnalytics = catchAsync(async (req, res, next) => {
        const { headlineId } = req.params;
        const userId = req.user.id;
        const { timeframe = '30d', period = 'daily' } = req.query;

        const headline = await Headline.findOne({ headlineId })
            .select('userId accessControl performance')
            .cache({ key: `headline:analytics:${headlineId}:${userId}:${timeframe}:${period}` });

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

        // Validate analytics request
        const validation = validateAnalyticsRequest({ timeframe, period });
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        try {
            const analyticsService = new AnalyticsService();
            const analytics = await analyticsService.getAnalytics(headlineId, timeframe, period);

            res.json({
                success: true,
                data: {
                    headlineId,
                    analytics
                }
            });
        } catch (error) {
            logger.error(`Analytics retrieval error for headlineId ${headlineId}:`, error);
            return next(new AppError('Analytics retrieval failed', 500));
        }
    });

    // Get trend analysis
    getTrendAnalysis = catchAsync(async (req, res, next) => {
        const { headlineId } = req.params;
        const userId = req.user.id;
        const { metric = 'views', timeframe = '30d' } = req.query;

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

        try {
            const analyticsService = new AnalyticsService();
            const trend = await analyticsService.getTrendAnalysis(headlineId, metric, timeframe);

            res.json({
                success: true,
                data: {
                    headlineId,
                    trend
                }
            });
        } catch (error) {
            logger.error(`Trend analysis error for headlineId ${headlineId}:`, error);
            return next(new AppError('Trend analysis failed', 500));
        }
    });

    // Update analytics data
    updateAnalytics = catchAsync(async (req, res, next) => {
        const { headlineId } = req.params;
        const userId = req.user.id;
        const { metrics } = req.body;

        const headline = await Headline.findOne({ headlineId });
        if (!headline) {
            return next(new AppError('Headline not found', 404));
        }

        // Check access permissions
        const hasAccess = headline.userId === userId ||
            headline.accessControl.collaborators.some(c => c.userId === userId && ['editor', 'admin'].includes(c.role));
        if (!hasAccess) {
            return next(new AppError('Access denied', 403));
        }

        try {
            await headline.recordPerformanceMetrics(metrics);
            headline.cacheVersion += 1;
            await headline.save();

            res.json({
                success: true,
                message: 'Analytics updated successfully',
                data: { headlineId }
            });
        } catch (error) {
            logger.error(`Analytics update error for headlineId ${headlineId}:`, error);
            return next(new AppError('Analytics update failed', 500));
        }
    });
}

export default new AnalyticsController();