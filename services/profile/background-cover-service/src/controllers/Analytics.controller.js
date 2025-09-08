import { AppError } from '../errors/app.error.js';
import { logger } from '../utils/logger.js';
import { catchAsync } from '../handler/catchAsync.js';
import { AnalyticsService } from '../services/AnalyticsService.js';
import CoverPhoto from '../models/CoverPhoto.js';
import Design from '../models/Design.model.js';
import { validate as uuidValidate } from 'uuid';
import { query, validationResult } from 'express-validator';

class AnalyticsController {
    // Validation middleware
    static validateAnalytics = [
        query('timeframe').optional().isIn(['7d', '30d', '90d', '1y']).withMessage('Invalid timeframe'),
        query('category').optional().isIn(['all', 'nature', 'abstract', 'business', 'technology', 'art', 'photography', 'design', 'minimal', 'colorful', 'dark', 'light', 'profile-cover', 'business-card', 'social-media', 'presentation', 'marketing', 'personal', 'portfolio']).withMessage('Invalid category'),
    ];

    // Get cover analytics summary
    getCoverAnalyticsSummary = catchAsync(async (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return next(new AppError(errors.array().map(e => e.msg).join(', '), 400));
        }

        const { timeframe = '30d', category = 'all' } = req.query;
        const userId = req.user.id;

        const summary = await AnalyticsService.getCoverAnalyticsSummary(userId, timeframe, category, req.user.groups || []);
        logger.info(`Cover analytics summary retrieved for user ${userId}`);

        res.status(200).json({
            success: true,
            data: summary
        });
    });

    // Get design analytics summary
    getDesignAnalyticsSummary = catchAsync(async (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return next(new AppError(errors.array().map(e => e.msg).join(', '), 400));
        }

        const { timeframe = '30d', category = 'all' } = req.query;
        const userId = req.user.id;

        const summary = await AnalyticsService.getDesignAnalyticsSummary(userId, timeframe, category, req.user.groups || []);
        logger.info(`Design analytics summary retrieved for user ${userId}`);

        res.status(200).json({
            success: true,
            data: summary
        });
    });

    // Get trending covers
    getTrendingCovers = catchAsync(async (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return next(new AppError(errors.array().map(e => e.msg).join(', '), 400));
        }

        const { timeframe = '7d', limit = 20, category = 'all' } = req.query;
        const userId = req.user.id;

        const covers = await AnalyticsService.getTrendingCovers(timeframe, limit, category, userId, req.user.groups || []);
        logger.info(`Trending covers retrieved for timeframe ${timeframe}`);

        res.status(200).json({
            success: true,
            data: covers
        });
    });

    // Get trending designs
    getTrendingDesigns = catchAsync(async (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return next(new AppError(errors.array().map(e => e.msg).join(', '), 400));
        }

        const { timeframe = '7d', limit = 20, category = 'all' } = req.query;
        const userId = req.user.id;

        const designs = await AnalyticsService.getTrendingDesigns(timeframe, limit, category, userId, req.user.groups || []);
        logger.info(`Trending designs retrieved for timeframe ${timeframe}`);

        res.status(200).json({
            success: true,
            data: designs
        });
    });

    // Get detailed cover analytics
    getCoverAnalytics = catchAsync(async (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return next(new AppError(errors.array().map(e => e.msg).join(', '), 400));
        }

        const { coverId } = req.params;
        const { timeframe = '30d' } = req.query;
        const userId = req.user.id;

        const analytics = await AnalyticsService.getCoverAnalytics(coverId, timeframe, userId, req.user.groups || []);
        logger.info(`Detailed analytics retrieved for cover ${coverId} by user ${userId}`);

        res.status(200).json({
            success: true,
            data: analytics
        });
    });

    // Get detailed design analytics
    getDesignAnalytics = catchAsync(async (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return next(new AppError(errors.array().map(e => e.msg).join(', '), 400));
        }

        const { designId } = req.params;
        const { timeframe = '30d' } = req.query;
        const userId = req.user.id;

        const analytics = await AnalyticsService.getDesignAnalytics(designId, timeframe, userId, req.user.groups || []);
        logger.info(`Detailed analytics retrieved for design ${designId} by user ${userId}`);

        res.status(200).json({
            success: true,
            data: analytics
        });
    });

    // Generate AI-driven analytics insights
    generateAnalyticsInsights = catchAsync(async (req, res, next) => {
        const { id, type } = req.params;
        const { timeframe = '30d' } = req.query;
        const userId = req.user.id;

        const insights = await AnalyticsService.generateAnalyticsInsights(id, type, timeframe, userId, req.user.groups || []);
        logger.info(`Analytics insights generated for ${type} ${id} by user ${userId}`);

        res.status(200).json({
            success: true,
            data: insights
        });
    });
}

export default new AnalyticsController();