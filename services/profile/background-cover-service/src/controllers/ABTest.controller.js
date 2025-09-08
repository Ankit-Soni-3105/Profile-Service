import { AppError } from '../errors/app.error.js';
import { logger } from '../utils/logger.js';
import { catchAsync } from '../handler/catchAsync.js';
import { ABTestService } from '../services/ABTestService.js';
import CoverPhoto from '../models/CoverPhoto.js';
import { validate as uuidValidate } from 'uuid';
import { body, param, query, validationResult } from 'express-validator';

class ABTestController {
    // Validation middleware
    static validateABTest = [
        body('variants').isArray({ min: 2 }).withMessage('At least two variants required'),
        body('variants.*').custom(uuidValidate).withMessage('Invalid variant IDs'),
        body('testGroup').isString().isLength({ max: 50 }).withMessage('Test group must be a string, max 50 chars'),
    ];

    // Create A/B test
    createABTest = catchAsync(async (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return next(new AppError(errors.array().map(e => e.msg).join(', '), 400));
        }

        const { coverId } = req.params;
        const { variants, testGroup } = req.body;
        const userId = req.user.id;

        const coverCount = await CoverPhoto.countDocuments({ userId, status: { $ne: 'deleted' } });
        const uploadLimit = req.user.accountType === 'free' ? 50 : req.user.accountType === 'premium' ? 500 : 1000;
        if (coverCount >= uploadLimit) {
            return next(new AppError(`Cover limit reached (${uploadLimit})`, 403));
        }

        const test = await ABTestService.createABTest(coverId, variants, testGroup, userId);
        logger.info(`A/B test created for cover ${coverId} by user ${userId}`);

        res.status(201).json({
            success: true,
            data: test
        });
    });

    // Track A/B test metrics
    trackABTestMetrics = catchAsync(async (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return next(new AppError(errors.array().map(e => e.msg).join(', '), 400));
        }

        const { coverId } = req.params;
        const { metric, value } = req.body;
        const userId = req.user.id;

        const testMetrics = await ABTestService.trackMetrics(coverId, metric, value, userId, req.user.groups || []);
        logger.info(`A/B test metric ${metric} updated for cover ${coverId} by user ${userId}`);

        res.status(200).json({
            success: true,
            data: testMetrics
        });
    });

    // Get A/B test results
    getABTestResults = catchAsync(async (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return next(new AppError(errors.array().map(e => e.msg).join(', '), 400));
        }

        const { coverId } = req.params;
        const { timeframe = '30d' } = req.query;
        const userId = req.user.id;

        const results = await ABTestService.getTestResults(coverId, timeframe, userId, req.user.groups || []);
        logger.info(`A/B test results retrieved for cover ${coverId} by user ${userId}`);

        res.status(200).json({
            success: true,
            data: results
        });
    });

    // End A/B test
    endABTest = catchAsync(async (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return next(new AppError(errors.array().map(e => e.msg).join(', '), 400));
        }

        const { coverId } = req.params;
        const userId = req.user.id;

        await ABTestService.endABTest(coverId, userId, req.user.groups || []);
        logger.info(`A/B test ended for cover ${coverId} by user ${userId}`);

        res.status(200).json({
            success: true,
            message: `A/B test ended for cover ${coverId}`
        });
    });

    // Bulk create A/B tests
    bulkCreateABTests = catchAsync(async (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return next(new AppError(errors.array().map(e => e.msg).join(', '), 400));
        }

        const { tests } = req.body;
        const userId = req.user.id;

        if (tests.length > 50) {
            return next(new AppError('Maximum 50 tests can be created at once', 400));
        }

        const results = await ABTestService.bulkCreateABTests(tests, userId);
        logger.info(`Bulk created ${tests.length} A/B tests by user ${userId}`);

        res.status(201).json({
            success: true,
            data: {
                total: tests.length,
                created: results.created,
                failed: results.failed
            }
        });
    });

    // Get all A/B tests for a user
    getUserABTests = catchAsync(async (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return next(new AppError(errors.array().map(e => e.msg).join(', '), 400));
        }

        const { page = 1, limit = 20 } = req.query;
        const userId = req.user.id;

        const tests = await ABTestService.getUserABTests(userId, req.user.groups || [], { page, limit });
        logger.info(`Retrieved A/B tests for user ${userId}`);

        res.status(200).json({
            success: true,
            data: tests
        });
    });

    // Generate AI-driven test variants
    generateTestVariants = catchAsync(async (req, res, next) => {
        const { coverId } = req.params;
        const { count = 3, style, mood } = req.body;
        const userId = req.user.id;

        if (count > 5) {
            return next(new AppError('Maximum 5 variations allowed', 400));
        }

        const variants = await ABTestService.generateTestVariants(coverId, { count, style, mood }, userId, req.user.groups || []);
        logger.info(`Generated ${variants.length} A/B test variants for cover ${coverId} by user ${userId}`);

        res.status(200).json({
            success: true,
            data: variants
        });
    });
}

export default new ABTestController();