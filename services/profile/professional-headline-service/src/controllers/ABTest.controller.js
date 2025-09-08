import Headline from '../models/headline.model.js';
import HeadlineHistory from '../models/headlineHistory.model.js';
import ABTestService from '../services/ABTestService.js';
import { validateABTest } from '../validations/abtest.validation.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { catchAsync } from '../handler/catchAsync.js';
import { v4 as uuidv4 } from 'uuid';

class ABTestController {
    // Create a new A/B test
    createABTest = catchAsync(async (req, res, next) => {
        const { headlineId, experimentName, hypothesis, variants, methodology = 'frequentist', duration = 14 } = req.body;
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

        // Validate A/B test request
        const validation = validateABTest({ experimentName, hypothesis, variants, methodology, duration });
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        try {
            const testId = `abt_${uuidv4().replace(/-/g, '')}`;
            const experimentData = {
                experimentId: testId,
                experimentName,
                experimentType: 'ab-test',
                hypothesis,
                methodology,
                variants: variants.map((v, index) => ({
                    variantId: `var_${uuidv4().replace(/-/g, '')}`,
                    variantName: v.name || `Variant ${index + 1}`,
                    headlineText: v.text,
                    trafficAllocation: v.trafficAllocation || (100 / variants.length),
                    isControl: index === 0,
                    performance: { impressions: 0, conversions: 0, conversionRate: 0 }
                })),
                duration: { planned: duration, actual: 0, minDuration: 7, maxDuration: 30 },
                status: 'planned'
            };

            // Save to history
            await headline.createHistoryRecord('tested', {
                eventCategory: 'experiment',
                summary: `Created A/B test ${testId} for headline ${headlineId}`,
                experiments: [experimentData],
                changes: [{
                    field: 'experiments',
                    oldValue: null,
                    newValue: experimentData,
                    changeType: 'create',
                    impact: 'major',
                    automated: false
                }]
            });

            headline.cacheVersion += 1;
            await headline.save();

            // Start async test setup
            const abTestService = new ABTestService();
            abTestService.setupTestAsync(testId, headline, experimentData, userId).catch(err => {
                logger.error(`Async test setup failed for testId ${testId}:`, err);
            });

            res.status(201).json({
                success: true,
                message: 'A/B test created successfully',
                data: { testId, status: 'planned' }
            });
        } catch (error) {
            logger.error(`A/B test creation error for headlineId ${headlineId}:`, error);
            return next(new AppError('A/B test creation failed', 500));
        }
    });

    // Get A/B test results
    getTestResults = catchAsync(async (req, res, next) => {
        const { testId } = req.params;
        const userId = req.user.id;
        const { page = 1, limit = 20 } = req.query;

        const historyRecord = await HeadlineHistory.findOne({ 'experiments.experimentId': testId })
            .select('headlineId userId experiments accessControl')
            .cache({ key: `abtest:results:${testId}:${userId}` });

        if (!historyRecord) {
            return next(new AppError('Test not found', 404));
        }

        const headline = await Headline.findOne({ headlineId: historyRecord.headlineId })
            .select('accessControl userId');
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

        const experiment = historyRecord.experiments.find(exp => exp.experimentId === testId);
        if (!experiment) {
            return next(new AppError('Experiment not found', 404));
        }

        const skip = (page - 1) * limit;
        const analyticsRecords = await HeadlineHistory.find({
            headlineId: historyRecord.headlineId,
            'analytics.experimentId': testId
        })
            .sort({ timestamp: -1 })
            .skip(skip)
            .limit(parseInt(limit))
            .select('analytics')
            .lean();

        res.json({
            success: true,
            data: {
                testId,
                experiment,
                analytics: analyticsRecords.map(r => r.analytics).flat(),
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    totalCount: analyticsRecords.length,
                    totalPages: Math.ceil(analyticsRecords.length / limit)
                }
            }
        });
    });

    // Stop an A/B test
    stopTest = catchAsync(async (req, res, next) => {
        const { testId } = req.params;
        const userId = req.user.id;

        const historyRecord = await HeadlineHistory.findOne({ 'experiments.experimentId': testId });
        if (!historyRecord) {
            return next(new AppError('Test not found', 404));
        }

        const headline = await Headline.findOne({ headlineId: historyRecord.headlineId });
        if (!headline) {
            return next(new AppError('Headline not found', 404));
        }

        // Check access permissions
        const hasAccess = headline.userId === userId ||
            headline.accessControl.collaborators.some(c => c.userId === userId && ['editor', 'admin'].includes(c.role));
        if (!hasAccess) {
            return next(new AppError('Access denied', 403));
        }

        const experiment = historyRecord.experiments.find(exp => exp.experimentId === testId);
        if (!experiment) {
            return next(new AppError('Experiment not found', 404));
        }

        try {
            experiment.status = 'completed';
            experiment.duration.actual = Math.floor((new Date() - new Date(historyRecord.timestamp)) / (1000 * 60 * 60 * 24));

            await historyRecord.save();
            headline.cacheVersion += 1;
            await headline.save();

            // Trigger async performance analysis
            const abTestService = new ABTestService();
            abTestService.analyzeTestPerformanceAsync(testId, headline, userId).catch(err => {
                logger.error(`Test performance analysis failed for testId ${testId}:`, err);
            });

            res.json({
                success: true,
                message: 'A/B test stopped successfully',
                data: { testId, status: 'completed' }
            });
        } catch (error) {
            logger.error(`Test stop error for testId ${testId}:`, error);
            return next(new AppError('Test stop failed', 500));
        }
    });
}

export default new ABTestController();