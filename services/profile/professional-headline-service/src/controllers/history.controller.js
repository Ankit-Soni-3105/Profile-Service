import Headline from '../models/Headline.model.js';
import HeadlineHistory from '../models/HeadlineHistory.model.js';
import HistoryService from '../services/headlinehistory.service.js';
import { validateHistoryQuery } from '../validations/history.validation.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { catchAsync } from '../handler/catchAsync.js';

class HistoryController {
    // Get history for a headline
    getHeadlineHistory = catchAsync(async (req, res, next) => {
        const { headlineId } = req.params;
        const userId = req.user.id;
        const { page = 1, limit = 20, eventType, eventCategory, startDate, endDate } = req.query;

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

        // Validate query parameters
        const validation = validateHistoryQuery({ eventType, eventCategory, startDate, endDate });
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        try {
            const historyService = new HistoryService();
            const history = await historyService.getHistory(headlineId, {
                page,
                limit,
                eventType,
                eventCategory,
                startDate,
                endDate
            });

            res.json({
                success: true,
                data: history
            });
        } catch (error) {
            logger.error(`History retrieval error for headlineId ${headlineId}:`, error);
            return next(new AppError('History retrieval failed', 500));
        }
    });

    // Get specific history record
    getHistoryRecord = catchAsync(async (req, res, next) => {
        const { historyId } = req.params;
        const userId = req.user.id;

        const historyRecord = await HeadlineHistory.findOne({ historyId })
            .cache({ key: `history:${historyId}:${userId}` });

        if (!historyRecord) {
            return next(new AppError('History record not found', 404));
        }

        const headline = await Headline.findOne({ headlineId: historyRecord.headlineId })
            .select('userId accessControl');
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

        res.json({
            success: true,
            data: historyRecord.getPublicData ? historyRecord.getPublicData() : historyRecord
        });
    });

    // Revert to a previous version
    revertToVersion = catchAsync(async (req, res, next) => {
        const { historyId } = req.params;
        const userId = req.user.id;

        const historyRecord = await HeadlineHistory.findOne({ historyId });
        if (!historyRecord) {
            return next(new AppError('History record not found', 404));
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

        try {
            const oldText = headline.text;
            headline.text = historyRecord.snapshot.text;
            headline.metadata = { ...historyRecord.snapshot.metadata };
            headline.optimization.overallScore = historyRecord.snapshot.optimizationScore;
            headline.cacheVersion += 1;

            await headline.createVersion(historyRecord.snapshot.text, `Reverted to history ${historyId}`, userId);

            await headline.createHistoryRecord('restored', {
                eventCategory: 'system',
                summary: `Reverted headline ${headline.headlineId} to history ${historyId}`,
                changes: [{
                    field: 'text',
                    oldValue: oldText,
                    newValue: historyRecord.snapshot.text,
                    changeType: 'update',
                    impact: 'major'
                }]
            });

            await headline.save();

            res.json({
                success: true,
                message: 'Headline reverted successfully',
                data: { headlineId: headline.headlineId, historyId }
            });
        } catch (error) {
            logger.error(`Revert error for historyId ${historyId}:`, error);
            return next(new AppError('Revert failed', 500));
        }
    });
}

export default new HistoryController();