import { AppError } from '../errors/app.error.js';
import { logger } from '../utils/logger.js';
import { catchAsync } from '../handler/catchAsync.js';
import { SchedulingService } from '../services/SchedulingService.js';
import CoverPhoto from '../models/CoverPhoto.js';
import Design from '../models/Design.model.js';
import { validate as uuidValidate } from 'uuid';
import { body, param, query, validationResult } from 'express-validator';

class SchedulingController {
    // Validation middleware
    static validateSchedule = [
        body('publishAt').isISO8601().toDate().withMessage('Invalid publishAt date'),
        body('platform').isIn(['linkedin', 'facebook', 'twitter', 'instagram', 'website', 'portfolio']).withMessage('Invalid platform'),
        body('timezone').optional().isString().matches(/^[A-Za-z]+\/[A-Za-z]+$/).withMessage('Invalid timezone format'),
    ];

    static validateAutoRotation = [
        body('interval').isInt({ min: 3600 }).withMessage('Interval must be at least 3600 seconds'),
        body('covers').isArray().withMessage('Covers must be an array'),
        body('covers.*').custom(uuidValidate).withMessage('Invalid cover IDs'),
    ];

    static validateBulkSchedule = [
        body('ids').isArray().withMessage('IDs must be an array'),
        body('ids.*').custom(uuidValidate).withMessage('Invalid ID'),
        body('type').isIn(['cover', 'design']).withMessage('Type must be "cover" or "design"'),
    ];

    // Schedule cover publication
    scheduleCoverPublication = catchAsync(async (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return next(new AppError(errors.array().map(e => e.msg).join(', '), 400));
        }

        const { coverId } = req.params;
        const { publishAt, platform, timezone } = req.body;
        const userId = req.user.id;

        const coverCount = await CoverPhoto.countDocuments({ userId, status: { $ne: 'deleted' } });
        const uploadLimit = req.user.accountType === 'free' ? 50 : req.user.accountType === 'premium' ? 500 : 1000;
        if (coverCount >= uploadLimit) {
            return next(new AppError(`Cover limit reached (${uploadLimit})`, 403));
        }

        const cover = await SchedulingService.scheduleCoverPublication(coverId, { publishAt, platform, timezone }, userId, req.user.groups || []);
        logger.info(`Publication scheduled for cover ${coverId} on ${platform} by user ${userId}`);

        res.status(200).json({
            success: true,
            data: { coverId, scheduling: cover.scheduling }
        });
    });

    // Schedule design publication
    scheduleDesignPublication = catchAsync(async (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return next(new AppError(errors.array().map(e => e.msg).join(', '), 400));
        }

        const { designId } = req.params;
        const { publishAt, platform, timezone } = req.body;
        const userId = req.user.id;

        const designCount = await Design.countDocuments({ userId, status: { $ne: 'deleted' } });
        const uploadLimit = req.user.accountType === 'free' ? 50 : req.user.accountType === 'premium' ? 500 : 1000;
        if (designCount >= uploadLimit) {
            return next(new AppError(`Design limit reached (${uploadLimit})`, 403));
        }

        const design = await SchedulingService.scheduleDesignPublication(designId, { publishAt, platform, timezone }, userId, req.user.groups || []);
        logger.info(`Publication scheduled for design ${designId} on ${platform} by user ${userId}`);

        res.status(200).json({
            success: true,
            data: { designId, publication: design.publication }
        });
    });

    // Enable cover auto-rotation
    enableCoverAutoRotation = catchAsync(async (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return next(new AppError(errors.array().map(e => e.msg).join(', '), 400));
        }

        const { coverId } = req.params;
        const { interval, covers } = req.body;
        const userId = req.user.id;

        const cover = await SchedulingService.enableCoverAutoRotation(coverId, { interval, covers }, userId, req.user.groups || []);
        logger.info(`Auto-rotation enabled for cover ${coverId} by user ${userId}`);

        res.status(200).json({
            success: true,
            data: { coverId, autoRotation: cover.scheduling.autoRotation }
        });
    });

    // Cancel scheduled publication
    cancelScheduledPublication = catchAsync(async (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return next(new AppError(errors.array().map(e => e.msg).join(', '), 400));
        }

        const { id, type } = req.params;
        const { jobId } = req.body;
        const userId = req.user.id;

        await SchedulingService.cancelScheduledPublication(id, type, jobId, userId, req.user.groups || []);
        logger.info(`Scheduled publication cancelled for ${type} ${id} by user ${userId}`);

        res.status(200).json({
            success: true,
            message: `Scheduled publication cancelled for ${type} ${id}`
        });
    });

    // Bulk schedule publications
    bulkSchedulePublications = catchAsync(async (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return next(new AppError(errors.array().map(e => e.msg).join(', '), 400));
        }

        const { ids, type, publishAt, platform, timezone } = req.body;
        const userId = req.user.id;

        if (ids.length > 50) {
            return next(new AppError('Maximum 50 items can be scheduled at once', 400));
        }

        const results = await SchedulingService.bulkSchedulePublications(ids, type, { publishAt, platform, timezone }, userId, req.user.groups || []);
        logger.info(`Bulk scheduled publications for ${ids.length} ${type}s by user ${userId}`);

        res.status(200).json({
            success: true,
            data: {
                total: ids.length,
                scheduled: results.scheduled.length,
                failed: results.failed
            }
        });
    });

    // Get scheduled publications
    getScheduledPublications = catchAsync(async (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return next(new AppError(errors.array().map(e => e.msg).join(', '), 400));
        }

        const { type, page = 1, limit = 20 } = req.query;
        const userId = req.user.id;

        const schedules = await SchedulingService.getScheduledPublications(type, userId, req.user.groups || [], { page, limit });
        logger.info(`Retrieved scheduled publications for ${type} by user ${userId}`);

        res.status(200).json({
            success: true,
            data: schedules
        });
    });

    // Pause auto-rotation
    pauseAutoRotation = catchAsync(async (req, res, next) => {
        const { coverId } = req.params;
        const userId = req.user.id;

        const cover = await SchedulingService.pauseAutoRotation(coverId, userId, req.user.groups || []);
        logger.info(`Auto-rotation paused for cover ${coverId} by user ${userId}`);

        res.status(200).json({
            success: true,
            data: { coverId, autoRotation: cover.scheduling.autoRotation }
        });
    });
}

export default new SchedulingController();