import { AppError } from '../errors/app.error.js';
import { logger } from '../utils/logger.js';
import CoverPhoto from '../models/CoverPhoto.js';
import Design from '../models/Design.model.js';
import { scheduleJob, cancelJob } from '../utils/queue.js';

export class SchedulingService {
    static async scheduleCoverPublication(coverId, { publishAt, platform, timezone = 'UTC' }, userId, groups = []) {
        const cover = await CoverPhoto.findOne({
            coverId,
            $or: [
                { userId },
                { 'accessControl.allowedUsers': userId },
                { 'accessControl.allowedGroups': { $in: groups } }
            ]
        });

        if (!cover) {
            throw new AppError('Cover photo not found or access denied', 404);
        }

        if (!cover.accessControl.allowShare) {
            throw new AppError('Sharing not allowed for this cover photo', 403);
        }

        cover.scheduling.isScheduled = true;
        cover.scheduling.publishAt = new Date(publishAt);
        cover.scheduling.timezone = timezone;
        cover.scheduling.autoRotation.covers = cover.scheduling.autoRotation.covers || [];
        cover.scheduling.autoRotation.covers = [...new Set([...cover.scheduling.autoRotation.covers, coverId])];

        const jobId = `publish_${coverId}_${Date.now()}`;
        await scheduleJob('publishCover', {
            coverId,
            platform,
            userId,
            publishAt,
            timezone
        }, { delay: new Date(publishAt).getTime() - Date.now(), jobId });

        cover.scheduling.jobId = jobId;
        cover.cacheVersion += 1;
        return await cover.save();
    }

    static async scheduleDesignPublication(designId, { publishAt, platform, timezone = 'UTC' }, userId, groups = []) {
        const design = await Design.findOne({
            designId,
            $or: [
                { userId },
                { 'accessControl.allowedUsers': userId },
                { 'accessControl.allowedGroups': { $in: groups } },
                { 'collaboration.collaborators': { $elemMatch: { userId, status: 'accepted', role: { $in: ['editor', 'admin'] } } } }
            ]
        });

        if (!design) {
            throw new AppError('Design not found or access denied', 404);
        }

        const jobId = `publish_${designId}_${Date.now()}`;
        design.publication.scheduledPublications.push({
            platform,
            scheduledFor: new Date(publishAt),
            status: 'scheduled',
            jobId,
            createdAt: new Date()
        });

        await scheduleJob('publishDesign', {
            designId,
            platform,
            userId,
            publishAt,
            timezone
        }, { delay: new Date(publishAt).getTime() - Date.now(), jobId });

        design.publication.isPublished = false;
        design.cacheVersion += 1;
        return await design.save();
    }

    static async enableCoverAutoRotation(coverId, { interval, covers }, userId, groups = []) {
        const cover = await CoverPhoto.findOne({
            coverId,
            $or: [
                { userId },
                { 'accessControl.allowedUsers': userId },
                { 'accessControl.allowedGroups': { $in: groups } }
            ]
        });

        if (!cover) {
            throw new AppError('Cover photo not found or access denied', 404);
        }

        const validCovers = await CoverPhoto.find({
            coverId: { $in: covers },
            $or: [
                { userId },
                { 'accessControl.allowedUsers': userId },
                { 'accessControl.allowedGroups': { $in: groups } }
            ]
        }).select('coverId');

        if (validCovers.length !== covers.length) {
            throw new AppError('One or more cover IDs are invalid or inaccessible', 400);
        }

        cover.scheduling.autoRotation = {
            enabled: true,
            interval,
            covers,
            jobId: `rotate_${coverId}_${Date.now()}`
        };

        await scheduleJob('rotateCovers', {
            coverId,
            covers,
            interval,
            userId
        }, { repeat: { every: interval * 1000 }, jobId: cover.scheduling.autoRotation.jobId });

        cover.cacheVersion += 1;
        return await cover.save();
    }

    static async cancelScheduledPublication(id, type, jobId, userId, groups = []) {
        const Model = type === 'cover' ? CoverPhoto : Design;
        const field = type === 'cover' ? 'coverId' : 'designId';

        const resource = await Model.findOne({
            [field]: id,
            $or: [
                { userId },
                { 'accessControl.allowedUsers': userId },
                { 'accessControl.allowedGroups': { $in: groups } },
                type === 'design' ? { 'collaboration.collaborators': { $elemMatch: { userId, status: 'accepted', role: { $in: ['editor', 'admin'] } } } } : {}
            ]
        });

        if (!resource) {
            throw new AppError(`${type} not found or access denied`, 404);
        }

        if (type === 'cover') {
            if (resource.scheduling.jobId !== jobId) {
                throw new AppError('Invalid job ID', 400);
            }
            resource.scheduling.isScheduled = false;
            resource.scheduling.jobId = null;
        } else {
            const publication = resource.publication.scheduledPublications.find(p => p.jobId === jobId);
            if (!publication) {
                throw new AppError('Scheduled publication not found', 404);
            }
            publication.status = 'cancelled';
        }

        await cancelJob(jobId);
        resource.cacheVersion += 1;
        await resource.save();
    }

    static async bulkSchedulePublications(ids, type, schedule, userId, groups = []) {
        const Model = type === 'cover' ? CoverPhoto : Design;
        const field = type === 'cover' ? 'coverId' : 'designId';

        const resources = await Model.find({
            [field]: { $in: ids },
            $or: [
                { userId },
                { 'accessControl.allowedUsers': userId },
                { 'accessControl.allowedGroups': { $in: groups } },
                type === 'design' ? { 'collaboration.collaborators': { $elemMatch: { userId, status: 'accepted', role: { $in: ['editor', 'admin'] } } } } : {}
            ]
        });

        const scheduled = [];
        const failed = [];

        for (const resource of resources) {
            try {
                if (type === 'cover') {
                    resource.scheduling.isScheduled = true;
                    resource.scheduling.publishAt = new Date(schedule.publishAt);
                    resource.scheduling.timezone = schedule.timezone || 'UTC';
                    resource.scheduling.jobId = `publish_${resource.coverId}_${Date.now()}`;
                    await scheduleJob('publishCover', {
                        coverId: resource.coverId,
                        platform: schedule.platform,
                        userId,
                        publishAt: schedule.publishAt,
                        timezone: schedule.timezone
                    }, { delay: new Date(schedule.publishAt).getTime() - Date.now(), jobId: resource.scheduling.jobId });
                } else {
                    resource.publication.scheduledPublications.push({
                        platform: schedule.platform,
                        scheduledFor: new Date(schedule.publishAt),
                        status: 'scheduled',
                        jobId: `publish_${resource.designId}_${Date.now()}`,
                        createdAt: new Date()
                    });
                    await scheduleJob('publishDesign', {
                        designId: resource.designId,
                        platform: schedule.platform,
                        userId,
                        publishAt: schedule.publishAt,
                        timezone: schedule.timezone
                    }, { delay: new Date(schedule.publishAt).getTime() - Date.now(), jobId: resource.publication.scheduledPublications[resource.publication.scheduledPublications.length - 1].jobId });
                }
                resource.cacheVersion += 1;
                scheduled.push(await resource.save());
            } catch (error) {
                failed.push({ [field]: resource[field], error: error.message });
            }
        }

        return { scheduled, failed };
    }

    static async getScheduledPublications(type, userId, groups = [], { page = 1, limit = 20 }) {
        const Model = type === 'cover' ? CoverPhoto : Design;
        const field = type === 'cover' ? 'coverId' : 'designId';

        const query = {
            $or: [
                { userId },
                { 'accessControl.allowedUsers': userId },
                { 'accessControl.allowedGroups': { $in: groups } },
                type === 'design' ? { 'collaboration.collaborators': { $elemMatch: { userId, status: 'accepted' } } } : {}
            ],
            [type === 'cover' ? 'scheduling.isScheduled' : 'publication.scheduledPublications.0']: { $exists: true }
        };

        const skip = (page - 1) * limit;
        const resources = await Model.find(query)
            .select(`${field} scheduling publication`)
            .sort({ updatedAt: -1 })
            .skip(skip)
            .limit(parseInt(limit))
            .cache({ key: `schedules:${type}:${userId}:${page}:${limit}` })
            .lean();

        const totalCount = await Model.countDocuments(query);
        const totalPages = Math.ceil(totalCount / limit);

        return {
            resources,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                totalCount,
                totalPages,
                hasNext: page < totalPages,
                hasPrev: page > 1
            }
        };
    }

    static async pauseAutoRotation(coverId, userId, groups = []) {
        const cover = await CoverPhoto.findOne({
            coverId,
            $or: [
                { userId },
                { 'accessControl.allowedUsers': userId },
                { 'accessControl.allowedGroups': { $in: groups } }
            ]
        });

        if (!cover) {
            throw new AppError('Cover photo not found or access denied', 404);
        }

        if (!cover.scheduling.autoRotation.enabled) {
            throw new AppError('Auto-rotation not enabled', 400);
        }

        await cancelJob(cover.scheduling.autoRotation.jobId);
        cover.scheduling.autoRotation.enabled = false;
        cover.scheduling.autoRotation.jobId = null;
        cover.cacheVersion += 1;
        return await cover.save();
    }
}