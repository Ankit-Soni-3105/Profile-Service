import { AppError } from '../errors/app.error.js';
import { logger } from '../utils/logger.js';
import CoverPhoto from '../models/CoverPhoto.js';
import { processImage, analyzeWithAI } from './cover.service.js';
import { v4 as uuidv4 } from 'uuid';

export class ABTestService {
    static async createABTest(coverId, variants, testGroup, userId) {
        const parentCover = await CoverPhoto.findOne({ coverId, userId });
        if (!parentCover) {
            throw new AppError('Parent cover photo not found or access denied', 404);
        }

        const variantCovers = await CoverPhoto.find({
            coverId: { $in: variants },
            userId,
            status: 'active',
            'processing.status': 'completed'
        });

        if (variantCovers.length !== variants.length) {
            throw new AppError('One or more variant IDs are invalid or not ready', 400);
        }

        parentCover.abTesting = {
            isTest: true,
            testGroup,
            variantId: '',
            parentCoverId: coverId,
            testMetrics: { impressions: 0, clicks: 0, conversions: 0, engagement: 0 }
        };

        for (const variant of variantCovers) {
            variant.abTesting = {
                isTest: true,
                testGroup,
                variantId: variant.coverId,
                parentCoverId: coverId,
                testMetrics: { impressions: 0, clicks: 0, conversions: 0, engagement: 0 }
            };
            await variant.save();
        }

        parentCover.cacheVersion += 1;
        await parentCover.save();

        return {
            coverId,
            abTesting: parentCover.abTesting,
            variants
        };
    }

    static async trackMetrics(coverId, metric, value, userId, groups = []) {
        const cover = await CoverPhoto.findOne({
            coverId,
            $or: [
                { userId },
                { 'accessControl.allowedUsers': userId },
                { 'accessControl.allowedGroups': { $in: groups } }
            ],
            'abTesting.isTest': true
        });

        if (!cover) {
            throw new AppError('Cover photo not found, not in A/B test, or access denied', 404);
        }

        cover.abTesting.testMetrics[metric] += value;
        cover.abTesting.testMetrics.engagement = (
            cover.abTesting.testMetrics.clicks * 0.5 +
            cover.abTesting.testMetrics.conversions * 2 +
            cover.abTesting.testMetrics.impressions * 0.1
        );

        cover.cacheVersion += 1;
        await cover.save();

        return {
            coverId,
            testMetrics: cover.abTesting.testMetrics
        };
    }

    static async getTestResults(coverId, timeframe, userId, groups = []) {
        let daysAgo = 30;
        switch (timeframe) {
            case '7d': daysAgo = 7; break;
            case '30d': daysAgo = 30; break;
            case '90d': daysAgo = 90; break;
            case '1y': daysAgo = 365; break;
        }

        const startDate = new Date();
        startDate.setDate(startDate.getDate() - daysAgo);

        const parentCover = await CoverPhoto.findOne({
            coverId,
            $or: [
                { userId },
                { 'accessControl.allowedUsers': userId },
                { 'accessControl.allowedGroups': { $in: groups } }
            ],
            'abTesting.isTest': true
        });

        if (!parentCover) {
            throw new AppError('Parent cover photo not found or not in A/B test', 404);
        }

        const variants = await CoverPhoto.find({
            'abTesting.parentCoverId': coverId,
            'abTesting.isTest': true,
            updatedAt: { $gte: startDate }
        }).select('coverId abTesting.testMetrics processing.thumbnails.medium.url');

        return {
            parent: {
                coverId,
                metrics: parentCover.abTesting.testMetrics,
                thumbnail: parentCover.processing.thumbnails.medium.url
            },
            variants: variants.map(v => ({
                coverId: v.coverId,
                metrics: v.abTesting.testMetrics,
                thumbnail: v.processing.thumbnails.medium.url
            }))
        };
    }

    static async endABTest(coverId, userId, groups = []) {
        const cover = await CoverPhoto.findOne({
            coverId,
            $or: [
                { userId },
                { 'accessControl.allowedUsers': userId },
                { 'accessControl.allowedGroups': { $in: groups } }
            ],
            'abTesting.isTest': true
        });

        if (!cover) {
            throw new AppError('Cover photo not found or not in A/B test', 404);
        }

        cover.abTesting.isTest = false;
        cover.cacheVersion += 1;
        await cover.save();

        const variants = await CoverPhoto.find({
            'abTesting.parentCoverId': coverId,
            'abTesting.isTest': true
        });

        for (const variant of variants) {
            variant.abTesting.isTest = false;
            variant.cacheVersion += 1;
            await variant.save();
        }
    }

    static async bulkCreateABTests(tests, userId) {
        const created = [];
        const failed = [];

        for (const test of tests) {
            try {
                const result = await this.createABTest(test.coverId, test.variants, test.testGroup, userId);
                created.push(result);
            } catch (error) {
                failed.push({ coverId: test.coverId, error: error.message });
            }
        }

        return { created, failed };
    }

    static async getUserABTests(userId, groups = [], { page = 1, limit = 20 }) {
        const skip = (page - 1) * limit;
        const query = {
            $or: [
                { userId },
                { 'accessControl.allowedUsers': userId },
                { 'accessControl.allowedGroups': { $in: groups } }
            ],
            'abTesting.isTest': true
        };

        const tests = await CoverPhoto.find(query)
            .select('coverId abTesting')
            .sort({ updatedAt: -1 })
            .skip(skip)
            .limit(parseInt(limit))
            .cache({ key: `abtests:${userId}:${page}:${limit}` })
            .lean();

        const totalCount = await CoverPhoto.countDocuments(query);
        const totalPages = Math.ceil(totalCount / limit);

        return {
            tests,
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

    static async generateTestVariants(coverId, { count, style, mood }, userId, groups = []) {
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

        const variations = await processImage(cover.processing.original.url, {
            count,
            style: style || 'professional',
            mood: mood || 'neutral',
            preserveAspectRatio: true
        });

        const variantCovers = [];
        for (const [index, variation] of variations.entries()) {
            const variantId = `${coverId}_var_${index + 1}`;
            const uploadResult = await uploadToCloudinary(variation.buffer, {
                folder: `covers/${userId}/variants`,
                public_id: variantId,
                resource_type: 'image',
                quality: 'auto:eco'
            });

            const variant = new CoverPhoto({
                coverId: variantId,
                userId,
                templateId: cover.templateId,
                name: `${cover.name}_variant_${index + 1}`,
                category: cover.category,
                tags: cover.tags,
                status: 'active',
                accessControl: cover.accessControl,
                dimensions: cover.dimensions,
                format: variation.format,
                processing: {
                    status: 'completed',
                    original: { url: uploadResult.secure_url, size: variation.size, cloudinaryId: uploadResult.public_id },
                    optimized: variation.optimized,
                    thumbnails: variation.thumbnails,
                    variants: []
                }
            });

            variantCovers.push(await variant.save());
        }

        return variantCovers.map(v => ({
            coverId: v.coverId,
            url: v.processing.original.url
        }));
    }
}