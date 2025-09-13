import Organization from '../models/Organization.js';
import { VerificationService } from './VerificationService.js';
import { NotificationService } from './NotificationService.js';
import { validateOrganization } from '../validations/organization.validation.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { metricsCollector } from '../utils/metrics.js';
import { cacheService } from '../services/cache.service.js';
import { createRateLimiter } from '../utils/rateLimiter.js';
import { CircuitBreaker } from '../utils/circuitBreaker.js';
import { retry } from '../utils/retry.js';
import { elasticsearchClient } from '../config/elasticsearch.js';
import { s3Client } from '../config/s3.js';
import mongoose from 'mongoose';
import sanitizeHtml from 'sanitize-html';
import moment from 'moment';
import { v4 as uuidv4 } from 'uuid';

// Rate limiters for high concurrency
const createLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15-minute window
    max: 5, // Allow 5 creates per user
    skipSuccessfulRequests: true,
    keyGenerator: (data) => `organization_create_${data.userId}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const updateLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5-minute window
    max: 15, // Allow 15 updates
    skipSuccessfulRequests: true,
    keyGenerator: (data) => `organization_update_${data.userId}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

const verifyLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30-minute window
    max: 3, // Strict limit for external verification
    skipSuccessfulRequests: true,
    keyGenerator: (data) => `organization_verify_${data.userId}`,
    redisClient: cacheService.getRedisClient(),
    standardHeaders: true,
});

class OrganizationService {
    constructor() {
        this.verificationService = new VerificationService();
        this.notificationService = new NotificationService();
        this.circuitBreaker = new CircuitBreaker({
            timeout: 10000,
            errorThresholdPercentage: 50,
            resetTimeout: 30000,
        });
        this.retryConfig = {
            retries: 3,
            delay: 100,
            backoff: 'exponential',
        };
    }

    /**
     * Create a new organization
     * @param {Object} data - Organization data (name, type, description, etc.)
     * @param {Object} options - Mongoose session options and request metadata
     * @returns {Promise<Object>} - Created organization
     */
    async createOrganization(data, options = {}) {
        const startTime = Date.now();
        const { userId, ip, userAgent, geoip, referrer } = options.request || {};
        const validation = validateOrganization(data);
        if (!validation.valid) {
            metricsCollector.increment('organization.validation_failed', { userId, errors: validation.errors.length });
            throw new AppError(`Validation failed: ${validation.message}`, 400);
        }

        await createLimiter({ userId }, null, () => { });

        const sanitizedData = this.sanitizeInput(data);
        sanitizedData.name = sanitizedData.name?.trim();
        sanitizedData.description = sanitizedData.description ? sanitizeHtml(sanitizedData.description) : null;

        const existingOrg = await Organization.findOne({ name: sanitizedData.name, status: { $ne: 'deleted' } });
        if (existingOrg) {
            throw new AppError('Organization with this name already exists', 409);
        }

        const session = options.session || await mongoose.startSession();
        try {
            if (!options.session) session.startTransaction();

            const organization = await Organization.create([{
                ...sanitizedData,
                createdBy: userId,
                metadata: {
                    ...sanitizedData.metadata,
                    createdBy: {
                        userId,
                        ip: ip || 'unknown',
                        userAgent: userAgent || 'unknown',
                        location: geoip || { country: 'unknown', city: 'unknown' },
                        referrer: referrer || 'direct',
                    },
                    importSource: sanitizedData.metadata?.importSource || 'manual',
                    version: 1,
                    updateCount: 0,
                },
                analytics: {
                    views: { total: 0, unique: 0, byDate: [] },
                    endorsements: { total: 0, byUser: [] },
                    interactions: { total: 0, byType: {} },
                },
                verification: {
                    status: 'pending',
                    confidence: 0,
                    verifiedBy: null,
                    verifiedAt: null,
                    details: [],
                },
                status: 'pending',
                privacy: {
                    isPublic: false,
                    showDetails: true,
                    searchable: true,
                },
            }], { session });

            this.processNewOrganizationAsync(organization[0]._id, userId).catch((err) => {
                logger.error(`Async processing failed for organization ${organization[0]._id}:`, err);
                metricsCollector.increment('organization.async_processing_failed', { organizationId: organization[0]._id });
            });

            if (organization[0].settings?.autoBackup) {
                await this.createBackup(organization[0]._id, 'create', userId, { session });
            }

            metricsCollector.increment('organization.created', { userId, name: organization[0].name, type: organization[0].type });
            metricsCollector.timing('organization.create_time', Date.now() - startTime);

            if (!options.session) await session.commitTransaction();
            return organization[0];
        } catch (error) {
            if (!options.session) await session.abortTransaction();
            logger.error(`Organization creation failed for user ${userId}:`, { error: error.message });
            metricsCollector.increment('organization.create_failed', { userId });
            throw error instanceof AppError ? error : new AppError('Failed to create organization', 500);
        } finally {
            if (!options.session) session.endSession();
        }
    }

    /**
     * Update organization metadata
     * @param {String} organizationId - Organization ID
     * @param {Object} updates - Update data
     * @param {Object} options - Mongoose session options and request metadata
     * @returns {Promise<Object>} - Updated organization
     */
    async updateOrganization(organizationId, updates, options = {}) {
        const startTime = Date.now();
        const { userId } = options.request || {};
        const sanitizedUpdates = this.sanitizeUpdates(updates);
        if (Object.keys(sanitizedUpdates).length === 0) {
            throw new AppError('No valid update fields provided', 400);
        }

        await updateLimiter({ userId }, null, () => { });

        const session = options.session || await mongoose.startSession();
        try {
            if (!options.session) session.startTransaction();

            const organization = await Organization.findById(organizationId).session(session);
            if (!organization || organization.status === 'deleted') {
                throw new AppError('Organization not found', 404);
            }

            if (sanitizedUpdates.name || sanitizedUpdates.type) {
                organization.versions = organization.versions || [];
                organization.versions.push({
                    versionNumber: organization.metadata.version + 1,
                    name: sanitizedUpdates.name || organization.name,
                    type: sanitizedUpdates.type || organization.type,
                    changeType: 'edit',
                    timestamp: new Date(),
                });
            }

            Object.assign(organization, sanitizedUpdates);
            organization.metadata.version += 1;
            organization.metadata.updateCount += 1;
            organization.metadata.lastModifiedBy = {
                userId,
                timestamp: new Date(),
                changes: Object.keys(sanitizedUpdates),
            };

            if (['name', 'type', 'website'].some(field => sanitizedUpdates[field])) {
                organization.verification.status = 'pending';
                this.processExternalVerification(organization._id, userId).catch((err) => {
                    logger.error(`Re-verification failed for organization ${organization._id}:`, err);
                });
            }

            await organization.save({ session });
            await this.indexForSearch(organization);
            await cacheService.deletePattern(`organization:${organizationId}:*`);

            metricsCollector.increment('organization.updated', { organizationId });
            metricsCollector.timing('organization.update_time', Date.now() - startTime);

            if (!options.session) await session.commitTransaction();
            return organization;
        } catch (error) {
            if (!options.session) await session.abortTransaction();
            logger.error(`Organization update failed for ${organizationId}:`, { error: error.message });
            metricsCollector.increment('organization.update_failed', { organizationId });
            throw error instanceof AppError ? error : new AppError('Failed to update organization', 500);
        } finally {
            if (!options.session) session.endSession();
        }
    }

    /**
     * Verify organization
     * @param {Object} data - Verification data (organizationId, name, type, website)
     * @returns {Promise<Object>} - Verification result
     */
    async verifyOrganization(data) {
        const startTime = Date.now();
        const { organizationId, name, type, website, userId } = data;

        await verifyLimiter({ userId }, null, () => { });

        try {
            const verificationResult = await this.circuitBreaker.fire(async () => {
                return await retry(() => this.verificationService.verifyOrganization({
                    organizationId,
                    name,
                    type,
                    website,
                }), this.retryConfig);
            });

            const session = await mongoose.startSession();
            try {
                session.startTransaction();

                const organization = await Organization.findById(organizationId).session(session);
                if (!organization || organization.status === 'deleted') {
                    throw new AppError('Organization not found', 404);
                }

                organization.verification = {
                    status: verificationResult.success ? 'verified' : 'failed',
                    confidence: verificationResult.confidence || 0,
                    verifiedBy: verificationResult.verifiedBy || 'external_api',
                    verifiedAt: new Date(),
                    details: verificationResult.details || [],
                };

                await organization.save({ session });
                await this.indexForSearch(organization);

                if (verificationResult.success) {
                    await this.notificationService.notifyUser({
                        userId,
                        message: `Organization ${organization.name} has been successfully verified`,
                        type: 'verification_success',
                    }, { session });
                } else {
                    await this.notificationService.notifyUser({
                        userId,
                        message: `Verification failed for organization ${organization.name}`,
                        type: 'verification_failed',
                    }, { session });
                }

                metricsCollector.increment('organization.verified', { organizationId, status: verificationResult.success ? 'verified' : 'failed' });
                metricsCollector.timing('organization.verify_time', Date.now() - startTime);

                await session.commitTransaction();
                return verificationResult;
            } catch (error) {
                await session.abortTransaction();
                throw error;
            } finally {
                session.endSession();
            }
        } catch (error) {
            logger.error(`Verification failed for organization ${organizationId}:`, { error: error.message });
            metricsCollector.increment('organization.verify_failed', { organizationId });
            throw error instanceof AppError ? error : new AppError('Failed to verify organization', 424);
        }
    }

    /**
     * Get organization analytics
     * @param {String} organizationId - Organization ID
     * @returns {Promise<Object>} - Analytics data
     */
    async getOrganizationAnalytics(organizationId) {
        const startTime = Date.now();
        const cacheKey = `organization_analytics:${organizationId}`;

        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('organization.analytics_cache_hit', { organizationId });
                return cached;
            }

            const organization = await Organization.findById(organizationId)
                .select('analytics')
                .lean();
            if (!organization || organization.status === 'deleted') {
                throw new AppError('Organization not found', 404);
            }

            const analytics = this.computeAnalytics(organization.analytics);
            await cacheService.set(cacheKey, analytics, 300, [`organization_analytics:${organizationId}`]);

            metricsCollector.increment('organization.analytics_fetched', { organizationId });
            metricsCollector.timing('organization.analytics_time', Date.now() - startTime);
            return analytics;
        } catch (error) {
            logger.error(`Failed to fetch analytics for organization ${organizationId}:`, { error: error.message });
            metricsCollector.increment('organization.analytics_failed', { organizationId });
            throw error instanceof AppError ? error : new AppError('Failed to fetch organization analytics', 500);
        }
    }

    /**
     * Bulk create organizations
     * @param {Array} organizationsData - Array of organization data
     * @param {Object} options - Mongoose session options and request metadata
     * @returns {Promise<Array>} - Created organizations
     */
    async bulkCreateOrganizations(organizationsData, options = {}) {
        const startTime = Date.now();
        const { userId } = options.request || {};

        if (!Array.isArray(organizationsData) || organizationsData.length === 0 || organizationsData.length > 20) {
            throw new AppError('Invalid or too many organizations (max 20)', 400);
        }

        await createLimiter({ userId }, null, () => { });

        const session = options.session || await mongoose.startSession();
        try {
            if (!options.session) session.startTransaction();

            const validatedOrganizations = [];
            for (const orgData of organizationsData) {
                const validation = validateOrganization(orgData);
                if (!validation.valid) {
                    throw new AppError(`Validation failed for organization: ${validation.message}`, 400);
                }

                const sanitizedData = this.sanitizeInput(orgData);
                sanitizedData.name = sanitizedData.name?.trim();
                sanitizedData.description = sanitizedData.description ? sanitizeHtml(sanitizedData.description) : null;

                const existingOrg = await Organization.findOne({ name: sanitizedData.name, status: { $ne: 'deleted' } }).session(session);
                if (existingOrg) {
                    throw new AppError(`Organization with name ${sanitizedData.name} already exists`, 409);
                }

                validatedOrganizations.push({
                    ...sanitizedData,
                    createdBy: userId,
                    metadata: {
                        ...sanitizedData.metadata,
                        createdBy: {
                            userId,
                            ip: options.request?.ip || 'unknown',
                            userAgent: options.request?.userAgent || 'unknown',
                            location: options.request?.geoip || { country: 'unknown', city: 'unknown' },
                            referrer: options.request?.referrer || 'direct',
                        },
                        importSource: sanitizedData.metadata?.importSource || 'bulk',
                        version: 1,
                        updateCount: 0,
                    },
                    analytics: {
                        views: { total: 0, unique: 0, byDate: [] },
                        endorsements: { total: 0, byUser: [] },
                        interactions: { total: 0, byType: {} },
                    },
                    verification: {
                        status: 'pending',
                        confidence: 0,
                        verifiedBy: null,
                        verifiedAt: null,
                        details: [],
                    },
                    status: 'pending',
                    privacy: {
                        isPublic: false,
                        showDetails: true,
                        searchable: true,
                    },
                });
            }

            const organizations = await Organization.insertMany(validatedOrganizations, { session });

            for (const org of organizations) {
                this.processNewOrganizationAsync(org._id, userId).catch((err) => {
                    logger.error(`Async processing failed for organization ${org._id}:`, err);
                });
            }

            metricsCollector.increment('organization.bulk_created', { userId, count: organizations.length });
            metricsCollector.timing('organization.bulk_create_time', Date.now() - startTime);

            if (!options.session) await session.commitTransaction();
            return organizations;
        } catch (error) {
            if (!options.session) await session.abortTransaction();
            logger.error(`Bulk organization creation failed for user ${userId}:`, { error: error.message });
            metricsCollector.increment('organization.bulk_create_failed', { userId });
            throw error instanceof AppError ? error : new AppError('Failed to bulk create organizations', 500);
        } finally {
            if (!options.session) session.endSession();
        }
    }

    /**
     * Index organization for search
     * @param {Object} organization - Organization document
     * @returns {Promise<void>}
     */
    async indexForSearch(organization) {
        try {
            await elasticsearchClient.index({
                index: 'organizations',
                id: organization._id.toString(),
                body: {
                    name: organization.name,
                    type: organization.type,
                    status: organization.status,
                    searchable: organization.privacy.searchable,
                    createdAt: organization.createdAt,
                },
            });
            metricsCollector.increment('organization.indexed', { organizationId: organization._id });
        } catch (error) {
            logger.error(`Failed to index organization ${organization._id}:`, { error: error.message });
            metricsCollector.increment('organization.index_failed', { organizationId: organization._id });
        }
    }

    /**
     * Create backup of organization
     * @param {String} organizationId - Organization ID
     * @param {String} action - Action type
     * @param {String} userId - User ID
     * @param {Object} options - Mongoose session options
     * @returns {Promise<void>}
     */
    async createBackup(organizationId, action, userId, options = {}) {
        try {
            const organization = await Organization.findById(organizationId).session(options.session);
            if (!organization) return;

            const backupKey = `backups/organizations/${organizationId}/${uuidv4()}.json`;
            await s3Client.upload({
                Bucket: 'user-backups',
                Key: backupKey,
                Body: Buffer.from(JSON.stringify(organization)),
                ContentType: 'application/json',
            }).promise();

            logger.info(`Backup created for organization ${organizationId} by ${userId} for action ${action}`);
            metricsCollector.increment('organization.backup_created', { organizationId, action });
        } catch (error) {
            logger.error(`Backup failed for organization ${organizationId}:`, { error: error.message });
            metricsCollector.increment('organization.backup_failed', { organizationId });
        }
    }

    /**
     * Update organization analytics
     * @param {String} organizationId - Organization ID
     * @param {String} type - Analytics type (view/interaction/endorsement)
     * @param {String} userId - User ID
     * @returns {Promise<void>}
     */
    async updateAnalytics(organizationId, type, userId) {
        const startTime = Date.now();
        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const organization = await Organization.findById(organizationId).session(session);
            if (!organization || organization.status === 'deleted') {
                throw new AppError('Organization not found', 404);
            }

            const today = moment().startOf('day').toDate();
            if (type === 'view') {
                organization.analytics.views.total += 1;
                if (!organization.analytics.views.byDate) organization.analytics.views.byDate = [];
                const viewEntry = organization.analytics.views.byDate.find(v => v.date.toDateString() === today.toDateString());
                if (viewEntry) {
                    viewEntry.count += 1;
                } else {
                    organization.analytics.views.byDate.push({ date: today, count: 1 });
                }
            } else if (type === 'endorsement') {
                organization.analytics.endorsements.total += 1;
                organization.analytics.endorsements.byUser.push({ userId, timestamp: new Date() });
            } else if (type === 'interaction') {
                organization.analytics.interactions.total += 1;
                organization.analytics.interactions.byType[options.interactionType || 'general'] =
                    (organization.analytics.interactions.byType[options.interactionType || 'general'] || 0) + 1;
            }

            await organization.save({ session });
            await cacheService.deletePattern(`organization_analytics:${organizationId}:*`);

            metricsCollector.increment(`organization.${type}_recorded`, { organizationId });
            metricsCollector.timing(`organization.${type}_update_time`, Date.now() - startTime);

            await session.commitTransaction();
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Failed to update ${type} analytics for organization ${organizationId}:`, { error: error.message });
            metricsCollector.increment(`organization.${type}_update_failed`, { organizationId });
            throw error instanceof AppError ? error : new AppError(`Failed to update ${type} analytics`, 500);
        } finally {
            session.endSession();
        }
    }

    /**
     * Compute analytics data
     * @param {Object} analytics - Analytics data
     * @returns {Object} - Computed analytics
     */
    computeAnalytics(analytics) {
        const viewsByMonth = analytics.views.byDate.reduce((acc, entry) => {
            const month = moment(entry.date).format('YYYY-MM');
            acc[month] = (acc[month] || 0) + entry.count;
            return acc;
        }, {});

        return {
            totalViews: analytics.views.total || 0,
            uniqueViews: analytics.views.unique || 0,
            viewsByMonth,
            totalEndorsements: analytics.endorsements.total || 0,
            totalInteractions: analytics.interactions.total || 0,
            interactionsByType: analytics.interactions.byType || {},
        };
    }

    /**
     * Sanitize input data
     * @param {Object} data - Input data
     * @returns {Object} - Sanitized data
     */
    sanitizeInput(data) {
        const sanitized = { ...data };
        if (data.description) sanitized.description = sanitizeHtml(data.description);
        return sanitized;
    }

    /**
     * Sanitize update data
     * @param {Object} updates - Update data
     * @returns {Object} - Sanitized updates
     */
    sanitizeUpdates(updates) {
        const allowedFields = [
            'name',
            'description',
            'type',
            'address',
            'website',
            'contacts',
            'tags',
            'privacy',
            'settings',
        ];
        const sanitized = {};
        for (const [key, value] of Object.entries(updates)) {
            if (allowedFields.includes(key)) {
                sanitized[key] = key === 'description' ? sanitizeHtml(value) : value;
            }
        }
        return sanitized;
    }

    /**
     * Process new organization asynchronously
     * @param {String} organizationId - Organization ID
     * @param {String} userId - User ID
     * @returns {Promise<void>}
     */
    async processNewOrganizationAsync(organizationId, userId) {
        try {
            const organization = await Organization.findById(organizationId);
            if (!organization) return;

            await this.circuitBreaker.fire(async () => {
                await retry(() => this.verificationService.verifyOrganization({
                    organizationId,
                    name: organization.name,
                    type: organization.type,
                    website: organization.website,
                }), this.retryConfig);
            });

            await this.indexForSearch(organization);
            metricsCollector.increment('organization.async_processed', { organizationId });
        } catch (error) {
            logger.error(`Async processing failed for organization ${organizationId}:`, { error: error.message });
            metricsCollector.increment('organization.async_processing_failed', { organizationId });
        }
    }

    /**
     * Process external verification
     * @param {String} organizationId - Organization ID
     * @param {String} userId - User ID
     * @returns {Promise<void>}
     */
    async processExternalVerification(organizationId, userId) {
        try {
            const organization = await Organization.findById(organizationId);
            if (!organization) return;

            const verificationResult = await this.circuitBreaker.fire(async () => {
                return await retry(() => this.verificationService.verifyOrganization({
                    organizationId,
                    name: organization.name,
                    type: organization.type,
                    website: organization.website,
                }), this.retryConfig);
            });

            organization.verification = {
                status: verificationResult.success ? 'verified' : 'failed',
                confidence: verificationResult.confidence || 0,
                verifiedBy: verificationResult.verifiedBy || 'external_api',
                verifiedAt: new Date(),
                details: verificationResult.details || [],
            };

            await organization.save();
            await this.indexForSearch(organization);

            metricsCollector.increment('organization.verification_processed', { organizationId });
        } catch (error) {
            logger.error(`External verification failed for organization ${organizationId}:`, { error: error.message });
            metricsCollector.increment('organization.verification_failed', { organizationId });
        }
    }
}

export default new OrganizationService();