import Organization from '../models/Organization.js';
import User from '../models/User.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { cacheService } from '../services/cache.service.js';
import { metricsCollector } from '../utils/metrics.js';
import { eventEmitter } from '../events/events.js';
import mongoose from 'mongoose';
import AWS from 'aws-sdk';
import { v4 as uuidv4 } from 'uuid';
import { searchClient } from '../config/search.config.js';
import sanitizeHtml from 'sanitize-html';

// Initialize AWS S3 for backups and media
const s3 = new AWS.S3({
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    region: process.env.AWS_REGION,
});

// Search engine configuration
const SEARCH_ENGINE = process.env.SEARCH_ENGINE || 'elasticsearch';
const INDEX_NAME = 'organizations';

// Validation schemas (assumed to be defined in organization.validation.js)
import { validateOrganization, validateMediaUpload } from '../validations/organization.validation.js';

class OrganizationService {
    /**
     * Create a new organization
     * @param {Object} orgData - Organization data
     * @param {Object} options - Options including session
     * @returns {Promise<Object>} - Created organization
     */
    async createOrganization(orgData, options = {}) {
        const startTime = Date.now();
        try {
            const sanitizedData = this.sanitizeData(orgData);
            const organization = new Organization({
                ...sanitizedData,
                status: {
                    workflow: 'pending',
                    isActive: true,
                    isDeleted: false,
                    isArchived: false,
                },
                analytics: { views: 0, shares: 0, endorsements: 0 },
                verification: { status: 'pending', verificationScore: 0 },
            });

            await organization.save(options);
            metricsCollector.increment('organization_service.created');
            logger.info(`Organization created: ${organization._id} in ${Date.now() - startTime}ms`);

            return organization;
        } catch (error) {
            logger.error(`Failed to create organization:`, error);
            metricsCollector.increment('organization_service.create_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Get organization by ID
     * @param {string} id - Organization ID
     * @param {string} userId - Requesting user ID
     * @returns {Promise<Object>} - Organization document
     */
    async getOrganizationById(id, userId) {
        const startTime = Date.now();
        try {
            const cacheKey = `organization:${id}:${userId}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('organization_service.cache_hit');
                return cached;
            }

            const organization = await Organization.findOne({
                _id: id,
                'status.isDeleted': false,
            })
                .read('secondaryPreferred')
                .select('name logo industry verification status analytics metadata members')
                .lean();

            if (!organization) {
                throw new AppError('Organization not found', 404);
            }

            await cacheService.set(cacheKey, organization, 600);
            metricsCollector.increment('organization_service.fetched');
            logger.info(`Fetched organization ${id} in ${Date.now() - startTime}ms`);

            return organization;
        } catch (error) {
            logger.error(`Failed to fetch organization ${id}:`, error);
            metricsCollector.increment('organization_service.fetch_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Update organization
     * @param {string} id - Organization ID
     * @param {string} userId - Requesting user ID
     * @param {Object} updates - Update data
     * @param {Object} options - Options including session and metadata
     * @returns {Promise<Object>} - Updated organization
     */
    async updateOrganization(id, userId, updates, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;
        try {
            const organization = await Organization.findOne({
                _id: id,
                'status.isDeleted': false,
            }).session(session);

            if (!organization) {
                throw new AppError('Organization not found', 404);
            }

            if (!this.hasPermission(userId, organization, 'update')) {
                throw new AppError('Access denied', 403);
            }

            Object.assign(organization, this.sanitizeData(updates));
            organization.metadata.lastModifiedBy = {
                userId: options.requestingUserId || userId,
                ip: options.ip,
                userAgent: options.userAgent,
                timestamp: new Date(),
            };

            await organization.save({ session });
            metricsCollector.increment('organization_service.updated');
            logger.info(`Organization updated: ${id} in ${Date.now() - startTime}ms`);

            return organization;
        } catch (error) {
            logger.error(`Failed to update organization ${id}:`, error);
            metricsCollector.increment('organization_service.update_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Delete organization
     * @param {string} id - Organization ID
     * @param {string} userId - Requesting user ID
     * @param {boolean} permanent - Permanent deletion flag
     * @param {Object} options - Options including session
     */
    async deleteOrganization(id, userId, permanent = false, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;
        try {
            const organization = await Organization.findOne({
                _id: id,
                'status.isDeleted': false,
            }).session(session);

            if (!organization) {
                throw new AppError('Organization not found', 404);
            }

            if (!this.hasPermission(userId, organization, 'delete')) {
                throw new AppError('Access denied', 403);
            }

            if (permanent) {
                await organization.deleteOne({ session });
            } else {
                organization.status.isDeleted = true;
                organization.status.deletedAt = new Date();
                await organization.save({ session });
            }

            metricsCollector.increment(permanent ? 'organization_service.permanently_deleted' : 'organization_service.soft_deleted');
            logger.info(`Organization ${id} deleted (permanent: ${permanent}) in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to delete organization ${id}:`, error);
            metricsCollector.increment('organization_service.delete_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Search organizations
     * @param {string} query - Search query
     * @param {Object} filters - Additional filters
     * @param {Object} options - Pagination options
     * @returns {Promise<Object>} - Search results
     */
    async searchOrganizations(query, filters = {}, options = { page: 1, limit: 20 }) {
        const startTime = Date.now();
        try {
            const searchQuery = this.buildSearchQuery(query, filters);
            let results;

            if (SEARCH_ENGINE === 'algolia') {
                results = await searchClient.search({
                    indexName: INDEX_NAME,
                    query,
                    filters: this.formatAlgoliaFilters(filters),
                    page: options.page - 1,
                    hitsPerPage: options.limit,
                });
            } else {
                results = await searchClient.search({
                    index: INDEX_NAME,
                    body: {
                        query: searchQuery,
                        from: (options.page - 1) * options.limit,
                        size: options.limit,
                    },
                });
            }

            const hits = SEARCH_ENGINE === 'algolia' ? results.hits : results.hits.hits.map((hit) => hit._source);
            const totalHits = SEARCH_ENGINE === 'algolia' ? results.nbHits : results.hits.total.value;

            metricsCollector.increment('organization_service.searched', { count: hits.length });
            logger.info(`Search returned ${hits.length} organizations in ${Date.now() - startTime}ms`);

            return {
                hits,
                totalHits,
                page: options.page,
                limit: options.limit,
                totalPages: Math.ceil(totalHits / options.limit),
            };
        } catch (error) {
            logger.error(`Search failed for query ${query}:`, error);
            metricsCollector.increment('organization_service.search_failed');
            throw new AppError('Failed to search organizations', 500);
        }
    }

    /**
     * Get trending organizations
     * @param {string} timeframe - Timeframe (e.g., '30d')
     * @param {string} industry - Industry filter
     * @param {number} limit - Number of results
     * @returns {Promise<Array>} - Trending organizations
     */
    async getTrendingOrganizations(timeframe, industry, limit) {
        const startTime = Date.now();
        try {
            const cacheKey = `trending_orgs:${timeframe}:${industry || 'all'}:${limit}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('organization_service.trending_cache_hit');
                return cached;
            }

            const query = {
                'status.isDeleted': false,
                'analytics.views': { $gt: 0 },
            };
            if (industry) query.industry = industry;

            const organizations = await Organization.find(query)
                .read('secondaryPreferred')
                .sort({ 'analytics.views': -1 })
                .limit(limit)
                .select('name logo industry verification status analytics')
                .lean();

            await cacheService.set(cacheKey, organizations, 300);
            metricsCollector.increment('organization_service.trending_fetched', { count: organizations.length });
            logger.info(`Fetched ${organizations.length} trending organizations in ${Date.now() - startTime}ms`);

            return organizations;
        } catch (error) {
            logger.error(`Failed to fetch trending organizations:`, error);
            metricsCollector.increment('organization_service.trending_fetch_failed');
            throw new AppError('Failed to fetch trending organizations', 500);
        }
    }

    /**
     * Validate media upload
     * @param {Array} files - Uploaded files
     * @param {Array} existingMedia - Existing media
     * @returns {Object} - Validation result
     */
    validateMediaUpload(files, existingMedia) {
        const startTime = Date.now();
        try {
            const validation = validateMediaUpload(files, existingMedia);
            logger.info(`Media validation completed in ${Date.now() - startTime}ms`);
            return validation;
        } catch (error) {
            logger.error(`Media validation failed:`, error);
            metricsCollector.increment('organization_service.media_validation_failed');
            throw new AppError('Media validation failed', 422);
        }
    }

    /**
     * Index organization for search
     * @param {Object} organization - Organization document
     */
    async indexForSearch(organization) {
        const startTime = Date.now();
        try {
            const indexData = {
                objectID: organization._id.toString(),
                name: organization.name,
                industry: organization.industry,
                description: organization.description,
                status: organization.status.workflow,
                createdAt: organization.createdAt,
            };

            if (SEARCH_ENGINE === 'algolia') {
                await searchClient.saveObject({
                    indexName: INDEX_NAME,
                    body: indexData,
                });
            } else {
                await searchClient.index({
                    index: INDEX_NAME,
                    id: organization._id.toString(),
                    body: indexData,
                });
            }

            metricsCollector.increment('organization_service.indexed');
            logger.info(`Indexed organization ${organization._id} for search in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to index organization ${organization._id}:`, error);
            metricsCollector.increment('organization_service.index_failed');
            throw new AppError('Failed to index organization', 500);
        }
    }

    /**
     * Merge organizations
     * @param {Array<string>} sourceIds - Source organization IDs
     * @param {string} targetId - Target organization ID
     * @param {string} userId - Requesting user ID
     * @param {Object} options - Options including session
     * @returns {Promise<Object>} - Merged organization
     */
    async mergeOrganizations(sourceIds, targetId, userId, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;
        try {
            const targetOrg = await Organization.findOne({
                _id: targetId,
                'status.isDeleted': false,
            }).session(session);

            if (!targetOrg) {
                throw new AppError('Target organization not found', 404);
            }

            if (!this.hasPermission(userId, targetOrg, 'merge')) {
                throw new AppError('Access denied', 403);
            }

            const sourceOrgs = await Organization.find({
                _id: { $in: sourceIds },
                'status.isDeleted': false,
            }).session(session);

            if (sourceOrgs.length !== sourceIds.length) {
                throw new AppError('One or more source organizations not found', 404);
            }

            // Merge logic (example: combine members, analytics, etc.)
            const mergedMembers = [
                ...(targetOrg.members || []),
                ...sourceOrgs.flatMap((org) => org.members || []),
            ].filter((value, index, self) => self.indexOf(value) === index);

            targetOrg.members = mergedMembers;
            targetOrg.analytics.views += sourceOrgs.reduce((sum, org) => sum + (org.analytics.views || 0), 0);
            targetOrg.analytics.shares += sourceOrgs.reduce((sum, org) => sum + (org.analytics.shares || 0), 0);
            targetOrg.metadata.lastModifiedBy = {
                userId,
                ip: options.ip,
                userAgent: options.userAgent,
                timestamp: new Date(),
            };

            // Soft delete source organizations
            for (const org of sourceOrgs) {
                org.status.isDeleted = true;
                org.status.deletedAt = new Date();
                await org.save({ session });
            }

            await targetOrg.save({ session });

            // Update search index
            await this.indexForSearch(targetOrg);

            metricsCollector.increment('organization_service.merged');
            logger.info(`Merged ${sourceIds.length} organizations into ${targetId} in ${Date.now() - startTime}ms`);

            return targetOrg;
        } catch (error) {
            logger.error(`Failed to merge organizations into ${targetId}:`, error);
            metricsCollector.increment('organization_service.merge_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Get organization analytics
     * @param {string} id - Organization ID
     * @param {string} timeframe - Timeframe (e.g., '30d')
     * @returns {Promise<Object>} - Analytics data
     */
    async getOrganizationAnalytics(id, timeframe) {
        const startTime = Date.now();
        try {
            const cacheKey = `org_analytics:${id}:${timeframe}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('organization_service.analytics_cache_hit');
                return cached;
            }

            const organization = await Organization.findById(id)
                .select('analytics metadata')
                .lean();

            if (!organization) {
                throw new AppError('Organization not found', 404);
            }

            const analytics = {
                views: organization.analytics.views || 0,
                shares: organization.analytics.shares || 0,
                endorsements: organization.analytics.endorsements || 0,
                members: organization.members?.length || 0,
                timeframe,
                lastUpdated: organization.metadata.lastModifiedBy?.timestamp || organization.createdAt,
            };

            await cacheService.set(cacheKey, analytics, 300);
            metricsCollector.increment('organization_service.analytics_fetched');
            logger.info(`Fetched analytics for organization ${id} in ${Date.now() - startTime}ms`);

            return analytics;
        } catch (error) {
            logger.error(`Failed to fetch analytics for organization ${id}:`, error);
            metricsCollector.increment('organization_service.analytics_fetch_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Assign roles to organization member
     * @param {string} organizationId - Organization ID
     * @param {string} userId - User ID
     * @param {Array<string>} roles - Roles to assign
     * @param {string} requestingUserId - Requesting user ID
     * @param {Object} options - Options including session
     * @returns {Promise<Object>} - Updated organization
     */
    async assignRoles(organizationId, userId, roles, requestingUserId, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;
        try {
            const organization = await Organization.findById(organizationId).session(session);
            if (!organization) {
                throw new AppError('Organization not found', 404);
            }

            const user = await User.findById(userId).lean();
            if (!user) {
                throw new AppError('User not found', 404);
            }

            organization.members = organization.members || [];
            const memberIndex = organization.members.findIndex((m) => m.userId.toString() === userId);
            if (memberIndex === -1) {
                organization.members.push({ userId, roles });
            } else {
                organization.members[memberIndex].roles = roles;
            }

            organization.metadata.lastModifiedBy = {
                userId: requestingUserId,
                ip: options.ip,
                userAgent: options.userAgent,
                timestamp: new Date(),
            };

            await organization.save({ session });
            metricsCollector.increment('organization_service.roles_assigned');
            logger.info(`Assigned roles to user ${userId} in organization ${organizationId} in ${Date.now() - startTime}ms`);

            return organization;
        } catch (error) {
            logger.error(`Failed to assign roles for organization ${organizationId}:`, error);
            metricsCollector.increment('organization_service.roles_assign_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Get organization members
     * @param {string} organizationId - Organization ID
     * @param {Object} options - Pagination options
     * @returns {Promise<Object>} - Members list
     */
    async getMembers(organizationId, options = { page: 1, limit: 20 }) {
        const startTime = Date.now();
        try {
            const organization = await Organization.findById(organizationId)
                .select('members')
                .lean();

            if (!organization) {
                throw new AppError('Organization not found', 404);
            }

            const page = Math.max(1, options.page);
            const limit = Math.min(100, Math.max(1, options.limit));
            const skip = (page - 1) * limit;

            const members = organization.members || [];
            const paginatedMembers = members.slice(skip, skip + limit);
            const totalCount = members.length;

            metricsCollector.increment('organization_service.members_fetched', { count: paginatedMembers.length });
            logger.info(`Fetched ${paginatedMembers.length} members for organization ${organizationId} in ${Date.now() - startTime}ms`);

            return {
                members: paginatedMembers,
                pagination: {
                    page,
                    limit,
                    totalCount,
                    totalPages: Math.ceil(totalCount / limit),
                },
            };
        } catch (error) {
            logger.error(`Failed to fetch members for organization ${organizationId}:`, error);
            metricsCollector.increment('organization_service.members_fetch_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Get organization statistics
     * @param {string} id - Organization ID
     * @returns {Promise<Object>} - Statistics
     */
    async getOrganizationStats(id) {
        const startTime = Date.now();
        try {
            const cacheKey = `org_stats:${id}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('organization_service.stats_cache_hit');
                return cached;
            }

            const organization = await Organization.findById(id)
                .select('analytics members status createdAt')
                .lean();

            if (!organization) {
                throw new AppError('Organization not found', 404);
            }

            const stats = {
                totalViews: organization.analytics.views || 0,
                totalShares: organization.analytics.shares || 0,
                totalEndorsements: organization.analytics.endorsements || 0,
                memberCount: organization.members?.length || 0,
                status: organization.status.workflow,
                ageInDays: Math.floor((Date.now() - new Date(organization.createdAt)) / (1000 * 60 * 60 * 24)),
            };

            await cacheService.set(cacheKey, stats, 3600);
            metricsCollector.increment('organization_service.stats_fetched');
            logger.info(`Fetched stats for organization ${id} in ${Date.now() - startTime}ms`);

            return stats;
        } catch (error) {
            logger.error(`Failed to fetch stats for organization ${id}:`, error);
            metricsCollector.increment('organization_service.stats_fetch_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Get audit logs
     * @param {string} organizationId - Organization ID
     * @param {Object} options - Options including page, limit, action
     * @returns {Promise<Array>} - Audit logs
     */
    async getAuditLogs(organizationId, options = { page: 1, limit: 20, action: null }) {
        const startTime = Date.now();
        try {
            const page = Math.max(1, options.page);
            const limit = Math.min(100, Math.max(1, options.limit));
            const skip = (page - 1) * limit;

            const query = { organizationId };
            if (options.action) query.action = options.action;

            const logs = await OrganizationAuditLog.find(query) // Assumed model for audit logs
                .skip(skip)
                .limit(limit)
                .lean();

            metricsCollector.increment('organization_service.audit_fetched', { count: logs.length });
            logger.info(`Fetched ${logs.length} audit logs for organization ${organizationId} in ${Date.now() - startTime}ms`);

            return logs;
        } catch (error) {
            logger.error(`Failed to fetch audit logs for organization ${organizationId}:`, error);
            metricsCollector.increment('organization_service.audit_fetch_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Count audit logs
     * @param {string} organizationId - Organization ID
     * @param {string} action - Action filter
     * @returns {Promise<number>} - Total count
     */
    async countAuditLogs(organizationId, action) {
        const startTime = Date.now();
        try {
            const query = { organizationId };
            if (action) query.action = action;

            const count = await OrganizationAuditLog.countDocuments(query);
            logger.info(`Counted ${count} audit logs for organization ${organizationId} in ${Date.now() - startTime}ms`);

            return count;
        } catch (error) {
            logger.error(`Failed to count audit logs for organization ${organizationId}:`, error);
            throw this.handleError(error);
        }
    }

    /**
     * Update user stats
     * @param {string} userId - User ID
     * @param {Object} options - Options including session
     */
    async updateUserStats(userId, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;
        try {
            const user = await User.findById(userId).session(session);
            if (!user) {
                throw new AppError('User not found', 404);
            }

            user.stats = user.stats || {};
            user.stats.organizations = await Organization.countDocuments({
                'members.userId': userId,
                'status.isDeleted': false,
            });

            await user.save({ session });
            logger.info(`Updated stats for user ${userId} in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to update stats for user ${userId}:`, error);
            metricsCollector.increment('organization_service.user_stats_update_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Update organization analytics
     * @param {string} organizationId - Organization ID
     * @param {Object} options - Options including session
     */
    async updateOrganizationAnalytics(organizationId, options = {}) {
        const startTime = Date.now();
        const session = options.session || null;
        try {
            const organization = await Organization.findById(organizationId).session(session);
            if (!organization) {
                throw new AppError('Organization not found', 404);
            }

            organization.analytics = organization.analytics || { views: 0, shares: 0, endorsements: 0 };
            organization.analytics.views += 1; // Example increment
            await organization.save({ session });

            logger.info(`Updated analytics for organization ${organizationId} in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to update analytics for organization ${organizationId}:`, error);
            metricsCollector.increment('organization_service.analytics_update_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Process new organization asynchronously
     * @param {string} organizationId - Organization ID
     * @param {string} userId - User ID
     */
    async processNewOrganizationAsync(organizationId, userId) {
        const startTime = Date.now();
        try {
            const organization = await Organization.findById(organizationId).lean();
            if (!organization) {
                throw new AppError('Organization not found', 404);
            }

            // Index for search
            await this.indexForSearch(organization);

            // Update user stats
            await this.updateUserStats(userId);

            // Create backup
            await this.createBackup(organizationId, 'create', userId);

            metricsCollector.increment('organization_service.async_processed');
            logger.info(`Async processing completed for organization ${organizationId} in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Async processing failed for organization ${organizationId}:`, error);
            metricsCollector.increment('organization_service.async_process_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Create backup
     * @param {string} organizationId - Organization ID
     * @param {string} action - Action type
     * @param {string} userId - User ID
     */
    async createBackup(organizationId, action, userId) {
        const startTime = Date.now();
        try {
            const organization = await Organization.findById(organizationId).lean();
            if (!organization) {
                throw new AppError('Organization not found', 404);
            }

            const backupKey = `org_backup_${organizationId}_${Date.now()}_${uuidv4()}`;
            await s3.upload({
                Bucket: process.env.S3_BACKUP_BUCKET,
                Key: backupKey,
                Body: JSON.stringify({
                    organization,
                    action,
                    userId,
                    timestamp: new Date(),
                }),
                ContentType: 'application/json',
                ServerSideEncryption: 'AES256',
            }).promise();

            metricsCollector.increment('organization_service.backup_created', { action });
            logger.info(`Backup created for organization ${organizationId} (${action}) in ${Date.now() - startTime}ms`);
        } catch (error) {
            logger.error(`Failed to create backup for organization ${organizationId}:`, error);
            metricsCollector.increment('organization_service.backup_failed');
            throw this.handleError(error);
        }
    }

    /**
     * Sanitize data
     * @param {Object} data - Input data
     * @returns {Object} - Sanitized data
     */
    sanitizeData(data) {
        return {
            ...data,
            name: sanitizeHtml(data.name || ''),
            description: sanitizeHtml(data.description || ''),
            industry: sanitizeHtml(data.industry || ''),
            logo: data.logo ? sanitizeHtml(data.logo) : undefined,
        };
    }

    /**
     * Build search query
     * @param {string} query - Search query
     * @param {Object} filters - Filters
     * @returns {Object} - Search query
     */
    buildSearchQuery(query, filters) {
        if (SEARCH_ENGINE === 'algolia') {
            return query;
        }

        return {
            bool: {
                must: query ? { match: { name: query } } : { match_all: {} },
                filter: Object.entries(filters).map(([key, value]) => ({ term: { [key]: value } })),
            },
        };
    }

    /**
     * Format Algolia filters
     * @param {Object} filters - Filters
     * @returns {string} - Algolia filter string
     */
    formatAlgoliaFilters(filters) {
        return Object.entries(filters)
            .map(([key, value]) => `${key}:${value}`)
            .join(' AND ');
    }

    /**
     * Check permissions
     * @param {string} userId - User ID
     * @param {Object} organization - Organization document
     * @param {string} action - Action type
     * @returns {boolean} - Permission granted
     */
    hasPermission(userId, organization, action) {
        const member = organization.members?.find((m) => m.userId.toString() === userId);
        if (!member) return false;

        const roles = member.roles || [];
        const permissions = {
            update: ['admin', 'editor'],
            delete: ['admin'],
            merge: ['admin'],
        };

        return roles.some((role) => permissions[action]?.includes(role));
    }

    /**
     * Handle errors
     * @param {Error} error - Error object
     * @returns {AppError}
     */
    handleError(error) {
        if (error.name === 'ValidationError') {
            return new AppError('Validation failed: ' + error.message, 400);
        }
        if (error.code === 11000) {
            return new AppError('Organization already exists', 409);
        }
        if (error.name === 'CastError') {
            return new AppError('Invalid organization ID', 400);
        }
        if (error.message.includes('timeout')) {
            return new AppError('Operation timed out', 504);
        }
        return new AppError('Operation failed', 500);
    }
}

export default new OrganizationService();