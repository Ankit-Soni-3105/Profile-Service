import Company from '../models/Company.js';
import CompanyService from '../services/CompanyService.js';
import VerificationService from '../services/VerificationService.js';
import MediaService from '../services/MediaService.js';
import TemplateService from '../services/TemplateService.js';
import NotificationService from '../services/NotificationService.js';
import { validateCompany, sanitizeInput } from '../validations/company.validation.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { catchAsync } from '../handler/catchAsync.js';
import { ApiResponse } from '../utils/response.js';
import { createRateLimiter } from '../utils/rateLimiter.js';
import { cacheService } from '../services/cache.service.js';
import { eventEmitter } from '../events/events.js';
import { metricsCollector } from '../utils/metrics.js';
import mongoose from 'mongoose';
import sanitizeHtml from 'sanitize-html';

// Rate limiters with enhanced configuration for scalability
const createCompanyLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 15, // 15 creates per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_company_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const updateCompanyLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 25, // 25 updates per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_company_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const verificationLimiter = createRateLimiter({
    windowMs: 30 * 60 * 1000, // 30 minutes
    max: 5, // 5 verification requests per 30 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `verify_company_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const bulkOperationsLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // 3 bulk operations per hour
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_company_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const mediaUploadLimiter = createRateLimiter({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 10, // 10 media uploads per 10 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `media_company_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

class CompanyController {
    constructor() {
        this.companyService = CompanyService;
        this.verificationService = VerificationService;
        this.mediaService = MediaService;
        this.templateService = TemplateService;
        this.notificationService = NotificationService;
    }

    /**
     * Create a new company
     * POST /api/v1/companies/:userId
     */
    createCompany = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const companyData = req.body;
        const requestingUserId = req.user.id;

        // Validate access permissions
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied: Cannot create company for another user', 403));
        }

        // Apply rate limiting
        await createCompanyLimiter(req, res, () => { });

        // Validate input data
        const validation = validateCompany(companyData);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        // Sanitize input
        const sanitizedData = sanitizeInput(companyData);

        // Check user limits
        const userCompanyCount = await Company.countDocuments({
            userId,
            'status': { $ne: 'deleted' },
        }).cache({ ttl: 300, key: `user_company_count_${userId}` });

        const limits = this.getUserLimits(req.user.accountType);
        if (userCompanyCount >= limits.maxCompanies) {
            return next(new AppError(`Company limit reached (${limits.maxCompanies})`, 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            // Create company with service
            const company = await this.companyService.createCompany({
                ...sanitizedData,
                userId,
                metadata: {
                    ...sanitizedData.metadata,
                    createdBy: {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        location: req.geoip,
                    },
                },
            }, { session });

            // Start async processing
            this.processNewCompanyAsync(company._id, requestingUserId)
                .catch((err) => logger.error(`Async processing failed for company ${company._id}:`, err));

            // Log metrics
            metricsCollector.increment('company.created', {
                userId,
                industry: company.industry,
                templateUsed: !!company.templateId,
            });

            // Emit event
            eventEmitter.emit('company.created', {
                companyId: company._id,
                userId,
                templateId: company.templateId,
            });

            // Create backup
            if (company.settings?.autoBackup) {
                this.companyService.createBackup(company._id, 'create', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for company ${company._id}:`, err));
            }

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`Company created successfully: ${company._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Company created successfully',
                data: {
                    id: company._id,
                    userId: company.userId,
                    name: company.name,
                    status: company.status,
                    createdAt: company.createdAt,
                    processingStatus: 'started',
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Company creation failed for user ${userId}:`, error);
            metricsCollector.increment('company.create_failed', { userId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.code === 11000) {
                return next(new AppError('Company with this name already exists', 409));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out', 504));
            }

            return next(new AppError('Failed to create company', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get user's companies with filtering and pagination
     * GET /api/v1/companies/:userId
     */
    getCompanies = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;

        // Validate access permissions
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const {
            page = 1,
            limit = 20,
            status,
            industry,
            search,
            sortBy = 'recent',
            templateId,
            tags,
            startDate,
            endDate,
            includeAnalytics = 'false',
        } = req.query;

        // Build query
        const query = this.buildCompanyQuery({
            userId,
            status,
            industry,
            search,
            templateId,
            tags,
            startDate,
            endDate,
        });

        // Build sort option
        const sortOption = this.buildSortOption(sortBy);

        // Pagination
        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit))); // Max 100 items
        const skip = (pageNum - 1) * limitNum;

        // Cache key
        const cacheKey = `companies:${userId}:${JSON.stringify({
            page: pageNum,
            limit: limitNum,
            status,
            industry,
            search,
            sortBy,
            templateId,
            tags,
            startDate,
            endDate,
        })}`;

        try {
            // Try cache first
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('company.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            // Query database with optimized read preference
            const [companies, totalCount] = await Promise.all([
                Company.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select(this.getSelectFields(includeAnalytics === 'true'))
                    .populate('templateId', 'name category')
                    .lean(),
                Company.countDocuments(query).cache({ ttl: 300, key: `company_count_${userId}` }),
            ]);

            // Process companies data
            const processedCompanies = await Promise.all(
                companies.map((comp) => this.processCompanyData(comp, includeAnalytics === 'true')),
            );

            const totalPages = Math.ceil(totalCount / limitNum);
            const hasNext = pageNum < totalPages;
            const hasPrev = pageNum > 1;

            const result = {
                companies: processedCompanies,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages,
                    hasNext,
                    hasPrev,
                    nextPage: hasNext ? pageNum + 1 : null,
                    prevPage: hasPrev ? pageNum - 1 : null,
                },
                filters: {
                    status: status || 'all',
                    industry: industry || 'all',
                    sortBy,
                    search: search || null,
                },
            };

            // Cache result with distributed Redis
            await cacheService.set(cacheKey, result, 300); // 5 minutes

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('company.fetched', {
                userId,
                count: companies.length,
                cached: false,
            });
            logger.info(`Fetched ${companies.length} companies for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch companies for user ${userId}:`, error);
            metricsCollector.increment('company.fetch_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid query parameters', 400));
            }
            return next(new AppError('Failed to fetch companies', 500));
        }
    });

    /**
     * Get single company by ID
     * GET /api/v1/companies/:userId/:id
     */
    getCompanyById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { includeAnalytics = 'false', includeVerification = 'false' } = req.query;

        try {
            const cacheKey = `company:${id}:${userId}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('company.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const company = await Company.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .populate('templateId', 'name category')
                .cache({ ttl: 600, key: cacheKey });

            if (!company) {
                return next(new AppError('Company not found', 404));
            }

            // Check access permissions
            const hasAccess = this.checkCompanyAccess(company, requestingUserId, req.user.isAdmin);
            if (!hasAccess) {
                return next(new AppError('Access denied', 403));
            }

            // Increment view count (async)
            if (requestingUserId !== userId) {
                company.incrementViews(true)
                    .catch((err) => logger.error(`View increment failed for company ${id}:`, err));
            }

            // Process response data
            const responseData = this.processCompanyData(company.toObject(), includeAnalytics === 'true', includeVerification === 'true');

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('company.viewed', {
                userId,
                viewerId: requestingUserId,
                isOwner: userId === requestingUserId,
            });
            logger.info(`Fetched company ${id} for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: responseData });
        } catch (error) {
            logger.error(`Failed to fetch company ${id}:`, error);
            metricsCollector.increment('company.view_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid company ID', 400));
            }
            return next(new AppError('Failed to fetch company', 500));
        }
    });

    /**
     * Update company
     * PUT /api/v1/companies/:userId/:id
     */
    updateCompany = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const updates = req.body;

        // Apply rate limiting
        await updateCompanyLimiter(req, res, () => { });

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const company = await Company.findOne({ _id: id, userId }).session(session);
            if (!company) {
                return next(new AppError('Company not found', 404));
            }

            // Validate updates
            const allowedUpdates = this.getAllowedUpdateFields();
            const sanitizedUpdates = this.sanitizeUpdates(updates, allowedUpdates);

            if (Object.keys(sanitizedUpdates).length === 0) {
                return next(new AppError('No valid update fields provided', 400));
            }

            // Create version if description changed
            let versionCreated = false;
            if (sanitizedUpdates.description && sanitizedUpdates.description !== company.description) {
                await company.createVersion(sanitizedUpdates.description, sanitizedUpdates.name || company.name, 'edit', {
                    userId: requestingUserId,
                }, { session });
                versionCreated = true;
            }

            // Update company
            Object.assign(company, sanitizedUpdates);

            // Update audit trail
            company.metadata.lastModifiedBy = {
                userId: requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date(),
            };

            // Trigger re-verification if critical fields changed
            if (sanitizedUpdates.name || sanitizedUpdates.website) {
                company.verification.status = 'pending';
                this.processExternalVerification(company._id, requestingUserId)
                    .catch((err) => logger.error(`Re-verification failed for company ${id}:`, err));
            }

            await company.save({ session });

            // Recalculate quality score
            if (sanitizedUpdates.description) {
                await company.calculateQualityScore({ session });
            }

            // Create backup
            if (company.settings?.autoBackup) {
                this.companyService.createBackup(company._id, 'update', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for company ${id}:`, err));
            }

            // Clear cache
            await cacheService.deletePattern(`company:${id}:*`);
            await cacheService.deletePattern(`companies:${userId}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('company.updated', {
                userId,
                versionCreated,
                fieldsUpdated: Object.keys(sanitizedUpdates).length,
            });

            // Emit event
            eventEmitter.emit('company.updated', {
                companyId: company._id,
                userId,
                changes: Object.keys(sanitizedUpdates),
                versionCreated,
            });

            logger.info(`Company updated successfully: ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Company updated successfully',
                data: {
                    id: company._id,
                    name: company.name,
                    status: company.status,
                    updatedAt: company.updatedAt,
                    versionCreated,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Company update failed for ${id}:`, error);
            metricsCollector.increment('company.update_failed', { userId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out', 504));
            }
            return next(new AppError('Failed to update company', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete company (soft or permanent)
     * DELETE /api/v1/companies/:userId/:id
     */
    deleteCompany = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { permanent = 'false' } = req.query;

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const company = await Company.findOne({ _id: id, userId }).session(session);
            if (!company) {
                return next(new AppError('Company not found', 404));
            }

            if (permanent === 'true') {
                // Permanent deletion
                await Company.findByIdAndDelete(id, { session });
                await this.mediaService.deleteAllMedia(id, 'company', { session });
                this.companyService.deleteAllBackups(id)
                    .catch((err) => logger.error(`Failed to delete backups for ${id}:`, err));
                metricsCollector.increment('company.permanently_deleted', { userId });
            } else {
                // Soft delete
                company.status = 'deleted';
                company.visibility = 'private';
                company.metadata.lastModifiedBy = {
                    userId: requestingUserId,
                    ip: req.ip,
                    userAgent: req.get('User-Agent'),
                    timestamp: new Date(),
                };
                await company.save({ session });
                metricsCollector.increment('company.soft_deleted', { userId });
            }

            // Clear cache
            await cacheService.deletePattern(`company:${id}:*`);
            await cacheService.deletePattern(`companies:${userId}:*`);

            // Emit event
            eventEmitter.emit('company.deleted', {
                companyId: id,
                userId,
                permanent: permanent === 'true',
            });

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`Company ${id} deleted (permanent: ${permanent}) in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: permanent === 'true' ? 'Company permanently deleted' : 'Company moved to trash',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Company deletion failed for ${id}:`, error);
            metricsCollector.increment('company.delete_failed', { userId });
            return next(new AppError('Failed to delete company', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Bulk operations on companies
     * POST /api/v1/companies/:userId/bulk
     */
    bulkOperations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { operation, companyIds, data = {} } = req.body;

        // Apply rate limiting
        await bulkOperationsLimiter(req, res, () => { });

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        // Validate input
        if (!Array.isArray(companyIds) || companyIds.length === 0) {
            return next(new AppError('Company IDs array is required', 400));
        }
        if (companyIds.length > 100) {
            return next(new AppError('Maximum 100 companies can be processed at once', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const query = { _id: { $in: companyIds }, userId };
            const { message } = await this.handleBulkOperation(operation, query, data, requestingUserId, req, { session });

            // Clear cache
            await Promise.all([
                cacheService.deletePattern(`companies:${userId}:*`),
                ...companyIds.map((id) => cacheService.deletePattern(`company:${id}:*`)),
            ]);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('company.bulk_operation', {
                userId,
                operation,
                count: companyIds.length,
            });
            logger.info(`Bulk operation ${operation} completed for ${companyIds.length} companies in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message,
                data: {
                    operation,
                    requested: companyIds.length,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk operation failed for user ${userId}:`, error);
            metricsCollector.increment('company.bulk_operation_failed', { userId, operation });
            return next(new AppError('Bulk operation failed', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get company analytics
     * GET /api/v1/companies/:userId/:id/analytics
     */
    getAnalytics = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { timeframe = '30d', metrics = 'basic' } = req.query;

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        try {
            const cacheKey = `analytics:company:${id}:${timeframe}:${metrics}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('company.analytics_cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const company = await Company.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('analytics verification metadata createdAt')
                .cache({ ttl: 900, key: cacheKey });

            if (!company) {
                return next(new AppError('Company not found', 404));
            }

            const analytics = this.processAnalyticsData(company, timeframe, metrics);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('company.analytics_viewed', { userId });
            logger.info(`Fetched analytics for company ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: analytics });
        } catch (error) {
            logger.error(`Analytics fetch failed for ${id}:`, error);
            metricsCollector.increment('company.analytics_fetch_failed', { userId });
            return next(new AppError('Failed to fetch analytics', 500));
        }
    });

    /**
     * Duplicate company
     * POST /api/v1/companies/:userId/:id/duplicate
     */
    duplicateCompany = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { name, includeVersions = 'false' } = req.body;

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const originalCompany = await Company.findOne({ _id: id, userId }).session(session);
            if (!originalCompany) {
                return next(new AppError('Company not found', 404));
            }

            // Check user limits
            const userCompanyCount = await Company.countDocuments({
                userId,
                'status': { $ne: 'deleted' },
            }).cache({ ttl: 300, key: `user_company_count_${userId}` });

            const limits = this.getUserLimits(req.user.accountType);
            if (userCompanyCount >= limits.maxCompanies) {
                return next(new AppError(`Company limit reached (${limits.maxCompanies})`, 403));
            }

            // Create duplicate
            const duplicateData = originalCompany.toObject();
            delete duplicateData._id;
            delete duplicateData.createdAt;
            delete duplicateData.updatedAt;
            delete duplicateData.analytics;

            duplicateData.name = name || `${originalCompany.name} (Copy)`;
            duplicateData.status = 'draft';
            duplicateData.metadata.createdBy = {
                userId: requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date(),
            };

            if (includeVersions !== 'true') {
                duplicateData.versions = [{
                    versionNumber: 1,
                    description: duplicateData.description,
                    name: duplicateData.name,
                    changeType: 'create',
                    isActive: true,
                }];
            }

            const duplicate = new Company(duplicateData);
            await duplicate.save({ session });

            // Create backup
            if (duplicate.settings?.autoBackup) {
                this.companyService.createBackup(duplicate._id, 'duplicate', requestingUserId, { session })
                    .catch((err) => logger.error(`Auto backup failed for duplicate ${duplicate._id}:`, err));
            }

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('company.duplicated', { userId });
            logger.info(`Company ${id} duplicated as ${duplicate._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Company duplicated successfully',
                data: {
                    originalId: id,
                    duplicateId: duplicate._id,
                    name: duplicate.name,
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Company duplication failed for ${id}:`, error);
            metricsCollector.increment('company.duplicate_failed', { userId });
            return next(new AppError('Failed to duplicate company', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Verify company
     * POST /api/v1/companies/:userId/:id/verify
     */
    verifyCompany = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        // Apply rate limiting
        await verificationLimiter(req, res, () => { });

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const company = await Company.findOne({ _id: id, userId }).session(session);
            if (!company) {
                return next(new AppError('Company not found', 404));
            }

            // Trigger verification with circuit breaker
            const verificationResult = await this.processExternalVerification(company._id, requestingUserId);
            if (!verificationResult.success) {
                return next(new AppError('Verification failed: ' + verificationResult.message, 424));
            }

            company.verification = {
                status: verificationResult.status,
                confidence: verificationResult.confidence,
                verifiedBy: verificationResult.verifiedBy,
                verifiedAt: new Date(),
                details: verificationResult.details,
            };

            await company.save({ session });

            // Notify user
            this.notificationService.notifyUser(userId, {
                type: 'verification_completed',
                message: `Company "${company.name}" verification ${verificationResult.status}`,
                data: { companyId: id },
            }).catch((err) => logger.error(`Notification failed for company ${id}:`, err));

            // Clear cache
            await cacheService.deletePattern(`company:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('company.verified', {
                userId,
                status: verificationResult.status,
            });
            logger.info(`Company ${id} verified in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Company verification completed',
                data: company.verification,
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Verification failed for company ${id}:`, error);
            metricsCollector.increment('company.verify_failed', { userId });
            if (error.message.includes('timeout')) {
                return next(new AppError('External API timeout', 503));
            }
            return next(new AppError('Failed to verify company', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Upload media for company
     * POST /api/v1/companies/:userId/:id/media
     */
    uploadMedia = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const files = req.files;

        // Apply rate limiting
        await mediaUploadLimiter(req, res, () => { });

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const company = await Company.findOne({ _id: id, userId }).session(session);
            if (!company) {
                return next(new AppError('Company not found', 404));
            }

            // Validate media
            const validation = this.validateMediaUpload(files, company.media);
            if (!validation.valid) {
                return next(new AppError(validation.message, 422));
            }

            // Process media
            const mediaResults = await this.mediaService.uploadMedia({
                files,
                entityId: id,
                entityType: 'company',
                userId,
            }, { session });

            // Virus scan
            const scanResults = await this.mediaService.scanMedia(mediaResults);
            if (scanResults.some((result) => result.infected)) {
                return next(new AppError('Media upload failed: Infected file detected', 422));
            }

            company.media.push(...mediaResults);
            await company.save({ session });

            // Clear cache
            await cacheService.deletePattern(`company:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('company.media_uploaded', {
                userId,
                count: mediaResults.length,
            });
            logger.info(`Uploaded ${mediaResults.length} media files for company ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Media uploaded successfully',
                data: { media: mediaResults },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Media upload failed for company ${id}:`, error);
            metricsCollector.increment('company.media_upload_failed', { userId });
            return next(new AppError('Failed to upload media', 422));
        } finally {
            session.endSession();
        }
    });

    /**
     * Share company
     * POST /api/v1/companies/:userId/:id/share
     */
    shareCompany = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const { platform } = req.body;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const company = await Company.findOne({ _id: id, userId }).session(session);
            if (!company) {
                return next(new AppError('Company not found', 404));
            }

            // Validate access
            const hasAccess = this.checkCompanyAccess(company, requestingUserId, req.user.isAdmin);
            if (!hasAccess) {
                return next(new AppError('Access denied', 403));
            }

            // Generate shareable link
            const shareLink = this.generateShareableLink(company, platform);

            // Track share
            company.analytics.shares.total += 1;
            company.analytics.shares.byPlatform = {
                ...company.analytics.shares.byPlatform,
                [platform]: (company.analytics.shares.byPlatform[platform] || 0) + 1,
            };
            await company.save({ session });

            // Clear cache
            await cacheService.deletePattern(`company:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('company.shared', { userId, platform });
            logger.info(`Company ${id} shared on ${platform} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Company shared successfully',
                data: { shareLink },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Share failed for company ${id}:`, error);
            metricsCollector.increment('company.share_failed', { userId });
            return next(new AppError('Failed to share company', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Endorse company
     * POST /api/v1/companies/:userId/:id/endorse
     */
    endorseCompany = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const company = await Company.findOne({ _id: id, userId }).session(session);
            if (!company) {
                return next(new AppError('Company not found', 404));
            }

            // Validate connection level
            const isConnected = await this.companyService.checkConnectionLevel(userId, requestingUserId);
            if (!isConnected) {
                return next(new AppError('Must be connected to endorse', 403));
            }

            // Check if already endorsed
            if (company.endorsements.some((e) => e.userId.toString() === requestingUserId)) {
                return next(new AppError('Company already endorsed by this user', 409));
            }

            // Add endorsement
            company.endorsements.push({
                userId: requestingUserId,
                endorsedAt: new Date(),
            });
            await company.save({ session });

            // Notify user
            this.notificationService.notifyUser(userId, {
                type: 'endorsement',
                message: `Your company "${company.name}" was endorsed`,
                data: { companyId: id, endorserId: requestingUserId },
            }).catch((err) => logger.error(`Notification failed for endorsement ${id}:`, err));

            // Clear cache
            await cacheService.deletePattern(`company:${id}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('company.endorsed', { userId, endorserId: requestingUserId });
            logger.info(`Company ${id} endorsed in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Company endorsed successfully',
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Endorsement failed for company ${id}:`, error);
            metricsCollector.increment('company.endorse_failed', { userId });
            return next(new AppError('Failed to endorse company', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get verification status
     * GET /api/v1/companies/:userId/:id/verification
     */
    getVerificationStatus = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        try {
            const cacheKey = `verification:company:${id}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('company.verification_cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const company = await Company.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .select('verification')
                .cache({ ttl: 60, key: cacheKey });

            if (!company) {
                return next(new AppError('Company not found', 404));
            }

            // Validate access
            if (userId !== requestingUserId && !req.user.isAdmin) {
                return next(new AppError('Access denied', 403));
            }

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('company.verification_viewed', { userId });
            logger.info(`Fetched verification status for company ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                data: company.verification,
            });
        } catch (error) {
            logger.error(`Verification status fetch failed for ${id}:`, error);
            metricsCollector.increment('company.verification_fetch_failed', { userId });
            return next(new AppError('Failed to fetch verification status', 500));
        }
    });

    /**
     * Get trending companies
     * GET /api/v1/companies/trending
     */
    getTrendingCompanies = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { timeframe = '7d', industry, limit = 20 } = req.query;

        const cacheKey = `trending:companies:${timeframe}:${industry || 'all'}:${limit}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('company.trending_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const companies = await this.companyService.getTrendingCompanies(timeframe, industry, parseInt(limit));
            const processedCompanies = await Promise.all(
                companies.map((comp) => this.processCompanyData(comp, false)),
            );

            const result = { companies: processedCompanies };
            await cacheService.set(cacheKey, result, 3600); // 1 hour

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('company.trending_viewed', { count: companies.length });
            logger.info(`Fetched ${companies.length} trending companies in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch trending companies:`, error);
            metricsCollector.increment('company.trending_fetch_failed');
            return next(new AppError('Failed to fetch trending companies', 500));
        }
    });

    /**
     * Get companies by industry
     * GET /api/v1/companies/industries/:industry
     */
    getCompaniesByIndustry = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { industry } = req.params;
        const { page = 1, limit = 20, sortBy = 'recent' } = req.query;

        const cacheKey = `companies:industry:${industry}:${page}:${limit}:${sortBy}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('company.industry_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const query = this.buildCompanyQuery({ industry });
            const sortOption = this.buildSortOption(sortBy);
            const pageNum = Math.max(1, parseInt(page));
            const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
            const skip = (pageNum - 1) * limitNum;

            const [companies, totalCount] = await Promise.all([
                Company.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select(this.getSelectFields(false))
                    .lean(),
                Company.countDocuments(query).cache({ ttl: 300, key: `company_industry_count_${industry}` }),
            ]);

            const processedCompanies = await Promise.all(
                companies.map((comp) => this.processCompanyData(comp, false)),
            );

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                companies: processedCompanies,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages,
                },
            };

            await cacheService.set(cacheKey, result, 1800); // 30 minutes

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('company.industry_viewed', { industry, count: companies.length });
            logger.info(`Fetched ${companies.length} companies for industry ${industry} in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch companies for industry ${industry}:`, error);
            metricsCollector.increment('company.industry_fetch_failed', { industry });
            return next(new AppError('Failed to fetch companies by industry', 500));
        }
    });

    /**
     * Search companies
     * GET /api/v1/companies/search
     */
    searchCompanies = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { query, page = 1, limit = 20, filters = {} } = req.query;

        const cacheKey = `search:companies:${query}:${JSON.stringify(filters)}:${page}:${limit}`;
        try {
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('company.search_cache_hit');
                return ApiResponse.success(res, cached);
            }

            const searchResults = await this.companyService.searchCompanies(query, filters, {
                page: parseInt(page),
                limit: parseInt(limit),
            });

            const result = {
                companies: searchResults.hits,
                totalCount: searchResults.total,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    totalPages: Math.ceil(searchResults.total / parseInt(limit)),
                },
            };

            await cacheService.set(cacheKey, result, 300); // 5 minutes

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('company.searched', { query, count: searchResults.hits.length });
            logger.info(`Search returned ${searchResults.hits.length} companies in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Search failed for query ${query}:`, error);
            metricsCollector.increment('company.search_failed');
            return next(new AppError('Failed to search companies', 500));
        }
    });

    /**
     * Export companies as CSV
     * GET /api/v1/companies/:userId/export
     */
    exportCompanies = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { format = 'csv', fields = 'name,description,industry,status' } = req.query;

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        try {
            const companies = await Company.find({ userId, status: { $ne: 'deleted' } })
                .read('secondaryPreferred')
                .select(fields.split(',').join(' '))
                .lean();

            const csvData = this.convertToCSV(companies, fields.split(','));
            const filename = `companies_${userId}_${Date.now()}.csv`;

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('company.exported', { userId, format });
            logger.info(`Exported ${companies.length} companies for user ${userId} in ${responseTime}ms`);

            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            return res.send(csvData);
        } catch (error) {
            logger.error(`Export failed for user ${userId}:`, error);
            metricsCollector.increment('company.export_failed', { userId });
            return next(new AppError('Failed to export companies', 500));
        }
    });

    // Helper Methods

    /**
     * Process new company asynchronously
     */
    async processNewCompanyAsync(companyId, userId) {
        try {
            const session = await mongoose.startSession();
            session.startTransaction();

            const company = await Company.findById(companyId).session(session);
            if (!company) {
                await session.abortTransaction();
                session.endSession();
                return;
            }

            // Extract keywords
            const keywords = await this.companyService.extractKeywords(company.description);
            company.keywords = keywords.slice(0, 20);

            // Calculate quality score
            await company.calculateQualityScore({ session });

            // Auto-verify
            await this.processExternalVerification(companyId, userId);

            // Index for search
            await this.companyService.indexForSearch(company);

            // Update user stats
            await this.companyService.updateUserStats(userId, { session });

            await company.save({ session });
            await session.commitTransaction();
            logger.info(`Async processing completed for company ${companyId}`);
        } catch (error) {
            logger.error(`Async processing failed for company ${companyId}:`, error);
        } finally {
            session.endSession();
        }
    }

    /**
     * Check access permissions
     */
    checkCompanyAccess(company, requestingUserId, isAdmin) {
        if (isAdmin) return true;
        if (company.userId.toString() === requestingUserId) return true;
        if (company.visibility === 'public') return true;
        return false;
    }

    /**
     * Get allowed update fields
     */
    getAllowedUpdateFields() {
        return [
            'name',
            'description',
            'industry',
            'tags',
            'keywords',
            'website',
            'location',
            'visibility',
            'status',
            'templateId',
        ];
    }

    /**
     * Sanitize updates
     */
    sanitizeUpdates(updates, allowedFields) {
        const sanitized = {};
        allowedFields.forEach((field) => {
            if (updates[field] !== undefined) {
                sanitized[field] = field === 'description' ? sanitizeHtml(updates[field]) : sanitizeInput(updates[field]);
            }
        });
        return sanitized;
    }

    /**
     * Process analytics data
     */
    processAnalyticsData(company, timeframe, metrics) {
        const analytics = company.analytics || {};
        const timeframeDate = new Date();

        switch (timeframe) {
            case '7d':
                timeframeDate.setDate(timeframeDate.getDate() - 7);
                break;
            case '30d':
                timeframeDate.setDate(timeframeDate.getDate() - 30);
                break;
            case '90d':
                timeframeDate.setDate(timeframeDate.getDate() - 90);
                break;
            default:
                timeframeDate.setDate(timeframeDate.getDate() - 30);
        }

        const filteredAnalytics = {
            views: {
                total: analytics.views?.total || 0,
                unique: analytics.views?.unique || 0,
                byDate: (analytics.views?.byDate || []).filter((v) => new Date(v.date) >= timeframeDate),
            },
            shares: {
                total: analytics.shares?.total || 0,
                byPlatform: analytics.shares?.byPlatform || {},
            },
            endorsements: analytics.endorsements?.total || 0,
        };

        if (metrics === 'detailed') {
            filteredAnalytics.verification = company.verification;
        }

        return filteredAnalytics;
    }

    /**
     * Get user limits
     */
    getUserLimits(accountType) {
        const limits = {
            free: { maxCompanies: 5, maxMedia: 5, maxSizeMB: 50 },
            premium: { maxCompanies: 25, maxMedia: 20, maxSizeMB: 200 },
            enterprise: { maxCompanies: 100, maxMedia: 50, maxSizeMB: 500 },
        };
        return limits[accountType] || limits.free;
    }

    /**
     * Build query for fetching companies
     */
    buildCompanyQuery({ userId, status, industry, search, templateId, tags, startDate, endDate }) {
        const query = { userId, status: { $ne: 'deleted' } };

        if (status && status !== 'all') {
            query.status = status;
        }
        if (industry && industry !== 'all') {
            query.industry = industry;
        }
        if (templateId) {
            query.templateId = templateId;
        }
        if (tags) {
            const tagArray = tags.split(',').map((tag) => tag.trim().toLowerCase());
            query.tags = { $in: tagArray };
        }
        if (startDate || endDate) {
            query.foundedDate = {};
            if (startDate) query.foundedDate.$gte = new Date(startDate);
            if (endDate) query.foundedDate.$lte = new Date(endDate);
        }
        if (search) {
            query.$text = { $search: search };
        }

        return query;
    }

    /**
     * Build sort option
     */
    buildSortOption(sortBy) {
        const sortOptions = {
            recent: { updatedAt: -1 },
            oldest: { createdAt: 1 },
            name: { name: 1 },
            popular: { 'analytics.views.total': -1 },
            quality: { 'qualityScore': -1 },
            verified: { 'verification.confidence': -1 },
        };
        return sortOptions[sortBy] || sortOptions.recent;
    }

    /**
     * Get select fields
     */
    getSelectFields(includeAnalytics) {
        const baseFields = 'name description status industry tags keywords website location visibility createdAt updatedAt templateId';
        return includeAnalytics ? baseFields + ' analytics' : baseFields;
    }

    /**
     * Process company data
     */
    async processCompanyData(company, includeAnalytics = false, includeVerification = false) {
        const processed = {
            ...company,
        };

        if (!includeAnalytics) {
            delete processed.analytics;
        }
        if (!includeVerification) {
            delete processed.verification;
        }

        return processed;
    }

    /**
     * Calculate trending score
     */
    calculateTrendingScore(company) {
        const viewsWeight = 0.4;
        const sharesWeight = 0.3;
        const endorsementsWeight = 0.2;
        const recencyWeight = 0.1;

        const daysSinceCreated = (Date.now() - new Date(company.createdAt)) / (1000 * 60 * 60 * 24);
        const recencyScore = Math.max(0, 10 - daysSinceCreated);

        return (
            (company.analytics.views.total * viewsWeight) +
            (company.analytics.shares.total * sharesWeight) +
            (company.endorsements.length * endorsementsWeight) +
            (recencyScore * recencyWeight)
        );
    }

    /**
     * Validate media upload
     */
    validateMediaUpload(files, existingMedia) {
        const limits = this.getUserLimits('premium'); // Use premium for validation
        const totalSize = files.reduce((sum, file) => sum + file.size, 0);
        const totalMedia = existingMedia.length + files.length;

        if (totalMedia > limits.maxMedia) {
            return { valid: false, message: `Maximum ${limits.maxMedia} media files allowed` };
        }
        if (totalSize > limits.maxSizeMB * 1024 * 1024) {
            return { valid: false, message: `Total media size exceeds ${limits.maxSizeMB}MB` };
        }

        return { valid: true };
    }

    /**
     * Process external verification
     */
    async processExternalVerification(companyId, userId) {
        try {
            const company = await Company.findById(companyId);
            const result = await this.verificationService.verifyCompany({
                companyId,
                userId,
                name: company.name,
                website: company.website,
                location: company.location,
            });

            return result;
        } catch (error) {
            logger.error(`External verification failed for company ${companyId}:`, error);
            return { success: false, message: error.message };
        }
    }

    /**
     * Generate shareable link
     */
    generateShareableLink(company, platform) {
        const baseUrl = process.env.APP_URL || 'https://app.example.com';
        return `${baseUrl}/companies/${company._id}/share?platform=${platform}`;
    }

    /**
     * Handle bulk operation
     */
    async handleBulkOperation(operation, query, data, requestingUserId, req, options = {}) {
        let updateData = {};
        let message = '';

        switch (operation) {
            case 'delete':
                updateData = {
                    status: 'deleted',
                    visibility: 'private',
                    updatedAt: new Date(),
                    'metadata.lastModifiedBy': {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = 'Companies moved to trash';
                break;
            case 'archive':
                updateData = {
                    status: 'archived',
                    updatedAt: new Date(),
                    'metadata.lastModifiedBy': {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = 'Companies archived';
                break;
            case 'publish':
                updateData = {
                    status: 'active',
                    visibility: 'public',
                    updatedAt: new Date(),
                    'metadata.lastModifiedBy': {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = 'Companies published';
                break;
            case 'updateIndustry':
                if (!data.industry) {
                    throw new AppError('Industry is required', 400);
                }
                updateData = {
                    industry: data.industry,
                    updatedAt: new Date(),
                    'metadata.lastModifiedBy': {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = `Industry updated to ${data.industry}`;
                break;
            case 'updateTags':
                if (!Array.isArray(data.tags)) {
                    throw new AppError('Tags array is required', 400);
                }
                updateData = {
                    $addToSet: {
                        tags: { $each: data.tags.map((tag) => tag.trim().toLowerCase()).slice(0, 15) },
                    },
                    updatedAt: new Date(),
                    'metadata.lastModifiedBy': {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = 'Tags updated';
                break;
            case 'updateVisibility':
                if (!data.visibility) {
                    throw new AppError('Visibility is required', 400);
                }
                updateData = {
                    visibility: data.visibility,
                    updatedAt: new Date(),
                    'metadata.lastModifiedBy': {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        timestamp: new Date(),
                    },
                };
                message = `Visibility updated to ${data.visibility}`;
                break;
        }

        const result = await Company.updateMany(query, updateData, options);
        return { message, result };
    }

    /**
     * Convert data to CSV
     */
    convertToCSV(data, fields) {
        const headers = fields.join(',');
        const rows = data.map((item) => {
            return fields.map((field) => {
                const value = item[field] || '';
                return `"${value.toString().replace(/"/g, '""')}"`;
            }).join(',');
        });
        return `${headers}\n${rows.join('\n')}`;
    }
}

export default new CompanyController();