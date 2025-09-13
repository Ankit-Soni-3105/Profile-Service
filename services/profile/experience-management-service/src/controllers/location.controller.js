import Location from '../models/Location.js';
import LocationService from '../services/LocationService.js';
import { validateLocation, sanitizeInput } from '../validations/location.validation.js';
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

// Rate limiters
const createLocationLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 20, // 20 creates per 15 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `create_location_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const updateLocationLimiter = createRateLimiter({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 30, // 30 updates per 5 minutes
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `update_location_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

const bulkOperationsLimiter = createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5, // 5 bulk operations per hour
    skipSuccessfulRequests: true,
    keyGenerator: (req) => `bulk_location_${req.user.id}`,
    redisClient: cacheService.getRedisClient(),
});

class LocationController {
    constructor() {
        this.locationService = LocationService;
    }

    /**
     * Create a new location
     * POST /api/v1/locations/:userId
     */
    createLocation = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const locationData = req.body;
        const requestingUserId = req.user.id;

        // Validate access permissions
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied: Cannot create location for another user', 403));
        }

        // Apply rate limiting
        await createLocationLimiter(req, res, () => { });

        // Validate input data
        const validation = validateLocation(locationData);
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        // Sanitize input
        const sanitizedData = sanitizeInput(locationData);

        // Check user limits
        const userLocationCount = await Location.countDocuments({
            userId,
            status: { $ne: 'deleted' },
        }).cache({ ttl: 300, key: `user_location_count_${userId}` });

        const limits = this.getUserLimits(req.user.accountType);
        if (userLocationCount >= limits.maxLocations) {
            return next(new AppError(`Location limit reached (${limits.maxLocations})`, 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            // Create location
            const location = await this.locationService.createLocation({
                ...sanitizedData,
                userId,
                metadata: {
                    createdBy: {
                        userId: requestingUserId,
                        ip: req.ip,
                        userAgent: req.get('User-Agent'),
                        location: req.geoip,
                    },
                },
            }, { session });

            // Log metrics
            metricsCollector.increment('location.created', { userId, country: location.country });

            // Emit event
            eventEmitter.emit('location.created', { locationId: location._id, userId });

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            logger.info(`Location created successfully: ${location._id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Location created successfully',
                data: {
                    id: location._id,
                    userId: location.userId,
                    city: location.city,
                    country: location.country,
                    status: location.status,
                    createdAt: location.createdAt,
                },
            }, 201);
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Location creation failed for user ${userId}:`, error);
            metricsCollector.increment('location.create_failed', { userId, error: error.name });

            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            if (error.code === 11000) {
                return next(new AppError('Location with this name already exists', 409));
            }
            if (error.name === 'MongoServerError' && error.message.includes('timeout')) {
                return next(new AppError('Database operation timed out', 504));
            }
            return next(new AppError('Failed to create location', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Get user's locations with filtering and pagination
     * GET /api/v1/locations/:userId
     */
    getLocations = catchAsync(async (req, res, next) => {
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
            country,
            search,
            sortBy = 'recent',
        } = req.query;

        // Build query
        const query = this.buildLocationQuery({ userId, status, country, search });

        // Build sort option
        const sortOption = this.buildSortOption(sortBy);

        // Pagination
        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
        const skip = (pageNum - 1) * limitNum;

        // Cache key
        const cacheKey = `locations:${userId}:${JSON.stringify({ page: pageNum, limit: limitNum, status, country, search, sortBy })}`;

        try {
            // Try cache first
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('location.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            // Query database
            const [locations, totalCount] = await Promise.all([
                Location.find(query)
                    .read('secondaryPreferred')
                    .sort(sortOption)
                    .skip(skip)
                    .limit(limitNum)
                    .select('city country state status createdAt updatedAt')
                    .lean(),
                Location.countDocuments(query).cache({ ttl: 300, key: `location_count_${userId}` }),
            ]);

            const totalPages = Math.ceil(totalCount / limitNum);
            const result = {
                locations,
                pagination: {
                    page: pageNum,
                    limit: limitNum,
                    totalCount,
                    totalPages,
                    hasNext: pageNum < totalPages,
                    hasPrev: pageNum > 1,
                    nextPage: pageNum < totalPages ? pageNum + 1 : null,
                    prevPage: pageNum > 1 ? pageNum - 1 : null,
                },
                filters: { status: status || 'all', country: country || 'all', sortBy, search: search || null },
            };

            // Cache result
            await cacheService.set(cacheKey, result, 300);

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('location.fetched', { userId, count: locations.length });
            logger.info(`Fetched ${locations.length} locations for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, result);
        } catch (error) {
            logger.error(`Failed to fetch locations for user ${userId}:`, error);
            metricsCollector.increment('location.fetch_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid query parameters', 400));
            }
            return next(new AppError('Failed to fetch locations', 500));
        }
    });

    /**
     * Get single location by ID
     * GET /api/v1/locations/:userId/:id
     */
    getLocationById = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        try {
            const cacheKey = `location:${id}:${userId}`;
            const cached = await cacheService.get(cacheKey);
            if (cached) {
                metricsCollector.increment('location.cache_hit', { userId });
                return ApiResponse.success(res, cached);
            }

            const location = await Location.findOne({ _id: id, userId })
                .read('secondaryPreferred')
                .cache({ ttl: 600, key: cacheKey });

            if (!location) {
                return next(new AppError('Location not found', 404));
            }

            // Check access permissions
            if (userId !== requestingUserId && !req.user.isAdmin && location.visibility !== 'public') {
                return next(new AppError('Access denied', 403));
            }

            const responseTime = Date.now() - startTime;
            metricsCollector.increment('location.viewed', { userId });
            logger.info(`Fetched location ${id} for user ${userId} in ${responseTime}ms`);

            return ApiResponse.success(res, { data: location });
        } catch (error) {
            logger.error(`Failed to fetch location ${id}:`, error);
            metricsCollector.increment('location.view_failed', { userId });
            if (error.name === 'CastError') {
                return next(new AppError('Invalid location ID', 400));
            }
            return next(new AppError('Failed to fetch location', 500));
        }
    });

    /**
     * Update location
     * PUT /api/v1/locations/:userId/:id
     */
    updateLocation = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;
        const updates = req.body;

        // Apply rate limiting
        await updateLocationLimiter(req, res, () => { });

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const location = await Location.findOne({ _id: id, userId }).session(session);
            if (!location) {
                return next(new AppError('Location not found', 404));
            }

            // Validate updates
            const allowedUpdates = ['city', 'country', 'state', 'address', 'visibility', 'status'];
            const sanitizedUpdates = this.sanitizeUpdates(updates, allowedUpdates);

            if (Object.keys(sanitizedUpdates).length === 0) {
                return next(new AppError('No valid update fields provided', 400));
            }

            // Update location
            Object.assign(location, sanitizedUpdates);
            location.metadata.lastModifiedBy = {
                userId: requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date(),
            };

            await location.save({ session });

            // Clear cache
            await cacheService.deletePattern(`location:${id}:*`);
            await cacheService.deletePattern(`locations:${userId}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('location.updated', { userId });
            logger.info(`Location updated successfully: ${id} in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message: 'Location updated successfully',
                data: {
                    id: location._id,
                    city: location.city,
                    country: location.country,
                    status: location.status,
                    updatedAt: location.updatedAt,
                },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Location update failed for ${id}:`, error);
            metricsCollector.increment('location.update_failed', { userId });
            if (error.name === 'ValidationError') {
                return next(new AppError('Validation failed: ' + error.message, 400));
            }
            return next(new AppError('Failed to update location', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Delete location
     * DELETE /api/v1/locations/:userId/:id
     */
    deleteLocation = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId, id } = req.params;
        const requestingUserId = req.user.id;

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const location = await Location.findOne({ _id: id, userId }).session(session);
            if (!location) {
                return next(new AppError('Location not found', 404));
            }

            location.status = 'deleted';
            location.visibility = 'private';
            location.metadata.lastModifiedBy = {
                userId: requestingUserId,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                timestamp: new Date(),
            };
            await location.save({ session });

            // Clear cache
            await cacheService.deletePattern(`location:${id}:*`);
            await cacheService.deletePattern(`locations:${userId}:*`);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('location.deleted', { userId });
            logger.info(`Location ${id} deleted in ${responseTime}ms`);

            return ApiResponse.success(res, { message: 'Location deleted successfully' });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Location deletion failed for ${id}:`, error);
            metricsCollector.increment('location.delete_failed', { userId });
            return next(new AppError('Failed to delete location', 500));
        } finally {
            session.endSession();
        }
    });

    /**
     * Bulk operations on locations
     * POST /api/v1/locations/:userId/bulk
     */
    bulkOperations = catchAsync(async (req, res, next) => {
        const startTime = Date.now();
        const { userId } = req.params;
        const requestingUserId = req.user.id;
        const { operation, locationIds, data = {} } = req.body;

        // Apply rate limiting
        await bulkOperationsLimiter(req, res, () => { });

        // Validate access
        if (userId !== requestingUserId && !req.user.isAdmin) {
            return next(new AppError('Access denied', 403));
        }

        // Validate input
        if (!Array.isArray(locationIds) || locationIds.length === 0) {
            return next(new AppError('Location IDs array is required', 400));
        }
        if (locationIds.length > 100) {
            return next(new AppError('Maximum 100 locations can be processed at once', 400));
        }

        const session = await mongoose.startSession();
        try {
            session.startTransaction();

            const query = { _id: { $in: locationIds }, userId };
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
                    message = 'Locations moved to trash';
                    break;
                case 'updateCountry':
                    if (!data.country) {
                        throw new AppError('Country is required', 400);
                    }
                    updateData = {
                        country: data.country,
                        updatedAt: new Date(),
                        'metadata.lastModifiedBy': {
                            userId: requestingUserId,
                            ip: req.ip,
                            userAgent: req.get('User-Agent'),
                            timestamp: new Date(),
                        },
                    };
                    message = `Country updated to ${data.country}`;
                    break;
                default:
                    throw new AppError('Invalid operation', 400);
            }

            const result = await Location.updateMany(query, updateData, { session });
            await Promise.all([
                cacheService.deletePattern(`locations:${userId}:*`),
                ...locationIds.map((id) => cacheService.deletePattern(`location:${id}:*`)),
            ]);

            await session.commitTransaction();
            const responseTime = Date.now() - startTime;
            metricsCollector.increment('location.bulk_operation', { userId, operation, count: locationIds.length });
            logger.info(`Bulk operation ${operation} completed for ${locationIds.length} locations in ${responseTime}ms`);

            return ApiResponse.success(res, {
                message,
                data: { operation, requested: locationIds.length },
            });
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk operation failed for user ${userId}:`, error);
            metricsCollector.increment('location.bulk_operation_failed', { userId });
            return next(new AppError('Bulk operation failed', 500));
        } finally {
            session.endSession();
        }
    });

    // Helper Methods

    getUserLimits(accountType) {
        const limits = {
            free: { maxLocations: 10 },
            premium: { maxLocations: 50 },
            enterprise: { maxLocations: 200 },
        };
        return limits[accountType] || limits.free;
    }

    buildLocationQuery({ userId, status, country, search }) {
        const query = { userId, status: { $ne: 'deleted' } };
        if (status && status !== 'all') query.status = status;
        if (country && country !== 'all') query.country = country;
        if (search) query.$text = { $search: search };
        return query;
    }

    buildSortOption(sortBy) {
        const sortOptions = {
            recent: { updatedAt: -1 },
            oldest: { createdAt: 1 },
            city: { city: 1 },
        };
        return sortOptions[sortBy] || sortOptions.recent;
    }

    sanitizeUpdates(updates, allowedFields) {
        const sanitized = {};
        allowedFields.forEach((field) => {
            if (updates[field] !== undefined) {
                sanitized[field] = field === 'address' ? sanitizeHtml(updates[field]) : sanitizeInput(updates[field]);
            }
        });
        return sanitized;
    }
}

export default new LocationController();