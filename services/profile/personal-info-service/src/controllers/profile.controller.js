// profile-service/src/controllers/profileController.js
import Profile from '../models/profile.model.js';
import { createHash } from 'crypto';
import redis from '../services/redis.service.js';
import { uploadToCloudinary, deleteFromCloudinary } from '../services/cloudinaryService.js';
import { sendEmail } from '../services/emailService.js';
import { validateImageFile, sanitizeInput, validateProfileData } from '../utils/validators.js';
import { ApiError } from '../utils/ApiError.js';
import { ApiResponse } from '../utils/ApiResponse.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import { logger } from '../utils/logger.js';
import rateLimit from 'express-rate-limit';
import { check, query } from 'express-validator';
import { EventEmitter } from 'events';
import mongoose from 'mongoose';
import promClient from 'prom-client';

// ===========================
// METRICS SETUP
// ===========================
export const requestCounter = new promClient.Counter({
    name: 'profile_requests_total',
    help: 'Total number of profile requests',
    labelNames: ['endpoint', 'method', 'status'],
});

export const requestLatency = new promClient.Histogram({
    name: 'profile_request_duration_seconds',
    help: 'Profile request latency in seconds',
    labelNames: ['endpoint', 'method'],
    buckets: [0.1, 0.5, 1, 2, 5],
});

// Event emitter for notifications
export const profileEventEmitter = new EventEmitter();

// ===========================
// RATE LIMITING CONFIGURATIONS
// ===========================
export const createProfileLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5,
    message: 'Too many profile creation attempts, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.user.userId, // User-specific rate limiting
});

export const updateProfileLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 20,
    message: 'Too many profile updates, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.user.userId,
});

export const searchLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 100,
    message: 'Too many search requests, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.user?.userId || req.ip, // User or IP-based
});

// ===========================
// CACHE CONFIGURATIONS
// ===========================
export const CACHE_TTL = {
    PROFILE: 300, // 5 minutes
    SEARCH_RESULTS: 180, // 3 minutes
    TRENDING: 600, // 10 minutes
    ANALYTICS: 1800, // 30 minutes
};

// ===========================
// UTILITY FUNCTIONS
// ===========================
export const generateCacheKey = (type, ...params) => {
    const key = `profile:${type}:${params.join(':')}`;
    return createHash('md5').update(key).digest('hex');
};

const setCacheData = async (key, data, ttl = CACHE_TTL.PROFILE) => {
    try {
        await redis.setex(key, ttl, JSON.stringify(data));
    } catch (error) {
        logger.warn('Cache set failed:', error.message);
    }
};

const getCacheData = async (key) => {
    try {
        const data = await redis.get(key);
        return data ? JSON.parse(data) : null;
    } catch (error) {
        logger.warn('Cache get failed:', error.message);
        return null;
    }
};

const deleteCacheData = async (key) => {
    try {
        await redis.del(key);
    } catch (error) {
        logger.warn('Cache delete failed:', error.message);
    }
};

// Sanitize metadata fields
const sanitizeMetadata = (metadata) => {
    if (!metadata) return {};
    return {
        ipAddress: sanitizeInput(metadata.ipAddress || ''),
        userAgent: sanitizeInput(metadata.userAgent || '', { allowedTags: [] }),
        sessionId: sanitizeInput(metadata.sessionId || ''),
        requestId: sanitizeInput(metadata.requestId || ''),
    };
};

// ===========================
// VALIDATION MIDDLEWARE
// ===========================
const searchValidation = [
    query('page').optional().isInt({ min: 1 }).toInt().withMessage('Page must be a positive integer'),
    query('limit').optional().isInt({ min: 1, max: 50 }).toInt().withMessage('Limit must be between 1 and 50'),
    query('minExperience').optional().isInt({ min: 0 }).toInt().withMessage('minExperience must be a non-negative integer'),
    query('maxExperience').optional().isInt({ max: 50 }).toInt().withMessage('maxExperience must be <= 50'),
    query('verifiedOnly').optional().isBoolean().toBoolean().withMessage('verifiedOnly must be a boolean'),
];

const nearbyValidation = [
    query('longitude').isFloat().toFloat().withMessage('Longitude must be a valid number'),
    query('latitude').isFloat().toFloat().withMessage('Latitude must be a valid number'),
    query('maxDistance').optional().isInt({ min: 1000, max: 100000 }).toInt().withMessage('maxDistance must be between 1000 and 100000'),
    query('limit').optional().isInt({ min: 1, max: 50 }).toInt().withMessage('Limit must be between 1 and 50'),
];

// ===========================
// PROFILE CRUD OPERATIONS
// ===========================
/**
 * Create a new profile
 * POST /api/v1/profiles
 */
export const createProfile = [
    createProfileLimiter,
    asyncHandler(async (req, res) => {
        const start = Date.now();
        const endpoint = 'createProfile';
        const { userId } = req.user;
        const profileData = req.body;

        try {
            // Check if profile already exists
            const existingProfile = await Profile.findOne({ userId }).lean();
            if (existingProfile) {
                requestCounter.inc({ endpoint, method: 'POST', status: 400 });
                throw new ApiError(400, 'Profile already exists for this user');
            }

            // Validate and sanitize input data
            const validatedData = await validateProfileData({
                ...profileData,
                metadata: sanitizeMetadata(profileData.metadata),
            });

            validatedData.userId = userId;

            // Create profile with transaction
            const session = await mongoose.startSession();
            let profile;
            try {
                session.startTransaction();
                profile = new Profile(validatedData);
                await profile.save({ session });
                await session.commitTransaction();

                // Emit event for notifications
                profileEventEmitter.emit('profileCreated', {
                    userId,
                    profileId: profile._id,
                    email: profile.contact.primaryEmail,
                });

                // Send welcome email asynchronously
                setImmediate(() => {
                    sendEmail({
                        to: profile.contact.primaryEmail,
                        template: 'profile-created',
                        data: {
                            name: profile.personalInfo.firstName,
                            profileUrl: profile.profileUrl,
                        },
                    }).catch((err) => logger.warn('Welcome email failed:', err.message));
                });
            } catch (error) {
                await session.abortTransaction();
                throw error;
            } finally {
                session.endSession();
            }

            // Cache the new profile
            const cacheKey = generateCacheKey('user', userId);
            await setCacheData(cacheKey, profile.getPublicProfile());

            requestCounter.inc({ endpoint, method: 'POST', status: 201 });
            requestLatency.observe({ endpoint, method: 'POST' }, (Date.now() - start) / 1000);

            res.status(201).json(
                new ApiResponse(201, profile.getPublicProfile(), 'Profile created successfully')
            );
        } catch (error) {
            requestCounter.inc({ endpoint, method: 'POST', status: error.statusCode || 500 });
            throw error;
        }
    }),
];

/**
 * Get profile by user ID or slug
 * GET /api/v1/profiles/:identifier
 */
export const getProfile = [
    asyncHandler(async (req, res) => {
        const start = Date.now();
        const endpoint = 'getProfile';
        const { identifier } = req.params;
        const { viewer } = req.query;

        try {
            // Determine if identifier is userId or slug
            const isSlug = !identifier.match(/^[0-9a-fA-F]{24}$/);
            const cacheKey = generateCacheKey(isSlug ? 'slug' : 'user', identifier);

            // Try cache first
            let profile = await getCacheData(cacheKey);

            if (!profile) {
                // Query database
                if (isSlug) {
                    profile = await Profile.findBySlug(identifier);
                } else {
                    profile = await Profile.findOne({
                        userId: identifier,
                        status: 'active',
                        'settings.visibility': { $in: ['public', 'connections'] },
                    }).lean();
                }

                if (!profile) {
                    requestCounter.inc({ endpoint, method: 'GET', status: 404 });
                    throw new ApiError(404, 'Profile not found');
                }

                // Cache the result
                await setCacheData(cacheKey, profile);
            }

            // Convert to Profile instance for methods if cached
            if (!(profile instanceof Profile)) {
                profile = new Profile(profile);
            }

            // Increment profile views asynchronously
            if (viewer && viewer !== profile.userId) {
                setImmediate(async () => {
                    try {
                        await profile.incrementProfileViews(viewer);
                        // Invalidate specific cache key
                        await deleteCacheData(cacheKey);
                    } catch (error) {
                        logger.warn('Failed to increment profile views:', error.message);
                    }
                });
            }

            // Get appropriate profile data based on viewer
            const isOwner = req.user?.userId === profile.userId;
            const profileData = isOwner ? profile.toObject() : profile.getPublicProfile();

            requestCounter.inc({ endpoint, method: 'GET', status: 200 });
            requestLatency.observe({ endpoint, method: 'GET' }, (Date.now() - start) / 1000);

            res.json(new ApiResponse(200, profileData, 'Profile retrieved successfully'));
        } catch (error) {
            requestCounter.inc({ endpoint, method: 'GET', status: error.statusCode || 500 });
            throw error;
        }
    }),
];

/**
 * Update profile (partial updates)
 * PATCH /api/v1/profiles/:userId
 */
export const updateProfile = [
    updateProfileLimiter,
    asyncHandler(async (req, res) => {
        const start = Date.now();
        const endpoint = 'updateProfile';
        const { userId } = req.params;
        const requesterId = req.user.userId;

        try {
            // Authorization check
            if (userId !== requesterId && req.user.role !== 'admin') {
                requestCounter.inc({ endpoint, method: 'PATCH', status: 403 });
                throw new ApiError(403, 'Unauthorized to update this profile');
            }

            // Validate and sanitize update data
            const validatedData = await validateProfileData(
                { ...req.body, metadata: sanitizeMetadata(req.body.metadata) },
                true
            );

            // Find profile
            const profile = await Profile.findOne({ userId, status: { $ne: 'deleted' } });
            if (!profile) {
                requestCounter.inc({ endpoint, method: 'PATCH', status: 404 });
                throw new ApiError(404, 'Profile not found');
            }

            // Update with transaction
            const session = await mongoose.startSession();
            try {
                session.startTransaction();
                // Apply partial updates using $set
                await Profile.updateOne(
                    { userId, status: { $ne: 'deleted' } },
                    { $set: validatedData },
                    { session }
                );
                await session.commitTransaction();

                // Reload updated profile
                const updatedProfile = await Profile.findOne({ userId }).lean();

                // Emit event
                profileEventEmitter.emit('profileUpdated', {
                    userId,
                    profileId: updatedProfile._id,
                    updatedFields: Object.keys(validatedData),
                });

                // Invalidate specific caches
                await deleteCacheData(generateCacheKey('user', userId));
                await deleteCacheData(generateCacheKey('slug', updatedProfile.settings.profileSlug));
                await deleteCacheData('profile:search:*');
                await deleteCacheData('profile:trending:*');

                logger.info(`Profile updated successfully for user: ${userId}`);
                requestCounter.inc({ endpoint, method: 'PATCH', status: 200 });
                requestLatency.observe({ endpoint, method: 'PATCH' }, (Date.now() - start) / 1000);

                res.json(
                    new ApiResponse(200, updatedProfile.getPublicProfile(), 'Profile updated successfully')
                );
            } catch (error) {
                await session.abortTransaction();
                throw error;
            } finally {
                session.endSession();
            }
        } catch (error) {
            requestCounter.inc({ endpoint, method: 'PATCH', status: error.statusCode || 500 });
            throw error;
        }
    }),
];

/**
 * Delete profile (soft delete)
 * DELETE /api/v1/profiles/:userId
 */
export const deleteProfile = [
    asyncHandler(async (req, res) => {
        const start = Date.now();
        const endpoint = 'deleteProfile';
        const { userId } = req.params;
        const requesterId = req.user.userId;

        try {
            // Authorization check
            if (userId !== requesterId && req.user.role !== 'admin') {
                requestCounter.inc({ endpoint, method: 'DELETE', status: 403 });
                throw new ApiError(403, 'Unauthorized to delete this profile');
            }

            const profile = await Profile.findOne({ userId, status: { $ne: 'deleted' } });
            if (!profile) {
                requestCounter.inc({ endpoint, method: 'DELETE', status: 404 });
                throw new ApiError(404, 'Profile not found');
            }

            // Soft delete with transaction
            const session = await mongoose.startSession();
            try {
                session.startTransaction();
                profile.status = 'deleted';
                profile.settings.searchable = false;
                profile.settings.visibility = 'private';
                await profile.save({ session });
                await session.commitTransaction();

                // Emit event
                profileEventEmitter.emit('profileDeleted', {
                    userId,
                    profileId: profile._id,
                });

                // Clean up media files asynchronously
                setImmediate(async () => {
                    try {
                        if (profile.media.profilePhoto.url) {
                            await deleteFromCloudinary(profile.media.profilePhoto.url);
                        }
                        if (profile.media.coverPhoto.url) {
                            await deleteFromCloudinary(profile.media.coverPhoto.url);
                        }
                        for (const image of profile.media.gallery) {
                            await deleteFromCloudinary(image.url);
                        }
                    } catch (error) {
                        logger.warn('Failed to clean up media files:', error.message);
                    }
                });

                // Invalidate specific caches
                await deleteCacheData(generateCacheKey('user', userId));
                await deleteCacheData(generateCacheKey('slug', profile.settings.profileSlug));

                logger.info(`Profile deleted successfully for user: ${userId}`);
                requestCounter.inc({ endpoint, method: 'DELETE', status: 200 });
                requestLatency.observe({ endpoint, method: 'DELETE' }, (Date.now() - start) / 1000);

                res.json(new ApiResponse(200, null, 'Profile deleted successfully'));
            } catch (error) {
                await session.abortTransaction();
                throw error;
            } finally {
                session.endSession();
            }
        } catch (error) {
            requestCounter.inc({ endpoint, method: 'DELETE', status: error.statusCode || 500 });
            throw error;
        }
    }),
];

// ===========================
// SEARCH AND DISCOVERY
// ===========================
/**
 * Search profiles with advanced filtering
 * GET /api/v1/profiles/search
 */
export const searchProfiles = [
    searchLimiter,
    searchValidation,
    asyncHandler(async (req, res) => {
        const start = Date.now();
        const endpoint = 'searchProfiles';
        const {
            q: query,
            page = 1,
            limit = 20,
            location,
            skills,
            experience,
            education,
            sortBy = 'relevance',
            minExperience = 0,
            maxExperience = 50,
            industries,
            employmentTypes,
            verifiedOnly = false,
            accountTypes,
        } = req.query;

        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                requestCounter.inc({ endpoint, method: 'GET', status: 400 });
                throw new ApiError(400, 'Validation failed', errors.array());
            }

            const pageNum = Math.max(1, parseInt(page));
            const limitNum = Math.min(50, Math.max(1, parseInt(limit)));

            // Generate cache key
            const searchParams = {
                query: query || '',
                page: pageNum,
                limit: limitNum,
                location,
                skills,
                experience,
                education,
                sortBy,
                minExperience,
                maxExperience,
                industries,
                employmentTypes,
                verifiedOnly,
                accountTypes,
            };
            const cacheKey = generateCacheKey('search', createHash('md5').update(JSON.stringify(searchParams)).digest('hex'));

            // Try cache first
            let searchResults = await getCacheData(cacheKey);

            if (!searchResults) {
                // Prepare search options
                const searchOptions = {
                    page: pageNum,
                    limit: limitNum,
                    location: sanitizeInput(location),
                    skills: skills ? skills.split(',').map(s => sanitizeInput(s)) : undefined,
                    experience: sanitizeInput(experience),
                    education: sanitizeInput(education),
                    sortBy,
                    minExperience: parseInt(minExperience),
                    maxExperience: parseInt(maxExperience),
                    industries: industries ? industries.split(',').map(s => sanitizeInput(s)) : undefined,
                    employmentTypes: employmentTypes
                        ? employmentTypes.split(',').map(s => sanitizeInput(s))
                        : undefined,
                    verifiedOnly: verifiedOnly === 'true',
                    accountTypes: accountTypes ? accountTypes.split(',').map(s => sanitizeInput(s)) : undefined,
                };

                // Execute search
                const profiles = await Profile.searchProfiles(query, searchOptions);

                // Get total count for pagination
                const totalCount = await Profile.countDocuments({
                    status: 'active',
                    'settings.visibility': 'public',
                    'settings.searchable': true,
                    ...(query && { $text: { $search: query } }),
                });

                searchResults = {
                    profiles,
                    pagination: {
                        page: pageNum,
                        limit: limitNum,
                        total: totalCount,
                        pages: Math.ceil(totalCount / limitNum),
                        hasNext: pageNum < Math.ceil(totalCount / limitNum),
                        hasPrev: pageNum > 1,
                    },
                };

                // Cache search results
                await setCacheData(cacheKey, searchResults, CACHE_TTL.SEARCH_RESULTS);
            }

            logger.info(`Search executed: query = "${query}", results = ${searchResults.profiles.length}`);
            requestCounter.inc({ endpoint, method: 'GET', status: 200 });
            requestLatency.observe({ endpoint, method: 'GET' }, (Date.now() - start) / 1000);

            res.json(new ApiResponse(200, searchResults, 'Search completed successfully'));
        } catch (error) {
            requestCounter.inc({ endpoint, method: 'GET', status: error.statusCode || 500 });
            throw error;
        }
    }),
];

/**
 * Get trending profiles
 * GET /api/v1/profiles/trending
 */
export const getTrendingProfiles = [
    asyncHandler(async (req, res) => {
        const start = Date.now();
        const endpoint = 'getTrendingProfiles';
        const { limit = 10, timeframe = 7 } = req.query;

        try {
            const limitNum = Math.min(50, Math.max(1, parseInt(limit)));
            const timeframeNum = Math.min(30, Math.max(1, parseInt(timeframe)));
            const cacheKey = generateCacheKey('trending', limitNum, timeframeNum);

            let trendingProfiles = await getCacheData(cacheKey);

            if (!trendingProfiles) {
                trendingProfiles = await Profile.getTrendingProfiles(limitNum, timeframeNum);
                await setCacheData(cacheKey, trendingProfiles, CACHE_TTL.TRENDING);
            }

            requestCounter.inc({ endpoint, method: 'GET', status: 200 });
            requestLatency.observe({ endpoint, method: 'GET' }, (Date.now() - start) / 1000);

            res.json(new ApiResponse(200, trendingProfiles, 'Trending profiles retrieved successfully'));
        } catch (error) {
            requestCounter.inc({ endpoint, method: 'GET', status: error.statusCode || 500 });
            throw error;
        }
    }),
];

/**
 * Get profiles near location
 * GET /api/v1/profiles/nearby
 */
export const getNearbyProfiles = [
    nearbyValidation,
    asyncHandler(async (req, res) => {
        const start = Date.now();
        const endpoint = 'getNearbyProfiles';
        const { longitude, latitude, maxDistance = 50000, limit = 20 } = req.query;

        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                requestCounter.inc({ endpoint, method: 'GET', status: 400 });
                throw new ApiError(400, 'Validation failed', errors.array());
            }

            const lng = parseFloat(longitude);
            const lat = parseFloat(latitude);
            const maxDist = Math.min(100000, Math.max(1000, parseInt(maxDistance)));
            const limitNum = Math.min(50, Math.max(1, parseInt(limit)));
            const cacheKey = generateCacheKey('nearby', lng, lat, maxDist, limitNum);

            let nearbyProfiles = await getCacheData(cacheKey);

            if (!nearbyProfiles) {
                nearbyProfiles = await Profile.getProfilesNearLocation(lng, lat, maxDist, limitNum);
                await setCacheData(cacheKey, nearbyProfiles, CACHE_TTL.PROFILE);
            }

            requestCounter.inc({ endpoint, method: 'GET', status: 200 });
            requestLatency.observe({ endpoint, method: 'GET' }, (Date.now() - start) / 1000);

            res.json(new ApiResponse(200, nearbyProfiles, 'Nearby profiles retrieved successfully'));
        } catch (error) {
            requestCounter.inc({ endpoint, method: 'GET', status: error.statusCode || 500 });
            throw error;
        }
    }),
];

/**
 * Get skill-based recommendations
 * GET /api/v1/profiles/recommendations
 */
export const getRecommendations = [
    asyncHandler(async (req, res) => {
        const start = Date.now();
        const endpoint = 'getRecommendations';
        const { userId } = req.user;
        const { limit = 10 } = req.query;

        try {
            const limitNum = Math.min(20, Math.max(1, parseInt(limit)));

            // Get user's profile to extract skills
            const userProfile = await Profile.findOne({ userId, status: 'active' })
                .select('skills.name')
                .lean();
            if (!userProfile || !userProfile.skills.length) {
                requestCounter.inc({ endpoint, method: 'GET', status: 200 });
                return res.json(
                    new ApiResponse(200, [], 'No recommendations available - please add skills to your profile')
                );
            }

            const userSkills = userProfile.skills.map(skill => skill.name);
            const cacheKey = generateCacheKey('recommendations', userId, limitNum);

            let recommendations = await getCacheData(cacheKey);

            if (!recommendations) {
                recommendations = await Profile.getSkillBasedRecommendations(userId, userSkills, limitNum);
                await setCacheData(cacheKey, recommendations, CACHE_TTL.PROFILE);
            }

            requestCounter.inc({ endpoint, method: 'GET', status: 200 });
            requestLatency.observe({ endpoint, method: 'GET' }, (Date.now() - start) / 1000);

            res.json(new ApiResponse(200, recommendations, 'Recommendations retrieved successfully'));
        } catch (error) {
            requestCounter.inc({ endpoint, method: 'GET', status: error.statusCode || 500 });
            throw error;
        }
    }),
];

// ===========================
// PROFILE ENHANCEMENT OPERATIONS
// ===========================
/**
 * Upload profile photo
 * POST /api/v1/profiles/:userId/photo
 */
export const uploadProfilePhoto = [
    asyncHandler(async (req, res) => {
        const start = Date.now();
        const endpoint = 'uploadProfilePhoto';
        const { userId } = req.params;
        const requesterId = req.user.userId;

        try {
            // Authorization check
            if (userId !== requesterId) {
                requestCounter.inc({ endpoint, method: 'POST', status: 403 });
                throw new ApiError(403, 'Unauthorized to update this profile');
            }

            if (!req.file) {
                requestCounter.inc({ endpoint, method: 'POST', status: 400 });
                throw new ApiError(400, 'No image file provided');
            }

            // Validate image file
            validateImageFile(req.file);

            const profile = await Profile.findOne({ userId, status: 'active' });
            if (!profile) {
                requestCounter.inc({ endpoint, method: 'POST', status: 404 });
                throw new ApiError(404, 'Profile not found');
            }

            // Update with transaction
            const session = await mongoose.startSession();
            try {
                session.startTransaction();
                let oldPhotoUrl = profile.media.profilePhoto.url;
                let oldThumbnailUrl = profile.media.profilePhoto.thumbnail;

                // Upload new photo with retry
                let uploadResult, thumbnailResult;
                let retries = 3;
                while (retries > 0) {
                    try {
                        uploadResult = await uploadToCloudinary(req.file.buffer, {
                            folder: 'profiles/photos',
                            transformation: [
                                { width: 400, height: 400, crop: 'fill', gravity: 'face' },
                                { quality: 'auto', format: 'auto' },
                            ],
                        });
                        thumbnailResult = await uploadToCloudinary(req.file.buffer, {
                            folder: 'profiles/thumbnails',
                            transformation: [
                                { width: 150, height: 150, crop: 'fill', gravity: 'face' },
                                { quality: 'auto', format: 'auto' },
                            ],
                        });
                        break;
                    } catch (error) {
                        retries--;
                        if (retries === 0) throw error;
                        await new Promise(resolve => setTimeout(resolve, 1000)); // Retry after 1s
                    }
                }

                // Update profile
                profile.media.profilePhoto = {
                    url: uploadResult.secure_url,
                    thumbnail: thumbnailResult.secure_url,
                    uploadedAt: new Date(),
                    size: req.file.size,
                    format: uploadResult.format,
                    isOptimized: true,
                };

                await profile.save({ session });
                await session.commitTransaction();

                // Delete old photo asynchronously
                if (oldPhotoUrl) {
                    setImmediate(async () => {
                        try {
                            await deleteFromCloudinary(oldPhotoUrl);
                            if (oldThumbnailUrl) await deleteFromCloudinary(oldThumbnailUrl);
                        } catch (error) {
                            logger.warn('Failed to delete old profile photo:', error.message);
                        }
                    });
                }

                // Invalidate specific cache
                await deleteCacheData(generateCacheKey('user', userId));
                await deleteCacheData(generateCacheKey('slug', profile.settings.profileSlug));

                // Emit event
                profileEventEmitter.emit('profilePhotoUpdated', {
                    userId,
                    profileId: profile._id,
                    photoUrl: uploadResult.secure_url,
                });

                logger.info(`Profile photo updated for user: ${userId}`);
                requestCounter.inc({ endpoint, method: 'POST', status: 200 });
                requestLatency.observe({ endpoint, method: 'POST' }, (Date.now() - start) / 1000);

                res.json(
                    new ApiResponse(200, profile.media.profilePhoto, 'Profile photo updated successfully')
                );
            } catch (error) {
                await session.abortTransaction();
                throw new ApiError(500, 'Failed to upload profile photo');
            } finally {
                session.endSession();
            }
        } catch (error) {
            requestCounter.inc({ endpoint, method: 'POST', status: error.statusCode || 500 });
            throw error;
        }
    }),
];

/**
 * Endorse a skill
 * POST /api/v1/profiles/:userId/skills/:skillName/endorse
 */
export const endorseSkill = [
    asyncHandler(async (req, res) => {
        const start = Date.now();
        const endpoint = 'endorseSkill';
        const { userId, skillName } = req.params;
        const endorserId = req.user.userId;

        try {
            if (userId === endorserId) {
                requestCounter.inc({ endpoint, method: 'POST', status: 400 });
                throw new ApiError(400, 'Cannot endorse your own skills');
            }

            const profile = await Profile.findOne({ userId, status: 'active' });
            if (!profile) {
                requestCounter.inc({ endpoint, method: 'POST', status: 404 });
                throw new ApiError(404, 'Profile not found');
            }

            const session = await mongoose.startSession();
            try {
                session.startTransaction();
                await profile.endorseSkill(skillName, endorserId);
                await session.commitTransaction();

                // Invalidate specific cache
                await deleteCacheData(generateCacheKey('user', userId));
                await deleteCacheData(generateCacheKey('slug', profile.settings.profileSlug));

                // Emit event
                profileEventEmitter.emit('skillEndorsed', {
                    userId,
                    skillName,
                    endorserId,
                    profileId: profile._id,
                });

                logger.info(`Skill "${skillName}" endorsed by ${endorserId} for user: ${userId}`);
                requestCounter.inc({ endpoint, method: 'POST', status: 200 });
                requestLatency.observe({ endpoint, method: 'POST' }, (Date.now() - start) / 1000);

                res.json(new ApiResponse(200, null, 'Skill endorsed successfully'));
            } catch (error) {
                await session.abortTransaction();
                throw new ApiError(400, error.message);
            } finally {
                session.endSession();
            }
        } catch (error) {
            requestCounter.inc({ endpoint, method: 'POST', status: error.statusCode || 500 });
            throw error;
        }
    }),
];

/**
 * Get profile analytics (owner only)
 * GET /api/v1/profiles/:userId/analytics
 */
export const getProfileAnalytics = [
    asyncHandler(async (req, res) => {
        const start = Date.now();
        const endpoint = 'getProfileAnalytics';
        const { userId } = req.params;
        const requesterId = req.user.userId;

        try {
            // Authorization check
            if (userId !== requesterId && req.user.role !== 'admin') {
                requestCounter.inc({ endpoint, method: 'GET', status: 403 });
                throw new ApiError(403, 'Unauthorized to view analytics');
            }

            const cacheKey = generateCacheKey('analytics', userId);
            let analytics = await getCacheData(cacheKey);

            if (!analytics) {
                const profile = await Profile.findOne({ userId, status: 'active' })
                    .select('analytics')
                    .lean();
                if (!profile) {
                    requestCounter.inc({ endpoint, method: 'GET', status: 404 });
                    throw new ApiError(404, 'Profile not found');
                }
                analytics = profile.analytics;
                await setCacheData(cacheKey, analytics, CACHE_TTL.ANALYTICS);
            }

            requestCounter.inc({ endpoint, method: 'GET', status: 200 });
            requestLatency.observe({ endpoint, method: 'GET' }, (Date.now() - start) / 1000);

            res.json(new ApiResponse(200, analytics, 'Analytics retrieved successfully'));
        } catch (error) {
            requestCounter.inc({ endpoint, method: 'GET', status: error.statusCode || 500 });
            throw error;
        }
    }),
];

/**
 * Get career progression insights
 * GET /api/v1/profiles/:userId/career-progression
 */
export const getCareerProgression = [
    asyncHandler(async (req, res) => {
        const start = Date.now();
        const endpoint = 'getCareerProgression';
        const { userId } = req.params;

        try {
            const profile = await Profile.findOne({
                userId,
                status: 'active',
                'settings.visibility': { $in: ['public', 'connections'] },
            })
                .select('experience')
                .lean();
            if (!profile) {
                requestCounter.inc({ endpoint, method: 'GET', status: 404 });
                throw new ApiError(404, 'Profile not found');
            }

            const profileInstance = new Profile(profile);
            const careerProgression = profileInstance.getCareerProgression();

            requestCounter.inc({ endpoint, method: 'GET', status: 200 });
            requestLatency.observe({ endpoint, method: 'GET' }, (Date.now() - start) / 1000);

            res.json(new ApiResponse(200, careerProgression, 'Career progression retrieved successfully'));
        } catch (error) {
            requestCounter.inc({ endpoint, method: 'GET', status: error.statusCode || 500 });
            throw error;
        }
    }),
];

// ===========================
// ADMIN OPERATIONS
// ===========================
/**
 * Get analytics summary (admin only)
 * GET /api/v1/profiles/admin/analytics
 */
export const getAnalyticsSummary = [
    asyncHandler(async (req, res) => {
        const start = Date.now();
        const endpoint = 'getAnalyticsSummary';
        const { timeframe = 30 } = req.query;

        try {
            // Admin authorization check
            if (req.user.role !== 'admin') {
                requestCounter.inc({ endpoint, method: 'GET', status: 403 });
                throw new ApiError(403, 'Admin access required');
            }

            const timeframeNum = Math.min(365, Math.max(1, parseInt(timeframe)));
            const cacheKey = generateCacheKey('admin_analytics', timeframeNum);
            let analyticsSummary = await getCacheData(cacheKey);

            if (!analyticsSummary) {
                analyticsSummary = await Profile.getAnalyticsSummary(timeframeNum);
                await setCacheData(cacheKey, analyticsSummary, CACHE_TTL.ANALYTICS);
            }

            requestCounter.inc({ endpoint, method: 'GET', status: 200 });
            requestLatency.observe({ endpoint, method: 'GET' }, (Date.now() - start) / 1000);

            res.json(new ApiResponse(200, analyticsSummary, 'Analytics summary retrieved successfully'));
        } catch (error) {
            requestCounter.inc({ endpoint, method: 'GET', status: error.statusCode || 500 });
            throw error;
        }
    }),
];

/**
 * Bulk update completion scores (admin only)
 * POST /api/v1/profiles/admin/bulk-update-scores
 */
export const bulkUpdateCompletionScores = [
    asyncHandler(async (req, res) => {
        const start = Date.now();
        const endpoint = 'bulkUpdateCompletionScores';
        const { batchSize = 1000 } = req.body;

        try {
            // Admin authorization check
            if (req.user.role !== 'admin') {
                requestCounter.inc({ endpoint, method: 'POST', status: 403 });
                throw new ApiError(403, 'Admin access required');
            }

            // Start bulk update process asynchronously
            setImmediate(async () => {
                try {
                    await Profile.bulkUpdateCompletionScores(batchSize);
                    logger.info('Bulk completion score update completed');
                    profileEventEmitter.emit('bulkCompletionScoresUpdated', { batchSize });
                } catch (error) {
                    logger.error('Bulk completion score update failed:', error);
                }
            });

            requestCounter.inc({ endpoint, method: 'POST', status: 200 });
            requestLatency.observe({ endpoint, method: 'POST' }, (Date.now() - start) / 1000);

            res.json(new ApiResponse(200, null, 'Bulk update process started'));
        } catch (error) {
            requestCounter.inc({ endpoint, method: 'POST', status: error.statusCode || 500 });
            throw error;
        }
    }),
];

/**
 * Bulk delete profiles (admin only)
 * POST /api/v1/profiles/admin/bulk-delete
 */
export const bulkDeleteProfiles = [
    asyncHandler(async (req, res) => {
        const start = Date.now();
        const endpoint = 'bulkDeleteProfiles';
        const { userIds } = req.body;

        try {
            // Admin authorization check
            if (req.user.role !== 'admin') {
                requestCounter.inc({ endpoint, method: 'POST', status: 403 });
                throw new ApiError(403, 'Admin access required');
            }

            if (!Array.isArray(userIds) || userIds.length === 0) {
                requestCounter.inc({ endpoint, method: 'POST', status: 400 });
                throw new ApiError(400, 'userIds must be a non-empty array');
            }

            // Soft delete with transaction
            const session = await mongoose.startSession();
            try {
                session.startTransaction();
                const result = await Profile.updateMany(
                    { userId: { $in: userIds }, status: { $ne: 'deleted' } },
                    { $set: { status: 'deleted', 'settings.searchable': false, 'settings.visibility': 'private' } },
                    { session }
                );
                await session.commitTransaction();

                // Invalidate caches for deleted profiles
                for (const userId of userIds) {
                    const profile = await Profile.findOne({ userId }).select('settings.profileSlug').lean();
                    if (profile) {
                        await deleteCacheData(generateCacheKey('user', userId));
                        await deleteCacheData(generateCacheKey('slug', profile.settings.profileSlug));
                    }
                }

                // Emit event
                profileEventEmitter.emit('bulkProfilesDeleted', { userIds });

                logger.info(`Bulk deleted ${result.modifiedCount} profiles`);
                requestCounter.inc({ endpoint, method: 'POST', status: 200 });
                requestLatency.observe({ endpoint, method: 'POST' }, (Date.now() - start) / 1000);

                res.json(new ApiResponse(200, { modifiedCount: result.modifiedCount }, 'Bulk delete completed'));
            } catch (error) {
                await session.abortTransaction();
                throw error;
            } finally {
                session.endSession();
            }
        } catch (error) {
            requestCounter.inc({ endpoint, method: 'POST', status: error.statusCode || 500 });
            throw error;
        }
    }),
];

/**
 * Health check endpoint
 * GET /api/v1/profiles/health
 */
export const healthCheck = asyncHandler(async (req, res) => {
    const start = Date.now();
    const endpoint = 'healthCheck';

    try {
        // Test database connection
        await Profile.findOne().limit(1).lean();

        // Test cache connection
        await redis.ping();

        requestCounter.inc({ endpoint, method: 'GET', status: 200 });
        requestLatency.observe({ endpoint, method: 'GET' }, (Date.now() - start) / 1000);

        res.json(
            new ApiResponse(200, {
                status: 'healthy',
                timestamp: new Date().toISOString(),
                database: 'connected',
                cache: 'connected',
            }, 'Service is healthy')
        );
    } catch (error) {
        requestCounter.inc({ endpoint, method: 'GET', status: 503 });
        res.status(503).json(
            new ApiResponse(503, {
                status: 'unhealthy',
                timestamp: new Date().toISOString(),
                error: error.message,
            }, 'Service is unhealthy')
        );
    }
});

// ===========================
// ERROR HANDLERS
// ===========================
/**
 * Global error handler for profile routes
 */
export const handleProfileErrors = (error, req, res, next) => {
    logger.error('Profile Controller Error:', {
        message: error.message,
        stack: error.stack,
        endpoint: req.path,
        method: req.method,
    });

    // MongoDB validation errors
    if (error.name === 'ValidationError') {
        const messages = Object.values(error.errors).map(err => err.message);
        return res.status(400).json(new ApiResponse(400, null, 'Validation Error', messages));
    }

    // MongoDB duplicate key errors
    if (error.code === 11000) {
        const field = Object.keys(error.keyPattern)[0];
        return res.status(409).json(new ApiResponse(409, null, `${field} already exists`));
    }

    // Cast errors (invalid ObjectId)
    if (error.name === 'CastError') {
        return res.status(400).json(new ApiResponse(400, null, 'Invalid ID format'));
    }

    // API errors
    if (error instanceof ApiError) {
        return res.status(error.statusCode).json(new ApiResponse(error.statusCode, null, error.message));
    }

    // Default server error
    res.status(500).json(new ApiResponse(500, null, 'Internal server error'));
};

// ===========================
// EXPORTS
// ===========================
export default {
    createProfile,
    getProfile,
    updateProfile,
    deleteProfile,
    searchProfiles,
    getTrendingProfiles,
    getNearbyProfiles,
    getRecommendations,
    uploadProfilePhoto,
    endorseSkill,
    getProfileAnalytics,
    getCareerProgression,
    getAnalyticsSummary,
    bulkUpdateCompletionScores,
    bulkDeleteProfiles,
    healthCheck,
    handleProfileErrors,
    createProfileLimiter,
    updateProfileLimiter,
    searchLimiter,
};