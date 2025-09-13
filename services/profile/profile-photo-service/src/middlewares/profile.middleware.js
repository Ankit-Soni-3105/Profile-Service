import jwt from 'jsonwebtoken';
import userModel from '../models/user.model.js';
import redisService from '../services/redis.service.js';
import ApiError from '../services/apierrors.service.js';
import asyncHandler from '../handler/asyncHandler.handler.js';
import { logger } from '../utils/logger.js';
import config from '../config/config.js';

// Error message constants
const ERRORS = {
    NO_TOKEN: 'Access token is required',
    INVALID_TOKEN: 'Invalid access token format',
    EXPIRED_TOKEN: 'Access token has expired',
    BLACKLISTED_TOKEN: 'Token has been revoked',
    USER_NOT_FOUND: 'User not found. Please login again.',
    INVALID_PAYLOAD: 'Invalid token payload',
    INACTIVE_ACCOUNT: 'User account is inactive',
    SUSPENDED_ACCOUNT: 'User account has been suspended',
    DELETED_ACCOUNT: 'User account has been deleted',
    EMAIL_NOT_VERIFIED: 'Email verification required',
    AUTH_FAILED: 'Authentication process failed',
    RATE_LIMIT_EXCEEDED: 'Too many authentication attempts. Try again after 15 minutes.',
    INVALID_ROLE: (roles) => `Access denied. Required roles: ${roles.join(', ')}`,
    INVALID_PERMISSIONS: (permissions) => `Access denied. Required permissions: ${permissions.join(', ')}`,
};

// Cache TTL constants (from config)
const CACHE_TTL = {
    USER_DATA: config.redis.cacheTtl,
    BLACKLIST_TOKEN: 86400, // 24 hours (can be moved to config if needed)
    RATE_LIMIT: 900, // 15 minutes (can be moved to config if needed)
};

// Helper function to validate token format
const isValidTokenFormat = (token) => /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/.test(token);

// Helper function to extract token from request
const extractToken = (req) => {
    if (req.headers.authorization?.startsWith('Bearer ')) {
        return req.headers.authorization.slice(7);
    }
    return req.cookies?.token || req.headers['x-access-token'] || null;
};

// Helper function to generate cache keys
const generateCacheKeys = (userId, token = null) => ({
    userData: `user:${userId}`,
    userSessions: `sessions:${userId}`,
    blacklistToken: token ? `blacklist:${token}` : null,
    rateLimitAuth: `rate_limit:auth:${userId}`,
    rateLimitIP: `rate_limit:ip:${req?.ip}`,
});

// Main Authentication Middleware
export const authenticateUser = asyncHandler(async (req, res, next) => {
    const startTime = Date.now();

    // Extract and validate token
    const token = extractToken(req);
    if (!token || !isValidTokenFormat(token)) {
        logger.auth('Authentication failed: Invalid or missing token', {
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            url: req.originalUrl,
        });
        throw new ApiError(401, token ? ERRORS.INVALID_TOKEN : ERRORS.NO_TOKEN);
    }

    // Check if token is blacklisted
    const cacheKeys = generateCacheKeys(null, token);
    const isTokenBlacklisted = await redisService.exists(cacheKeys.blacklistToken);
    if (isTokenBlacklisted) {
        logger.auth('Authentication failed: Token blacklisted', {
            tokenPrefix: token.substring(0, 20) + '...',
            ip: req.ip,
        });
        throw new ApiError(401, ERRORS.BLACKLISTED_TOKEN);
    }

    // Verify JWT token
    let decoded;
    try {
    decoded = jwt.verify(token, config.jwt.secret);
    } catch (jwtError) {
        logger.auth('Authentication failed: Token verification error', {
            error: jwtError.message,
            tokenPrefix: token.substring(0, 20) + '...',
            ip: req.ip,
        });
        if (jwtError.name === 'TokenExpiredError') {
            throw new ApiError(401, ERRORS.EXPIRED_TOKEN);
        } else if (jwtError.name === 'JsonWebTokenError') {
            throw new ApiError(401, ERRORS.INVALID_TOKEN);
        }
        throw new ApiError(401, ERRORS.AUTH_FAILED);
    }

    const userId = decoded._id || decoded.id;
    if (!userId) {
        throw new ApiError(401, ERRORS.INVALID_PAYLOAD);
    }

    const userCacheKeys = generateCacheKeys(userId, token);

    // Try to get user from Redis cache
    let user = await redisService.get(userCacheKeys.userData);
    let fromCache = false;

    if (user) {
        user = JSON.parse(user);
        fromCache = true;
        logger.cache('User data retrieved from cache', {
            userId,
            cacheKey: userCacheKeys.userData,
        });
    } else {
        // Get user from database
        try {
            user = await userModel.findById(userId).select('-password -refreshToken -__v');
            if (!user) {
                logger.auth('Authentication failed: User not found', { userId, ip: req.ip });
                throw new ApiError(401, ERRORS.USER_NOT_FOUND);
            }

            // Cache user data
            await redisService.setEx(userCacheKeys.userData, JSON.stringify(user), CACHE_TTL.USER_DATA);
            logger.cache('User data cached', {
                userId,
                cacheKey: userCacheKeys.userData,
                ttl: CACHE_TTL.USER_DATA,
            });
        } catch (dbError) {
            logger.error('Database error during authentication', {
                userId,
                error: dbError.message,
                stack: dbError.stack,
            });
            throw new ApiError(dbError.name === 'CastError' ? 400 : 500, ERRORS.AUTH_FAILED);
        }
    }

    // User status validations
    if (user.status === 'inactive') {
        throw new ApiError(403, ERRORS.INACTIVE_ACCOUNT);
    }
    if (user.status === 'suspended') {
        throw new ApiError(403, ERRORS.SUSPENDED_ACCOUNT);
    }
    if (user.status === 'deleted') {
        throw new ApiError(403, ERRORS.DELETED_ACCOUNT);
    }
    if (config.app.requireEmailVerification && !user.isEmailVerified) {
        throw new ApiError(403, ERRORS.EMAIL_NOT_VERIFIED);
    }

    // Set user and token data in request
    req.user = user;
    req.tokenData = {
        token,
        decoded,
        issuedAt: new Date(decoded.iat * 1000),
        expiresAt: new Date(decoded.exp * 1000),
        fromCache,
    };

    // Update user activity asynchronously
    setImmediate(async () => {
        try {
            const updatedUser = await userModel.findByIdAndUpdate(
                userId,
                {
                    lastActivity: new Date(),
                    lastIP: req.ip,
                    lastUserAgent: req.get('User-Agent'),
                },
                { new: true }
            );
            if (fromCache && updatedUser) {
                updatedUser.lastActivity = new Date();
                await redisService.setEx(userCacheKeys.userData, JSON.stringify(updatedUser), CACHE_TTL.USER_DATA);
            }
        } catch (updateError) {
            logger.warn('Failed to update user activity', {
                userId,
                error: updateError.message,
            });
        }
    });

    logger.auth('User authenticated successfully', {
        userId: user._id,
        email: user.email,
        role: user.role,
        fromCache,
        processingTime: Date.now() - startTime,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
    });

    next();
});

// Optional Authentication Middleware
export const optionalAuth = asyncHandler(async (req, res, next) => {
    const token = extractToken(req);
    if (token && isValidTokenFormat(token)) {
        try {
            await authenticateUser(req, res, () => { });
        } catch (error) {
            logger.warn('Optional authentication failed', {
                error: error.message,
                ip: req.ip,
            });
        }
    }
    next();
});

// Role-based Authorization Middleware
export const authorize = (...roles) => asyncHandler(async (req, res, next) => {
    if (!req.user) {
        throw new ApiError(401, ERRORS.AUTH_FAILED);
    }
    if (!roles.includes(req.user.role)) {
        logger.auth('Authorization failed: Insufficient role', {
            userId: req.user._id,
            userRole: req.user.role,
            requiredRoles: roles,
            ip: req.ip,
        });
        throw new ApiError(403, ERRORS.INVALID_ROLE(roles));
    }
    logger.auth('User authorized successfully', {
        userId: req.user._id,
        userRole: req.user.role,
        requiredRoles: roles,
    });
    next();
});

// Permission-based Authorization Middleware
export const checkPermissions = (...permissions) => asyncHandler(async (req, res, next) => {
    if (!req.user) {
        throw new ApiError(401, ERRORS.AUTH_FAILED);
    }
    const userPermissions = req.user.permissions || [];
    if (!permissions.some((perm) => userPermissions.includes(perm))) {
        logger.auth('Authorization failed: Insufficient permissions', {
            userId: req.user._id,
            userPermissions,
            requiredPermissions: permissions,
            ip: req.ip,
        });
        throw new ApiError(403, ERRORS.INVALID_PERMISSIONS(permissions));
    }
    logger.auth('Permission check passed', {
        userId: req.user._id,
        userPermissions,
        requiredPermissions: permissions,
    });
    next();
});

// Token Blacklist Middleware
export const blacklistToken = asyncHandler(async (req, res, next) => {
    const token = req.tokenData?.token;
    if (token) {
        const cacheKey = `blacklist:${token}`;
        const expiresIn = req.tokenData?.expiresAt
            ? Math.floor((req.tokenData.expiresAt - new Date()) / 1000)
            : CACHE_TTL.BLACKLIST_TOKEN;

        await redisService.setEx(cacheKey, 'revoked', Math.max(expiresIn, 60));
        logger.auth('Token blacklisted successfully', {
            userId: req.user?._id,
            tokenPrefix: token.substring(0, 20) + '...',
            expiresIn,
        });
    }
    next();
});

// Rate Limiting Middleware for Authentication Endpoints
export const authRateLimit = (maxAttempts = 5, windowMs = 15 * 60 * 1000) => asyncHandler(async (req, res, next) => {
    const rateLimitKey = req.body?.email
        ? `rate_limit:auth:${req.body.email}`
        : `rate_limit:auth_ip:${req.ip}`;

    const attempts = parseInt(await redisService.get(rateLimitKey) || '0', 10);
    if (attempts >= maxAttempts) {
        logger.auth('Rate limit exceeded', {
            ip: req.ip,
            email: req.body?.email,
            attempts,
            maxAttempts,
        });
        throw new ApiError(429, ERRORS.RATE_LIMIT_EXCEEDED);
    }

    await redisService.setEx(rateLimitKey, attempts + 1, Math.floor(windowMs / 1000));
    next();
});

export default authenticateUser;