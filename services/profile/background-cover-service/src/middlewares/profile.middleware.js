import jwt from 'jsonwebtoken';
import { getCache, setCache } from '../services/redis.service.js';

// Middleware for authentication and authorization
export const authProfileMiddleware = async (req, res, next) => {
    try {
        const token = req.cookies?.token || req.headers.authorization?.split(" ")[1];
        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }

        // Check Redis cache for token
        const cachedUser = await getCache(`auth:${token}`);
        if (cachedUser) {
            req.user = cachedUser;
            return next();
        }

        // Verify JWT token
        const decoded = jwt.verify(token, process.env.JWT_SECRET_FILE);
        if (!decoded || !decoded.userId) {
            return res.status(401).json({ error: 'Invalid token' });
        }

        // Cache decoded user data with 1-hour TTL
        await setCache(`auth:${token}`, { userId: decoded.userId, email: decoded.email }, 3600);

        // Attach user to request
        req.user = { userId: decoded.userId, email: decoded.email };
        next();
    } catch (error) {
        console.error('Authentication error:', error.message);
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token expired' });
        }
        res.status(401).json({ error: 'Authentication failed' });
    }
};

export default authProfileMiddleware;