import multer from 'multer';
import { logger } from '../utils/logger.js';
import { ApiError } from '../utils/ApiError.js';

// Configure Multer for in-memory storage
const storage = multer.memoryStorage();
export const upload = multer({
    storage,
    limits: {
        fileSize: 5 * 1024 * 1024, // 5MB limit
        files: 1, // Single file upload
    },
    fileFilter: (req, file, cb) => {
        const allowedMimes = ['image/jpeg', 'image/png', 'image/webp'];
        if (allowedMimes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            logger.warn('Invalid file type uploaded', { mimetype: file.mimetype });
            cb(new ApiError(400, 'Invalid file type. Only JPEG, PNG, and WebP are allowed'));
        }
    },
});
