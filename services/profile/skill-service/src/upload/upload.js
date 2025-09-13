import multer from 'multer';
import { v4 as uuidv4 } from 'uuid';
import ApiError from '../utils/apiError.js';
import { logger } from '../config/logger.js';

// File filter for allowed mime types
const fileFilter = (req, file, cb) => {
    const allowedTypes = [
        'image/jpeg',
        'image/png',
        'image/gif',
        'video/mp4',
        'video/mpeg',
        'video/webm',
    ];
    if (allowedTypes.includes(file.mimetype)) {
        cb(null, true);
    } else {
        logger.warn('Invalid file type uploaded', {
            mimetype: file.mimetype,
            ip: req.ip,
        });
        cb(new ApiError(400, 'Invalid file type. Only images and videos are allowed.'));
    }
};

// Multer storage configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        const ext = file.mimetype.split('/')[1];
        cb(null, `${uuidv4()}-${Date.now()}.${ext}`);
    },
});

// Multer configuration
const upload = multer({
    storage,
    fileFilter,
    limits: {
        fileSize: 50 * 1024 * 1024, // 50MB limit
        files: 10, // Max 10 files per request
    },
});

// Middleware to handle single file upload
export const uploadSingle = (fieldName) => asyncHandler(async (req, res, next) => {
    upload.single(fieldName)(req, res, (err) => {
        if (err instanceof multer.MulterError) {
            logger.error('Multer upload error', {
                error: err.message,
                field: fieldName,
                ip: req.ip,
            });
            return next(new ApiError(400, `Multer error: ${err.message}`));
        }
        if (err) {
            return next(err);
        }
        logger.info('File uploaded via Multer', {
            field: fieldName,
            filename: req.file?.filename,
            ip: req.ip,
        });
        next();
    });
});

// Middleware to handle multiple file uploads
export const uploadMultiple = (fieldName, maxCount = 5) => asyncHandler(async (req, res, next) => {
    upload.array(fieldName, maxCount)(req, res, (err) => {
        if (err instanceof multer.MulterError) {
            logger.error('Multer upload error', {
                error: err.message,
                field: fieldName,
                ip: req.ip,
            });
            return next(new ApiError(400, `Multer error: ${err.message}`));
        }
        if (err) {
            return next(err);
        }
        logger.info('Multiple files uploaded via Multer', {
            field: fieldName,
            fileCount: req.files?.length,
            ip: req.ip,
        });
        next();
    });
});

export default upload;