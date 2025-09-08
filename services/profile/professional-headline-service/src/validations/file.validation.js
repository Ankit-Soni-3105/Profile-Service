import sanitize from 'sanitize-filename';

export const validateImageFile = (file) => {
    const maxSize = 10 * 1024 * 1024; // 10MB
    const allowedMimetypes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
    const allowedExtensions = ['.jpg', '.jpeg', '.png', '.webp', '.gif'];

    if (!file) {
        return { valid: false, message: 'No file provided' };
    }

    if (file.size > maxSize) {
        return { valid: false, message: `File size exceeds ${maxSize / (1024 * 1024)}MB` };
    }

    if (!allowedMimetypes.includes(file.mimetype)) {
        return { valid: false, message: 'Invalid file type. Allowed: JPEG, PNG, WebP, GIF' };
    }

    const extension = file.originalname.slice(file.originalname.lastIndexOf('.')).toLowerCase();
    if (!allowedExtensions.includes(extension)) {
        return { valid: false, message: 'Invalid file extension. Allowed: .jpg, .jpeg, .png, .webp, .gif' };
    }

    return { valid: true };
};

export const sanitizeFileName = (filename) => {
    if (!filename) return `cover_${Date.now()}`;
    return sanitize(filename).replace(/[^a-zA-Z0-9-_]/g, '').slice(0, 100);
};