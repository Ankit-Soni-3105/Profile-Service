import validator from 'validator';
import DOMPurify from 'isomorphic-dompurify';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';

// Constants for validation limits
const VALIDATION_LIMITS = {
    TITLE: {
        MIN_LENGTH: 3,
        MAX_LENGTH: 200,
        ALLOWED_CHARS: /^[a-zA-Z0-9\s\-_.,!?()&'":;]+$/
    },
    CONTENT: {
        MIN_LENGTH: 10,
        MAX_LENGTH: 50000, // 50KB text limit
        MAX_PARAGRAPHS: 500,
        MAX_SENTENCES: 2000
    },
    CATEGORY: {
        ALLOWED_VALUES: [
            'business', 'technology', 'education', 'health', 'finance',
            'science', 'entertainment', 'sports', 'politics', 'travel',
            'lifestyle', 'food', 'art', 'personal', 'research', 'other'
        ]
    },
    TAGS: {
        MAX_COUNT: 10,
        MIN_LENGTH: 2,
        MAX_LENGTH: 30,
        PATTERN: /^[a-zA-Z0-9\-_\s]+$/
    },
    DESCRIPTION: {
        MAX_LENGTH: 500
    },
    METADATA: {
        MAX_SIZE: 5120, // 5KB JSON
        MAX_DEPTH: 5
    }
};

// Rate limiting constants
const RATE_LIMITS = {
    CONTENT_CHANGES_PER_HOUR: 20,
    BULK_OPERATIONS_PER_HOUR: 5,
    API_CALLS_PER_MINUTE: 60
};

// Forbidden patterns and content
const FORBIDDEN_PATTERNS = [
    // Malicious scripts
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
    // SQL injection patterns
    /(\b(union|select|insert|update|delete|drop|create|alter)\b)/gi,
    // XSS patterns
    /javascript:|vbscript:|onload=|onerror=|onclick=/gi,
    // Suspicious URLs
    /https?:\/\/[^\s]*\.(tk|ml|ga|cf|bit\.ly|tinyurl)[\s\/]/gi
];

// Profanity and spam detection
const SPAM_INDICATORS = [
    /(.)\1{10,}/gi, // Repeated characters
    /^[A-Z\s!]{20,}$/g, // All caps
    /(free|buy|click|now|urgent|limited|offer){3,}/gi // Spam words
];

/**
 * Advanced input sanitization
 */
export const sanitizeInput = (input, options = {}) => {
    if (typeof input !== 'string') {
        if (typeof input === 'object' && input !== null) {
            return sanitizeObject(input, options);
        }
        return input;
    }

    // Remove null bytes and control characters
    let sanitized = input.replace(/\0/g, '').replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');

    // Normalize unicode
    sanitized = sanitized.normalize('NFC');

    // HTML sanitization
    if (options.allowHTML) {
        sanitized = DOMPurify.sanitize(sanitized, {
            ALLOWED_TAGS: ['p', 'br', 'strong', 'em', 'u', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'ul', 'ol', 'li', 'blockquote'],
            ALLOWED_ATTR: ['class', 'id']
        });
    } else {
        // Strip all HTML
        sanitized = sanitized.replace(/<[^>]*>/g, '');
    }

    // Trim and normalize whitespace
    sanitized = sanitized.trim().replace(/\s+/g, ' ');

    return sanitized;
};

/**
 * Sanitize object recursively
 */
const sanitizeObject = (obj, options = {}, depth = 0) => {
    if (depth > VALIDATION_LIMITS.METADATA.MAX_DEPTH) {
        throw new AppError('Object nesting too deep', 400);
    }

    if (Array.isArray(obj)) {
        return obj.map(item => sanitizeInput(item, options));
    }

    const sanitized = {};
    for (const [key, value] of Object.entries(obj)) {
        const cleanKey = sanitizeInput(key, { allowHTML: false });
        sanitized[cleanKey] = sanitizeInput(value, options);
    }

    return sanitized;
};

/**
 * Comprehensive summary validation
 */
export const validateSummary = (data) => {
    const errors = [];
    const warnings = [];

    try {
        // Validate required fields
        if (!data.title) {
            errors.push('Title is required');
        } else {
            const titleValidation = validateTitle(data.title);
            if (!titleValidation.valid) {
                errors.push(...titleValidation.errors);
            }
            warnings.push(...(titleValidation.warnings || []));
        }

        if (!data.content) {
            errors.push('Content is required');
        } else {
            const contentValidation = validateContent(data.content);
            if (!contentValidation.valid) {
                errors.push(...contentValidation.errors);
            }
            warnings.push(...(contentValidation.warnings || []));
        }

        // Validate optional fields
        if (data.category) {
            const categoryValidation = validateCategory(data.category);
            if (!categoryValidation.valid) {
                errors.push(...categoryValidation.errors);
            }
        }

        if (data.tags) {
            const tagsValidation = validateTags(data.tags);
            if (!tagsValidation.valid) {
                errors.push(...tagsValidation.errors);
            }
        }

        if (data.description) {
            const descValidation = validateDescription(data.description);
            if (!descValidation.valid) {
                errors.push(...descValidation.errors);
            }
        }

        if (data.metadata) {
            const metadataValidation = validateMetadata(data.metadata);
            if (!metadataValidation.valid) {
                errors.push(...metadataValidation.errors);
            }
        }

        if (data.sharing) {
            const sharingValidation = validateSharing(data.sharing);
            if (!sharingValidation.valid) {
                errors.push(...sharingValidation.errors);
            }
        }

        if (data.settings) {
            const settingsValidation = validateSettings(data.settings);
            if (!settingsValidation.valid) {
                errors.push(...settingsValidation.errors);
            }
        }

        // Security validations
        const securityValidation = validateSecurity(data);
        if (!securityValidation.valid) {
            errors.push(...securityValidation.errors);
        }

        // Business logic validations
        const businessValidation = validateBusinessRules(data);
        if (!businessValidation.valid) {
            errors.push(...businessValidation.errors);
        }
        warnings.push(...(businessValidation.warnings || []));

    } catch (error) {
        logger.error('Validation error:', error);
        errors.push('Validation process failed');
    }

    return {
        valid: errors.length === 0,
        errors,
        warnings,
        message: errors.length > 0 ? errors.join('; ') : 'Validation passed'
    };
};

/**
 * Title validation
 */
const validateTitle = (title) => {
    const errors = [];
    const warnings = [];

    if (typeof title !== 'string') {
        errors.push('Title must be a string');
        return { valid: false, errors };
    }

    const cleanTitle = title.trim();

    // Length validation
    if (cleanTitle.length < VALIDATION_LIMITS.TITLE.MIN_LENGTH) {
        errors.push(`Title must be at least ${VALIDATION_LIMITS.TITLE.MIN_LENGTH} characters`);
    }

    if (cleanTitle.length > VALIDATION_LIMITS.TITLE.MAX_LENGTH) {
        errors.push(`Title must not exceed ${VALIDATION_LIMITS.TITLE.MAX_LENGTH} characters`);
    }

    // Character validation
    if (!VALIDATION_LIMITS.TITLE.ALLOWED_CHARS.test(cleanTitle)) {
        errors.push('Title contains invalid characters');
    }

    // Duplicate word detection
    const words = cleanTitle.toLowerCase().split(/\s+/);
    const uniqueWords = new Set(words);
    if (words.length - uniqueWords.size > 3) {
        warnings.push('Title contains many repeated words');
    }

    // All caps check
    if (cleanTitle === cleanTitle.toUpperCase() && cleanTitle.length > 10) {
        warnings.push('Title is in all caps');
    }

    // Spam detection
    for (const pattern of SPAM_INDICATORS) {
        if (pattern.test(cleanTitle)) {
            errors.push('Title appears to be spam');
            break;
        }
    }

    return { valid: errors.length === 0, errors, warnings };
};

/**
 * Content validation
 */
const validateContent = (content) => {
    const errors = [];
    const warnings = [];

    if (typeof content !== 'string') {
        errors.push('Content must be a string');
        return { valid: false, errors };
    }

    const cleanContent = content.trim();

    // Length validation
    if (cleanContent.length < VALIDATION_LIMITS.CONTENT.MIN_LENGTH) {
        errors.push(`Content must be at least ${VALIDATION_LIMITS.CONTENT.MIN_LENGTH} characters`);
    }

    if (cleanContent.length > VALIDATION_LIMITS.CONTENT.MAX_LENGTH) {
        errors.push(`Content must not exceed ${VALIDATION_LIMITS.CONTENT.MAX_LENGTH} characters`);
    }

    // Structure validation
    const paragraphs = cleanContent.split(/\n\s*\n/);
    const sentences = cleanContent.split(/[.!?]+/).filter(s => s.trim().length > 0);

    if (paragraphs.length > VALIDATION_LIMITS.CONTENT.MAX_PARAGRAPHS) {
        errors.push(`Content has too many paragraphs (max: ${VALIDATION_LIMITS.CONTENT.MAX_PARAGRAPHS})`);
    }

    if (sentences.length > VALIDATION_LIMITS.CONTENT.MAX_SENTENCES) {
        errors.push(`Content has too many sentences (max: ${VALIDATION_LIMITS.CONTENT.MAX_SENTENCES})`);
    }

    // Quality checks
    const wordCount = cleanContent.split(/\s+/).length;
    const averageWordsPerSentence = wordCount / sentences.length;

    if (averageWordsPerSentence > 50) {
        warnings.push('Sentences are very long on average');
    }

    if (averageWordsPerSentence < 3) {
        warnings.push('Sentences are very short on average');
    }

    // Spam and security validation
    for (const pattern of SPAM_INDICATORS) {
        if (pattern.test(cleanContent)) {
            errors.push('Content appears to be spam');
            break;
        }
    }

    for (const pattern of FORBIDDEN_PATTERNS) {
        if (pattern.test(cleanContent)) {
            errors.push('Content contains forbidden patterns');
            break;
        }
    }

    // Encoding validation
    try {
        // Check for valid UTF-8
        const encoded = encodeURIComponent(cleanContent);
        decodeURIComponent(encoded);
    } catch {
        errors.push('Content contains invalid encoding');
    }

    return { valid: errors.length === 0, errors, warnings };
};

/**
 * Category validation
 */
const validateCategory = (category) => {
    const errors = [];

    if (typeof category !== 'string') {
        errors.push('Category must be a string');
        return { valid: false, errors };
    }

    const cleanCategory = category.trim().toLowerCase();

    if (!VALIDATION_LIMITS.CATEGORY.ALLOWED_VALUES.includes(cleanCategory)) {
        errors.push(`Invalid category. Allowed: ${VALIDATION_LIMITS.CATEGORY.ALLOWED_VALUES.join(', ')}`);
    }

    return { valid: errors.length === 0, errors };
};

/**
 * Tags validation
 */
const validateTags = (tags) => {
    const errors = [];
    const warnings = [];

    if (!Array.isArray(tags)) {
        errors.push('Tags must be an array');
        return { valid: false, errors };
    }

    if (tags.length > VALIDATION_LIMITS.TAGS.MAX_COUNT) {
        errors.push(`Too many tags (max: ${VALIDATION_LIMITS.TAGS.MAX_COUNT})`);
    }

    const processedTags = new Set();

    for (let i = 0; i < tags.length; i++) {
        const tag = tags[i];

        if (typeof tag !== 'string') {
            errors.push(`Tag at index ${i} must be a string`);
            continue;
        }

        const cleanTag = tag.trim().toLowerCase();

        if (cleanTag.length < VALIDATION_LIMITS.TAGS.MIN_LENGTH) {
            errors.push(`Tag "${tag}" is too short (min: ${VALIDATION_LIMITS.TAGS.MIN_LENGTH})`);
        }

        if (cleanTag.length > VALIDATION_LIMITS.TAGS.MAX_LENGTH) {
            errors.push(`Tag "${tag}" is too long (max: ${VALIDATION_LIMITS.TAGS.MAX_LENGTH})`);
        }

        if (!VALIDATION_LIMITS.TAGS.PATTERN.test(cleanTag)) {
            errors.push(`Tag "${tag}" contains invalid characters`);
        }

        if (processedTags.has(cleanTag)) {
            warnings.push(`Duplicate tag: "${tag}"`);
        } else {
            processedTags.add(cleanTag);
        }
    }

    return { valid: errors.length === 0, errors, warnings };
};

/**
 * Description validation
 */
const validateDescription = (description) => {
    const errors = [];

    if (typeof description !== 'string') {
        errors.push('Description must be a string');
        return { valid: false, errors };
    }

    if (description.trim().length > VALIDATION_LIMITS.DESCRIPTION.MAX_LENGTH) {
        errors.push(`Description too long (max: ${VALIDATION_LIMITS.DESCRIPTION.MAX_LENGTH})`);
    }

    return { valid: errors.length === 0, errors };
};

/**
 * Metadata validation
 */
const validateMetadata = (metadata) => {
    const errors = [];

    if (typeof metadata !== 'object' || metadata === null) {
        errors.push('Metadata must be an object');
        return { valid: false, errors };
    }

    try {
        const jsonString = JSON.stringify(metadata);
        if (jsonString.length > VALIDATION_LIMITS.METADATA.MAX_SIZE) {
            errors.push(`Metadata too large (max: ${VALIDATION_LIMITS.METADATA.MAX_SIZE} bytes)`);
        }

        // Validate metadata structure depth
        const checkDepth = (obj, depth = 0) => {
            if (depth > VALIDATION_LIMITS.METADATA.MAX_DEPTH) {
                throw new Error('Too deep');
            }

            if (typeof obj === 'object' && obj !== null) {
                for (const value of Object.values(obj)) {
                    checkDepth(value, depth + 1);
                }
            }
        };

        checkDepth(metadata);

    } catch (error) {
        if (error.message === 'Too deep') {
            errors.push('Metadata nesting too deep');
        } else {
            errors.push('Invalid metadata structure');
        }
    }

    return { valid: errors.length === 0, errors };
};

/**
 * Sharing settings validation
 */
const validateSharing = (sharing) => {
    const errors = [];

    if (typeof sharing !== 'object' || sharing === null) {
        errors.push('Sharing must be an object');
        return { valid: false, errors };
    }

    if (sharing.visibility) {
        const allowedVisibility = ['private', 'public', 'unlisted', 'team'];
        if (!allowedVisibility.includes(sharing.visibility)) {
            errors.push(`Invalid visibility. Allowed: ${allowedVisibility.join(', ')}`);
        }
    }

    if (sharing.collaborators && Array.isArray(sharing.collaborators)) {
        if (sharing.collaborators.length > 50) {
            errors.push('Too many collaborators (max: 50)');
        }

        for (const collaborator of sharing.collaborators) {
            if (!collaborator.userId || typeof collaborator.userId !== 'string') {
                errors.push('Invalid collaborator userId');
            }

            if (!collaborator.accessLevel || !['read', 'write', 'admin'].includes(collaborator.accessLevel)) {
                errors.push('Invalid collaborator access level');
            }
        }
    }

    return { valid: errors.length === 0, errors };
};

/**
 * Settings validation
 */
const validateSettings = (settings) => {
    const errors = [];

    if (typeof settings !== 'object' || settings === null) {
        errors.push('Settings must be an object');
        return { valid: false, errors };
    }

    if (settings.autoBackup !== undefined && typeof settings.autoBackup !== 'boolean') {
        errors.push('autoBackup must be a boolean');
    }

    if (settings.aiEnhancements !== undefined && typeof settings.aiEnhancements !== 'boolean') {
        errors.push('aiEnhancements must be a boolean');
    }

    if (settings.notifications && typeof settings.notifications === 'object') {
        const allowedNotifications = ['email', 'push', 'sms'];
        for (const [key, value] of Object.entries(settings.notifications)) {
            if (!allowedNotifications.includes(key)) {
                errors.push(`Invalid notification type: ${key}`);
            }
            if (typeof value !== 'boolean') {
                errors.push(`Notification ${key} must be a boolean`);
            }
        }
    }

    return { valid: errors.length === 0, errors };
};

/**
 * Security validation
 */
const validateSecurity = (data) => {
    const errors = [];

    // Check for malicious patterns in all string fields
    const stringFields = ['title', 'content', 'description'];

    for (const field of stringFields) {
        if (data[field] && typeof data[field] === 'string') {
            for (const pattern of FORBIDDEN_PATTERNS) {
                if (pattern.test(data[field])) {
                    errors.push(`Security violation detected in ${field}`);
                    break;
                }
            }
        }
    }

    // Validate URLs if present
    if (data.externalLinks && Array.isArray(data.externalLinks)) {
        for (const link of data.externalLinks) {
            if (typeof link === 'string' && !validator.isURL(link, {
                protocols: ['http', 'https'],
                require_protocol: true,
                require_valid_protocol: true
            })) {
                errors.push(`Invalid URL: ${link}`);
            }
        }
    }

    return { valid: errors.length === 0, errors };
};

/**
 * Business rules validation
 */
const validateBusinessRules = (data) => {
    const errors = [];
    const warnings = [];

    // Content quality checks
    if (data.content && data.title) {
        const contentWords = data.content.trim().split(/\s+/).length;
        const titleWords = data.title.trim().split(/\s+/).length;

        if (contentWords < titleWords * 3) {
            warnings.push('Content seems too short compared to title');
        }

        if (contentWords > 10000 && !data.category) {
            warnings.push('Long content should have a category');
        }
    }

    // Category-specific rules
    if (data.category === 'research' && data.content) {
        if (!data.content.includes('references') && !data.content.includes('bibliography')) {
            warnings.push('Research summaries should typically include references');
        }
    }

    if (data.category === 'business' && data.sharing?.visibility === 'public') {
        warnings.push('Business summaries should be carefully reviewed before making public');
    }

    // Template consistency
    if (data.templateId && !data.category) {
        warnings.push('Using a template but no category specified');
    }

    return { valid: errors.length === 0, errors, warnings };
};

/**
 * Validate bulk operations
 */
export const validateBulkOperation = (operation, summaryIds, data = {}) => {
    const errors = [];

    // Validate operation
    const allowedOperations = ['delete', 'archive', 'publish', 'updateCategory', 'updateTags', 'updateVisibility'];
    if (!allowedOperations.includes(operation)) {
        errors.push('Invalid bulk operation');
    }

    // Validate summary IDs
    if (!Array.isArray(summaryIds)) {
        errors.push('Summary IDs must be an array');
    } else if (summaryIds.length === 0) {
        errors.push('At least one summary ID required');
    } else if (summaryIds.length > 100) {
        errors.push('Too many summaries for bulk operation (max: 100)');
    } else {
        for (const id of summaryIds) {
            if (!validator.isMongoId(id)) {
                errors.push(`Invalid summary ID: ${id}`);
                break;
            }
        }
    }

    // Validate operation-specific data
    switch (operation) {
        case 'updateCategory':
            if (!data.category) {
                errors.push('Category is required for updateCategory operation');
            } else {
                const categoryValidation = validateCategory(data.category);
                if (!categoryValidation.valid) {
                    errors.push(...categoryValidation.errors);
                }
            }
            break;

        case 'updateTags':
            if (!data.tags) {
                errors.push('Tags are required for updateTags operation');
            } else {
                const tagsValidation = validateTags(data.tags);
                if (!tagsValidation.valid) {
                    errors.push(...tagsValidation.errors);
                }
            }
            break;

        case 'updateVisibility':
            if (!data.visibility) {
                errors.push('Visibility is required for updateVisibility operation');
            } else {
                const allowedVisibility = ['private', 'public', 'unlisted', 'team'];
                if (!allowedVisibility.includes(data.visibility)) {
                    errors.push(`Invalid visibility: ${data.visibility}`);
                }
            }
            break;
    }

    return {
        valid: errors.length === 0,
        errors,
        message: errors.length > 0 ? errors.join('; ') : 'Bulk operation validation passed'
    };
};

/**
 * Rate limiting validation
 */
export const validateRateLimit = (userId, operation, count = 1) => {
    // This would integrate with your rate limiting system
    // Return structure for consistency
    return {
        valid: true,
        errors: [],
        remaining: RATE_LIMITS[operation] || 100
    };
};

/**
 * File upload validation (if needed)
 */
export const validateFileUpload = (file, maxSize = 5 * 1024 * 1024) => {
    const errors = [];

    if (!file) {
        errors.push('File is required');
        return { valid: false, errors };
    }

    const allowedTypes = ['text/plain', 'application/pdf', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];

    if (!allowedTypes.includes(file.mimetype)) {
        errors.push('Invalid file type');
    }

    if (file.size > maxSize) {
        errors.push(`File too large (max: ${Math.round(maxSize / 1024 / 1024)}MB)`);
    }

    // Check for malicious file names
    if (/\.(exe|bat|cmd|scr|com|pif)$/i.test(file.originalname)) {
        errors.push('Forbidden file type');
    }

    return { valid: errors.length === 0, errors };
};

/**
 * Database query validation
 */
export const validateQuery = (query) => {
    const errors = [];

    // Prevent NoSQL injection
    const checkForInjection = (obj) => {
        for (const [key, value] of Object.entries(obj)) {
            if (key.startsWith('$') && !['$text', '$regex', '$in', '$nin', '$exists'].includes(key)) {
                errors.push('Potentially malicious query operator');
            }

            if (typeof value === 'object' && value !== null) {
                checkForInjection(value);
            }
        }
    };

    checkForInjection(query);

    return { valid: errors.length === 0, errors };
};

export default {
    validateSummary,
    validateBulkOperation,
    validateRateLimit,
    validateFileUpload,
    validateQuery,
    sanitizeInput,
    VALIDATION_LIMITS,
    RATE_LIMITS
};