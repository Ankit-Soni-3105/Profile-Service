import { logger } from './logger.js';
import validator from 'validator';
import sanitizeHtml from 'sanitize-html';

// Validate image file
export const validateImageFile = (file) => {
    if (!file) {
        throw new Error('No image file provided');
    }

    const allowedMimes = ['image/jpeg', 'image/png', 'image/webp'];
    const maxSize = 5 * 1024 * 1024; // 5MB

    if (!allowedMimes.includes(file.mimetype)) {
        throw new Error('Invalid image format. Only JPEG, PNG, and WebP are allowed');
    }

    if (file.size > maxSize) {
        throw new Error('Image size exceeds 5MB limit');
    }

    return true;
};

// Sanitize input strings
export const sanitizeInput = (input, options = {}) => {
    if (!input || typeof input !== 'string') return input;

    const defaultOptions = {
        allowedTags: [], // No HTML tags allowed by default
        allowedAttributes: {},
    };

    return sanitizeHtml(input, { ...defaultOptions, ...options });
};

// Validate profile data
export const validateProfileData = async (data, isPartial = false) => {
    const validatedData = { ...data };

    // Required fields for full validation (not partial updates)
    if (!isPartial) {
        if (!data.userId) throw new Error('userId is required');
        if (!data.personalInfo?.firstName) throw new Error('First name is required');
        if (!data.personalInfo?.lastName) throw new Error('Last name is required');
        if (!data.contact?.primaryEmail) throw new Error('Primary email is required');
    }

    // Sanitize and validate strings
    if (data.personalInfo) {
        validatedData.personalInfo = {
            ...data.personalInfo,
            firstName: sanitizeInput(data.personalInfo.firstName),
            middleName: sanitizeInput(data.personalInfo.middleName),
            lastName: sanitizeInput(data.personalInfo.lastName),
            pronouns: sanitizeInput(data.personalInfo.pronouns),
            tagline: sanitizeInput(data.personalInfo.tagline),
        };

        if (data.personalInfo.firstName && !validator.isLength(data.personalInfo.firstName, { max: 50 })) {
            throw new Error('First name must be 50 characters or less');
        }
        if (data.personalInfo.lastName && !validator.isLength(data.personalInfo.lastName, { max: 50 })) {
            throw new Error('Last name must be 50 characters or less');
        }
        if (data.personalInfo.tagline && !validator.isLength(data.personalInfo.tagline, { max: 120 })) {
            throw new Error('Tagline must be 120 characters or less');
        }
    }

    // Validate email
    if (data.contact?.primaryEmail) {
        if (!validator.isEmail(data.contact.primaryEmail)) {
            throw new Error('Invalid primary email format');
        }
        validatedData.contact = {
            ...data.contact,
            primaryEmail: validator.normalizeEmail(data.contact.primaryEmail),
            secondaryEmail: data.contact.secondaryEmail
                ? validator.normalizeEmail(data.contact.secondaryEmail)
                : data.contact.secondaryEmail,
            phoneNumber: sanitizeInput(data.contact.phoneNumber),
            website: sanitizeInput(data.contact.website),
            socialLinks: {
                linkedin: sanitizeInput(data.contact.socialLinks?.linkedin),
                twitter: sanitizeInput(data.contact.socialLinks?.twitter),
                github: sanitizeInput(data.contact.socialLinks?.github),
                instagram: sanitizeInput(data.contact.socialLinks?.instagram),
                youtube: sanitizeInput(data.contact.socialLinks?.youtube),
                facebook: sanitizeInput(data.contact.socialLinks?.facebook),
            },
        };
    }

    // Validate skills
    if (data.skills && Array.isArray(data.skills)) {
        validatedData.skills = data.skills.map(skill => ({
            ...skill,
            name: sanitizeInput(skill.name),
            category: sanitizeInput(skill.category),
            level: sanitizeInput(skill.level),
        }));

        for (const skill of validatedData.skills) {
            if (skill.name && !validator.isLength(skill.name, { max: 50 })) {
                throw new Error(`Skill name "${skill.name}" must be 50 characters or less`);
            }
        }
    }

    // Validate experience
    if (data.experience && Array.isArray(data.experience)) {
        validatedData.experience = data.experience.map(exp => ({
            ...exp,
            company: sanitizeInput(exp.company),
            position: sanitizeInput(exp.position),
            description: sanitizeInput(exp.description, { allowedTags: ['p', 'b', 'i', 'ul', 'li'] }),
        }));
    }

    // Validate metadata
    if (data.metadata) {
        validatedData.metadata = {
            ipAddress: sanitizeInput(data.metadata.ipAddress),
            userAgent: sanitizeInput(data.metadata.userAgent, { allowedTags: [] }),
            sessionId: sanitizeInput(data.metadata.sessionId),
            requestId: sanitizeInput(data.metadata.requestId),
        };
    }

    logger.info('Profile data validated successfully', { userId: data.userId });
    return validatedData;
};