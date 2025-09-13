// utils/sanitizer.js
import xss from 'xss'; // Requires 'xss' (npm install xss)
import { logger } from './logger.js';

const xssOptions = {
    whiteList: {
        a: ['href', 'title', 'target'],
        strong: [],
        em: [],
        // Add allowed tags/attributes
    },
    stripIgnoreTag: true,
    stripIgnoreTagBody: ['script'],
};

export const sanitizeInput = (input) => {
    if (typeof input === 'string') {
        const sanitized = xss(input, xssOptions).trim();
        logger.debug('Input sanitized', { originalLength: input.length, sanitizedLength: sanitized.length });
        return sanitized;
    } else if (Array.isArray(input)) {
        return input.map(sanitizeInput);
    } else if (typeof input === 'object' && input !== null) {
        const sanitizedObj = {};
        for (const key in input) {
            sanitizedObj[key] = sanitizeInput(input[key]);
        }
        return sanitizedObj;
    }
    return input;
};