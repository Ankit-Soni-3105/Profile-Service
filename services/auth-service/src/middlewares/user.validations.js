import { body } from 'express-validator';

export const userValidationRules = [
    body('username')
        .notEmpty().withMessage('Username is required')
        .isLength({ min: 3 }).withMessage('Username must be at least 3 characters long').bail()
        .custom((value) => {
            const firstLetter = value[0];
            const specialCharRegex = /[^a-zA-Z0-9]/; // Accepts special chars like !, @, # etc.

            if (firstLetter !== firstLetter.toUpperCase()) {
                throw new Error('First letter of name must be capitalized');
            }

            if (!specialCharRegex.test(value)) {
                throw new Error('Name must contain at least one special character');
            }

            return true;
        })
        .trim(),

    body('email')
        .notEmpty().withMessage('Email is required')
        .isEmail().withMessage('Invalid email format')
        .custom((value => {
            const regex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
            if (!regex.test(value)) {
                throw new Error('Invalid email format');
            }
            return true;
        }))
        .customSanitizer(value => value.toLowerCase())
        .trim(),

    body('password')
        .notEmpty().withMessage('Password is required')
        .isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
];
