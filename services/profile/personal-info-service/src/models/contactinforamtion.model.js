import mongoose from 'mongoose';

const contactInfoSchema = new mongoose.Schema({
    // User identifier linked to personal info
    userId: {
        type: String,
        required: [true, 'User ID is required'],
        index: true, // Fast lookup by userId
    },
    // Primary email with validation and uniqueness
    primaryEmail: {
        type: String,
        required: [true, 'Primary email is required'],
        unique: true,
        trim: true,
        lowercase: true, // Normalize email case
        match: [/^\S+@\S+\.\S+$/, 'Please provide a valid email address'],
        index: true, // Fast email-based search
    },
    // Optional secondary email
    secondaryEmail: {
        type: String,
        trim: true,
        lowercase: true,
        match: [/^\S+@\S+\.\S+$/, 'Please provide a valid email address'],
        default: '',
    },
    // Phone number in E.164 format (e.g., +12025550123)
    phoneNumber: {
        type: String,
        validate: {
            validator: function (v) {
                return /^\+?[1-9]\d{1,14}$/.test(v); // E.164 format
            },
            message: 'Phone number must be in E.164 format (e.g., +12025550123)',
        },
        default: '',
    },
    // Website URL with validation
    website: {
        type: String,
        trim: true,
        validate: {
            validator: function (v) {
                return v === '' || /^https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*)$/.test(v);
            },
            message: 'Please provide a valid URL starting with http:// or https://',
        },
        default: '',
    },
    // Timestamps for tracking
    createdAt: {
        type: Date,
        default: Date.now,
    },
    updatedAt: {
        type: Date,
        default: Date.now,
    },
}, {
    timestamps: true,
});

// Compound index for userId and primaryEmail
contactInfoSchema.index({ userId: 1, primaryEmail: 1 });

// Pre-save hook to update timestamp
contactInfoSchema.pre('save', function (next) {
    this.updatedAt = Date.now();
    next();
});

// Model export
const contactModel = mongoose.model('contactInfo', contactInfoSchema);

export default contactModel;