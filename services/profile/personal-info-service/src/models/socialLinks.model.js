import mongoose from 'mongoose';

const socialLinksSchema = new mongoose.Schema({
    // User identifier linked to personal info
    userId: {
        type: String,
        required: [true, 'User ID is required'],
        index: true, // Fast lookup by userId
    },
    // Social media links with validation
    twitter: {
        type: String,
        trim: true,
        validate: {
            validator: function (v) {
                return v === '' || /^https?:\/\/(www\.)?twitter\.com\/[A-Za-z0-9_]{1,15}$/.test(v);
            },
            message: 'Please provide a valid Twitter URL',
        },
        default: '',
    },
    linkedin: {
        type: String,
        trim: true,
        validate: {
            validator: function (v) {
                return v === '' || /^https?:\/\/(www\.)?linkedin\.com\/in\/[A-Za-z0-9_-]{5,30}\/?$/.test(v);
            },
            message: 'Please provide a valid LinkedIn URL',
        },
        default: '',
    },
    instagram: {
        type: String,
        trim: true,
        validate: {
            validator: function (v) {
                return v === '' || /^https?:\/\/(www\.)?instagram\.com\/[A-Za-z0-9_.]{1,30}\/?$/.test(v);
            },
            message: 'Please provide a valid Instagram URL',
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

// Indexing
socialLinksSchema.index({ userId: 1 }); // Fast lookup by userId

// Pre-save hook to update timestamp
socialLinksSchema.pre('save', function (next) {
    this.updatedAt = Date.now();
    next();
});

// Model export
const socialLinksModel = mongoose.model('socialLinks', socialLinksSchema);

export default socialLinksModel;