// profile-service/src/models/profileModel.js
import mongoose from 'mongoose';

const profileSchema = new mongoose.Schema({
    userId: {
        type: String,
        required: true,
        unique: true,
        index: true
    }, // From auth
    firstName: {
        type: String,
        required: true
    }, // From auth
    middleName: {
        type: String,
        default: ''
    },
    lastName: {
        type: String,
        required: true
    }, // From auth
    pronouns: {
        type: String,
        enum: ['he/him', 'she/her', 'they/them', ''], default: ''
    },
    tagline: {
        type: String,
        default: ''
    }, // Subtitle
    city: {
        type: String,
        default: ''
    },
    state: {
        type: String,
        default: ''
    },
    country: {
        type: String,
        default: ''
    },
    zipCode: {
        type: String,
        default: ''
    },
    timeZone: {
        type: String,
        default: 'UTC'
    }, // Detect via client IP or something in controller
    profileSlug: {
        type: String,
        unique: true, sparse: true
    }, // Custom URL slug
    vanityUrlChecked: {
        type: Boolean,
        default: false
    }, // For availability
    primaryEmail: {
        type: String,
        required: true, index: true
    }, // From auth
    secondaryEmail: {
        type: String,
        default: ''
    },
    phoneNumber: {
        type: String,
        default: ''
    }, // Format in controller (e.g., +1-XXX-XXX-XXXX)
    website: {
        type: String,
        default: ''
    }, // Validate URL in controller
    socialLinks: {
        twitter: {
            type: String,
            default: ''
        },
        instagram: {
            type: String,
            default: ''
        },
        // Add more as needed
    },
    createdAt: {
        type: Date,
        default: Date.now,
        index: true
    },
    lastUpdated: {
        type: Date,
        default: Date.now,
        index: true
    },
}, {
    timestamps: true, // Auto createdAt/updatedAt
});

// Indexes for fast queries
profileSchema.index({ userId: 1, lastUpdated: -1 }); // Sort by recent updates
profileSchema.index({ profileSlug: 1 }); // Unique slug search

// Pre-save hook for updating lastUpdated
profileSchema.pre('save', function (next) {
    this.lastUpdated = Date.now();
    next();
});

// Validation examples (add more)
profileSchema.path('website').validate(function (value) {
    if (!value) return true;
    return /^(https?:\/\/)?([\w-]+\.)+[\w-]+(\/[\w- ./?%&=]*)?$/.test(value);
}, 'Invalid website URL');

profileSchema.path('phoneNumber').validate(function (value) {
    if (!value) return true;
    return /^\+?[1-9]\d{1,14}$/.test(value); // E.164 format
}, 'Invalid phone number');

const profileModel = mongoose.model('profile', profileSchema);

export default profileModel;