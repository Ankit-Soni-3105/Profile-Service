import mongoose from 'mongoose';
import { createHash } from 'crypto';

// ===========================
// OPTIMIZED SUB-SCHEMAS
// ===========================
const layerSchema = new mongoose.Schema({
    id: {
        type: String,
        required: true,
        validate: {
            validator: function (v) {
                return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(v);
            },
            message: 'Invalid layer UUID'
        }
    },
    type: {
        type: String,
        enum: ['background', 'image', 'text', 'shape', 'logo', 'overlay', 'gradient'],
        required: true,
        index: true
    },
    name: {
        type: String,
        required: true,
        trim: true,
        maxlength: 100
    },
    visible: {
        type: Boolean,
        default: true
    },
    locked: {
        type: Boolean,
        default: false
    },
    order: {
        type: Number,
        required: true,
        index: true
    },
    position: {
        x: { type: Number, default: 0 },
        y: { type: Number, default: 0 },
        z: { type: Number, default: 0 }
    },
    size: {
        width: { type: Number, required: true, min: 0 },
        height: { type: Number, required: true, min: 0 },
        maintainAspectRatio: { type: Boolean, default: true }
    },
    rotation: {
        type: Number,
        default: 0,
        min: -360,
        max: 360
    },
    opacity: {
        type: Number,
        default: 1,
        min: 0,
        max: 1
    },
    blendMode: {
        type: String,
        enum: ['normal', 'multiply', 'screen', 'overlay', 'soft-light', 'hard-light', 'color-dodge', 'color-burn', 'darken', 'lighten'],
        default: 'normal'
    },
    content: {
        text: { type: String, default: '', maxlength: 1000 },
        fontFamily: { type: String, default: 'Arial' },
        fontSize: { type: Number, default: 16, min: 8, max: 200 },
        fontWeight: { type: String, enum: ['normal', 'bold', '100', '200', '300', '400', '500', '600', '700', '800', '900'], default: 'normal' },
        fontStyle: { type: String, enum: ['normal', 'italic'], default: 'normal' },
        textAlign: { type: String, enum: ['left', 'center', 'right', 'justify'], default: 'left' },
        textDecoration: { type: String, enum: ['none', 'underline', 'overline', 'line-through'], default: 'none' },
        lineHeight: { type: Number, default: 1.2, min: 0.5, max: 3 },
        letterSpacing: { type: Number, default: 0, min: -10, max: 10 },
        imageUrl: { type: String, default: '' },
        imageFit: { type: String, enum: ['cover', 'contain', 'fill', 'scale-down'], default: 'cover' },
        imagePosition: { type: String, default: 'center center' },
        shapeType: { type: String, enum: ['rectangle', 'circle', 'ellipse', 'triangle', 'polygon', 'star'], default: 'rectangle' },
        borderRadius: { type: Number, default: 0, min: 0 },
        gradientType: { type: String, enum: ['linear', 'radial', 'conic'], default: 'linear' },
        gradientAngle: { type: Number, default: 0, min: 0, max: 360 },
        gradientStops: [{
            color: { type: String, required: true, match: /^#[0-9A-F]{6}$/i },
            position: { type: Number, required: true, min: 0, max: 100 }
        }]
    },
    styling: {
        backgroundColor: { type: String, default: 'transparent', match: /^#[0-9A-F]{6}$|^transparent$/i },
        backgroundImage: { type: String, default: '' },
        color: { type: String, default: '#000000', match: /^#[0-9A-F]{6}$/i },
        border: {
            width: { type: Number, default: 0, min: 0, max: 50 },
            style: { type: String, enum: ['none', 'solid', 'dashed', 'dotted'], default: 'none' },
            color: { type: String, default: '#000000', match: /^#[0-9A-F]{6}$/i }
        },
        shadow: {
            enabled: { type: Boolean, default: false },
            x: { type: Number, default: 0 },
            y: { type: Number, default: 0 },
            blur: { type: Number, default: 0, min: 0 },
            color: { type: String, default: 'rgba(0,0,0,0.5)' },
            inset: { type: Boolean, default: false }
        },
        filters: {
            blur: { type: Number, default: 0, min: 0, max: 20 },
            brightness: { type: Number, default: 100, min: 0, max: 200 },
            contrast: { type: Number, default: 100, min: 0, max: 200 },
            saturate: { type: Number, default: 100, min: 0, max: 200 },
            hueRotate: { type: Number, default: 0, min: 0, max: 360 },
            invert: { type: Number, default: 0, min: 0, max: 100 },
            grayscale: { type: Number, default: 0, min: 0, max: 100 },
            sepia: { type: Number, default: 0, min: 0, max: 100 }
        }
    },
    animations: [{
        type: { type: String, enum: ['fade', 'slide', 'zoom', 'rotate', 'bounce', 'pulse'], default: 'fade' },
        duration: { type: Number, default: 1000, min: 100, max: 10000 },
        delay: { type: Number, default: 0, min: 0, max: 10000 },
        easing: { type: String, enum: ['ease', 'ease-in', 'ease-out', 'ease-in-out', 'linear'], default: 'ease' },
        direction: { type: String, enum: ['normal', 'reverse', 'alternate', 'alternate-reverse'], default: 'normal' },
        iterationCount: { type: String, default: '1' }
    }],
    constraints: {
        lockAspectRatio: { type: Boolean, default: false },
        minWidth: { type: Number, default: 0, min: 0 },
        minHeight: { type: Number, default: 0, min: 0 },
        maxWidth: { type: Number, default: 0, min: 0 },
        maxHeight: { type: Number, default: 0, min: 0 },
        snapToGrid: { type: Boolean, default: false },
        constrainToCanvas: { type: Boolean, default: true }
    },
    customizable: {
        type: Boolean,
        default: true
    },
    customizableProperties: [{
        property: { type: String, required: true },
        type: { type: String, enum: ['text', 'color', 'image', 'number', 'boolean'], required: true },
        label: { type: String, required: true, maxlength: 100 },
        defaultValue: { type: String, default: '' },
        options: [{ type: String, maxlength: 100 }], // For select-type properties
        min: { type: Number }, // For number properties
        max: { type: Number }, // For number properties
        step: { type: Number }, // For number properties
        required: { type: Boolean, default: false }
    }],
    quality: {
        layerQualityScore: { type: Number, default: 0, min: 0, max: 10, index: true },
        lastAssessedAt: { type: Date },
        assessmentVersion: { type: String, default: '1.0' }
    }
}, { _id: false });

const canvasSchema = new mongoose.Schema({
    width: {
        type: Number,
        required: true,
        min: 100,
        max: 8192,
        index: true
    },
    height: {
        type: Number,
        required: true,
        min: 100,
        max: 8192,
        index: true
    },
    aspectRatio: {
        type: Number,
        index: true
    },
    backgroundColor: {
        type: String,
        default: '#FFFFFF',
        match: /^#[0-9A-F]{6}$|^transparent$/i
    },
    backgroundImage: {
        type: String,
        default: ''
    },
    dpi: {
        type: Number,
        default: 72,
        enum: [72, 150, 300, 600]
    },
    colorSpace: {
        type: String,
        enum: ['RGB', 'CMYK', 'sRGB', 'Adobe RGB'],
        default: 'sRGB'
    },
    units: {
        type: String,
        enum: ['px', 'in', 'cm', 'mm', 'pt'],
        default: 'px'
    },
    gridSettings: {
        enabled: { type: Boolean, default: false },
        size: { type: Number, default: 20, min: 5, max: 100 },
        color: { type: String, default: '#E0E0E0', match: /^#[0-9A-F]{6}$/i },
        opacity: { type: Number, default: 0.5, min: 0.1, max: 1 }
    },
    guides: [{
        type: { type: String, enum: ['vertical', 'horizontal'], required: true },
        position: { type: Number, required: true },
        color: { type: String, default: '#FF0000', match: /^#[0-9A-F]{6}$/i }
    }],
    margin: {
        top: { type: Number, default: 0, min: 0 },
        right: { type: Number, default: 0, min: 0 },
        bottom: { type: Number, default: 0, min: 0 },
        left: { type: Number, default: 0, min: 0 }
    },
    bleed: {
        enabled: { type: Boolean, default: false },
        size: { type: Number, default: 0, min: 0, max: 50 }
    }
}, { _id: false });

const previewSchema = new mongoose.Schema({
    thumbnail: {
        url: { type: String, required: true },
        width: { type: Number, default: 300 },
        height: { type: Number, default: 200 },
        size: { type: Number }, // in bytes
        generatedAt: { type: Date, default: Date.now }
    },
    preview: {
        url: { type: String, required: true },
        width: { type: Number, default: 800 },
        height: { type: Number, default: 600 },
        size: { type: Number }, // in bytes
        generatedAt: { type: Date, default: Date.now }
    },
    fullResolution: {
        url: { type: String, default: '' },
        width: { type: Number },
        height: { type: Number },
        size: { type: Number }, // in bytes
        generatedAt: { type: Date }
    },
    mockups: [{
        type: { type: String, enum: ['desktop', 'mobile', 'tablet', 'linkedin', 'facebook', 'twitter', 'instagram'], required: true },
        url: { type: String, required: true },
        generatedAt: { type: Date, default: Date.now }
    }],
    gif: {
        url: { type: String, default: '' },
        duration: { type: Number }, // in milliseconds
        fps: { type: Number, default: 30, min: 1, max: 60 },
        size: { type: Number }, // in bytes
        generatedAt: { type: Date }
    }
}, { _id: false });

const usageStatsSchema = new mongoose.Schema({
    totalUses: { type: Number, default: 0, index: true },
    uniqueUsers: { type: Number, default: 0 },
    totalDownloads: { type: Number, default: 0, index: true },
    totalViews: { type: Number, default: 0, index: true },
    likes: { type: Number, default: 0, index: true },
    shares: { type: Number, default: 0 },
    bookmarks: { type: Number, default: 0 },
    ratings: {
        average: { type: Number, default: 0, min: 0, max: 5, index: true },
        count: { type: Number, default: 0 },
        distribution: {
            1: { type: Number, default: 0 },
            2: { type: Number, default: 0 },
            3: { type: Number, default: 0 },
            4: { type: Number, default: 0 },
            5: { type: Number, default: 0 }
        }
    },
    popularityScore: {
        type: Number,
        default: 0,
        min: 0,
        max: 100,
        index: true
    },
    trendingScore: {
        type: Number,
        default: 0,
        min: 0,
        max: 100
    },
    conversionRate: { type: Number, default: 0, min: 0, max: 100 },
    avgCustomizationTime: { type: Number, default: 0 }, // in seconds
    recentActivity: [{
        action: { type: String, enum: ['view', 'use', 'download', 'like', 'share', 'bookmark', 'rate'], required: true },
        userId: { type: String },
        timestamp: { type: Date, default: Date.now },
        metadata: { type: mongoose.Schema.Types.Mixed }
    }]
}, { _id: false });

const compatibilitySchema = new mongoose.Schema({
    platforms: [{
        type: String,
        enum: ['web', 'mobile', 'desktop', 'tablet', 'print'],
        index: true
    }],
    browsers: [{
        type: String,
        enum: ['chrome', 'firefox', 'safari', 'edge', 'opera', 'ie11']
    }],
    devices: [{
        type: String,
        enum: ['desktop', 'laptop', 'tablet', 'mobile', 'smart-tv', 'smartwatch']
    }],
    outputFormats: [{
        format: { type: String, enum: ['jpeg', 'png', 'webp', 'svg', 'pdf', 'gif'], required: true },
        quality: { type: String, enum: ['web', 'print', 'high'], default: 'web' },
        maxSize: { type: Number, min: 0 }, // in MB
        supported: { type: Boolean, default: true }
    }],
    socialPlatforms: [{
        platform: { type: String, enum: ['linkedin', 'facebook', 'twitter', 'instagram', 'youtube', 'pinterest'], required: true },
        dimensions: {
            width: { type: Number, required: true, min: 100 },
            height: { type: Number, required: true, min: 100 },
            aspectRatio: { type: Number, required: true }
        },
        recommendations: [{ type: String, maxlength: 200 }]
    }],
    printSpecs: {
        minDPI: { type: Number, default: 300, min: 72 },
        colorProfile: { type: String, enum: ['RGB', 'CMYK'], default: 'RGB' },
        bleedRequirement: { type: Number, default: 0, min: 0 }
    }
}, { _id: false });

const accessControlSchema = new mongoose.Schema({
    visibility: {
        type: String,
        enum: ['public', 'private', 'restricted'],
        default: 'public',
        index: true
    },
    allowedUsers: [{
        type: String,
        validate: {
            validator: function (v) {
                return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(v);
            },
            message: 'Invalid user UUID'
        },
        index: true
    }],
    allowedGroups: [{
        type: String,
        validate: {
            validator: function (v) {
                return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(v);
            },
            message: 'Invalid group UUID'
        },
        index: true
    }],
    organizationId: { type: String, index: true },
    teamId: { type: String, index: true }
}, { _id: false });

// ===========================
// MAIN TEMPLATE SCHEMA
// ===========================
const templateSchema = new mongoose.Schema({
    templateId: {
        type: String,
        required: true,
        unique: true,
        index: true,
        immutable: true
    },
    createdBy: {
        type: String,
        required: true,
        index: true
    },
    name: {
        type: String,
        required: true,
        trim: true,
        maxlength: 200,
        index: 'text'
    },
    description: {
        type: String,
        default: '',
        maxlength: 2000,
        index: 'text'
    },
    category: {
        type: String,
        enum: ['business', 'creative', 'minimal', 'modern', 'vintage', 'abstract', 'nature', 'technology', 'professional', 'artistic'],
        required: true,
        index: true
    },
    subcategory: {
        type: String,
        default: '',
        maxlength: 50,
        index: true
    },
    tags: [{
        type: String,
        trim: true,
        maxlength: 30,
        index: true
    }],
    canvas: {
        type: canvasSchema,
        required: true
    },
    layers: [layerSchema],
    previews: {
        type: previewSchema,
        required: true
    },
    usageStats: {
        type: usageStatsSchema,
        default: () => ({})
    },
    compatibility: {
        type: compatibilitySchema,
        default: () => ({})
    },
    accessControl: {
        type: accessControlSchema,
        default: () => ({})
    },
    pricing: {
        type: {
            type: String,
            enum: ['free', 'premium', 'pro', 'enterprise'],
            default: 'free',
            index: true
        },
        price: {
            type: Number,
            default: 0,
            min: 0
        },
        currency: {
            type: String,
            default: 'USD',
            enum: ['USD', 'EUR', 'GBP', 'INR', 'JPY']
        },
        discounts: [{
            type: { type: String, enum: ['percentage', 'fixed'], required: true },
            value: { type: Number, required: true, min: 0 },
            code: { type: String, unique: true, sparse: true },
            validFrom: { type: Date, required: true },
            validUntil: { type: Date, required: true },
            usageLimit: { type: Number, default: 0, min: 0 },
            usageCount: { type: Number, default: 0, min: 0 }
        }]
    },
    customization: {
        difficulty: {
            type: String,
            enum: ['beginner', 'intermediate', 'advanced'],
            default: 'beginner',
            index: true
        },
        customizableElements: [{
            elementId: { type: String, required: true },
            elementType: { type: String, enum: ['text', 'image', 'color', 'font', 'size', 'position'], required: true },
            label: { type: String, required: true, maxlength: 100 },
            description: { type: String, default: '', maxlength: 500 },
            required: { type: Boolean, default: false },
            defaultValue: { type: String, default: '' },
            validation: {
                type: { type: String, enum: ['text', 'email', 'url', 'number', 'color'], default: 'text' },
                minLength: { type: Number, min: 0 },
                maxLength: { type: Number, min: 0 },
                pattern: { type: String },
                options: [{ type: String, maxlength: 100 }]
            }
        }],
        presetVariations: [{
            name: { type: String, required: true, maxlength: 100 },
            description: { type: String, default: '', maxlength: 500 },
            previewUrl: { type: String, required: true },
            modifications: [{ type: mongoose.Schema.Types.Mixed }]
        }],
        colorSchemes: [{
            name: { type: String, required: true, maxlength: 100 },
            colors: [{
                role: { type: String, enum: ['primary', 'secondary', 'accent', 'background', 'text'], required: true },
                value: { type: String, required: true, match: /^#[0-9A-F]{6}$/i }
            }],
            previewUrl: { type: String }
        }],
        fontPairings: [{
            name: { type: String, required: true, maxlength: 100 },
            heading: { type: String, required: true },
            body: { type: String, required: true },
            accent: { type: String, default: '' }
        }]
    },
    aiFeatures: {
        smartResize: { type: Boolean, default: false },
        autoColorAdjustment: { type: Boolean, default: false },
        contentSuggestions: { type: Boolean, default: false },
        brandMatching: { type: Boolean, default: false },
        generatedVariations: [{
            name: { type: String, required: true, maxlength: 100 },
            description: { type: String, default: '', maxlength: 500 },
            previewUrl: { type: String, required: true },
            aiPrompt: { type: String, maxlength: 500 },
            generatedAt: { type: Date, default: Date.now }
        }],
        optimizationSuggestions: [{
            type: { type: String, enum: ['layout', 'color', 'typography', 'imagery'], required: true },
            suggestion: { type: String, required: true, maxlength: 500 },
            confidence: { type: Number, min: 0, max: 1 },
            impact: { type: String, enum: ['low', 'medium', 'high'], default: 'medium' }
        }]
    },
    collaboration: {
        allowCollaboration: { type: Boolean, default: false },
        collaborators: [{
            userId: { type: String, required: true },
            role: { type: String, enum: ['viewer', 'editor', 'admin'], required: true },
            permissions: [{
                type: String,
                enum: ['view', 'edit', 'comment', 'share', 'delete']
            }],
            invitedAt: { type: Date, default: Date.now },
            invitedBy: { type: String, required: true },
            acceptedAt: { type: Date }
        }],
        comments: [{
            commentId: { type: String, required: true },
            userId: { type: String, required: true },
            content: { type: String, required: true, maxlength: 1000 },
            position: {
                x: { type: Number },
                y: { type: Number }
            },
            layerId: { type: String },
            resolved: { type: Boolean, default: false },
            replies: [{
                userId: { type: String, required: true },
                content: { type: String, required: true, maxlength: 500 },
                createdAt: { type: Date, default: Date.now }
            }],
            createdAt: { type: Date, default: Date.now }
        }],
        revisionHistory: [{
            revisionId: { type: String, required: true },
            userId: { type: String, required: true },
            changes: { type: String, required: true, maxlength: 1000 },
            snapshot: { type: mongoose.Schema.Types.Mixed },
            createdAt: { type: Date, default: Date.now }
        }]
    },
    quality: {
        designScore: { type: Number, default: 0, min: 0, max: 10, index: true },
        usabilityScore: { type: Number, default: 0, min: 0, max: 10 },
        accessibilityScore: { type: Number, default: 0, min: 0, max: 10 },
        performanceScore: { type: Number, default: 0, min: 0, max: 10 },
        overallQuality: { type: Number, default: 0, min: 0, max: 10, index: true },
        reviewStatus: {
            type: String,
            enum: ['pending', 'approved', 'rejected', 'needs-improvement'],
            default: 'pending',
            index: true
        },
        reviewedBy: { type: String },
        reviewedAt: { type: Date },
        reviewNotes: { type: String, maxlength: 1000 }
    },
    licensing: {
        license: {
            type: String,
            enum: ['cc0', 'cc-by', 'cc-by-sa', 'cc-by-nc', 'cc-by-nc-sa', 'proprietary', 'custom'],
            default: 'cc0',
            index: true
        },
        attribution: {
            required: { type: Boolean, default: false },
            text: { type: String, default: '', maxlength: 200 }
        },
        commercialUse: { type: Boolean, default: true },
        modifications: { type: Boolean, default: true },
        redistribution: { type: Boolean, default: true },
        customTerms: { type: String, default: '', maxlength: 2000 }
    },
    analytics: {
        conversionRate: { type: Number, default: 0, min: 0, max: 100 },
        avgRating: { type: Number, default: 0, min: 0, max: 5 },
        completionRate: { type: Number, default: 0, min: 0, max: 100 },
        timeToComplete: { type: Number, default: 0, min: 0 }, // seconds
        dropoffPoints: [{
            step: { type: String, required: true, maxlength: 100 },
            percentage: { type: Number, min: 0, max: 100 }
        }],
        userSegments: [{
            segment: { type: String, required: true, maxlength: 100 },
            usage: { type: Number, min: 0 },
            satisfaction: { type: Number, min: 0, max: 5 }
        }],
        seasonalTrends: [{
            month: { type: Number, min: 1, max: 12 },
            usage: { type: Number, default: 0, min: 0 }
        }],
        deviceUsage: {
            desktop: { type: Number, default: 0, min: 0 },
            mobile: { type: Number, default: 0, min: 0 },
            tablet: { type: Number, default: 0, min: 0 }
        }
    },
    metadata: {
        industry: [{
            type: String,
            enum: ['technology', 'finance', 'healthcare', 'education', 'retail', 'real-estate', 'consulting', 'marketing', 'non-profit', 'government', 'entertainment', 'food-beverage'],
            index: true
        }],
        designStyle: [{
            type: String,
            enum: ['minimalist', 'modern', 'vintage', 'corporate', 'creative', 'elegant', 'bold', 'playful', 'professional', 'artistic'],
            index: true
        }],
        colorPalette: [{
            name: { type: String, required: true, maxlength: 100 },
            hex: { type: String, required: true, match: /^#[0-9A-F]{6}$/i },
            role: { type: String, enum: ['primary', 'secondary', 'accent', 'neutral'], required: true }
        }],
        targetAudience: [{
            type: String,
            enum: ['business-professionals', 'entrepreneurs', 'creatives', 'students', 'marketers', 'developers', 'designers', 'small-business', 'enterprise', 'personal'],
            index: true
        }],
        skillLevel: {
            type: String,
            enum: ['beginner', 'intermediate', 'advanced', 'expert'],
            default: 'beginner',
            index: true
        },
        timeToCustomize: {
            type: Number,
            min: 1,
            max: 120, // minutes
            default: 15
        },
        keywords: [{
            type: String,
            trim: true,
            maxlength: 50,
            index: true
        }],
        language: {
            type: String,
            default: 'en',
            index: true
        },
        region: [{
            type: String,
            enum: ['global', 'north-america', 'europe', 'asia-pacific', 'latin-america', 'middle-east', 'africa'],
            index: true
        }],
        dependencies: [{
            templateId: { type: String, index: true },
            version: { type: String, default: 'latest' },
            purpose: { type: String, enum: ['base', 'overlay', 'component'], default: 'component' }
        }]
    },
    versions: [{
        versionId: { type: String, required: true },
        versionNumber: { type: String, required: true },
        changelog: { type: String, maxlength: 1000 },
        layers: [layerSchema],
        canvas: canvasSchema,
        previewUrl: { type: String, required: true },
        isActive: { type: Boolean, default: false },
        createdAt: { type: Date, default: Date.now },
        createdBy: { type: String, required: true },
        quality: {
            layerQualityScore: { type: Number, default: 0, min: 0, max: 10 },
            overallQuality: { type: Number, default: 0, min: 0, max: 10 }
        }
    }],
    status: {
        type: String,
        enum: ['draft', 'active', 'inactive', 'archived', 'deleted', 'under-review'],
        default: 'draft',
        index: true
    },
    createdAt: {
        type: Date,
        default: Date.now,
        index: true
    },
    updatedAt: {
        type: Date,
        default: Date.now,
        index: true
    },
    lastUsedAt: {
        type: Date,
        index: true
    },
    cacheVersion: {
        type: Number,
        default: 0
    }
}, {
    timestamps: {
        createdAt: 'createdAt',
        updatedAt: 'updatedAt'
    },
    versionKey: 'version',
    strict: true,
    collection: 'templates',
    read: 'secondaryPreferred',
    shardKey: { category: 1, createdBy: 1 },
    toJSON: {
        transform: function (doc, ret) {
            ret.id = ret._id;
            delete ret._id;
            delete ret.__v;
            return ret;
        }
    },
    toObject: {
        transform: function (doc, ret) {
            ret.id = ret._id;
            delete ret._id;
            delete ret.__v;
            return ret;
        }
    }
});

// ===========================
// OPTIMIZED INDEXES
// ===========================
templateSchema.index({ templateId: 1 }, { unique: true, name: 'idx_templateId_unique' });
templateSchema.index({ createdBy: 1, status: 1 }, { name: 'idx_creator_status' });
templateSchema.index({ category: 1, status: 1, 'accessControl.visibility': 1 }, { name: 'idx_category_search' });
templateSchema.index({ 'usageStats.popularityScore': -1, status: 1 }, { name: 'idx_popularity' });
templateSchema.index({ 'quality.overallQuality': -1, status: 1 }, { name: 'idx_quality' });
templateSchema.index({ 'usageStats.ratings.average': -1, 'usageStats.totalUses': -1 }, { name: 'idx_rating_usage' });
templateSchema.index({ 'pricing.type': 1, category: 1, status: 1 }, { name: 'idx_pricing_category' });
templateSchema.index({ 'metadata.industry': 1, status: 1, 'accessControl.visibility': 1 }, { name: 'idx_industry' });
templateSchema.index({ 'metadata.targetAudience': 1, status: 1 }, { name: 'idx_target_audience' });
templateSchema.index({ 'metadata.skillLevel': 1, 'customization.difficulty': 1 }, { name: 'idx_difficulty' });
templateSchema.index({ 'canvas.aspectRatio': 1, category: 1, status: 1 }, { name: 'idx_aspect_ratio' });
templateSchema.index({ tags: 1, status: 1, 'accessControl.visibility': 1 }, { name: 'idx_tags' });
templateSchema.index({ 'metadata.colorPalette.hex': 1, status: 1 }, { name: 'idx_colors' });
templateSchema.index({ lastUsedAt: -1, 'usageStats.totalUses': -1 }, { name: 'idx_recent_popular' });
templateSchema.index({ updatedAt: -1, status: 1 }, { name: 'idx_recent_updates' });
templateSchema.index({ 'quality.reviewStatus': 1, createdAt: -1 }, { name: 'idx_review_queue' });
templateSchema.index({ 'accessControl.allowedUsers': 1, status: 1 }, { name: 'idx_allowed_users' });
templateSchema.index({ 'accessControl.allowedGroups': 1, status: 1 }, { name: 'idx_allowed_groups' });
templateSchema.index({ 'metadata.dependencies.templateId': 1, status: 1 }, { name: 'idx_dependencies' });
templateSchema.index({
    name: 'text',
    description: 'text',
    tags: 'text',
    'metadata.keywords': 'text',
    'customization.customizableElements.label': 'text'
}, {
    weights: {
        name: 10,
        tags: 8,
        'metadata.keywords': 6,
        description: 4,
        'customization.customizableElements.label': 2
    },
    name: 'idx_fulltext_search'
});

// ===========================
// PRE/POST HOOKS
// ===========================
templateSchema.pre('save', function (next) {
    if (!this.templateId) {
        this.templateId = this.generateTemplateId();
    }

    if (this.canvas?.width && this.canvas?.height) {
        this.canvas.aspectRatio = Math.round((this.canvas.width / this.canvas.height) * 100) / 100;
    }

    this.calculateQualityScores();
    this.calculatePopularityScore();

    if (this.isModified() && !this.isNew) {
        this.cacheVersion += 1;
    }

    this.updatedAt = new Date();
    next();
});

templateSchema.pre(/^find/, function (next) {
    if (!this.getQuery().status) {
        this.where({ status: { $ne: 'deleted' } });
    }
    next();
});

templateSchema.pre(['findOneAndUpdate', 'updateOne', 'updateMany'], function (next) {
    this.set({ updatedAt: new Date(), cacheVersion: { $inc: 1 } });
    next();
});

// ===========================
// INSTANCE METHODS
// ===========================
templateSchema.methods.generateTemplateId = function () {
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substring(2, 8);
    return `tpl_${timestamp}${random}`;
};

templateSchema.methods.calculateQualityScores = function () {
    let designScore = 0;

    // Layer quality (up to 3 points)
    const layerCount = this.layers.length;
    if (layerCount >= 3 && layerCount <= 10) designScore += 3;
    else if (layerCount > 10) designScore += 2;
    else designScore += layerCount * 0.5;

    // Color harmony (up to 2.5 points)
    const colors = this.metadata?.colorPalette || [];
    if (colors.length >= 3) designScore += 2.5;
    else if (colors.length >= 2) designScore += 1.5;

    // Canvas setup (up to 2 points)
    if (this.canvas?.width && this.canvas?.height) {
        const aspectRatio = this.canvas.aspectRatio || 1;
        if (aspectRatio >= 0.5 && aspectRatio <= 2) designScore += 2;
        else designScore += 1;
    }

    // Customization options (up to 2.5 points)
    const customizableCount = this.customization?.customizableElements?.length || 0;
    if (customizableCount >= 5) designScore += 2.5;
    else designScore += customizableCount * 0.5;

    this.quality.designScore = Math.min(designScore, 10);

    // Usability Score
    let usabilityScore = 0;
    if (this.customization?.difficulty === 'beginner') usabilityScore += 4;
    else if (this.customization?.difficulty === 'intermediate') usabilityScore += 3;
    else usabilityScore += 2;

    if (this.metadata?.timeToCustomize <= 10) usabilityScore += 3;
    else if (this.metadata?.timeToCustomize <= 30) usabilityScore += 2;
    else usabilityScore += 1;

    if (this.previews?.thumbnail?.url && this.previews?.preview?.url) usabilityScore += 3;

    this.quality.usabilityScore = Math.min(usabilityScore, 10);

    // Overall Quality
    this.quality.overallQuality = Math.round(
        (this.quality.designScore * 0.5) +
        (this.quality.usabilityScore * 0.3) +
        (this.quality.performanceScore * 0.2)
    );

    // Layer Quality
    let layerQualityScore = 0;
    const hasTextLayer = this.layers.some(layer => layer.type === 'text');
    const hasImageLayer = this.layers.some(layer => layer.type === 'image');
    if (hasTextLayer && hasImageLayer) layerQualityScore += 4;
    else if (hasTextLayer || hasImageLayer) layerQualityScore += 2;

    const hasAnimations = this.layers.some(layer => layer.animations?.length > 0);
    if (hasAnimations) layerQualityScore += 3;

    const hasCustomizable = this.layers.some(layer => layer.customizable);
    if (hasCustomizable) layerQualityScore += 3;

    this.layers.forEach(layer => {
        layer.quality.layerQualityScore = Math.min(layerQualityScore, 10);
    });

    return this.quality;
};

templateSchema.methods.calculatePopularityScore = function () {
    const uses = this.usageStats.totalUses || 0;
    const views = this.usageStats.totalViews || 0;
    const rating = this.usageStats.ratings?.average || 0;
    const downloads = this.usageStats.totalDownloads || 0;

    const ageInDays = (Date.now() - this.createdAt) / (1000 * 60 * 60 * 24);
    const ageFactor = Math.max(0.1, 1 - (ageInDays / 365));

    const baseScore = (uses * 2) + (views * 0.1) + (rating * 10) + (downloads * 5) + (this.quality.overallQuality * 3);
    this.usageStats.popularityScore = Math.min(100, Math.round(baseScore * ageFactor));

    return this.usageStats.popularityScore;
};

templateSchema.methods.incrementUsage = async function (userId = null, action = 'use') {
    const now = new Date();

    switch (action) {
        case 'use':
            this.usageStats.totalUses += 1;
            this.lastUsedAt = now;
            break;
        case 'view':
            this.usageStats.totalViews += 1;
            break;
        case 'download':
            this.usageStats.totalDownloads += 1;
            break;
        case 'like':
            this.usageStats.likes += 1;
            break;
        case 'share':
            this.usageStats.shares += 1;
            break;
        case 'bookmark':
            this.usageStats.bookmarks += 1;
            break;
    }

    // Add to recent activity (keep last 50)
    this.usageStats.recentActivity.unshift({
        action,
        userId,
        timestamp: now
    });

    if (this.usageStats.recentActivity.length > 50) {
        this.usageStats.recentActivity = this.usageStats.recentActivity.slice(0, 50);
    }

    this.calculatePopularityScore();
    this.cacheVersion += 1;

    return this.save({ validateBeforeSave: false });
};

templateSchema.methods.createVersion = function (changes = '', layers = null, canvas = null, qualityData = {}) {
    const versionId = `v${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    const versionNumber = `${this.versions.length + 1}.0`;

    // Mark current versions as inactive
    this.versions.forEach(v => v.isActive = false);

    this.versions.push({
        versionId,
        versionNumber,
        changelog: changes,
        layers: layers || this.layers,
        canvas: canvas || this.canvas,
        previewUrl: this.previews.preview.url,
        isActive: true,
        createdAt: new Date(),
        createdBy: this.createdBy,
        quality: qualityData
    });

    // Keep only last 10 versions
    if (this.versions.length > 10) {
        this.versions = this.versions.slice(-10);
    }

    return versionId;
};

templateSchema.methods.updateLayerQuality = function (layerId, metrics) {
    const layer = this.layers.find(l => l.id === layerId);
    if (layer) {
        layer.quality.layerQualityScore = metrics.layerQualityScore || layer.quality.layerQualityScore;
        layer.quality.lastAssessedAt = new Date();
        this.calculateQualityScores();
        this.cacheVersion += 1;
        return this.save({ validateBeforeSave: false });
    }
    return null;
};

templateSchema.methods.getPublicData = function () {
    const template = this.toObject();

    // Remove sensitive data
    delete template.collaboration.revisionHistory;
    delete template.usageStats.recentActivity;
    delete template.versions;

    // Simplify analytics
    template.analytics = {
        conversionRate: template.analytics.conversionRate,
        avgRating: template.analytics.avgRating,
        totalUses: template.usageStats.totalUses,
        totalViews: template.usageStats.totalViews
    };

    return template;
};

// ===========================
// STATIC METHODS
// ===========================
templateSchema.statics.findByCategory = function (category, options = {}) {
    const {
        page = 1,
        limit = 20,
        sortBy = 'popularity',
        pricing = 'all',
        difficulty = 'all',
        minRating = 0,
        userId,
        allowedGroups = []
    } = options;

    const query = {
        category,
        status: 'active',
        'quality.reviewStatus': 'approved'
    };

    if (pricing !== 'all') {
        query['pricing.type'] = pricing;
    }

    if (difficulty !== 'all') {
        query['customization.difficulty'] = difficulty;
    }

    if (minRating > 0) {
        query['usageStats.ratings.average'] = { $gte: minRating };
    }

    if (userId) {
        query.$or = [
            { 'accessControl.visibility': 'public' },
            { createdBy: userId },
            { 'accessControl.visibility': 'restricted', 'accessControl.allowedUsers': userId },
            { 'accessControl.visibility': 'restricted', 'accessControl.allowedGroups': { $in: allowedGroups } }
        ];
    } else {
        query['accessControl.visibility'] = 'public';
    }

    let sortOption = {};
    switch (sortBy) {
        case 'recent':
            sortOption = { createdAt: -1 };
            break;
        case 'popular':
            sortOption = { 'usageStats.popularityScore': -1, 'usageStats.totalUses': -1 };
            break;
        case 'rating':
            sortOption = { 'usageStats.ratings.average': -1, 'usageStats.ratings.count': -1 };
            break;
        case 'quality':
            sortOption = { 'quality.overallQuality': -1 };
            break;
        case 'uses':
            sortOption = { 'usageStats.totalUses': -1 };
            break;
        default:
            sortOption = { 'usageStats.popularityScore': -1, createdAt: -1 };
    }

    const skip = (page - 1) * limit;

    return this.find(query)
        .sort(sortOption)
        .skip(skip)
        .limit(limit)
        .select('-versions -collaboration.revisionHistory -usageStats.recentActivity')
        .cache({ key: `templates:category:${category}:${page}:${limit}:${sortBy}:${userId || 'public'}` })
        .lean();
};

templateSchema.statics.searchTemplates = function (searchQuery, filters = {}) {
    const {
        categories = [],
        industries = [],
        targetAudience = [],
        priceRange = 'all',
        difficulty = 'all',
        aspectRatios = [],
        colors = [],
        page = 1,
        limit = 20,
        userId,
        allowedGroups = []
    } = filters;

    const pipeline = [];

    const matchStage = {
        status: 'active',
        'quality.reviewStatus': 'approved'
    };

    if (searchQuery && searchQuery.trim()) {
        matchStage.$text = { $search: searchQuery.trim() };
    }

    if (categories.length > 0) {
        matchStage.category = { $in: categories };
    }

    if (industries.length > 0) {
        matchStage['metadata.industry'] = { $in: industries };
    }

    if (targetAudience.length > 0) {
        matchStage['metadata.targetAudience'] = { $in: targetAudience };
    }

    if (priceRange !== 'all') {
        if (priceRange === 'free') {
            matchStage['pricing.type'] = 'free';
        } else if (priceRange === 'paid') {
            matchStage['pricing.type'] = { $ne: 'free' };
        }
    }

    if (difficulty !== 'all') {
        matchStage['customization.difficulty'] = difficulty;
    }

    if (aspectRatios.length > 0) {
        matchStage['canvas.aspectRatio'] = { $in: aspectRatios };
    }

    if (userId) {
        matchStage.$or = [
            { 'accessControl.visibility': 'public' },
            { createdBy: userId },
            { 'accessControl.visibility': 'restricted', 'accessControl.allowedUsers': userId },
            { 'accessControl.visibility': 'restricted', 'accessControl.allowedGroups': { $in: allowedGroups } }
        ];
    } else {
        matchStage['accessControl.visibility'] = 'public';
    }

    pipeline.push({ $match: matchStage });

    // Add relevance scoring
    pipeline.push({
        $addFields: {
            relevanceScore: {
                $add: [
                    { $multiply: ['$usageStats.popularityScore', 0.4] },
                    { $multiply: ['$quality.overallQuality', 0.3] },
                    { $multiply: ['$usageStats.ratings.average', 0.6] },
                    searchQuery && searchQuery.trim() ? { $meta: 'textScore' } : 0
                ]
            }
        }
    });

    pipeline.push({ $sort: { relevanceScore: -1, createdAt: -1 } });

    const skip = (page - 1) * limit;
    pipeline.push({ $skip: skip });
    pipeline.push({ $limit: limit });

    pipeline.push({
        $project: {
            templateId: 1,
            createdBy: 1,
            name: 1,
            description: 1,
            category: 1,
            tags: 1,
            'canvas.width': 1,
            'canvas.height': 1,
            'canvas.aspectRatio': 1,
            'previews.thumbnail': 1,
            'previews.preview': 1,
            'usageStats.totalUses': 1,
            'usageStats.ratings.average': 1,
            'usageStats.ratings.count': 1,
            'usageStats.popularityScore': 1,
            'pricing.type': 1,
            'pricing.price': 1,
            'customization.difficulty': 1,
            'metadata.timeToCustomize': 1,
            'quality.overallQuality': 1,
            createdAt: 1,
            relevanceScore: 1
        }
    });

    return this.aggregate(pipeline).cache({ key: `search:templates:${searchQuery}:${JSON.stringify(filters)}:${userId || 'public'}` });
};

templateSchema.statics.getFeaturedTemplates = function (limit = 10, category = null, userId = null, allowedGroups = []) {
    const query = {
        status: 'active',
        'accessControl.visibility': { $in: ['public', 'restricted'] },
        'quality.reviewStatus': 'approved'
    };

    if (category) {
        query.category = category;
    }

    if (userId) {
        query.$or = [
            { 'accessControl.visibility': 'public' },
            { createdBy: userId },
            { 'accessControl.visibility': 'restricted', 'accessControl.allowedUsers': userId },
            { 'accessControl.visibility': 'restricted', 'accessControl.allowedGroups': { $in: allowedGroups } }
        ];
    } else {
        query['accessControl.visibility'] = 'public';
    }

    return this.find(query)
        .sort({ 'usageStats.popularityScore': -1, createdAt: -1 })
        .limit(limit)
        .select('templateId name category previews.thumbnail usageStats.totalUses usageStats.ratings.average pricing.type')
        .cache({ key: `featured:${category || 'all'}:${limit}:${userId || 'public'}` })
        .lean();
};

templateSchema.statics.getTrendingTemplates = function (timeframe = 7, limit = 20, userId = null, allowedGroups = []) {
    const daysAgo = new Date();
    daysAgo.setDate(daysAgo.getDate() - timeframe);

    const query = {
        status: 'active',
        'quality.reviewStatus': 'approved',
        updatedAt: { $gte: daysAgo },
        'usageStats.totalUses': { $gte: 3 }
    };

    if (userId) {
        query.$or = [
            { 'accessControl.visibility': 'public' },
            { createdBy: userId },
            { 'accessControl.visibility': 'restricted', 'accessControl.allowedUsers': userId },
            { 'accessControl.visibility': 'restricted', 'accessControl.allowedGroups': { $in: allowedGroups } }
        ];
    } else {
        query['accessControl.visibility'] = 'public';
    }

    return this.find(query)
        .sort({
            'usageStats.popularityScore': -1,
            'usageStats.totalUses': -1,
            'quality.overallQuality': -1
        })
        .limit(limit)
        .select('templateId name category previews.thumbnail usageStats.popularityScore usageStats.totalUses quality.overallQuality')
        .cache({ key: `trending:templates:${timeframe}:${limit}:${userId || 'public'}` })
        .lean();
};

templateSchema.statics.getDependentTemplates = function (templateId, options = {}) {
    const { page = 1, limit = 20, sortBy = 'popularity' } = options;

    const query = {
        'metadata.dependencies.templateId': templateId,
        status: 'active',
        'quality.reviewStatus': 'approved'
    };

    let sortOption = {};
    switch (sortBy) {
        case 'recent':
            sortOption = { createdAt: -1 };
            break;
        case 'popular':
            sortOption = { 'usageStats.popularityScore': -1, 'usageStats.totalUses': -1 };
            break;
        case 'quality':
            sortOption = { 'quality.overallQuality': -1 };
            break;
        default:
            sortOption = { 'usageStats.popularityScore': -1, createdAt: -1 };
    }

    const skip = (page - 1) * limit;

    return this.find(query)
        .sort(sortOption)
        .skip(skip)
        .limit(limit)
        .select('templateId name category previews.thumbnail usageStats.popularityScore quality.overallQuality')
        .cache({ key: `dependent:templates:${templateId}:${page}:${limit}:${sortBy}` })
        .lean();
};

// Export model
const Template = mongoose.model('Template', templateSchema);

Template.createCollection({
    capped: false,
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: ["templateId", "createdBy", "name", "category", "canvas", "layers", "previews"],
            properties: {
                templateId: {
                    bsonType: "string",
                    description: "Template ID is required and must be a string"
                },
                createdBy: {
                    bsonType: "string",
                    description: "Creator ID is required and must be a string"
                },
                name: {
                    bsonType: "string",
                    maxLength: 200,
                    description: "Template name is required with max length 200"
                },
                category: {
                    bsonType: "string",
                    enum: ['business', 'creative', 'minimal', 'modern', 'vintage', 'abstract', 'nature', 'technology', 'professional', 'artistic'],
                    description: "Category must be from predefined list"
                }
            }
        }
    }
}).catch((error) => {
    // console.loga
});

export default Template;