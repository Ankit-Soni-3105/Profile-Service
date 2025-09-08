import mongoose from 'mongoose';
import { createHash } from 'crypto';

// ===========================
// OPTIMIZED SUB-SCHEMAS
// ===========================
const exportHistorySchema = new mongoose.Schema({
    exportId: {
        type: String,
        required: true,
        validate: {
            validator: function (v) {
                return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(v);
            },
            message: 'Invalid export UUID'
        }
    },
    format: {
        type: String,
        enum: ['jpeg', 'png', 'webp', 'svg', 'pdf', 'gif'],
        required: true,
        index: true
    },
    quality: {
        type: String,
        enum: ['web', 'print', 'high'],
        default: 'web'
    },
    dimensions: {
        width: { type: Number, required: true, min: 100, max: 8192 },
        height: { type: Number, required: true, min: 100, max: 8192 }
    },
    fileSize: { type: Number, min: 0 }, // in bytes
    downloadUrl: { type: String, required: true },
    exportedAt: { type: Date, default: Date.now, index: true },
    expiresAt: { type: Date }, // URL expiration
    downloadCount: { type: Number, default: 0, min: 0 },
    settings: {
        dpi: { type: Number, enum: [72, 150, 300, 600], default: 72 },
        colorSpace: { type: String, enum: ['RGB', 'CMYK', 'sRGB', 'Adobe RGB'], default: 'sRGB' },
        compression: { type: Number, min: 10, max: 100, default: 85 },
        includeBleed: { type: Boolean, default: false },
        cropMarks: { type: Boolean, default: false }
    }
}, { _id: false });

const customizationSchema = new mongoose.Schema({
    elementId: {
        type: String,
        required: true,
        validate: {
            validator: function (v) {
                return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(v);
            },
            message: 'Invalid element UUID'
        }
    },
    elementType: {
        type: String,
        enum: ['text', 'image', 'color', 'font', 'size', 'position', 'opacity', 'rotation'],
        required: true,
        index: true
    },
    originalValue: { type: mongoose.Schema.Types.Mixed },
    customValue: { type: mongoose.Schema.Types.Mixed },
    timestamp: { type: Date, default: Date.now },
    confidence: { type: Number, min: 0, max: 1, default: 1 }, // For AI suggestions
    source: {
        type: String,
        enum: ['user', 'ai-suggestion', 'template-default', 'auto-adjustment'],
        default: 'user'
    },
    validation: {
        type: { type: String, enum: ['text', 'email', 'url', 'number', 'color'], default: 'text' },
        minLength: { type: Number, min: 0 },
        maxLength: { type: Number, min: 0 },
        pattern: { type: String },
        options: [{ type: String, maxlength: 100 }]
    }
}, { _id: false });

const brandingSchema = new mongoose.Schema({
    enabled: { type: Boolean, default: false },
    brandProfile: {
        companyName: { type: String, default: '', maxlength: 100, trim: true },
        logo: {
            url: { type: String, default: '' },
            position: {
                type: String,
                enum: ['top-left', 'top-center', 'top-right', 'center-left', 'center', 'center-right', 'bottom-left', 'bottom-center', 'bottom-right'],
                default: 'bottom-right'
            },
            size: { type: Number, min: 0.1, max: 1, default: 0.2 }, // percentage
            opacity: { type: Number, min: 0.1, max: 1, default: 1 }
        },
        colors: {
            primary: { type: String, default: '#000000', match: /^#[0-9A-F]{6}$/i },
            secondary: { type: String, default: '#000000', match: /^#[0-9A-F]{6}$/i },
            accent: { type: String, default: '#000000', match: /^#[0-9A-F]{6}$/i },
            text: { type: String, default: '#000000', match: /^#[0-9A-F]{6}$/i },
            background: { type: String, default: '#FFFFFF', match: /^#[0-9A-F]{6}$|^transparent$/i }
        },
        fonts: {
            primary: { type: String, default: 'Arial' },
            secondary: { type: String, default: 'Arial' },
            accent: { type: String, default: 'Arial' }
        },
        style: {
            type: String,
            enum: ['professional', 'creative', 'minimal', 'bold', 'elegant'],
            default: 'professional'
        }
    },
    appliedElements: [{
        elementId: { type: String, required: true },
        brandingType: {
            type: String,
            enum: ['color', 'font', 'logo', 'style'],
            required: true
        },
        appliedAt: { type: Date, default: Date.now }
    }],
    autoApply: { type: Boolean, default: false },
    consistency: { type: Number, min: 0, max: 100, default: 0, index: true }
}, { _id: false });

const collaborationSchema = new mongoose.Schema({
    isCollaborative: { type: Boolean, default: false },
    shareSettings: {
        shareId: {
            type: String,
            unique: true,
            sparse: true,
            validate: {
                validator: function (v) {
                    return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(v);
                },
                message: 'Invalid share UUID'
            }
        },
        accessLevel: {
            type: String,
            enum: ['view', 'comment', 'edit', 'admin'],
            default: 'view'
        },
        passwordProtected: { type: Boolean, default: false },
        password: { type: String, default: '' }, // Hashed
        expiresAt: { type: Date },
        allowDownload: { type: Boolean, default: false },
        allowCopy: { type: Boolean, default: false }
    },
    collaborators: [{
        userId: {
            type: String,
            required: true,
            validate: {
                validator: function (v) {
                    return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(v);
                },
                message: 'Invalid user UUID'
            },
            index: true
        },
        email: { type: String, match: /^[^\s@]+@[^\s@]+\.[^\s@]+$/ },
        role: {
            type: String,
            enum: ['viewer', 'commenter', 'editor', 'admin'],
            required: true
        },
        permissions: [{
            type: String,
            enum: ['view', 'comment', 'edit', 'export', 'share', 'delete']
        }],
        invitedAt: { type: Date, default: Date.now },
        invitedBy: { type: String, required: true },
        acceptedAt: { type: Date },
        status: {
            type: String,
            enum: ['pending', 'accepted', 'declined', 'revoked'],
            default: 'pending'
        }
    }],
    comments: [{
        commentId: {
            type: String,
            required: true,
            validate: {
                validator: function (v) {
                    return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(v);
                },
                message: 'Invalid comment UUID'
            }
        },
        userId: { type: String, required: true },
        content: { type: String, required: true, maxlength: 1000, trim: true },
        position: {
            x: { type: Number },
            y: { type: Number },
            elementId: { type: String }
        },
        resolved: { type: Boolean, default: false },
        resolvedBy: { type: String },
        resolvedAt: { type: Date },
        replies: [{
            replyId: {
                type: String,
                required: true,
                validate: {
                    validator: function (v) {
                        return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(v);
                    },
                    message: 'Invalid reply UUID'
                }
            },
            userId: { type: String, required: true },
            content: { type: String, required: true, maxlength: 500, trim: true },
            createdAt: { type: Date, default: Date.now },
            edited: { type: Boolean, default: false },
            editedAt: { type: Date }
        }],
        priority: {
            type: String,
            enum: ['low', 'medium', 'high', 'urgent'],
            default: 'medium'
        },
        category: {
            type: String,
            enum: ['general', 'design', 'content', 'technical', 'branding'],
            default: 'general'
        },
        createdAt: { type: Date, default: Date.now },
        updatedAt: { type: Date, default: Date.now }
    }],
    activityLog: [{
        action: {
            type: String,
            enum: ['created', 'edited', 'commented', 'shared', 'exported', 'restored', 'duplicated'],
            required: true
        },
        userId: { type: String, required: true },
        details: { type: String, maxlength: 500, trim: true },
        elementId: { type: String },
        timestamp: { type: Date, default: Date.now },
        metadata: { type: mongoose.Schema.Types.Mixed }
    }]
}, { _id: false });

const versionHistorySchema = new mongoose.Schema({
    versionId: {
        type: String,
        required: true,
        validate: {
            validator: function (v) {
                return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(v);
            },
            message: 'Invalid version UUID'
        }
    },
    versionNumber: { type: String, required: true }, // e.g., "1.0", "1.1"
    name: { type: String, default: '', maxlength: 100, trim: true },
    description: { type: String, default: '', maxlength: 500, trim: true },
    snapshot: {
        customizations: [customizationSchema],
        branding: brandingSchema,
        canvas: { type: mongoose.Schema.Types.Mixed },
        layers: { type: mongoose.Schema.Types.Mixed }
    },
    changes: [{
        type: {
            type: String,
            enum: ['element-added', 'element-removed', 'element-modified', 'branding-applied', 'text-changed', 'image-changed', 'color-changed'],
            required: true
        },
        elementId: { type: String },
        before: { type: mongoose.Schema.Types.Mixed },
        after: { type: mongoose.Schema.Types.Mixed },
        description: { type: String, maxlength: 200, trim: true }
    }],
    createdBy: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, index: true },
    isAutoSave: { type: Boolean, default: false },
    previewUrl: { type: String, default: '' },
    size: { type: Number, default: 0, min: 0 }, // Snapshot size in bytes
    quality: {
        design: { type: Number, min: 0, max: 10, default: 0 },
        branding: { type: Number, min: 0, max: 10, default: 0 },
        accessibility: { type: Number, min: 0, max: 10, default: 0 },
        overall: { type: Number, min: 0, max: 10, default: 0 }
    }
}, { _id: false });

const aiAssistanceSchema = new mongoose.Schema({
    suggestions: [{
        suggestionId: {
            type: String,
            required: true,
            validate: {
                validator: function (v) {
                    return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(v);
                },
                message: 'Invalid suggestion UUID'
            }
        },
        type: {
            type: String,
            enum: ['color-palette', 'font-pairing', 'layout-improvement', 'content-suggestion', 'brand-consistency', 'accessibility'],
            required: true,
            index: true
        },
        title: { type: String, required: true, maxlength: 100, trim: true },
        description: { type: String, required: true, maxlength: 500, trim: true },
        elementId: { type: String },
        suggestedValue: { type: mongoose.Schema.Types.Mixed },
        currentValue: { type: mongoose.Schema.Types.Mixed },
        confidence: { type: Number, min: 0, max: 1, required: true },
        impact: {
            type: String,
            enum: ['low', 'medium', 'high'],
            default: 'medium'
        },
        category: {
            type: String,
            enum: ['design', 'usability', 'branding', 'accessibility', 'performance'],
            required: true
        },
        status: {
            type: String,
            enum: ['pending', 'accepted', 'rejected', 'dismissed'],
            default: 'pending',
            index: true
        },
        createdAt: { type: Date, default: Date.now },
        respondedAt: { type: Date }
    }],
    autoAdjustments: [{
        adjustmentId: {
            type: String,
            required: true,
            validate: {
                validator: function (v) {
                    return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(v);
                },
                message: 'Invalid adjustment UUID'
            }
        },
        type: {
            type: String,
            enum: ['smart-crop', 'color-harmony', 'text-scaling', 'element-alignment', 'spacing-optimization'],
            required: true
        },
        elementId: { type: String, required: true },
        before: { type: mongoose.Schema.Types.Mixed },
        after: { type: mongoose.Schema.Types.Mixed },
        reason: { type: String, maxlength: 300, trim: true },
        confidence: { type: Number, min: 0, max: 1 },
        appliedAt: { type: Date, default: Date.now },
        canRevert: { type: Boolean, default: true }
    }],
    preferences: {
        enableSuggestions: { type: Boolean, default: true },
        autoApplyLowRisk: { type: Boolean, default: false },
        suggestionFrequency: {
            type: String,
            enum: ['real-time', 'periodic', 'on-request'],
            default: 'periodic'
        },
        categories: [{
            type: String,
            enum: ['design', 'usability', 'branding', 'accessibility', 'performance']
        }]
    },
    learningData: {
        acceptanceRate: { type: Number, min: 0, max: 100, default: 0 },
        preferredSuggestionTypes: [{ type: String, maxlength: 100 }],
        rejectedSuggestionTypes: [{ type: String, maxlength: 100 }],
        designStyle: {
            type: String,
            enum: ['minimal', 'bold', 'elegant', 'playful', 'professional'],
            default: 'professional'
        },
        lastAnalyzed: { type: Date }
    }
}, { _id: false });

const performanceMetricsSchema = new mongoose.Schema({
    loadTimes: {
        initial: { type: Number, default: 0, min: 0 }, // milliseconds
        preview: { type: Number, default: 0, min: 0 },
        export: { type: Number, default: 0, min: 0 }
    },
    editingSessions: [{
        sessionId: {
            type: String,
            required: true,
            validate: {
                validator: function (v) {
                    return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(v);
                },
                message: 'Invalid session UUID'
            }
        },
        startTime: { type: Date, required: true },
        endTime: { type: Date },
        duration: { type: Number, min: 0 }, // milliseconds
        actions: { type: Number, default: 0, min: 0 },
        saves: { type: Number, default: 0, min: 0 },
        exports: { type: Number, default: 0, min: 0 }
    }],
    usage: {
        totalEdits: { type: Number, default: 0, min: 0 },
        totalSaves: { type: Number, default: 0, min: 0 },
        totalExports: { type: Number, default: 0, min: 0 },
        totalTimeSpent: { type: Number, default: 0, min: 0 }, // milliseconds
        averageSessionDuration: { type: Number, default: 0, min: 0 },
        completionRate: { type: Number, min: 0, max: 100, default: 0 }
    },
    errors: [{
        errorType: { type: String, required: true, maxlength: 100 },
        message: { type: String, required: true, maxlength: 500 },
        stack: { type: String, maxlength: 2000 },
        timestamp: { type: Date, default: Date.now },
        resolved: { type: Boolean, default: false },
        userAgent: { type: String, maxlength: 500 },
        url: { type: String, maxlength: 500 }
    }],
    feedback: {
        satisfaction: { type: Number, min: 1, max: 5 },
        easeOfUse: { type: Number, min: 1, max: 5 },
        featureCompleteness: { type: Number, min: 1, max: 5 },
        performance: { type: Number, min: 1, max: 5 },
        comments: { type: String, maxlength: 1000, trim: true },
        submittedAt: { type: Date }
    }
}, { _id: false });

const accessControlSchema = new mongoose.Schema({
    visibility: {
        type: String,
        enum: ['public', 'private', 'restricted'],
        default: 'private',
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
// MAIN DESIGN SCHEMA
// ===========================
const designSchema = new mongoose.Schema({
    designId: {
        type: String,
        required: true,
        unique: true,
        index: true,
        immutable: true
    },
    userId: {
        type: String,
        required: true,
        index: true
    },
    templateId: {
        type: String,
        index: true,
        validate: {
            validator: async function (v) {
                if (!v) return true; // Allow null templateId
                const Template = mongoose.model('Template');
                return await Template.exists({ templateId: v });
            },
            message: 'Invalid templateId'
        }
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
        maxlength: 1000,
        trim: true,
        index: 'text'
    },
    category: {
        type: String,
        enum: ['profile-cover', 'business-card', 'social-media', 'presentation', 'marketing', 'personal', 'portfolio'],
        required: true,
        index: true
    },
    status: {
        type: String,
        enum: ['draft', 'in-progress', 'completed', 'published', 'archived', 'deleted'],
        default: 'draft',
        index: true
    },
    accessControl: {
        type: accessControlSchema,
        default: () => ({})
    },
    customizations: [customizationSchema],
    branding: {
        type: brandingSchema,
        default: () => ({})
    },
    collaboration: {
        type: collaborationSchema,
        default: () => ({})
    },
    versionHistory: [versionHistorySchema],
    currentVersion: {
        type: String,
        default: '1.0'
    },
    exportHistory: [exportHistorySchema],
    aiAssistance: {
        type: aiAssistanceSchema,
        default: () => ({})
    },
    performanceMetrics: {
        type: performanceMetricsSchema,
        default: () => ({})
    },
    tags: [{
        type: String,
        trim: true,
        maxlength: 30,
        index: true
    }],
    dimensions: {
        width: { type: Number, required: true, min: 100, max: 8192 },
        height: { type: Number, required: true, min: 100, max: 8192 },
        aspectRatio: { type: Number, index: true }
    },
    format: {
        type: String,
        enum: ['jpeg', 'png', 'webp', 'svg', 'pdf'],
        default: 'png'
    },
    quality: {
        design: { type: Number, min: 0, max: 10, default: 0 },
        branding: { type: Number, min: 0, max: 10, default: 0 },
        accessibility: { type: Number, min: 0, max: 10, default: 0 },
        overall: { type: Number, min: 0, max: 10, default: 0, index: true }
    },
    analytics: {
        views: { type: Number, default: 0, min: 0 },
        likes: { type: Number, default: 0, min: 0 },
        shares: { type: Number, default: 0, min: 0 },
        downloads: { type: Number, default: 0, min: 0 },
        comments: { type: Number, default: 0, min: 0 },
        collaborators: { type: Number, default: 0, min: 0 },
        editTime: { type: Number, default: 0, min: 0 }, // milliseconds
        lastViewed: { type: Date },
        popularityScore: { type: Number, default: 0, min: 0, max: 100, index: true }
    },
    optimization: {
        fileSize: { type: Number, default: 0, min: 0 }, // current file size in bytes
        loadTime: { type: Number, default: 0, min: 0 }, // milliseconds
        isOptimized: { type: Boolean, default: false },
        optimizedAt: { type: Date },
        optimizations: [{
            type: {
                type: String,
                enum: ['image-compression', 'layer-merge', 'color-reduction', 'format-conversion'],
                required: true
            },
            before: { type: Number, min: 0 },
            after: { type: Number, min: 0 },
            savings: { type: Number, min: 0 }, // percentage
            appliedAt: { type: Date, default: Date.now }
        }]
    },
    backup: {
        isBackedUp: { type: Boolean, default: false },
        backupUrl: { type: String, default: '' },
        backupDate: { type: Date },
        backupProvider: {
            type: String,
            enum: ['s3', 'gcs', 'azure', 'cloudinary'],
            default: 's3'
        },
        backupSize: { type: Number, min: 0 }, // in bytes
        autoBackup: { type: Boolean, default: true }
    },
    publication: {
        isPublished: { type: Boolean, default: false },
        publishedAt: { type: Date },
        publishedTo: [{
            platform: {
                type: String,
                enum: ['linkedin', 'facebook', 'twitter', 'instagram', 'website', 'portfolio'],
                required: true
            },
            url: { type: String },
            status: {
                type: String,
                enum: ['pending', 'published', 'failed'],
                default: 'pending'
            },
            publishedAt: { type: Date },
            metadata: { type: mongoose.Schema.Types.Mixed }
        }],
        scheduledPublications: [{
            platform: { type: String, required: true },
            scheduledFor: { type: Date, required: true },
            status: {
                type: String,
                enum: ['scheduled', 'published', 'cancelled', 'failed'],
                default: 'scheduled'
            },
            createdAt: { type: Date, default: Date.now }
        }]
    },
    compliance: {
        brandGuidelines: {
            compliant: { type: Boolean, default: true },
            violations: [{
                type: { type: String, required: true, maxlength: 100 },
                description: { type: String, required: true, maxlength: 500 },
                severity: {
                    type: String,
                    enum: ['low', 'medium', 'high', 'critical'],
                    default: 'medium'
                },
                elementId: { type: String },
                detectedAt: { type: Date, default: Date.now }
            }],
            lastChecked: { type: Date }
        },
        accessibility: {
            wcagLevel: {
                type: String,
                enum: ['A', 'AA', 'AAA'],
                default: 'AA'
            },
            compliant: { type: Boolean, default: false },
            issues: [{
                type: {
                    type: String,
                    enum: ['contrast', 'text-size', 'alt-text', 'color-only', 'focus-indicator'],
                    required: true
                },
                description: { type: String, required: true, maxlength: 500 },
                severity: {
                    type: String,
                    enum: ['low', 'medium', 'high', 'critical'],
                    default: 'medium'
                },
                elementId: { type: String },
                suggestion: { type: String, maxlength: 500 },
                detectedAt: { type: Date, default: Date.now }
            }],
            lastChecked: { type: Date }
        },
        legal: {
            copyrightClearance: { type: Boolean, default: true },
            stockImageLicensed: { type: Boolean, default: true },
            trademarkCompliant: { type: Boolean, default: true },
            issues: [{ type: String, maxlength: 500 }],
            lastChecked: { type: Date }
        }
    },
    integrations: {
        connectedApps: [{
            appName: { type: String, required: true, maxlength: 100 },
            appId: { type: String, required: true },
            permissions: [{ type: String, maxlength: 50 }],
            connectedAt: { type: Date, default: Date.now },
            lastSync: { type: Date },
            status: {
                type: String,
                enum: ['active', 'inactive', 'error'],
                default: 'active'
            }
        }],
        webhooks: [{
            url: { type: String, required: true, match: /^https?:\/\/[^\s$.?#].[^\s]*$/ },
            events: [{
                type: String,
                enum: ['design.created', 'design.updated', 'design.published', 'design.exported', 'design.commented']
            }],
            secret: { type: String, maxlength: 200 },
            active: { type: Boolean, default: true },
            lastTriggered: { type: Date },
            failures: { type: Number, default: 0, min: 0 }
        }],
        apis: {
            canvaIntegration: {
                enabled: { type: Boolean, default: false },
                canvaDesignId: { type: String },
                lastSync: { type: Date }
            },
            figmaIntegration: {
                enabled: { type: Boolean, default: false },
                figmaFileKey: { type: String },
                figmaNodeId: { type: String },
                lastSync: { type: Date }
            },
            adobeIntegration: {
                enabled: { type: Boolean, default: false },
                creativeCloudId: { type: String },
                lastSync: { type: Date }
            }
        }
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
    lastEditedAt: {
        type: Date,
        index: true
    },
    completedAt: {
        type: Date,
        index: true
    },
    cacheVersion: {
        type: Number,
        default: 0,
        min: 0
    }
}, {
    timestamps: {
        createdAt: 'createdAt',
        updatedAt: 'updatedAt'
    },
    versionKey: 'version',
    strict: true,
    collection: 'designs',
    read: 'secondaryPreferred',
    shardKey: { userId: 1, category: 1 },
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
designSchema.index({ designId: 1 }, { unique: true, name: 'idx_designId_unique' });
designSchema.index({ userId: 1, status: 1 }, { name: 'idx_user_status' });
designSchema.index({ userId: 1, updatedAt: -1 }, { name: 'idx_user_recent' });
designSchema.index({ templateId: 1, status: 1 }, { name: 'idx_template_usage' });
designSchema.index({ category: 1, status: 1, 'accessControl.visibility': 1 }, { name: 'idx_category_search' });
designSchema.index({ 'analytics.popularityScore': -1, status: 1 }, { name: 'idx_popularity' });
designSchema.index({ 'quality.overall': -1, status: 1 }, { name: 'idx_quality' });
designSchema.index({ 'collaboration.collaborators.userId': 1, status: 1 }, { name: 'idx_collaboration' });
designSchema.index({ 'accessControl.allowedUsers': 1, status: 1 }, { name: 'idx_allowed_users' });
designSchema.index({ 'accessControl.allowedGroups': 1, status: 1 }, { name: 'idx_allowed_groups' });
designSchema.index({ tags: 1, status: 1, 'accessControl.visibility': 1 }, { name: 'idx_tags' });
designSchema.index({ 'dimensions.aspectRatio': 1, category: 1 }, { name: 'idx_aspect_ratio' });
designSchema.index({ completedAt: -1, userId: 1 }, { name: 'idx_completed' });
designSchema.index({ lastEditedAt: -1, status: 1 }, { name: 'idx_recent_activity' });
designSchema.index({ 'branding.consistency': -1, 'branding.enabled': 1 }, { name: 'idx_branding' });
designSchema.index({ 'aiAssistance.suggestions.status': 1, 'aiAssistance.suggestions.type': 1 }, { name: 'idx_ai_suggestions' });
designSchema.index({
    name: 'text',
    description: 'text',
    tags: 'text'
}, {
    weights: {
        name: 10,
        tags: 6,
        description: 4
    },
    name: 'idx_fulltext_search'
});

// ===========================
// PRE/POST HOOKS
// ===========================
designSchema.pre('save', function (next) {
    if (!this.designId) {
        this.designId = this.generateDesignId();
    }

    if (this.dimensions?.width && this.dimensions?.height) {
        this.dimensions.aspectRatio = Math.round((this.dimensions.width / this.dimensions.height) * 100) / 100;
    }

    this.calculateQualityScores();
    this.updateAnalytics();

    if (this.status === 'completed' && !this.completedAt) {
        this.completedAt = new Date();
    }

    if (this.isModified() && !this.isNew) {
        this.lastEditedAt = new Date();
        this.cacheVersion += 1;
    }

    this.updatedAt = new Date();
    next();
});

designSchema.pre(/^find/, function (next) {
    if (!this.getQuery().status) {
        this.where({ status: { $ne: 'deleted' } });
    }
    next();
});

designSchema.pre(['findOneAndUpdate', 'updateOne', 'updateMany'], function (next) {
    this.set({
        updatedAt: new Date(),
        lastEditedAt: new Date(),
        cacheVersion: { $inc: 1 }
    });
    next();
});

// ===========================
// INSTANCE METHODS
// ===========================
designSchema.methods.generateDesignId = function () {
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substring(2, 8);
    return `des_${timestamp}${random}`;
};

designSchema.methods.calculateQualityScores = function () {
    // Design Quality Score
    let designScore = 0;

    // Customization completeness (4 points)
    const customizationCount = this.customizations?.length || 0;
    if (customizationCount >= 5) designScore += 4;
    else designScore += customizationCount * 0.8;

    // Branding consistency (3 points)
    if (this.branding?.enabled) {
        designScore += Math.min(3, this.branding.consistency / 33.33);
    } else {
        designScore += 1.5;
    }

    // Version history indicates iteration (2 points)
    const versionCount = this.versionHistory?.length || 0;
    if (versionCount >= 3) designScore += 2;
    else designScore += versionCount * 0.7;

    // Export readiness (1 point)
    if (this.exportHistory?.length > 0) designScore += 1;

    this.quality.design = Math.min(designScore, 10);

    // Branding Quality Score
    let brandingScore = 0;
    if (this.branding?.enabled) {
        brandingScore = this.branding.consistency / 10;

        // Bonus for complete brand profile
        const profile = this.branding.brandProfile;
        if (profile?.companyName && profile?.colors?.primary && profile?.fonts?.primary) {
            brandingScore += 2;
        }
    }
    this.quality.branding = Math.min(brandingScore, 10);

    // Accessibility Score
    let accessibilityScore = 10;
    if (this.compliance?.accessibility?.issues) {
        this.compliance.accessibility.issues.forEach(issue => {
            switch (issue.severity) {
                case 'critical': accessibilityScore -= 2.5; break;
                case 'high': accessibilityScore -= 1.5; break;
                case 'medium': accessibilityScore -= 1; break;
                case 'low': accessibilityScore -= 0.5; break;
            }
        });
    }
    this.quality.accessibility = Math.max(0, accessibilityScore);

    // Overall Quality Score
    this.quality.overall = Math.round(
        (this.quality.design * 0.5) +
        (this.quality.branding * 0.3) +
        (this.quality.accessibility * 0.2)
    );

    return this.quality;
};

designSchema.methods.updateAnalytics = function () {
    const views = this.analytics.views || 0;
    const likes = this.analytics.likes || 0;
    const shares = this.analytics.shares || 0;
    const downloads = this.analytics.downloads || 0;
    const comments = this.analytics.comments || 0;

    const ageInDays = (Date.now() - this.createdAt) / (1000 * 60 * 60 * 24);
    const ageFactor = Math.max(0.3, 1 - (ageInDays / 365));

    const baseScore = (views * 0.5) + (likes * 3) + (shares * 5) + (downloads * 7) + (comments * 2) + (this.quality.overall * 3);
    this.analytics.popularityScore = Math.min(100, Math.round(baseScore * ageFactor));

    return this.analytics.popularityScore;
};

designSchema.methods.createVersion = function (changes = '', userId = null, qualityData = {}) {
    const versionId = `v${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
    const versionNumber = `${parseInt(this.currentVersion.split('.')[0]) + 1}.0`;

    const snapshot = {
        customizations: [...(this.customizations || [])],
        branding: JSON.parse(JSON.stringify(this.branding || {})),
        canvas: JSON.parse(JSON.stringify(this.dimensions || {})),
        layers: [] // Would contain layer data in real implementation
    };

    this.versionHistory.push({
        versionId,
        versionNumber,
        name: `Version ${versionNumber}`,
        description: changes,
        snapshot,
        changes: [],
        createdBy: userId || this.userId,
        createdAt: new Date(),
        isAutoSave: !changes,
        previewUrl: '',
        size: JSON.stringify(snapshot).length,
        quality: qualityData
    });

    if (this.versionHistory.length > 20) {
        this.versionHistory = this.versionHistory.slice(-20);
    }

    this.currentVersion = versionNumber;
    this.cacheVersion += 1;
    return versionId;
};

designSchema.methods.addCustomization = function (elementId, elementType, originalValue, customValue, source = 'user') {
    const existingIndex = this.customizations.findIndex(c => c.elementId === elementId && c.elementType === elementType);

    const customization = {
        elementId,
        elementType,
        originalValue,
        customValue,
        timestamp: new Date(),
        confidence: source === 'ai-suggestion' ? 0.9 : 1,
        source,
        validation: {
            type: elementType === 'color' ? 'color' : elementType === 'text' ? 'text' : elementType === 'size' ? 'number' : 'text'
        }
    };

    if (existingIndex >= 0) {
        this.customizations[existingIndex] = customization;
    } else {
        this.customizations.push(customization);
    }

    if (this.customizations.length % 5 === 0) {
        this.createVersion('Auto-save after 5 customizations');
    }

    this.cacheVersion += 1;
    return this.save({ validateBeforeSave: false });
};

designSchema.methods.incrementViews = async function (userId = null) {
    const now = new Date();
    const lastViewed = this.analytics.lastViewed;

    if (!lastViewed || (now - lastViewed) > 3600000) {
        this.analytics.views += 1;
        this.analytics.lastViewed = now;
        this.updateAnalytics();
        this.cacheVersion += 1;
        return this.save({ validateBeforeSave: false });
    }
};

designSchema.methods.getPublicData = function () {
    const design = this.toObject();

    delete design.versionHistory;
    delete design.performanceMetrics.errors;
    delete design.collaboration.comments;
    delete design.aiAssistance.suggestions;
    delete design.integrations.webhooks;

    design.analytics = {
        views: design.analytics.views,
        likes: design.analytics.likes,
        shares: design.analytics.shares,
        downloads: design.analytics.downloads,
        popularityScore: design.analytics.popularityScore
    };

    return design;
};

// ===========================
// STATIC METHODS
// ===========================
designSchema.statics.findUserDesigns = function (userId, options = {}) {
    const {
        status = 'all',
        category = 'all',
        page = 1,
        limit = 20,
        sortBy = 'updated',
        allowedGroups = []
    } = options;

    const query = {
        $or: [
            { userId },
            { 'accessControl.allowedUsers': userId },
            { 'accessControl.allowedGroups': { $in: allowedGroups } },
            { 'collaboration.collaborators.userId': userId, 'collaboration.collaborators.status': 'accepted' }
        ]
    };

    if (status !== 'all') {
        query.status = status;
    }

    if (category !== 'all') {
        query.category = category;
    }

    let sortOption = {};
    switch (sortBy) {
        case 'created': sortOption = { createdAt: -1 }; break;
        case 'updated': sortOption = { updatedAt: -1 }; break;
        case 'name': sortOption = { name: 1 }; break;
        case 'popular': sortOption = { 'analytics.popularityScore': -1, 'analytics.views': -1 }; break;
        case 'quality': sortOption = { 'quality.overall': -1 }; break;
        default: sortOption = { updatedAt: -1 };
    }

    const skip = (page - 1) * limit;

    return this.find(query)
        .sort(sortOption)
        .skip(skip)
        .limit(limit)
        .select('-versionHistory -performanceMetrics.errors -collaboration.comments.replies')
        .cache({ key: `user:designs:${userId}:${page}:${limit}:${sortBy}:${status}:${category}` })
        .lean();
};

designSchema.statics.searchDesigns = function (searchQuery, filters = {}) {
    const {
        categories = [],
        userId,
        visibility = ['public'],
        allowedGroups = [],
        minQuality = 0,
        dateRange = null,
        page = 1,
        limit = 20,
        sortBy = 'relevance'
    } = filters;

    const pipeline = [];

    const matchStage = {
        status: { $nin: ['deleted', 'archived'] }
    };

    if (searchQuery && searchQuery.trim()) {
        matchStage.$text = { $search: searchQuery.trim() };
    }

    if (categories.length > 0) {
        matchStage.category = { $in: categories };
    }

    if (userId) {
        matchStage.$or = [
            { 'accessControl.visibility': { $in: visibility } },
            { userId },
            { 'accessControl.allowedUsers': userId },
            { 'accessControl.allowedGroups': { $in: allowedGroups } },
            { 'collaboration.collaborators.userId': userId, 'collaboration.collaborators.status': 'accepted' }
        ];
    } else {
        matchStage['accessControl.visibility'] = { $in: visibility };
    }

    if (minQuality > 0) {
        matchStage['quality.overall'] = { $gte: minQuality };
    }

    if (dateRange) {
        matchStage.createdAt = { $gte: new Date(dateRange.from), $lte: new Date(dateRange.to) };
    }

    pipeline.push({ $match: matchStage });

    pipeline.push({
        $addFields: {
            relevanceScore: {
                $add: [
                    { $multiply: ['$analytics.popularityScore', 0.4] },
                    { $multiply: ['$quality.overall', 0.3] },
                    { $multiply: ['$analytics.views', 0.001] },
                    searchQuery && searchQuery.trim() ? { $meta: 'textScore' } : 0
                ]
            }
        }
    });

    let sortStage = {};
    switch (sortBy) {
        case 'recent': sortStage = { updatedAt: -1 }; break;
        case 'popular': sortStage = { 'analytics.popularityScore': -1, 'analytics.views': -1 }; break;
        case 'quality': sortStage = { 'quality.overall': -1 }; break;
        case 'views': sortStage = { 'analytics.views': -1 }; break;
        default: sortStage = { relevanceScore: -1, updatedAt: -1 };
    }

    pipeline.push({ $sort: sortStage });

    const skip = (page - 1) * limit;
    pipeline.push({ $skip: skip });
    pipeline.push({ $limit: limit });

    pipeline.push({
        $project: {
            designId: 1,
            userId: 1,
            name: 1,
            description: 1,
            category: 1,
            status: 1,
            'accessControl.visibility': 1,
            dimensions: 1,
            'analytics.views': 1,
            'analytics.likes': 1,
            'analytics.popularityScore': 1,
            'quality.overall': 1,
            tags: { $slice: ['$tags', 5] },
            createdAt: 1,
            updatedAt: 1,
            relevanceScore: 1
        }
    });

    return this.aggregate(pipeline).cache({ key: `search:designs:${searchQuery}:${JSON.stringify(filters)}:${userId || 'public'}` });
};

designSchema.statics.getTrendingDesigns = function (timeframe = 7, limit = 20, category = null, userId = null, allowedGroups = []) {
    const daysAgo = new Date();
    daysAgo.setDate(daysAgo.getDate() - timeframe);

    const query = {
        status: { $in: ['completed', 'published'] },
        updatedAt: { $gte: daysAgo },
        'analytics.views': { $gte: 5 }
    };

    if (category) {
        query.category = category;
    }

    if (userId) {
        query.$or = [
            { 'accessControl.visibility': 'public' },
            { userId },
            { 'accessControl.allowedUsers': userId },
            { 'accessControl.allowedGroups': { $in: allowedGroups } },
            { 'collaboration.collaborators.userId': userId, 'collaboration.collaborators.status': 'accepted' }
        ];
    } else {
        query['accessControl.visibility'] = 'public';
    }

    return this.find(query)
        .sort({
            'analytics.popularityScore': -1,
            'analytics.views': -1,
            'quality.overall': -1
        })
        .limit(limit)
        .select('designId userId name category analytics.views analytics.likes analytics.popularityScore quality.overall')
        .cache({ key: `trending:designs:${timeframe}:${limit}:${category || 'all'}:${userId || 'public'}` })
        .lean();
};

designSchema.statics.getCollaborativeDesigns = function (userId, limit = 20) {
    return this.find({
        $or: [
            { 'collaboration.collaborators.userId': userId, 'collaboration.collaborators.status': 'accepted' },
            { 'accessControl.allowedUsers': userId },
            { 'accessControl.allowedGroups': { $in: [] } } // Empty array for safety
        ],
        status: { $nin: ['deleted', 'archived'] }
    })
        .sort({ 'collaboration.activityLog.timestamp': -1 })
        .limit(limit)
        .select('designId userId name category collaboration.collaborators collaboration.shareSettings updatedAt')
        .cache({ key: `collaborative:${userId}:${limit}` })
        .lean();
};

designSchema.statics.getAnalyticsSummary = function (userId, timeframe = 30) {
    const daysAgo = new Date();
    daysAgo.setDate(daysAgo.getDate() - timeframe);

    return this.aggregate([
        {
            $match: {
                userId,
                createdAt: { $gte: daysAgo },
                status: { $ne: 'deleted' }
            }
        },
        {
            $group: {
                _id: null,
                totalDesigns: { $sum: 1 },
                completedDesigns: { $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] } },
                totalViews: { $sum: '$analytics.views' },
                totalLikes: { $sum: '$analytics.likes' },
                totalShares: { $sum: '$analytics.shares' },
                totalDownloads: { $sum: '$analytics.downloads' },
                avgQuality: { $avg: '$quality.overall' },
                totalEditTime: { $sum: '$analytics.editTime' },
                categories: { $addToSet: '$category' }
            }
        },
        {
            $project: {
                _id: 0,
                totalDesigns: 1,
                completedDesigns: 1,
                completionRate: {
                    $multiply: [
                        { $divide: ['$completedDesigns', { $max: ['$totalDesigns', 1] }] },
                        100
                    ]
                },
                totalViews: 1,
                totalLikes: 1,
                totalShares: 1,
                totalDownloads: 1,
                avgQuality: { $round: ['$avgQuality', 1] },
                totalEditTime: 1,
                avgEditTimePerDesign: {
                    $round: [{ $divide: ['$totalEditTime', { $max: ['$totalDesigns', 1] }] }, 0]
                },
                categories: 1
            }
        }
    ]).cache({ key: `analytics:${userId}:${timeframe}` });
};

designSchema.statics.bulkUpdateQuality = function (batchSize = 100) {
    const cursor = this.find({ status: { $ne: 'deleted' } }).cursor();
    let processed = 0;

    return cursor.eachAsync(async (design) => {
        const quality = design.calculateQualityScores();
        await this.updateOne(
            { _id: design._id },
            {
                $set: {
                    'quality.design': quality.design,
                    'quality.branding': quality.branding,
                    'quality.accessibility': quality.accessibility,
                    'quality.overall': quality.overall,
                    updatedAt: new Date(),
                    cacheVersion: { $inc: 1 }
                }
            }
        );

        processed++;
        if (processed % 50 === 0) {
            console.log(`Updated quality scores for ${processed} designs`);
        }
    });
};

// ===========================
// VALIDATION METHODS
// ===========================
designSchema.methods.validateBrandingCompliance = function () {
    if (!this.branding?.enabled) return { compliant: true, violations: [] };

    const violations = [];
    const brandProfile = this.branding.brandProfile;

    if (brandProfile.colors?.primary) {
        const primaryColorUsed = this.customizations.some(c =>
            c.elementType === 'color' && c.customValue === brandProfile.colors.primary
        );
        if (!primaryColorUsed) {
            violations.push({
                type: 'brand-color-missing',
                description: 'Primary brand color not used in design',
                severity: 'medium'
            });
        }
    }

    if (brandProfile.fonts?.primary) {
        const brandFontUsed = this.customizations.some(c =>
            c.elementType === 'font' && c.customValue === brandProfile.fonts.primary
        );
        if (!brandFontUsed) {
            violations.push({
                type: 'brand-font-missing',
                description: 'Primary brand font not used in design',
                severity: 'low'
            });
        }
    }

    if (brandProfile.logo?.url) {
        const logoUsed = this.customizations.some(c =>
            c.elementType === 'image' && c.customValue === brandProfile.logo.url
        );
        if (!logoUsed) {
            violations.push({
                type: 'brand-logo-missing',
                description: 'Brand logo not used in design',
                severity: 'medium'
            });
        }
    }

    return {
        compliant: violations.length === 0,
        violations
    };
};

designSchema.methods.validateAccessibility = function () {
    const issues = [];

    const colorOnlyCustomizations = this.customizations.filter(c =>
        c.elementType === 'color' && !c.customValue.includes('text')
    );

    if (colorOnlyCustomizations.length > 5) {
        issues.push({
            type: 'color-only',
            description: 'Design may rely too heavily on color to convey information',
            severity: 'medium',
            suggestion: 'Consider adding text labels or icons'
        });
    }

    const smallTextElements = this.customizations.filter(c =>
        c.elementType === 'size' && typeof c.customValue === 'number' && c.customValue < 14
    );

    if (smallTextElements.length > 0) {
        issues.push({
            type: 'text-size',
            description: 'Some text elements may be too small for accessibility (below 14px)',
            severity: 'high',
            suggestion: 'Increase font size to at least 14px'
        });
    }

    const imagesWithoutAlt = this.customizations.filter(c =>
        c.elementType === 'image' && !c.customValue.altText
    );

    if (imagesWithoutAlt.length > 0) {
        issues.push({
            type: 'alt-text',
            description: 'Some images lack alt text for accessibility',
            severity: 'high',
            suggestion: 'Add descriptive alt text to all images'
        });
    }

    return {
        compliant: issues.length === 0,
        issues,
        wcagLevel: issues.some(i => i.severity === 'critical') ? null :
            issues.some(i => i.severity === 'high') ? 'A' : 'AA'
    };
};

// ===========================
// VIRTUAL FIELDS
// ===========================
designSchema.virtual('isCompleted').get(function () {
    return this.status === 'completed' || this.status === 'published';
});

designSchema.virtual('collaboratorCount').get(function () {
    return this.collaboration?.collaborators?.filter(c => c.status === 'accepted').length || 0;
});

designSchema.virtual('totalEngagement').get(function () {
    const { views, likes, shares, downloads, comments } = this.analytics;
    return (views || 0) + (likes || 0) * 2 + (shares || 0) * 3 + (downloads || 0) * 4 + (comments || 0) * 2;
});

designSchema.virtual('editingEfficiency').get(function () {
    const editTime = this.analytics.editTime || 0;
    const customizations = this.customizations?.length || 1;
    return Math.round(editTime / customizations / 1000); // seconds per customization
});

// ===========================
// QUERY HELPERS
// ===========================
designSchema.query.byUser = function (userId) {
    return this.where({ userId });
};

designSchema.query.publicOnly = function () {
    return this.where({ 'accessControl.visibility': 'public', status: { $nin: ['draft', 'deleted', 'archived'] } });
};

designSchema.query.collaborative = function () {
    return this.where({ 'collaboration.isCollaborative': true });
};

designSchema.query.highQuality = function (minScore = 7) {
    return this.where({ 'quality.overall': { $gte: minScore } });
};

designSchema.query.cache = function (options = {}) {
    return this; // Placeholder for cache middleware
};

// ===========================
// EXPORT MODEL
// ===========================
const Design = mongoose.model('Design', designSchema);

Design.createCollection({
    capped: false,
    validator: {
        $jsonSchema: {
            bsonType: "object",
            required: ["designId", "userId", "name", "category", "dimensions"],
            properties: {
                designId: {
                    bsonType: "string",
                    description: "Design ID is required and must be a string"
                },
                userId: {
                    bsonType: "string",
                    description: "User ID is required and must be a string"
                },
                name: {
                    bsonType: "string",
                    maxLength: 200,
                    description: "Design name is required with max length 200"
                },
                category: {
                    bsonType: "string",
                    enum: ['profile-cover', 'business-card', 'social-media', 'presentation', 'marketing', 'personal', 'portfolio'],
                    description: "Category must be from predefined list"
                },
                dimensions: {
                    bsonType: "object",
                    required: ["width", "height"],
                    properties: {
                        width: {
                            bsonType: "number",
                            minimum: 100,
                            maximum: 8192
                        },
                        height: {
                            bsonType: "number",
                            minimum: 100,
                            maximum: 8192
                        }
                    }
                }
            }
        }
    }
}).catch(() => {
    // Collection might already exist
});

export default Design;