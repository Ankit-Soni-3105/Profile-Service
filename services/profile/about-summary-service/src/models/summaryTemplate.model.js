import mongoose from 'mongoose';
import { v4 as uuidv4 } from 'uuid';
import validator from 'validator';
import crypto from 'crypto';

// Validation functions
const validateUserId = (userId) => {
    return validator.isUUID(userId) || validator.isMongoId(userId);
};

const validateEmail = (email) => {
    return validator.isEmail(email);
};

const validateURL = (url) => {
    return !url || validator.isURL(url);
};

const validateHexColor = (color) => {
    return !color || /^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/.test(color);
};

const validateTemplateContent = (content) => {
    if (!content || typeof content !== 'string') return false;
    const trimmed = content.trim();
    return trimmed.length >= 50 && trimmed.length <= 10000;
};

// Sub-schemas for better organization and performance
const variableSchema = new mongoose.Schema({
    _id: {
        type: String,
        default: () => uuidv4(),
    },
    name: {
        type: String,
        required: true,
        maxlength: 50,
        trim: true,
        match: /^[a-zA-Z_][a-zA-Z0-9_]*$/, // Valid variable name
    },
    label: {
        type: String,
        required: true,
        maxlength: 100,
        trim: true,
    },
    type: {
        type: String,
        enum: ['text', 'textarea', 'number', 'email', 'url', 'phone', 'select', 'multiselect', 'date', 'boolean', 'file'],
        required: true,
    },
    description: {
        type: String,
        maxlength: 500,
        trim: true,
    },
    placeholder: {
        type: String,
        maxlength: 200,
        trim: true,
    },
    defaultValue: {
        type: mongoose.Schema.Types.Mixed,
    },
    validation: {
        required: {
            type: Boolean,
            default: false,
        },
        minLength: {
            type: Number,
            min: 0,
        },
        maxLength: {
            type: Number,
            min: 1,
        },
        pattern: {
            type: String,
            maxlength: 500,
        },
        min: Number,
        max: Number,
        options: [{
            value: String,
            label: String,
            description: String,
        }],
        customValidator: {
            type: String,
            maxlength: 1000,
        },
    },
    ui: {
        order: {
            type: Number,
            default: 0,
        },
        group: {
            type: String,
            maxlength: 50,
        },
        width: {
            type: String,
            enum: ['full', 'half', 'third', 'quarter'],
            default: 'full',
        },
        helpText: {
            type: String,
            maxlength: 300,
        },
        icon: {
            type: String,
            maxlength: 50,
        },
        conditional: {
            dependsOn: String,
            condition: String,
            value: mongoose.Schema.Types.Mixed,
        },
    },
    analytics: {
        usageCount: {
            type: Number,
            default: 0,
            min: 0,
        },
        errorCount: {
            type: Number,
            default: 0,
            min: 0,
        },
        averageFillTime: {
            type: Number,
            default: 0,
            min: 0,
        },
        skipRate: {
            type: Number,
            default: 0,
            min: 0,
            max: 100,
        },
    },
    isActive: {
        type: Boolean,
        default: true,
    },
    createdAt: {
        type: Date,
        default: Date.now,
    },
}, { _id: true });

const sectionSchema = new mongoose.Schema({
    _id: {
        type: String,
        default: () => uuidv4(),
    },
    name: {
        type: String,
        required: true,
        maxlength: 100,
        trim: true,
    },
    title: {
        type: String,
        required: true,
        maxlength: 200,
        trim: true,
    },
    description: {
        type: String,
        maxlength: 1000,
        trim: true,
    },
    content: {
        type: String,
        required: true,
        maxlength: 5000,
        trim: true,
    },
    order: {
        type: Number,
        required: true,
        min: 0,
    },
    isOptional: {
        type: Boolean,
        default: false,
    },
    variables: [String], // References to variable names used in this section
    styling: {
        backgroundColor: {
            type: String,
            validate: [validateHexColor, 'Invalid hex color'],
        },
        textColor: {
            type: String,
            validate: [validateHexColor, 'Invalid hex color'],
        },
        fontSize: {
            type: String,
            enum: ['xs', 'sm', 'base', 'lg', 'xl', '2xl'],
            default: 'base',
        },
        fontWeight: {
            type: String,
            enum: ['normal', 'medium', 'semibold', 'bold'],
            default: 'normal',
        },
        alignment: {
            type: String,
            enum: ['left', 'center', 'right', 'justify'],
            default: 'left',
        },
        margin: {
            top: {
                type: Number,
                default: 0,
                min: 0,
                max: 100,
            },
            bottom: {
                type: Number,
                default: 0,
                min: 0,
                max: 100,
            },
        },
    },
    conditions: [{
        variableName: String,
        operator: {
            type: String,
            enum: ['equals', 'not_equals', 'contains', 'not_contains', 'greater', 'less', 'exists', 'not_exists'],
        },
        value: mongoose.Schema.Types.Mixed,
    }],
    analytics: {
        includeRate: {
            type: Number,
            default: 100,
            min: 0,
            max: 100,
        },
        editRate: {
            type: Number,
            default: 0,
            min: 0,
            max: 100,
        },
        averageLength: {
            type: Number,
            default: 0,
            min: 0,
        },
    },
    isActive: {
        type: Boolean,
        default: true,
    },
}, { _id: true });

const analyticsSchema = new mongoose.Schema({
    usage: {
        totalUses: {
            type: Number,
            default: 0,
            min: 0,
        },
        uniqueUsers: {
            type: Number,
            default: 0,
            min: 0,
        },
        completionRate: {
            type: Number,
            default: 0,
            min: 0,
            max: 100,
        },
        averageCompletionTime: {
            type: Number,
            default: 0,
            min: 0, // in seconds
        },
        abandonmentRate: {
            type: Number,
            default: 0,
            min: 0,
            max: 100,
        },
    },
    performance: {
        successRate: {
            type: Number,
            default: 100,
            min: 0,
            max: 100,
        },
        errorRate: {
            type: Number,
            default: 0,
            min: 0,
            max: 100,
        },
        averageRating: {
            type: Number,
            default: 0,
            min: 0,
            max: 5,
        },
        totalRatings: {
            type: Number,
            default: 0,
            min: 0,
        },
    },
    trends: {
        daily: [{
            date: {
                type: Date,
                required: true,
            },
            uses: {
                type: Number,
                default: 0,
                min: 0,
            },
            uniqueUsers: {
                type: Number,
                default: 0,
                min: 0,
            },
            completions: {
                type: Number,
                default: 0,
                min: 0,
            },
            averageRating: {
                type: Number,
                default: 0,
                min: 0,
                max: 5,
            },
        }],
        weekly: [{
            week: {
                type: Date,
                required: true,
            },
            uses: {
                type: Number,
                default: 0,
                min: 0,
            },
            uniqueUsers: {
                type: Number,
                default: 0,
                min: 0,
            },
            completions: {
                type: Number,
                default: 0,
                min: 0,
            },
            averageRating: {
                type: Number,
                default: 0,
                min: 0,
                max: 5,
            },
        }],
        monthly: [{
            month: {
                type: Date,
                required: true,
            },
            uses: {
                type: Number,
                default: 0,
                min: 0,
            },
            uniqueUsers: {
                type: Number,
                default: 0,
                min: 0,
            },
            completions: {
                type: Number,
                default: 0,
                min: 0,
            },
            averageRating: {
                type: Number,
                default: 0,
                min: 0,
                max: 5,
            },
        }],
    },
    demographics: {
        industries: [{
            industry: String,
            count: {
                type: Number,
                default: 0,
                min: 0,
            },
            percentage: {
                type: Number,
                default: 0,
                min: 0,
                max: 100,
            },
        }],
        experienceLevels: [{
            level: String,
            count: {
                type: Number,
                default: 0,
                min: 0,
            },
            percentage: {
                type: Number,
                default: 0,
                min: 0,
                max: 100,
            },
        }],
        locations: [{
            country: String,
            count: {
                type: Number,
                default: 0,
                min: 0,
            },
            percentage: {
                type: Number,
                default: 0,
                min: 0,
                max: 100,
            },
        }],
    },
    feedback: {
        ratings: [{
            rating: {
                type: Number,
                required: true,
                min: 1,
                max: 5,
            },
            count: {
                type: Number,
                default: 0,
                min: 0,
            },
        }],
        comments: [{
            userId: String,
            comment: {
                type: String,
                maxlength: 1000,
                trim: true,
            },
            rating: {
                type: Number,
                min: 1,
                max: 5,
            },
            helpful: {
                type: Number,
                default: 0,
                min: 0,
            },
            createdAt: {
                type: Date,
                default: Date.now,
            },
            isPublic: {
                type: Boolean,
                default: true,
            },
            sentiment: {
                type: String,
                enum: ['positive', 'neutral', 'negative'],
            },
        }],
        suggestions: [{
            userId: String,
            suggestion: {
                type: String,
                required: true,
                maxlength: 1000,
                trim: true,
            },
            category: {
                type: String,
                enum: ['content', 'variables', 'structure', 'ui', 'performance', 'other'],
            },
            priority: {
                type: String,
                enum: ['low', 'medium', 'high', 'critical'],
                default: 'medium',
            },
            status: {
                type: String,
                enum: ['pending', 'reviewing', 'approved', 'implemented', 'rejected'],
                default: 'pending',
            },
            votes: {
                type: Number,
                default: 0,
            },
            createdAt: {
                type: Date,
                default: Date.now,
            },
        }],
    },
    lastCalculated: {
        type: Date,
        default: Date.now,
    },
}, { _id: false });

const aiConfigSchema = new mongoose.Schema({
    enabled: {
        type: Boolean,
        default: false,
    },
    features: {
        autoComplete: {
            type: Boolean,
            default: false,
        },
        grammarCheck: {
            type: Boolean,
            default: false,
        },
        toneAdjustment: {
            type: Boolean,
            default: false,
        },
        contentSuggestions: {
            type: Boolean,
            default: false,
        },
        smartVariables: {
            type: Boolean,
            default: false,
        },
    },
    models: {
        primary: {
            type: String,
            enum: ['gpt-4', 'gpt-3.5-turbo', 'claude-3', 'gemini-pro', 'custom'],
            default: 'gpt-3.5-turbo',
        },
        backup: {
            type: String,
            enum: ['gpt-4', 'gpt-3.5-turbo', 'claude-3', 'gemini-pro', 'custom'],
        },
        customEndpoint: {
            type: String,
            validate: [validateURL, 'Invalid API endpoint URL'],
        },
    },
    parameters: {
        temperature: {
            type: Number,
            min: 0,
            max: 2,
            default: 0.7,
        },
        maxTokens: {
            type: Number,
            min: 1,
            max: 4096,
            default: 1000,
        },
        topP: {
            type: Number,
            min: 0,
            max: 1,
            default: 1,
        },
        frequencyPenalty: {
            type: Number,
            min: -2,
            max: 2,
            default: 0,
        },
        presencePenalty: {
            type: Number,
            min: -2,
            max: 2,
            default: 0,
        },
    },
    prompts: {
        systemPrompt: {
            type: String,
            maxlength: 2000,
            default: 'You are a professional LinkedIn summary writing assistant. Help users create compelling, authentic professional summaries.',
        },
        userPrompt: {
            type: String,
            maxlength: 2000,
            default: 'Based on the following information, help improve this professional summary: {{variables}}',
        },
        enhancementPrompts: [{
            type: {
                type: String,
                enum: ['grammar', 'tone', 'structure', 'engagement', 'keywords'],
                required: true,
            },
            prompt: {
                type: String,
                required: true,
                maxlength: 1000,
            },
        }],
    },
    usage: {
        requestCount: {
            type: Number,
            default: 0,
            min: 0,
        },
        successCount: {
            type: Number,
            default: 0,
            min: 0,
        },
        errorCount: {
            type: Number,
            default: 0,
            min: 0,
        },
        totalCost: {
            type: Number,
            default: 0,
            min: 0,
        },
        averageResponseTime: {
            type: Number,
            default: 0,
            min: 0,
        },
    },
}, { _id: false });

const sharingSchema = new mongoose.Schema({
    isPublic: {
        type: Boolean,
        default: false,
        index: true,
    },
    visibility: {
        type: String,
        enum: ['private', 'public', 'organization', 'premium_only', 'invite_only'],
        default: 'private',
        index: true,
    },
    allowForks: {
        type: Boolean,
        default: false,
    },
    allowRating: {
        type: Boolean,
        default: true,
    },
    allowComments: {
        type: Boolean,
        default: true,
    },
    licenseType: {
        type: String,
        enum: ['proprietary', 'creative_commons', 'mit', 'apache', 'gpl', 'custom'],
        default: 'proprietary',
    },
    customLicense: {
        type: String,
        maxlength: 2000,
    },
    collaborators: [{
        userId: {
            type: String,
            required: true,
            validate: [validateUserId, 'Invalid user ID'],
        },
        email: {
            type: String,
            validate: [validateEmail, 'Invalid email format'],
        },
        role: {
            type: String,
            enum: ['viewer', 'editor', 'co_owner', 'admin'],
            default: 'viewer',
        },
        permissions: {
            canEdit: {
                type: Boolean,
                default: false,
            },
            canDelete: {
                type: Boolean,
                default: false,
            },
            canShare: {
                type: Boolean,
                default: false,
            },
            canViewAnalytics: {
                type: Boolean,
                default: false,
            },
            canManageCollaborators: {
                type: Boolean,
                default: false,
            },
        },
        invitedAt: {
            type: Date,
            default: Date.now,
        },
        acceptedAt: Date,
        lastAccessedAt: Date,
        status: {
            type: String,
            enum: ['pending', 'accepted', 'declined', 'revoked'],
            default: 'pending',
        },
    }],
    marketplace: {
        isListed: {
            type: Boolean,
            default: false,
            index: true,
        },
        price: {
            type: Number,
            min: 0,
            default: 0,
        },
        currency: {
            type: String,
            enum: ['USD', 'EUR', 'GBP', 'INR', 'JPY', 'CAD', 'AUD'],
            default: 'USD',
        },
        isFree: {
            type: Boolean,
            default: true,
        },
        purchaseCount: {
            type: Number,
            default: 0,
            min: 0,
        },
        revenue: {
            type: Number,
            default: 0,
            min: 0,
        },
    },
    forks: [{
        userId: String,
        templateId: String,
        forkedAt: {
            type: Date,
            default: Date.now,
        },
        changes: String,
    }],
}, { _id: false });

const complianceSchema = new mongoose.Schema({
    dataProcessing: {
        gdprCompliant: {
            type: Boolean,
            default: true,
        },
        ccpaCompliant: {
            type: Boolean,
            default: true,
        },
        dataRetentionDays: {
            type: Number,
            default: 365,
            min: 1,
        },
        anonymizeAfterDays: {
            type: Number,
            default: 1095, // 3 years
            min: 1,
        },
    },
    content: {
        moderationStatus: {
            type: String,
            enum: ['pending', 'approved', 'rejected', 'flagged', 'under_review'],
            default: 'pending',
            index: true,
        },
        moderatedBy: String,
        moderatedAt: Date,
        moderationNotes: String,
        contentFlags: [{
            type: {
                type: String,
                enum: ['inappropriate', 'spam', 'copyright', 'offensive', 'misleading'],
            },
            reason: String,
            reportedBy: String,
            reportedAt: {
                type: Date,
                default: Date.now,
            },
            status: {
                type: String,
                enum: ['open', 'investigating', 'resolved', 'dismissed'],
                default: 'open',
            },
        }],
    },
    security: {
        accessLevel: {
            type: String,
            enum: ['public', 'restricted', 'confidential', 'top_secret'],
            default: 'public',
        },
        encryptionRequired: {
            type: Boolean,
            default: false,
        },
        auditTrail: [{
            userId: String,
            action: {
                type: String,
                enum: ['create', 'read', 'update', 'delete', 'share', 'fork', 'rate'],
                required: true,
            },
            details: mongoose.Schema.Types.Mixed,
            ip: String,
            userAgent: String,
            timestamp: {
                type: Date,
                default: Date.now,
            },
            success: {
                type: Boolean,
                default: true,
            },
        }],
    },
}, { _id: false });

// Main Template Schema
const summaryTemplateSchema = new mongoose.Schema({
    _id: {
        type: String,
        default: () => uuidv4(),
    },
    name: {
        type: String,
        required: [true, 'Template name is required'],
        maxlength: [100, 'Template name cannot exceed 100 characters'],
        minlength: [3, 'Template name must be at least 3 characters'],
        trim: true,
        index: true,
    },
    slug: {
        type: String,
        unique: true,
        sparse: true,
        maxlength: 100,
        lowercase: true,
        trim: true,
        index: true,
    },
    title: {
        type: String,
        required: [true, 'Template title is required'],
        maxlength: [200, 'Template title cannot exceed 200 characters'],
        minlength: [5, 'Template title must be at least 5 characters'],
        trim: true,
    },
    description: {
        type: String,
        required: [true, 'Template description is required'],
        maxlength: [1000, 'Description cannot exceed 1000 characters'],
        minlength: [20, 'Description must be at least 20 characters'],
        trim: true,
    },
    content: {
        type: String,
        required: [true, 'Template content is required'],
        validate: [validateTemplateContent, 'Content must be between 50-10000 characters'],
        trim: true,
    },
    authorId: {
        type: String,
        required: [true, 'Author ID is required'],
        validate: [validateUserId, 'Invalid author ID format'],
        index: true,
    },
    category: {
        type: String,
        required: [true, 'Category is required'],
        enum: [
            'professional', 'creative', 'academic', 'entrepreneurial', 'technical',
            'sales', 'marketing', 'leadership', 'student', 'freelancer', 'consultant',
            'executive', 'nonprofit', 'healthcare', 'finance', 'legal', 'education'
        ],
        index: true,
    },
    subcategory: {
        type: String,
        maxlength: 50,
        trim: true,
        index: true,
    },
    industry: {
        type: String,
        maxlength: 100,
        trim: true,
        index: true,
    },
    experienceLevel: {
        type: String,
        enum: ['entry', 'junior', 'mid', 'senior', 'lead', 'executive', 'c_level', 'founder', 'student', 'any'],
        index: true,
    },
    tags: [{
        type: String,
        maxlength: 30,
        trim: true,
        lowercase: true,
    }],
    variables: [variableSchema],
    sections: [sectionSchema],
    metadata: {
        version: {
            type: String,
            default: '1.0.0',
            match: /^\d+\.\d+\.\d+$/,
        },
        language: {
            type: String,
            default: 'en',
            enum: ['en', 'hi', 'es', 'fr', 'de', 'pt', 'it', 'ja', 'ko', 'zh', 'ar', 'ru'],
            index: true,
        },
        targetAudience: {
            type: String,
            enum: ['recruiters', 'clients', 'peers', 'general', 'investors', 'students', 'employers'],
        },
        difficulty: {
            type: String,
            enum: ['beginner', 'intermediate', 'advanced', 'expert'],
            default: 'beginner',
            index: true,
        },
        estimatedTime: {
            type: Number,
            min: 1,
            max: 120, // minutes
            default: 15,
        },
        wordCount: {
            type: Number,
            min: 0,
        },
        characterCount: {
            type: Number,
            min: 0,
        },
        requiredFields: {
            type: Number,
            min: 0,
            default: 0,
        },
        optionalFields: {
            type: Number,
            min: 0,
            default: 0,
        },
    },
    styling: {
        theme: {
            type: String,
            enum: ['minimal', 'modern', 'professional', 'creative', 'bold', 'classic'],
            default: 'professional',
        },
        colors: {
            primary: {
                type: String,
                validate: [validateHexColor, 'Invalid primary color'],
                default: '#0066cc',
            },
            secondary: {
                type: String,
                validate: [validateHexColor, 'Invalid secondary color'],
                default: '#666666',
            },
            accent: {
                type: String,
                validate: [validateHexColor, 'Invalid accent color'],
                default: '#ff6b35',
            },
            background: {
                type: String,
                validate: [validateHexColor, 'Invalid background color'],
                default: '#ffffff',
            },
            text: {
                type: String,
                validate: [validateHexColor, 'Invalid text color'],
                default: '#333333',
            },
        },
        typography: {
            fontFamily: {
                type: String,
                enum: ['Arial', 'Helvetica', 'Times', 'Georgia', 'Verdana', 'Courier', 'Impact', 'Comic Sans MS'],
                default: 'Arial',
            },
            fontSize: {
                type: String,
                enum: ['small', 'medium', 'large'],
                default: 'medium',
            },
            lineHeight: {
                type: Number,
                min: 1.0,
                max: 3.0,
                default: 1.5,
            },
            letterSpacing: {
                type: Number,
                min: -2,
                max: 5,
                default: 0,
            },
        },
        layout: {
            spacing: {
                type: String,
                enum: ['tight', 'normal', 'loose'],
                default: 'normal',
            },
            alignment: {
                type: String,
                enum: ['left', 'center', 'right', 'justify'],
                default: 'left',
            },
            sectionSpacing: {
                type: Number,
                min: 0,
                max: 50,
                default: 20,
            },
        },
        customCSS: {
            type: String,
            maxlength: 5000,
        },
    },
    quality: {
        overallScore: {
            type: Number,
            min: 0,
            max: 100,
            default: 0,
            index: true,
        },
        scores: {
            content: {
                type: Number,
                min: 0,
                max: 100,
                default: 0,
            },
            usability: {
                type: Number,
                min: 0,
                max: 100,
                default: 0,
            },
            design: {
                type: Number,
                min: 0,
                max: 100,
                default: 0,
            },
            effectiveness: {
                type: Number,
                min: 0,
                max: 100,
                default: 0,
            },
            completeness: {
                type: Number,
                min: 0,
                max: 100,
                default: 0,
            },
        },
        issues: [{
            type: {
                type: String,
                enum: ['content', 'structure', 'variables', 'styling', 'performance', 'accessibility'],
                required: true,
            },
            severity: {
                type: String,
                enum: ['info', 'warning', 'error', 'critical'],
                required: true,
            },
            message: {
                type: String,
                required: true,
                maxlength: 500,
            },
            location: String,
            suggestion: String,
            fixed: {
                type: Boolean,
                default: false,
            },
            createdAt: {
                type: Date,
                default: Date.now,
            },
        }],
        lastAnalyzed: {
            type: Date,
            default: Date.now,
        },
    },
    status: {
        type: String,
        enum: ['draft', 'testing', 'review', 'approved', 'published', 'deprecated', 'archived'],
        default: 'draft',
        index: true,
    },
    visibility: {
        type: String,
        enum: ['private', 'team', 'organization', 'public'],
        default: 'private',
        index: true,
    },
    analytics: analyticsSchema,
    ai: aiConfigSchema,
    sharing: sharingSchema,
    compliance: complianceSchema,
    integrations: {
        linkedinCompatible: {
            type: Boolean,
            default: true,
        },
        resumeCompatible: {
            type: Boolean,
            default: false,
        },
        portfolioCompatible: {
            type: Boolean,
            default: false,
        },
        socialMediaCompatible: {
            type: Boolean,
            default: false,
        },
        exportFormats: [{
            format: {
                type: String,
                enum: ['pdf', 'docx', 'txt', 'html', 'md', 'json'],
                required: true,
            },
            supported: {
                type: Boolean,
                default: true,
            },
            lastExported: {
                type: Date,
            },
            exportCount: {
                type: Number,
                default: 0,
                min: 0,
            },
            template: {
                type: String,
                maxlength: 5000,
            },
            configuration: {
                type: mongoose.Schema.Types.Mixed,
            },
        }],
        externalApis: [{
            name: {
                type: String,
                required: true,
                maxlength: 100,
            },
            endpoint: {
                type: String,
                validate: [validateURL, 'Invalid API endpoint URL'],
            },
            enabled: {
                type: Boolean,
                default: false,
            },
            lastSynced: {
                type: Date,
            },
            syncCount: {
                type: Number,
                default: 0,
                min: 0,
            },
        }],
    },
}, {
    timestamps: true,
    collection: 'summaryTemplates',
    versionKey: false,
    minimize: false,
    strict: true,
});

// Compound Indexes for Scale (optimized for 1M+ users)
summaryTemplateSchema.index({ authorId: 1, status: 1, createdAt: -1 }); // Author-specific queries
summaryTemplateSchema.index({ category: 1, status: 1, 'quality.overallScore': -1 }); // Category-based search
summaryTemplateSchema.index({ industry: 1, experienceLevel: 1, status: 1 }); // Industry and experience queries
summaryTemplateSchema.index({ 'sharing.isPublic': 1, status: 1, createdAt: -1 }); // Public template discovery
summaryTemplateSchema.index({ 'analytics.usage.totalUses': -1, status: 1 }); // Popular templates
summaryTemplateSchema.index({ 'sharing.marketplace.isListed': 1, 'quality.overallScore': -1 }); // Marketplace listings
summaryTemplateSchema.index({ 'compliance.content.moderationStatus': 1, createdAt: 1 }); // Moderation queue

// Partial indexes for better performance
summaryTemplateSchema.index({ 'ai.enabled': 1 }, { partialFilterExpression: { 'ai.enabled': true } });
summaryTemplateSchema.index({ 'sharing.isPublic': 1 }, { partialFilterExpression: { 'sharing.isPublic': true } });
summaryTemplateSchema.index({ 'sharing.marketplace.isListed': 1 }, { partialFilterExpression: { 'sharing.marketplace.isListed': true } });

// Text search index with weights
summaryTemplateSchema.index({
    name: 'text',
    title: 'text',
    description: 'text',
    content: 'text',
    tags: 'text',
    industry: 'text',
    subcategory: 'text'
}, {
    weights: {
        name: 10,
        title: 8,
        description: 6,
        content: 4,
        tags: 8,
        industry: 3,
        subcategory: 3,
    },
    name: 'template_search_index'
});

// TTL index for auto-cleanup of archived templates
summaryTemplateSchema.index({ updatedAt: 1 }, {
    expireAfterSeconds: 31536000, // 1 year
    partialFilterExpression: { status: 'archived' }
});

// Virtual properties
summaryTemplateSchema.virtual('url').get(function () {
    return `/template/${this.slug || this._id}`;
});

summaryTemplateSchema.virtual('wordCount').get(function () {
    return this.content ? this.content.trim().split(/\s+/).length : 0;
});

summaryTemplateSchema.virtual('variableCount').get(function () {
    return this.variables ? this.variables.length : 0;
});

summaryTemplateSchema.virtual('sectionCount').get(function () {
    return this.sections ? this.sections.length : 0;
});

summaryTemplateSchema.virtual('isAuthor').get(function () {
    return (userId) => this.authorId === userId;
});

// Instance Methods
summaryTemplateSchema.methods.calculateQualityScore = function () {
    const content = this.content || '';
    const title = this.title || '';
    const description = this.description || '';

    // Content score: Based on length and variable usage
    const variableMatches = (content.match(/\{\{[a-zA-Z_][a-zA-Z0-9_]*\}\}/g) || []).length;
    this.quality.scores.content = Math.min(100,
        (content.length >= 100 ? 30 : 0) + // Minimum length
        (variableMatches >= this.variables.length ? 30 : Math.min(30, variableMatches * 5)) + // Variable usage
        (this.sections.length >= 2 ? 20 : 10) + // Section structure
        (description.length >= 50 ? 20 : 0) // Description length
    );

    // Usability score: Based on variable validation and UI configuration
    const requiredVariables = this.variables.filter(v => v.validation.required).length;
    const hasUIConfig = this.variables.some(v => v.ui.helpText || v.ui.icon || v.ui.conditional);
    this.quality.scores.usability = Math.min(100,
        (requiredVariables >= 1 ? 30 : 10) + // Required fields
        (this.variables.length >= 3 ? 20 : 0) + // Variable count
        (hasUIConfig ? 20 : 0) + // UI configuration
        (this.metadata.requiredFields + this.metadata.optionalFields >= 3 ? 30 : 0) // Field completeness
    );

    // Design score: Based on styling and theme
    const hasCustomStyling = this.styling.customCSS || this.sections.some(s => s.styling.backgroundColor || s.styling.textColor);
    this.quality.scores.design = Math.min(100,
        (this.styling.theme !== 'professional' ? 20 : 10) + // Theme variety
        (this.styling.colors.primary !== '#0066cc' || this.styling.colors.accent !== '#ff6b35' ? 30 : 0) + // Custom colors
        (hasCustomStyling ? 30 : 0) + // Custom styling
        (this.styling.typography.fontFamily !== 'Arial' ? 20 : 10) // Custom typography
    );

    // Effectiveness score: Based on analytics and feedback
    this.quality.scores.effectiveness = Math.min(100,
        (this.analytics.usage.totalUses >= 100 ? 30 : Math.min(30, this.analytics.usage.totalUses / 5)) + // Usage
        (this.analytics.performance.averageRating >= 3 ? 30 : Math.min(30, this.analytics.performance.averageRating * 10)) + // Rating
        (this.analytics.usage.completionRate >= 50 ? 20 : 0) + // Completion rate
        (this.analytics.feedback.ratings.length > 0 ? 20 : 0) // Feedback presence
    );

    // Completeness score: Based on metadata and structure
    this.quality.scores.completeness = Math.min(100,
        (this.metadata.targetAudience ? 20 : 0) + // Target audience
        (this.metadata.industry ? 20 : 0) + // Industry
        (this.metadata.language !== 'en' ? 20 : 10) + // Language diversity
        (this.sections.length >= 3 && this.variables.length >= 3 ? 40 : 20) // Structure completeness
    );

    // Overall score as weighted average
    this.quality.overallScore = Math.round(
        (this.quality.scores.content * 0.25) +
        (this.quality.scores.usability * 0.25) +
        (this.quality.scores.design * 0.20) +
        (this.quality.scores.effectiveness * 0.20) +
        (this.quality.scores.completeness * 0.10)
    );

    this.quality.lastAnalyzed = new Date();

    return this.save();
};

summaryTemplateSchema.methods.incrementUsage = function (userId) {
    this.analytics.usage.totalUses += 1;
    if (!this.analytics.usage.uniqueUsers.includes(userId)) {
        this.analytics.usage.uniqueUsers += 1;
    }

    const today = new Date();
    today.setHours(0, 0, 0, 0);

    let dailyTrend = this.analytics.trends.daily.find(t => t.date.getTime() === today.getTime());
    if (!dailyTrend) {
        dailyTrend = { date: today, uses: 0, uniqueUsers: 0, completions: 0, averageRating: 0 };
        this.analytics.trends.daily.push(dailyTrend);
    }
    dailyTrend.uses += 1;
    if (!dailyTrend.uniqueUsers.includes(userId)) {
        dailyTrend.uniqueUsers += 1;
    }

    this.analytics.lastCalculated = new Date();
    return this.save();
};

summaryTemplateSchema.methods.validateVariables = function (values) {
    const errors = [];
    this.variables.forEach(variable => {
        const value = values[variable.name];

        if (variable.validation.required && (value === undefined || value === null || value === '')) {
            errors.push(`Variable ${variable.name} is required`);
        }

        if (value && variable.validation.minLength && value.length < variable.validation.minLength) {
            errors.push(`Variable ${variable.name} must be at least ${variable.validation.minLength} characters`);
        }

        if (value && variable.validation.maxLength && value.length > variable.validation.maxLength) {
            errors.push(`Variable ${variable.name} must not exceed ${variable.validation.maxLength} characters`);
        }

        if (value && variable.validation.pattern) {
            try {
                const regex = new RegExp(variable.validation.pattern);
                if (!regex.test(value)) {
                    errors.push(`Variable ${variable.name} does not match pattern: ${variable.validation.pattern}`);
                }
            } catch (e) {
                errors.push(`Invalid pattern for variable ${variable.name}`);
            }
        }

        if (variable.type === 'email' && value && !validator.isEmail(value)) {
            errors.push(`Variable ${variable.name} must be a valid email`);
        }

        if (variable.type === 'url' && value && !validator.isURL(value)) {
            errors.push(`Variable ${variable.name} must be a valid URL`);
        }

        if (variable.type === 'number' && value !== undefined && isNaN(value)) {
            errors.push(`Variable ${variable.name} must be a valid number`);
        }
    });

    return errors.length > 0 ? errors : null;
};

// Static Methods for Scalability
summaryTemplateSchema.statics.findByAuthor = async function (authorId, options = {}) {
    const { status = 'published', limit = 20, skip = 0, sort = { createdAt: -1 } } = options;
    return this.find({
        authorId,
        status,
        'compliance.content.moderationStatus': 'approved'
    })
        .select('name slug title description category status createdAt quality.overallScore')
        .sort(sort)
        .skip(skip)
        .limit(limit)
        .lean()
        .cache(3600); // Cache for 1 hour
};

summaryTemplateSchema.statics.findPublicTemplates = async function (options = {}) {
    const { category, industry, limit = 20, skip = 0, sort = { 'analytics.usage.totalUses': -1 } } = options;
    const query = {
        'sharing.isPublic': true,
        status: 'published',
        'compliance.content.moderationStatus': 'approved'
    };
    if (category) query.category = category;
    if (industry) query.industry = industry;

    return this.find(query)
        .select('name slug title description category industry createdAt analytics.usage.totalUses quality.overallScore')
        .sort(sort)
        .skip(skip)
        .limit(limit)
        .lean()
        .cache(3600); // Cache for 1 hour
};

summaryTemplateSchema.statics.searchTemplates = async function (searchTerm, options = {}) {
    const { limit = 20, skip = 0, status = 'published', isPublic = true } = options;
    return this.find({
        $text: { $search: searchTerm },
        status,
        'sharing.isPublic': isPublic,
        'compliance.content.moderationStatus': 'approved'
    })
        .select('name slug title description category createdAt quality.overallScore')
        .sort({ score: { $meta: "textScore" } })
        .skip(skip)
        .limit(limit)
        .lean()
        .cache(1800); // Cache for 30 minutes
};

summaryTemplateSchema.statics.getAnalyticsSummary = async function (authorId, timeRange = '30d') {
    const date = new Date();
    let startDate;

    switch (timeRange) {
        case '7d':
            startDate = new Date(date.setDate(date.getDate() - 7));
            break;
        case '30d':
            startDate = new Date(date.setDate(date.getDate() - 30));
            break;
        case '90d':
            startDate = new Date(date.setDate(date.getDate() - 90));
            break;
        default:
            startDate = new Date(date.setDate(date.getDate() - 30));
    }

    return this.aggregate([
        { $match: { authorId, status: 'published', 'compliance.content.moderationStatus': 'approved' } },
        {
            $project: {
                name: 1,
                title: 1,
                'analytics.usage': 1,
                'analytics.performance': 1,
                'analytics.demographics': 1,
                trends: {
                    $filter: {
                        input: '$analytics.trends.daily',
                        as: 'item',
                        cond: { $gte: ['$$item.date', startDate] }
                    }
                }
            }
        },
        { $sort: { 'analytics.usage.totalUses': -1 } },
        { $limit: 10 }
    ]);
};

summaryTemplateSchema.statics.bulkUpdateStatus = async function (authorId, templateIds, status) {
    return this.updateMany(
        { _id: { $in: templateIds }, authorId, 'compliance.content.moderationStatus': 'approved' },
        { $set: { status, updatedAt: new Date() } },
        { multi: true }
    );
};

summaryTemplateSchema.statics.cleanupDeprecated = async function () {
    const oneYearAgo = new Date();
    oneYearAgo.setFullYear(oneYearAgo.getFullYear() - 1);
    return this.updateMany(
        { status: 'deprecated', updatedAt: { $lte: oneYearAgo } },
        { $set: { status: 'archived', updatedAt: new Date() } }
    );
};

summaryTemplateSchema.statics.getCollaboratedTemplates = async function (userId, options = {}) {
    const { status = 'published', limit = 20, skip = 0 } = options;
    return this.find({
        'sharing.collaborators.userId': userId,
        'sharing.collaborators.status': 'accepted',
        status,
        'compliance.content.moderationStatus': 'approved'
    })
        .select('name slug title description status sharing.collaborators')
        .sort({ updatedAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean()
        .cache(3600); // Cache for 1 hour
};

// Pre-save middleware for slug generation and metadata update
summaryTemplateSchema.pre('save', function (next) {
    if (!this.slug && this.name) {
        this.slug = this.name.toLowerCase()
            .replace(/[^a-z0-9]+/g, '-')
            .replace(/(^-|-$)/g, '');
    }

    this.metadata.wordCount = this.content ? this.content.trim().split(/\s+/).length : 0;
    this.metadata.characterCount = this.content ? this.content.length : 0;
    this.metadata.requiredFields = this.variables.filter(v => v.validation.required).length;
    this.metadata.optionalFields = this.variables.length - this.metadata.requiredFields;

    next();
});

// Pre-update middleware for updating audit trail
summaryTemplateSchema.pre(['updateOne', 'updateMany', 'findOneAndUpdate'], function (next) {
    this.set({
        'compliance.security.auditTrail': {
            $push: {
                userId: this.getOptions().userId || 'system',
                action: this.getOptions().action || 'update',
                ip: this.getOptions().ip,
                userAgent: this.getOptions().userAgent,
                timestamp: new Date(),
                success: true
            }
        }
    });
    next();
});

// Model
const SummaryTemplate = mongoose.model('SummaryTemplate', summaryTemplateSchema);

export default SummaryTemplate;