import Headline from '../models/headline.model.js';
import HeadlineHistory from '../models/headlineHistory.model.js';
import { analyzeWithAI } from '../services/headline.service.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { catchAsync } from '../handler/catchAsync.js';
import { v4 as uuidv4 } from 'uuid';
import { validateSuggestion } from '../validations/suggestion.validation.js';

class SuggestionController {
    // Create a new suggestion for a headline
    createSuggestion = catchAsync(async (req, res, next) => {
        const { headlineId, suggestedText, reason, category } = req.body;
        const userId = req.user.id;

        const headline = await Headline.findOne({ headlineId, status: { $ne: 'deleted' } });
        if (!headline) {
            return next(new AppError('Headline not found', 404));
        }

        // Check access permissions
        const hasAccess = headline.userId === userId ||
            headline.accessControl.collaborators.some(c => c.userId === userId && ['editor', 'contributor', 'admin'].includes(c.role));
        if (!hasAccess) {
            return next(new AppError('Access denied', 403));
        }

        // Validate suggestion
        const validation = validateSuggestion({ suggestedText, reason, category });
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        try {
            const suggestion = {
                suggestionId: `sug_${uuidv4().replace(/-/g, '')}`,
                originalText: headline.text,
                suggestedText,
                reason: reason || 'Suggestion for improvement',
                category: category || 'clarity',
                accepted: false,
                confidence: 0.8,
                aiGenerated: req.body.aiGenerated || false
            };

            headline.optimization.suggestions.push(suggestion);
            headline.cacheVersion += 1;

            // Create history record
            await headline.createHistoryRecord('collaborated', {
                eventCategory: 'collaboration',
                summary: `New suggestion created for headline ${headlineId}`,
                collaboration: [{
                    collaboratorId: userId,
                    collaboratorName: req.user.name || '',
                    collaboratorEmail: req.user.email || '',
                    collaboratorRole: headline.userId === userId ? 'owner' : 'contributor',
                    action: 'suggested',
                    contribution: 'moderate',
                    suggestions: [suggestion]
                }],
                changes: [{
                    field: 'optimization.suggestions',
                    path: `optimization.suggestions.${suggestion.suggestionId}`,
                    oldValue: null,
                    newValue: suggestion,
                    changeType: 'create',
                    impact: 'moderate',
                    automated: suggestion.aiGenerated
                }]
            });

            await headline.save();

            res.status(201).json({
                success: true,
                message: 'Suggestion created successfully',
                data: { suggestionId: suggestion.suggestionId }
            });
        } catch (error) {
            logger.error(`Suggestion creation error for headlineId ${headlineId}:`, error);
            return next(new AppError('Suggestion creation failed', 500));
        }
    });

    // Accept a suggestion
    acceptSuggestion = catchAsync(async (req, res, next) => {
        const { headlineId, suggestionId } = req.params;
        const userId = req.user.id;

        const headline = await Headline.findOne({ headlineId, status: { $ne: 'deleted' } });
        if (!headline) {
            return next(new AppError('Headline not found', 404));
        }

        // Check access permissions
        const hasAccess = headline.userId === userId ||
            headline.accessControl.collaborators.some(c => c.userId === userId && ['editor', 'admin'].includes(c.role));
        if (!hasAccess) {
            return next(new AppError('Access denied', 403));
        }

        const suggestion = headline.optimization.suggestions.find(s => s.suggestionId === suggestionId);
        if (!suggestion) {
            return next(new AppError('Suggestion not found', 404));
        }

        try {
            suggestion.accepted = true;
            suggestion.acceptedAt = new Date();
            suggestion.acceptedBy = userId;

            // Apply suggestion
            const oldText = headline.text;
            headline.text = suggestion.suggestedText;
            headline.cacheVersion += 1;

            // Create new version
            await headline.createVersion(suggestion.suggestedText, `Accepted suggestion ${suggestionId}`, userId);

            // Create history record
            await headline.createHistoryRecord('updated', {
                eventCategory: 'collaboration',
                summary: `Suggestion ${suggestionId} accepted for headline ${headlineId}`,
                collaboration: [{
                    collaboratorId: userId,
                    collaboratorName: req.user.name || '',
                    collaboratorEmail: req.user.email || '',
                    collaboratorRole: headline.userId === userId ? 'owner' : 'contributor',
                    action: 'accepted',
                    contribution: 'major',
                    suggestions: [suggestion]
                }],
                changes: [{
                    field: 'text',
                    oldValue: oldText,
                    newValue: suggestion.suggestedText,
                    changeType: 'update',
                    impact: 'major',
                    automated: suggestion.aiGenerated
                }, {
                    field: 'optimization.suggestions',
                    path: `optimization.suggestions.${suggestionId}.accepted`,
                    oldValue: false,
                    newValue: true,
                    changeType: 'update',
                    impact: 'moderate'
                }]
            });

            // Start async AI analysis for updated text
            this.processSuggestionAsync(headline, suggestion, userId);

            await headline.save();

            res.json({
                success: true,
                message: 'Suggestion accepted successfully',
                data: { suggestionId, newText: headline.text }
            });
        } catch (error) {
            logger.error(`Suggestion acceptance error for suggestionId ${suggestionId}:`, error);
            return next(new AppError('Suggestion acceptance failed', 500));
        }
    });

    // Reject a suggestion
    rejectSuggestion = catchAsync(async (req, res, next) => {
        const { headlineId, suggestionId } = req.params;
        const { reason } = req.body;
        const userId = req.user.id;

        const headline = await Headline.findOne({ headlineId, status: { $ne: 'deleted' } });
        if (!headline) {
            return next(new AppError('Headline not found', 404));
        }

        // Check access permissions
        const hasAccess = headline.userId === userId ||
            headline.accessControl.collaborators.some(c => c.userId === userId && ['editor', 'admin'].includes(c.role));
        if (!hasAccess) {
            return next(new AppError('Access denied', 403));
        }

        const suggestion = headline.optimization.suggestions.find(s => s.suggestionId === suggestionId);
        if (!suggestion) {
            return next(new AppError('Suggestion not found', 404));
        }

        try {
            headline.optimization.suggestions = headline.optimization.suggestions.filter(
                s => s.suggestionId !== suggestionId
            );
            headline.cacheVersion += 1;

            // Create history record
            await headline.createHistoryRecord('collaborated', {
                eventCategory: 'collaboration',
                summary: `Suggestion ${suggestionId} rejected for headline ${headlineId}`,
                collaboration: [{
                    collaboratorId: userId,
                    collaboratorName: req.user.name || '',
                    collaboratorEmail: req.user.email || '',
                    collaboratorRole: headline.userId === userId ? 'owner' : 'contributor',
                    action: 'rejected',
                    contribution: 'moderate',
                    suggestions: [{ ...suggestion.toObject(), reason }]
                }],
                changes: [{
                    field: 'optimization.suggestions',
                    path: `optimization.suggestions.${suggestionId}`,
                    oldValue: suggestion,
                    newValue: null,
                    changeType: 'delete',
                    impact: 'moderate',
                    automated: suggestion.aiGenerated
                }]
            });

            await headline.save();

            res.json({
                success: true,
                message: 'Suggestion rejected successfully',
                data: { suggestionId }
            });
        } catch (error) {
            logger.error(`Suggestion rejection error for suggestionId ${suggestionId}:`, error);
            return next(new AppError('Suggestion rejection failed', 500));
        }
    });

    // Get all suggestions for a headline
    getSuggestions = catchAsync(async (req, res, next) => {
        const { headlineId } = req.params;
        const userId = req.user.id;

        const headline = await Headline.findOne({ headlineId })
            .select('optimization.suggestions accessControl userId')
            .cache({ key: `headline:suggestions:${headlineId}:${userId}` });

        if (!headline) {
            return next(new AppError('Headline not found', 404));
        }

        // Check access permissions
        const hasAccess = headline.userId === userId ||
            headline.accessControl.visibility === 'public' ||
            headline.accessControl.collaborators.some(c => c.userId === userId);
        if (!hasAccess) {
            return next(new AppError('Access denied', 403));
        }

        res.json({
            success: true,
            data: {
                headlineId,
                suggestions: headline.optimization.suggestions
            }
        });
    });

    // Async processing for accepted suggestion
    processSuggestionAsync = async (headline, suggestion, userId) => {
        try {
            headline.status = 'processing';
            headline.metadata.lastAnalyzedAt = new Date();
            await headline.save();

            const aiAnalysis = await analyzeWithAI(suggestion.suggestedText, {
                analyzeTone: true,
                analyzeSentiment: true,
                generateKeywords: true,
                assessOptimization: true,
                detectIndustry: true
            });

            headline.metadata = {
                ...headline.metadata.toObject(),
                language: aiAnalysis.language || headline.metadata.language,
                tone: aiAnalysis.tone || headline.metadata.tone,
                formality: aiAnalysis.formality || headline.metadata.formality,
                keywords: aiAnalysis.keywords || [],
                readabilityScore: aiAnalysis.readabilityScore || headline.metadata.readabilityScore,
                sentimentScore: aiAnalysis.sentimentScore || headline.metadata.sentimentScore,
                uniquenessScore: aiAnalysis.uniquenessScore || headline.metadata.uniquenessScore,
                seoScore: aiAnalysis.seoScore || headline.metadata.seoScore
            };

            headline.aiAnalysis = {
                emotionalTone: aiAnalysis.emotionalTone || headline.aiAnalysis.emotionalTone,
                personalityTraits: aiAnalysis.personalityTraits || [],
                careerStage: aiAnalysis.careerStage || headline.aiAnalysis.careerStage,
                skillsIdentified: aiAnalysis.skillsIdentified || [],
                valueProposition: aiAnalysis.valueProposition || headline.aiAnalysis.valueProposition
            };

            headline.optimization = {
                ...headline.optimization.toObject(),
                suggestions: headline.optimization.suggestions,
                overallScore: aiAnalysis.overallScore || headline.optimization.overallScore,
                categoryScores: {
                    ...headline.optimization.categoryScores,
                    ...aiAnalysis.categoryScores
                }
            };

            headline.status = 'active';
            headline.tags = [...new Set([...headline.tags, ...(aiAnalysis.tags || []).map(tag => tag.toLowerCase())])].slice(0, 10);
            headline.cacheVersion += 1;

            await headline.createHistoryRecord('analyzed', {
                eventCategory: 'system',
                summary: `AI analysis completed for accepted suggestion ${suggestion.suggestionId}`,
                changes: [{
                    field: 'metadata',
                    oldValue: { ...headline.metadata.toObject() },
                    newValue: headline.metadata,
                    changeType: 'update',
                    impact: 'moderate',
                    automated: true
                }, {
                    field: 'aiAnalysis',
                    oldValue: { ...headline.aiAnalysis.toObject() },
                    newValue: headline.aiAnalysis,
                    changeType: 'update',
                    impact: 'moderate',
                    automated: true
                }]
            });

            await headline.save();
            logger.info(`Suggestion processed successfully: ${suggestion.suggestionId}`);
        } catch (error) {
            logger.error(`Suggestion processing failed for suggestionId ${suggestion.suggestionId}:`, error);
            headline.status = 'failed';
            headline.moderation.status = 'flagged';
            headline.moderation.flagReason = error.message;
            await headline.save();
        }
    };
}

export default new SuggestionController();