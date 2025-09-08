import Headline from '../models/headline.model.js';
import HeadlineTest from '../models/headlineTest.model.js';
import { analyzeWithAI } from '../services/headline.service.js';
import { validateHeadlineText } from '../validations/headline.validation.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { catchAsync } from '../handler/catchAsync.js';
import { v4 as uuidv4 } from 'uuid';

class HeadlineController {
    // Create a new headline
    createHeadline = catchAsync(async (req, res, next) => {
        const { text, title, description, category, tags, visibility = 'private', source = 'manual' } = req.body;
        const userId = req.user.id;

        // Validate headline text
        const validation = validateHeadlineText({ text, title, description });
        if (!validation.valid) {
            return next(new AppError(validation.message, 400));
        }

        // Check user headline limits
        const userHeadlineCount = await Headline.countDocuments({
            userId,
            status: { $ne: 'deleted' }
        });

        const headlineLimit = req.user.accountType === 'free' ? 20 :
            req.user.accountType === 'premium' ? 200 : 500;

        if (userHeadlineCount >= headlineLimit) {
            return next(new AppError(`Headline limit reached (${headlineLimit} headlines)`, 403));
        }

        try {
            // Create headline document
            const headlineData = {
                headlineId: `hl_${uuidv4().replace(/-/g, '')}`,
                userId,
                text,
                originalText: text,
                title: title || 'Untitled Headline',
                description: description || '',
                category: category || 'specialist',
                tags: tags ? tags.split(',').map(tag => tag.trim().toLowerCase()).slice(0, 10) : [],
                source,
                accessControl: {
                    visibility,
                    teamId: null,
                    organizationId: null,
                    collaborators: [],
                    shareSettings: {
                        allowPublicView: visibility === 'public',
                        allowCopy: visibility === 'public',
                        allowSuggestions: true,
                        trackViews: true
                    }
                },
                status: 'draft',
                metadata: {
                    characterCount: text.length,
                    wordCount: text.trim().split(/\s+/).length,
                    language: 'en',
                    tone: 'professional',
                    formality: 'semi-formal',
                    targetAudience: 'recruiters',
                    industry: req.user.industry || 'general',
                    keywords: [],
                    readabilityScore: 75,
                    sentimentScore: { positive: 0.7, negative: 0.1, neutral: 0.2 },
                    uniquenessScore: 80,
                    seoScore: 60
                },
                optimization: {
                    overallScore: 70,
                    categoryScores: {
                        grammar: 85,
                        clarity: 75,
                        impact: 70,
                        relevance: 80,
                        professionalism: 85
                    }
                }
            };

            const headline = new Headline(headlineData);
            await headline.save();

            // Start async AI analysis
            this.processHeadlineAsync(headline, userId);

            res.status(201).json({
                success: true,
                message: 'Headline creation started',
                data: {
                    headlineId: headline.headlineId,
                    status: 'processing',
                    estimatedTime: '15-30 seconds'
                }
            });
        } catch (error) {
            logger.error(`Headline creation error for headlineId ${headlineData.headlineId}:`, error);
            return next(new AppError('Headline creation failed', 500));
        }
    });

    // Async processing pipeline for AI analysis
    processHeadlineAsync = async (headline, userId) => {
        try {
            headline.status = 'processing';
            headline.metadata.lastAnalyzedAt = new Date();
            await headline.save();

            // Perform AI analysis
            const aiAnalysis = await analyzeWithAI(headline.text, {
                analyzeTone: true,
                analyzeSentiment: true,
                generateKeywords: true,
                assessOptimization: true,
                detectIndustry: true
            });

            // Update headline with AI analysis results
            headline.metadata = {
                ...headline.metadata,
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
                ...headline.optimization,
                suggestions: aiAnalysis.suggestions || [],
                overallScore: aiAnalysis.overallScore || headline.optimization.overallScore,
                categoryScores: {
                    ...headline.optimization.categoryScores,
                    ...aiAnalysis.categoryScores
                }
            };

            headline.status = 'active';
            headline.tags = [...new Set([...headline.tags, ...(aiAnalysis.tags || []).map(tag => tag.toLowerCase())])].slice(0, 10);
            await headline.save();

            logger.info(`Headline processed successfully: ${headline.headlineId}`);
        } catch (error) {
            logger.error(`Headline processing failed for headlineId ${headline.headlineId}:`, error);
            headline.status = 'failed';
            headline.moderation.status = 'flagged';
            headline.moderation.flagReason = error.message;
            await headline.save();
        }
    };

    // Get headline status
    getHeadlineStatus = catchAsync(async (req, res, next) => {
        const { headlineId } = req.params;
        const userId = req.user.id;

        const headline = await Headline.findOne({ headlineId, userId })
            .select('status metadata.lastAnalyzedAt moderation')
            .cache({ key: `headline:status:${headlineId}:${userId}` });

        if (!headline) {
            return next(new AppError('Headline not found', 404));
        }

        res.json({
            success: true,
            data: {
                headlineId,
                status: headline.status,
                lastAnalyzedAt: headline.metadata.lastAnalyzedAt,
                moderationStatus: headline.moderation.status,
                error: headline.moderation.flagReason
            }
        });
    });

    // Get user's headlines with filtering and pagination
    getUserHeadlines = catchAsync(async (req, res, next) => {
        const userId = req.user.id;
        const {
            page = 1,
            limit = 20,
            category,
            status,
            sortBy = 'recent',
            search
        } = req.query;

        const query = { userId };

        if (category) query.category = category;
        if (status && status !== 'all') query.status = status;
        else query.status = { $ne: 'deleted' };
        if (search) query.$text = { $search: search };

        let sortOption = {};
        switch (sortBy) {
            case 'recent': sortOption = { updatedAt: -1 }; break;
            case 'performance': sortOption = { 'performance.profileViews.total': -1 }; break;
            case 'optimization': sortOption = { 'optimization.overallScore': -1 }; break;
            case 'name': sortOption = { title: 1 }; break;
            default: sortOption = { updatedAt: -1 };
        }

        const skip = (page - 1) * limit;

        const headlines = await Headline.find(query)
            .sort(sortOption)
            .skip(skip)
            .limit(parseInt(limit))
            .select('headlineId text title category status metadata optimization performance createdAt updatedAt')
            .cache({ key: `user:headlines:${userId}:${page}:${limit}:${sortBy}:${status || ''}:${category || ''}:${search || ''}` })
            .lean();

        const totalCount = await Headline.countDocuments(query);
        const totalPages = Math.ceil(totalCount / limit);

        res.json({
            success: true,
            data: {
                headlines,
                pagination: {
                    page: parseInt(page),
                    limit: parseInt(limit),
                    totalCount,
                    totalPages,
                    hasNext: page < totalPages,
                    hasPrev: page > 1
                }
            }
        });
    });

    // Get single headline details
    getHeadlineById = catchAsync(async (req, res, next) => {
        const { headlineId } = req.params;
        const userId = req.user?.id;

        const headline = await Headline.findOne({ headlineId })
            .cache({ key: `headline:${headlineId}:${userId || 'public'}` });

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

        // Increment view count (async)
        if (userId && userId !== headline.userId) {
            headline.recordPerformanceMetrics({ profileViews: 1 }).catch(err =>
                logger.error(`View increment failed for headlineId ${headlineId}:`, err)
            );
        }

        res.json({
            success: true,
            data: userId === headline.userId ? headline.toObject() : headline.getPublicData()
        });
    });

    // Update headline metadata
    updateHeadline = catchAsync(async (req, res, next) => {
        const { headlineId } = req.params;
        const userId = req.user.id;
        const updates = req.body;

        const headline = await Headline.findOne({ headlineId, userId });

        if (!headline) {
            return next(new AppError('Headline not found', 404));
        }

        // Allowed update fields
        const allowedUpdates = [
            'text', 'title', 'description', 'category', 'tags',
            'accessControl.visibility', 'accessControl.shareSettings'
        ];

        const updateData = {};
        Object.keys(updates).forEach(key => {
            if (allowedUpdates.includes(key)) {
                if (key === 'tags' && Array.isArray(updates[key])) {
                    updateData[key] = updates[key].map(tag => tag.trim().toLowerCase()).slice(0, 10);
                } else if (key.startsWith('accessControl.')) {
                    updateData[key] = updates[key];
                } else if (key === 'text') {
                    const validation = validateHeadlineText({ text: updates[key] });
                    if (!validation.valid) {
                        throw new AppError(validation.message, 400);
                    }
                    updateData[key] = updates[key];
                } else {
                    updateData[key] = updates[key];
                }
            }
        });

        if (Object.keys(updateData).length === 0) {
            return next(new AppError('No valid update fields provided', 400));
        }

        if (updateData.text) {
            headline.createVersion(updateData.text, 'Text updated via API', userId);
        }

        const updatedHeadline = await Headline.findOneAndUpdate(
            { headlineId, userId },
            { $set: updateData, $inc: { cacheVersion: 1 } },
            { new: true, runValidators: true }
        );

        // Re-run AI analysis if text was updated
        if (updateData.text) {
            this.processHeadlineAsync(updatedHeadline, userId);
        }

        res.json({
            success: true,
            message: 'Headline updated successfully',
            data: updatedHeadline.getPublicData()
        });
    });

    // Delete headline (soft or permanent)
    deleteHeadline = catchAsync(async (req, res, next) => {
        const { headlineId } = req.params;
        const userId = req.user.id;
        const { permanent = false } = req.query;

        const headline = await Headline.findOne({ headlineId, userId });

        if (!headline) {
            return next(new AppError('Headline not found', 404));
        }

        if (permanent) {
            await Headline.findByIdAndDelete(headline._id);
            res.json({
                success: true,
                message: 'Headline permanently deleted'
            });
        } else {
            headline.status = 'deleted';
            headline.cacheVersion += 1;
            await headline.save();

            res.json({
                success: true,
                message: 'Headline moved to trash'
            });
        }
    });

    // Create A/B test for headlines
    createHeadlineTest = catchAsync(async (req, res, next) => {
        const { testName, description, category, variants, configuration } = req.body;
        const userId = req.user.id;

        if (!variants || variants.length < 2 || variants.length > 10) {
            return next(new AppError('Test must have between 2 and 10 variants', 400));
        }

        // Validate each variant
        for (const variant of variants) {
            const validation = validateHeadlineText({ text: variant.text, name: variant.name });
            if (!validation.valid) {
                return next(new AppError(`Invalid variant: ${validation.message}`, 400));
            }
        }

        try {
            const testData = {
                testId: `test_${uuidv4().replace(/-/g, '')}`,
                userId,
                testName,
                description: description || '',
                category: category || 'tone-optimization',
                status: 'draft',
                variants: variants.map((variant, index) => ({
                    variantId: `var_${uuidv4().replace(/-/g, '')}`,
                    headlineId: variant.headlineId || `hl_${uuidv4().replace(/-/g, '')}`,
                    text: variant.text,
                    name: variant.name,
                    description: variant.description || '',
                    trafficAllocation: variant.trafficAllocation || (100 / variants.length),
                    isControl: index === 0,
                    metadata: {
                        characterCount: variant.text.length,
                        wordCount: variant.text.trim().split(/\s+/).length,
                        tone: variant.tone || 'professional',
                        optimizationScore: 70
                    }
                })),
                configuration: {
                    testType: configuration?.testType || 'ab',
                    hypothesis: configuration?.hypothesis || 'Testing headline variations for better engagement',
                    primaryMetric: configuration?.primaryMetric || 'profileViews',
                    secondaryMetrics: configuration?.secondaryMetrics || [],
                    targetAudience: configuration?.targetAudience || {},
                    trafficSplit: configuration?.trafficSplit || 'equal'
                },
                audit: {
                    createdBy: userId
                }
            };

            const headlineTest = new HeadlineTest(testData);
            await headlineTest.save();

            // Start async processing for variants
            this.processTestVariantsAsync(headlineTest, userId);

            res.status(201).json({
                success: true,
                message: 'Headline test created successfully',
                data: {
                    testId: headlineTest.testId,
                    status: headlineTest.status
                }
            });
        } catch (error) {
            logger.error(`Headline test creation error for testId ${testData.testId}:`, error);
            return next(new AppError('Headline test creation failed', 500));
        }
    });

    // Async processing for test variants
    processTestVariantsAsync = async (headlineTest, userId) => {
        try {
            headlineTest.status = 'processing';
            await headlineTest.save();

            for (const variant of headlineTest.variants) {
                const aiAnalysis = await analyzeWithAI(variant.text, {
                    analyzeTone: true,
                    analyzeSentiment: true,
                    generateKeywords: true,
                    assessOptimization: true
                });

                variant.metadata = {
                    ...variant.metadata,
                    tone: aiAnalysis.tone || variant.metadata.tone,
                    optimizationScore: aiAnalysis.optimizationScore || variant.metadata.optimizationScore
                };

                // Create headline document if headlineId doesn't exist
                if (!(await Headline.findOne({ headlineId: variant.headlineId }))) {
                    const headline = new Headline({
                        headlineId: variant.headlineId,
                        userId,
                        text: variant.text,
                        originalText: variant.text,
                        title: variant.name,
                        category: headlineTest.category,
                        source: 'test-variant',
                        status: 'draft',
                        metadata: {
                            characterCount: variant.text.length,
                            wordCount: variant.text.trim().split(/\s+/).length,
                            language: aiAnalysis.language || 'en',
                            tone: aiAnalysis.tone || 'professional',
                            industry: aiAnalysis.industry || 'general'
                        }
                    });
                    await headline.save();
                }
            }

            headlineTest.status = 'scheduled';
            headlineTest.timeline.scheduledStartAt = new Date();
            await headlineTest.startTest();
            await headlineTest.save();

            logger.info(`Headline test processed successfully: ${headlineTest.testId}`);
        } catch (error) {
            logger.error(`Headline test processing failed for testId ${headlineTest.testId}:`, error);
            headlineTest.status = 'failed';
            await headlineTest.addAlert('error-occurred', error.message, 'error');
            await headlineTest.save();
        }
    };

    // Get test status
    getTestStatus = catchAsync(async (req, res, next) => {
        const { testId } = req.params;
        const userId = req.user.id;

        const test = await HeadlineTest.findOne({ testId, userId })
            .select('status timeline results statisticalAnalysis')
            .cache({ key: `test:status:${testId}:${userId}` });

        if (!test) {
            return next(new AppError('Test not found', 404));
        }

        res.json({
            success: true,
            data: {
                testId,
                status: test.status,
                timeline: test.timeline,
                winner: test.results.winner,
                significance: test.statisticalAnalysis.significance
            }
        });
    });

    // Get test analytics
    getTestAnalytics = catchAsync(async (req, res, next) => {
        const { testId } = req.params;
        const userId = req.user.id;
        const { timeframe = '30d' } = req.query;

        const test = await HeadlineTest.findOne({ testId, userId })
            .cache({ key: `test:analytics:${testId}:${userId}:${timeframe}` });

        if (!test) {
            return next(new AppError('Test not found', 404));
        }

        const daysAgo = new Date();
        switch (timeframe) {
            case '7d': daysAgo.setDate(daysAgo.getDate() - 7); break;
            case '30d': daysAgo.setDate(daysAgo.getDate() - 30); break;
            case '90d': daysAgo.setDate(daysAgo.getDate() - 90); break;
        }

        const analytics = {
            summary: {
                totalImpressions: test.performance.overall.impressions,
                totalConversions: test.performance.overall.conversions,
                engagementRate: test.performance.overall.conversionRates?.engagementRate || 0,
                statisticalSignificance: test.statisticalAnalysis.significance.isSignificant,
                winner: test.results.winner
            },
            variants: test.performance.byVariant.map(variant => ({
                variantId: variant.variantId,
                metrics: {
                    impressions: variant.metrics.impressions,
                    profileViews: variant.metrics.profileViews,
                    conversions: variant.metrics.conversions,
                    engagementRate: variant.metrics.conversionRates?.engagementRate || 0
                }
            })),
            insights: test.results.insights,
            recommendations: test.results.recommendations
        };

        res.json({
            success: true,
            data: analytics
        });
    });
}

export default new HeadlineController();