import natural from 'natural';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import Headline from '../models/headline.model.js';
import HeadlineTest from '../models/headlineTest.model.js';
import { analyzeTextComplexity, calculateSentiment } from '../utils/textAnalysis.js';
import { generateKeywords } from '../utils/keywordExtractor.js';
import { aiClient } from '../config/ai.config.js';

class HeadlineService {
    async analyzeWithAI(text, options = {}) {
        const {
            analyzeTone = true,
            analyzeSentiment = true,
            generateKeywords = true,
            assessOptimization = true,
            detectIndustry = true
        } = options;

        try {
            const analysisResult = {
                language: 'en',
                tone: 'professional',
                formality: 'semi-formal',
                keywords: [],
                readabilityScore: 70,
                sentimentScore: { positive: 0.7, negative: 0.1, neutral: 0.2 },
                uniquenessScore: 80,
                seoScore: 60,
                emotionalTone: 'neutral',
                personalityTraits: [],
                careerStage: 'mid-level',
                skillsIdentified: [],
                valueProposition: 'general',
                suggestions: [],
                categoryScores: {
                    grammar: 85,
                    clarity: 75,
                    impact: 70,
                    relevance: 80,
                    professionalism: 85
                },
                overallScore: 70,
                tags: [],
                industry: 'general'
            };

            // Language detection
            const languageResponse = await aiClient.detectLanguage(text);
            analysisResult.language = languageResponse.language || 'en';

            // Tone analysis
            if (analyzeTone) {
                const toneResponse = await aiClient.analyzeTone(text);
                analysisResult.tone = toneResponse.primaryTone || 'professional';
                analysisResult.formality = toneResponse.formality || 'semi-formal';
                analysisResult.emotionalTone = toneResponse.emotionalTone || 'neutral';
            }

            // Sentiment analysis
            if (analyzeSentiment) {
                analysisResult.sentimentScore = calculateSentiment(text);
            }

            // Keyword generation
            if (generateKeywords) {
                analysisResult.keywords = await generateKeywords(text, { maxKeywords: 10 });
                analysisResult.tags = analysisResult.keywords.map(k => k.toLowerCase());
            }

            // Optimization assessment
            if (assessOptimization) {
                const complexity = analyzeTextComplexity(text);
                analysisResult.readabilityScore = complexity.readabilityScore;

                const optimizationResponse = await aiClient.optimizeText(text, {
                    target: 'professional-headline',
                    maxLength: 160
                });

                analysisResult.suggestions = optimizationResponse.suggestions || [];
                analysisResult.overallScore = optimizationResponse.score || 70;
                analysisResult.categoryScores = {
                    grammar: optimizationResponse.grammarScore || 85,
                    clarity: optimizationResponse.clarityScore || 75,
                    impact: optimizationResponse.impactScore || 70,
                    relevance: optimizationResponse.relevanceScore || 80,
                    professionalism: optimizationResponse.professionalismScore || 85
                };
            }

            // Industry detection
            if (detectIndustry) {
                const industryResponse = await aiClient.detectIndustry(text);
                analysisResult.industry = industryResponse.industry || 'general';
                analysisResult.careerStage = industryResponse.careerStage || 'mid-level';
                analysisResult.skillsIdentified = industryResponse.skills || [];
                analysisResult.valueProposition = industryResponse.valueProposition || 'general';
            }

            // Uniqueness analysis
            const existingHeadlines = await Headline.find({ status: { $ne: 'deleted' } })
                .select('text')
                .limit(1000);

            const tfidf = new natural.TfIdf();
            existingHeadlines.forEach(h => tfidf.addDocument(h.text));
            tfidf.addDocument(text);

            const uniquenessScore = this.calculateUniquenessScore(tfidf, text);
            analysisResult.uniquenessScore = uniquenessScore;

            // SEO scoring
            analysisResult.seoScore = this.calculateSeoScore(text, analysisResult.keywords);

            logger.info(`AI analysis completed for text: ${text.substring(0, 50)}...`);
            return analysisResult;
        } catch (error) {
            logger.error('AI analysis failed:', error);
            throw new AppError('Failed to analyze headline with AI', 500);
        }
    }

    calculateUniquenessScore(tfidf, text) {
        let score = 100;
        const terms = tfidf.listTerms(0);

        terms.forEach(term => {
            const docsWithTerm = tfidf.tfidf(term.term, 0);
            if (docsWithTerm > 1) {
                score -= (docsWithTerm / tfidf.documents.length) * 100;
            }
        });

        return Math.max(50, Math.min(100, Math.round(score)));
    }

    calculateSeoScore(text, keywords) {
        let score = 60;
        const wordCount = text.trim().split(/\s+/).length;

        // Basic SEO scoring logic
        if (wordCount <= 20) score += 10;
        if (keywords.length >= 3) score += 10;
        if (text.length <= 160) score += 10;

        // Check for keyword density
        const keywordCount = keywords.reduce((count, keyword) =>
            count + (text.toLowerCase().split(keyword.toLowerCase()).length - 1), 0);
        if (keywordCount / wordCount <= 0.03) score += 10;

        return Math.min(100, score);
    }

    async optimizeHeadline(headlineId, options = {}) {
        const headline = await Headline.findOne({ headlineId });
        if (!headline) {
            throw new AppError('Headline not found', 404);
        }

        try {
            const optimizationResult = await aiClient.optimizeText(headline.text, {
                target: 'professional-headline',
                maxLength: 160,
                tone: options.tone || headline.metadata.tone,
                industry: options.industry || headline.metadata.industry,
                audience: options.audience || headline.metadata.targetAudience
            });

            const newVersion = {
                text: optimizationResult.optimizedText,
                reason: 'Automated optimization',
                userId: headline.userId,
                scores: {
                    overall: optimizationResult.score || 70,
                    grammar: optimizationResult.grammarScore || 85,
                    clarity: optimizationResult.clarityScore || 75,
                    impact: optimizationResult.impactScore || 70,
                    relevance: optimizationResult.relevanceScore || 80,
                    professionalism: optimizationResult.professionalismScore || 85
                }
            };

            headline.versions.push(newVersion);
            headline.text = optimizationResult.optimizedText;
            headline.optimization = {
                overallScore: optimizationResult.score || 70,
                categoryScores: {
                    grammar: optimizationResult.grammarScore || 85,
                    clarity: optimizationResult.clarityScore || 75,
                    impact: optimizationResult.impactScore || 70,
                    relevance: optimizationResult.relevanceScore || 80,
                    professionalism: optimizationResult.professionalismScore || 85
                },
                suggestions: optimizationResult.suggestions || []
            };
            headline.cacheVersion += 1;

            await headline.save();
            logger.info(`Headline optimized successfully: ${headlineId}`);
            return headline;
        } catch (error) {
            logger.error(`Headline optimization failed for ${headlineId}:`, error);
            throw new AppError('Headline optimization failed', 500);
        }
    }

    async analyzeTestPerformance(testId) {
        const test = await HeadlineTest.findOne({ testId });
        if (!test) {
            throw new AppError('Test not found', 404);
        }

        try {
            const performanceData = test.performance.byVariant.map(variant => ({
                variantId: variant.variantId,
                metrics: {
                    impressions: variant.metrics.impressions,
                    profileViews: variant.metrics.profileViews,
                    conversions: variant.metrics.conversions,
                    engagementRate: variant.metrics.conversionRates?.engagementRate || 0
                }
            }));

            const statisticalAnalysis = this.calculateStatisticalSignificance(performanceData);

            test.statisticalAnalysis = {
                significance: {
                    isSignificant: statisticalAnalysis.pValue < 0.05,
                    pValue: statisticalAnalysis.pValue,
                    confidenceLevel: statisticalAnalysis.confidenceLevel
                },
                metrics: statisticalAnalysis.metrics
            };

            // Determine winner
            const winner = performanceData.reduce((prev, current) =>
                (prev.metrics.engagementRate > current.metrics.engagementRate) ? prev : current
            );

            test.results.winner = {
                variantId: winner.variantId,
                confidence: statisticalAnalysis.confidenceLevel
            };

            test.results.insights = this.generateInsights(performanceData, statisticalAnalysis);
            test.results.recommendations = this.generateRecommendations(performanceData, winner);

            await test.save();
            Swiss
            logger.info(`Performance analysis completed for test: ${testId}`);
            return test;
        } catch (error) {
            logger.error(`Test performance analysis failed for ${testId}:`, error);
            throw new AppError('Test performance analysis failed', 500);
        }
    }

    calculateStatisticalSignificance(variants) {
        // Simplified statistical analysis using chi-squared test
        const totalImpressions = variants.reduce((sum, v) => sum + v.metrics.impressions, 0);
        const totalConversions = variants.reduce((sum, v) => sum + v.metrics.conversions, 0);

        const expectedRate = totalConversions / totalImpressions;
        let chiSquare = 0;

        variants.forEach(variant => {
            const expected = variant.metrics.impressions * expectedRate;
            const observed = variant.metrics.conversions;
            chiSquare += Math.pow(observed - expected, 2) / expected;
        });

        // Simplified p-value calculation
        const pValue = Math.min(1, Math.exp(-chiSquare / 2));

        return {
            pValue,
            confidenceLevel: Math.round((1 - pValue) * 100),
            metrics: variants.map(v => ({
                variantId: v.variantId,
                conversionRate: v.metrics.conversions / (v.metrics.impressions || 1)
            }))
        };
    }

    generateInsights(performanceData, statisticalAnalysis) {
        const insights = [];

        performanceData.forEach(variant => {
            const conversionRate = variant.metrics.conversions / (variant.metrics.impressions || 1);
            insights.push({
                variantId: variant.variantId,
                performance: conversionRate > 0.1 ? 'strong' : conversionRate > 0.05 ? 'moderate' : 'weak',
                relativePerformance: statisticalAnalysis.metrics.find(m => m.variantId === variant.variantId).conversionRate
            });
        });

        return insights;
    }

    generateRecommendations(performanceData, winner) {
        const recommendations = [];

        if (winner.metrics.engagementRate > 0.1) {
            recommendations.push({
                action: 'promote',
                variantId: winner.variantId,
                reason: 'Highest performing variant based on engagement rate'
            });
        }

        performanceData.forEach(variant => {
            if (variant.variantId !== winner.variantId && variant.metrics.engagementRate < 0.05) {
                recommendations.push({
                    action: 'revise',
                    variantId: variant.variantId,
                    reason: 'Low engagement rate compared to winner'
                });
            }
        });

        return recommendations;
    }
}

export default new HeadlineService();