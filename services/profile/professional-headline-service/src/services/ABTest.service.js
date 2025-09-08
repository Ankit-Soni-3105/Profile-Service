import Headline from '../models/Headline.model.js';
import HeadlineHistory from '../models/HeadlineHistory.model.js';
import { analyzeWithAI } from './headline.service.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { v4 as uuidv4 } from 'uuid';

class ABTestService {
    async setupTestAsync(testId, headline, experimentData, userId) {
        try {
            headline.status = 'processing';
            await headline.save();

            // Perform AI analysis for each variant
            for (const variant of experimentData.variants) {
                const analysis = await analyzeWithAI(variant.headlineText, {
                    analyzeTone: true,
                    analyzeSentiment: true,
                    generateKeywords: true,
                    assessOptimization: true,
                    detectIndustry: true
                });

                variant.performance = {
                    impressions: 0,
                    conversions: 0,
                    conversionRate: 0,
                    analysis
                };
            }

            // Update history with initial analysis
            await headline.createHistoryRecord('analyzed', {
                eventCategory: 'experiment',
                summary: `Initial analysis completed for A/B test ${testId}`,
                experiments: [experimentData],
                changes: experimentData.variants.map(v => ({
                    field: 'experiments.variants',
                    path: `experiments.variants.${v.variantId}`,
                    oldValue: null,
                    newValue: v,
                    changeType: 'create',
                    impact: 'moderate',
                    automated: true
                }))
            });

            headline.status = 'active';
            headline.cacheVersion += 1;
            await headline.save();

            logger.info(`A/B test setup completed for testId ${testId}`);
        } catch (error) {
            logger.error(`A/B test setup failed for testId ${testId}:`, error);
            headline.status = 'failed';
            await headline.save();
            throw new AppError('Test setup failed', 500);
        }
    }

    async analyzeTestPerformanceAsync(testId, headline, userId) {
        try {
            const historyRecord = await HeadlineHistory.findOne({ 'experiments.experimentId': testId });
            if (!historyRecord) {
                throw new AppError('Test not found', 404);
            }

            const experiment = historyRecord.experiments.find(exp => exp.experimentId === testId);
            if (!experiment) {
                throw new AppError('Experiment not found', 404);
            }

            // Perform statistical analysis
            const performanceData = experiment.variants.map(variant => ({
                variantId: variant.variantId,
                metrics: {
                    impressions: variant.performance.impressions,
                    conversions: variant.performance.conversions,
                    conversionRate: variant.performance.conversionRate
                }
            }));

            const statisticalAnalysis = this.calculateStatisticalSignificance(performanceData);

            experiment.results = {
                winner: statisticalAnalysis.winner?.variantId || '',
                confidence: statisticalAnalysis.confidenceLevel,
                statisticalSignificance: statisticalAnalysis.pValue < 0.05,
                pValue: statisticalAnalysis.pValue,
                sampleSize: performanceData.reduce((sum, v) => sum + v.metrics.impressions, 0),
                effectSize: statisticalAnalysis.effectSize
            };

            experiment.learnings = this.generateInsights(performanceData, statisticalAnalysis);

            await historyRecord.save();

            // If there's a clear winner, apply it
            if (statisticalAnalysis.winner) {
                const winningVariant = experiment.variants.find(v => v.variantId === statisticalAnalysis.winner.variantId);
                if (winningVariant) {
                    const oldText = headline.text;
                    headline.text = winningVariant.headlineText;
                    headline.cacheVersion += 1;

                    await headline.createHistoryRecord('optimized', {
                        eventCategory: 'experiment',
                        summary: `Applied winning variant ${winningVariant.variantId} from test ${testId}`,
                        changes: [{
                            field: 'text',
                            oldValue: oldText,
                            newValue: winningVariant.headlineText,
                            changeType: 'update',
                            impact: 'major',
                            automated: true
                        }]
                    });

                    await headline.save();
                }
            }

            logger.info(`Performance analysis completed for testId ${testId}`);
        } catch (error) {
            logger.error(`Test performance analysis failed for testId ${testId}:`, error);
            throw new AppError('Test performance analysis failed', 500);
        }
    }

    calculateStatisticalSignificance(variants) {
        const totalImpressions = variants.reduce((sum, v) => sum + v.metrics.impressions, 0);
        const totalConversions = variants.reduce((sum, v) => sum + v.metrics.conversions, 0);
        const expectedRate = totalConversions / (totalImpressions || 1);

        let chiSquare = 0;
        variants.forEach(variant => {
            const expected = variant.metrics.impressions * expectedRate;
            const observed = variant.metrics.conversions;
            chiSquare += Math.pow(observed - expected, 2) / (expected || 1);
        });

        const pValue = Math.min(1, Math.exp(-chiSquare / 2));
        const winner = variants.reduce((prev, current) =>
            (prev.metrics.conversionRate > current.metrics.conversionRate) ? prev : current, { metrics: { conversionRate: 0 } });

        return {
            pValue,
            confidenceLevel: Math.round((1 - pValue) * 100),
            effectSize: Math.max(...variants.map(v => v.metrics.conversionRate)) - Math.min(...variants.map(v => v.metrics.conversionRate)),
            winner: winner.metrics.conversionRate > 0 ? winner : null
        };
    }

    generateInsights(performanceData, statisticalAnalysis) {
        return performanceData.map(variant => ({
            insight: `Variant ${variant.variantId} achieved ${variant.metrics.conversionRate.toFixed(2)}% conversion rate`,
            impact: variant.metrics.conversionRate > 0.1 ? 'high' : variant.metrics.conversionRate > 0.05 ? 'medium' : 'low',
            actionable: statisticalAnalysis.pValue < 0.05,
            category: 'performance',
            confidence: statisticalAnalysis.confidenceLevel / 100
        }));
    }
}

export default new ABTestService();