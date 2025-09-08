import Headline from '../models/Headline.model.js';
import HeadlineHistory from '../models/HeadlineHistory.model.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';

class AnalyticsService {
    async getAnalytics(headlineId, timeframe, period) {
        try {
            const startDate = new Date();
            let daysAgo = 30;
            switch (timeframe) {
                case '7d': daysAgo = 7; break;
                case '30d': daysAgo = 30; break;
                case '90d': daysAgo = 90; break;
                case '1y': daysAgo = 365; break;
            }
            startDate.setDate(startDate.getDate() - daysAgo);

            const analyticsRecords = await HeadlineHistory.find({
                headlineId,
                'analytics.period': period,
                'analytics.startDate': { $gte: startDate }
            })
                .select('analytics')
                .lean()
                .cache({ key: `analytics:${headlineId}:${timeframe}:${period}` });

            const headline = await Headline.findOne({ headlineId })
                .select('performance')
                .lean();

            return {
                summary: {
                    totalViews: headline.performance.profileViews.total,
                    engagementRate: headline.performance.conversionRates.engagementRate,
                    clickThroughRate: headline.performance.conversionRates.clickThroughRate
                },
                detailed: analyticsRecords.map(r => r.analytics).flat(),
                timeframe,
                period
            };
        } catch (error) {
            logger.error(`Analytics retrieval failed for headlineId ${headlineId}:`, error);
            throw new AppError('Analytics retrieval failed', 500);
        }
    }

    async getTrendAnalysis(headlineId, metric, timeframe) {
        try {
            const startDate = new Date();
            let daysAgo = 30;
            switch (timeframe) {
                case '7d': daysAgo = 7; break;
                case '30d': daysAgo = 30; break;
                case '90d': daysAgo = 90; break;
                case '1y': daysAgo = 365; break;
            }
            startDate.setDate(startDate.getDate() - daysAgo);

            const analyticsRecords = await HeadlineHistory.find({
                headlineId,
                'analytics.startDate': { $gte: startDate },
                [`analytics.metrics.${metric}`]: { $exists: true }
            })
                .select('analytics')
                .sort({ 'analytics.startDate': 1 })
                .lean()
                .cache({ key: `trend:${headlineId}:${metric}:${timeframe}` });

            if (analyticsRecords.length < 2) {
                return { trend: 'insufficient-data', change: 0, dataPoints: analyticsRecords.length };
            }

            const values = analyticsRecords.map(r => r.analytics[0].metrics[metric]);
            const currentValue = values[values.length - 1];
            const previousValue = values[values.length - 2];
            const change = previousValue > 0 ? ((currentValue - previousValue) / previousValue) * 100 : 0;

            let trend = 'stable';
            const threshold = 5;
            if (change > threshold) trend = 'improving';
            else if (change < -threshold) trend = 'declining';

            return {
                trend,
                change: Math.round(change * 100) / 100,
                currentValue,
                previousValue,
                dataPoints: values.length,
                period: analyticsRecords[0].analytics[0].period,
                lastCalculated: analyticsRecords[analyticsRecords.length - 1].analytics[0].calculatedAt
            };
        } catch (error) {
            logger.error(`Trend analysis failed for headlineId ${headlineId}:`, error);
            throw new AppError('Trend analysis failed', 500);
        }
    }
}

export default new AnalyticsService();