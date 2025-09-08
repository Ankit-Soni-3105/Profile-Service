import HeadlineHistory from '../models/headlineHistory.model.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';

class HistoryService {
    async getHistory(headlineId, options) {
        const { page = 1, limit = 20, eventType, eventCategory, startDate, endDate } = options;

        const query = { headlineId };
        if (eventType) query.eventType = eventType;
        if (eventCategory) query.eventCategory = eventCategory;
        if (startDate) query.timestamp = { $gte: new Date(startDate) };
        if (endDate) query.timestamp = { ...query.timestamp, $lte: new Date(endDate) };

        const skip = (page - 1) * limit;
        const historyRecords = await HeadlineHistory.find(query)
            .sort({ timestamp: -1 })
            .skip(skip)
            .limit(parseInt(limit))
            .select('historyId eventType eventCategory summary description changes snapshot performanceSnapshot timestamp')
            .cache({ key: `history:${headlineId}:${page}:${limit}:${eventType || ''}:${eventCategory || ''}:${startDate || ''}:${endDate || ''}` })
            .lean();

        const totalCount = await HeadlineHistory.countDocuments(query);

        return {
            headlineId,
            history: historyRecords,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                totalCount,
                totalPages: Math.ceil(totalCount / limit)
            }
        };
    }
}

export default new HistoryService();