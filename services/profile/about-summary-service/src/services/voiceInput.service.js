import Summary from '../models/Summary.js';
import { logger } from '../utils/logger.js';
import { AppError } from '../errors/app.error.js';
import { cacheService } from '../services/cache.service.js';
import { metricsCollector } from '../utils/metrics.js';
import { eventEmitter } from '../events/events.js';
import mongoose from 'mongoose';
import speechToTextApi from '../services/speechToText.api.js'; // Hypothetical speech-to-text API client

class VoiceInputService {
    constructor() {
        this.model = Summary;
        this.defaultCacheTTL = 300; // 5 minutes
    }

    /**
     * Process voice input to create or update a summary
     */
    async processVoiceInput(summaryId, userId, audioData, language, options) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            let summary;
            let isNew = false;

            if (summaryId) {
                summary = await this.model.findById(summaryId).session(session);
                if (!summary) {
                    throw new AppError('Summary not found', 404);
                }
                // Check access
                if (!this.checkAccess(summary, userId)) {
                    throw new AppError('Access denied', 403);
                }
            } else {
                summary = new this.model({
                    userId,
                    title: 'Voice-Generated Summary',
                    content: '',
                    versions: [],
                    metadata: { wordCount: 0, characterCount: 0, createdBy: userId },
                    settings: { maxVersions: 50 },
                    flags: { isDeleted: false },
                });
                isNew = true;
            }

            // Transcribe audio
            const transcription = await speechToTextApi.transcribe({
                audio: audioData,
                language,
                options,
            });

            // Update or create summary
            const newContent = isNew ? transcription : `${summary.content}\n${transcription}`;
            const newVersion = {
                versionNumber: summary.versions.length + 1,
                content: newContent,
                title: summary.title,
                changeType: 'voice_input',
                isActive: true,
                createdAt: new Date(),
                stats: {
                    characterCount: newContent.length,
                    wordCount: newContent.trim().split(/\s+/).length,
                    paragraphCount: newContent.split('\n\n').length,
                    sentenceCount: newContent.split(/[.!?]+/).length - 1,
                },
                voiceInput: {
                    voiceInputId: new mongoose.Types.ObjectId(),
                    language,
                    transcription,
                    createdBy: userId,
                    createdAt: new Date(),
                },
            };

            // Deactivate previous versions
            summary.versions.forEach(v => (v.isActive = false));
            summary.versions.push(newVersion);

            // Limit versions
            if (summary.versions.length > summary.settings.maxVersions) {
                summary.versions = summary.versions.slice(-summary.settings.maxVersions);
            }

            // Update summary
            summary.content = newContent;
            summary.metadata.wordCount = newContent.trim().split(/\s+/).length;
            summary.metadata.characterCount = newContent.length;
            summary.metadata.lastEditedBy = { userId, timestamp: new Date() };

            // Store voice input
            summary.voiceInputs = summary.voiceInputs || [];
            summary.voiceInputs.push({
                voiceInputId: newVersion.voiceInput.voiceInputId,
                language,
                transcription,
                createdBy: userId,
                createdAt: new Date(),
                status: 'applied',
            });

            // Limit voice inputs
            if (summary.voiceInputs.length > 20) {
                summary.voiceInputs = summary.voiceInputs.slice(-20);
            }

            const savedSummary = await summary.save({ session });

            // Update user stats
            await this.updateUserStats(userId, isNew ? 'create_voice_summary' : 'update_voice_summary', session);

            await session.commitTransaction();

            // Clear cache
            await this.clearSummaryCache(savedSummary._id, userId);

            // Schedule async processing
            this.scheduleAsyncProcessing(savedSummary._id, newVersion.voiceInput);

            return {
                summaryId: savedSummary._id,
                content: savedSummary.content,
            };
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Voice input processing failed for summary ${summaryId || 'new'}:`, error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    /**
     * Get supported languages
     */
    async getSupportedLanguages(userId) {
        try {
            return await speechToTextApi.getSupportedLanguages();
        } catch (error) {
            logger.error(`Supported languages fetch failed for user ${userId}:`, error);
            return ['en-US', 'es-ES', 'fr-FR', 'de-DE', 'zh-CN']; // Fallback
        }
    }

    /**
     * Get voice input history
     */
    async getVoiceInputHistory(summaryId, userId, { page, limit }) {
        try {
            const summary = await this.model.findById(summaryId).lean();
            if (!summary) {
                throw new AppError('Summary not found', 404);
            }

            // Check access
            if (!this.checkAccess(summary, userId)) {
                throw new AppError('Access denied', 403);
            }

            const skip = (page - 1) * limit;
            const voiceInputs = (summary.voiceInputs || [])
                .sort((a, b) => b.createdAt - a.createdAt)
                .slice(skip, skip + limit)
                .map(v => ({
                    voiceInputId: v.voiceInputId,
                    language: v.language,
                    transcription: v.transcription,
                    status: v.status,
                    createdAt: v.createdAt,
                    createdBy: v.createdBy,
                }));

            const totalCount = summary.voiceInputs?.length || 0;
            const totalPages = Math.ceil(totalCount / limit);

            return {
                history: voiceInputs,
                pagination: {
                    page,
                    limit,
                    totalCount,
                    totalPages,
                    hasNext: page < totalPages,
                    hasPrev: page > 1,
                },
            };
        } catch (error) {
            logger.error(`Voice input history fetch failed for summary ${summaryId}:`, error);
            throw error;
        }
    }

    /**
     * Bulk process voice inputs
     */
    async bulkProcessVoiceInputs(inputs, userId, language, options) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const summaries = await Promise.all(
                inputs.map(async (input, index) => {
                    const summary = new this.model({
                        userId,
                        title: `Voice-Generated Summary ${index + 1}`,
                        content: '',
                        versions: [],
                        metadata: { wordCount: 0, characterCount: 0, createdBy: userId },
                        settings: { maxVersions: 50 },
                        flags: { isDeleted: false },
                    });

                    const transcription = await speechToTextApi.transcribe({
                        audio: input.audioData,
                        language,
                        options,
                    });

                    const newVersion = {
                        versionNumber: 1,
                        content: transcription,
                        title: summary.title,
                        changeType: 'voice_input',
                        isActive: true,
                        createdAt: new Date(),
                        stats: {
                            characterCount: transcription.length,
                            wordCount: transcription.trim().split(/\s+/).length,
                            paragraphCount: transcription.split('\n\n').length,
                            sentenceCount: transcription.split(/[.!?]+/).length - 1,
                        },
                        voiceInput: {
                            voiceInputId: new mongoose.Types.ObjectId(),
                            language,
                            transcription,
                            createdBy: userId,
                            createdAt: new Date(),
                        },
                    };

                    summary.versions.push(newVersion);
                    summary.content = transcription;
                    summary.metadata.wordCount = transcription.trim().split(/\s+/).length;
                    summary.metadata.characterCount = transcription.length;
                    summary.metadata.lastEditedBy = { userId, timestamp: new Date() };

                    summary.voiceInputs = summary.voiceInputs || [];
                    summary.voiceInputs.push({
                        voiceInputId: newVersion.voiceInput.voiceInputId,
                        language,
                        transcription,
                        createdBy: userId,
                        createdAt: new Date(),
                        status: 'applied',
                    });

                    const savedSummary = await summary.save({ session });
                    this.scheduleAsyncProcessing(savedSummary._id, newVersion.voiceInput);

                    return {
                        summaryId: savedSummary._id,
                        content: savedSummary.content,
                    };
                })
            );

            // Update user stats
            await this.updateUserStats(userId, 'bulk_create_voice_summaries', session);

            await session.commitTransaction();

            return {
                requested: inputs.length,
                created: summaries.length,
                summaries,
            };
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Bulk voice input processing failed for user ${userId}:`, error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    /**
     * Delete a voice input
     */
    async deleteVoiceInput(summaryId, userId, voiceInputId) {
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            const summary = await this.model.findById(summaryId).session(session);
            if (!summary) {
                throw new AppError('Summary not found', 404);
            }

            // Check access
            if (!this.checkAccess(summary, userId)) {
                throw new AppError('Access denied', 403);
            }

            const voiceInput = summary.voiceInputs?.find(
                v => v.voiceInputId.toString() === voiceInputId && v.status === 'applied'
            );
            if (!voiceInput) {
                throw new AppError('Voice input not found or already deleted', 404);
            }

            voiceInput.status = 'deleted';
            voiceInput.deletedAt = new Date();
            voiceInput.deletedBy = userId;

            await summary.save({ session });
            await this.updateUserStats(userId, 'delete_voice_input', session);

            await session.commitTransaction();
        } catch (error) {
            await session.abortTransaction();
            logger.error(`Voice input deletion failed for summary ${summaryId}:`, error);
            throw error;
        } finally {
            session.endSession();
        }
    }

    // Helper Methods

    /**
     * Check access permissions
     */
    checkAccess(summary, userId) {
        if (!summary) return false;
        if (summary.sharing?.isPublic) return true;
        if (summary.userId === userId) return true;
        if (summary.sharing?.collaborators?.some(c => c.userId === userId && c.status === 'accepted')) {
            return true;
        }
        return false;
    }

    /**
     * Update user stats
     */
    async updateUserStats(userId, action, session) {
        try {
            metricsCollector.increment(`voice.${action}`, { userId });
        } catch (error) {
            logger.error(`Failed to update user stats for ${userId}:`, error);
        }
    }

    /**
     * Clear summary cache
     */
    async clearSummaryCache(summaryId, userId) {
        try {
            const patterns = [
                `summary:${summaryId}:*`,
                `summaries:${userId}:*`,
                `voice:${summaryId}:*`,
            ];
            await Promise.all(patterns.map(pattern => cacheService.deletePattern(pattern)));
        } catch (error) {
            logger.error(`Cache clearing failed for summary ${summaryId}:`, error);
        }
    }

    /**
     * Schedule async processing
     */
    scheduleAsyncProcessing(summaryId, voiceInput) {
        setTimeout(async () => {
            try {
                // Placeholder for async tasks (e.g., transcription quality analysis)
                logger.info(`Async processing completed for voice input in summary ${summaryId}`);
            } catch (error) {
                logger.error(`Async processing failed for summary ${summaryId}:`, error);
            }
        }, 1000);
    }
}

export default VoiceInputService;