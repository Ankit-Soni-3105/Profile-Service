import mongoose from 'mongoose';

const photoHistorySchema = new mongoose.Schema({
    userId: {
        type: String,
        required: true,
        index: true
    },
    photoId: {
        type: String,
        required: true,
        index: true
    },
    action: {
        type: String,
        enum: ['upload', 'crop', 'optimize', 'remove'],
        required: true
    },
    timestamp: {
        type: Date,
        default: Date.now,
        index: true
    },
    details: {
        type: Map,
        of: String,
        default: {}
    }, // e.g., { cropRatio: '1:1' }
}, {
    timestamps: true,
});

photoHistorySchema.index({ userId: 1, timestamp: -1 }); // Sort by user and recent history

const PhotoHistory = mongoose.model('PhotoHistory', photoHistorySchema);
export default PhotoHistory;