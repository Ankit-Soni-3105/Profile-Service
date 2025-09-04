import mongoose from 'mongoose';

const photoSettingsSchema = new mongoose.Schema({
  userId: { type: String, required: true, index: true },
  visibility: { type: String, enum: ['public', 'private', 'connections'], default: 'public' },
  cropRatio: { type: Number, default: 1.0 }, // Aspect ratio (e.g., 1:1)
  optimizationLevel: { type: String, enum: ['low', 'medium', 'high'], default: 'medium' },
  accessibilityTags: { type: [String], default: ['image'] }, // e.g., ['profile', 'avatar']
  createdAt: { type: Date, default: Date.now },
}, {
  timestamps: true,
});

photoSettingsSchema.index({ userId: 1 });

const PhotoSettings = mongoose.model('PhotoSettings', photoSettingsSchema);
export default PhotoSettings;