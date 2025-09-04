import mongoose from 'mongoose';

const photoSchema = new mongoose.Schema({
  userId: { type: String, required: true, index: true }, // User identifier
  photoId: { type: String, required: true, unique: true, index: true }, // Unique photo ID
  url: { type: String, required: true }, // Cloudinary URL
  status: { type: String, enum: ['pending', 'processed', 'failed'], default: 'pending' },
  fileName: { type: String, required: true }, // Original file name
  fileSize: { type: Number, required: true }, // Size in bytes
  mimeType: { type: String, required: true }, // e.g., image/jpeg
  createdAt: { type: Date, default: Date.now, index: true },
  updatedAt: { type: Date, default: Date.now },
}, {
  timestamps: true,
});

photoSchema.index({ userId: 1, createdAt: -1 }); // Sort by user and recent photos

photoSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

const Photo = mongoose.model('Photo', photoSchema);
export default Photo;