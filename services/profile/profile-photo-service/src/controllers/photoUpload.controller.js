
import { uploadToCloudinary } from '../utils/cloudinary.js';
import Photo from '../models/photo.model.js';
import PhotoHistory from '../models/photo.history.model.js';
import { v4 as uuidv4 } from 'uuid';
import { setCache } from '../services/redis.service.js';
import { promises as fs } from 'fs';

export const uploadPhoto = async (req, res) => {
  try {
    const userId = req.user.userId;
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const { buffer, originalname, mimetype, size } = req.file;
    const photoId = uuidv4();

    // Write buffer to temporary file
    const tempFilePath = `/tmp/${photoId}-${originalname}`;
    await fs.writeFile(tempFilePath, buffer);

    // Upload to Cloudinary
    const result = await uploadToCloudinary(tempFilePath);
    await fs.unlink(tempFilePath); // Clean up

    // Save to MongoDB
    const photo = new Photo({
      userId,
      photoId,
      url: result.secure_url,
      fileName: originalname,
      fileSize: size,
      mimeType: mimetype,
    });
    await photo.save();

    // Log history
    await PhotoHistory.create({
      userId,
      photoId,
      action: 'upload',
      details: { originalSize: `${size} bytes` },
    });

    // Cache
    const cacheKey = `photo:${userId}:${photoId}`;
    await setCache(cacheKey, photo, 3600);

    res.status(201).json({ 
        photoId, 
        url: 
        result.secure_url, 
        message: 'Photo uploaded successfully' 
    });
  } catch (error) {
    console.error('Error uploading photo:', error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
};

export default { uploadPhoto };