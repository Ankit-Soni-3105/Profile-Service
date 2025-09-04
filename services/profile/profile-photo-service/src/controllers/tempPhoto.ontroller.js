import { uploadToCloudinary } from '../config/cloudinary.js';
import Photo from '../models/photo.model.js';
import PhotoHistory from '../models/photo.history.model.js';
import { v4 as uuidv4 } from 'uuid';
import { getCache, setCache } from '../services/redis.service.js';
import { promises as fs } from 'fs';

export const uploadTempPhoto = async (req, res) => {
  try {
    const userId = req.user.userId;
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const { buffer, originalname, mimetype, size } = req.file;
    const photoId = `temp-${uuidv4()}`;

    const tempFilePath = `/tmp/${photoId}-${originalname}`;
    await fs.writeFile(tempFilePath, buffer);

    const result = await uploadToCloudinary(tempFilePath, { folder: 'temp-photos' });
    await fs.unlink(tempFilePath);

    const photo = new Photo({
      userId,
      photoId,
      url: result.secure_url,
      fileName: originalname,
      fileSize: size,
      mimeType: mimetype,
      status: 'pending',
    });
    await photo.save();

    await PhotoHistory.create({
      userId,
      photoId,
      action: 'upload-temp',
    });

    const cacheKey = `tempphoto:${userId}:${photoId}`;
    await setCache(cacheKey, photo, 3600);

    res.status(201).json({ photoId, url: result.secure_url, message: 'Temporary photo uploaded' });
  } catch (error) {
    console.error('Error uploading temp photo:', error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
};
