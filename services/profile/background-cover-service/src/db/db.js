import mongoose from 'mongoose';
import config from '../config/config.js';

export async function connectDB() {
    await mongoose.connect(config.MONGO_URI).then(() => {
        console.log('MongoDB connected successfully');
    }).catch((error) => {
        console.error('MongoDB connection error:', error);
    });
}
