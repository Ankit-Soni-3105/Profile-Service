// profile-service/src/kafka/consumer.js
import { Kafka } from 'kafkajs';
import config from '../config/config.js';
import { setCache } from '../services/redis.service.js';
import profileModel from '../models/profile.model.js';

const kafka = new Kafka({
    clientId: config.kafka.clientId,
    brokers: config.kafka.brokers,
});

const consumer = kafka.consumer({ groupId: config.kafka.groupId || 'profile-group' });
0

export const connectConsumer = async () => {
    let attempts = 0;
    const maxAttempts = 5;
    while (attempts < maxAttempts) {
        try {
            await consumer.connect();
            await consumer.subscribe({ topic: config.kafka.profileEventsTopic, fromBeginning: true });
            console.log('✅ Kafka Consumer connected (Profile Service)');
            break;
        } catch (error) {
            attempts++;
            console.log(`Attempt ${attempts} failed to connect to Kafka: ${error.message}`);
            if (attempts === maxAttempts) throw error;
            await new Promise((resolve) => setTimeout(resolve, 5000 * attempts));
        }
    }

    await consumer.run({
        eachMessage: async ({ topic, partition, message }) => {
            try {
                const eventType = message.key.toString();
                const userData = JSON.parse(message.value.toString());
                console.log(`📥 User event consumed in Profile Service: ${eventType}`, userData);

                // Process based on eventType (e.g., 'user-created' from auth)
                if (eventType === 'user-created') {
                    // Create initial profile with auth data (name, email)
                    const newProfile = new profileModel({
                        userId: userData.userId, // Assume auth sends userId
                        firstName: userData.firstName,
                        lastName: userData.lastName,
                        email: userData.email,
                        // Baki fields default/empty
                    });
                    await newProfile.save();

                    // Cache in Redis immediately
                    await setCache(`profile:${userData.userId}`, JSON.stringify(newProfile.toObject()), config.redis.cacheTtl);
                    console.log(`✅ Profile cached for userId: ${userData.userId}`);
                }
                // Add more eventTypes if needed, jaise 'user-updated'
            } catch (error) {
                console.error(`Failed to process message: ${error.message}`);
                // Dead-letter queue ya retry logic add for production
            }
        },
    });
};

export const disconnectConsumer = async () => {
    await consumer.disconnect();
    console.log('🔴 Kafka Consumer disconnected (Profile Service)');
};

// Graceful shutdown
process.on('SIGTERM', async () => {
    await disconnectConsumer();
    process.exit(0);
});

process.on('SIGINT', async () => {
    await disconnectConsumer();
    process.exit(0);
});