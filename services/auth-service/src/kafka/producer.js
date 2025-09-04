// auth-service/src/kafka/producer.js
import { Kafka } from "kafkajs";
import config from "../config/config.js";

const kafka = new Kafka({
  clientId: "auth-service",
  brokers: [config.KAFKA_BROKER || "kafka:29092"], // Default to docker service name
});

const producer = kafka.producer();

export const connectProducer = async () => {
  let attempts = 0;
  const maxAttempts = 5;
  while (attempts < maxAttempts) {
    try {
      await producer.connect();
      console.log("✅ Kafka Producer connected (Auth Service)");
      break;
    } catch (error) {
      attempts++;
      console.log(`Attempt ${attempts} failed to connect to Kafka: ${error.message}`);
      if (attempts === maxAttempts) throw error;
      await new Promise((resolve) => setTimeout(resolve, 5000 * attempts)); // Exponential backoff
    }
  }
};

export const sendUserEvent = async (eventType, userData) => {
  try {
    await producer.send({
      topic: "user-events",
      messages: [
        {
          key: eventType,
          value: JSON.stringify(userData),
        },
      ],
    });
    console.log(`📤 User event produced from Auth Service by ${eventType}:`, userData);
  } catch (error) {
    console.error(`Failed to produce user event ${eventType}: ${error.message}`);
    throw error; // Let the controller handle this
  }
};

export const disconnectProducer = async () => {
  await producer.disconnect();
  console.log("🔴 Kafka Producer disconnected (Auth Service)");
};

// Graceful shutdown
process.on("SIGTERM", async () => {
  await disconnectProducer();
  process.exit(0);
});

process.on("SIGINT", async () => {
  await disconnectProducer();
  process.exit(0);
});