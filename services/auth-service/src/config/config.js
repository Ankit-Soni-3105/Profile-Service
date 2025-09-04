import "dotenv/config";

const _config = {
    PORT: process.env.PORT,
    MONGO_URI: process.env.MONGO_URI,
    JWT_SECRET: process.env.JWT_SECRET,
    JWT_EXPIRATION: process.env.JWT_EXPIRATION,

    REDIS_HOST: process.env.REDIS_HOST,
    REDIS_PORT: process.env.REDIS_PORT,
    REDIS_PASSWORD: process.env.REDIS_PASSWORD,

    KAFKA_BROKER: process.env.KAFKA_BROKER,
    
    EMAIL_SERVICES: process.env.EMAIL_SERVICES,
    EMAIL_HOST: process.env.EMAIL_HOST,
    EMAIL_PORT: process.env.EMAIL_PORT,

    MY_EMAIL: process.env.MY_EMAIL,
    EMAIL_PASSWORD: process.env.EMAIL_PASSWORD,
};

const config = Object.freeze(_config);

export default config;
