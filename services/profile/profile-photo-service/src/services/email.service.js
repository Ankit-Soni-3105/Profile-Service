import AWS from 'aws-sdk';
import { logger } from '../utils/logger.js';
import config from '../config/config.js';

// Configure AWS SES
AWS.config.update({
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    region: process.env.AWS_REGION || 'us-east-1',
});

const ses = new AWS.SES({ apiVersion: '2010-12-01' });

// Email templates configuration
const TEMPLATES = {
    'profile-created': {
        subject "Welcome to Your Profile!",
        template: (data) => `
            <h1>Welcome, ${data.name}!</h1>
            <p>Your profile has been successfully created.</p>
            <p>View your profile here: <a href="${data.profileUrl}">${data.profileUrl}</a></p>
            <p>Start connecting and showcasing your skills!</p>
        `,
    },
    // Add more templates as needed
};

// Send email with retry logic
export const sendEmail = async ({ to, template, data }) => {
    try {
        if (!to || !template || !TEMPLATES[template]) {
            throw new Error('Invalid email parameters');
        }

        const params = {
            Source: process.env.EMAIL_FROM || 'no-reply@yourdomain.com',
            Destination: { ToAddresses: [to] },
            Message: {
                Subject: { Data: TEMPLATES[template].subject },
                Body: {
                    Html: { Data: TEMPLATES[template].template(data) },
                    Text: { Data: TEMPLATES[template].template(data).replace(/<[^>]+>/g, '') },
                },
            },
        };

        let retries = 3;
        while (retries > 0) {
            try {
                await ses.sendEmail(params).promise();
                logger.info(`Email sent to ${to}`, { template });
                return;
            } catch (error) {
                retries--;
                if (retries === 0) {
                    throw new Error(`Failed to send email after 3 attempts: ${error.message}`);
                }
                logger.warn(`Email send attempt failed for ${to}`, { message: error.message, retriesLeft: retries });
                await new Promise(resolve => setTimeout(resolve, 1000));
            }
        }
    } catch (error) {
        logger.error('Failed to send email', { message: error.message, to, template });
        throw error;
    }
};