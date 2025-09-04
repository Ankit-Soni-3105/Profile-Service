import twilio from 'twilio';

const client = twilio(
    process.env.TWILIO_ACCOUNT_SID,
    process.env.TWILIO_AUTH_TOKEN
);

export const sendOTPViaSMS = async (phone, otp) => {
    try {
        const message = await client.messages.create({
            body: `Your OTP is: ${otp}`,
            from: process.env.TWILIO_PHONE_NUMBER,
            to: phone,  
        });

        console.log('OTP sent:', message.sid);
        return message;
    } catch (error) {
        console.error('Twilio Error:', error.message);
        throw new Error('Failed to send OTP');
    }
};
