import mongoose from "mongoose";


const phoneOtpSchema = new mongoose.Schema({
    phone: {
        type: String,
        required: true
    },
    otp: {
        type: String,
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now,
        expires: 300// 5 minutes expiration
    }
});

export default mongoose.model("phoneOtp", phoneOtpSchema);
