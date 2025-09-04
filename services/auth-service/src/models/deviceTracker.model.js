import mongoose from "mongoose";


const loggedEmailSchema = new mongoose.Schema({
    email: {
        type: String,
    },
    verifiedPhone: {
        type: String,
    },
    usedOtpOverride: {
        type: Boolean,
        default: false
     },
});

const deviceTrackerSchema = new mongoose.Schema({
    deviceId: {
        type: String,
        required: true,
        unique: false, // Multiple entries can exist
    },
    loggedEmails: [loggedEmailSchema],
    permanentlyBlocked: {
        type: Boolean,
        default: false,
    },
    lastLogin: {
        type: Date,
        default: Date.now,
    },
}, {
    timestamps: true,
});

export default mongoose.model("deviceTracker", deviceTrackerSchema);
