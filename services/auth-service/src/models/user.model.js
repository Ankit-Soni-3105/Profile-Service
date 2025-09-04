import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import config from '../config/config.js';

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        minlength: 3,
        maxlength: 20,
    },
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true,
    },
    password: {
        type: String,
        required: false,
        minlength: 6,
    },
    accountVerified: {
        type: Boolean,
        default: false,
    },
    googleId: {
        type: String,
        unique: true,
        sparse: true
    },
    followers: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'user'
    }],
    following: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'user'
    }],
    verificationCode: {
        type: Number,
    },
    deviceLogins: [
        {
            deviceId: {
                type: String
            },
            attempts: {
                type: Number,
                default: 1
            },
            lastLogin: {
                type: Date,
                default: Date.now
            }
        }
    ],
    isEmailVerified: {
        type: Boolean,
        default: false
    },
    hasSolvedPuzzle: {
        type: Boolean,
        default: false
    },
    githubId: {
        type: String
    },
    avatarUrl: {
        type: String
    },
    token: {
        type: String
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    lastActivityAt: {
        type: Date,
        default: Date.now
    }
},
    {
        timestamps: true,
    }
);

userSchema.statics.hashPassword = async function (password) {
    if (!password) {
        throw new Error("Password is required");
    }
    const salt = await bcrypt.genSalt(10);
    return await bcrypt.hash(password, salt);
}

userSchema.methods.comparePassword = async function (password) {
    if (!password) {
        throw new Error("Password is required");
    }
    if (!this.password) {
        throw new Error("User password is not set");
    }
    return await bcrypt.compare(password, this.password);
}

userSchema.methods.generateAuthToken = async function () {
    const token = jwt.sign(
        {
            _id: this._id,
            username: this.username,
            email: this.email,
        },
        config.JWT_SECRET,
        {
            expiresIn: config.JWT_EXPIRATION,
        });

    return token;
}


userSchema.methods.generateVerificationCode = function () {
    function generateRandomFiveDigitNumber() {
        const firstDigit = Math.floor(Math.random() * 9) + 1;
        const remainingDigits = Math.floor(Math.random() * 10000)
            .toString()
            .padStart(4, 0);

        return parseInt(firstDigit + remainingDigits);
    }
    const verificationCode = generateRandomFiveDigitNumber();
    this.verificationCode = verificationCode;
    this.verificationCodeExpire = Date.now() + 10 * 60 * 1000;

    return verificationCode;
};



userSchema.statics.isVerifyToken = function (token) {
    if (!token) {
        throw new Error("Token is required");
    }
    return jwt.verify(token, config.JWT_SECRET);
}

const userModel = mongoose.model('user', userSchema);
export default userModel;