import userModel from '../models/user.model.js';
import { validationResult } from 'express-validator';
import redisClient from '../services/redis.service.js';
import { generateEmailTemplate } from '../utils/utils.js';
import { createUser, getAllusers, loginUserService, sendEmail } from '../services/user.service.js';
import crypto from 'crypto';
import deviceTrackerModel from '../models/deviceTracker.model.js';
import phoneModel from '../models/phone.model.js';
import { sendOTPViaSMS } from '../services/twillio.service.js';
import { createClient } from 'redis';
import { sendUserEvent } from '../kafka/producer.js';



export const createUserController = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    try {
        const { username, email, password } = req.body;

        const userAgent = req.headers['user-agent'] || 'unknown-agent';
        const ipAddress = req.ip || req.connection.remoteAddress || 'unknown-ip';
        const deviceId = crypto.createHash('sha256').update(ipAddress + userAgent).digest('hex');

        let deviceTracker = await deviceTrackerModel.findOne({ deviceId });

        if (deviceTracker?.permanentlyBlocked) {
            return res.status(403).json({ message: "This device is permanently blocked. Contact support." });
        }

        // STEP 2: Create tracker if not exists
        if (!deviceTracker) {
            deviceTracker = new deviceTrackerModel({
                deviceId,
                loggedEmails: [],
                lastLogin: new Date()
            });
        }

        const emailAlreadyExists = deviceTracker.loggedEmails.some(e => e.email === email);

        if (!emailAlreadyExists) {
            if (deviceTracker.loggedEmails.length >= 3) {
                const otpOverrideEntry = deviceTracker.loggedEmails.find(e => e.usedOtpOverride);

                if (!otpOverrideEntry) {
                    return res.status(403).json({
                        otpOverrideRequired: true,
                        message: "Too many emails created from this device. Verify with phone number to continue."
                    });
                }

                if (otpOverrideEntry.verifiedPhone !== phone) {
                    deviceTracker.permanentlyBlocked = true;
                    await deviceTracker.save();
                    return res.status(403).json({
                        message: "OTP override phone mismatch. This device is permanently blocked."
                    });
                }
            }

            deviceTracker.loggedEmails.push({ email });
        }

        await deviceTracker.save();

        const user = await createUser({
            username,
            email,
            password
        });

        // console.log("user in controller", user.password);

        if (!user) {
            return res.status(400).json({ error: "User creation failed" });
        }

        const token = await user.generateAuthToken();
        // console.log("token in controller", token);

        if (!token) {
            return res.status(500).json({ error: "Token generation failed" });
        }

        const verificationCode = await user.generateVerificationCode();
        await user.save();
        await sendVerificationCode(
            verificationCode,
            user.username,
            user.email
        );

        return res.status(201).json({
            message: `User created successfully. Verification code sent to ${user.email} please check your email.`,
            user: {
                _id: user._id,
                username: user.username,
                email: user.email,
            },
            token
        });
    } catch (error) {
        console.log("Error in createUserController:", error);
        return res.status(500).json({ error: error.message });
    }
}

async function sendVerificationCode(
    verificationCode,
    username,
    email
) {
    try {
        const message = generateEmailTemplate(verificationCode);
        await sendEmail({ email, subject: "Your Verification Code", message });
        console.log(`Verification code sent to ${username} (${email})`);
    } catch (err) {
        console.log(err);
        res.status(400).json({ message: err.message });
    }
}

export const loginUserController = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
        const { email, password } = req.body;
        const user = await loginUserService({ email, password });

        // Step 1: Check if email is verified
        if (!user.accountVerified) {
            return res.status(403).json({
                message: "Your account is not verified. Please verify it using the OTP sent to your email.",
            });
        }

        // Step 2: Generate deviceId from IP + User-Agent
        const userAgent = req.headers['user-agent'] || 'unknown-agent';
        const ipAddress = req.ip || req.connection.remoteAddress || 'unknown-ip';
        const deviceId = crypto.createHash('sha256').update(ipAddress + userAgent).digest('hex');
        // console.log("Device Id:", deviceId);

        let deviceTracker = await deviceTrackerModel.findOne({ deviceId });

        // Step 3: Blocked device check
        if (deviceTracker?.permanentlyBlocked) {
            return res.status(403).json({
                message: "This device is permanently blocked. Please contact support.",
            });
        }

        // Step 4: Create deviceTracker if doesn't exist
        if (!deviceTracker) {
            deviceTracker = new deviceTrackerModel({
                deviceId,
                loggedEmails: [],
                lastLogin: new Date(),
            });
        }

        const emailAlreadyLogged = deviceTracker.loggedEmails.some(e => e.email === email);

        if (!emailAlreadyLogged) {
            if (deviceTracker.loggedEmails.length >= 3) {
                const otpOverrideEntry = deviceTracker.loggedEmails.find(e => e.usedOtpOverride);

                if (!otpOverrideEntry) {
                    return res.status(401).json({
                        otpOverrideRequired: true,
                        message: "Too many emails logged in from this device. Verify with phone number to continue.",
                    });
                } else if (otpOverrideEntry.verifiedPhone !== user.phone) {
                    deviceTracker.permanentlyBlocked = true;
                    await deviceTracker.save();
                    return res.status(403).json({
                        message: "You used a different phone number after OTP override. This device is now permanently blocked.",
                    });
                }
            }

            deviceTracker.loggedEmails.push({ email });
            deviceTracker.lastLogin = new Date();
            await deviceTracker.save();
        }

        // Step 5: Device login rate limit (3 attempts/day)
        const existingDeviceLogin = user.deviceLogins.find(d => d.deviceId === deviceId);
        const now = new Date();

        if (existingDeviceLogin) {
            const timeDiff = now - new Date(existingDeviceLogin.lastLogin);

            if (timeDiff > 24 * 60 * 60 * 1000) {
                existingDeviceLogin.attempts = 1;
                existingDeviceLogin.lastLogin = now;
            } else {
                if (existingDeviceLogin.attempts >= 3) {
                    return res.status(429).json({
                        message: "Login limit exceeded for this device. Please use a different device.",
                    });
                } else {
                    existingDeviceLogin.attempts += 1;
                    existingDeviceLogin.lastLogin = now;
                }
            }
        } else {
            user.deviceLogins.push({
                deviceId,
                attempts: 1,
                lastLogin: now,
            });
        }

        await user.save();

        // Step 6: Check inactivity (>7 days)
        const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
        // const sevenDaysAgo = new Date(Date.now() - 10 * 1000);
        if (user.lastActivityAt < sevenDaysAgo) {
            user.accountVerified = false;

            const verificationCode = await user.generateVerificationCode();
            await sendVerificationCode(verificationCode, user.username, user.email);
            await user.save();

            return res.status(403).json({
                message:
                    "Your account was inactive for over 7 days. We've sent a new OTP to verify your email before you can login.",
            });
        }

        // Step 7: Finalize login
        user.lastActivityAt = now;
        await user.save();

        const token = await user.generateAuthToken();

        await sendUserEvent("user-login", {
            userId: user._id.toString(),
            email: user.email,
            username: user.username,
            deviceId,
            ipAddress,
            userAgent,
            timestamp: now,
        });

        return res.status(200).json({
            message: "User login successful",
            user,
            token,
        });
    } catch (error) {
        console.log("Error in loginUserController:", error);
        return res.status(500).json({ error: error.message });
    }
};

export const sendOtpByPhoneController = async (req, res) => {
    try {
        const { phone } = req.body;
        const otp = Math.floor(100000 + Math.random() * 900000).toString();// Generate a 6-digit OTP


        const redisClient = createClient();
        await redisClient.connect(); // Make sure to await this in async setup


        // Save OTP in DB or Redis (with expiry 2 mins)
        await redisClient.setEx(`otp:${phone}`, 120, otp); // 120 seconds = 2 mins

        await sendOTPViaSMS(phone, otp);

        res.status(200).json({ message: 'OTP sent successfully' });
    } catch (err) {
        console.log("otp sending error ", err)
        res.status(500).json({ error: "Failed to send OTP." });
    }
};

export const verifyPhoneOtpController = async (req, res) => {
    try {
        const { phone, otp, deviceId, email } = req.body;

        const storedOtp = await phoneModel.findOne({ phone });

        if (!storedOtp || storedOtp.otp !== otp) {
            return res.status(400).json({ message: "Invalid or expired OTP." });
        }

        const deviceTracker = await deviceTrackerModel.findOne({ deviceId });

        if (!deviceTracker) {
            return res.status(404).json({ message: "Device not found." });
        }

        // Allow OTP override once
        deviceTracker.loggedEmails.push({
            email,
            verifiedPhone: phone,
            usedOtpOverride: true
        });

        await deviceTracker.save();
        await phoneModel.deleteOne({ phone });

        return res.status(200).json({ message: "OTP verified. You are now logged in." });
    } catch (error) {
        console.log("Error in verifyPhoneOtpController:", error);
        return res.status(500).json({ error: error.message });
    }
};

export const verifyPuzzle = async (req, res) => {
    const { userId, type, answer } = req.body;

    // Dummy correct answers for testing
    const correctAnswers = {
        math: '12', // e.g. 5 + 7
        captcha: 'Xy7a2', // pre-generated
        image: 'dog', // Image shown was of a dog
    };

    if (answer !== correctAnswers[type]) {
        return res.status(400).json({ success: false, message: 'Wrong answer!' });
    }

    await userModel.findByIdAndUpdate(
        userId,
        { hasSolvedPuzzle: true }
    );
    return res.json({ success: true, message: 'Puzzle solved!' });
};

export const verifyUserByOtpController = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    try {
        const { email, verificationCode } = req.body;
        // console.log("Verification code received:", verificationCode);

        if (!email || !verificationCode) {
            return res.status(400).json({ error: "Email and verification code are required" });
        }

        const user = await userModel.findOne({ email });
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }
        if (user.accountVerified) {
            return res.status(400).json({ error: "User is already verified" });
        }

        console.log("User verification code:", user.verificationCode);

        // if (user.verificationCode !== verificationCode) {
        //     return res.status(400).json({ error: "Invalid verification code" });
        // }

        // if (user.verificationCodeExpire < Date.now()) {
        //     return res.status(400).json({ error: "Verification code has expired" });
        // }
        if (user.verificationCode == verificationCode) {
            user.accountVerified = true;
            user.verificationCode = null;
            await user.save();
        } else {
            return res.status(400).json({ error: "Invalid verification Code, Please try again or check your email for the correct code." });
        }


        return res.status(200).json({
            message: "User verified successfully",
            user: {
                _id: user._id,
                username: user.username,
                email: user.email,
            }
        });

    } catch (error) {
        console.log("Error in verifyUserByOtpController:", error);
        return res.status(500).json({ error: error.message });
    }
}

export const getUserController = async (req, res) => {
    try {
        const user = req.user;
        console.log("User data in getUserController:", user);
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        return res.status(200).json({
            message: "User retrieved successfully",
            user: {
                _id: user._id,
                username: user.username,
                email: user.email,
                password: user.password,
            }
        });
    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
}

export const logoutUserController = async (req, res) => {
    try {
        // console.log("Token data in logout:", req.tokenData);
        const timeremainingTokenData = req.tokenData.exp * 1000 - Date.now();
        await redisClient.set(
            `blacklist:${req.tokenData.token}`,
            true,
            'EX',
            Math.floor(timeremainingTokenData / 1000) // Set expiration time in seconds
        );

        res.status(200).json({
            message: "User logged out successfully",
        });

    } catch (error) {
        console.log("Error in logoutUserController:", error);
        return res.status(500).json({ error: error.message });
    }
}

export const getallUserController = async (req, res) => {
    try {
        const userId = req.user._id;

        if (!userId) {
            return res.status(400).json({ error: "User ID is required" });
        }

        const users = await getAllusers({
            userId: userId
        })

        if (!users || users.length === 0) {
            return res.status(404).json({ error: "No users found" });
        }

        return res.status(200).json({
            message: "Users retrieved successfully",
            users: users.map(user => ({
                _id: user._id,
                username: user.username,
                email: user.email,
            }))
        });

    } catch (error) {
        console.log("Error in getallUserController:", error);
        return res.status(500).json({ error: error.message });
    }
}

export const followUserController = async (req, res) => {
    try {
        const { targetUserId } = req.body;
        const currentUserId = req.user._id;

        if (targetUserId === currentUserId.toString()) {
            return res.status(400).json({ error: "You can't follow yourself." });
        }

        const targetUser = await userModel.findById(targetUserId);
        const currentUser = await userModel.findById(currentUserId);

        if (!targetUser || !currentUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        if (targetUser.followers.includes(currentUserId)) {
            return res.status(400).json({ error: 'Already following' });
        }

        targetUser.followers.push(currentUserId);
        currentUser.following.push(targetUserId);

        await targetUser.save();
        await currentUser.save();

        // Emit socket event
        const io = req.app.get('io');
        io.to(targetUserId).emit('follow-request', {
            message: `${currentUser.username} has followed you.`,
            from: currentUserId,
        });

        res.status(200).json({ message: 'Followed successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

export const unfollowUserController = async (req, res) => {
    try {
        const { targetUserId } = req.body;
        const currentUserId = req.user._id;

        const targetUser = await userModel.findById(targetUserId);
        const currentUser = await userModel.findById(currentUserId);

        if (!targetUser || !currentUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        targetUser.followers = targetUser.followers.filter(
            id => id.toString() !== currentUserId.toString()
        );
        currentUser.following = currentUser.following.filter(
            id => id.toString() !== targetUserId.toString()
        );

        await targetUser.save();
        await currentUser.save();

        res.status(200).json({ message: 'Unfollowed successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

// export const loginUserController = async (req, res) => {
//     // Validate request body
//     const errors = validationResult(req);
//     if (!errors.isEmpty()) {
//         return res.status(400).json({ errors: errors.array() });
//     }
//     try {
//         const { email, password } = req.body;

//         const user = await loginUserService({
//             email,
//             password
//         });

//         if (!user.accountVerified) {
//             return res.status(403).json({
//                 message: "Your account is not verified. Please verify it using the OTP sent to your email."
//             });
//         }

//         const userAgent = req.headers['user-agent'] || 'unknown-agent';
//         const ipAddress = req.ip || req.connection.remoteAddress || 'unknown-ip';

//         const deviceId = crypto.createHash('sha256')
//             .update(ipAddress + userAgent)
//             .digest('hex');

//         console.log("Device Id: ", deviceId);

//         const deviceTracker = await deviceTrackerModel.findOne({ deviceId });

//         if (deviceTracker?.permanentlyBlocked) {
//             return res.status(403).json({
//                 message: "This device is permanently blocked. Please contact support."
//             });
//         }

//         if (!deviceTracker) {
//             deviceTracker = new deviceTrackerModel({
//                 deviceId,
//                 loggedEmails: [],
//                 lastLogin: new Date()
//             });
//         } else {
//             const emailExists = deviceTracker.loggedEmails.some(log => log.email === email);

//             if (!emailExists) {
//                 if (deviceTracker.loggedEmails.length >= 3) {
//                     const usedOtp = deviceTracker.loggedEmails.some(e => e.usedOtpOverride);

//                     if (!usedOtp) {
//                         return res.status(401).json({
//                             otpOverrideRequired: true,
//                             message: "Too many emails logged in from this device. Verify with phone number to continue."
//                         });
//                     } else {
//                         const lastUsedPhone = deviceTracker.loggedEmails.find(e => e.usedOtpOverride)?.verifiedPhone;//
//                         if (user.phone !== lastUsedPhone) {
//                             deviceTracker.permanentlyBlocked = true;
//                             await deviceTracker.save();
//                             return res.status(403).json({
//                                 message: "You used a different phone number after OTP override. This device is now permanently blocked."
//                             });
//                         }
//                     }
//                 } else {
//                     deviceTracker.loggedEmails.push({ email });
//                 }
//                 await deviceTracker.save();
//             }
//         }

//         const alreadyUsed = deviceTracker.loggedEmails.find(entry => entry.email === email);

//         if (!alreadyUsed) {
//             if (deviceTracker.loggedEmails.length >= 3) {
//                 const usedOverride = deviceTracker.loggedEmails.find(entry => entry.usedOtpOverride);

//                 if (!usedOverride) {
//                     return res.status(429).json({
//                         otpOverrideRequired: true,
//                         emailTryingToLogin: email,
//                         message: "Login blocked on this device after 3 accounts. You may override this once by verifying your phone via OTP."
//                     });
//                 } else if (usedOverride && usedOverride.verifiedPhone !== user.phone) {
//                     deviceTracker.permanentlyBlocked = true;
//                     await deviceTracker.save();

//                     return res.status(403).json({
//                         message: "You tried to login with another number after using OTP override. This device is now permanently blocked."
//                     });
//                 }
//             } else {
//                 deviceTracker.loggedEmails.push({ email });
//             }
//         }

//         deviceTracker.lastLogin = new Date();
//         await deviceTracker.save();

//         const existingDevice = user.deviceLogins.find(device => device.deviceId === deviceId);

//         if (existingDevice) {
//             const now = Date.now();
//             const timeDiff = now - new Date(existingDevice.lastLogin).getTime();

//             if (timeDiff > 24 * 60 * 60 * 1000) {
//                 existingDevice.attempts = 1;
//                 existingDevice.lastLogin = new Date();
//             } else {
//                 if (existingDevice.attempts >= 3) {
//                     return res.status(429).json({
//                         message: "Login limit exceeded for this device. Please use a different device."
//                     });
//                 } else {
//                     existingDevice.attempts += 1;
//                     existingDevice.lastLogin = new Date();
//                 }
//             }
//         } else {
//             user.deviceLogins.push({
//                 deviceId,
//                 attempts: 1,
//                 lastLogin: new Date()
//             });
//         }

//         await user.save();

//         const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
//         // const sevenDaysAgo = new Date(Date.now() - 10 * 1000);
//         if (user.accountVerified && user.lastActivityAt < sevenDaysAgo) {
//             user.accountVerified = false;

//             // Generate new OTP code and send email
//             const verificationCode = await user.generateVerificationCode(); // You should have this method in schema
//             await sendVerificationCode(verificationCode, user.username, user.email);

//             await user.save();

//             return res.status(403).json({
//                 message:
//                     "Your account was inactive for over 7 days. We've sent a new OTP to verify your email before you can login.",
//             });
//         }

//         if (!user.accountVerified) {
//             return res.status(403).json({
//                 message:
//                     "Your account is not verified. Please check your email for the OTP verification.",
//             });
//         }


//         user.lastActivityAt = new Date();
//         await user.save();


//         const token = await user.generateAuthToken();

//         return res.status(200).json({
//             message: "User login successful",
//             user,
//             token
//         });
//     } catch (error) {
//         console.log("Error in loginUserController:", error);
//         return res.status(500).json({ error: error.message });
//     }
// }