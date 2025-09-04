import { Router } from "express";
import passport from 'passport';
import jwt from 'jsonwebtoken';
import crypto from "crypto"
import userModel from "../models/user.model.js";

const router = Router();


router.get('/google',
    passport.authenticate(
        'google',
        {
            scope: ['profile', 'email']
        }
    )
);

// Callback route
router.get('/google/callback',
    passport.authenticate('google', { session: false }),
    async (req, res) => {
        try {
            const user = req.user;

            // STEP 1: Get IP + User-Agent
            const userAgent = req.headers['user-agent'] || 'unknown-agent';
            const ipAddress = req.ip || req.connection.remoteAddress || 'unknown-ip';

            // STEP 2: Create hashed device ID
            const deviceId = crypto.createHash('sha256')
                .update(ipAddress + userAgent)
                .digest('hex');

            // STEP 3: Check device login in DB
            const existingDevice = user.deviceLogins.find(device => device.deviceId === deviceId);

            if (existingDevice) {
                const now = Date.now();
                const timeDiff = now - new Date(existingDevice.lastLogin).getTime();

                // Reset attempts after 24 hrs
                if (timeDiff > 24 * 60 * 60 * 1000) {
                    existingDevice.attempts = 1;
                    existingDevice.lastLogin = new Date();
                } else {
                    if (existingDevice.attempts >= 3) {
                        return res.status(429).json({
                            message: "Login limit exceeded for this device via Google OAuth. Please use a different device."
                        });
                    } else {
                        existingDevice.attempts += 1;
                        existingDevice.lastLogin = new Date();
                    }
                }
            } else {
                user.deviceLogins.push({
                    deviceId,
                    attempts: 1,
                    lastLogin: new Date()
                });
            }

            await user.save();

            // STEP 4: Generate JWT token
            const token = jwt.sign({
                id: user._id,
                email: user.email
            }, process.env.JWT_SECRET, { expiresIn: '1h' });

            // STEP 5: Redirect to frontend
            res.redirect(`http://localhost:5173/oauth-success?token=${token}`);
        } catch (err) {
            console.error("OAuth Error:", err);
            res.status(500).json({ error: "Google login failed" });
        }
    }
);

export default router;