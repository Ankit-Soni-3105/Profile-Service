import { Router } from "express";
import axios from "axios";
import User from "../models/user.model.js";
import jwt from "jsonwebtoken";

const router = Router();

// Step 1: Redirect to GitHub OAuth
router.get("/github", (req, res) => {
    const redirectUrl = `https://github.com/login/oauth/authorize?client_id=${process.env.GITHUB_CLIENT_ID}&scope=user:email`;
    res.redirect(redirectUrl);
});

// Step 2: GitHub OAuth Callback
router.get("/github/callback", async (req, res) => {
    try {
        const { code } = req.query;
        if (!code) {
            return res.status(400).send("Authorization code is required.");
        }

        console.log("🔐 GitHub OAuth Code:", code);

        // Step 3: Exchange code for access token
        const tokenResponse = await axios.post(
            "https://github.com/login/oauth/access_token",
            {
                client_id: process.env.GITHUB_CLIENT_ID,
                client_secret: process.env.GITHUB_CLIENT_SECRET,
                code,
            },
            {
                headers: { Accept: "application/json" },
            }
        );

        const access_token = tokenResponse.data.access_token;
        if (!access_token) {
            return res.status(401).send("Failed to retrieve GitHub access token.");
        }

        // Step 4: Get user profile and email
        const [userResponse, emailResponse] = await Promise.all([
            axios.get("https://api.github.com/user", {
                headers: { Authorization: `Bearer ${access_token}` },
            }),
            axios.get("https://api.github.com/user/emails", {
                headers: { Authorization: `Bearer ${access_token}` },
            }),
        ]);

        const githubUser = userResponse.data;
        const primaryEmail =
            emailResponse.data.find((email) => email.primary && email.verified)?.email ||
            githubUser.email;

        if (!primaryEmail) {
            return res.status(400).send("Email not found or not verified.");
        }

        // Step 5: Find or create user
        let user = await User.findOne({ githubId: githubUser.id });

        if (!user) {
            user = await User.create({
                githubId: githubUser.id,
                username: githubUser.login,
                email: primaryEmail,
                avatarUrl: githubUser.avatar_url,
            });
        }

        // Step 6: Generate JWT
        const token = jwt.sign(
            { id: user._id },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRATION || "7d" }
        );

        user.token = token;
        await user.save();

        // ✅ Step 7: Redirect to frontend with token
        res.redirect(`http://localhost:5173/github-auth-success?token=${token}`);
    } catch (error) {
        console.error("❌ GitHub Auth Error:", error.message);
        return res.status(500).send("GitHub authentication failed.");
    }
});

export default router;
