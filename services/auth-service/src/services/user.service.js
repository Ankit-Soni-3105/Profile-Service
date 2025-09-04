import config from "../config/config.js";
import userModel from "../models/user.model.js";
import nodemailer from "nodemailer";


export const createUser = async ({
    username,
    email,
    password,
}) => {
    if (!username || !email || !password) {
        throw new Error("All fields are required");
    }

    // Check if the user already exists
    const existingUser = await userModel.findOne(
        {
            $or: [
                { email },
                { username }
            ]
        }
    );

    if (existingUser) {
        throw new Error("User already exists");
    }

    const registrationAttemptByUser = await userModel.find({
        $or: [
            { email }
        ]
    })
    if (registrationAttemptByUser.length > 3) {
        return res.status(403).json(
            {
                message: "Your Registration Attempt Limit is exeeded. Please try again after an hours."
            }
        )
    }

    const hashedPassword = await userModel.hashPassword(password);

    const user = new userModel({
        username,
        email,
        password: hashedPassword,
    });

    await user.save();
    return user;
}


export const sendEmail = async ({
    email,
    subject,
    message
}) => {
    const transporter = nodemailer.createTransport({
        service: config.EMAIL_SERVICES,
        host: config.EMAIL_HOST,
        port: config.EMAIL_PORT,
        secure: false,
        auth: {
            user: config.MY_EMAIL,
            pass: config.EMAIL_PASSWORD
        }
    });

    const options = {
        from: config.MY_EMAIL,
        to: email,
        subject,
        html: message
    }
    await transporter.sendMail(options);
}

export const loginUserService = async ({
    email,
    password,
}) => {
    if (!email || !password) {
        throw new Error("Email and password are required");
    }

    // Check if the user exists
    const user = await userModel.findOne({ email }).select('+password');
    // console.log("user in service: ", user);

    if (!user) {
        throw new Error("Invalid credentials");
    }

    const isMatch = await user.comparePassword(password);

    if (!isMatch) {
        throw new Error("Invalid credentials");
    }

    return user;
}

export const getUserById = async (email, password) => {
    if (!email || !password) {
        throw new Error("Email and password are required");
    }

    const user = await userModel.findOne({ email }).select('-password');

    if (!user) {
        throw new Error("User not found");
    }
    return user;
}

export const getAllusers = async ({
    userId
}) => {
    try {
        if (!userId) {
            throw new Error("User ID is required");
        }
        const users = await userModel.find({
            _id: { $ne: userId }
        })
        return users;
    } catch (error) {
        console.error("Error fetching users:", error);
        throw new Error("Failed to fetch users");
    }
}