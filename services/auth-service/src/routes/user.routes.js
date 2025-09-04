import { Router } from "express";
import { userValidationRules } from "../middlewares/user.validations.js";
import { createUserController, followUserController, getallUserController, getUserController, loginUserController, logoutUserController, unfollowUserController, verifyPuzzle, verifyUserByOtpController } from "../controllers/user.controller.js";
import '../utils/Authpassport.js';
import jwt from 'jsonwebtoken';
import config from "../config/config.js";
import { authenticateUsers } from "../middlewares/auth.middleware.js";



const router = Router();

router.post(
    '/register',
    userValidationRules,
    createUserController
);

router.post(
    '/login',
    loginUserController
);

router.post(
    '/verify-account',
    authenticateUsers,
    verifyUserByOtpController
);

router.get(
    '/profile',
    authenticateUsers,
    getUserController
);

router.get(
    '/logout',
    authenticateUsers,
    logoutUserController
);

router.get(
    '/get-all-users',
    authenticateUsers,
    getallUserController
)

// router.get(
//     '/google-auth',
//     passport.authenticate('google', { scope: ['profile', 'email'] })
// )

router.get(
    '/follow',
    authenticateUsers,
    followUserController
)

router.get(
    '/unfollow',
    authenticateUsers,
    unfollowUserController
)

router.get(
    '/verify-puzzle',
    authenticateUsers,
    verifyPuzzle
)

export default router;