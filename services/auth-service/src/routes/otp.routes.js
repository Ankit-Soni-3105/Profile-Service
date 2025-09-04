import { Router } from 'express';
import { sendOtpByPhoneController, verifyPhoneOtpController } from '../controllers/user.controller.js';
// import { authenticateUser } from '../middlewares/auth.middleware.js';

const router = Router();

router.post(
    '/send-otp',
    sendOtpByPhoneController
);
router.post(
    '/verify-otp',
    verifyPhoneOtpController
);

export default router;
