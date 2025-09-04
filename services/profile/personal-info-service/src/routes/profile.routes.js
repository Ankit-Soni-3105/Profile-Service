import { Router } from "express";

import authProfileMiddleware from "../middlewares/profile.middleware.js";

import { getPersonalInfo, updatePersonalInfo } from "../controllers/personalInfoController.js";
import { createContact } from "../controllers/contactController.js";
import { getLocation } from "../controllers/locationController.js";
import { getTimezone } from "../controllers/timezoneController.js";
import { getProfileUrl } from "../controllers/ProfileUrlController.js";
import { getVanityUrl } from "../controllers/vanityUrlController.js";
import { getWebsite } from "../controllers/websiteController.js";
import { getSocialLinks } from "../controllers/socialLinksController.js";
import { getUpdateHistory } from "../controllers/updateHistoryController.js";

const router = Router();

router.get(
    '/personal/:userId', 
    authProfileMiddleware, 
    getPersonalInfo
);

router.put(
    '/personal/:userId', 
    authProfileMiddleware, 
    updatePersonalInfo
);

// Contact Routes
router.post(
    '/personal/contact', 
    authProfileMiddleware, 
    createContact
);

// Location Routes
router.get(
    '/personal/location/:userId', 
    authProfileMiddleware, 
    getLocation
);

// Timezone Routes
router.get(
    '/personal/timezone/:userId', 
    authProfileMiddleware, 
    getTimezone
);

// Profile URL Routes
router.get(
    '/personal/profileurl/:userId', 
    authProfileMiddleware, 
    getProfileUrl
);

// Vanity URL Routes
router.get(
    '/personal/vanityurl/:userId', 
    authProfileMiddleware, 
    getVanityUrl
);

// Website Routes
router.get(
    '/personal/website/:userId', 
    authProfileMiddleware, 
    getWebsite
);

// Social Links Routes
router.get(
    '/personal/social/:userId', 
    authProfileMiddleware, 
    getSocialLinks
);

// Update History Routes
router.get(
    '/personal/updatehistory/:userId', 
    authProfileMiddleware, 
    getUpdateHistory
);

export default router;