import { Router } from "express";
import authProfileMiddleware from "../middlewares/profile.middleware.js";

import { uploadPhoto } from "../controllers/photoUpload.controller.js";
import { cropPhoto } from "../controllers/cropping.controller.js";
import { optimizePhoto } from "../controllers/optimization.controller.js";
import { removeBackground } from "../controllers/backgroundRemoval.controller.js";
import { adjustQuality } from "../controllers/quality.controller.js";
import { setVisibility } from "../controllers/visibility.controller.js";
import { getHistory } from "../controllers/history.controller.js";
import { uploadTempPhoto } from "../controllers/tempPhoto.ontroller.js";
import { setAccessibility } from "../controllers/accessibility.controller.js";
import { downloadPhoto } from "../controllers/download.controller.js";



const router = Router();

router.post(
    '/photo/upload',
    authProfileMiddleware,
    uploadMiddleware,
    uploadPhoto
);

// Photo Cropping Routes
router.put(
    '/photo/crop',
    authProfileMiddleware,
    cropPhoto
);

// Photo Optimization Routes
router.put(
    '/photo/optimize',
    authProfileMiddleware,
    optimizePhoto
);

// Photo Background Removal Routes
router.put(
    '/photo/remove-background',
    authProfileMiddleware,
    removeBackground
);

// Photo Quality Adjustment Routes
router.put(
    '/photo/quality',
    authProfileMiddleware,
    adjustQuality
);

// Photo Visibility Routes
router.put(
    '/photo/visibility',
    authProfileMiddleware,
    setVisibility
);

// Photo History Routes
router.get(
    '/photo/:photoId/history',
    authProfileMiddleware,
    getHistory
);

// Temp Photo Upload Routes
router.post(
    '/photo/temp-upload',
    authProfileMiddleware,
    uploadMiddleware,
    uploadTempPhoto
);

// Photo Accessibility Routes
router.put(
    '/photo/accessibility',
    authProfileMiddleware,
    setAccessibility
);

// Photo Download Routes
router.get(
    '/photo/:photoId',
    authProfileMiddleware,
    downloadPhoto
);

export default router;