import { Router } from 'express';
import { UserController } from '../controllers/userController';
import { authMiddleware } from '../middleware/auth.middleware';

const router = Router();

/**
 * User Endpoints
 * All routes require authentication via authMiddleware
 */

// Get all user consents
router.get('/user/consents', authMiddleware, UserController.getConsents);

// Revoke consent for a specific client
router.delete('/user/consents/:clientId', authMiddleware, UserController.revokeConsent);

// Update user profile
router.patch('/user/profile', authMiddleware, UserController.updateProfile);

export default router;
