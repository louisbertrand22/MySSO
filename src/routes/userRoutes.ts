import { Router } from 'express';
import { UserController } from '../controllers/userController';
import { authMiddleware } from '../middleware/auth.middleware';

const router = Router();

/**
 * @swagger
 * /user/consents:
 *   get:
 *     tags: [User]
 *     summary: List all consents granted by the authenticated user
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of consents
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   clientId:
 *                     type: string
 *                   clientName:
 *                     type: string
 *                   scopes:
 *                     type: array
 *                     items:
 *                       type: string
 *                   createdAt:
 *                     type: string
 *                     format: date-time
 *       401:
 *         description: Unauthorized
 */
router.get('/user/consents', authMiddleware, UserController.getConsents);

/**
 * @swagger
 * /user/consents/{clientId}:
 *   delete:
 *     tags: [User]
 *     summary: Revoke consent for a specific client
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: clientId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Consent revoked
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: Consent not found
 */
router.delete('/user/consents/:clientId', authMiddleware, UserController.revokeConsent);

/**
 * @swagger
 * /user/account:
 *   delete:
 *     tags: [User]
 *     summary: Delete own account (GDPR — full cascade)
 *     description: Permanently deletes the authenticated user's account, sessions, tokens, auth codes, and consents.
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Account deleted
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Server error
 */
router.delete('/user/account', authMiddleware, UserController.deleteAccount);

/**
 * @swagger
 * /user/profile:
 *   patch:
 *     tags: [User]
 *     summary: Update user profile (username)
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *     responses:
 *       200:
 *         description: Profile updated
 *       400:
 *         description: Validation error
 *       401:
 *         description: Unauthorized
 */
router.patch('/user/profile', authMiddleware, UserController.updateProfile);

/**
 * @swagger
 * /user/password:
 *   patch:
 *     tags: [User]
 *     summary: Change password
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [currentPassword, newPassword]
 *             properties:
 *               currentPassword:
 *                 type: string
 *               newPassword:
 *                 type: string
 *     responses:
 *       200:
 *         description: Password changed
 *       401:
 *         description: Current password incorrect
 *       400:
 *         description: Validation error
 */
router.patch('/user/password', authMiddleware, UserController.changePassword);

/**
 * @swagger
 * /user/sessions:
 *   get:
 *     tags: [User]
 *     summary: List active sessions for the authenticated user
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of active sessions
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 sessions:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: string
 *                       ip:
 *                         type: string
 *                       userAgent:
 *                         type: string
 *                       createdAt:
 *                         type: string
 *                         format: date-time
 *                       lastSeenAt:
 *                         type: string
 *                         format: date-time
 *                       expiresAt:
 *                         type: string
 *                         format: date-time
 *       401:
 *         description: Unauthorized
 */
router.get('/user/sessions', authMiddleware, UserController.getSessions);

/**
 * @swagger
 * /user/sessions/{sessionId}:
 *   delete:
 *     tags: [User]
 *     summary: Revoke a specific session
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: sessionId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Session revoked
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: Session not found
 */
router.delete('/user/sessions/:sessionId', authMiddleware, UserController.revokeSession);

export default router;
