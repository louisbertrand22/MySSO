import { Router } from 'express';
import { AuthController } from '../controllers/authController';
import { authMiddleware } from '../middleware/auth.middleware';

const router = Router();

/**
 * @swagger
 * /auth/register:
 *   post:
 *     tags: [Auth]
 *     summary: Register a new user
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, password]
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *                 format: password
 *               username:
 *                 type: string
 *     responses:
 *       201:
 *         description: User created
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/TokenResponse'
 *       400:
 *         description: Validation error or email already taken
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
router.post('/auth/register', AuthController.register);

/**
 * @swagger
 * /auth/login:
 *   post:
 *     tags: [Auth]
 *     summary: Login with email and password
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, password]
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *               password:
 *                 type: string
 *                 format: password
 *     responses:
 *       200:
 *         description: Login successful
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/TokenResponse'
 *       401:
 *         description: Invalid credentials
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       403:
 *         description: Account disabled
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
router.post('/auth/login', AuthController.login);

/**
 * @swagger
 * /auth/refresh:
 *   post:
 *     tags: [Auth]
 *     summary: Refresh access token using a refresh token
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               refresh_token:
 *                 type: string
 *     responses:
 *       200:
 *         description: New token pair issued
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/TokenResponse'
 *       401:
 *         description: Invalid or expired refresh token
 */
router.post('/auth/refresh', AuthController.refresh);

/**
 * @swagger
 * /auth/logout:
 *   post:
 *     tags: [Auth]
 *     summary: Logout and revoke session/tokens
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Logged out successfully
 */
router.post('/auth/logout', AuthController.logout);

/**
 * @swagger
 * /.well-known/openid-configuration:
 *   get:
 *     tags: [OAuth2/OIDC]
 *     summary: OpenID Connect discovery document
 *     responses:
 *       200:
 *         description: OIDC provider metadata
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 */
router.get('/.well-known/openid-configuration', AuthController.getOpenIdConfiguration);

/**
 * @swagger
 * /authorize:
 *   get:
 *     tags: [OAuth2/OIDC]
 *     summary: OAuth2 authorization endpoint
 *     parameters:
 *       - in: query
 *         name: response_type
 *         required: true
 *         schema:
 *           type: string
 *           enum: [code]
 *       - in: query
 *         name: client_id
 *         required: true
 *         schema:
 *           type: string
 *       - in: query
 *         name: redirect_uri
 *         required: true
 *         schema:
 *           type: string
 *       - in: query
 *         name: scope
 *         schema:
 *           type: string
 *           example: openid profile email
 *       - in: query
 *         name: state
 *         schema:
 *           type: string
 *       - in: query
 *         name: nonce
 *         schema:
 *           type: string
 *       - in: query
 *         name: code_challenge
 *         schema:
 *           type: string
 *       - in: query
 *         name: code_challenge_method
 *         schema:
 *           type: string
 *           enum: [plain, S256]
 *     responses:
 *       302:
 *         description: Redirect to login or consent screen
 */
router.get('/login', AuthController.authorize);
router.get('/authorize', AuthController.authorize);

/**
 * @swagger
 * /consent:
 *   get:
 *     tags: [OAuth2/OIDC]
 *     summary: Consent screen (protected — requires active session)
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Consent page rendered
 *       401:
 *         description: Not authenticated
 */
router.get('/consent', authMiddleware, AuthController.consent);

/**
 * @swagger
 * /auth/authorize:
 *   post:
 *     tags: [OAuth2/OIDC]
 *     summary: Submit consent decision
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [approved]
 *             properties:
 *               approved:
 *                 type: boolean
 *               scopes:
 *                 type: array
 *                 items:
 *                   type: string
 *     responses:
 *       302:
 *         description: Redirect to client redirect_uri with code or error
 */
router.post('/auth/authorize', authMiddleware, AuthController.handleConsent);

/**
 * @swagger
 * /token:
 *   post:
 *     tags: [OAuth2/OIDC]
 *     summary: Token endpoint — exchange authorization code for tokens
 *     requestBody:
 *       required: true
 *       content:
 *         application/x-www-form-urlencoded:
 *           schema:
 *             type: object
 *             required: [grant_type, client_id, redirect_uri]
 *             properties:
 *               grant_type:
 *                 type: string
 *                 enum: [authorization_code, refresh_token]
 *               code:
 *                 type: string
 *               redirect_uri:
 *                 type: string
 *               client_id:
 *                 type: string
 *               client_secret:
 *                 type: string
 *               code_verifier:
 *                 type: string
 *               refresh_token:
 *                 type: string
 *     responses:
 *       200:
 *         description: Token response
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/TokenResponse'
 *       400:
 *         description: Invalid request
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
router.post('/token', AuthController.token);

/**
 * @swagger
 * /userinfo:
 *   get:
 *     tags: [OAuth2/OIDC]
 *     summary: UserInfo endpoint — returns claims for the authenticated user
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User claims
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 sub:
 *                   type: string
 *                 email:
 *                   type: string
 *                 name:
 *                   type: string
 *                 preferred_username:
 *                   type: string
 *       401:
 *         description: Unauthorized
 */
router.get('/userinfo', authMiddleware, AuthController.userinfo);

/**
 * @swagger
 * /jwks.json:
 *   get:
 *     tags: [OAuth2/OIDC]
 *     summary: JSON Web Key Set (public keys for JWT verification)
 *     responses:
 *       200:
 *         description: JWKS document
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 keys:
 *                   type: array
 *                   items:
 *                     type: object
 */
router.get('/jwks.json', AuthController.jwks);

export default router;
