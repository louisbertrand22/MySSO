import { Router } from 'express';
import { AuthController } from '../controllers/authController';
import { authMiddleware } from '../middleware/auth.middleware';

const router = Router();

/**
 * API Auth Endpoints
 */

// Register endpoint
router.post('/auth/register', AuthController.register);

// Login endpoint
router.post('/auth/login', AuthController.login);

// Refresh token endpoint
router.post('/auth/refresh', AuthController.refresh);

// Logout endpoint
router.post('/auth/logout', AuthController.logout);

/**
 * OpenID Connect Discovery
 * GET /.well-known/openid-configuration
 */
router.get('/.well-known/openid-configuration', AuthController.getOpenIdConfiguration);

/**
 * OAuth2/OIDC Endpoints
 */

// Login endpoint for OAuth2 flow (same as authorize)
// GET /login?redirect_uri=...
router.get('/login', AuthController.authorize);

// Authorization endpoint
router.get('/authorize', AuthController.authorize);

// Consent screen endpoint (protected)
router.get('/consent', authMiddleware, AuthController.consent);

// Handle consent decision (protected)
router.post('/auth/authorize', authMiddleware, AuthController.handleConsent);

// Token endpoint
router.post('/token', AuthController.token);

// UserInfo endpoint (protected)
router.get('/userinfo', authMiddleware, AuthController.userinfo);

// JWKS endpoint
router.get('/jwks.json', AuthController.jwks);

export default router;
