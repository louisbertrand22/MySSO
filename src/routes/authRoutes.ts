import { Router } from 'express';
import { AuthController } from '../controllers/authController';

const router = Router();

/**
 * OpenID Connect Discovery
 * GET /.well-known/openid-configuration
 */
router.get('/.well-known/openid-configuration', AuthController.getOpenIdConfiguration);

/**
 * OAuth2/OIDC Endpoints
 */

// Authorization endpoint
router.get('/authorize', AuthController.authorize);

// Token endpoint
router.post('/token', AuthController.token);

// UserInfo endpoint
router.get('/userinfo', AuthController.userinfo);

// JWKS endpoint
router.get('/jwks.json', AuthController.jwks);

export default router;
