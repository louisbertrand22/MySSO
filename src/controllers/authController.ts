import { Request, Response } from 'express';
import { JwtService } from '../services/jwtService';
import { config } from '../config/env';
import { AuthService } from '../services/authService';
import { AuthenticatedRequest } from '../middleware/auth.middleware';
import { SecurityLogger } from '../services/securityLogger';
import { AuthCodeService } from '../services/authCodeService';
import { ConsentService } from '../services/consentService';
import { ClientService } from '../services/clientService';
import { ScopeService } from '../services/scopeService';

/**
 * Auth Controller
 * Handles OAuth2/OpenID Connect authentication endpoints and API auth routes
 */
export class AuthController {
  /**
   * POST /auth/register
   * Register a new user
   */
  static async register(req: Request, res: Response): Promise<void> {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        res.status(400).json({ error: "Email and password are required" });
        return;
      }

      const prisma = AuthService.getPrisma();
      const existing = await prisma.user.findUnique({ where: { email } });
      
      if (existing) {
        res.status(400).json({ error: "User already exists" });
        return;
      }

      const passwordHash = await AuthService.hashPassword(password);
      const user = await prisma.user.create({ 
        data: { email, passwordHash },
        select: { id: true, email: true, createdAt: true }
      });

      res.json({ user });
    } catch (error) {
      console.error('Register error:', error);
      res.status(500).json({ 
        error: "Internal server error",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  }

  /**
   * POST /auth/login
   * Login and get access and refresh tokens
   */
  static async login(req: Request, res: Response): Promise<void> {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        res.status(400).json({ error: "Email and password are required" });
        return;
      }

      const prisma = AuthService.getPrisma();
      const user = await prisma.user.findUnique({ where: { email } });

      if (!user || !(await AuthService.verifyPassword(password, user.passwordHash))) {
        res.status(401).json({ error: "Invalid credentials" });
        return;
      }

      // Generate tokens using the new generateTokens service
      const { accessToken, refreshToken } = await AuthService.generateTokens(
        user.id,
        user.email
      );

      // Set refresh token as HttpOnly cookie
      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
      });

      res.json({ accessToken, refreshToken });
    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({ 
        error: "Internal server error",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  }

  /**
   * POST /auth/refresh
   * Refresh access token using refresh token
   */
  static async refresh(req: Request, res: Response): Promise<void> {
    try {
      // Get refresh token from body or cookie
      const refreshToken = req.body.refreshToken || req.cookies.refreshToken;

      if (!refreshToken) {
        res.status(400).json({ error: "Refresh token is required" });
        return;
      }

      // Verify the JWT signature of the refresh token
      let decoded: any;
      try {
        decoded = JwtService.verify(refreshToken);
      } catch (error) {
        if (error instanceof Error) {
          if (error.name === 'TokenExpiredError') {
            res.status(403).json({ error: "Refresh token expired" });
            return;
          }
          if (error.name === 'JsonWebTokenError') {
            res.status(403).json({ error: "Invalid refresh token" });
            return;
          }
        }
        res.status(403).json({ error: "Invalid refresh token" });
        return;
      }

      // Verify it's a refresh token type
      if (decoded.type !== "refresh") {
        res.status(403).json({ error: "Invalid token type" });
        return;
      }

      const prisma = AuthService.getPrisma();
      
      // Check if refresh token exists in database
      const stored = await prisma.refreshToken.findUnique({ 
        where: { token: refreshToken },
        include: { user: true }
      });

      if (!stored) {
        res.status(403).json({ error: "Invalid refresh token" });
        return;
      }

      // Check if token is expired (database expiration check)
      if (stored.expiresAt < new Date()) {
        await prisma.refreshToken.delete({ where: { token: refreshToken } });
        res.status(403).json({ error: "Refresh token expired" });
        return;
      }

      // Check if user still exists (handle deleted user case)
      if (!stored.user) {
        await prisma.refreshToken.delete({ where: { token: refreshToken } });
        res.status(403).json({ error: "User not found" });
        return;
      }

      // Token rotation: Delete the old refresh token
      await prisma.refreshToken.delete({ where: { token: refreshToken } });

      // Generate new token pair
      const { accessToken: newAccessToken, refreshToken: newRefreshToken } = 
        await AuthService.generateTokens(stored.userId, stored.user.email);
      
      // Set new refresh token as HttpOnly cookie
      res.cookie('refreshToken', newRefreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
      });

      res.json({ 
        accessToken: newAccessToken, 
        refreshToken: newRefreshToken 
      });
    } catch (error) {
      console.error('Refresh error:', error);
      res.status(500).json({ 
        error: "Internal server error",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  }

  /**
   * POST /auth/logout
   * Logout and invalidate refresh token(s) and sessions
   */
  static async logout(req: Request, res: Response): Promise<void> {
    try {
      // Get refresh token from body or cookie
      const refreshToken = req.body.refreshToken || req.cookies.refreshToken;
      const all = req.body.all;

      if (!refreshToken) {
        // Clear cookie even if no token provided
        res.clearCookie('refreshToken');
        res.status(400).json({ error: "Refresh token is required" });
        return;
      }

      const prisma = AuthService.getPrisma();
      
      // Find the refresh token to get the user ID
      const stored = await prisma.refreshToken.findUnique({
        where: { token: refreshToken },
        select: { userId: true }
      });

      if (!stored) {
        // Token doesn't exist, but we'll clear the cookie and consider this a successful logout
        res.clearCookie('refreshToken');
        res.json({ message: "Logged out" });
        return;
      }

      const userId = stored.userId;

      // If 'all' flag is set, delete all refresh tokens and revoke all sessions for this user
      if (all === true) {
        // Delete all refresh tokens for this user
        await prisma.refreshToken.deleteMany({
          where: { userId }
        });

        // Revoke all sessions for this user
        await prisma.session.updateMany({
          where: { 
            userId,
            revokedAt: null // Only revoke sessions that haven't been revoked yet
          },
          data: { 
            revokedAt: new Date() 
          }
        });

        // Clear cookie
        res.clearCookie('refreshToken');

        // Log security event
        SecurityLogger.logLogout(userId, true);
        SecurityLogger.logRevocation(userId, 'all', { 
          reason: 'User logged out from all devices' 
        });

        res.json({ message: "Logged out from all devices" });
        return;
      }

      // Otherwise, just delete the specific refresh token and revoke associated session
      await prisma.refreshToken.delete({ 
        where: { token: refreshToken } 
      }).catch(() => {
        // Ignore error if token doesn't exist
      });

      // Revoke the current session (most recent session for this user)
      // We revoke the most recent non-revoked session
      const sessions = await prisma.session.findMany({
        where: { 
          userId,
          revokedAt: null
        },
        orderBy: { createdAt: 'desc' },
        take: 1
      });

      if (sessions.length > 0) {
        await prisma.session.update({
          where: { id: sessions[0].id },
          data: { revokedAt: new Date() }
        });

        SecurityLogger.logSessionRevocation(userId, sessions[0].id, 'single');
      }

      // Clear cookie
      res.clearCookie('refreshToken');

      // Log security event
      SecurityLogger.logLogout(userId, false);
      SecurityLogger.logRevocation(userId, 'single', { 
        reason: 'User logged out' 
      });

      res.json({ message: "Logged out" });
    } catch (error) {
      console.error('Logout error:', error);
      // Even on error, try to clear the cookie
      res.clearCookie('refreshToken');
      res.status(500).json({ 
        error: "Internal server error",
        message: error instanceof Error ? error.message : "Unknown error"
      });
    }
  }

  /**
   * GET /.well-known/openid-configuration
   * Returns OpenID Connect discovery document
   */
  static async getOpenIdConfiguration(_req: Request, res: Response): Promise<void> {
    const baseUrl = config.jwt.issuer;
    
    const configuration = {
      issuer: baseUrl,
      authorization_endpoint: `${baseUrl}/authorize`,
      token_endpoint: `${baseUrl}/token`,
      userinfo_endpoint: `${baseUrl}/userinfo`,
      jwks_uri: `${baseUrl}/jwks.json`,
      response_types_supported: ['code', 'token', 'id_token'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'],
      scopes_supported: ['openid', 'profile', 'email'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
      claims_supported: ['sub', 'name', 'email', 'email_verified', 'updated_at', 'iat', 'auth_time', 'nonce'],
      code_challenge_methods_supported: ['plain', 'S256'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
    };

    res.json(configuration);
  }

  /**
   * GET /authorize
   * OAuth2 authorization endpoint
   * Redirects to consent screen if user is authenticated
   */
  static async authorize(req: Request, res: Response): Promise<void> {
    try {
      const { redirect_uri, client_id, response_type, scope, state, nonce, code_challenge, code_challenge_method } = req.query;

      // Validate redirect_uri parameter
      if (!redirect_uri || typeof redirect_uri !== 'string') {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing or invalid redirect_uri parameter',
        });
        return;
      }

      // Extract client_id if provided
      const clientId = client_id && typeof client_id === 'string' ? client_id : undefined;

      // Validate redirect_uri is in whitelist
      if (!await AuthCodeService.isRedirectUriAllowed(redirect_uri, clientId)) {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'redirect_uri not allowed for this client',
        });
        return;
      }

      // Extract PKCE parameters
      const codeChallenge = code_challenge && typeof code_challenge === 'string' ? code_challenge : undefined;
      const codeChallengeMethod = code_challenge_method && typeof code_challenge_method === 'string' 
        ? code_challenge_method 
        : 'plain'; // Default to 'plain' if not specified

      // Validate code_challenge_method if provided
      if (codeChallenge && codeChallengeMethod !== 'plain' && codeChallengeMethod !== 'S256') {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'code_challenge_method must be either plain or S256',
        });
        return;
      }

      // Extract nonce for OIDC
      const nonceParam = nonce && typeof nonce === 'string' ? nonce : undefined;

      // Check if user is authenticated via Authorization header
      const authHeader = req.headers.authorization;
      
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        // User not authenticated - return error with instructions
        res.status(401).json({
          error: 'unauthorized',
          error_description: 'User must be authenticated. Please login first and include access token in Authorization header.',
        });
        return;
      }

      // Extract and verify the access token
      const token = authHeader.substring(7);
      let decoded: any;
      
      try {
        decoded = JwtService.verify(token);
      } catch (error) {
        res.status(401).json({
          error: 'unauthorized',
          error_description: 'Invalid or expired access token',
        });
        return;
      }

      // Extract user ID from token
      const userId = decoded.sub;
      if (!userId) {
        res.status(401).json({
          error: 'unauthorized',
          error_description: 'Invalid token: missing user ID',
        });
        return;
      }

      // If no client_id is provided, we can't show a consent screen
      // Generate code immediately for backward compatibility
      if (!clientId) {
        const code = await AuthCodeService.generateAuthCode(
          userId, 
          redirect_uri, 
          clientId,
          nonceParam,
          codeChallenge,
          codeChallengeMethod
        );
        const redirectUrl = new URL(redirect_uri);
        redirectUrl.searchParams.set('code', code);
        if (state && typeof state === 'string') {
          redirectUrl.searchParams.set('state', state);
        }
        res.redirect(redirectUrl.toString());
        return;
      }

      // Check if user has already consented to this client
      const hasConsent = await ConsentService.hasConsent(userId, clientId);

      if (hasConsent) {
        // User has already consented, generate code immediately
        const code = await AuthCodeService.generateAuthCode(
          userId, 
          redirect_uri, 
          clientId,
          nonceParam,
          codeChallenge,
          codeChallengeMethod
        );
        const redirectUrl = new URL(redirect_uri);
        redirectUrl.searchParams.set('code', code);
        if (state && typeof state === 'string') {
          redirectUrl.searchParams.set('state', state);
        }
        res.redirect(redirectUrl.toString());
        return;
      }

      // User hasn't consented yet, redirect to consent screen
      // Build consent URL with query parameters
      const consentUrl = new URL(`${config.jwt.issuer}/consent`);
      consentUrl.searchParams.set('client_id', clientId);
      consentUrl.searchParams.set('redirect_uri', redirect_uri);
      if (response_type && typeof response_type === 'string') {
        consentUrl.searchParams.set('response_type', response_type);
      }
      if (scope && typeof scope === 'string') {
        consentUrl.searchParams.set('scope', scope);
      }
      if (state && typeof state === 'string') {
        consentUrl.searchParams.set('state', state);
      }
      if (nonceParam) {
        consentUrl.searchParams.set('nonce', nonceParam);
      }
      if (codeChallenge) {
        consentUrl.searchParams.set('code_challenge', codeChallenge);
        consentUrl.searchParams.set('code_challenge_method', codeChallengeMethod);
      }

      res.redirect(consentUrl.toString());
    } catch (error) {
      console.error('Authorization error:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Failed to process authorization request',
      });
    }
  }

  /**
   * GET /consent
   * Display consent screen with client information
   */
  static async consent(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const { client_id, redirect_uri, scope, state } = req.query;

      // Validate required parameters
      if (!client_id || typeof client_id !== 'string') {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing or invalid client_id parameter',
        });
        return;
      }

      if (!redirect_uri || typeof redirect_uri !== 'string') {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing or invalid redirect_uri parameter',
        });
        return;
      }

      // User must be authenticated (via middleware)
      if (!req.user) {
        res.status(401).json({
          error: 'unauthorized',
          error_description: 'User must be authenticated',
        });
        return;
      }

      // Get client details
      const client = await ClientService.getClient(client_id);
      if (!client) {
        res.status(400).json({
          error: 'invalid_client',
          error_description: 'Client not found',
        });
        return;
      }

      // Validate redirect_uri matches client's registered URIs
      if (!client.redirectUris.includes(redirect_uri)) {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'redirect_uri not registered for this client',
        });
        return;
      }

      // Parse requested scopes
      const requestedScopes = scope && typeof scope === 'string' 
        ? scope.split(' ') 
        : ScopeService.getDefaultScopes();

      // Validate scopes against client's allowed scopes
      const clientAllowedScopes = (client as any).allowedScopes || ScopeService.getDefaultScopes();
      const validScopes = ScopeService.validateClientScopes(requestedScopes, clientAllowedScopes);

      // Get scope details for display
      const scopeDetails = await ScopeService.getScopeDetails(validScopes);

      // Return consent screen data
      res.json({
        client: {
          id: client.clientId,
          name: client.name,
        },
        scopes: scopeDetails,
        redirect_uri,
        state: state && typeof state === 'string' ? state : undefined,
      });
    } catch (error) {
      console.error('Consent screen error:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Failed to load consent screen',
      });
    }
  }

  /**
   * POST /auth/authorize
   * Handle user consent decision (approve or deny)
   */
  static async handleConsent(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const { client_id, redirect_uri, approved, scope, state, nonce, code_challenge, code_challenge_method } = req.body;

      // Validate required parameters
      if (!client_id || typeof client_id !== 'string') {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing or invalid client_id parameter',
        });
        return;
      }

      if (!redirect_uri || typeof redirect_uri !== 'string') {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing or invalid redirect_uri parameter',
        });
        return;
      }

      if (typeof approved !== 'boolean') {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing or invalid approved parameter',
        });
        return;
      }

      // User must be authenticated (via middleware)
      if (!req.user) {
        res.status(401).json({
          error: 'unauthorized',
          error_description: 'User must be authenticated',
        });
        return;
      }

      const userId = req.user.sub;

      // Validate client exists
      const client = await ClientService.getClient(client_id);
      if (!client) {
        res.status(400).json({
          error: 'invalid_client',
          error_description: 'Client not found',
        });
        return;
      }

      // Validate redirect_uri
      if (!client.redirectUris.includes(redirect_uri)) {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'redirect_uri not registered for this client',
        });
        return;
      }

      const redirectUrl = new URL(redirect_uri);

      // Handle denial
      if (!approved) {
        redirectUrl.searchParams.set('error', 'access_denied');
        redirectUrl.searchParams.set('error_description', 'User denied authorization');
        if (state && typeof state === 'string') {
          redirectUrl.searchParams.set('state', state);
        }
        res.redirect(redirectUrl.toString());
        return;
      }

      // Handle approval
      // Parse scopes
      const requestedScopes = Array.isArray(scope) ? scope : 
                     typeof scope === 'string' ? scope.split(' ') : 
                     ScopeService.getDefaultScopes();

      // Validate scopes against client's allowed scopes
      const clientAllowedScopes = (client as any).allowedScopes || ScopeService.getDefaultScopes();
      const validScopes = ScopeService.validateClientScopes(requestedScopes, clientAllowedScopes);

      // Never grant scopes that are not declared by the client
      if (validScopes.length === 0) {
        res.status(400).json({
          error: 'invalid_scope',
          error_description: 'No valid scopes requested for this client',
        });
        return;
      }

      // Grant consent with validated scopes
      await ConsentService.grantConsent(userId, client_id, validScopes);

      // Extract PKCE and nonce parameters
      const nonceParam = nonce && typeof nonce === 'string' ? nonce : undefined;
      const codeChallenge = code_challenge && typeof code_challenge === 'string' ? code_challenge : undefined;
      const codeChallengeMethod = code_challenge_method && typeof code_challenge_method === 'string' 
        ? code_challenge_method 
        : 'plain';

      // Generate authorization code with PKCE and nonce
      const code = await AuthCodeService.generateAuthCode(
        userId, 
        redirect_uri, 
        client_id,
        nonceParam,
        codeChallenge,
        codeChallengeMethod
      );

      // Redirect with authorization code
      redirectUrl.searchParams.set('code', code);
      if (state && typeof state === 'string') {
        redirectUrl.searchParams.set('state', state);
      }

      res.redirect(redirectUrl.toString());
    } catch (error) {
      console.error('Handle consent error:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Failed to process consent',
      });
    }
  }

  /**
   * POST /token
   * OAuth2 token endpoint
   * Exchanges authorization code for access, refresh, and ID tokens
   */
  static async token(req: Request, res: Response): Promise<void> {
    try {
      const { grant_type, code, redirect_uri, code_verifier, client_id, client_secret } = req.body;

      // Validate grant_type
      if (!grant_type) {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing grant_type parameter',
        });
        return;
      }

      // For authorization code flow
      if (grant_type === 'authorization_code') {
        // Validate required parameters
        if (!code || !redirect_uri) {
          res.status(400).json({
            error: 'invalid_request',
            error_description: 'Missing code or redirect_uri parameter',
          });
          return;
        }

        // Validate and consume the authorization code (with PKCE verification)
        const result = await AuthCodeService.validateAndConsumeAuthCode(
          code, 
          redirect_uri,
          code_verifier // Will be verified if code_challenge was provided
        );

        if (!result) {
          res.status(400).json({
            error: 'invalid_grant',
            error_description: 'Invalid, expired, or already used authorization code, or PKCE verification failed',
          });
          return;
        }

        const { userId, clientId, nonce } = result;

        // Client authentication for confidential clients
        if (clientId && client_secret) {
          // Verify client credentials
          const client = await ClientService.validateClient(clientId, client_secret);
          if (!client) {
            res.status(401).json({
              error: 'invalid_client',
              error_description: 'Invalid client credentials',
            });
            return;
          }
        } else if (clientId && client_id) {
          // Basic validation: ensure client_id matches
          if (client_id !== clientId) {
            res.status(400).json({
              error: 'invalid_request',
              error_description: 'client_id mismatch',
            });
            return;
          }
        }

        // Get user details
        const prisma = AuthService.getPrisma();
        const user = await prisma.user.findUnique({
          where: { id: userId },
          select: { id: true, email: true },
        });

        if (!user) {
          res.status(400).json({
            error: 'invalid_grant',
            error_description: 'User not found',
          });
          return;
        }

        // Get user's consented scopes for this client
        let scopes: string[] = [];
        if (clientId) {
          const consentedScopes = await ConsentService.getConsentScopes(userId, clientId);
          if (consentedScopes) {
            scopes = consentedScopes;
          }
        }

        // Generate access and refresh tokens with scopes
        const { accessToken, refreshToken } = await AuthService.generateTokens(
          user.id,
          user.email,
          scopes.length > 0 ? scopes : undefined
        );

        // Generate ID token if 'openid' scope is present
        let idToken: string | undefined;
        if (scopes.includes('openid')) {
          idToken = JwtService.generateIdToken(
            user.id,
            user.email,
            nonce || undefined,
            clientId || undefined
          );
        }

        // Set refresh token as HttpOnly cookie
        res.cookie('refreshToken', refreshToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });

        // Return tokens in OAuth2/OIDC format
        const response: any = {
          access_token: accessToken,
          token_type: 'Bearer',
          expires_in: 900, // 15 minutes
          refresh_token: refreshToken,
          scope: scopes.join(' '),
        };

        // Add id_token if generated
        if (idToken) {
          response.id_token = idToken;
        }

        res.json(response);
        return;
      }

      // Unsupported grant type
      res.status(400).json({
        error: 'unsupported_grant_type',
        error_description: `Grant type '${grant_type}' is not supported`,
      });
    } catch (error) {
      console.error('Token error:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Failed to exchange authorization code for tokens',
      });
    }
  }

  /**
   * GET /userinfo
   * OpenID Connect UserInfo endpoint
   * Returns information about the authenticated user based on granted scopes
   */
  static async userinfo(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      // The authMiddleware has already verified the token and attached user info
      if (!req.user) {
        res.status(401).json({
          error: 'unauthorized',
          error_description: 'User not authenticated',
        });
        return;
      }

      // Get user details from database
      const prisma = AuthService.getPrisma();
      const user = await prisma.user.findUnique({
        where: { id: req.user.sub },
        select: {
          id: true,
          email: true,
          createdAt: true,
        },
      });

      if (!user) {
        res.status(404).json({
          error: 'not_found',
          error_description: 'User not found',
        });
        return;
      }

      // Extract scopes from the token
      const scopes = req.user.scope ? 
        (Array.isArray(req.user.scope) ? req.user.scope : req.user.scope.split(' ')) : 
        [];

      // Build response based on scopes
      const userInfo: any = {
        sub: user.id, // 'sub' is always returned
      };

      // Add profile claims if 'profile' scope is granted
      if (scopes.includes('profile')) {
        // In a real application, you would have more profile fields
        // For now, we'll add basic info
        userInfo.name = user.email.split('@')[0]; // Simple name derivation
        userInfo.updated_at = Math.floor(user.createdAt.getTime() / 1000);
      }

      // Add email claims if 'email' scope is granted
      if (scopes.includes('email')) {
        userInfo.email = user.email;
        userInfo.email_verified = true;
      }

      res.json(userInfo);
    } catch (error) {
      console.error('UserInfo error:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Failed to retrieve user information',
      });
    }
  }

  /**
   * GET /jwks.json
   * JSON Web Key Set endpoint
   */
  static async jwks(_req: Request, res: Response): Promise<void> {
    try {
      const jwks = JwtService.getPublicJwk();
      res.json(jwks);
    } catch (error) {
      res.status(500).json({
        error: 'server_error',
        error_description: 'Failed to load JWKS',
      });
    }
  }
}
