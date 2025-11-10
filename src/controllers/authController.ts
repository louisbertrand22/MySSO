import { Request, Response } from 'express';
import { JwtService } from '../services/jwtService';
import { config } from '../config/env';
import { AuthService } from '../services/authService';
import { AuthenticatedRequest } from '../middleware/auth.middleware';
import { SecurityLogger } from '../services/securityLogger';

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
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
      claims_supported: ['sub', 'name', 'email', 'email_verified'],
    };

    res.json(configuration);
  }

  /**
   * GET /authorize
   * OAuth2 authorization endpoint (placeholder)
   */
  static async authorize(_req: Request, res: Response): Promise<void> {
    // TODO: Implement authorization flow
    res.status(501).json({
      error: 'not_implemented',
      error_description: 'Authorization endpoint not yet implemented',
    });
  }

  /**
   * POST /token
   * OAuth2 token endpoint (placeholder)
   */
  static async token(_req: Request, res: Response): Promise<void> {
    // TODO: Implement token exchange
    res.status(501).json({
      error: 'not_implemented',
      error_description: 'Token endpoint not yet implemented',
    });
  }

  /**
   * GET /userinfo
   * OpenID Connect UserInfo endpoint
   * Returns information about the authenticated user
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

      // Return userinfo in OpenID Connect format
      res.json({
        sub: user.id,
        email: user.email,
        email_verified: true,
      });
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
