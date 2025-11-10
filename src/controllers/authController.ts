import { Request, Response } from 'express';
import { JwtService } from '../services/jwtService';
import { config } from '../config/env';
import { AuthService } from '../services/authService';

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

      // Generate tokens with user email in payload
      const accessToken = JwtService.sign({ 
        sub: user.id, 
        email: user.email 
      }, { expiresIn: "15m" });
      
      const refreshToken = JwtService.sign({ 
        sub: user.id, 
        type: "refresh" 
      }, { expiresIn: "7d" });

      await prisma.refreshToken.create({ 
        data: { 
          userId: user.id, 
          token: refreshToken, 
          expiresAt: new Date(Date.now() + 7 * 24 * 3600 * 1000) 
        } 
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
      const { refreshToken } = req.body;

      if (!refreshToken) {
        res.status(400).json({ error: "Refresh token is required" });
        return;
      }

      const prisma = AuthService.getPrisma();
      const stored = await prisma.refreshToken.findUnique({ 
        where: { token: refreshToken },
        include: { user: true }
      });

      if (!stored) {
        res.status(403).json({ error: "Invalid refresh token" });
        return;
      }

      // Check if token is expired
      if (stored.expiresAt < new Date()) {
        await prisma.refreshToken.delete({ where: { token: refreshToken } });
        res.status(403).json({ error: "Refresh token expired" });
        return;
      }

      // Generate new access token with email
      const newAccessToken = JwtService.sign({ 
        sub: stored.userId,
        email: stored.user.email
      }, { expiresIn: "15m" });
      
      res.json({ accessToken: newAccessToken });
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
   * Logout and invalidate refresh token
   */
  static async logout(req: Request, res: Response): Promise<void> {
    try {
      const { refreshToken } = req.body;

      if (!refreshToken) {
        res.status(400).json({ error: "Refresh token is required" });
        return;
      }

      const prisma = AuthService.getPrisma();
      await prisma.refreshToken.delete({ 
        where: { token: refreshToken } 
      }).catch(() => {
        // Ignore error if token doesn't exist
      });

      res.json({ message: "Logged out" });
    } catch (error) {
      console.error('Logout error:', error);
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
   * OpenID Connect UserInfo endpoint (placeholder)
   */
  static async userinfo(_req: Request, res: Response): Promise<void> {
    // TODO: Implement userinfo endpoint
    res.status(501).json({
      error: 'not_implemented',
      error_description: 'UserInfo endpoint not yet implemented',
    });
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
