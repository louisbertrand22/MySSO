import { Request, Response, NextFunction } from 'express';
import { JwtService } from '../services/jwtService';

/**
 * Extended Request interface to include user information
 */
export interface AuthenticatedRequest extends Request {
  user?: {
    sub: string;
    email?: string;
    [key: string]: any;
  };
}

/**
 * JWT Authentication Middleware
 * Verifies the JWT token from the Authorization header
 * and attaches the decoded user information to the request
 */
export function authMiddleware(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): void {
  try {
    // Get the Authorization header
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      res.status(401).json({
        error: 'unauthorized',
        message: 'No authorization header provided',
      });
      return;
    }

    // Check if it's a Bearer token
    if (!authHeader.startsWith('Bearer ')) {
      res.status(401).json({
        error: 'unauthorized',
        message: 'Invalid authorization header format. Expected: Bearer <token>',
      });
      return;
    }

    // Extract the token
    const token = authHeader.substring(7); // Remove 'Bearer ' prefix

    if (!token) {
      res.status(401).json({
        error: 'unauthorized',
        message: 'No token provided',
      });
      return;
    }

    // Verify the token
    const decoded = JwtService.verify(token);

    // Attach user information to the request
    req.user = decoded;

    // Continue to the next middleware/route handler
    next();
  } catch (error) {
    // Handle JWT verification errors
    if (error instanceof Error) {
      if (error.name === 'TokenExpiredError') {
        res.status(401).json({
          error: 'token_expired',
          message: 'Token has expired',
        });
        return;
      }

      if (error.name === 'JsonWebTokenError') {
        res.status(401).json({
          error: 'invalid_token',
          message: 'Invalid token',
        });
        return;
      }

      if (error.name === 'NotBeforeError') {
        res.status(401).json({
          error: 'token_not_active',
          message: 'Token not active yet',
        });
        return;
      }
    }

    // Generic error
    res.status(401).json({
      error: 'unauthorized',
      message: 'Authentication failed',
    });
  }
}

/**
 * Optional authentication middleware
 * Similar to authMiddleware but does not fail if no token is provided
 * Useful for endpoints that work with or without authentication
 */
export function optionalAuthMiddleware(
  req: AuthenticatedRequest,
  _res: Response,
  next: NextFunction
): void {
  try {
    const authHeader = req.headers.authorization;

    // If no auth header, just continue without attaching user
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      next();
      return;
    }

    const token = authHeader.substring(7);

    if (token) {
      try {
        const decoded = JwtService.verify(token);
        req.user = decoded;
      } catch (error) {
        // Silently ignore verification errors for optional auth
        // The endpoint can check if req.user exists to determine auth status
      }
    }

    next();
  } catch (error) {
    // Even if there's an error, continue without authentication
    next();
  }
}
