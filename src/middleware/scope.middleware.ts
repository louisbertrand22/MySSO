import { Response, NextFunction } from 'express';
import { AuthenticatedRequest } from './auth.middleware';

/**
 * Scope Middleware
 * Validates that the authenticated user has the required scope(s)
 */

/**
 * Create a middleware that requires a specific scope
 * @param requiredScope - The scope that is required
 * @returns Express middleware function
 */
export function requireScope(requiredScope: string) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    // Check if user is authenticated
    if (!req.user) {
      res.status(401).json({
        error: 'unauthorized',
        message: 'Authentication required',
      });
      return;
    }

    // Get scopes from the JWT token
    const userScopes: string[] = req.user.scopes || [];
    
    // Also check the 'scope' claim (space-separated string format)
    if (!userScopes.length && req.user.scope) {
      const scopeString = req.user.scope as string;
      userScopes.push(...scopeString.split(' '));
    }

    // Check if user has the required scope
    if (!userScopes.includes(requiredScope)) {
      res.status(403).json({
        error: 'insufficient_scope',
        message: `This endpoint requires the '${requiredScope}' scope`,
        required_scope: requiredScope,
        user_scopes: userScopes,
      });
      return;
    }

    // User has the required scope, continue
    next();
  };
}

/**
 * Create a middleware that requires ANY of the specified scopes
 * @param requiredScopes - Array of scopes where at least one is required
 * @returns Express middleware function
 */
export function requireAnyScope(...requiredScopes: string[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    // Check if user is authenticated
    if (!req.user) {
      res.status(401).json({
        error: 'unauthorized',
        message: 'Authentication required',
      });
      return;
    }

    // Get scopes from the JWT token
    const userScopes: string[] = req.user.scopes || [];
    
    // Also check the 'scope' claim (space-separated string format)
    if (!userScopes.length && req.user.scope) {
      const scopeString = req.user.scope as string;
      userScopes.push(...scopeString.split(' '));
    }

    // Check if user has at least one of the required scopes
    const hasRequiredScope = requiredScopes.some((scope) =>
      userScopes.includes(scope)
    );

    if (!hasRequiredScope) {
      res.status(403).json({
        error: 'insufficient_scope',
        message: `This endpoint requires one of the following scopes: ${requiredScopes.join(', ')}`,
        required_scopes: requiredScopes,
        user_scopes: userScopes,
      });
      return;
    }

    // User has at least one required scope, continue
    next();
  };
}

/**
 * Create a middleware that requires ALL of the specified scopes
 * @param requiredScopes - Array of scopes where all are required
 * @returns Express middleware function
 */
export function requireAllScopes(...requiredScopes: string[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    // Check if user is authenticated
    if (!req.user) {
      res.status(401).json({
        error: 'unauthorized',
        message: 'Authentication required',
      });
      return;
    }

    // Get scopes from the JWT token
    const userScopes: string[] = req.user.scopes || [];
    
    // Also check the 'scope' claim (space-separated string format)
    if (!userScopes.length && req.user.scope) {
      const scopeString = req.user.scope as string;
      userScopes.push(...scopeString.split(' '));
    }

    // Check if user has all required scopes
    const hasAllScopes = requiredScopes.every((scope) =>
      userScopes.includes(scope)
    );

    if (!hasAllScopes) {
      const missingScopes = requiredScopes.filter(
        (scope) => !userScopes.includes(scope)
      );

      res.status(403).json({
        error: 'insufficient_scope',
        message: `This endpoint requires all of the following scopes: ${requiredScopes.join(', ')}`,
        required_scopes: requiredScopes,
        missing_scopes: missingScopes,
        user_scopes: userScopes,
      });
      return;
    }

    // User has all required scopes, continue
    next();
  };
}
