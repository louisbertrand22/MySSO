import { Response } from 'express';
import { AuthenticatedRequest } from '../middleware/auth.middleware';
import { AuthService } from '../services/authService';
import { ScopeService } from '../services/scopeService';

/**
 * Admin Controller
 * Handles administrative endpoints that require special scopes
 */
export class AdminController {
  /**
   * GET /admin/dashboard
   * Admin dashboard endpoint - requires 'admin' scope
   */
  static async dashboard(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          error: 'unauthorized',
          message: 'Authentication required',
        });
        return;
      }

      // Get some admin statistics
      const prisma = AuthService.getPrisma();
      
      const [userCount, clientCount, consentCount] = await Promise.all([
        prisma.user.count(),
        prisma.client.count(),
        prisma.userConsent.count(),
      ]);

      res.json({
        message: 'Admin dashboard access granted',
        user: {
          id: req.user.sub,
          email: req.user.email,
          scopes: req.user.scopes || [],
        },
        statistics: {
          totalUsers: userCount,
          totalClients: clientCount,
          totalConsents: consentCount,
        },
      });
    } catch (error) {
      console.error('Admin dashboard error:', error);
      res.status(500).json({
        error: 'server_error',
        message: 'Failed to load admin dashboard',
      });
    }
  }

  /**
   * GET /admin/users
   * List all users - requires 'read:users' scope
   */
  static async listUsers(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        res.status(401).json({
          error: 'unauthorized',
          message: 'Authentication required',
        });
        return;
      }

      const prisma = AuthService.getPrisma();
      const users = await prisma.user.findMany({
        select: {
          id: true,
          email: true,
          createdAt: true,
        },
        orderBy: {
          createdAt: 'desc',
        },
      });

      res.json({
        users,
        total: users.length,
      });
    } catch (error) {
      console.error('List users error:', error);
      res.status(500).json({
        error: 'server_error',
        message: 'Failed to list users',
      });
    }
  }

  /**
   * GET /admin/scopes
   * List all available scopes - requires 'admin' scope
   */
  static async listScopes(_req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const scopes = await ScopeService.getAllScopes();

      res.json({
        scopes,
        total: scopes.length,
      });
    } catch (error) {
      console.error('List scopes error:', error);
      res.status(500).json({
        error: 'server_error',
        message: 'Failed to list scopes',
      });
    }
  }

  /**
   * GET /admin/clients
   * List all OAuth2 clients - requires 'read:clients' scope
   */
  static async listClients(_req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const prisma = AuthService.getPrisma();
      const clients = await prisma.client.findMany({
        select: {
          id: true,
          name: true,
          clientId: true,
          redirectUris: true,
          createdAt: true,
          updatedAt: true,
        },
        orderBy: {
          createdAt: 'desc',
        },
      });

      res.json({
        clients,
        total: clients.length,
      });
    } catch (error) {
      console.error('List clients error:', error);
      res.status(500).json({
        error: 'server_error',
        message: 'Failed to list clients',
      });
    }
  }
}
