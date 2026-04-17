import { Request, Response } from 'express';
import { AuthenticatedRequest } from '../middleware/auth.middleware';
import { AuthService } from '../services/authService';
import { ClientService } from '../services/clientService';
import { SecurityLogger } from '../services/securityLogger';

// Express v5 types params/query as string | string[]; helpers normalize to string
const sp = (v: string | string[] | undefined): string | undefined =>
  Array.isArray(v) ? v[0] : v;
const param = (v: string | string[]): string =>
  Array.isArray(v) ? v[0] : v;

export class AdminController {
  // ─── Dashboard / Metrics ──────────────────────────────────────────────────

  static async dashboard(_req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const prisma = AuthService.getPrisma();
      const now = new Date();
      const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);

      const [totalUsers, totalClients, totalConsents, activeSessionsCount, recentTokenGrants, consentsByClient] =
        await Promise.all([
          prisma.user.count(),
          prisma.client.count(),
          prisma.userConsent.count(),
          prisma.session.count({ where: { expiresAt: { gt: now }, revokedAt: null } }),
          prisma.auditLog.count({ where: { event: 'TOKEN_GRANT', timestamp: { gte: yesterday } } }),
          prisma.userConsent.groupBy({
            by: ['clientId'],
            _count: { clientId: true },
            orderBy: { _count: { clientId: 'desc' } },
            take: 5,
          }),
        ]);

      const topClientIds = consentsByClient.map((r) => r.clientId);
      const topClients = await prisma.client.findMany({
        where: { clientId: { in: topClientIds } },
        select: { clientId: true, name: true },
      });
      const clientNameMap = Object.fromEntries(topClients.map((c) => [c.clientId, c.name]));

      res.json({
        statistics: {
          totalUsers,
          totalClients,
          totalConsents,
          activeSessions: activeSessionsCount,
          tokenGrantsLast24h: recentTokenGrants,
        },
        topClientsByConsents: consentsByClient.map((r) => ({
          clientId: r.clientId,
          name: clientNameMap[r.clientId] ?? r.clientId,
          consentCount: r._count.clientId,
        })),
      });
    } catch (error) {
      console.error('Admin dashboard error:', error);
      res.status(500).json({ error: 'server_error', message: 'Failed to load dashboard' });
    }
  }

  // ─── Users ────────────────────────────────────────────────────────────────

  static async listUsers(_req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const prisma = AuthService.getPrisma();
      const users = await prisma.user.findMany({
        select: {
          id: true,
          email: true,
          username: true,
          isDisabled: true,
          createdAt: true,
          _count: { select: { sessions: true, consents: true } },
        },
        orderBy: { createdAt: 'desc' },
      });
      res.json({ users, total: users.length });
    } catch (error) {
      console.error('List users error:', error);
      res.status(500).json({ error: 'server_error', message: 'Failed to list users' });
    }
  }

  static async getUser(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const prisma = AuthService.getPrisma();
      const id = param(req.params['id']);
      const user = await prisma.user.findUnique({
        where: { id },
        select: {
          id: true,
          email: true,
          username: true,
          isDisabled: true,
          createdAt: true,
          sessions: {
            select: { id: true, createdAt: true, expiresAt: true, revokedAt: true },
            orderBy: { createdAt: 'desc' },
            take: 10,
          },
          consents: {
            select: {
              id: true,
              clientId: true,
              scopes: true,
              createdAt: true,
              client: { select: { name: true } },
            },
          },
        },
      });
      if (!user) { res.status(404).json({ error: 'not_found', message: 'User not found' }); return; }
      res.json({ user });
    } catch (error) {
      console.error('Get user error:', error);
      res.status(500).json({ error: 'server_error', message: 'Failed to get user' });
    }
  }

  static async updateUser(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const prisma = AuthService.getPrisma();
      const id = param(req.params['id']);
      const { isDisabled } = req.body as { isDisabled?: boolean };

      if (typeof isDisabled !== 'boolean') {
        res.status(400).json({ error: 'invalid_request', message: 'isDisabled must be a boolean' });
        return;
      }

      const user = await prisma.user.update({
        where: { id },
        data: { isDisabled },
        select: { id: true, email: true, isDisabled: true },
      });

      SecurityLogger.logAdminAction(req.user!.sub, isDisabled ? 'DISABLE_USER' : 'ENABLE_USER', id);
      res.json({ user });
    } catch (error) {
      console.error('Update user error:', error);
      res.status(500).json({ error: 'server_error', message: 'Failed to update user' });
    }
  }

  static async deleteUser(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const prisma = AuthService.getPrisma();
      const id = param(req.params['id']);

      const user = await prisma.user.findUnique({ where: { id }, select: { email: true } });
      if (!user) { res.status(404).json({ error: 'not_found', message: 'User not found' }); return; }

      await prisma.user.delete({ where: { id } });
      SecurityLogger.logAdminAction(req.user!.sub, 'DELETE_USER', id, { email: user.email });
      res.json({ message: 'User deleted successfully' });
    } catch (error) {
      console.error('Delete user error:', error);
      res.status(500).json({ error: 'server_error', message: 'Failed to delete user' });
    }
  }

  // ─── Clients ──────────────────────────────────────────────────────────────

  static async listClients(_req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const prisma = AuthService.getPrisma();
      const clients = await prisma.client.findMany({
        select: {
          id: true,
          name: true,
          clientId: true,
          redirectUris: true,
          allowedScopes: true,
          createdAt: true,
          updatedAt: true,
          _count: { select: { consents: true, authCodes: true } },
        },
        orderBy: { createdAt: 'desc' },
      });
      res.json({ clients, total: clients.length });
    } catch (error) {
      console.error('List clients error:', error);
      res.status(500).json({ error: 'server_error', message: 'Failed to list clients' });
    }
  }

  static async createClient(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const { name, redirectUris } = req.body as { name: string; redirectUris: string[] };
      if (!name || typeof name !== 'string') {
        res.status(400).json({ error: 'invalid_request', message: 'name is required' }); return;
      }
      if (!Array.isArray(redirectUris) || redirectUris.length === 0) {
        res.status(400).json({ error: 'invalid_request', message: 'redirectUris must be a non-empty array' }); return;
      }
      const client = await ClientService.registerClient(name, redirectUris);
      SecurityLogger.logAdminAction(req.user!.sub, 'CREATE_CLIENT', client.clientId);
      res.status(201).json({
        client_id: client.clientId,
        client_secret: client.clientSecret,
        client_name: client.name,
        redirect_uris: client.redirectUris,
        message: 'Client created. Store the client_secret securely — it will not be shown again.',
      });
    } catch (error) {
      console.error('Create client error:', error);
      res.status(500).json({ error: 'server_error', message: 'Failed to create client' });
    }
  }

  static async updateClient(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const clientId = param(req.params['clientId']);
      const updates = req.body as { name?: string; redirectUris?: string[]; allowedScopes?: string[] };
      const client = await ClientService.updateClient(clientId, updates);
      if (!client) { res.status(404).json({ error: 'not_found', message: 'Client not found' }); return; }
      SecurityLogger.logAdminAction(req.user!.sub, 'UPDATE_CLIENT', clientId);
      res.json({ client });
    } catch (error) {
      console.error('Update client error:', error);
      res.status(500).json({ error: 'server_error', message: 'Failed to update client' });
    }
  }

  static async rotateClientSecret(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const clientId = param(req.params['clientId']);
      const result = await ClientService.rotateClientSecret(clientId);
      if (!result) { res.status(404).json({ error: 'not_found', message: 'Client not found' }); return; }
      SecurityLogger.logAdminAction(req.user!.sub, 'ROTATE_CLIENT_SECRET', clientId);
      res.json({
        client_id: result.clientId,
        client_secret: result.clientSecret,
        message: 'Secret rotated. Store the new client_secret securely — it will not be shown again.',
      });
    } catch (error) {
      console.error('Rotate secret error:', error);
      res.status(500).json({ error: 'server_error', message: 'Failed to rotate client secret' });
    }
  }

  static async deleteClient(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const clientId = param(req.params['clientId']);
      const deleted = await ClientService.deleteClient(clientId);
      if (!deleted) { res.status(404).json({ error: 'not_found', message: 'Client not found' }); return; }
      SecurityLogger.logAdminAction(req.user!.sub, 'DELETE_CLIENT', clientId);
      res.json({ message: 'Client deleted successfully' });
    } catch (error) {
      console.error('Delete client error:', error);
      res.status(500).json({ error: 'server_error', message: 'Failed to delete client' });
    }
  }

  // ─── Scopes ───────────────────────────────────────────────────────────────

  static async listScopes(_req: Request, res: Response): Promise<void> {
    try {
      const prisma = AuthService.getPrisma();
      const scopes = await prisma.scope.findMany({ orderBy: { name: 'asc' } });
      res.json({ scopes, total: scopes.length });
    } catch (error) {
      console.error('List scopes error:', error);
      res.status(500).json({ error: 'server_error', message: 'Failed to list scopes' });
    }
  }

  static async createScope(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const prisma = AuthService.getPrisma();
      const { name, description } = req.body as { name: string; description: string };
      if (!name || !description) {
        res.status(400).json({ error: 'invalid_request', message: 'name and description are required' }); return;
      }
      const scope = await prisma.scope.create({ data: { name: name.trim(), description: description.trim() } });
      SecurityLogger.logAdminAction(req.user!.sub, 'CREATE_SCOPE', name);
      res.status(201).json({ scope });
    } catch (error) {
      console.error('Create scope error:', error);
      res.status(500).json({ error: 'server_error', message: 'Failed to create scope' });
    }
  }

  static async updateScope(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const prisma = AuthService.getPrisma();
      const id = param(req.params['id']);
      const { description } = req.body as { description: string };
      if (!description) {
        res.status(400).json({ error: 'invalid_request', message: 'description is required' }); return;
      }
      const scope = await prisma.scope.update({ where: { id }, data: { description: description.trim() } });
      SecurityLogger.logAdminAction(req.user!.sub, 'UPDATE_SCOPE', scope.name);
      res.json({ scope });
    } catch (error) {
      console.error('Update scope error:', error);
      res.status(500).json({ error: 'server_error', message: 'Failed to update scope' });
    }
  }

  static async deleteScope(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const prisma = AuthService.getPrisma();
      const id = param(req.params['id']);
      const scope = await prisma.scope.findUnique({ where: { id } });
      if (!scope) { res.status(404).json({ error: 'not_found', message: 'Scope not found' }); return; }
      await prisma.scope.delete({ where: { id } });
      SecurityLogger.logAdminAction(req.user!.sub, 'DELETE_SCOPE', scope.name);
      res.json({ message: 'Scope deleted successfully' });
    } catch (error) {
      console.error('Delete scope error:', error);
      res.status(500).json({ error: 'server_error', message: 'Failed to delete scope' });
    }
  }

  // ─── Audit Log ────────────────────────────────────────────────────────────

  static async getAuditLogs(req: Request, res: Response): Promise<void> {
    try {
      const prisma = AuthService.getPrisma();
      const page = Math.max(1, parseInt(sp(req.query.page as string | string[]) ?? '1', 10));
      const limit = Math.min(100, Math.max(1, parseInt(sp(req.query.limit as string | string[]) ?? '50', 10)));
      const event = sp(req.query.event as string | string[]);
      const userId = sp(req.query.userId as string | string[]);

      const where = {
        ...(event && { event }),
        ...(userId && { userId }),
      };

      const [logs, total] = await Promise.all([
        prisma.auditLog.findMany({
          where,
          orderBy: { timestamp: 'desc' },
          skip: (page - 1) * limit,
          take: limit,
        }),
        prisma.auditLog.count({ where }),
      ]);

      res.json({ logs, total, page, limit, pages: Math.ceil(total / limit) });
    } catch (error) {
      console.error('Get audit logs error:', error);
      res.status(500).json({ error: 'server_error', message: 'Failed to get audit logs' });
    }
  }
}
