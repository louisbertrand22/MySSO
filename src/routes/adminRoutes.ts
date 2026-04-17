import { Router } from 'express';
import { AdminController } from '../controllers/adminController';
import { authMiddleware, requireScope } from '../middleware';

const router = Router();

// Dashboard metrics
router.get('/admin/dashboard', authMiddleware, requireScope('admin'), AdminController.dashboard);

// Users
router.get('/admin/users', authMiddleware, requireScope('admin'), AdminController.listUsers);
router.get('/admin/users/:id', authMiddleware, requireScope('admin'), AdminController.getUser);
router.patch('/admin/users/:id', authMiddleware, requireScope('admin'), AdminController.updateUser);
router.delete('/admin/users/:id', authMiddleware, requireScope('admin'), AdminController.deleteUser);

// Clients
router.get('/admin/clients', authMiddleware, requireScope('admin'), AdminController.listClients);
router.post('/admin/clients', authMiddleware, requireScope('admin'), AdminController.createClient);
router.patch('/admin/clients/:clientId', authMiddleware, requireScope('admin'), AdminController.updateClient);
router.post('/admin/clients/:clientId/rotate-secret', authMiddleware, requireScope('admin'), AdminController.rotateClientSecret);
router.delete('/admin/clients/:clientId', authMiddleware, requireScope('admin'), AdminController.deleteClient);

// Scopes
router.get('/admin/scopes', authMiddleware, requireScope('admin'), AdminController.listScopes);
router.post('/admin/scopes', authMiddleware, requireScope('admin'), AdminController.createScope);
router.patch('/admin/scopes/:id', authMiddleware, requireScope('admin'), AdminController.updateScope);
router.delete('/admin/scopes/:id', authMiddleware, requireScope('admin'), AdminController.deleteScope);

// Audit log
router.get('/admin/audit-logs', authMiddleware, requireScope('admin'), AdminController.getAuditLogs);

export default router;
