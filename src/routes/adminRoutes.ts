import { Router } from 'express';
import { AdminController } from '../controllers/adminController';
import { authMiddleware, requireScope, requireAnyScope } from '../middleware';

const router = Router();

/**
 * Admin Routes
 * All routes require authentication and specific scopes
 */

// Admin dashboard - requires 'admin' scope
router.get('/admin/dashboard', authMiddleware, requireScope('admin'), AdminController.dashboard);

// List all users - requires 'read:users' or 'admin' scope
router.get('/admin/users', authMiddleware, requireAnyScope('read:users', 'admin'), AdminController.listUsers);

// List all scopes - requires 'admin' scope
router.get('/admin/scopes', authMiddleware, requireScope('admin'), AdminController.listScopes);

// List all clients - requires 'read:clients' or 'admin' scope
router.get('/admin/clients', authMiddleware, requireAnyScope('read:clients', 'admin'), AdminController.listClients);

export default router;
