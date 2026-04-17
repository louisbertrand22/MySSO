import { Router } from 'express';
import { AdminController } from '../controllers/adminController';
import { authMiddleware, requireScope } from '../middleware';

const router = Router();

/**
 * @swagger
 * /admin/dashboard:
 *   get:
 *     tags: [Admin]
 *     summary: Dashboard metrics
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Aggregated metrics
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 totalUsers:
 *                   type: integer
 *                 totalClients:
 *                   type: integer
 *                 totalConsents:
 *                   type: integer
 *                 activeSessions:
 *                   type: integer
 *                 tokenGrantsLast24h:
 *                   type: integer
 *                 topClients:
 *                   type: array
 *                   items:
 *                     type: object
 *       401:
 *         description: Unauthorized
 *       403:
 *         description: Requires admin scope
 */
router.get('/admin/dashboard', authMiddleware, requireScope('admin'), AdminController.dashboard);

/**
 * @swagger
 * /admin/users:
 *   get:
 *     tags: [Admin]
 *     summary: List users
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: search
 *         schema:
 *           type: string
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           default: 1
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 20
 *     responses:
 *       200:
 *         description: Paginated user list
 */
router.get('/admin/users', authMiddleware, requireScope('admin'), AdminController.listUsers);

/**
 * @swagger
 * /admin/users/{id}:
 *   get:
 *     tags: [Admin]
 *     summary: Get user details with sessions and consents
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: User details
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/User'
 *       404:
 *         description: User not found
 *   patch:
 *     tags: [Admin]
 *     summary: Update user (disable/enable, set admin)
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               isDisabled:
 *                 type: boolean
 *               isAdmin:
 *                 type: boolean
 *     responses:
 *       200:
 *         description: Updated user
 *   delete:
 *     tags: [Admin]
 *     summary: Delete user
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: User deleted
 */
router.get('/admin/users/:id', authMiddleware, requireScope('admin'), AdminController.getUser);
router.patch('/admin/users/:id', authMiddleware, requireScope('admin'), AdminController.updateUser);
router.delete('/admin/users/:id', authMiddleware, requireScope('admin'), AdminController.deleteUser);

/**
 * @swagger
 * /admin/clients:
 *   get:
 *     tags: [Admin]
 *     summary: List all OAuth2 clients
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of clients
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Client'
 *   post:
 *     tags: [Admin]
 *     summary: Create a new OAuth2 client
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [name, redirectUris]
 *             properties:
 *               name:
 *                 type: string
 *               redirectUris:
 *                 type: array
 *                 items:
 *                   type: string
 *               allowedScopes:
 *                 type: array
 *                 items:
 *                   type: string
 *     responses:
 *       201:
 *         description: Client created — secret shown once
 */
router.get('/admin/clients', authMiddleware, requireScope('admin'), AdminController.listClients);
router.post('/admin/clients', authMiddleware, requireScope('admin'), AdminController.createClient);

/**
 * @swagger
 * /admin/clients/{clientId}:
 *   patch:
 *     tags: [Admin]
 *     summary: Update client name, redirectUris, or allowedScopes
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: clientId
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               redirectUris:
 *                 type: array
 *                 items:
 *                   type: string
 *               allowedScopes:
 *                 type: array
 *                 items:
 *                   type: string
 *     responses:
 *       200:
 *         description: Updated client
 *   delete:
 *     tags: [Admin]
 *     summary: Delete client
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: clientId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Client deleted
 */
router.patch('/admin/clients/:clientId', authMiddleware, requireScope('admin'), AdminController.updateClient);
router.delete('/admin/clients/:clientId', authMiddleware, requireScope('admin'), AdminController.deleteClient);

/**
 * @swagger
 * /admin/clients/{clientId}/rotate-secret:
 *   post:
 *     tags: [Admin]
 *     summary: Rotate client secret — new secret shown once
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: clientId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: New plaintext secret
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 clientSecret:
 *                   type: string
 */
router.post('/admin/clients/:clientId/rotate-secret', authMiddleware, requireScope('admin'), AdminController.rotateClientSecret);

/**
 * @swagger
 * /admin/scopes:
 *   get:
 *     tags: [Admin]
 *     summary: List all scopes
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of scopes
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Scope'
 *   post:
 *     tags: [Admin]
 *     summary: Create a scope
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [name, description]
 *             properties:
 *               name:
 *                 type: string
 *               description:
 *                 type: string
 *     responses:
 *       201:
 *         description: Scope created
 */
router.get('/admin/scopes', authMiddleware, requireScope('admin'), AdminController.listScopes);
router.post('/admin/scopes', authMiddleware, requireScope('admin'), AdminController.createScope);

/**
 * @swagger
 * /admin/scopes/{id}:
 *   patch:
 *     tags: [Admin]
 *     summary: Update scope description
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               description:
 *                 type: string
 *     responses:
 *       200:
 *         description: Updated scope
 *   delete:
 *     tags: [Admin]
 *     summary: Delete scope
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Scope deleted
 */
router.patch('/admin/scopes/:id', authMiddleware, requireScope('admin'), AdminController.updateScope);
router.delete('/admin/scopes/:id', authMiddleware, requireScope('admin'), AdminController.deleteScope);

/**
 * @swagger
 * /admin/audit-logs:
 *   get:
 *     tags: [Admin]
 *     summary: Query audit logs
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: event
 *         schema:
 *           type: string
 *       - in: query
 *         name: userId
 *         schema:
 *           type: string
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           default: 1
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 50
 *     responses:
 *       200:
 *         description: Paginated audit logs
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 logs:
 *                   type: array
 *                   items:
 *                     $ref: '#/components/schemas/AuditLog'
 *                 total:
 *                   type: integer
 *                 pages:
 *                   type: integer
 */
router.get('/admin/audit-logs', authMiddleware, requireScope('admin'), AdminController.getAuditLogs);

export default router;
