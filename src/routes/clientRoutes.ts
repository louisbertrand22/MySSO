import { Router } from 'express';
import { ClientController } from '../controllers/clientController';

const router = Router();

/**
 * @swagger
 * /clients/register:
 *   post:
 *     tags: [Clients]
 *     summary: Register a new OAuth2 client
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
 *         description: Client created — clientSecret shown once
 *         content:
 *           application/json:
 *             schema:
 *               allOf:
 *                 - $ref: '#/components/schemas/Client'
 *                 - type: object
 *                   properties:
 *                     clientSecret:
 *                       type: string
 */
router.post('/clients/register', ClientController.register);

/**
 * @swagger
 * /clients/{clientId}:
 *   get:
 *     tags: [Clients]
 *     summary: Get client details
 *     parameters:
 *       - in: path
 *         name: clientId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Client details (secret excluded)
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Client'
 *       404:
 *         description: Client not found
 *   delete:
 *     tags: [Clients]
 *     summary: Delete a client
 *     parameters:
 *       - in: path
 *         name: clientId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       204:
 *         description: Client deleted
 *       404:
 *         description: Client not found
 */
router.get('/clients/:clientId', ClientController.getClient);
router.delete('/clients/:clientId', ClientController.delete);

/**
 * @swagger
 * /clients/{clientId}/redirect-uris:
 *   put:
 *     tags: [Clients]
 *     summary: Update client redirect URIs
 *     parameters:
 *       - in: path
 *         name: clientId
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [redirectUris]
 *             properties:
 *               redirectUris:
 *                 type: array
 *                 items:
 *                   type: string
 *     responses:
 *       200:
 *         description: Updated client
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Client'
 */
router.put('/clients/:clientId/redirect-uris', ClientController.updateRedirectUris);

export default router;
