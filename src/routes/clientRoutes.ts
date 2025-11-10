import { Router } from 'express';
import { ClientController } from '../controllers/clientController';

const router = Router();

/**
 * Client Management Routes
 */

// Register a new client
router.post('/clients/register', ClientController.register);

// Get client details
router.get('/clients/:clientId', ClientController.getClient);

// Update client redirect URIs
router.put('/clients/:clientId/redirect-uris', ClientController.updateRedirectUris);

// Delete a client
router.delete('/clients/:clientId', ClientController.delete);

export default router;
