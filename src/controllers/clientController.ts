import { Request, Response } from 'express';
import { ClientService } from '../services/clientService';

/**
 * Client Controller
 * Handles OAuth2 client registration and management endpoints
 */
export class ClientController {
  /**
   * POST /clients/register
   * Register a new OAuth2 client application
   */
  static async register(req: Request, res: Response): Promise<void> {
    try {
      const { name, redirectUris } = req.body;

      // Validate inputs
      if (!name || typeof name !== 'string') {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'Client name is required and must be a string',
        });
        return;
      }

      if (!redirectUris || !Array.isArray(redirectUris)) {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'redirectUris is required and must be an array',
        });
        return;
      }

      if (redirectUris.length === 0) {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'At least one redirect URI is required',
        });
        return;
      }

      // Register the client
      const client = await ClientService.registerClient(name, redirectUris);

      // Return client credentials
      // WARNING: clientSecret is only returned once - client must store it securely
      res.status(201).json({
        client_id: client.clientId,
        client_secret: client.clientSecret,
        client_name: client.name,
        redirect_uris: client.redirectUris,
        created_at: client.createdAt.toISOString(),
        message:
          'Client registered successfully. Store the client_secret securely - it will not be shown again.',
      });
    } catch (error) {
      console.error('Client registration error:', error);

      if (error instanceof Error) {
        res.status(400).json({
          error: 'invalid_request',
          error_description: error.message,
        });
      } else {
        res.status(500).json({
          error: 'server_error',
          error_description: 'Failed to register client',
        });
      }
    }
  }

  /**
   * DELETE /clients/:clientId
   * Delete a registered client
   */
  static async delete(req: Request, res: Response): Promise<void> {
    try {
      const { clientId } = req.params;

      if (!clientId) {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'Client ID is required',
        });
        return;
      }

      const deleted = await ClientService.deleteClient(clientId as string);

      if (!deleted) {
        res.status(404).json({
          error: 'not_found',
          error_description: 'Client not found',
        });
        return;
      }

      res.json({
        message: 'Client deleted successfully',
      });
    } catch (error) {
      console.error('Client deletion error:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Failed to delete client',
      });
    }
  }

  /**
   * PUT /clients/:clientId/redirect-uris
   * Update client redirect URIs
   */
  static async updateRedirectUris(req: Request, res: Response): Promise<void> {
    try {
      const { clientId } = req.params;
      const { redirectUris } = req.body;

      if (!clientId) {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'Client ID is required',
        });
        return;
      }

      if (!redirectUris || !Array.isArray(redirectUris)) {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'redirectUris is required and must be an array',
        });
        return;
      }

      if (redirectUris.length === 0) {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'At least one redirect URI is required',
        });
        return;
      }

      const client = await ClientService.updateRedirectUris(
        clientId as string,
        redirectUris
      );

      if (!client) {
        res.status(404).json({
          error: 'not_found',
          error_description: 'Client not found',
        });
        return;
      }

      res.json({
        client_id: client.clientId,
        client_name: client.name,
        redirect_uris: client.redirectUris,
        message: 'Redirect URIs updated successfully',
      });
    } catch (error) {
      console.error('Client update error:', error);

      if (error instanceof Error) {
        res.status(400).json({
          error: 'invalid_request',
          error_description: error.message,
        });
      } else {
        res.status(500).json({
          error: 'server_error',
          error_description: 'Failed to update client',
        });
      }
    }
  }

  /**
   * GET /clients/:clientId
   * Get client details (without secret)
   */
  static async getClient(req: Request, res: Response): Promise<void> {
    try {
      const { clientId } = req.params;

      if (!clientId) {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'Client ID is required',
        });
        return;
      }

      const client = await ClientService.getClient(clientId as string);

      if (!client) {
        res.status(404).json({
          error: 'not_found',
          error_description: 'Client not found',
        });
        return;
      }

      res.json({
        client_id: client.clientId,
        client_name: client.name,
        redirect_uris: client.redirectUris,
      });
    } catch (error) {
      console.error('Get client error:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Failed to get client details',
      });
    }
  }
}
