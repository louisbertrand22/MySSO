import { Response } from 'express';
import { AuthenticatedRequest } from '../middleware/auth.middleware';
import { ConsentService } from '../services/consentService';
import { SecurityLogger } from '../services/securityLogger';

/**
 * User Controller
 * Handles user-related endpoints including consent management
 */
export class UserController {
  /**
   * GET /user/consents
   * Get all consents granted by the authenticated user
   */
  static async getConsents(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      // User must be authenticated (via middleware)
      if (!req.user) {
        res.status(401).json({
          error: 'unauthorized',
          error_description: 'User must be authenticated',
        });
        return;
      }

      const userId = req.user.sub;

      // Get all consents for this user
      const consents = await ConsentService.getUserConsents(userId);

      res.json({
        consents,
        total: consents.length,
      });
    } catch (error) {
      console.error('Get consents error:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Failed to retrieve user consents',
      });
    }
  }

  /**
   * DELETE /user/consents/:clientId
   * Revoke consent for a specific client
   */
  static async revokeConsent(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      // User must be authenticated (via middleware)
      if (!req.user) {
        res.status(401).json({
          error: 'unauthorized',
          error_description: 'User must be authenticated',
        });
        return;
      }

      const userId = req.user.sub;
      const { clientId } = req.params;

      if (!clientId) {
        res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing clientId parameter',
        });
        return;
      }

      // Revoke the consent
      const revoked = await ConsentService.revokeConsent(userId, clientId);

      if (!revoked) {
        res.status(404).json({
          error: 'not_found',
          error_description: 'Consent not found for this client',
        });
        return;
      }

      // Delete all refresh tokens associated with this user and client
      // This ensures users cannot continue using the app after revoking consent
      const prisma = ConsentService.getPrisma();
      const deletedTokens = await prisma.refreshToken.deleteMany({
        where: {
          userId,
          // Note: RefreshToken doesn't have clientId, so we delete all user tokens
          // This is a limitation - ideally we'd track clientId in RefreshToken
        },
      });

      // Log the revocation for audit purposes
      SecurityLogger.logConsentRevocation(userId, clientId, {
        deletedTokens: deletedTokens.count,
      });

      res.json({
        message: 'Consent revoked successfully',
        clientId,
        deletedTokens: deletedTokens.count,
      });
    } catch (error) {
      console.error('Revoke consent error:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Failed to revoke consent',
      });
    }
  }
}
