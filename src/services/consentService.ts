import { PrismaClient } from '@prisma/client';
import { ScopeService } from './scopeService';

const prisma = new PrismaClient();

/**
 * Consent Service
 * Manages user consent for OAuth2 client applications
 */
export class ConsentService {
  /**
   * Check if user has already granted consent to a client
   * @param userId - User ID
   * @param clientId - Client ID
   * @returns True if consent exists, false otherwise
   */
  static async hasConsent(userId: string, clientId: string): Promise<boolean> {
    const consent = await prisma.userConsent.findUnique({
      where: {
        userId_clientId: {
          userId,
          clientId,
        },
      },
    });

    return !!consent;
  }

  /**
   * Get existing consent scopes for a user and client
   * @param userId - User ID
   * @param clientId - Client ID
   * @returns Array of granted scopes or null if no consent exists
   */
  static async getConsentScopes(
    userId: string,
    clientId: string
  ): Promise<string[] | null> {
    const consent = await prisma.userConsent.findUnique({
      where: {
        userId_clientId: {
          userId,
          clientId,
        },
      },
      select: {
        scopes: true,
      },
    });

    return consent ? consent.scopes : null;
  }

  /**
   * Grant consent from user to client
   * @param userId - User ID
   * @param clientId - Client ID
   * @param scopes - Array of scopes granted
   * @returns Created consent record
   */
  static async grantConsent(
    userId: string,
    clientId: string,
    scopes: string[] = ['openid', 'profile', 'email']
  ): Promise<{
    id: string;
    userId: string;
    clientId: string;
    scopes: string[];
    createdAt: Date;
  }> {
    // Filter to only include valid scopes
    const validScopes = await ScopeService.filterValidScopes(scopes);

    const consent = await prisma.userConsent.upsert({
      where: {
        userId_clientId: {
          userId,
          clientId,
        },
      },
      update: {
        scopes: validScopes,
      },
      create: {
        userId,
        clientId,
        scopes: validScopes,
      },
    });

    return consent;
  }

  /**
   * Revoke consent from user to client
   * @param userId - User ID
   * @param clientId - Client ID
   * @returns True if consent was revoked, false if it didn't exist
   */
  static async revokeConsent(userId: string, clientId: string): Promise<boolean> {
    try {
      await prisma.userConsent.delete({
        where: {
          userId_clientId: {
            userId,
            clientId,
          },
        },
      });
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Get all consents for a user
   * @param userId - User ID
   * @returns Array of consent records with client details
   */
  static async getUserConsents(userId: string): Promise<
    Array<{
      id: string;
      clientId: string;
      clientName: string;
      scopes: string[];
      createdAt: Date;
    }>
  > {
    const consents = await prisma.userConsent.findMany({
      where: { userId },
      include: {
        client: {
          select: {
            name: true,
          },
        },
      },
    });

    return consents.map((consent) => ({
      id: consent.id,
      clientId: consent.clientId,
      clientName: consent.client.name,
      scopes: consent.scopes,
      createdAt: consent.createdAt,
    }));
  }

  /**
   * Get Prisma client instance
   */
  static getPrisma(): PrismaClient {
    return prisma;
  }
}
