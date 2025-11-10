import { PrismaClient } from '@prisma/client';
import { randomBytes } from 'crypto';
import argon2 from 'argon2';

const prisma = new PrismaClient();

/**
 * Client Service
 * Manages OAuth2 client registration and validation
 */
export class ClientService {
  /**
   * Generate a cryptographically secure random client ID
   * Format: client_<random_hex>
   */
  private static generateClientId(): string {
    const randomHex = randomBytes(16).toString('hex');
    return `client_${randomHex}`;
  }

  /**
   * Generate a cryptographically secure random client secret
   * Format: secret_<random_hex>
   */
  private static generateClientSecret(): string {
    const randomHex = randomBytes(32).toString('hex');
    return `secret_${randomHex}`;
  }

  /**
   * Hash client secret using argon2
   * @param clientSecret - Plain text client secret
   * @returns Hashed client secret
   */
  private static async hashClientSecret(clientSecret: string): Promise<string> {
    return await argon2.hash(clientSecret, {
      type: argon2.argon2id,
      memoryCost: 65536, // 64 MB
      timeCost: 3,
      parallelism: 4,
    });
  }

  /**
   * Verify client secret against stored hash
   * @param clientSecret - Plain text client secret to verify
   * @param hash - Stored hash
   * @returns True if valid, false otherwise
   */
  static async verifyClientSecret(
    clientSecret: string,
    hash: string
  ): Promise<boolean> {
    try {
      return await argon2.verify(hash, clientSecret);
    } catch (error) {
      return false;
    }
  }

  /**
   * Register a new OAuth2 client
   * @param name - Client application name
   * @param redirectUris - Array of allowed redirect URIs
   * @returns Object with client details including clientId and clientSecret (plain text)
   */
  static async registerClient(
    name: string,
    redirectUris: string[]
  ): Promise<{
    id: string;
    name: string;
    clientId: string;
    clientSecret: string;
    redirectUris: string[];
    createdAt: Date;
  }> {
    // Validate inputs
    if (!name || name.trim().length === 0) {
      throw new Error('Client name is required');
    }

    if (!redirectUris || redirectUris.length === 0) {
      throw new Error('At least one redirect URI is required');
    }

    // Validate redirect URIs format
    for (const uri of redirectUris) {
      try {
        new URL(uri);
      } catch (error) {
        throw new Error(`Invalid redirect URI: ${uri}`);
      }
    }

    // Generate client credentials
    let clientId: string;
    let attempts = 0;
    const maxAttempts = 5;

    // Ensure unique clientId (retry on collision)
    do {
      clientId = this.generateClientId();
      const existing = await prisma.client.findUnique({
        where: { clientId },
      });

      if (!existing) {
        break;
      }

      attempts++;
      if (attempts >= maxAttempts) {
        throw new Error('Failed to generate unique client ID');
      }
    } while (attempts < maxAttempts);

    const clientSecret = this.generateClientSecret();
    const hashedSecret = await this.hashClientSecret(clientSecret);

    // Create client in database
    const client = await prisma.client.create({
      data: {
        name: name.trim(),
        clientId,
        clientSecret: hashedSecret,
        redirectUris,
      },
    });

    // Return client details with plain text secret (only time it's available)
    return {
      id: client.id,
      name: client.name,
      clientId: client.clientId,
      clientSecret, // Plain text - must be stored by client application
      redirectUris: client.redirectUris,
      createdAt: client.createdAt,
    };
  }

  /**
   * Validate client credentials
   * @param clientId - Client ID
   * @param clientSecret - Client secret (plain text)
   * @returns Client if valid, null otherwise
   */
  static async validateClient(
    clientId: string,
    clientSecret: string
  ): Promise<{
    id: string;
    name: string;
    clientId: string;
    redirectUris: string[];
  } | null> {
    // Find client by clientId
    const client = await prisma.client.findUnique({
      where: { clientId },
    });

    if (!client) {
      return null;
    }

    // Verify client secret
    const isValid = await this.verifyClientSecret(
      clientSecret,
      client.clientSecret
    );

    if (!isValid) {
      return null;
    }

    // Return client details (without secret)
    return {
      id: client.id,
      name: client.name,
      clientId: client.clientId,
      redirectUris: client.redirectUris,
    };
  }

  /**
   * Check if a redirect URI is allowed for a specific client
   * @param clientId - Client ID
   * @param redirectUri - Redirect URI to validate
   * @returns True if allowed, false otherwise
   */
  static async isRedirectUriAllowedForClient(
    clientId: string,
    redirectUri: string
  ): Promise<boolean> {
    const client = await prisma.client.findUnique({
      where: { clientId },
      select: { redirectUris: true },
    });

    if (!client) {
      return false;
    }

    return client.redirectUris.includes(redirectUri);
  }

  /**
   * Get client by clientId (without secret)
   * @param clientId - Client ID
   * @returns Client details or null
   */
  static async getClient(clientId: string): Promise<{
    id: string;
    name: string;
    clientId: string;
    redirectUris: string[];
    allowedScopes?: string[];
  } | null> {
    const client = await prisma.client.findUnique({
      where: { clientId },
      select: {
        id: true,
        name: true,
        clientId: true,
        redirectUris: true,
        allowedScopes: true,
      },
    });

    return client;
  }

  /**
   * Delete a client
   * @param clientId - Client ID
   * @returns True if deleted, false if not found
   */
  static async deleteClient(clientId: string): Promise<boolean> {
    try {
      await prisma.client.delete({
        where: { clientId },
      });
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Update client redirect URIs
   * @param clientId - Client ID
   * @param redirectUris - New array of redirect URIs
   * @returns Updated client or null if not found
   */
  static async updateRedirectUris(
    clientId: string,
    redirectUris: string[]
  ): Promise<{
    id: string;
    name: string;
    clientId: string;
    redirectUris: string[];
  } | null> {
    // Validate redirect URIs format
    for (const uri of redirectUris) {
      try {
        new URL(uri);
      } catch (error) {
        throw new Error(`Invalid redirect URI: ${uri}`);
      }
    }

    try {
      const client = await prisma.client.update({
        where: { clientId },
        data: { redirectUris },
        select: {
          id: true,
          name: true,
          clientId: true,
          redirectUris: true,
        },
      });

      return client;
    } catch (error) {
      return null;
    }
  }

  /**
   * Get Prisma client instance
   */
  static getPrisma(): PrismaClient {
    return prisma;
  }
}
