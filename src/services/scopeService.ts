import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

/**
 * Scope Service
 * Manages scope operations and validation
 */
export class ScopeService {
  /**
   * Get all available scopes
   * @returns Array of all scopes
   */
  static async getAllScopes(): Promise<
    Array<{
      id: string;
      name: string;
      description: string;
      createdAt: Date;
    }>
  > {
    const scopes = await prisma.scope.findMany({
      orderBy: { name: 'asc' },
    });

    return scopes;
  }

  /**
   * Get scope by name
   * @param name - Scope name
   * @returns Scope or null if not found
   */
  static async getScopeByName(
    name: string
  ): Promise<{
    id: string;
    name: string;
    description: string;
    createdAt: Date;
  } | null> {
    const scope = await prisma.scope.findUnique({
      where: { name },
    });

    return scope;
  }

  /**
   * Validate that all requested scopes exist
   * @param scopes - Array of scope names to validate
   * @returns True if all scopes exist, false otherwise
   */
  static async validateScopes(scopes: string[]): Promise<boolean> {
    if (!scopes || scopes.length === 0) {
      return false;
    }

    const uniqueScopes = [...new Set(scopes)];

    const validScopes = await prisma.scope.findMany({
      where: {
        name: {
          in: uniqueScopes,
        },
      },
      select: { name: true },
    });

    return validScopes.length === uniqueScopes.length;
  }

  /**
   * Filter scopes to only include valid ones
   * @param scopes - Array of scope names to filter
   * @returns Array of valid scope names
   */
  static async filterValidScopes(scopes: string[]): Promise<string[]> {
    if (!scopes || scopes.length === 0) {
      return [];
    }

    const uniqueScopes = [...new Set(scopes)];

    const validScopes = await prisma.scope.findMany({
      where: {
        name: {
          in: uniqueScopes,
        },
      },
      select: { name: true },
    });

    return validScopes.map((s) => s.name);
  }

  /**
   * Get scope details for multiple scopes
   * @param scopeNames - Array of scope names
   * @returns Array of scope details
   */
  static async getScopeDetails(
    scopeNames: string[]
  ): Promise<
    Array<{
      name: string;
      description: string;
    }>
  > {
    if (!scopeNames || scopeNames.length === 0) {
      return [];
    }

    const scopes = await prisma.scope.findMany({
      where: {
        name: {
          in: scopeNames,
        },
      },
      select: {
        name: true,
        description: true,
      },
      orderBy: { name: 'asc' },
    });

    return scopes;
  }

  /**
   * Validate scopes against client's allowed scopes
   * @param requestedScopes - Scopes being requested
   * @param clientAllowedScopes - Scopes allowed for the client
   * @returns Filtered array of scopes that are both requested and allowed
   */
  static validateClientScopes(
    requestedScopes: string[],
    clientAllowedScopes: string[]
  ): string[] {
    if (!requestedScopes || requestedScopes.length === 0) {
      return [];
    }

    // Only return scopes that are in both arrays
    const validScopes = requestedScopes.filter((scope) =>
      clientAllowedScopes.includes(scope)
    );

    return validScopes;
  }

  /**
   * Get default scopes for OAuth2 flow
   * @returns Array of default scope names
   */
  static getDefaultScopes(): string[] {
    return ['openid', 'profile', 'email', 'username'];
  }

  /**
   * Get Prisma client instance
   */
  static getPrisma(): PrismaClient {
    return prisma;
  }
}
