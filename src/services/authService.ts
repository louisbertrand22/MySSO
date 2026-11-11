import { PrismaClient } from "@prisma/client"
import { HashService } from "./hashService"
import { JwtService } from "./jwtService"
import { randomBytes } from "crypto"

const prisma = new PrismaClient()

/** Default refresh token / session lifetime, in days */
export const DEFAULT_REFRESH_TTL_DAYS = 90

/**
 * Authentication Service
 * Provides core authentication functionality using existing services
 */
export class AuthService {
  /**
   * Hash a password using HashService
   * @param password - Plain text password
   * @returns Hashed password
   */
  static async hashPassword(password: string): Promise<string> {
    return HashService.hashPassword(password)
  }

  /**
   * Verify a password against its hash
   * @param password - Plain text password
   * @param hash - Hashed password
   * @returns True if password matches
   */
  static async verifyPassword(password: string, hash: string): Promise<boolean> {
    return HashService.verifyPassword(hash, password)
  }

  /**
   * Generate an access token (JWT with 15min expiration)
   * @param userId - User ID
   * @returns Access token
   */
  static generateAccessToken(userId: string): string {
    return JwtService.sign({ sub: userId }, { expiresIn: "15m" })
  }

  /**
   * Generate a refresh token (JWT with 90 day expiration)
   * @param userId - User ID
   * @returns Refresh token
   */
  static generateRefreshToken(userId: string): string {
    return JwtService.sign({ sub: userId, type: "refresh" }, { expiresIn: "90d" })
  }

  /**
   * Generate both access and refresh tokens for a user
   * Creates a new session or updates an existing one (on token refresh).
   */
  static async generateTokens(
    userId: string,
    email?: string,
    scopes?: string[],
    options?: {
      ip?: string;
      userAgent?: string;
      existingSessionId?: string;
      /** OAuth client the refresh token is bound to (null/undefined = first-party SSO session) */
      clientId?: string;
      /** Refresh token / session lifetime in days (defaults to 90) */
      refreshTtlDays?: number;
    }
  ): Promise<{ accessToken: string; refreshToken: string }> {
    // Fetch user to get createdAt timestamp
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { createdAt: true, email: true, username: true }
    })

    if (!user) {
      throw new Error("User not found")
    }

    // Build access token payload
    const accessTokenPayload: any = {
      sub: userId, 
      email: email || user.email,
      createdAt: user.createdAt.toISOString()
    };

    // Include username if present
    if (user.username) {
      accessTokenPayload.username = user.username;
    }

    // Include scopes if provided
    if (scopes && scopes.length > 0) {
      accessTokenPayload.scope = scopes.join(' ');
      accessTokenPayload.scopes = scopes;
    }

    // Generate unique identifier for this refresh token (jti claim)
    const jti = randomBytes(16).toString("hex")

    // Generate refresh token with unique jti to prevent token reuse
    const ttlDays = options?.refreshTtlDays ?? DEFAULT_REFRESH_TTL_DAYS
    const refreshToken = JwtService.sign(
      { sub: userId, type: "refresh", jti },
      { expiresIn: `${ttlDays}d` }
    )

    const sessionExpiry = new Date(Date.now() + ttlDays * 24 * 3600 * 1000);

    let sessionId: string;
    if (options?.existingSessionId) {
      // Refresh flow: update lastSeenAt on the existing session instead of creating a new one
      await prisma.session.update({
        where: { id: options.existingSessionId },
        data: { lastSeenAt: new Date(), expiresAt: sessionExpiry },
      });
      sessionId = options.existingSessionId;
    } else {
      const session = await prisma.session.create({
        data: {
          userId,
          ip: options?.ip,
          userAgent: options?.userAgent,
          expiresAt: sessionExpiry,
        },
      });
      sessionId = session.id;
    }

    // Access token carries the session id (OIDC "sid") so the account page can tell
    // which session is the current one
    accessTokenPayload.sid = sessionId;
    // OAuth client the token was issued to (RFC 9068 client_id), used by introspection and revocation
    if (options?.clientId) accessTokenPayload.client_id = options.clientId;
    const accessToken = JwtService.sign(accessTokenPayload, { expiresIn: "15m" })

    // Store refresh token linked to the session
    await prisma.refreshToken.create({
      data: {
        userId,
        token: refreshToken,
        sessionId,
        clientId: options?.clientId ?? null,
        expiresAt: sessionExpiry,
      },
    })

    return { accessToken, refreshToken }
  }

  /**
   * Get Prisma client instance
   */
  static getPrisma(): PrismaClient {
    return prisma
  }
}

// Export for backward compatibility
export const {
  hashPassword,
  verifyPassword,
  generateAccessToken,
  generateRefreshToken,
} = AuthService

export { prisma }
