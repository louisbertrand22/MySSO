import { PrismaClient } from "@prisma/client"
import { HashService } from "./hashService"
import { JwtService } from "./jwtService"
import { randomBytes } from "crypto"

const prisma = new PrismaClient()

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
   * Generate a refresh token (JWT with 7 day expiration)
   * @param userId - User ID
   * @returns Refresh token
   */
  static generateRefreshToken(userId: string): string {
    return JwtService.sign({ sub: userId, type: "refresh" }, { expiresIn: "7d" })
  }

  /**
   * Generate both access and refresh tokens for a user
   * Also creates a session in the database for tracking
   * @param userId - User ID
   * @param email - User email (optional, included in access token)
   * @param scopes - Optional array of scopes to include in the access token
   * @returns Object containing accessToken and refreshToken
   */
  static async generateTokens(userId: string, email?: string, scopes?: string[]): Promise<{
    accessToken: string
    refreshToken: string
  }> {
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

    // Generate access token with user email, createdAt, and scopes
    const accessToken = JwtService.sign(
      accessTokenPayload, 
      { expiresIn: "15m" }
    )

    // Generate unique identifier for this refresh token (jti claim)
    const jti = randomBytes(16).toString("hex")

    // Generate refresh token with unique jti to prevent token reuse
    const refreshToken = JwtService.sign(
      { sub: userId, type: "refresh", jti },
      { expiresIn: "7d" }
    )

    // Store refresh token in database
    await prisma.refreshToken.create({
      data: {
        userId,
        token: refreshToken,
        expiresAt: new Date(Date.now() + 7 * 24 * 3600 * 1000), // 7 days
      },
    })

    // Create a session for tracking
    await prisma.session.create({
      data: {
        userId,
        expiresAt: new Date(Date.now() + 7 * 24 * 3600 * 1000), // 7 days (same as refresh token)
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
