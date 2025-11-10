import { PrismaClient } from "@prisma/client"
import { HashService } from "./hashService"
import { JwtService } from "./jwtService"

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
   * @param userId - User ID
   * @param email - User email (optional, included in access token)
   * @returns Object containing accessToken and refreshToken
   */
  static async generateTokens(userId: string, email?: string): Promise<{
    accessToken: string
    refreshToken: string
  }> {
    // Generate access token with user email if provided
    const accessToken = email
      ? JwtService.sign({ sub: userId, email }, { expiresIn: "15m" })
      : JwtService.sign({ sub: userId }, { expiresIn: "15m" })

    // Generate refresh token
    const refreshToken = JwtService.sign(
      { sub: userId, type: "refresh" },
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
