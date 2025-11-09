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
