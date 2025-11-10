import { PrismaClient } from "@prisma/client"
import { randomUUID } from "crypto"

const prisma = new PrismaClient()

/**
 * Authorization Code Service
 * Manages OAuth2 authorization codes for the authorization code flow
 */
export class AuthCodeService {
  // Whitelist of allowed redirect URIs
  // In production, this should be fetched from a database or configuration
  private static ALLOWED_REDIRECT_URIS = [
    'http://localhost:5173',
    'http://localhost:3001',
    'http://localhost:3000/callback',
    'http://localhost:5173/callback',
    'http://localhost:3001/callback',
  ]

  // Auth code expiration time in seconds (60 seconds as per requirements)
  private static AUTH_CODE_EXPIRATION_SECONDS = 60

  /**
   * Generate a new authorization code for a user
   * @param userId - User ID
   * @param redirectUri - Redirect URI where the user will be sent
   * @returns Authorization code
   */
  static async generateAuthCode(userId: string, redirectUri: string): Promise<string> {
    // Validate redirect URI
    if (!this.isRedirectUriAllowed(redirectUri)) {
      throw new Error('Invalid redirect_uri: not in whitelist')
    }

    // Generate unique code (UUID)
    const code = randomUUID()

    // Calculate expiration time (60 seconds from now)
    const expiresAt = new Date(Date.now() + this.AUTH_CODE_EXPIRATION_SECONDS * 1000)

    // Store code in database
    await prisma.authCode.create({
      data: {
        code,
        userId,
        redirectUri,
        expiresAt,
      },
    })

    return code
  }

  /**
   * Validate and consume an authorization code
   * Returns user ID if valid, null if invalid/expired/used
   * @param code - Authorization code
   * @param redirectUri - Redirect URI to validate against
   * @returns User ID if valid, null otherwise
   */
  static async validateAndConsumeAuthCode(
    code: string,
    redirectUri: string
  ): Promise<string | null> {
    // Find the auth code
    const authCode = await prisma.authCode.findUnique({
      where: { code },
    })

    // Check if code exists
    if (!authCode) {
      return null
    }

    // Check if code has already been used
    if (authCode.usedAt) {
      return null
    }

    // Check if code has expired
    if (authCode.expiresAt < new Date()) {
      // Delete expired code
      await prisma.authCode.delete({ where: { code } })
      return null
    }

    // Check if redirect URI matches
    if (authCode.redirectUri !== redirectUri) {
      return null
    }

    // Mark code as used (single-use enforcement)
    await prisma.authCode.update({
      where: { code },
      data: { usedAt: new Date() },
    })

    // Delete the code after use (alternative to marking as used)
    await prisma.authCode.delete({ where: { code } })

    return authCode.userId
  }

  /**
   * Validate if a redirect URI is in the whitelist
   * @param redirectUri - Redirect URI to validate
   * @returns True if allowed, false otherwise
   */
  static isRedirectUriAllowed(redirectUri: string): boolean {
    // In development, be more permissive
    if (process.env.NODE_ENV === 'development') {
      // Check if it's a localhost URL
      try {
        const url = new URL(redirectUri)
        if (url.hostname === 'localhost' || url.hostname === '127.0.0.1') {
          return true
        }
      } catch (error) {
        return false
      }
    }

    // Check against whitelist
    return this.ALLOWED_REDIRECT_URIS.includes(redirectUri)
  }

  /**
   * Clean up expired authorization codes
   * This should be called periodically (e.g., via a cron job)
   */
  static async cleanupExpiredCodes(): Promise<number> {
    const result = await prisma.authCode.deleteMany({
      where: {
        expiresAt: {
          lt: new Date(),
        },
      },
    })

    return result.count
  }

  /**
   * Get Prisma client instance
   */
  static getPrisma(): PrismaClient {
    return prisma
  }
}
