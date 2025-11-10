import { PrismaClient } from "@prisma/client"
import { randomUUID, createHash } from "crypto"
import { ClientService } from "./clientService"

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
   * @param clientId - Optional client ID to associate with the auth code
   * @param nonce - Optional nonce for OIDC
   * @param codeChallenge - Optional code challenge for PKCE
   * @param codeChallengeMethod - Optional code challenge method for PKCE
   * @returns Authorization code
   */
  static async generateAuthCode(
    userId: string, 
    redirectUri: string, 
    clientId?: string,
    nonce?: string,
    codeChallenge?: string,
    codeChallengeMethod?: string
  ): Promise<string> {
    // Validate redirect URI
    if (!await this.isRedirectUriAllowed(redirectUri, clientId)) {
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
        clientId: clientId || null,
        nonce: nonce || null,
        codeChallenge: codeChallenge || null,
        codeChallengeMethod: codeChallengeMethod || null,
        expiresAt,
      },
    })

    return code
  }

  /**
   * Validate and consume an authorization code
   * Returns user ID, client ID, nonce, and PKCE info if valid, null if invalid/expired/used
   * @param code - Authorization code
   * @param redirectUri - Redirect URI to validate against
   * @param codeVerifier - Optional code verifier for PKCE
   * @returns Object with userId, clientId, nonce, and PKCE info if valid, null otherwise
   */
  static async validateAndConsumeAuthCode(
    code: string,
    redirectUri: string,
    codeVerifier?: string
  ): Promise<{ 
    userId: string; 
    clientId: string | null;
    nonce: string | null;
    codeChallenge: string | null;
    codeChallengeMethod: string | null;
  } | null> {
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

    // PKCE verification if code challenge was provided during authorization
    if (authCode.codeChallenge) {
      if (!codeVerifier) {
        // Code verifier is required when code challenge was provided
        return null
      }

      // Verify the code verifier against the code challenge
      if (!this.verifyPKCE(codeVerifier, authCode.codeChallenge, authCode.codeChallengeMethod || 'plain')) {
        return null
      }
    }

    // Mark code as used (single-use enforcement)
    await prisma.authCode.update({
      where: { code },
      data: { usedAt: new Date() },
    })

    // Delete the code after use (alternative to marking as used)
    await prisma.authCode.delete({ where: { code } })

    return {
      userId: authCode.userId,
      clientId: authCode.clientId,
      nonce: authCode.nonce,
      codeChallenge: authCode.codeChallenge,
      codeChallengeMethod: authCode.codeChallengeMethod,
    }
  }

  /**
   * Validate if a redirect URI is in the whitelist
   * @param redirectUri - Redirect URI to validate
   * @param clientId - Optional client ID to check against
   * @returns True if allowed, false otherwise
   */
  static async isRedirectUriAllowed(redirectUri: string, clientId?: string): Promise<boolean> {
    // If clientId is provided, check against client's registered URIs
    if (clientId) {
      const isAllowed = await ClientService.isRedirectUriAllowedForClient(
        clientId,
        redirectUri
      )
      return isAllowed
    }

    // Fallback: In development, be more permissive for backward compatibility
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

    // Check against legacy whitelist (for backward compatibility)
    return this.ALLOWED_REDIRECT_URIS.includes(redirectUri)
  }

  /**
   * Verify PKCE code verifier against code challenge
   * @param codeVerifier - Code verifier provided by client
   * @param codeChallenge - Code challenge stored during authorization
   * @param codeChallengeMethod - Method used to generate the challenge (plain or S256)
   * @returns True if verification succeeds, false otherwise
   */
  static verifyPKCE(codeVerifier: string, codeChallenge: string, codeChallengeMethod: string): boolean {
    if (codeChallengeMethod === 'S256') {
      // SHA-256 hash the code verifier and base64url encode it
      const hash = createHash('sha256').update(codeVerifier).digest('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '')
      return hash === codeChallenge
    } else if (codeChallengeMethod === 'plain') {
      // Plain method: code verifier must match code challenge exactly
      return codeVerifier === codeChallenge
    }
    
    // Unknown method
    return false
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
