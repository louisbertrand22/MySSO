import jwt from 'jsonwebtoken';
import fs from 'fs';
import path from 'path';
import { config } from '../config/env';

/**
 * JWT Service
 * Handles JWT signing and verification using RS256 algorithm with RSA keys
 */
export class JwtService {
  private static privateKey: Buffer | null = null;
  private static publicKey: Buffer | null = null;

  /**
   * Load RSA keys from the keys directory
   */
  private static loadKeys(): void {
    if (!this.privateKey || !this.publicKey) {
      const privateKeyPath = path.join(config.keysDir, 'private.pem');
      const publicKeyPath = path.join(config.keysDir, 'public.pem');

      if (!fs.existsSync(privateKeyPath) || !fs.existsSync(publicKeyPath)) {
        throw new Error('RSA keys not found. Please run npm install to generate keys.');
      }

      this.privateKey = fs.readFileSync(privateKeyPath);
      this.publicKey = fs.readFileSync(publicKeyPath);
    }
  }

  /**
   * Sign a JWT token with RS256
   * @param payload - Token payload
   * @param options - Additional JWT options
   * @returns Signed JWT token
   */
  static sign(payload: object, options?: jwt.SignOptions): string {
    this.loadKeys();
    
    const defaultOptions: jwt.SignOptions = {
      algorithm: 'RS256',
      issuer: config.jwt.issuer,
      expiresIn: config.jwt.expiration,
    };

    return jwt.sign(payload, this.privateKey!, {
      ...defaultOptions,
      ...options,
    });
  }

  /**
   * Verify a JWT token
   * @param token - JWT token to verify
   * @returns Decoded token payload
   */
  static verify(token: string): any {
    this.loadKeys();
    
    return jwt.verify(token, this.publicKey!, {
      algorithms: ['RS256'],
      issuer: config.jwt.issuer,
    });
  }

  /**
   * Decode a JWT token without verification (for inspection)
   * @param token - JWT token to decode
   * @returns Decoded token payload
   */
  static decode(token: string): any {
    return jwt.decode(token);
  }

  /**
   * Generate a test JWT token
   * @returns Test JWT token
   */
  static generateTestToken(): string {
    const payload = {
      sub: 'test-user-id',
      email: 'test@example.com',
      name: 'Test User',
    };

    return this.sign(payload);
  }

  /**
   * Generate an OpenID Connect ID Token
   * @param userId - User ID (sub claim)
   * @param email - User email
   * @param nonce - Optional nonce from authorization request
   * @param audience - Client ID (aud claim)
   * @returns Signed ID token
   */
  static generateIdToken(
    userId: string,
    email: string,
    nonce?: string,
    audience?: string
  ): string {
    const now = Math.floor(Date.now() / 1000);
    
    const payload: any = {
      sub: userId,
      email,
      email_verified: true,
      iat: now,
      auth_time: now,
    };

    // Add nonce if provided (for replay attack prevention)
    if (nonce) {
      payload.nonce = nonce;
    }

    const options: jwt.SignOptions = {
      algorithm: 'RS256',
      issuer: config.jwt.issuer,
      expiresIn: config.jwt.expiration,
    };

    // Add audience if provided
    if (audience) {
      options.audience = audience;
    }

    this.loadKeys();
    return jwt.sign(payload, this.privateKey!, options);
  }

  /**
   * Get public key in JWK format for JWKS endpoint
   * @returns JWK public key
   */
  static getPublicJwk(): object {
    this.loadKeys();
    
    // For simplicity, we'll read the JWKS from file
    const jwksPath = path.join(config.keysDir, 'jwks.json');
    
    if (fs.existsSync(jwksPath)) {
      const jwks = JSON.parse(fs.readFileSync(jwksPath, 'utf-8'));
      return jwks;
    }
    
    return { keys: [] };
  }
}
