import jwt from 'jsonwebtoken';
import crypto from 'crypto';
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
   * Load the RSA signing keys.
   *
   * Production must set JWT_PRIVATE_KEY (PEM, or the PEM encoded in base64): the keys/
   * directory is regenerated on every Vercel build, which would invalidate every token
   * (sessions, refresh tokens of OAuth clients, JWKS) at each deployment.
   * The public key is derived from the private key unless JWT_PUBLIC_KEY is also set.
   * Without the variable, keys are read from KEYS_DIR (local development).
   */
  private static loadKeys(): void {
    if (this.privateKey && this.publicKey) return;

    const envPrivate = readPemEnv('JWT_PRIVATE_KEY');
    if (envPrivate) {
      const privateKeyObject = crypto.createPrivateKey(envPrivate);
      const envPublic = readPemEnv('JWT_PUBLIC_KEY');
      this.privateKey = Buffer.from(envPrivate);
      this.publicKey = envPublic
        ? Buffer.from(envPublic)
        : Buffer.from(crypto.createPublicKey(privateKeyObject).export({ type: 'spki', format: 'pem' }) as string);
      return;
    }

    if (process.env.VERCEL) {
      console.error('JWT_PRIVATE_KEY is not set: signing keys change at every deployment and all tokens become invalid.');
    }

    const privateKeyPath = path.join(config.keysDir, 'private.pem');
    const publicKeyPath = path.join(config.keysDir, 'public.pem');

    if (!fs.existsSync(privateKeyPath) || !fs.existsSync(publicKeyPath)) {
      throw new Error('RSA keys not found. Set JWT_PRIVATE_KEY or run npm install to generate keys.');
    }

    this.privateKey = fs.readFileSync(privateKeyPath);
    this.publicKey = fs.readFileSync(publicKeyPath);
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
   * @param username - Optional username (preferred_username claim)
   * @returns Signed ID token
   */
  static generateIdToken(
    userId: string,
    email: string,
    nonce?: string,
    audience?: string,
    username?: string
  ): string {
    const now = Math.floor(Date.now() / 1000);
    
    const payload: any = {
      sub: userId,
      email,
      email_verified: true,
      iat: now,
      auth_time: now,
    };

    // Add username if provided
    if (username) {
      payload.preferred_username = username;
    }

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
    // Built from the loaded public key, so the JWKS always matches the signing key
    const jwk = crypto.createPublicKey(this.publicKey!).export({ format: 'jwk' }) as { n: string; e: string };
    return { keys: [{ kty: 'RSA', use: 'sig', alg: 'RS256', kid: 'default', n: jwk.n, e: jwk.e }] };
  }
}

/** Reads a PEM from an env variable, accepting raw PEM (with real or escaped newlines) or base64 */
function readPemEnv(name: string): string | null {
  const raw = process.env[name]?.trim();
  if (!raw) return null;
  if (raw.includes('-----BEGIN')) return raw.replace(/\\n/g, '\n');
  return Buffer.from(raw, 'base64').toString('utf8');
}
