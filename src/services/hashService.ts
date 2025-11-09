import * as argon2 from 'argon2';

/**
 * Password hashing service using Argon2id
 * Provides secure password hashing and verification
 */
export class HashService {
  /**
   * Hash a password using Argon2id
   * @param password - Plain text password to hash
   * @returns Hashed password
   */
  static async hashPassword(password: string): Promise<string> {
    return argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 2 ** 16, // 64 MB
      timeCost: 3,
      parallelism: 1,
    });
  }

  /**
   * Verify a password against its hash
   * @param hash - Hashed password
   * @param password - Plain text password to verify
   * @returns True if password matches, false otherwise
   */
  static async verifyPassword(hash: string, password: string): Promise<boolean> {
    try {
      return await argon2.verify(hash, password);
    } catch (error) {
      return false;
    }
  }
}
