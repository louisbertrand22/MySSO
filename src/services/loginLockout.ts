import { prisma } from './authService';
import { config } from '../config/env';

/**
 * Temporary account lockout after repeated wrong passwords.
 * After LOGIN_MAX_ATTEMPTS failures in a row, the account is locked for LOGIN_LOCK_MINUTES.
 * A successful login or a password reset clears the counter.
 */
export class LoginLockout {
  /**
   * Counts a wrong password. Returns the lock end date when this failure locks the account.
   * The increment is atomic, so parallel attempts cannot slip past the limit.
   */
  static async recordFailure(userId: string, previousLockedUntil: Date | null): Promise<Date | null> {
    const previousLockExpired = previousLockedUntil !== null && previousLockedUntil <= new Date();
    const { failedLoginAttempts } = await prisma.user.update({
      where: { id: userId },
      // A finished lock starts a fresh count
      data: previousLockExpired
        ? { failedLoginAttempts: 1, lockedUntil: null }
        : { failedLoginAttempts: { increment: 1 } },
      select: { failedLoginAttempts: true },
    });

    if (failedLoginAttempts < config.lockout.maxAttempts) return null;

    const lockedUntil = new Date(Date.now() + config.lockout.lockMinutes * 60 * 1000);
    await prisma.user.update({
      where: { id: userId },
      data: { lockedUntil, failedLoginAttempts: 0 },
    });
    return lockedUntil;
  }

  static async reset(userId: string): Promise<void> {
    await prisma.user.update({
      where: { id: userId },
      data: { failedLoginAttempts: 0, lockedUntil: null },
    });
  }
}
