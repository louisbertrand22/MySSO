import fs from 'fs';
import path from 'path';

const LOG_DIR = path.join(process.cwd(), 'logs');
const LOG_FILE = path.join(LOG_DIR, 'security.log');

function ensureLogDir(): void {
  if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
  }
}

function writeLog(entry: Record<string, any>): void {
  const line = JSON.stringify(entry) + '\n';
  console.log('[SECURITY]', line.trimEnd());
  try {
    ensureLogDir();
    fs.appendFileSync(LOG_FILE, line);
  } catch (err) {
    console.error('[SECURITY] Failed to write to log file:', err);
  }
}

/**
 * Security Logger Service
 * Logs security-related events for audit purposes.
 * Events are written to both stdout and logs/security.log (newline-delimited JSON).
 */
export class SecurityLogger {
  static logLoginSuccess(userId: string, email: string, ip?: string): void {
    writeLog({
      timestamp: new Date().toISOString(),
      event: 'LOGIN_SUCCESS',
      userId,
      email,
      ip,
    });
  }

  static logLoginFailure(email: string, ip?: string, reason?: string): void {
    writeLog({
      timestamp: new Date().toISOString(),
      event: 'LOGIN_FAILURE',
      email,
      ip,
      reason,
    });
  }

  static logRegister(userId: string, email: string, ip?: string): void {
    writeLog({
      timestamp: new Date().toISOString(),
      event: 'REGISTER',
      userId,
      email,
      ip,
    });
  }

  static logTokenGrant(userId: string, clientId: string | null, scopes: string[]): void {
    writeLog({
      timestamp: new Date().toISOString(),
      event: 'TOKEN_GRANT',
      userId,
      clientId,
      scopes,
    });
  }

  static logRevocation(userId: string, scope: 'single' | 'all', metadata?: Record<string, any>): void {
    writeLog({
      timestamp: new Date().toISOString(),
      event: 'TOKEN_REVOCATION',
      userId,
      scope,
      ...metadata,
    });
  }

  static logSessionRevocation(userId: string, sessionId: string, scope: 'single' | 'all'): void {
    writeLog({
      timestamp: new Date().toISOString(),
      event: 'SESSION_REVOCATION',
      userId,
      sessionId,
      scope,
    });
  }

  static logLogout(userId: string, allDevices: boolean = false): void {
    writeLog({
      timestamp: new Date().toISOString(),
      event: 'LOGOUT',
      userId,
      allDevices,
    });
  }

  static logConsentRevocation(userId: string, clientId: string, metadata?: Record<string, any>): void {
    writeLog({
      timestamp: new Date().toISOString(),
      event: 'CONSENT_REVOCATION',
      userId,
      clientId,
      ...metadata,
    });
  }
}
