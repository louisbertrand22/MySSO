import fs from 'fs';
import path from 'path';
import { Prisma } from '@prisma/client';
import { prisma } from './authService';

const LOG_DIR = path.join(process.cwd(), 'logs');
const LOG_FILE = path.join(LOG_DIR, 'security.log');

function ensureLogDir(): void {
  if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
  }
}

function writeLog(entry: Record<string, unknown>): void {
  const line = JSON.stringify(entry) + '\n';
  console.log('[SECURITY]', line.trimEnd());
  try {
    ensureLogDir();
    fs.appendFileSync(LOG_FILE, line);
  } catch (err) {
    console.error('[SECURITY] Failed to write to log file:', err);
  }

  // Also persist to DB for the audit log viewer
  const { timestamp, event, userId, email, ip, ...rest } = entry as Record<string, unknown>;
  const data = Object.keys(rest).length > 0 ? (rest as Prisma.InputJsonValue) : undefined;
  prisma.auditLog
    .create({
      data: {
        timestamp: timestamp ? new Date(timestamp as string) : new Date(),
        event: event as string,
        userId: userId as string | undefined,
        email: email as string | undefined,
        ip: ip as string | undefined,
        data,
      },
    })
    .catch((err: unknown) => console.error('[SECURITY] Failed to write audit log to DB:', err));
}

export class SecurityLogger {
  static logLoginSuccess(userId: string, email: string, ip?: string): void {
    writeLog({ timestamp: new Date().toISOString(), event: 'LOGIN_SUCCESS', userId, email, ip });
  }

  static logLoginFailure(email: string, ip?: string, reason?: string): void {
    writeLog({ timestamp: new Date().toISOString(), event: 'LOGIN_FAILURE', email, ip, reason });
  }

  static logRegister(userId: string, email: string, ip?: string): void {
    writeLog({ timestamp: new Date().toISOString(), event: 'REGISTER', userId, email, ip });
  }

  static logTokenGrant(userId: string, clientId: string | null, scopes: string[]): void {
    writeLog({ timestamp: new Date().toISOString(), event: 'TOKEN_GRANT', userId, clientId, scopes });
  }

  static logRevocation(userId: string, scope: 'single' | 'all', metadata?: Record<string, unknown>): void {
    writeLog({ timestamp: new Date().toISOString(), event: 'TOKEN_REVOCATION', userId, scope, ...metadata });
  }

  static logSessionRevocation(userId: string, sessionId: string, scope: 'single' | 'all'): void {
    writeLog({ timestamp: new Date().toISOString(), event: 'SESSION_REVOCATION', userId, sessionId, scope });
  }

  static logLogout(userId: string, allDevices: boolean = false): void {
    writeLog({ timestamp: new Date().toISOString(), event: 'LOGOUT', userId, allDevices });
  }

  static logConsentRevocation(userId: string, clientId: string, metadata?: Record<string, unknown>): void {
    writeLog({ timestamp: new Date().toISOString(), event: 'CONSENT_REVOCATION', userId, clientId, ...metadata });
  }

  static logAdminAction(adminId: string, action: string, target?: string, metadata?: Record<string, unknown>): void {
    writeLog({ timestamp: new Date().toISOString(), event: 'ADMIN_ACTION', userId: adminId, action, target, ...metadata });
  }
}
