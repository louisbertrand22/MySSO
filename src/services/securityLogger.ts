/**
 * Security Logger Service
 * Logs security-related events for audit purposes
 */
export class SecurityLogger {
  /**
   * Log a token revocation event
   */
  static logRevocation(userId: string, scope: 'single' | 'all', metadata?: Record<string, any>): void {
    const timestamp = new Date().toISOString();
    const logEntry = {
      timestamp,
      event: 'TOKEN_REVOCATION',
      userId,
      scope,
      ...metadata
    };
    
    console.log('[SECURITY]', JSON.stringify(logEntry));
  }

  /**
   * Log a session revocation event
   */
  static logSessionRevocation(userId: string, sessionId: string, scope: 'single' | 'all'): void {
    const timestamp = new Date().toISOString();
    const logEntry = {
      timestamp,
      event: 'SESSION_REVOCATION',
      userId,
      sessionId,
      scope
    };
    
    console.log('[SECURITY]', JSON.stringify(logEntry));
  }

  /**
   * Log a logout event
   */
  static logLogout(userId: string, allDevices: boolean = false): void {
    const timestamp = new Date().toISOString();
    const logEntry = {
      timestamp,
      event: 'LOGOUT',
      userId,
      allDevices
    };
    
    console.log('[SECURITY]', JSON.stringify(logEntry));
  }

  /**
   * Log a consent revocation event
   */
  static logConsentRevocation(userId: string, clientId: string, metadata?: Record<string, any>): void {
    const timestamp = new Date().toISOString();
    const logEntry = {
      timestamp,
      event: 'CONSENT_REVOCATION',
      userId,
      clientId,
      ...metadata
    };
    
    console.log('[SECURITY]', JSON.stringify(logEntry));
  }
}
