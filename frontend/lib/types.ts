export interface User {
  id: string;
  email: string;
  username?: string;
  createdAt: string;
  scopes?: string[];
}

export interface Consent {
  id: string;
  clientId: string;
  clientName: string;
  scopes: string[];
  createdAt: string;
}

export interface ConsentsResponse {
  consents: Consent[];
  total: number;
}

export interface SessionInfo {
  id: string;
  ip: string | null;
  userAgent: string | null;
  createdAt: string;
  lastSeenAt: string;
  expiresAt: string;
}

export interface SessionsResponse {
  sessions: SessionInfo[];
}

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface RegisterCredentials {
  email: string;
  password: string;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
}

export interface AuthResponse {
  accessToken: string;
  refreshToken: string;
}

export interface RegisterResponse {
  user: User;
}

export interface ApiError {
  error: string;
  message?: string;
}

// ─── Admin types ──────────────────────────────────────────────────────────────

export interface AdminUser {
  id: string;
  email: string;
  username?: string;
  isDisabled: boolean;
  createdAt: string;
  _count: { sessions: number; consents: number };
}

export interface AdminUserDetail extends AdminUser {
  sessions: Array<{ id: string; createdAt: string; expiresAt: string; revokedAt: string | null }>;
  consents: Array<{ id: string; clientId: string; scopes: string[]; createdAt: string; client: { name: string } }>;
}

export interface AdminClient {
  id: string;
  name: string;
  clientId: string;
  redirectUris: string[];
  allowedScopes: string[];
  createdAt: string;
  updatedAt: string;
  _count: { consents: number; authCodes: number };
}

export interface AdminScope {
  id: string;
  name: string;
  description: string;
  createdAt: string;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  event: string;
  userId?: string;
  email?: string;
  ip?: string;
  data?: Record<string, unknown>;
}

export interface DashboardStats {
  statistics: {
    totalUsers: number;
    totalClients: number;
    totalConsents: number;
    activeSessions: number;
    tokenGrantsLast24h: number;
  };
  topClientsByConsents: Array<{ clientId: string; name: string; consentCount: number }>;
}
