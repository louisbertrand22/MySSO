import {
  AdminUser,
  AdminUserDetail,
  AdminClient,
  AdminScope,
  AuditLog,
  DashboardStats,
} from './types';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000';

async function adminFetch<T>(
  path: string,
  token: string,
  options: RequestInit = {}
): Promise<T> {
  const res = await fetch(`${API_URL}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
      ...(options.headers ?? {}),
    },
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.message || err.error || `Request failed: ${res.status}`);
  }
  return res.json();
}

export const AdminApi = {
  // Dashboard
  getDashboard: (token: string) =>
    adminFetch<DashboardStats>('/admin/dashboard', token),

  // Users
  listUsers: (token: string) =>
    adminFetch<{ users: AdminUser[]; total: number }>('/admin/users', token),

  getUser: (token: string, id: string) =>
    adminFetch<{ user: AdminUserDetail }>(`/admin/users/${id}`, token),

  updateUser: (token: string, id: string, isDisabled: boolean) =>
    adminFetch<{ user: AdminUser }>(`/admin/users/${id}`, token, {
      method: 'PATCH',
      body: JSON.stringify({ isDisabled }),
    }),

  deleteUser: (token: string, id: string) =>
    adminFetch<{ message: string }>(`/admin/users/${id}`, token, { method: 'DELETE' }),

  // Clients
  listClients: (token: string) =>
    adminFetch<{ clients: AdminClient[]; total: number }>('/admin/clients', token),

  createClient: (token: string, name: string, redirectUris: string[]) =>
    adminFetch<{ client_id: string; client_secret: string; client_name: string; redirect_uris: string[]; message: string }>(
      '/admin/clients',
      token,
      { method: 'POST', body: JSON.stringify({ name, redirectUris }) }
    ),

  updateClient: (
    token: string,
    clientId: string,
    updates: { name?: string; redirectUris?: string[]; allowedScopes?: string[] }
  ) =>
    adminFetch<{ client: AdminClient }>(`/admin/clients/${clientId}`, token, {
      method: 'PATCH',
      body: JSON.stringify(updates),
    }),

  rotateClientSecret: (token: string, clientId: string) =>
    adminFetch<{ client_id: string; client_secret: string; message: string }>(
      `/admin/clients/${clientId}/rotate-secret`,
      token,
      { method: 'POST' }
    ),

  deleteClient: (token: string, clientId: string) =>
    adminFetch<{ message: string }>(`/admin/clients/${clientId}`, token, { method: 'DELETE' }),

  // Scopes
  listScopes: (token: string) =>
    adminFetch<{ scopes: AdminScope[]; total: number }>('/admin/scopes', token),

  createScope: (token: string, name: string, description: string) =>
    adminFetch<{ scope: AdminScope }>('/admin/scopes', token, {
      method: 'POST',
      body: JSON.stringify({ name, description }),
    }),

  updateScope: (token: string, id: string, description: string) =>
    adminFetch<{ scope: AdminScope }>(`/admin/scopes/${id}`, token, {
      method: 'PATCH',
      body: JSON.stringify({ description }),
    }),

  deleteScope: (token: string, id: string) =>
    adminFetch<{ message: string }>(`/admin/scopes/${id}`, token, { method: 'DELETE' }),

  // Settings
  getSettings: (token: string) =>
    adminFetch<{ requireEmailVerification: boolean }>('/admin/settings', token),

  updateSettings: (token: string, settings: { requireEmailVerification: boolean }) =>
    adminFetch<{ requireEmailVerification: boolean }>('/admin/settings', token, {
      method: 'PATCH',
      body: JSON.stringify(settings),
    }),

  // Audit logs
  getAuditLogs: (token: string, params: { page?: number; limit?: number; event?: string; userId?: string } = {}) => {
    const qs = new URLSearchParams();
    if (params.page) qs.set('page', String(params.page));
    if (params.limit) qs.set('limit', String(params.limit));
    if (params.event) qs.set('event', params.event);
    if (params.userId) qs.set('userId', params.userId);
    return adminFetch<{ logs: AuditLog[]; total: number; page: number; limit: number; pages: number }>(
      `/admin/audit-logs?${qs}`,
      token
    );
  },
};
