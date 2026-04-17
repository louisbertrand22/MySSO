'use client';

import React, { useEffect, useState, useCallback } from 'react';
import { useAuth } from '@/contexts/AuthContext';
import { AdminApi } from '@/lib/adminApi';
import { AuditLog } from '@/lib/types';

const EVENT_BADGE: Record<string, string> = {
  LOGIN_SUCCESS: 'bg-green-900/40 text-green-300',
  LOGIN_FAILURE: 'bg-red-900/40 text-red-300',
  REGISTER: 'bg-blue-900/40 text-blue-300',
  LOGOUT: 'bg-gray-700 text-gray-300',
  TOKEN_GRANT: 'bg-indigo-900/40 text-indigo-300',
  TOKEN_REVOCATION: 'bg-orange-900/40 text-orange-300',
  SESSION_REVOCATION: 'bg-orange-900/40 text-orange-300',
  CONSENT_REVOCATION: 'bg-yellow-900/40 text-yellow-300',
  ADMIN_ACTION: 'bg-purple-900/40 text-purple-300',
};

const ALL_EVENTS = [
  'LOGIN_SUCCESS', 'LOGIN_FAILURE', 'REGISTER', 'LOGOUT',
  'TOKEN_GRANT', 'TOKEN_REVOCATION', 'SESSION_REVOCATION',
  'CONSENT_REVOCATION', 'ADMIN_ACTION',
];

export default function AdminAuditPage() {
  const { accessToken } = useAuth();
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [total, setTotal] = useState(0);
  const [pages, setPages] = useState(1);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filterEvent, setFilterEvent] = useState('');
  const [filterUser, setFilterUser] = useState('');
  const [expanded, setExpanded] = useState<string | null>(null);

  const load = useCallback(() => {
    if (!accessToken) return;
    setLoading(true);
    AdminApi.getAuditLogs(accessToken, {
      page,
      limit: 50,
      event: filterEvent || undefined,
      userId: filterUser || undefined,
    })
      .then((r) => { setLogs(r.logs); setTotal(r.total); setPages(r.pages); })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [accessToken, page, filterEvent, filterUser]);

  useEffect(() => { setPage(1); }, [filterEvent, filterUser]);
  useEffect(load, [load]);

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">Journal d'audit</h1>
        <span className="text-sm text-gray-400">{total} entrées</span>
      </div>

      {/* Filters */}
      <div className="flex gap-3 flex-wrap">
        <select
          value={filterEvent}
          onChange={(e) => setFilterEvent(e.target.value)}
          className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
        >
          <option value="">Tous les événements</option>
          {ALL_EVENTS.map((e) => <option key={e} value={e}>{e}</option>)}
        </select>
        <input
          placeholder="Filtrer par User ID..."
          value={filterUser}
          onChange={(e) => setFilterUser(e.target.value)}
          className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 w-64"
        />
        <button onClick={load} className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white text-sm font-semibold rounded-lg transition-colors">
          Actualiser
        </button>
      </div>

      {error && <p className="text-red-400 text-sm">{error}</p>}

      <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
        {loading ? (
          <p className="px-6 py-8 text-gray-400 text-sm">Chargement...</p>
        ) : logs.length === 0 ? (
          <p className="px-6 py-8 text-gray-400 text-sm">Aucun événement trouvé.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-gray-700/50 text-gray-400 uppercase text-xs">
                <tr>
                  <th className="px-5 py-3 text-left">Horodatage</th>
                  <th className="px-5 py-3 text-left">Événement</th>
                  <th className="px-5 py-3 text-left">Email</th>
                  <th className="px-5 py-3 text-left">IP</th>
                  <th className="px-5 py-3 text-left">Données</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700">
                {logs.map((log) => (
                  <React.Fragment key={log.id}>
                    <tr
                      className="hover:bg-gray-700/30 cursor-pointer"
                      onClick={() => setExpanded(expanded === log.id ? null : log.id)}
                    >
                      <td className="px-5 py-3 text-gray-400 whitespace-nowrap text-xs">
                        {new Date(log.timestamp).toLocaleString('fr-FR')}
                      </td>
                      <td className="px-5 py-3">
                        <span className={`inline-block px-2 py-0.5 rounded-full text-xs font-semibold ${EVENT_BADGE[log.event] ?? 'bg-gray-700 text-gray-300'}`}>
                          {log.event}
                        </span>
                      </td>
                      <td className="px-5 py-3 text-gray-300 text-xs">{log.email ?? '—'}</td>
                      <td className="px-5 py-3 text-gray-400 font-mono text-xs">{log.ip ?? '—'}</td>
                      <td className="px-5 py-3 text-gray-500 text-xs">
                        {log.data ? <span className="text-indigo-400">▶ voir détails</span> : '—'}
                      </td>
                    </tr>
                    {expanded === log.id && log.data && (
                      <tr key={`${log.id}-detail`} className="bg-gray-900">
                        <td colSpan={5} className="px-5 py-3">
                          <pre className="text-xs text-gray-300 font-mono whitespace-pre-wrap">
                            {JSON.stringify(log.data, null, 2)}
                          </pre>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Pagination */}
      {pages > 1 && (
        <div className="flex items-center justify-center gap-2">
          <button
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page === 1}
            className="px-4 py-2 bg-gray-800 border border-gray-700 text-gray-300 text-sm rounded-lg disabled:opacity-40 hover:bg-gray-700 transition-colors"
          >
            ← Précédent
          </button>
          <span className="text-sm text-gray-400">Page {page} / {pages}</span>
          <button
            onClick={() => setPage((p) => Math.min(pages, p + 1))}
            disabled={page === pages}
            className="px-4 py-2 bg-gray-800 border border-gray-700 text-gray-300 text-sm rounded-lg disabled:opacity-40 hover:bg-gray-700 transition-colors"
          >
            Suivant →
          </button>
        </div>
      )}
    </div>
  );
}
