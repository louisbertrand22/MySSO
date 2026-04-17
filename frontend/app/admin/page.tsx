'use client';

import { useEffect, useState } from 'react';
import { useAuth } from '@/contexts/AuthContext';
import { AdminApi } from '@/lib/adminApi';
import { DashboardStats } from '@/lib/types';

function StatCard({ label, value, sub }: { label: string; value: number | string; sub?: string }) {
  return (
    <div className="bg-gray-800 rounded-xl p-5 border border-gray-700">
      <p className="text-sm text-gray-400">{label}</p>
      <p className="mt-1 text-3xl font-bold text-white">{value}</p>
      {sub && <p className="mt-1 text-xs text-gray-500">{sub}</p>}
    </div>
  );
}

export default function AdminDashboard() {
  const { accessToken } = useAuth();
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!accessToken) return;
    AdminApi.getDashboard(accessToken)
      .then(setStats)
      .catch((e) => setError(e.message));
  }, [accessToken]);

  if (error) return <div className="p-8 text-red-400">{error}</div>;
  if (!stats) return <div className="p-8 text-gray-400">Chargement...</div>;

  const { statistics, topClientsByConsents } = stats;

  return (
    <div className="p-8 space-y-8">
      <h1 className="text-2xl font-bold text-white">Tableau de bord</h1>

      <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-4">
        <StatCard label="Utilisateurs" value={statistics.totalUsers} />
        <StatCard label="Applications" value={statistics.totalClients} />
        <StatCard label="Consentements" value={statistics.totalConsents} />
        <StatCard label="Sessions actives" value={statistics.activeSessions} />
        <StatCard label="Tokens (24h)" value={statistics.tokenGrantsLast24h} />
      </div>

      <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-700">
          <h2 className="text-base font-semibold text-white">Top applications par consentements</h2>
        </div>
        {topClientsByConsents.length === 0 ? (
          <p className="px-6 py-8 text-sm text-gray-400">Aucune donnée</p>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-gray-700/50 text-gray-400 uppercase text-xs">
              <tr>
                <th className="px-6 py-3 text-left">Application</th>
                <th className="px-6 py-3 text-left">Client ID</th>
                <th className="px-6 py-3 text-right">Consentements</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {topClientsByConsents.map((c) => (
                <tr key={c.clientId} className="hover:bg-gray-700/30">
                  <td className="px-6 py-3 text-white font-medium">{c.name}</td>
                  <td className="px-6 py-3 text-gray-400 font-mono text-xs">{c.clientId}</td>
                  <td className="px-6 py-3 text-right text-indigo-300 font-semibold">{c.consentCount}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
