'use client';

import { useEffect, useState } from 'react';
import { useAuth } from '@/contexts/AuthContext';
import { AdminApi } from '@/lib/adminApi';
import { DashboardStats } from '@/lib/types';
import { Card, PageHeader } from '@/components/ui/Card';
import { Alert, EmptyState, Skeleton } from '@/components/ui/Feedback';
import { Table, Td, Th, Tr } from '@/components/ui/Table';
import { AppsIcon } from '@/components/ui/Icons';

function Stat({ label, value, hint }: { label: string; value: number; hint?: string }) {
  return (
    <div className="bg-surface px-5 py-4">
      <p className="text-[13px] text-muted">{label}</p>
      <p className="tabular mt-1 text-2xl font-semibold tracking-tight">{value.toLocaleString('fr-FR')}</p>
      {hint && <p className="mt-0.5 text-xs text-subtle">{hint}</p>}
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

  return (
    <div className="space-y-8">
      <PageHeader title="Vue d’ensemble" description="L’activité de MySSO en un coup d’œil." />

      {error && <Alert tone="danger">{error}</Alert>}

      <div className="grid grid-cols-2 gap-px overflow-hidden rounded-[var(--radius-card)] border border-line bg-line shadow-[var(--shadow-card)] lg:grid-cols-5">
        {stats ? (
          <>
            <Stat label="Utilisateurs" value={stats.statistics.totalUsers} />
            <Stat label="Applications" value={stats.statistics.totalClients} />
            <Stat label="Autorisations" value={stats.statistics.totalConsents} />
            <Stat label="Sessions actives" value={stats.statistics.activeSessions} />
            <Stat label="Jetons émis" value={stats.statistics.tokenGrantsLast24h} hint="24 dernières heures" />
          </>
        ) : (
          Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="bg-surface px-5 py-4">
              <Skeleton className="h-4 w-20" />
              <Skeleton className="mt-2 h-7 w-12" />
            </div>
          ))
        )}
      </div>

      <Card>
        <div className="border-b border-line px-5 py-4">
          <h2 className="text-[15px] font-semibold">Applications les plus utilisées</h2>
          <p className="text-sm text-muted">Classées par nombre d’utilisateurs qui les ont autorisées.</p>
        </div>
        {!stats ? (
          <div className="space-y-2 p-5">
            <Skeleton className="h-8 w-full" />
            <Skeleton className="h-8 w-full" />
          </div>
        ) : stats.topClientsByConsents.length === 0 ? (
          <div className="px-5">
            <EmptyState icon={<AppsIcon size={18} />} title="Aucune autorisation pour l’instant">
              Les applications apparaîtront ici dès qu’un utilisateur en aura autorisé une.
            </EmptyState>
          </div>
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Application</Th>
                <Th>Client ID</Th>
                <Th align="right">Autorisations</Th>
              </tr>
            </thead>
            <tbody>
              {stats.topClientsByConsents.map((c) => (
                <Tr key={c.clientId}>
                  <Td className="font-medium">{c.name}</Td>
                  <Td className="font-mono text-xs text-muted">{c.clientId}</Td>
                  <Td align="right" className="tabular font-medium">{c.consentCount}</Td>
                </Tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </div>
  );
}
