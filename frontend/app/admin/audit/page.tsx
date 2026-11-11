'use client';

import React, { useEffect, useState, useCallback } from 'react';
import { useAuth } from '@/contexts/AuthContext';
import { AdminApi } from '@/lib/adminApi';
import { AuditLog } from '@/lib/types';
import { formatDate } from '@/lib/format';
import { Card, PageHeader } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Input, Select } from '@/components/ui/Field';
import { Alert, Badge, EmptyState, Skeleton } from '@/components/ui/Feedback';
import { Table, Td, Th, Tr } from '@/components/ui/Table';
import { ArrowLeftIcon, ArrowRightIcon, ChevronRightIcon, ListIcon, RefreshIcon } from '@/components/ui/Icons';

type Tone = 'neutral' | 'accent' | 'warning' | 'danger';

const EVENTS: Record<string, { label: string; tone: Tone }> = {
  LOGIN_SUCCESS: { label: 'Connexion', tone: 'accent' },
  LOGIN_FAILURE: { label: 'Échec de connexion', tone: 'danger' },
  REGISTER: { label: 'Inscription', tone: 'accent' },
  LOGOUT: { label: 'Déconnexion', tone: 'neutral' },
  TOKEN_GRANT: { label: 'Jeton émis', tone: 'neutral' },
  TOKEN_REVOCATION: { label: 'Jeton révoqué', tone: 'warning' },
  SESSION_REVOCATION: { label: 'Session fermée', tone: 'warning' },
  CONSENT_REVOCATION: { label: 'Accès retiré', tone: 'warning' },
  ADMIN_ACTION: { label: 'Action admin', tone: 'neutral' },
};

export default function AdminAuditPage() {
  const { accessToken } = useAuth();
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [total, setTotal] = useState(0);
  const [pages, setPages] = useState(1);
  const [page, setPage] = useState(1);
  const [error, setError] = useState<string | null>(null);
  const [filterEvent, setFilterEvent] = useState('');
  const [filterUser, setFilterUser] = useState('');
  const [expanded, setExpanded] = useState<string | null>(null);
  const [reloads, setReloads] = useState(0);

  // A request is identified by its parameters; "loading" = latest response is for older params
  const requestKey = `${page}|${filterEvent}|${filterUser}|${reloads}`;
  const [loadedKey, setLoadedKey] = useState<string | null>(null);
  const loading = loadedKey !== requestKey;

  useEffect(() => {
    if (!accessToken) return;
    let cancelled = false;
    AdminApi.getAuditLogs(accessToken, {
      page,
      limit: 50,
      event: filterEvent || undefined,
      userId: filterUser || undefined,
    })
      .then((r) => {
        if (cancelled) return;
        setLogs(r.logs); setTotal(r.total); setPages(r.pages); setError(null);
      })
      .catch((e) => !cancelled && setError(e.message))
      .finally(() => !cancelled && setLoadedKey(requestKey));
    return () => { cancelled = true; };
  }, [accessToken, page, filterEvent, filterUser, requestKey]);

  const load = useCallback(() => setReloads((n) => n + 1), []);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Journal d’audit"
        description={`${total.toLocaleString('fr-FR')} événements enregistrés`}
        actions={<Button variant="secondary" size="sm" onClick={load} loading={loading}><RefreshIcon size={15} /> Actualiser</Button>}
      />

      <div className="flex flex-wrap gap-3">
        <div className="w-full sm:w-56">
          <Select value={filterEvent} onChange={(e) => { setFilterEvent(e.target.value); setPage(1); }} aria-label="Type d’événement">
            <option value="">Tous les événements</option>
            {Object.entries(EVENTS).map(([value, { label }]) => <option key={value} value={value}>{label}</option>)}
          </Select>
        </div>
        <div className="w-full sm:w-72">
          <Input placeholder="Filtrer par ID utilisateur" value={filterUser} onChange={(e) => { setFilterUser(e.target.value); setPage(1); }} className="font-mono text-[13px]" aria-label="ID utilisateur" />
        </div>
      </div>

      {error && <Alert tone="danger">{error}</Alert>}

      <Card>
        {loading && logs.length === 0 ? (
          <div className="space-y-2 p-5">{[0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-8 w-full" />)}</div>
        ) : logs.length === 0 ? (
          <div className="px-5"><EmptyState icon={<ListIcon size={18} />} title="Aucun événement">Aucun événement ne correspond à ces filtres.</EmptyState></div>
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Date</Th>
                <Th>Événement</Th>
                <Th>Utilisateur</Th>
                <Th>IP</Th>
                <Th align="right"><span className="sr-only">Détails</span></Th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log) => {
                const event = EVENTS[log.event] ?? { label: log.event, tone: 'neutral' as Tone };
                const open = expanded === log.id;
                return (
                  <React.Fragment key={log.id}>
                    <Tr onClick={log.data ? () => setExpanded(open ? null : log.id) : undefined}>
                      <Td className="tabular whitespace-nowrap text-[13px] text-muted">{formatDate(log.timestamp, true)}</Td>
                      <Td><Badge tone={event.tone}>{event.label}</Badge></Td>
                      <Td className="text-[13px]">{log.email ?? '—'}</Td>
                      <Td className="font-mono text-xs text-muted">{log.ip ?? '—'}</Td>
                      <Td align="right">
                        {log.data && (
                          <ChevronRightIcon size={16} className={`ml-auto text-subtle transition-transform ${open ? 'rotate-90' : ''}`} aria-label={open ? 'Masquer les détails' : 'Voir les détails'} />
                        )}
                      </Td>
                    </Tr>
                    {open && log.data && (
                      <tr>
                        <td colSpan={5} className="border-b border-line bg-surface-2/60 px-5 py-3">
                          <pre className="overflow-x-auto font-mono text-xs leading-relaxed text-muted">{JSON.stringify(log.data, null, 2)}</pre>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </Table>
        )}
      </Card>

      {pages > 1 && (
        <div className="flex items-center justify-between">
          <Button variant="secondary" size="sm" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1}>
            <ArrowLeftIcon size={15} /> Précédent
          </Button>
          <span className="tabular text-sm text-muted">Page {page} sur {pages}</span>
          <Button variant="secondary" size="sm" onClick={() => setPage((p) => Math.min(pages, p + 1))} disabled={page === pages}>
            Suivant <ArrowRightIcon size={15} />
          </Button>
        </div>
      )}
    </div>
  );
}
