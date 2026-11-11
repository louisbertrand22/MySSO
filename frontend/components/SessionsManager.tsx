'use client';

import { useEffect, useMemo, useState } from 'react';
import { ApiService } from '@/lib/api';
import { formatDate, parseDevice, timeAgo } from '@/lib/format';
import type { SessionInfo } from '@/lib/types';
import { Button } from './ui/Button';
import { Alert, Badge, EmptyState, Skeleton } from './ui/Feedback';
import { AppsIcon, ChevronDownIcon, DeviceIcon, PhoneIcon } from './ui/Icons';
import { useOverlay } from './ui/Overlays';

/** Groups shown before "Afficher plus" */
const VISIBLE_GROUPS = 5;

interface SessionGroup {
  key: string;
  kind: 'device' | 'app';
  title: string;
  mobile: boolean;
  sessions: SessionInfo[];
  lastSeenAt: string;
}

/**
 * Sessions of a third-party application are opened from that application's server,
 * so their user agent says nothing about the user's device: group them by application.
 * MySSO sessions are grouped by browser and system.
 */
function groupSessions(sessions: SessionInfo[]): SessionGroup[] {
  const groups = new Map<string, SessionGroup>();
  for (const session of sessions) {
    const { browser, os, mobile } = parseDevice(session.userAgent);
    const key = session.client ? `app:${session.client.clientId}` : `device:${browser}|${os}`;
    let group = groups.get(key);
    if (!group) {
      group = session.client
        ? { key, kind: 'app', title: session.client.name, mobile: false, sessions: [], lastSeenAt: session.lastSeenAt }
        : { key, kind: 'device', title: `${browser} · ${os}`, mobile, sessions: [], lastSeenAt: session.lastSeenAt };
      groups.set(key, group);
    }
    group.sessions.push(session);
    if (session.lastSeenAt > group.lastSeenAt) group.lastSeenAt = session.lastSeenAt;
  }
  return [...groups.values()].sort((a, b) => b.lastSeenAt.localeCompare(a.lastSeenAt));
}

const plural = (n: number, word: string) => `${n} ${word}${n > 1 ? 's' : ''}`;

function ipSummary(sessions: SessionInfo[]): string {
  const ips = [...new Set(sessions.map((s) => s.ip).filter(Boolean))] as string[];
  if (ips.length === 0) return 'IP inconnue';
  return ips.length === 1 ? ips[0] : `${ips[0]} +${ips.length - 1}`;
}

function SessionIcon({ kind, mobile }: { kind: 'device' | 'app'; mobile: boolean }) {
  const Icon = kind === 'app' ? AppsIcon : mobile ? PhoneIcon : DeviceIcon;
  return (
    <div className="grid size-9 shrink-0 place-items-center rounded-[var(--radius-control)] bg-surface-2 text-muted">
      <Icon size={18} />
    </div>
  );
}

export default function SessionsManager({ accessToken }: { accessToken: string }) {
  const { confirm, toast } = useOverlay();
  const [sessions, setSessions] = useState<SessionInfo[] | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set());
  const [showAll, setShowAll] = useState(false);

  useEffect(() => {
    ApiService.getSessions(accessToken)
      .then((data) => {
        setError('');
        setSessions(data.sessions);
      })
      .catch(() => setError('Les sessions n’ont pas pu être chargées.'));
  }, [accessToken]);

  const current = sessions?.find((s) => s.current) ?? null;
  const groups = useMemo(() => groupSessions((sessions ?? []).filter((s) => !s.current)), [sessions]);
  const others = groups.reduce((n, g) => n + g.sessions.length, 0);

  const removeLocally = (ids: string[]) =>
    setSessions((prev) => prev?.filter((s) => !ids.includes(s.id)) ?? null);

  const toggle = (key: string) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  const revokeOne = async (session: SessionInfo) => {
    setBusy(session.id);
    try {
      await ApiService.revokeSession(accessToken, session.id);
      removeLocally([session.id]);
      toast('Session fermée.');
    } catch {
      toast('La session n’a pas pu être fermée.', 'danger');
    } finally {
      setBusy(null);
    }
  };

  const revokeGroup = async (group: SessionGroup) => {
    const count = group.sessions.length;
    const ok = await confirm({
      title: count > 1 ? `Fermer les ${count} sessions ?` : 'Fermer cette session ?',
      description:
        group.kind === 'app'
          ? `${group.title} sera déconnecté de votre compte et devra vous reconnecter.`
          : `${group.title} sera déconnecté. Vous devrez vous y reconnecter.`,
      confirmLabel: count > 1 ? 'Tout fermer' : 'Fermer la session',
      tone: 'danger',
    });
    if (!ok) return;
    setBusy(group.key);
    const results = await Promise.allSettled(group.sessions.map((s) => ApiService.revokeSession(accessToken, s.id)));
    const closed = group.sessions.filter((_, i) => results[i].status === 'fulfilled').map((s) => s.id);
    removeLocally(closed);
    setBusy(null);
    if (closed.length === count) toast(count > 1 ? `${count} sessions fermées.` : 'Session fermée.');
    else toast('Certaines sessions n’ont pas pu être fermées.', 'danger');
  };

  const revokeOthers = async () => {
    const ok = await confirm({
      title: 'Fermer toutes les autres sessions ?',
      description: `${plural(others, 'session')} sur vos autres appareils et applications seront déconnectées. Cet appareil reste connecté.`,
      confirmLabel: 'Tout fermer',
      tone: 'danger',
    });
    if (!ok) return;
    setBusy('others');
    try {
      const closed = await ApiService.revokeOtherSessions(accessToken);
      setSessions((prev) => prev?.filter((s) => s.current) ?? null);
      toast(closed > 1 ? `${closed} sessions fermées.` : 'Session fermée.');
    } catch {
      toast('Les sessions n’ont pas pu être fermées.', 'danger');
    } finally {
      setBusy(null);
    }
  };

  if (error) return <Alert tone="danger">{error}</Alert>;
  if (!sessions) {
    return (
      <div className="space-y-3 py-1">
        <Skeleton className="h-12 w-full" />
        <Skeleton className="h-12 w-full" />
      </div>
    );
  }
  if (sessions.length === 0) {
    return <EmptyState icon={<DeviceIcon size={18} />} title="Aucune session ouverte" />;
  }

  const visibleGroups = showAll ? groups : groups.slice(0, VISIBLE_GROUPS);
  const hiddenGroups = groups.length - visibleGroups.length;

  return (
    <div>
      {current && (() => {
        const { browser, os, mobile } = parseDevice(current.userAgent);
        return (
          <div className="mb-3 flex items-center gap-3 rounded-[var(--radius-control)] border border-line bg-surface-2/50 px-3 py-3">
            <SessionIcon kind="device" mobile={mobile} />
            <div className="min-w-0 flex-1">
              <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm font-medium">
                <span className="truncate">{browser} · {os}</span>
                <Badge tone="accent">Cet appareil</Badge>
              </p>
              <p className="text-[13px] text-muted">
                Connecté depuis le {formatDate(current.createdAt)} · <span className="whitespace-nowrap font-mono text-xs">{current.ip ?? 'IP inconnue'}</span>
              </p>
            </div>
          </div>
        );
      })()}

      {groups.length > 0 && (
        <>
          <div className="flex flex-wrap items-center justify-between gap-2 pb-1">
            <p className="text-[13px] text-muted">
              {current ? 'Autres sessions' : 'Sessions'} : <span className="tabular">{plural(others, 'session')}</span>
              {groups.length > 1 && <> sur <span className="tabular">{groups.length}</span> appareils ou applications</>}
            </p>
            {current && others > 1 && (
              <Button variant="danger-ghost" size="sm" loading={busy === 'others'} disabled={busy !== null && busy !== 'others'} onClick={revokeOthers}>
                Fermer toutes les autres
              </Button>
            )}
          </div>

          <ul className="divide-y divide-line">
            {visibleGroups.map((group) => {
              const count = group.sessions.length;
              const isOpen = expanded.has(group.key);
              const panelId = `sessions-${group.key.replace(/[^a-z0-9]/gi, '-')}`;
              return (
                <li key={group.key} className="py-3">
                  <div className="flex items-center justify-between gap-3">
                    <button
                      type="button"
                      onClick={() => count > 1 && toggle(group.key)}
                      aria-expanded={count > 1 ? isOpen : undefined}
                      aria-controls={count > 1 ? panelId : undefined}
                      className={`flex min-w-0 flex-1 items-center gap-3 rounded-[var(--radius-control)] text-left ${count > 1 ? 'cursor-pointer' : 'cursor-default'}`}
                    >
                      <SessionIcon kind={group.kind} mobile={group.mobile} />
                      <span className="min-w-0">
                        <span className="flex items-center gap-2 text-sm font-medium">
                          <span className="truncate">{group.title}</span>
                          {count > 1 && <Badge mono>{count}</Badge>}
                          {count > 1 && (
                            <ChevronDownIcon size={14} className={`shrink-0 text-muted transition-transform ${isOpen ? 'rotate-180' : ''}`} />
                          )}
                        </span>
                        <span className="block text-[13px] text-muted">
                          {group.kind === 'app' ? 'Application · ' : ''}Actif {timeAgo(group.lastSeenAt)} · <span className="whitespace-nowrap font-mono text-xs">{ipSummary(group.sessions)}</span>
                        </span>
                      </span>
                    </button>
                    <Button
                      variant="ghost"
                      size="sm"
                      loading={busy === group.key}
                      disabled={busy !== null && busy !== group.key}
                      onClick={() => revokeGroup(group)}
                    >
                      {count > 1 ? 'Tout fermer' : 'Fermer'}
                    </Button>
                  </div>

                  {count > 1 && isOpen && (
                    <ul id={panelId} className="animate-enter ml-12 mt-2 divide-y divide-line border-l border-line pl-3">
                      {group.sessions.map((s) => (
                        <li key={s.id} className="flex items-center justify-between gap-3 py-2">
                          <p className="min-w-0 text-[13px] text-muted">
                            <span className="block truncate text-fg">Actif {timeAgo(s.lastSeenAt)}</span>
                            <span className="block">
                              Ouverte le {formatDate(s.createdAt, true)} · <span className="whitespace-nowrap font-mono text-xs">{s.ip ?? 'IP inconnue'}</span>
                            </span>
                          </p>
                          <Button
                            variant="ghost"
                            size="sm"
                            loading={busy === s.id}
                            disabled={busy !== null && busy !== s.id}
                            onClick={() => revokeOne(s)}
                          >
                            Fermer
                          </Button>
                        </li>
                      ))}
                    </ul>
                  )}
                </li>
              );
            })}
          </ul>

          {hiddenGroups > 0 && (
            <button
              type="button"
              onClick={() => setShowAll(true)}
              className="mt-1 text-[13px] font-medium text-accent-text hover:underline"
            >
              Afficher {hiddenGroups} de plus
            </button>
          )}
        </>
      )}
    </div>
  );
}
