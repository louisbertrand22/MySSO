'use client';

import { useCallback, useEffect, useState } from 'react';
import { ApiService } from '@/lib/api';
import { Consent } from '@/lib/types';
import { formatDate } from '@/lib/format';
import { Button } from './ui/Button';
import { Alert, Badge, EmptyState, Skeleton } from './ui/Feedback';
import { AppsIcon } from './ui/Icons';
import { useOverlay } from './ui/Overlays';

export default function ConsentsManager({ accessToken }: { accessToken: string }) {
  const { confirm, toast } = useOverlay();
  const [consents, setConsents] = useState<Consent[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<string | null>(null);

  const loadConsents = useCallback(async () => {
    try {
      setIsLoading(true);
      setError(null);
      const data = await ApiService.getConsents(accessToken);
      setConsents(data.consents);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Les applications n’ont pas pu être chargées.');
    } finally {
      setIsLoading(false);
    }
  }, [accessToken]);

  useEffect(() => {
    loadConsents();
  }, [loadConsents]);

  const handleRevoke = async (consent: Consent) => {
    const ok = await confirm({
      title: `Retirer l’accès de ${consent.clientName} ?`,
      description: 'L’application sera déconnectée de votre compte. Elle vous redemandera votre accord à la prochaine connexion.',
      confirmLabel: 'Retirer l’accès',
      tone: 'danger',
    });
    if (!ok) return;

    try {
      setRevoking(consent.clientId);
      await ApiService.revokeConsent(accessToken, consent.clientId);
      setConsents((prev) => prev.filter((c) => c.clientId !== consent.clientId));
      toast(`Accès de ${consent.clientName} retiré.`);
    } catch (err) {
      toast(err instanceof Error ? err.message : 'L’accès n’a pas pu être retiré.', 'danger');
    } finally {
      setRevoking(null);
    }
  };

  if (isLoading) {
    return (
      <div className="space-y-3 py-1">
        <Skeleton className="h-14 w-full" />
        <Skeleton className="h-14 w-full" />
      </div>
    );
  }

  if (error) return <Alert tone="danger">{error}</Alert>;

  if (consents.length === 0) {
    return (
      <EmptyState icon={<AppsIcon size={18} />} title="Aucune application connectée">
        Quand vous autoriserez une application à utiliser votre compte MySSO, elle apparaîtra ici.
      </EmptyState>
    );
  }

  return (
    <ul className="-my-1 divide-y divide-line">
      {consents.map((consent) => (
        <li key={consent.id} className="flex flex-col gap-3 py-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex min-w-0 gap-3">
            <div className="grid size-9 shrink-0 place-items-center rounded-[var(--radius-control)] border border-line bg-surface-2 text-sm font-semibold">
              {consent.clientName.charAt(0).toUpperCase()}
            </div>
            <div className="min-w-0 space-y-1.5">
              <p className="text-sm font-medium">
                {consent.clientName}
                <span className="ml-2 font-normal text-subtle">autorisée le {formatDate(consent.createdAt)}</span>
              </p>
              <div className="flex flex-wrap gap-1">
                {consent.scopes.map((scope) => (
                  <Badge key={scope} mono>{scope}</Badge>
                ))}
              </div>
            </div>
          </div>
          <Button variant="secondary" size="sm" className="self-start sm:self-center" loading={revoking === consent.clientId} onClick={() => handleRevoke(consent)}>
            Retirer l’accès
          </Button>
        </li>
      ))}
    </ul>
  );
}
