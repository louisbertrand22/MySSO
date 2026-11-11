'use client';

import { useRouter, useSearchParams } from 'next/navigation';
import { Suspense, useState, useEffect, useCallback } from 'react';
import { useAuth } from '@/contexts/AuthContext';
import AuthShell, { StatusIcon } from '@/components/AuthShell';
import { Button, ButtonLink, TextLink } from '@/components/ui/Button';
import { Alert, Skeleton } from '@/components/ui/Feedback';
import { AlertIcon, CheckIcon, ExternalIcon } from '@/components/ui/Icons';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000';

interface Scope {
  name: string;
  description: string;
}

interface ConsentData {
  client: {
    id: string;
    name: string;
  };
  scopes: Scope[];
  redirect_uri: string;
  state?: string;
}

function ConsentContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { user, accessToken, isLoading, refreshAccessToken, logout } = useAuth();
  const [consentData, setConsentData] = useState<ConsentData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState<'approve' | 'deny' | null>(null);

  // Not logged in: go through the login page and come back here
  useEffect(() => {
    if (!isLoading && !user) {
      const here = `/consent?${searchParams.toString()}`;
      router.replace(`/login?returnTo=${encodeURIComponent(here)}`);
    }
  }, [isLoading, user, router, searchParams]);

  useEffect(() => {
    if (!accessToken) return;
    const controller = new AbortController();
    fetch(`${API_URL}/consent?${searchParams.toString()}`, {
      headers: { Authorization: `Bearer ${accessToken}` },
      signal: controller.signal,
    })
      .then(async (response) => {
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
          throw new Error(data.error_description || 'Impossible de charger la demande d’autorisation.');
        }
        setConsentData(data);
      })
      .catch((err) => {
        if (err.name !== 'AbortError') setError(err.message);
      });
    return () => controller.abort();
  }, [accessToken, searchParams]);

  const submitDecision = useCallback(
    async (approved: boolean) => {
      if (!accessToken || !consentData) return;
      setSubmitting(approved ? 'approve' : 'deny');
      setError(null);

      const body = {
        client_id: consentData.client.id,
        redirect_uri: consentData.redirect_uri,
        approved,
        scope: consentData.scopes.map((s) => s.name),
        state: searchParams.get('state') ?? undefined,
        nonce: searchParams.get('nonce') ?? undefined,
        code_challenge: searchParams.get('code_challenge') ?? undefined,
        code_challenge_method: searchParams.get('code_challenge_method') ?? undefined,
      };

      const send = (token: string) =>
        fetch(`${API_URL}/auth/authorize`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          body: JSON.stringify(body),
        });

      try {
        let response = await send(accessToken);
        if (response.status === 401) {
          // Access token expired while the page was open: refresh once and retry
          await refreshAccessToken();
          const fresh = localStorage.getItem('accessToken');
          if (fresh) response = await send(fresh);
        }
        const data = await response.json().catch(() => ({}));
        if (!response.ok || !data.redirect_to) {
          throw new Error(data.error_description || 'La décision n’a pas pu être enregistrée.');
        }
        window.location.href = data.redirect_to;
      } catch (err) {
        setError(err instanceof Error ? err.message : 'La décision n’a pas pu être enregistrée.');
        setSubmitting(null);
      }
    },
    [accessToken, consentData, refreshAccessToken, searchParams]
  );

  const switchAccount = async () => {
    await logout();
    const here = `/consent?${searchParams.toString()}`;
    router.replace(`/login?returnTo=${encodeURIComponent(here)}`);
  };

  if (error && !consentData) {
    return (
      <AuthShell
        icon={<StatusIcon tone="danger"><AlertIcon size={20} /></StatusIcon>}
        title="Autorisation impossible"
        description={error}
      >
        <ButtonLink href="/dashboard" variant="secondary" className="w-full">Aller à mon compte</ButtonLink>
      </AuthShell>
    );
  }

  if (isLoading || !user || !consentData) {
    return (
      <AuthShell title={<Skeleton className="h-6 w-56" />}>
        <div className="space-y-3">
          <Skeleton className="h-14 w-full" />
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      </AuthShell>
    );
  }

  const redirectHost = (() => {
    try {
      return new URL(consentData.redirect_uri).host;
    } catch {
      return consentData.redirect_uri;
    }
  })();

  return (
    <AuthShell
      title={<><span className="text-accent-text">{consentData.client.name}</span> souhaite accéder à votre compte</>}
      below={<>Vous pourrez retirer cet accès à tout moment depuis <TextLink href="/dashboard#applications">votre compte</TextLink>.</>}
    >
      <div className="space-y-5">
        <div className="flex items-center gap-3 rounded-[var(--radius-control)] border border-line bg-surface-2 px-3 py-2.5">
          <div className="grid size-8 shrink-0 place-items-center rounded-[7px] bg-accent-soft text-sm font-semibold text-accent-text">
            {(user.username || user.email).charAt(0).toUpperCase()}
          </div>
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-medium">{user.username || user.email}</p>
            {user.username && <p className="truncate text-[13px] text-muted">{user.email}</p>}
          </div>
          <button type="button" onClick={switchAccount} className="shrink-0 text-[13px] font-medium text-muted hover:text-fg">
            Pas vous ?
          </button>
        </div>

        {consentData.scopes.length > 0 && (
          <div className="space-y-2.5">
            <p className="text-sm font-medium">Cette application pourra :</p>
            <ul className="space-y-2">
              {consentData.scopes.map((scope) => (
                <li key={scope.name} className="flex gap-2.5 text-sm">
                  <CheckIcon size={16} className="mt-0.5 shrink-0 text-accent-text" />
                  <span>
                    {scope.description || scope.name}
                    <span className="ml-1.5 font-mono text-xs text-subtle">{scope.name}</span>
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}

        <p className="flex items-center gap-2 text-[13px] text-muted">
          <ExternalIcon size={14} className="shrink-0" />
          Vous serez redirigé vers <span className="font-medium text-fg">{redirectHost}</span>
        </p>

        {error && <Alert tone="danger">{error}</Alert>}

        <div className="grid grid-cols-2 gap-2.5">
          <Button variant="secondary" size="lg" onClick={() => submitDecision(false)} loading={submitting === 'deny'} disabled={submitting !== null}>
            Refuser
          </Button>
          <Button size="lg" onClick={() => submitDecision(true)} loading={submitting === 'approve'} disabled={submitting !== null}>
            Autoriser
          </Button>
        </div>
      </div>
    </AuthShell>
  );
}

export default function ConsentPage() {
  return (
    <Suspense>
      <ConsentContent />
    </Suspense>
  );
}
