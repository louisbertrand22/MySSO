'use client';

import { useRouter, useSearchParams } from 'next/navigation';
import { Suspense, useState, useEffect, useCallback } from 'react';
import { useAuth } from '@/contexts/AuthContext';

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
  const { user, accessToken, isLoading, refreshAccessToken } = useAuth();
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

  if (error && !consentData) {
    return (
      <div className="flex-1 flex items-center justify-center p-6">
        <div className="max-w-md w-full p-8 rounded-xl border border-zinc-200 dark:border-zinc-800 text-center">
          <h1 className="text-xl font-semibold mb-2">Autorisation impossible</h1>
          <p className="text-zinc-600 dark:text-zinc-400">{error}</p>
        </div>
      </div>
    );
  }

  if (isLoading || !user || !consentData) {
    return (
      <div className="flex-1 flex items-center justify-center p-6">
        <p className="text-zinc-500">Chargement…</p>
      </div>
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
    <div className="flex-1 flex items-center justify-center p-6">
      <div className="max-w-md w-full p-8 rounded-xl border border-zinc-200 dark:border-zinc-800">
        <h1 className="text-xl font-semibold mb-2">{consentData.client.name} demande l’accès à votre compte</h1>
        <p className="text-sm text-zinc-600 dark:text-zinc-400 mb-6">
          Connecté en tant que <strong>{user.email}</strong>
        </p>

        {consentData.scopes.length > 0 && (
          <ul className="space-y-3 mb-6">
            {consentData.scopes.map((scope) => (
              <li key={scope.name}>
                <p className="font-medium">{scope.description || scope.name}</p>
                <p className="text-xs text-zinc-500 font-mono">{scope.name}</p>
              </li>
            ))}
          </ul>
        )}

        <p className="text-sm text-zinc-600 dark:text-zinc-400 mb-6">
          Vous serez redirigé vers <strong>{redirectHost}</strong>.
        </p>

        {error && <p className="text-sm text-red-600 dark:text-red-400 mb-4">{error}</p>}

        <div className="flex gap-3">
          <button
            onClick={() => submitDecision(true)}
            disabled={submitting !== null}
            className="flex-1 bg-zinc-900 text-white dark:bg-white dark:text-zinc-900 px-4 py-2 rounded-lg disabled:opacity-50"
          >
            {submitting === 'approve' ? 'Autorisation…' : 'Autoriser'}
          </button>
          <button
            onClick={() => submitDecision(false)}
            disabled={submitting !== null}
            className="flex-1 border border-zinc-300 dark:border-zinc-700 px-4 py-2 rounded-lg disabled:opacity-50"
          >
            {submitting === 'deny' ? 'Refus…' : 'Refuser'}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function ConsentPage() {
  return (
    <Suspense>
      <ConsentContent />
    </Suspense>
  );
}
