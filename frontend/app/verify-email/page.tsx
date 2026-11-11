'use client';

import { Suspense, useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import AuthShell, { StatusIcon } from '@/components/AuthShell';
import { ButtonLink } from '@/components/ui/Button';
import { Spinner } from '@/components/ui/Feedback';
import { AlertIcon, CheckIcon } from '@/components/ui/Icons';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000';

type Status = 'loading' | 'success' | 'error';

function VerifyEmailContent() {
  const searchParams = useSearchParams();
  const token = searchParams.get('token');
  const [result, setResult] = useState<{ status: Exclude<Status, 'loading'>; message: string } | null>(null);
  const setStatus = (status: Exclude<Status, 'loading'>, message: string) => setResult({ status, message });

  useEffect(() => {
    if (!token) return;
    fetch(`${API_URL}/auth/verify-email?token=${encodeURIComponent(token)}`)
      .then(async (res) => {
        const data = await res.json().catch(() => ({}));
        if (res.ok) setStatus('success', data.message || 'Votre adresse e-mail est confirmée.');
        else setStatus('error', data.error_description || 'Ce lien est invalide ou a expiré.');
      })
      .catch(() => setStatus('error', 'Le serveur ne répond pas. Réessayez dans quelques instants.'));
  }, [token]);

  const status: Status = !token ? 'error' : result?.status ?? 'loading';
  const message = !token ? 'Le lien ne contient pas de jeton de vérification.' : result?.message ?? '';

  if (status === 'loading') {
    return (
      <AuthShell icon={<StatusIcon tone="neutral"><Spinner size={18} /></StatusIcon>} title="Vérification en cours…">
        <p className="text-sm text-muted">Nous confirmons votre adresse e-mail.</p>
      </AuthShell>
    );
  }

  if (status === 'success') {
    return (
      <AuthShell icon={<StatusIcon tone="accent"><CheckIcon size={20} /></StatusIcon>} title="Adresse e-mail confirmée" description={message}>
        <ButtonLink href="/login" size="lg" className="w-full">Se connecter</ButtonLink>
      </AuthShell>
    );
  }

  return (
    <AuthShell
      icon={<StatusIcon tone="danger"><AlertIcon size={20} /></StatusIcon>}
      title="Lien invalide"
      description={<>{message} Connectez-vous pour recevoir un nouveau lien.</>}
    >
      <ButtonLink href="/login" variant="secondary" className="w-full">Retour à la connexion</ButtonLink>
    </AuthShell>
  );
}

export default function VerifyEmailPage() {
  return (
    <Suspense>
      <VerifyEmailContent />
    </Suspense>
  );
}
