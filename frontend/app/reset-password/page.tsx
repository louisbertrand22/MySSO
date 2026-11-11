'use client';

import { Suspense, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import AuthShell, { StatusIcon } from '@/components/AuthShell';
import { Button, ButtonLink } from '@/components/ui/Button';
import { Field, PasswordInput } from '@/components/ui/Field';
import { Alert } from '@/components/ui/Feedback';
import { AlertIcon, CheckIcon } from '@/components/ui/Icons';
import { passwordError } from '@/lib/password';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000';

function ResetPasswordContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const token = searchParams.get('token') || '';
  const [newPassword, setNewPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [done, setDone] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const policyError = passwordError(newPassword);
    if (policyError) {
      setError(policyError);
      return;
    }
    if (newPassword !== confirm) {
      setError('Les deux mots de passe sont différents.');
      return;
    }
    setLoading(true);
    setError('');
    try {
      const res = await fetch(`${API_URL}/auth/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, newPassword }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error_description || 'Ce lien est invalide ou a expiré.');
      setDone(true);
      setTimeout(() => router.push('/login'), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Le serveur ne répond pas. Réessayez.');
    } finally {
      setLoading(false);
    }
  };

  if (!token) {
    return (
      <AuthShell
        icon={<StatusIcon tone="danger"><AlertIcon size={20} /></StatusIcon>}
        title="Lien incomplet"
        description="Ce lien de réinitialisation est incomplet ou incorrect. Faites une nouvelle demande."
      >
        <ButtonLink href="/forgot-password" className="w-full">Nouvelle demande</ButtonLink>
      </AuthShell>
    );
  }

  if (done) {
    return (
      <AuthShell
        icon={<StatusIcon tone="accent"><CheckIcon size={20} /></StatusIcon>}
        title="Mot de passe modifié"
        description="Toutes vos sessions ont été fermées par sécurité. Redirection vers la connexion…"
      >
        <ButtonLink href="/login" className="w-full">Se connecter</ButtonLink>
      </AuthShell>
    );
  }

  return (
    <AuthShell title="Nouveau mot de passe" description="Le lien expire au bout d’une heure et ne sert qu’une fois.">
      <form onSubmit={handleSubmit} className="space-y-4">
        {error && <Alert tone="danger">{error}</Alert>}
        <Field label="Nouveau mot de passe" hint="8 caractères minimum, avec une majuscule, une minuscule et un chiffre.">
          <PasswordInput required autoComplete="new-password" autoFocus value={newPassword} onChange={(e) => setNewPassword(e.target.value)} />
        </Field>
        <Field label="Confirmer le mot de passe">
          <PasswordInput required autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
        </Field>
        <Button type="submit" size="lg" className="w-full" loading={loading}>
          Enregistrer le mot de passe
        </Button>
      </form>
    </AuthShell>
  );
}

export default function ResetPasswordPage() {
  return (
    <Suspense>
      <ResetPasswordContent />
    </Suspense>
  );
}
