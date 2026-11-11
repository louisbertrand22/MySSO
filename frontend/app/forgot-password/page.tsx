'use client';

import { useState } from 'react';
import AuthShell, { StatusIcon } from '@/components/AuthShell';
import { Button, ButtonLink, TextLink } from '@/components/ui/Button';
import { Field, Input } from '@/components/ui/Field';
import { Alert } from '@/components/ui/Feedback';
import { ArrowLeftIcon, MailIcon } from '@/components/ui/Icons';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000';

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState('');
  const [submitted, setSubmitted] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const res = await fetch(`${API_URL}/auth/forgot-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      });
      if (res.status === 429) {
        throw new Error('Trop de demandes. Réessayez dans une heure.');
      }
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error_description || 'Le serveur ne répond pas. Réessayez.');
      }
      setSubmitted(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Le serveur ne répond pas. Réessayez.');
    } finally {
      setLoading(false);
    }
  };

  if (submitted) {
    return (
      <AuthShell
        icon={<StatusIcon tone="accent"><MailIcon size={20} /></StatusIcon>}
        title="Vérifiez votre boîte mail"
        description={<>Si un compte existe pour <span className="font-medium text-fg">{email}</span>, vous allez recevoir un lien de réinitialisation valable 1 heure.</>}
      >
        <ButtonLink href="/login" variant="secondary" className="w-full">
          <ArrowLeftIcon size={16} /> Retour à la connexion
        </ButtonLink>
      </AuthShell>
    );
  }

  return (
    <AuthShell
      title="Mot de passe oublié"
      description="Indiquez l’adresse e-mail de votre compte. Nous vous enverrons un lien pour choisir un nouveau mot de passe."
      below={<TextLink href="/login">Retour à la connexion</TextLink>}
    >
      <form onSubmit={handleSubmit} className="space-y-4">
        {error && <Alert tone="danger">{error}</Alert>}
        <Field label="Adresse e-mail">
          <Input
            type="email"
            required
            autoComplete="email"
            autoFocus
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="vous@exemple.fr"
          />
        </Field>
        <Button type="submit" size="lg" className="w-full" loading={loading}>
          Envoyer le lien
        </Button>
      </form>
    </AuthShell>
  );
}
