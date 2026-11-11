'use client';

import { Suspense, useState } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import { useAuth } from '@/contexts/AuthContext';
import AuthForm from '@/components/AuthForm';
import AuthShell, { StatusIcon } from '@/components/AuthShell';
import { ButtonLink, TextLink } from '@/components/ui/Button';
import { ArrowLeftIcon, MailIcon } from '@/components/ui/Icons';

function RegisterContent() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const { register } = useAuth();
  const [error, setError] = useState<string | null>(null);
  const [verificationEmail, setVerificationEmail] = useState<string | null>(null);

  const returnTo = searchParams.get('returnTo');

  const loginHref = returnTo
    ? `/login?returnTo=${encodeURIComponent(returnTo)}`
    : '/login';

  const handleSubmit = async (email: string, password: string) => {
    setError(null);
    try {
      const result = await register({ email, password });
      if (result.requireEmailVerification) {
        setVerificationEmail(email);
      } else {
        router.push(loginHref);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'L’inscription a échoué. Réessayez.');
    }
  };

  if (verificationEmail) {
    return (
      <AuthShell
        icon={<StatusIcon tone="accent"><MailIcon size={20} /></StatusIcon>}
        title="Vérifiez votre boîte mail"
        description={<>Un lien d’activation a été envoyé à <span className="font-medium text-fg">{verificationEmail}</span>. Il reste valable 24 heures.</>}
      >
        <ButtonLink href={loginHref} variant="secondary" className="w-full">
          <ArrowLeftIcon size={16} /> Retour à la connexion
        </ButtonLink>
      </AuthShell>
    );
  }

  return (
    <AuthShell
      title="Créer un compte"
      description="Votre compte MySSO vous connecte à toutes les applications partenaires."
      below={<>Déjà inscrit ? <TextLink href={loginHref}>Se connecter</TextLink></>}
    >
      <AuthForm mode="register" onSubmit={handleSubmit} error={error} />
    </AuthShell>
  );
}

export default function RegisterPage() {
  return (
    <Suspense>
      <RegisterContent />
    </Suspense>
  );
}
