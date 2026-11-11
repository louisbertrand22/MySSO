'use client';

import { Suspense, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { useAuth } from '@/contexts/AuthContext';
import { ApiService } from '@/lib/api';
import AuthForm from '@/components/AuthForm';
import { resolveReturnTo } from '@/lib/redirect';
import AuthShell, { StatusIcon } from '@/components/AuthShell';
import { Button, TextLink } from '@/components/ui/Button';
import { Alert } from '@/components/ui/Feedback';
import { ArrowLeftIcon, MailIcon } from '@/components/ui/Icons';

// API error codes → messages for the user
const LOGIN_ERRORS: Record<string, string> = {
  'Invalid credentials': 'Adresse e-mail ou mot de passe incorrect.',
  account_disabled: 'Ce compte a été désactivé. Contactez l’administrateur.',
  too_many_requests: 'Trop de tentatives. Patientez quelques minutes avant de réessayer.',
  server_error: 'Le service rencontre un problème. Réessayez dans quelques instants.',
};

function LoginContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { login } = useAuth();
  const [error, setError] = useState<string | null>(null);
  const [unverifiedEmail, setUnverifiedEmail] = useState<string | null>(null);
  const [resendLoading, setResendLoading] = useState(false);
  const [resendDone, setResendDone] = useState(false);

  const returnTo = searchParams.get('returnTo');
  const redirect = resolveReturnTo(returnTo);

  const handleSubmit = async (email: string, password: string) => {
    setError(null);
    setUnverifiedEmail(null);
    setResendDone(false);
    try {
      await login({ email, password });
      if (redirect.external) {
        window.location.href = redirect.href;
      } else {
        router.push(redirect.href);
      }
  } catch (err: unknown) {
      // Backend sometimes returns a thrown object with { error: 'email_not_verified', email }
      // AuthContext.login currently re-throws the parsed error which may be an Error with
      // attached fields or a plain object. Be defensive and support several shapes.
      let code: string | undefined;
      let emailFromErr: string | undefined;

      if (!err) {
        setError('La connexion a échoué. Réessayez.');
        return;
      }

      // If it's an Error instance with extra properties
      if (err instanceof Error) {
        // try direct properties first (narrow unknown -> record safely)
        const asObj = err as unknown as Record<string, unknown>;
        code = (asObj['code'] as string | undefined) || (asObj['error'] as string | undefined);
        emailFromErr = asObj['email'] as string | undefined;

        // Some errors may have a JSON string in message (e.g. thrown from fetch). Try to parse it.
        if (!code) {
          try {
            const parsed = JSON.parse(err.message);
            code = parsed?.error || parsed?.code;
            emailFromErr = parsed?.email;
          } catch {}
        }
      } else if (typeof err === 'object' && err !== null) {
        // Plain object thrown
        const obj = err as Record<string, unknown>;
        code = (obj['code'] as string | undefined) || (obj['error'] as string | undefined);
        emailFromErr = obj['email'] as string | undefined;
      } else if (typeof err === 'string') {
        // Might be a JSON string
        try {
          const parsed = JSON.parse(err);
          code = parsed?.error || parsed?.code;
          emailFromErr = parsed?.email;
        } catch {
            // fallback to string message
            setError(err);
          return;
        }
      }

      if (code === 'email_not_verified') {
        setUnverifiedEmail(emailFromErr || email);
      } else {
        setError(LOGIN_ERRORS[code ?? ''] ?? 'La connexion a échoué. Réessayez.');
      }
    }
  };

  const handleResend = async () => {
    if (!unverifiedEmail) return;
    setResendLoading(true);
    try {
      await ApiService.resendVerification(unverifiedEmail);
      setResendDone(true);
    } catch {
      // always show success to avoid leaking info
      setResendDone(true);
    } finally {
      setResendLoading(false);
    }
  };

  const registerHref = returnTo
    ? `/register?returnTo=${encodeURIComponent(returnTo)}`
    : '/register';

  if (unverifiedEmail) {
    return (
      <AuthShell
        icon={<StatusIcon tone="warning"><MailIcon size={20} /></StatusIcon>}
        title="Confirmez votre adresse e-mail"
        description={<>Un lien d’activation a été envoyé à <span className="font-medium text-fg">{unverifiedEmail}</span>. Cliquez dessus pour activer votre compte, puis reconnectez-vous.</>}
      >
        <div className="space-y-3">
          {resendDone ? (
            <Alert tone="success">Un nouveau lien vient d’être envoyé.</Alert>
          ) : (
            <Button className="w-full" size="lg" loading={resendLoading} onClick={handleResend}>
              Renvoyer le lien
            </Button>
          )}
          <Button
            variant="ghost"
            className="w-full"
            onClick={() => { setUnverifiedEmail(null); setResendDone(false); }}
          >
            <ArrowLeftIcon size={16} /> Retour à la connexion
          </Button>
        </div>
      </AuthShell>
    );
  }

  return (
    <AuthShell
      title="Connexion"
      description="Un seul compte pour toutes vos applications."
      below={<>Pas encore de compte ? <TextLink href={registerHref}>Créer un compte</TextLink></>}
    >
      <AuthForm
        mode="login"
        onSubmit={handleSubmit}
        error={error}
        passwordAside={<TextLink href="/forgot-password" className="text-[13px]">Mot de passe oublié ?</TextLink>}
      />
    </AuthShell>
  );
}

export default function LoginPage() {
  return (
    <Suspense>
      <LoginContent />
    </Suspense>
  );
}
