'use client';

import { Suspense, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { useAuth } from '@/contexts/AuthContext';
import { ApiService } from '@/lib/api';
import AuthForm from '@/components/AuthForm';

function LoginContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { login } = useAuth();
  const [error, setError] = useState<string | null>(null);
  const [unverifiedEmail, setUnverifiedEmail] = useState<string | null>(null);
  const [resendLoading, setResendLoading] = useState(false);
  const [resendDone, setResendDone] = useState(false);

  const returnTo = searchParams.get('returnTo');
  const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000';

  const isBackendUrl = returnTo && returnTo.startsWith(apiUrl);
  const safeRedirect = (returnTo && returnTo.startsWith('/')) || isBackendUrl ? returnTo : '/dashboard';

  const handleSubmit = async (email: string, password: string) => {
    setError(null);
    setUnverifiedEmail(null);
    setResendDone(false);
    try {
      await login({ email, password });
      if (isBackendUrl) {
        window.location.href = safeRedirect!;
      } else {
        router.push(safeRedirect!);
      }
  } catch (err: unknown) {
      // Backend sometimes returns a thrown object with { error: 'email_not_verified', email }
      // AuthContext.login currently re-throws the parsed error which may be an Error with
      // attached fields or a plain object. Be defensive and support several shapes.
      let code: string | undefined;
      let emailFromErr: string | undefined;

      if (!err) {
        setError('Login failed');
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
        setError(err instanceof Error ? err.message : 'Login failed');
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

  return (
    <div className="flex-1 flex items-center justify-center bg-gray-900 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-white">
            Se connecter à MySSO
          </h2>
          <p className="mt-2 text-center text-sm text-gray-300">
            Vous n&apos;avez pas de compte ?{' '}
            <Link href={registerHref} className="font-medium text-indigo-400 hover:text-indigo-300">
                S&apos;inscrire pour un compte gratuit
            </Link>
          </p>
        </div>

        <div className="mt-8 bg-gray-800 py-8 px-4 shadow-lg sm:rounded-lg sm:px-10">
          {unverifiedEmail ? (
            <div className="space-y-4 text-center">
              <div className="w-14 h-14 bg-yellow-900/40 rounded-full flex items-center justify-center mx-auto">
                <svg className="w-8 h-8 text-yellow-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                </svg>
              </div>
              <p className="text-white font-semibold">E-mail non vérifié</p>
              <p className="text-sm text-gray-400">
                Vérifiez votre boîte mail pour{' '}
                <span className="text-white">{unverifiedEmail}</span>{' '}
                et cliquez sur le lien d&apos;activation.
              </p>
              {resendDone ? (
                <p className="text-sm text-green-400">Un nouveau lien a été envoyé.</p>
              ) : (
                <button
                  onClick={handleResend}
                  disabled={resendLoading}
                  className="w-full py-2.5 px-4 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white font-semibold rounded-xl shadow transition-all text-sm"
                >
                  {resendLoading ? 'Envoi...' : 'Renvoyer le lien de vérification'}
                </button>
              )}
              <button
                onClick={() => { setUnverifiedEmail(null); setResendDone(false); }}
                className="text-sm text-gray-400 hover:text-gray-300"
              >
                ← Retour
              </button>
            </div>
          ) : (
            <>
              <AuthForm mode="login" onSubmit={handleSubmit} error={error} />
              <div className="mt-4 text-center">
                <Link href="/forgot-password" className="text-sm text-indigo-400 hover:text-indigo-300">
                  Mot de passe oublié ?
                </Link>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense>
      <LoginContent />
    </Suspense>
  );
}
