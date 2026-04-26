'use client';

import { Suspense, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { useAuth } from '@/contexts/AuthContext';
import AuthForm from '@/components/AuthForm';

function RegisterContent() {
  const searchParams = useSearchParams();
  const { register } = useAuth();
  const [error, setError] = useState<string | null>(null);
  const [verificationEmail, setVerificationEmail] = useState<string | null>(null);

  const returnTo = searchParams.get('returnTo');
  const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000';
  const isBackendUrl = returnTo && returnTo.startsWith(apiUrl);

  const loginHref = returnTo
    ? `/login?returnTo=${encodeURIComponent(returnTo)}`
    : '/login';

  const handleSubmit = async (email: string, password: string) => {
    setError(null);
    try {
      await register({ email, password });
      setVerificationEmail(email);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Une erreur est survenue lors de l\'inscription');
    }
  };

  if (verificationEmail) {
    return (
      <div className="flex-1 flex items-center justify-center bg-gray-900 py-12 px-4">
        <div className="max-w-md w-full space-y-8">
          <div className="bg-gray-800 py-8 px-6 shadow-lg rounded-xl text-center space-y-5">
            <div className="w-16 h-16 bg-indigo-900/40 rounded-full flex items-center justify-center mx-auto">
              <svg className="w-9 h-9 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
              </svg>
            </div>
            <div>
              <h2 className="text-xl font-bold text-white">Vérifiez votre e-mail</h2>
              <p className="mt-2 text-sm text-gray-400">
                Un lien d'activation a été envoyé à{' '}
                <span className="text-white font-medium">{verificationEmail}</span>.
                <br />
                Cliquez sur le lien pour activer votre compte.
              </p>
            </div>
            <p className="text-xs text-gray-500">
              Le lien expire dans 24 heures.
            </p>
            <Link
              href={loginHref}
              className="inline-block text-sm text-indigo-400 hover:text-indigo-300 font-medium"
            >
              ← Retour à la connexion
            </Link>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1 flex items-center justify-center bg-gray-900 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-white">
            Créer votre compte MySSO
          </h2>
          <p className="mt-2 text-center text-sm text-gray-300">
            Vous avez déjà un compte ?{' '}
            <Link href={loginHref} className="font-medium text-indigo-400 hover:text-indigo-300">
              Se connecter
            </Link>
          </p>
        </div>

        <div className="mt-8 bg-gray-800 py-8 px-4 shadow sm:rounded-lg sm:px-10">
          <AuthForm mode="register" onSubmit={handleSubmit} error={error} />
        </div>
      </div>
    </div>
  );
}

export default function RegisterPage() {
  return (
    <Suspense>
      <RegisterContent />
    </Suspense>
  );
}
