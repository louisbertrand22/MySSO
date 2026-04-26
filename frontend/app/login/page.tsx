'use client';

import { Suspense, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { useAuth } from '@/contexts/AuthContext';
import AuthForm from '@/components/AuthForm';

function LoginContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { login } = useAuth();
  const [error, setError] = useState<string | null>(null);

  const returnTo = searchParams.get('returnTo');
  const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000';

  // Allow relative paths or full URLs pointing to the backend only (prevent open redirect)
  const isBackendUrl = returnTo && returnTo.startsWith(apiUrl);
  const safeRedirect = (returnTo && returnTo.startsWith('/')) || isBackendUrl ? returnTo : '/dashboard';

  const handleSubmit = async (email: string, password: string) => {
    setError(null);
    try {
      await login({ email, password });
      if (isBackendUrl) {
        window.location.href = safeRedirect!;
      } else {
        router.push(safeRedirect!);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
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
            Vous n'avez pas de compte ?{' '}
            <Link href={registerHref} className="font-medium text-indigo-400 hover:text-indigo-300">
              S'inscrire pour un compte gratuit
            </Link>
          </p>
        </div>

        <div className="mt-8 bg-gray-800 py-8 px-4 shadow-lg sm:rounded-lg sm:px-10">
          <AuthForm mode="login" onSubmit={handleSubmit} error={error} />
          <div className="mt-4 text-center">
            <Link href="/forgot-password" className="text-sm text-indigo-400 hover:text-indigo-300">
              Mot de passe oublié ?
            </Link>
          </div>
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
