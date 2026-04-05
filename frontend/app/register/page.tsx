'use client';

import { Suspense, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { useAuth } from '@/contexts/AuthContext';
import AuthForm from '@/components/AuthForm';

function RegisterContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { register } = useAuth();
  const [error, setError] = useState<string | null>(null);

  const returnTo = searchParams.get('returnTo');
  // Only allow relative paths to prevent open redirect
  const safeRedirect = returnTo && returnTo.startsWith('/') ? returnTo : '/dashboard';

  const handleSubmit = async (email: string, password: string) => {
    setError(null);
    try {
      await register({ email, password });
      router.push(safeRedirect);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred during registration');
    }
  };

  const loginHref = returnTo
    ? `/login?returnTo=${encodeURIComponent(returnTo)}`
    : '/login';

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
