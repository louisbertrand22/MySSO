'use client';

import { useState, Suspense } from 'react';
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

  const handleSubmit = async (email: string, password: string) => {
    setError(null);
    try {
      await register({ email, password });

      if (returnTo) {
        const decodedPath = decodeURIComponent(returnTo);
        const baseUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000';
        const fullUrl = new URL(decodedPath, baseUrl).toString();
        setTimeout(() => {
          window.location.replace(fullUrl);
        }, 100);
      } else {
        router.push('/dashboard');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred during registration');
    }
  };

  return (
    <div className="flex-1 flex items-center justify-center bg-gray-900 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-white">
            Créer votre compte MySSO
          </h2>
          <p className="mt-2 text-center text-sm text-gray-300">
            Vous avez déjà un compte ?{' '}
            <Link href={returnTo ? `/login?returnTo=${encodeURIComponent(returnTo)}` : '/login'} className="font-medium text-indigo-400 hover:text-indigo-300">
              Se connecter
            </Link>
          </p>
        </div>
        
        <div className="mt-8 bg-gray-800 py-8 px-4 shadow-lg sm:rounded-lg sm:px-10">
          <AuthForm mode="register" onSubmit={handleSubmit} error={error} />
        </div>
      </div>
    </div>
  );
}

export default function RegisterPage() {
  return (
    <Suspense fallback={<div className="flex justify-center p-10">Loading...</div>}>
      <RegisterContent />
    </Suspense>
  );
}
