'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { useAuth } from '@/contexts/AuthContext';
import AuthForm from '@/components/AuthForm';

export default function RegisterPage() {
  const router = useRouter();
  const { register } = useAuth();
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (email: string, password: string) => {
    setError(null);
    try {
      await register({ email, password });
      router.push('/dashboard');
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
            <Link href="/login" className="font-medium text-indigo-400 hover:text-indigo-300">
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
