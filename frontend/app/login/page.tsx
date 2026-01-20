'use client';

import { useState, Suspense } from 'react';
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

  const handleSubmit = async (email: string, password: string) => {
    setError(null);
    try {
      await login({ email, password });
      
      if (returnTo) {
        // 1. Décoder le paramètre pour obtenir le chemin (ex: /authorize?...)
        const decodedPath = decodeURIComponent(returnTo);
        
        // 2. Construire une URL absolue propre vers le BACKEND (3000)
        const baseUrl = "http://localhost:3000";
        const fullUrl = new URL(decodedPath, baseUrl).toString();

        console.log("Redirection forcée vers :", fullUrl);

        // 3. Utiliser un délai et replace pour forcer le navigateur
        setTimeout(() => {
          window.location.replace(fullUrl);
        }, 100);
      } else {
        router.push('/dashboard');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
            Sign in to MySSO
          </h2>
          <p className="mt-2 text-center text-sm text-gray-600">
            Connect to access <strong>WatchAsset</strong>
          </p>
        </div>
        
        <div className="mt-8 bg-white py-8 px-4 shadow sm:rounded-lg sm:px-10">
          <AuthForm mode="login" onSubmit={handleSubmit} error={error} />
        </div>
      </div>
    </div>
  );
}

// Le composant doit être enveloppé dans Suspense pour Next.js
export default function LoginPage() {
  return (
    <Suspense fallback={<div className="flex justify-center p-10">Loading auth form...</div>}>
      <LoginContent />
    </Suspense>
  );
}