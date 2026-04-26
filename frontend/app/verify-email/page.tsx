'use client';

import { Suspense, useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import Link from 'next/link';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000';

type Status = 'loading' | 'success' | 'error';

function VerifyEmailContent() {
  const searchParams = useSearchParams();
  const [status, setStatus] = useState<Status>('loading');
  const [message, setMessage] = useState('');

  useEffect(() => {
    const token = searchParams.get('token');

    if (!token) {
      setStatus('error');
      setMessage('Lien invalide — aucun token présent dans l\'URL.');
      return;
    }

    fetch(`${API_URL}/auth/verify-email?token=${encodeURIComponent(token)}`)
      .then(async (res) => {
        const data = await res.json();
        if (res.ok) {
          setStatus('success');
          setMessage(data.message || 'Adresse e-mail vérifiée avec succès.');
        } else {
          setStatus('error');
          setMessage(data.error_description || 'Lien invalide ou expiré.');
        }
      })
      .catch(() => {
        setStatus('error');
        setMessage('Erreur réseau. Réessayez plus tard.');
      });
  }, [searchParams]);

  return (
    <div className="flex-1 flex items-center justify-center bg-gray-900 py-12 px-4">
      <div className="max-w-md w-full">
        <div className="bg-gray-800 py-8 px-6 shadow-lg rounded-xl text-center space-y-5">
          {status === 'loading' && (
            <>
              <div className="inline-block animate-spin rounded-full h-12 w-12 border-4 border-indigo-400 border-t-indigo-600 mx-auto" />
              <p className="text-gray-400 text-sm">Vérification en cours...</p>
            </>
          )}

          {status === 'success' && (
            <>
              <div className="w-16 h-16 bg-green-900/40 rounded-full flex items-center justify-center mx-auto">
                <svg className="w-9 h-9 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
              </div>
              <div>
                <p className="text-white font-semibold text-lg">E-mail vérifié !</p>
                <p className="text-sm text-gray-400 mt-1">{message}</p>
              </div>
              <Link
                href="/login"
                className="inline-block py-2.5 px-6 bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-700 hover:to-purple-700 text-white font-semibold rounded-xl shadow transition-all text-sm"
              >
                Se connecter
              </Link>
            </>
          )}

          {status === 'error' && (
            <>
              <div className="w-16 h-16 bg-red-900/40 rounded-full flex items-center justify-center mx-auto">
                <svg className="w-9 h-9 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </div>
              <div>
                <p className="text-white font-semibold text-lg">Lien invalide</p>
                <p className="text-sm text-gray-400 mt-1">{message}</p>
              </div>
              <Link
                href="/login"
                className="inline-block text-sm text-indigo-400 hover:text-indigo-300 font-medium"
              >
                ← Retour à la connexion
              </Link>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

export default function VerifyEmailPage() {
  return (
    <Suspense>
      <VerifyEmailContent />
    </Suspense>
  );
}
