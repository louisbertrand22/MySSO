'use client';

import { useState } from 'react';
import Link from 'next/link';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000';

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState('');
  const [submitted, setSubmitted] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const res = await fetch(`${API_URL}/auth/forgot-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      });
      if (res.status === 429) {
        throw new Error('Trop de tentatives. Réessayez dans une heure.');
      }
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.error_description || 'Erreur serveur');
      }
      setSubmitted(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Erreur serveur');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex-1 flex items-center justify-center bg-gray-900 py-12 px-4">
      <div className="max-w-md w-full space-y-8">
        <div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-white">
            Mot de passe oublié
          </h2>
          <p className="mt-2 text-center text-sm text-gray-400">
            <Link href="/login" className="font-medium text-indigo-400 hover:text-indigo-300">
              ← Retour à la connexion
            </Link>
          </p>
        </div>

        <div className="bg-gray-800 py-8 px-6 shadow-lg rounded-xl">
          {submitted ? (
            <div className="text-center space-y-4">
              <div className="w-14 h-14 bg-green-900/40 rounded-full flex items-center justify-center mx-auto">
                <svg className="w-8 h-8 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
              </div>
              <p className="text-white font-semibold">E-mail envoyé</p>
              <p className="text-sm text-gray-400">
                Si un compte existe pour <span className="text-white">{email}</span>, vous recevrez un lien de réinitialisation valable <strong>1 heure</strong>.
              </p>
              <Link href="/login" className="inline-block mt-2 text-indigo-400 hover:text-indigo-300 text-sm font-medium">
                Retour à la connexion
              </Link>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-5">
              <p className="text-sm text-gray-400">
                Saisissez votre adresse e-mail. Si un compte lui est associé, vous recevrez un lien de réinitialisation.
              </p>
              <div>
                <label htmlFor="email" className="block text-sm font-medium text-gray-300 mb-1">
                  Adresse e-mail
                </label>
                <input
                  id="email"
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full px-4 py-2.5 bg-gray-700 border border-gray-600 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 text-sm"
                  placeholder="vous@exemple.com"
                />
              </div>
              {error && <p className="text-sm text-red-400">{error}</p>}
              <button
                type="submit"
                disabled={loading}
                className="w-full py-2.5 px-4 bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-700 hover:to-purple-700 disabled:opacity-50 text-white font-semibold rounded-xl shadow transition-all text-sm"
              >
                {loading ? 'Envoi...' : 'Envoyer le lien de réinitialisation'}
              </button>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
