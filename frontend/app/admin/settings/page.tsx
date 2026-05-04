'use client';

import { useEffect, useState } from 'react';
import { useAuth } from '@/contexts/AuthContext';
import { AdminApi } from '@/lib/adminApi';

export default function AdminSettingsPage() {
  const { accessToken } = useAuth();
  const [requireEmailVerification, setRequireEmailVerification] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  useEffect(() => {
    if (!accessToken) return;
    AdminApi.getSettings(accessToken)
      .then((s) => setRequireEmailVerification(s.requireEmailVerification))
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [accessToken]);

  async function handleSave() {
    if (!accessToken) return;
    setSaving(true);
    setError(null);
    setSuccess(false);
    try {
      const updated = await AdminApi.updateSettings(accessToken, { requireEmailVerification });
      setRequireEmailVerification(updated.requireEmailVerification);
      setSuccess(true);
      setTimeout(() => setSuccess(false), 3000);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Erreur inconnue');
    } finally {
      setSaving(false);
    }
  }

  if (loading) return <div className="p-8 text-gray-400">Chargement...</div>;

  return (
    <div className="p-8 max-w-2xl space-y-8">
      <h1 className="text-2xl font-bold text-white">Paramètres</h1>

      <div className="bg-gray-800 rounded-xl border border-gray-700 divide-y divide-gray-700">
        <div className="px-6 py-4">
          <h2 className="text-base font-semibold text-white">Inscription</h2>
        </div>

        <div className="px-6 py-5 flex items-center justify-between gap-6">
          <div>
            <p className="text-sm font-medium text-white">Vérification d'email obligatoire</p>
            <p className="mt-1 text-xs text-gray-400">
              Si activé, les nouveaux utilisateurs doivent confirmer leur adresse e-mail avant de pouvoir se connecter.
            </p>
          </div>
          <button
            type="button"
            onClick={() => setRequireEmailVerification((v) => !v)}
            className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 focus:ring-offset-gray-800 ${
              requireEmailVerification ? 'bg-indigo-600' : 'bg-gray-600'
            }`}
            role="switch"
            aria-checked={requireEmailVerification}
          >
            <span
              className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ${
                requireEmailVerification ? 'translate-x-5' : 'translate-x-0'
              }`}
            />
          </button>
        </div>
      </div>

      {error && (
        <p className="text-sm text-red-400">{error}</p>
      )}
      {success && (
        <p className="text-sm text-green-400">Paramètres sauvegardés.</p>
      )}

      <button
        type="button"
        onClick={handleSave}
        disabled={saving}
        className="px-5 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-sm font-semibold text-white transition-colors"
      >
        {saving ? 'Enregistrement...' : 'Enregistrer'}
      </button>
    </div>
  );
}
