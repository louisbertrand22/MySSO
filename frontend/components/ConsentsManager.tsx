'use client';

import { useState, useEffect } from 'react';
import { ApiService } from '@/lib/api';
import { Consent } from '@/lib/types';

interface ConsentsManagerProps {
  accessToken: string;
}

export default function ConsentsManager({ accessToken }: ConsentsManagerProps) {
  const [consents, setConsents] = useState<Consent[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<string | null>(null);

  const loadConsents = async () => {
    try {
      setIsLoading(true);
      setError(null);
      const data = await ApiService.getConsents(accessToken);
      setConsents(data.consents);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Échec du chargement des consentements');
      console.error('Error loading consents:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadConsents();
  }, [accessToken]);

  const handleRevoke = async (clientId: string) => {
    if (!confirm('Êtes-vous sûr de vouloir révoquer l\'accès pour cette application ? Vous devrez l\'autoriser à nouveau pour l\'utiliser.')) {
      return;
    }

    try {
      setRevoking(clientId);
      await ApiService.revokeConsent(accessToken, clientId);
      
      // Remove the consent from the list
      setConsents(consents.filter(c => c.clientId !== clientId));
      
      // Show success message
      alert('Consentement révoqué avec succès');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Échec de la révocation du consentement');
      console.error('Error revoking consent:', err);
    } finally {
      setRevoking(null);
    }
  };

  if (isLoading) {
    return (
      <div className="flex justify-center items-center py-12">
        <div className="inline-block animate-spin rounded-full h-10 w-10 border-4 border-indigo-400 border-t-indigo-600"></div>
      </div>
    );
  }

  return (
    <div>
      {error && (
        <div className="mb-4 bg-red-900/30 border-l-4 border-red-500 text-red-300 px-5 py-4 rounded-xl shadow-lg flex items-center gap-3">
          <svg className="w-5 h-5 text-red-400 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
          </svg>
          <span className="font-medium">{error}</span>
        </div>
      )}

      {consents.length === 0 ? (
        <div className="text-center py-12">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-gray-700 to-gray-800 mb-4">
            <svg
              className="w-8 h-8 text-gray-400"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              aria-hidden="true"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
              />
            </svg>
          </div>
          <h3 className="text-lg font-bold text-gray-200">Aucune application autorisée</h3>
          <p className="mt-2 text-sm text-gray-400 max-w-sm mx-auto">
            Vous n'avez pas encore autorisé d'applications tierces. Lorsque vous le ferez, elles apparaîtront ici.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {consents.map((consent) => (
            <div key={consent.id} className="p-5 bg-gradient-to-r from-gray-700/50 to-gray-800/50 rounded-xl border border-gray-600 hover:shadow-lg transition-all duration-200 hover:border-indigo-500">
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-3 mb-2">
                    <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-cyan-600 rounded-lg flex items-center justify-center flex-shrink-0 shadow">
                      <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                      </svg>
                    </div>
                    <div className="min-w-0 flex-1">
                      <p className="text-base font-bold text-gray-100 truncate">
                        {consent.clientName}
                      </p>
                      <p className="text-xs text-gray-400 font-mono mt-0.5">
                        {consent.clientId}
                      </p>
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-2 mb-3">
                    {consent.scopes.map((scope) => (
                      <span
                        key={scope}
                        className="inline-flex items-center px-3 py-1 rounded-lg text-xs font-semibold bg-gradient-to-r from-indigo-900/50 to-purple-900/50 text-indigo-300 border border-indigo-700"
                      >
                        {scope}
                      </span>
                    ))}
                  </div>
                  <div className="flex items-center gap-2 text-xs text-gray-400">
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                    </svg>
                    <span>Autorisé le {new Date(consent.createdAt).toLocaleDateString('fr-FR')}</span>
                  </div>
                </div>
                <div className="flex-shrink-0">
                  <button
                    onClick={() => handleRevoke(consent.clientId)}
                    disabled={revoking === consent.clientId}
                    className="inline-flex items-center px-4 py-2.5 border-2 border-red-600 text-sm font-semibold rounded-xl text-red-300 bg-red-900/30 hover:bg-red-900/50 hover:border-red-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200 hover:shadow-md"
                  >
                    {revoking === consent.clientId ? (
                      <>
                        <div className="animate-spin rounded-full h-4 w-4 border-2 border-red-400 border-t-red-700 mr-2"></div>
                        Révocation...
                      </>
                    ) : (
                      <>
                        <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                        </svg>
                        Révoquer l'accès
                      </>
                    )}
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
