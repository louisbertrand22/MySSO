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
      setError(err instanceof Error ? err.message : 'Failed to load consents');
      console.error('Error loading consents:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadConsents();
  }, [accessToken]);

  const handleRevoke = async (clientId: string) => {
    if (!confirm('Are you sure you want to revoke access for this application? You will need to authorize it again to use it.')) {
      return;
    }

    try {
      setRevoking(clientId);
      await ApiService.revokeConsent(accessToken, clientId);
      
      // Remove the consent from the list
      setConsents(consents.filter(c => c.clientId !== clientId));
      
      // Show success message
      alert('Consent revoked successfully');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to revoke consent');
      console.error('Error revoking consent:', err);
    } finally {
      setRevoking(null);
    }
  };

  if (isLoading) {
    return (
      <div className="flex justify-center items-center py-8">
        <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-600"></div>
      </div>
    );
  }

  return (
    <div>
      {error && (
        <div className="mb-4 bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded">
          {error}
        </div>
      )}

      {consents.length === 0 ? (
        <div className="text-center py-8">
          <svg
            className="mx-auto h-12 w-12 text-gray-400"
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
          <h3 className="mt-2 text-sm font-medium text-gray-900">No authorized applications</h3>
          <p className="mt-1 text-sm text-gray-500">
            You haven't authorized any third-party applications yet.
          </p>
        </div>
      ) : (
        <div className="overflow-hidden">
          <ul className="divide-y divide-gray-200">
            {consents.map((consent) => (
              <li key={consent.id} className="py-4">
                <div className="flex items-center justify-between">
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-gray-900 truncate">
                      {consent.clientName}
                    </p>
                    <p className="text-sm text-gray-500">
                      Client ID: {consent.clientId}
                    </p>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {consent.scopes.map((scope) => (
                        <span
                          key={scope}
                          className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-indigo-100 text-indigo-800"
                        >
                          {scope}
                        </span>
                      ))}
                    </div>
                    <p className="mt-1 text-xs text-gray-500">
                      Authorized on {new Date(consent.createdAt).toLocaleDateString()}
                    </p>
                  </div>
                  <div className="ml-4 flex-shrink-0">
                    <button
                      onClick={() => handleRevoke(consent.clientId)}
                      disabled={revoking === consent.clientId}
                      className="inline-flex items-center px-3 py-2 border border-transparent text-sm leading-4 font-medium rounded-md text-red-700 bg-red-100 hover:bg-red-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      {revoking === consent.clientId ? (
                        <>
                          <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-red-700 mr-2"></div>
                          Revoking...
                        </>
                      ) : (
                        'Revoke Access'
                      )}
                    </button>
                  </div>
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
