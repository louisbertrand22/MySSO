'use client';

import { useSearchParams } from 'next/navigation';
import { Suspense, useState, useEffect } from 'react';

interface Scope {
  name: string;
  description: string;
}

interface ConsentData {
  client: {
    id: string;
    name: string;
  };
  scopes: Scope[];
  redirect_uri: string;
  state?: string;
}

function ConsentContent() {
  const searchParams = useSearchParams();
  const clientId = searchParams.get('client_id');
  const [consentData, setConsentData] = useState<ConsentData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchConsentData = async () => {
      try {
        const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000';
        const params = new URLSearchParams(searchParams.toString());
        const response = await fetch(`${apiUrl}/consent?${params.toString()}`, {
          credentials: 'include', // Include cookies for authentication
        });

        if (!response.ok) {
          throw new Error('Failed to load consent information');
        }

        const data = await response.json();
        setConsentData(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'An error occurred');
      } finally {
        setLoading(false);
      }
    };

    fetchConsentData();
  }, [searchParams]);

  const handleApprove = async () => {
    // Au lieu de fetch, on redirige l'utilisateur vers le backend 
    // pour qu'il traite le POST et redirige physiquement le navigateur.
    const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000';
    const params = new URLSearchParams(searchParams.toString());
    params.set('approved', 'true');
    
    // On redirige vers l'endpoint du back qui va générer le code et rediriger vers 3001
    window.location.href = `${apiUrl}/authorize?${params.toString()}`;
  };

  const handleDeny = async () => {
    const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000';
    const params = new URLSearchParams(searchParams.toString());
    params.set('approved', 'false');
    
    window.location.href = `${apiUrl}/authorize?${params.toString()}`;
  };

  if (loading) {
    return (
      <div className="flex-1 flex items-center justify-center bg-gray-50">
        <div className="text-center">
          <p className="text-gray-600">Chargement...</p>
        </div>
      </div>
    );
  }

  if (error || !consentData) {
    return (
      <div className="flex-1 flex items-center justify-center bg-gray-50">
        <div className="max-w-md w-full p-8 bg-white shadow rounded-lg text-center">
          <h1 className="text-2xl font-bold mb-4 text-red-600">Erreur</h1>
          <p className="mb-6 text-gray-700">{error || 'Unable to load consent information'}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1 flex items-center justify-center bg-gray-50">
      <div className="max-w-md w-full p-8 bg-white shadow rounded-lg">
        <h1 className="text-2xl font-bold mb-4 text-center text-gray-900">Autorisation requise</h1>
        <p className="mb-6 text-center text-gray-700">
          L'application <strong>{consentData.client.name}</strong> souhaite accéder à votre compte MySSO.
        </p>
        
        {consentData.scopes && consentData.scopes.length > 0 && (
          <div className="mb-6">
            <h2 className="text-lg font-semibold mb-3 text-gray-800">Permissions demandées :</h2>
            <ul className="space-y-2">
              {consentData.scopes.map((scope) => (
                <li key={scope.name} className="flex items-start">
                  <svg className="w-5 h-5 text-indigo-600 mt-0.5 mr-2 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                  </svg>
                  <div>
                    <p className="font-medium text-gray-900">{scope.name}</p>
                    <p className="text-sm text-gray-600">{scope.description}</p>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        )}
        
        <div className="flex gap-4 justify-center">
          <button 
            onClick={handleApprove}
            className="bg-indigo-600 text-white px-6 py-2 rounded hover:bg-indigo-700 transition-colors"
          >
            Accepter
          </button>
          <button 
            onClick={handleDeny}
            className="bg-gray-400 text-white px-6 py-2 rounded hover:bg-gray-500 transition-colors"
          >
            Refuser
          </button>
        </div>
      </div>
    </div>
  );
}

export default function ConsentPage() {
  return (
    <Suspense fallback={<div>Chargement du consentement...</div>}>
      <ConsentContent />
    </Suspense>
  );
}