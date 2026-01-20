'use client';

import { useSearchParams } from 'next/navigation';
import { Suspense } from 'react';

function ConsentContent() {
  const searchParams = useSearchParams();
  const clientId = searchParams.get('client_id');

  const handleApprove = async () => {
  // Au lieu de fetch, on redirige l'utilisateur vers le backend 
  // pour qu'il traite le POST et redirige physiquement le navigateur.
  const params = new URLSearchParams(searchParams.toString());
  params.set('approved', 'true');
  
  // On redirige vers l'endpoint du back qui va générer le code et rediriger vers 3001
  window.location.href = `http://localhost:3000/authorize?${params.toString()}`;
};

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="max-w-md w-full p-8 bg-white shadow rounded-lg text-center">
        <h1 className="text-2xl font-bold mb-4">Autorisation requise</h1>
        <p className="mb-6">
          L'application <strong>{clientId}</strong> souhaite accéder à votre compte MySSO.
        </p>
        <div className="flex gap-4 justify-center">
          <button 
            onClick={handleApprove}
            className="bg-indigo-600 text-white px-6 py-2 rounded hover:bg-indigo-700"
          >
            Accepter
          </button>
          <button className="bg-gray-200 px-6 py-2 rounded">Refuser</button>
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