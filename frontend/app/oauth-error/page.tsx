'use client';

import { Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import Link from 'next/link';

const ERROR_CONFIG: Record<string, { title: string; description: string; icon: 'denied' | 'invalid' | 'server' }> = {
  access_denied: {
    title: 'Accès refusé',
    description: "Vous avez refusé l'autorisation à cette application. Vous pouvez fermer cette fenêtre ou retourner à l'application.",
    icon: 'denied',
  },
  invalid_client: {
    title: 'Application non reconnue',
    description: "L'application qui tente de se connecter n'est pas enregistrée ou a été désactivée. Contactez le développeur de l'application.",
    icon: 'invalid',
  },
  invalid_request: {
    title: 'Requête invalide',
    description: "La requête d'autorisation contient des paramètres manquants ou incorrects.",
    icon: 'invalid',
  },
  unauthorized_client: {
    title: 'Application non autorisée',
    description: "Cette application n'est pas autorisée à utiliser ce type d'autorisation.",
    icon: 'invalid',
  },
  invalid_scope: {
    title: 'Permissions invalides',
    description: "Les permissions demandées par cette application sont invalides ou non supportées.",
    icon: 'invalid',
  },
  server_error: {
    title: 'Erreur serveur',
    description: "Une erreur interne s'est produite. Veuillez réessayer dans quelques instants.",
    icon: 'server',
  },
  temporarily_unavailable: {
    title: 'Service temporairement indisponible',
    description: 'Le service est temporairement indisponible. Veuillez réessayer dans quelques instants.',
    icon: 'server',
  },
};

const DEFAULT_ERROR = {
  title: "Erreur d'autorisation",
  description: "Une erreur s'est produite lors du processus d'autorisation.",
  icon: 'server' as const,
};

function DeniedIcon() {
  return (
    <div className="mx-auto flex items-center justify-center h-20 w-20 rounded-full bg-orange-100 dark:bg-orange-900/30">
      <svg className="h-10 w-10 text-orange-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
      </svg>
    </div>
  );
}

function InvalidIcon() {
  return (
    <div className="mx-auto flex items-center justify-center h-20 w-20 rounded-full bg-red-100 dark:bg-red-900/30">
      <svg className="h-10 w-10 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
      </svg>
    </div>
  );
}

function ServerIcon() {
  return (
    <div className="mx-auto flex items-center justify-center h-20 w-20 rounded-full bg-gray-100 dark:bg-gray-700">
      <svg className="h-10 w-10 text-gray-500 dark:text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
      </svg>
    </div>
  );
}

function OAuthErrorContent() {
  const searchParams = useSearchParams();
  const errorCode = searchParams.get('error') || '';
  const errorDescription = searchParams.get('error_description');
  const clientName = searchParams.get('client_name');

  const config = ERROR_CONFIG[errorCode] || DEFAULT_ERROR;

  return (
    <div className="flex-1 flex items-center justify-center bg-gray-50 dark:bg-gray-900 py-12 px-4">
      <div className="max-w-md w-full">
        <div className="bg-white dark:bg-gray-800 shadow-xl rounded-2xl overflow-hidden border border-gray-100 dark:border-gray-700">
          <div className="px-8 pt-10 pb-8 text-center">
            {config.icon === 'denied' && <DeniedIcon />}
            {config.icon === 'invalid' && <InvalidIcon />}
            {config.icon === 'server' && <ServerIcon />}

            <h1 className="mt-6 text-2xl font-bold text-gray-900 dark:text-white">
              {config.title}
            </h1>

            {clientName && (
              <p className="mt-2 text-sm font-medium text-indigo-600 dark:text-indigo-400">
                {clientName}
              </p>
            )}

            <p className="mt-3 text-sm text-gray-500 dark:text-gray-400 leading-relaxed">
              {errorDescription || config.description}
            </p>

            {errorCode && (
              <div className="mt-4 inline-flex items-center px-3 py-1 rounded-full bg-gray-100 dark:bg-gray-700">
                <code className="text-xs text-gray-600 dark:text-gray-300 font-mono">{errorCode}</code>
              </div>
            )}
          </div>

          <div className="px-8 pb-8 flex flex-col gap-3">
            {errorCode === 'access_denied' ? (
              <p className="text-center text-sm text-gray-400 dark:text-gray-500">
                Vous pouvez fermer cette fenêtre.
              </p>
            ) : (
              <Link
                href="/login"
                className="w-full flex justify-center py-2.5 px-4 rounded-xl text-sm font-semibold text-white bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-700 hover:to-purple-700 transition-all duration-200 shadow-md"
              >
                Retour à la connexion
              </Link>
            )}

            <a
              href="/"
              className="w-full flex justify-center py-2.5 px-4 rounded-xl text-sm font-semibold text-gray-600 dark:text-gray-400 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 transition-all duration-200"
            >
              Page d'accueil
            </a>
          </div>
        </div>

        <p className="mt-6 text-center text-xs text-gray-400 dark:text-gray-600">
          MySSO — Système d'authentification sécurisé
        </p>
      </div>
    </div>
  );
}

export default function OAuthErrorPage() {
  return (
    <Suspense>
      <OAuthErrorContent />
    </Suspense>
  );
}
