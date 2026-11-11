'use client';

import { Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import AuthShell, { StatusIcon } from '@/components/AuthShell';
import { ButtonLink } from '@/components/ui/Button';
import { AlertIcon, LockIcon, XIcon } from '@/components/ui/Icons';

type Kind = 'denied' | 'invalid' | 'server';

const ERROR_CONFIG: Record<string, { title: string; description: string; kind: Kind }> = {
  access_denied: {
    title: 'Accès refusé',
    description: 'Vous avez refusé l’accès à cette application. Vous pouvez fermer cette fenêtre ou revenir à l’application.',
    kind: 'denied',
  },
  invalid_client: {
    title: 'Application inconnue',
    description: 'Cette application n’est pas enregistrée ou a été désactivée. Contactez son développeur.',
    kind: 'invalid',
  },
  invalid_request: {
    title: 'Demande incomplète',
    description: 'La demande de connexion contient des paramètres manquants ou incorrects.',
    kind: 'invalid',
  },
  unauthorized_client: {
    title: 'Application non autorisée',
    description: 'Cette application n’a pas le droit d’utiliser ce mode de connexion.',
    kind: 'invalid',
  },
  invalid_scope: {
    title: 'Permissions invalides',
    description: 'Les permissions demandées par cette application n’existent pas ou ne lui sont pas accordées.',
    kind: 'invalid',
  },
  server_error: {
    title: 'Erreur du serveur',
    description: 'Une erreur interne s’est produite. Réessayez dans quelques instants.',
    kind: 'server',
  },
  temporarily_unavailable: {
    title: 'Service indisponible',
    description: 'Le service est momentanément indisponible. Réessayez dans quelques instants.',
    kind: 'server',
  },
};

const DEFAULT_ERROR = {
  title: 'Connexion impossible',
  description: 'Une erreur s’est produite pendant la connexion à l’application.',
  kind: 'server' as Kind,
};

function OAuthErrorContent() {
  const searchParams = useSearchParams();
  const errorCode = searchParams.get('error') || '';
  const errorDescription = searchParams.get('error_description');
  const clientName = searchParams.get('client_name');
  const config = ERROR_CONFIG[errorCode] || DEFAULT_ERROR;

  const icon =
    config.kind === 'denied' ? (
      <StatusIcon tone="warning"><XIcon size={20} /></StatusIcon>
    ) : config.kind === 'invalid' ? (
      <StatusIcon tone="danger"><LockIcon size={20} /></StatusIcon>
    ) : (
      <StatusIcon tone="neutral"><AlertIcon size={20} /></StatusIcon>
    );

  return (
    <AuthShell
      icon={icon}
      title={config.title}
      description={
        <div className="space-y-3">
          {clientName && <p className="font-medium text-fg">{clientName}</p>}
          <p>{errorDescription || config.description}</p>
          {errorCode && <p className="font-mono text-xs text-subtle">Code : {errorCode}</p>}
        </div>
      }
    >
      <div className="space-y-2.5">
        {errorCode !== 'access_denied' && <ButtonLink href="/login" className="w-full">Retour à la connexion</ButtonLink>}
        <ButtonLink href="/" variant={errorCode === 'access_denied' ? 'primary' : 'ghost'} className="w-full">
          Accueil MySSO
        </ButtonLink>
      </div>
    </AuthShell>
  );
}

export default function OAuthErrorPage() {
  return (
    <Suspense>
      <OAuthErrorContent />
    </Suspense>
  );
}
