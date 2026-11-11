'use client';

import { Suspense, useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { useAuth } from '@/contexts/AuthContext';
import AuthShell, { StatusIcon } from '@/components/AuthShell';
import { ButtonLink } from '@/components/ui/Button';
import { Spinner } from '@/components/ui/Feedback';
import { AlertIcon } from '@/components/ui/Icons';

/**
 * OAuth2 Callback Page Content
 * Handles the authorization code callback from the SSO server
 */
function CallbackPageContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { setTokens } = useAuth();
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const handleCallback = async () => {
      try {
        // Get the authorization code from URL
        const code = searchParams?.get('code');
        
        if (!code) {
          setError('Aucun code d’autorisation n’a été reçu.');
          setLoading(false);
          return;
        }

        // Exchange the code for tokens
        const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000';
        const redirectUri = `${window.location.origin}/callback`;

        const response = await fetch(`${apiUrl}/token`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            grant_type: 'authorization_code',
            code: code,
            redirect_uri: redirectUri,
          }),
        });

        if (!response.ok) {
          const errorData = await response.json();
          throw new Error(errorData.error_description || 'L’échange du code a échoué.');
        }

        const data = await response.json();

        // Store the tokens
        if (data.access_token && data.refresh_token) {
          setTokens(data.access_token, data.refresh_token);
          
          // Redirect to dashboard
          router.push('/dashboard');
        } else {
          throw new Error('Réponse du serveur inattendue.');
        }
      } catch (err) {
        console.error('OAuth2 callback error:', err);
        setError(err instanceof Error ? err.message : 'Une erreur est survenue.');
        setLoading(false);
      }
    };

    handleCallback();
  }, [searchParams, router, setTokens]);

  if (loading) {
    return (
      <AuthShell icon={<StatusIcon tone="neutral"><Spinner size={18} /></StatusIcon>} title="Connexion en cours…">
        <p className="text-sm text-muted">Finalisation de l’autorisation.</p>
      </AuthShell>
    );
  }

  if (error) {
    return (
      <AuthShell
        icon={<StatusIcon tone="danger"><AlertIcon size={20} /></StatusIcon>}
        title="La connexion a échoué"
        description={error}
      >
        <ButtonLink href="/login" className="w-full">Retour à la connexion</ButtonLink>
      </AuthShell>
    );
  }

  return null;
}

/**
 * OAuth2 Callback Page
 * Wraps the content in Suspense boundary for useSearchParams
 */
export default function CallbackPage() {
  return (
    <Suspense fallback={<AuthShell title="Connexion en cours…"><Spinner /></AuthShell>}>
      <CallbackPageContent />
    </Suspense>
  );
}
