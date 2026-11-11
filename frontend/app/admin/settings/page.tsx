'use client';

import { useEffect, useState } from 'react';
import { useAuth } from '@/contexts/AuthContext';
import { AdminApi } from '@/lib/adminApi';
import { PageHeader, Section } from '@/components/ui/Card';
import { Switch } from '@/components/ui/Field';
import { Alert, Skeleton } from '@/components/ui/Feedback';
import { useOverlay } from '@/components/ui/Overlays';

export default function AdminSettingsPage() {
  const { accessToken } = useAuth();
  const { toast } = useOverlay();
  const [requireEmailVerification, setRequireEmailVerification] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!accessToken) return;
    AdminApi.getSettings(accessToken)
      .then((s) => setRequireEmailVerification(s.requireEmailVerification))
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [accessToken]);

  // Settings are saved as soon as they change: no separate "Save" step to forget
  const toggleEmailVerification = async (value: boolean) => {
    if (!accessToken) return;
    const previous = requireEmailVerification;
    setRequireEmailVerification(value);
    setSaving(true);
    try {
      const updated = await AdminApi.updateSettings(accessToken, { requireEmailVerification: value });
      setRequireEmailVerification(updated.requireEmailVerification);
      toast(value ? 'Vérification de l’e-mail activée.' : 'Vérification de l’e-mail désactivée.');
    } catch (e) {
      setRequireEmailVerification(previous);
      toast(e instanceof Error ? e.message : 'Le paramètre n’a pas pu être enregistré.', 'danger');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="max-w-3xl space-y-6">
      <PageHeader title="Paramètres" description="Les réglages s’appliquent immédiatement à tous les utilisateurs." />

      {error && <Alert tone="danger">{error}</Alert>}

      <Section title="Inscription">
        <div className="flex items-center justify-between gap-6 py-1">
          <div className="space-y-1">
            <p className="text-sm font-medium">Vérification de l’e-mail obligatoire</p>
            <p className="text-sm text-muted">
              Les nouveaux comptes doivent confirmer leur adresse e-mail avant de pouvoir se connecter.
            </p>
          </div>
          {loading ? (
            <Skeleton className="h-6 w-10 rounded-full" />
          ) : (
            <Switch label="Vérification de l’e-mail obligatoire" checked={requireEmailVerification} onChange={toggleEmailVerification} disabled={saving} />
          )}
        </div>
      </Section>
    </div>
  );
}
