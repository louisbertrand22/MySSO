'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/contexts/AuthContext';
import { useTheme } from '@/contexts/ThemeContext';
import AppHeader, { Avatar, THEME_OPTIONS } from '@/components/AppHeader';
import ConsentsManager from '@/components/ConsentsManager';
import ChangePasswordForm from '@/components/ChangePasswordForm';
import InstallApp from '@/components/InstallApp';
import SessionsManager from '@/components/SessionsManager';
import { Section, Row } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Input, Segmented } from '@/components/ui/Field';
import { PageLoader } from '@/components/ui/Feedback';
import { CopyIcon, DownloadIcon } from '@/components/ui/Icons';
import { useOverlay } from '@/components/ui/Overlays';
import { ApiService } from '@/lib/api';
import { validateUsername } from '@/lib/validation';
import { formatDate } from '@/lib/format';

const SECTIONS = [
  { id: 'profil', label: 'Profil' },
  { id: 'securite', label: 'Sécurité' },
  { id: 'applications', label: 'Applications' },
  { id: 'preferences', label: 'Préférences' },
];

function UsernameRow() {
  const { user, accessToken, refreshAccessToken } = useAuth();
  const { toast } = useOverlay();
  const [editing, setEditing] = useState(false);
  const [value, setValue] = useState('');
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);

  if (!user) return null;

  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!accessToken) return;
    const validation = validateUsername(value);
    if (!validation.isValid) {
      setError(validation.error || 'Nom d’utilisateur invalide.');
      return;
    }
    setSaving(true);
    setError('');
    try {
      await ApiService.updateProfile(accessToken, value);
      await refreshAccessToken(); // the username lives in the access token
      setEditing(false);
      toast('Nom d’utilisateur enregistré.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Le nom d’utilisateur n’a pas pu être enregistré.');
    } finally {
      setSaving(false);
    }
  };

  if (editing) {
    return (
      <form onSubmit={save} className="space-y-2">
        <div className="flex max-w-sm gap-2">
          <Input
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="camille_r"
            disabled={saving}
            autoFocus
            aria-label="Nom d’utilisateur"
            aria-invalid={error ? true : undefined}
            className="h-8"
          />
          <Button type="submit" size="sm" loading={saving}>Enregistrer</Button>
          <Button variant="ghost" size="sm" onClick={() => { setEditing(false); setError(''); }} disabled={saving}>Annuler</Button>
        </div>
        {error ? <p className="text-[13px] text-danger-text">{error}</p> : <p className="text-[13px] text-muted">3 à 20 caractères : lettres, chiffres, _ et -.</p>}
      </form>
    );
  }

  return (
    <div className="flex items-center justify-between gap-4">
      <span className={user.username ? '' : 'text-muted'}>{user.username || 'Non défini'}</span>
      <Button variant="secondary" size="sm" onClick={() => { setValue(user.username || ''); setEditing(true); }}>
        {user.username ? 'Modifier' : 'Définir'}
      </Button>
    </div>
  );
}

export default function DashboardPage() {
  const router = useRouter();
  const { user, accessToken, isLoading, logout } = useAuth();
  const { preference, setPreference } = useTheme();
  const { confirm, toast } = useOverlay();

  useEffect(() => {
    if (!isLoading && !user) {
      router.push('/login');
    }
  }, [user, isLoading, router]);

  const copyId = async () => {
    if (!user) return;
    try {
      await navigator.clipboard.writeText(user.id);
      toast('Identifiant copié.');
    } catch {
      toast('La copie a échoué.', 'danger');
    }
  };

  const [exporting, setExporting] = useState(false);
  const exportData = async () => {
    if (!accessToken) return;
    setExporting(true);
    try {
      const { blob, filename } = await ApiService.exportData(accessToken);
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      toast('Export téléchargé.');
    } catch {
      toast('L’export n’a pas pu être généré.', 'danger');
    } finally {
      setExporting(false);
    }
  };

  const deleteAccount = async () => {
    if (!user || !accessToken) return;
    const ok = await confirm({
      title: 'Supprimer définitivement votre compte ?',
      description: 'Vos sessions, accès accordés aux applications et données de profil seront effacés. Cette action est irréversible.',
      confirmLabel: 'Supprimer mon compte',
      tone: 'danger',
      requireText: user.email,
    });
    if (!ok) return;
    try {
      await ApiService.deleteAccount(accessToken);
      await logout();
      router.push('/login');
    } catch (err) {
      toast(err instanceof Error ? err.message : 'Le compte n’a pas pu être supprimé.', 'danger');
    }
  };

  if (isLoading || !user) {
    return <PageLoader label="Chargement de votre compte…" />;
  }

  const name = user.username || user.email.split('@')[0];

  return (
    <div className="flex flex-1 flex-col">
      <AppHeader />

      <main id="main" className="mx-auto w-full max-w-3xl flex-1 px-5 pb-20 pt-10 sm:px-8">
        <div className="flex items-center gap-4">
          <Avatar name={name} size={52} />
          <div className="min-w-0">
            <h1 className="truncate text-2xl font-semibold tracking-tight">Bonjour, {name}</h1>
            <p className="truncate text-sm text-muted">{user.email}</p>
          </div>
        </div>

        <nav aria-label="Sections du compte" className="sticky top-14 z-20 mt-8 flex gap-1 overflow-x-auto border-b border-line bg-bg/85 backdrop-blur-md">
          {SECTIONS.map((s) => (
            <a key={s.id} href={`#${s.id}`} className="whitespace-nowrap border-b-2 border-transparent px-2.5 pb-2.5 pt-3 text-sm text-muted transition-colors hover:border-line-strong hover:text-fg">
              {s.label}
            </a>
          ))}
        </nav>

        <div className="mt-8 space-y-6">
          <Section id="profil" title="Profil" description="Les informations partagées avec les applications que vous autorisez.">
            <dl>
              <Row label="Nom d’utilisateur"><UsernameRow /></Row>
              <Row label="Adresse e-mail">{user.email}</Row>
              <Row label="Membre depuis">{formatDate(user.createdAt)}</Row>
              <Row label="Identifiant" last>
                <button type="button" onClick={copyId} className="group inline-flex max-w-full items-center gap-2 font-mono text-xs text-muted hover:text-fg" title="Copier l’identifiant">
                  <span className="truncate">{user.id}</span>
                  <CopyIcon size={14} className="shrink-0 opacity-60 group-hover:opacity-100" />
                </button>
              </Row>
            </dl>
          </Section>

          <Section id="securite" title="Sécurité" description="Votre mot de passe et les appareils connectés à votre compte.">
            <dl>
              <Row label="Mot de passe">{accessToken && <ChangePasswordForm accessToken={accessToken} />}</Row>
            </dl>
            <h3 className="mb-1 mt-5 text-sm font-medium">Sessions ouvertes</h3>
            <p className="mb-3 text-[13px] text-muted">Fermez les sessions que vous ne reconnaissez pas.</p>
            {accessToken && <SessionsManager accessToken={accessToken} />}
          </Section>

          <Section id="applications" title="Applications autorisées" description="Les applications qui peuvent utiliser votre compte MySSO.">
            {accessToken && <ConsentsManager accessToken={accessToken} />}
          </Section>

          <Section id="preferences" title="Préférences">
            <dl>
              <Row label="Thème">
                <Segmented label="Thème" value={preference} onChange={setPreference} options={THEME_OPTIONS} />
              </Row>
              <Row label="Application" last>
                <InstallApp />
              </Row>
            </dl>
          </Section>

          <Section id="donnees" title="Vos données" description="Téléchargez une copie de tout ce que MySSO conserve sur vous (RGPD, art. 15 et 20).">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <p className="max-w-md text-sm text-muted">
                Profil, sessions, applications autorisées et activité de sécurité, au format JSON. Votre mot de passe et vos jetons n’y figurent pas.
              </p>
              <Button variant="secondary" size="sm" loading={exporting} onClick={exportData}>
                <DownloadIcon size={15} /> Exporter mes données
              </Button>
            </div>
          </Section>

          <Section title="Supprimer le compte" tone="danger" description="Efface votre compte et toutes les données associées (RGPD, art. 17).">
            <Button variant="danger" size="sm" onClick={deleteAccount}>Supprimer mon compte</Button>
          </Section>
        </div>
      </main>
    </div>
  );
}
