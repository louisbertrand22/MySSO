'use client';

import { useCallback, useEffect, useState } from 'react';
import { useAuth } from '@/contexts/AuthContext';
import { AdminApi } from '@/lib/adminApi';
import { AdminClient } from '@/lib/types';
import { Card, PageHeader } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Field, Input, Textarea } from '@/components/ui/Field';
import { Alert, Badge, EmptyState, Skeleton } from '@/components/ui/Feedback';
import { Table, Td, Th, Tr } from '@/components/ui/Table';
import { AppsIcon, CopyIcon, PlusIcon } from '@/components/ui/Icons';
import { Dialog, useOverlay } from '@/components/ui/Overlays';

type Modal =
  | { type: 'create' }
  | { type: 'edit'; client: AdminClient }
  | { type: 'secret'; clientId: string; secret: string; isNew: boolean }
  | null;

const DEFAULT_SCOPES = 'openid profile email username';

function CopyValue({ label, value }: { label: string; value: string }) {
  const { toast } = useOverlay();
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      toast(`${label} copié.`);
    } catch {
      toast('La copie a échoué.', 'danger');
    }
  };
  return (
    <div className="space-y-1.5">
      <p className="text-[13px] text-muted">{label}</p>
      <div className="flex items-start gap-2 rounded-[var(--radius-control)] border border-line bg-surface-2 px-3 py-2">
        <code className="min-w-0 flex-1 break-all font-mono text-[13px]">{value}</code>
        <button type="button" onClick={copy} className="shrink-0 text-subtle hover:text-fg" aria-label={`Copier ${label}`}>
          <CopyIcon size={16} />
        </button>
      </div>
    </div>
  );
}

export default function AdminClientsPage() {
  const { accessToken } = useAuth();
  const { confirm, toast } = useOverlay();
  const [clients, setClients] = useState<AdminClient[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [modal, setModal] = useState<Modal>(null);
  const [acting, setActing] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const [formName, setFormName] = useState('');
  const [formRedirects, setFormRedirects] = useState('');
  const [formScopes, setFormScopes] = useState('');
  const [formTtl, setFormTtl] = useState('90');

  const load = useCallback(() => {
    if (!accessToken) return;
    setLoading(true);
    AdminApi.listClients(accessToken)
      .then((r) => setClients(r.clients))
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [accessToken]);

  useEffect(load, [load]);

  const openCreate = () => {
    setFormName(''); setFormRedirects(''); setFormScopes(DEFAULT_SCOPES); setFormTtl('90'); setFormError(null);
    setModal({ type: 'create' });
  };

  const openEdit = (c: AdminClient) => {
    setFormName(c.name);
    setFormRedirects(c.redirectUris.join('\n'));
    setFormScopes(c.allowedScopes.join(' '));
    setFormTtl(String(c.refreshTokenTtlDays ?? 90));
    setFormError(null);
    setModal({ type: 'edit', client: c });
  };

  const readForm = () => {
    const redirectUris = formRedirects.split('\n').map((s) => s.trim()).filter(Boolean);
    const allowedScopes = formScopes.split(/[\s,]+/).filter(Boolean);
    const ttl = Number(formTtl);
    if (!formName.trim()) return { error: 'Donnez un nom à l’application.' };
    if (redirectUris.length === 0) return { error: 'Ajoutez au moins une URL de redirection.' };
    if (!Number.isInteger(ttl) || ttl < 1 || ttl > 365) return { error: 'La durée de session doit être un nombre de jours entre 1 et 365.' };
    return { name: formName.trim(), redirectUris, allowedScopes, ttl };
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!accessToken || !modal || modal.type === 'secret') return;
    const form = readForm();
    if ('error' in form) {
      setFormError(form.error ?? null);
      return;
    }
    setSaving(true);
    setFormError(null);
    try {
      if (modal.type === 'create') {
        const result = await AdminApi.createClient(accessToken, form.name, form.redirectUris);
        // Creation only takes name + redirect URIs: apply scopes and lifetime right after
        await AdminApi.updateClient(accessToken, result.client_id, { allowedScopes: form.allowedScopes, refreshTokenTtlDays: form.ttl });
        setModal({ type: 'secret', clientId: result.client_id, secret: result.client_secret, isNew: true });
      } else {
        await AdminApi.updateClient(accessToken, modal.client.clientId, {
          name: form.name,
          redirectUris: form.redirectUris,
          allowedScopes: form.allowedScopes,
          refreshTokenTtlDays: form.ttl,
        });
        setModal(null);
        toast('Application mise à jour.');
      }
      load();
    } catch (err) {
      setFormError(err instanceof Error ? err.message : 'L’enregistrement a échoué.');
    } finally {
      setSaving(false);
    }
  };

  const rotateSecret = async (c: AdminClient) => {
    if (!accessToken) return;
    const ok = await confirm({
      title: `Générer un nouveau secret pour ${c.name} ?`,
      description: 'L’ancien secret cessera de fonctionner immédiatement. L’application devra être mise à jour avec le nouveau.',
      confirmLabel: 'Générer un nouveau secret',
      tone: 'danger',
    });
    if (!ok) return;
    setActing(c.clientId);
    try {
      const result = await AdminApi.rotateClientSecret(accessToken, c.clientId);
      setModal({ type: 'secret', clientId: result.client_id, secret: result.client_secret, isNew: false });
    } catch (err) {
      toast(err instanceof Error ? err.message : 'La génération a échoué.', 'danger');
    } finally {
      setActing(null);
    }
  };

  const deleteClient = async (c: AdminClient) => {
    if (!accessToken) return;
    const ok = await confirm({
      title: `Supprimer ${c.name} ?`,
      description: 'L’application ne pourra plus connecter personne. Les autorisations et sessions associées seront supprimées.',
      confirmLabel: 'Supprimer',
      tone: 'danger',
      requireText: c.name,
    });
    if (!ok) return;
    setActing(c.clientId);
    try {
      await AdminApi.deleteClient(accessToken, c.clientId);
      setClients((prev) => prev.filter((x) => x.clientId !== c.clientId));
      toast('Application supprimée.');
    } catch (err) {
      toast(err instanceof Error ? err.message : 'La suppression a échoué.', 'danger');
    } finally {
      setActing(null);
    }
  };

  const formOpen = modal?.type === 'create' || modal?.type === 'edit';

  return (
    <div className="space-y-6">
      <PageHeader
        title="Applications"
        description="Les applications autorisées à connecter leurs utilisateurs via MySSO."
        actions={<Button onClick={openCreate}><PlusIcon size={16} /> Nouvelle application</Button>}
      />

      {error && <Alert tone="danger">{error}</Alert>}

      <Card>
        {loading ? (
          <div className="space-y-2 p-5">{[0, 1].map((i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
        ) : clients.length === 0 ? (
          <div className="px-5">
            <EmptyState
              icon={<AppsIcon size={18} />}
              title="Aucune application"
              action={<Button size="sm" variant="secondary" onClick={openCreate}><PlusIcon size={15} /> Ajouter la première</Button>}
            >
              Enregistrez une application pour obtenir son identifiant et son secret.
            </EmptyState>
          </div>
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Application</Th>
                <Th>Scopes</Th>
                <Th align="right">Session</Th>
                <Th align="right">Utilisateurs</Th>
                <Th align="right"><span className="sr-only">Actions</span></Th>
              </tr>
            </thead>
            <tbody>
              {clients.map((c) => (
                <Tr key={c.clientId}>
                  <Td>
                    <p className="font-medium">{c.name}</p>
                    <p className="font-mono text-xs text-muted">{c.clientId}</p>
                  </Td>
                  <Td>
                    <div className="flex flex-wrap gap-1">
                      {c.allowedScopes.map((s) => <Badge key={s} mono>{s}</Badge>)}
                    </div>
                  </Td>
                  <Td align="right" className="tabular whitespace-nowrap text-muted">{c.refreshTokenTtlDays ?? 90} j</Td>
                  <Td align="right" className="tabular">{c._count.consents}</Td>
                  <Td align="right">
                    <div className="flex justify-end gap-1">
                      <Button variant="ghost" size="sm" onClick={() => openEdit(c)}>Modifier</Button>
                      <Button variant="ghost" size="sm" disabled={acting === c.clientId} onClick={() => rotateSecret(c)}>Nouveau secret</Button>
                      <Button variant="danger-ghost" size="sm" disabled={acting === c.clientId} onClick={() => deleteClient(c)}>Supprimer</Button>
                    </div>
                  </Td>
                </Tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>

      <Dialog
        open={formOpen}
        onClose={() => setModal(null)}
        size="lg"
        title={modal?.type === 'create' ? 'Nouvelle application' : 'Modifier l’application'}
      >
        <form id="client-form" onSubmit={handleSave} className="space-y-4">
          {formError && <Alert tone="danger">{formError}</Alert>}
          <Field label="Nom">
            <Input value={formName} onChange={(e) => setFormName(e.target.value)} placeholder="Carnet de notes" autoFocus />
          </Field>
          <Field label="URL de redirection" hint="Une par ligne. Elles doivent correspondre exactement à celles envoyées par l’application.">
            <Textarea rows={3} value={formRedirects} onChange={(e) => setFormRedirects(e.target.value)} placeholder="https://app.exemple.fr/auth/callback" className="font-mono text-[13px]" />
          </Field>
          <div className="grid gap-4 sm:grid-cols-[1fr_140px]">
            <Field label="Scopes autorisés" hint="Séparés par des espaces.">
              <Input value={formScopes} onChange={(e) => setFormScopes(e.target.value)} className="font-mono text-[13px]" />
            </Field>
            <Field label="Session (jours)" hint="Prolongée à chaque visite.">
              <Input type="number" min={1} max={365} value={formTtl} onChange={(e) => setFormTtl(e.target.value)} className="tabular" />
            </Field>
          </div>
          <div className="flex flex-col-reverse gap-2 pt-1 sm:flex-row sm:justify-end">
            <Button variant="secondary" onClick={() => setModal(null)} disabled={saving}>Annuler</Button>
            <Button type="submit" loading={saving}>{modal?.type === 'create' ? 'Créer l’application' : 'Enregistrer'}</Button>
          </div>
        </form>
      </Dialog>

      <Dialog
        open={modal?.type === 'secret'}
        onClose={() => setModal(null)}
        title={modal?.type === 'secret' && modal.isNew ? 'Application créée' : 'Nouveau secret généré'}
        description="Copiez le secret maintenant : il ne sera plus jamais affiché."
        footer={<Button onClick={() => setModal(null)}>J’ai copié le secret</Button>}
      >
        {modal?.type === 'secret' && (
          <div className="space-y-3">
            <CopyValue label="Client ID" value={modal.clientId} />
            <CopyValue label="Client secret" value={modal.secret} />
            <Alert tone="warning">Gardez ce secret côté serveur. Ne le placez jamais dans du code exécuté par le navigateur.</Alert>
          </div>
        )}
      </Dialog>
    </div>
  );
}
