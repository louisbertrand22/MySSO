'use client';

import { useCallback, useEffect, useState } from 'react';
import { useAuth } from '@/contexts/AuthContext';
import { AdminApi } from '@/lib/adminApi';
import { AdminScope } from '@/lib/types';
import { formatDate } from '@/lib/format';
import { Card, PageHeader } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Field, Input } from '@/components/ui/Field';
import { Alert, EmptyState, Skeleton } from '@/components/ui/Feedback';
import { Table, Td, Th, Tr } from '@/components/ui/Table';
import { TagIcon } from '@/components/ui/Icons';
import { useOverlay } from '@/components/ui/Overlays';

export default function AdminScopesPage() {
  const { accessToken } = useAuth();
  const { confirm, toast } = useOverlay();
  const [scopes, setScopes] = useState<AdminScope[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [acting, setActing] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const [newName, setNewName] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editDesc, setEditDesc] = useState('');

  const load = useCallback(() => {
    if (!accessToken) return;
    setLoading(true);
    AdminApi.listScopes(accessToken)
      .then((r) => setScopes(r.scopes))
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [accessToken]);

  useEffect(load, [load]);

  const createScope = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!accessToken || !newName.trim() || !newDesc.trim()) return;
    setCreating(true);
    try {
      const { scope } = await AdminApi.createScope(accessToken, newName.trim(), newDesc.trim());
      setScopes((prev) => [...prev, scope].sort((a, b) => a.name.localeCompare(b.name)));
      setNewName('');
      setNewDesc('');
      toast(`Scope ${scope.name} ajouté.`);
    } catch (err) {
      toast(err instanceof Error ? err.message : 'L’ajout a échoué.', 'danger');
    } finally {
      setCreating(false);
    }
  };

  const saveEdit = async (e: React.FormEvent, id: string) => {
    e.preventDefault();
    if (!accessToken) return;
    setActing(id);
    try {
      const { scope } = await AdminApi.updateScope(accessToken, id, editDesc);
      setScopes((prev) => prev.map((s) => (s.id === id ? scope : s)));
      setEditingId(null);
      toast('Description enregistrée.');
    } catch (err) {
      toast(err instanceof Error ? err.message : 'L’enregistrement a échoué.', 'danger');
    } finally {
      setActing(null);
    }
  };

  const deleteScope = async (scope: AdminScope) => {
    if (!accessToken) return;
    const ok = await confirm({
      title: `Supprimer le scope ${scope.name} ?`,
      description: 'Les applications qui le demandent ne pourront plus l’obtenir.',
      confirmLabel: 'Supprimer',
      tone: 'danger',
    });
    if (!ok) return;
    setActing(scope.id);
    try {
      await AdminApi.deleteScope(accessToken, scope.id);
      setScopes((prev) => prev.filter((s) => s.id !== scope.id));
      toast('Scope supprimé.');
    } catch (err) {
      toast(err instanceof Error ? err.message : 'La suppression a échoué.', 'danger');
    } finally {
      setActing(null);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Scopes"
        description="Les permissions qu’une application peut demander. La description est celle que voient les utilisateurs sur l’écran d’autorisation."
      />

      <Card className="p-5">
        <form onSubmit={createScope} className="grid gap-3 sm:grid-cols-[200px_1fr_auto] sm:items-end">
          <Field label="Nom">
            <Input placeholder="read:reports" value={newName} onChange={(e) => setNewName(e.target.value)} className="font-mono text-[13px]" />
          </Field>
          <Field label="Description affichée">
            <Input placeholder="Lire vos rapports" value={newDesc} onChange={(e) => setNewDesc(e.target.value)} />
          </Field>
          <Button type="submit" disabled={!newName.trim() || !newDesc.trim()} loading={creating}>Ajouter</Button>
        </form>
      </Card>

      {error && <Alert tone="danger">{error}</Alert>}

      <Card>
        {loading ? (
          <div className="space-y-2 p-5">{[0, 1, 2].map((i) => <Skeleton key={i} className="h-9 w-full" />)}</div>
        ) : scopes.length === 0 ? (
          <div className="px-5"><EmptyState icon={<TagIcon size={18} />} title="Aucun scope défini" /></div>
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Nom</Th>
                <Th>Description</Th>
                <Th>Créé le</Th>
                <Th align="right"><span className="sr-only">Actions</span></Th>
              </tr>
            </thead>
            <tbody>
              {scopes.map((s) => (
                <Tr key={s.id}>
                  <Td className="whitespace-nowrap font-mono text-[13px] font-medium">{s.name}</Td>
                  <Td className="w-full">
                    {editingId === s.id ? (
                      <form id={`edit-${s.id}`} onSubmit={(e) => saveEdit(e, s.id)}>
                        <Input value={editDesc} onChange={(e) => setEditDesc(e.target.value)} className="h-8" autoFocus aria-label={`Description de ${s.name}`} />
                      </form>
                    ) : (
                      <span className="text-muted">{s.description}</span>
                    )}
                  </Td>
                  <Td className="whitespace-nowrap text-muted">{formatDate(s.createdAt)}</Td>
                  <Td align="right">
                    <div className="flex justify-end gap-1">
                      {editingId === s.id ? (
                        <>
                          <Button type="submit" form={`edit-${s.id}`} size="sm" loading={acting === s.id}>Enregistrer</Button>
                          <Button variant="ghost" size="sm" onClick={() => setEditingId(null)}>Annuler</Button>
                        </>
                      ) : (
                        <>
                          <Button variant="ghost" size="sm" onClick={() => { setEditingId(s.id); setEditDesc(s.description); }}>Modifier</Button>
                          <Button variant="danger-ghost" size="sm" disabled={acting === s.id} onClick={() => deleteScope(s)}>Supprimer</Button>
                        </>
                      )}
                    </div>
                  </Td>
                </Tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </div>
  );
}
