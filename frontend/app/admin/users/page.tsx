'use client';

import { useCallback, useEffect, useState } from 'react';
import { useAuth } from '@/contexts/AuthContext';
import { AdminApi } from '@/lib/adminApi';
import { AdminUser } from '@/lib/types';
import { formatDate } from '@/lib/format';
import { Card, PageHeader } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Field';
import { Alert, Badge, EmptyState, Skeleton } from '@/components/ui/Feedback';
import { Table, Td, Th, Tr } from '@/components/ui/Table';
import { SearchIcon, UserIcon } from '@/components/ui/Icons';
import { useOverlay } from '@/components/ui/Overlays';

export default function AdminUsersPage() {
  const { accessToken, user: me } = useAuth();
  const { confirm, toast } = useOverlay();
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [acting, setActing] = useState<string | null>(null);

  const load = useCallback(() => {
    if (!accessToken) return;
    setLoading(true);
    AdminApi.listUsers(accessToken)
      .then((r) => setUsers(r.users))
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [accessToken]);

  useEffect(load, [load]);

  const toggleDisable = async (user: AdminUser) => {
    if (!accessToken) return;
    const disabling = !user.isDisabled;
    const ok = await confirm({
      title: disabling ? `Désactiver ${user.email} ?` : `Réactiver ${user.email} ?`,
      description: disabling
        ? 'Ce compte ne pourra plus se connecter ni renouveler ses sessions. Vous pourrez le réactiver plus tard.'
        : 'Ce compte pourra de nouveau se connecter.',
      confirmLabel: disabling ? 'Désactiver' : 'Réactiver',
      tone: disabling ? 'danger' : 'default',
    });
    if (!ok) return;
    setActing(user.id);
    try {
      const { user: updated } = await AdminApi.updateUser(accessToken, user.id, disabling);
      setUsers((prev) => prev.map((u) => (u.id === updated.id ? { ...u, isDisabled: updated.isDisabled } : u)));
      toast(disabling ? 'Compte désactivé.' : 'Compte réactivé.');
    } catch (e) {
      toast(e instanceof Error ? e.message : 'L’action a échoué.', 'danger');
    } finally {
      setActing(null);
    }
  };

  const deleteUser = async (user: AdminUser) => {
    if (!accessToken) return;
    const ok = await confirm({
      title: `Supprimer ${user.email} ?`,
      description: 'Le compte, ses sessions et ses autorisations seront effacés définitivement.',
      confirmLabel: 'Supprimer',
      tone: 'danger',
      requireText: user.email,
    });
    if (!ok) return;
    setActing(user.id);
    try {
      await AdminApi.deleteUser(accessToken, user.id);
      setUsers((prev) => prev.filter((u) => u.id !== user.id));
      toast('Compte supprimé.');
    } catch (e) {
      toast(e instanceof Error ? e.message : 'La suppression a échoué.', 'danger');
    } finally {
      setActing(null);
    }
  };

  const q = search.trim().toLowerCase();
  const filtered = users.filter((u) => u.email.toLowerCase().includes(q) || (u.username ?? '').toLowerCase().includes(q));

  return (
    <div className="space-y-6">
      <PageHeader title="Utilisateurs" description={loading ? 'Chargement…' : `${users.length.toLocaleString('fr-FR')} comptes`} />

      <div className="relative max-w-sm">
        <SearchIcon size={16} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-subtle" />
        <Input type="search" placeholder="Rechercher par e-mail ou nom" value={search} onChange={(e) => setSearch(e.target.value)} className="pl-9" aria-label="Rechercher un utilisateur" />
      </div>

      {error && <Alert tone="danger">{error}</Alert>}

      <Card>
        {loading ? (
          <div className="space-y-2 p-5">{[0, 1, 2].map((i) => <Skeleton key={i} className="h-9 w-full" />)}</div>
        ) : filtered.length === 0 ? (
          <div className="px-5">
            <EmptyState icon={<UserIcon size={18} />} title={search ? 'Aucun résultat' : 'Aucun utilisateur'}>
              {search && <>Aucun compte ne correspond à « {search} ».</>}
            </EmptyState>
          </div>
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Compte</Th>
                <Th align="right">Sessions</Th>
                <Th align="right">Applications</Th>
                <Th>Statut</Th>
                <Th>Inscrit le</Th>
                <Th align="right"><span className="sr-only">Actions</span></Th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((u) => (
                <Tr key={u.id} muted={u.isDisabled}>
                  <Td>
                    <p className="font-medium">{u.email}</p>
                    <p className="text-[13px] text-muted">{u.username ?? '—'}</p>
                  </Td>
                  <Td align="right" className="tabular">{u._count.sessions}</Td>
                  <Td align="right" className="tabular">{u._count.consents}</Td>
                  <Td>{u.isDisabled ? <Badge tone="danger">Désactivé</Badge> : <Badge tone="accent">Actif</Badge>}</Td>
                  <Td className="whitespace-nowrap text-muted">{formatDate(u.createdAt)}</Td>
                  <Td align="right">
                    {u.id !== me?.id && (
                      <div className="flex justify-end gap-1">
                        <Button variant="ghost" size="sm" disabled={acting === u.id} onClick={() => toggleDisable(u)}>
                          {u.isDisabled ? 'Réactiver' : 'Désactiver'}
                        </Button>
                        <Button variant="danger-ghost" size="sm" disabled={acting === u.id} onClick={() => deleteUser(u)}>
                          Supprimer
                        </Button>
                      </div>
                    )}
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
