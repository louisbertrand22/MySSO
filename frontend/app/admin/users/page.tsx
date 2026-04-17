'use client';

import { useEffect, useState } from 'react';
import { useAuth } from '@/contexts/AuthContext';
import { AdminApi } from '@/lib/adminApi';
import { AdminUser } from '@/lib/types';

export default function AdminUsersPage() {
  const { accessToken } = useAuth();
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [acting, setActing] = useState<string | null>(null);

  const load = () => {
    if (!accessToken) return;
    setLoading(true);
    AdminApi.listUsers(accessToken)
      .then((r) => setUsers(r.users))
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(load, [accessToken]);

  const toggleDisable = async (user: AdminUser) => {
    if (!accessToken) return;
    if (!confirm(`${user.isDisabled ? 'Réactiver' : 'Désactiver'} ${user.email} ?`)) return;
    setActing(user.id);
    try {
      const { user: updated } = await AdminApi.updateUser(accessToken, user.id, !user.isDisabled);
      setUsers((prev) => prev.map((u) => (u.id === updated.id ? { ...u, isDisabled: updated.isDisabled } : u)));
    } catch (e) {
      alert(e instanceof Error ? e.message : 'Erreur');
    } finally {
      setActing(null);
    }
  };

  const deleteUser = async (user: AdminUser) => {
    if (!accessToken) return;
    if (!confirm(`Supprimer définitivement ${user.email} ? Cette action est irréversible.`)) return;
    setActing(user.id);
    try {
      await AdminApi.deleteUser(accessToken, user.id);
      setUsers((prev) => prev.filter((u) => u.id !== user.id));
    } catch (e) {
      alert(e instanceof Error ? e.message : 'Erreur');
    } finally {
      setActing(null);
    }
  };

  const filtered = users.filter(
    (u) =>
      u.email.toLowerCase().includes(search.toLowerCase()) ||
      (u.username ?? '').toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">Utilisateurs</h1>
        <span className="text-sm text-gray-400">{users.length} au total</span>
      </div>

      <input
        type="text"
        placeholder="Rechercher par email ou nom d'utilisateur..."
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        className="w-full px-4 py-2.5 bg-gray-800 border border-gray-700 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
      />

      {error && <p className="text-red-400 text-sm">{error}</p>}

      <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
        {loading ? (
          <p className="px-6 py-8 text-gray-400 text-sm">Chargement...</p>
        ) : filtered.length === 0 ? (
          <p className="px-6 py-8 text-gray-400 text-sm">Aucun utilisateur trouvé.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-gray-700/50 text-gray-400 uppercase text-xs">
                <tr>
                  <th className="px-6 py-3 text-left">Email</th>
                  <th className="px-6 py-3 text-left">Nom d'utilisateur</th>
                  <th className="px-6 py-3 text-center">Sessions</th>
                  <th className="px-6 py-3 text-center">Consentements</th>
                  <th className="px-6 py-3 text-center">Statut</th>
                  <th className="px-6 py-3 text-left">Créé le</th>
                  <th className="px-6 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700">
                {filtered.map((u) => (
                  <tr key={u.id} className={`hover:bg-gray-700/30 ${u.isDisabled ? 'opacity-50' : ''}`}>
                    <td className="px-6 py-3 text-white font-medium">{u.email}</td>
                    <td className="px-6 py-3 text-gray-400">{u.username ?? '—'}</td>
                    <td className="px-6 py-3 text-center text-gray-300">{u._count.sessions}</td>
                    <td className="px-6 py-3 text-center text-gray-300">{u._count.consents}</td>
                    <td className="px-6 py-3 text-center">
                      <span className={`inline-block px-2 py-0.5 rounded-full text-xs font-semibold ${u.isDisabled ? 'bg-red-900/40 text-red-300' : 'bg-green-900/40 text-green-300'}`}>
                        {u.isDisabled ? 'Désactivé' : 'Actif'}
                      </span>
                    </td>
                    <td className="px-6 py-3 text-gray-400 whitespace-nowrap">
                      {new Date(u.createdAt).toLocaleDateString('fr-FR')}
                    </td>
                    <td className="px-6 py-3 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => toggleDisable(u)}
                          disabled={acting === u.id}
                          className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors disabled:opacity-50 ${
                            u.isDisabled
                              ? 'bg-green-900/40 text-green-300 hover:bg-green-900/70'
                              : 'bg-yellow-900/40 text-yellow-300 hover:bg-yellow-900/70'
                          }`}
                        >
                          {u.isDisabled ? 'Réactiver' : 'Désactiver'}
                        </button>
                        <button
                          onClick={() => deleteUser(u)}
                          disabled={acting === u.id}
                          className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-red-900/40 text-red-300 hover:bg-red-900/70 transition-colors disabled:opacity-50"
                        >
                          Supprimer
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
