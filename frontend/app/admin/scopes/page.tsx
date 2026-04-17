'use client';

import { useEffect, useState } from 'react';
import { useAuth } from '@/contexts/AuthContext';
import { AdminApi } from '@/lib/adminApi';
import { AdminScope } from '@/lib/types';

export default function AdminScopesPage() {
  const { accessToken } = useAuth();
  const [scopes, setScopes] = useState<AdminScope[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [acting, setActing] = useState<string | null>(null);

  // Create form
  const [newName, setNewName] = useState('');
  const [newDesc, setNewDesc] = useState('');

  // Edit state
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editDesc, setEditDesc] = useState('');

  const load = () => {
    if (!accessToken) return;
    setLoading(true);
    AdminApi.listScopes(accessToken)
      .then((r) => setScopes(r.scopes))
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(load, [accessToken]);

  const createScope = async () => {
    if (!accessToken || !newName.trim() || !newDesc.trim()) return;
    try {
      const { scope } = await AdminApi.createScope(accessToken, newName.trim(), newDesc.trim());
      setScopes((prev) => [...prev, scope].sort((a, b) => a.name.localeCompare(b.name)));
      setNewName(''); setNewDesc('');
    } catch (e) {
      alert(e instanceof Error ? e.message : 'Erreur');
    }
  };

  const saveEdit = async (id: string) => {
    if (!accessToken) return;
    setActing(id);
    try {
      const { scope } = await AdminApi.updateScope(accessToken, id, editDesc);
      setScopes((prev) => prev.map((s) => (s.id === id ? scope : s)));
      setEditingId(null);
    } catch (e) {
      alert(e instanceof Error ? e.message : 'Erreur');
    } finally {
      setActing(null);
    }
  };

  const deleteScope = async (scope: AdminScope) => {
    if (!accessToken) return;
    if (!confirm(`Supprimer le scope "${scope.name}" ?`)) return;
    setActing(scope.id);
    try {
      await AdminApi.deleteScope(accessToken, scope.id);
      setScopes((prev) => prev.filter((s) => s.id !== scope.id));
    } catch (e) {
      alert(e instanceof Error ? e.message : 'Erreur');
    } finally {
      setActing(null);
    }
  };

  return (
    <div className="p-8 space-y-6">
      <h1 className="text-2xl font-bold text-white">Scopes</h1>

      {/* Create */}
      <div className="bg-gray-800 rounded-xl border border-gray-700 p-5 space-y-3">
        <h2 className="text-sm font-semibold text-gray-300">Nouveau scope</h2>
        <div className="flex gap-3">
          <input
            placeholder="Nom (ex: read:reports)"
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            className="w-48 px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white text-sm font-mono focus:outline-none focus:ring-2 focus:ring-indigo-500"
          />
          <input
            placeholder="Description"
            value={newDesc}
            onChange={(e) => setNewDesc(e.target.value)}
            className="flex-1 px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
          />
          <button
            onClick={createScope}
            disabled={!newName.trim() || !newDesc.trim()}
            className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-white text-sm font-semibold rounded-lg transition-colors"
          >
            Ajouter
          </button>
        </div>
      </div>

      {error && <p className="text-red-400 text-sm">{error}</p>}

      <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
        {loading ? (
          <p className="px-6 py-8 text-gray-400 text-sm">Chargement...</p>
        ) : scopes.length === 0 ? (
          <p className="px-6 py-8 text-gray-400 text-sm">Aucun scope défini.</p>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-gray-700/50 text-gray-400 uppercase text-xs">
              <tr>
                <th className="px-6 py-3 text-left">Nom</th>
                <th className="px-6 py-3 text-left">Description</th>
                <th className="px-6 py-3 text-left">Créé le</th>
                <th className="px-6 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {scopes.map((s) => (
                <tr key={s.id} className="hover:bg-gray-700/30">
                  <td className="px-6 py-3 text-indigo-300 font-mono font-semibold">{s.name}</td>
                  <td className="px-6 py-3 text-gray-300">
                    {editingId === s.id ? (
                      <input
                        value={editDesc}
                        onChange={(e) => setEditDesc(e.target.value)}
                        className="w-full px-2 py-1 bg-gray-700 border border-indigo-500 rounded text-white text-sm focus:outline-none"
                        autoFocus
                      />
                    ) : (
                      s.description
                    )}
                  </td>
                  <td className="px-6 py-3 text-gray-400 whitespace-nowrap">
                    {new Date(s.createdAt).toLocaleDateString('fr-FR')}
                  </td>
                  <td className="px-6 py-3 text-right">
                    <div className="flex items-center justify-end gap-2">
                      {editingId === s.id ? (
                        <>
                          <button onClick={() => saveEdit(s.id)} disabled={acting === s.id} className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-green-900/40 text-green-300 hover:bg-green-900/70 disabled:opacity-50 transition-colors">Enregistrer</button>
                          <button onClick={() => setEditingId(null)} className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-gray-700 text-gray-300 hover:bg-gray-600 transition-colors">Annuler</button>
                        </>
                      ) : (
                        <>
                          <button onClick={() => { setEditingId(s.id); setEditDesc(s.description); }} className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-gray-700 text-gray-200 hover:bg-gray-600 transition-colors">Modifier</button>
                          <button onClick={() => deleteScope(s)} disabled={acting === s.id} className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-red-900/40 text-red-300 hover:bg-red-900/70 disabled:opacity-50 transition-colors">Supprimer</button>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
