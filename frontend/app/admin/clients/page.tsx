'use client';

import { useEffect, useState } from 'react';
import { useAuth } from '@/contexts/AuthContext';
import { AdminApi } from '@/lib/adminApi';
import { AdminClient } from '@/lib/types';

type Modal =
  | { type: 'create' }
  | { type: 'edit'; client: AdminClient }
  | { type: 'secret'; clientId: string; secret: string }
  | null;

export default function AdminClientsPage() {
  const { accessToken } = useAuth();
  const [clients, setClients] = useState<AdminClient[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [modal, setModal] = useState<Modal>(null);
  const [acting, setActing] = useState<string | null>(null);

  // Form state
  const [formName, setFormName] = useState('');
  const [formRedirects, setFormRedirects] = useState('');
  const [formScopes, setFormScopes] = useState('');

  const load = () => {
    if (!accessToken) return;
    setLoading(true);
    AdminApi.listClients(accessToken)
      .then((r) => setClients(r.clients))
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(load, [accessToken]);

  const openCreate = () => {
    setFormName(''); setFormRedirects(''); setFormScopes('openid profile email username');
    setModal({ type: 'create' });
  };

  const openEdit = (c: AdminClient) => {
    setFormName(c.name);
    setFormRedirects(c.redirectUris.join('\n'));
    setFormScopes(c.allowedScopes.join(' '));
    setModal({ type: 'edit', client: c });
  };

  const handleCreate = async () => {
    if (!accessToken) return;
    const redirectUris = formRedirects.split('\n').map((s) => s.trim()).filter(Boolean);
    try {
      const result = await AdminApi.createClient(accessToken, formName, redirectUris);
      setModal({ type: 'secret', clientId: result.client_id, secret: result.client_secret });
      load();
    } catch (e) {
      alert(e instanceof Error ? e.message : 'Erreur');
    }
  };

  const handleEdit = async () => {
    if (!accessToken || modal?.type !== 'edit') return;
    const redirectUris = formRedirects.split('\n').map((s) => s.trim()).filter(Boolean);
    const allowedScopes = formScopes.split(/[\s,]+/).filter(Boolean);
    try {
      await AdminApi.updateClient(accessToken, modal.client.clientId, { name: formName, redirectUris, allowedScopes });
      setModal(null);
      load();
    } catch (e) {
      alert(e instanceof Error ? e.message : 'Erreur');
    }
  };

  const rotateSecret = async (clientId: string) => {
    if (!accessToken) return;
    if (!confirm('Faire tourner le secret ? Toutes les intégrations existantes devront être mises à jour.')) return;
    setActing(clientId);
    try {
      const result = await AdminApi.rotateClientSecret(accessToken, clientId);
      setModal({ type: 'secret', clientId: result.client_id, secret: result.client_secret });
    } catch (e) {
      alert(e instanceof Error ? e.message : 'Erreur');
    } finally {
      setActing(null);
    }
  };

  const deleteClient = async (clientId: string) => {
    if (!accessToken) return;
    if (!confirm('Supprimer cette application ? Les consentements associés seront également supprimés.')) return;
    setActing(clientId);
    try {
      await AdminApi.deleteClient(accessToken, clientId);
      setClients((prev) => prev.filter((c) => c.clientId !== clientId));
    } catch (e) {
      alert(e instanceof Error ? e.message : 'Erreur');
    } finally {
      setActing(null);
    }
  };

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">Applications OAuth2</h1>
        <button
          onClick={openCreate}
          className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-semibold rounded-lg transition-colors"
        >
          + Nouvelle application
        </button>
      </div>

      {error && <p className="text-red-400 text-sm">{error}</p>}

      <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
        {loading ? (
          <p className="px-6 py-8 text-gray-400 text-sm">Chargement...</p>
        ) : clients.length === 0 ? (
          <p className="px-6 py-8 text-gray-400 text-sm">Aucune application enregistrée.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-gray-700/50 text-gray-400 uppercase text-xs">
                <tr>
                  <th className="px-6 py-3 text-left">Nom</th>
                  <th className="px-6 py-3 text-left">Client ID</th>
                  <th className="px-6 py-3 text-center">Consentements</th>
                  <th className="px-6 py-3 text-left">Scopes</th>
                  <th className="px-6 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700">
                {clients.map((c) => (
                  <tr key={c.clientId} className="hover:bg-gray-700/30">
                    <td className="px-6 py-3 text-white font-medium">{c.name}</td>
                    <td className="px-6 py-3 text-gray-400 font-mono text-xs">{c.clientId}</td>
                    <td className="px-6 py-3 text-center text-gray-300">{c._count.consents}</td>
                    <td className="px-6 py-3">
                      <div className="flex flex-wrap gap-1">
                        {c.allowedScopes.map((s) => (
                          <span key={s} className="px-1.5 py-0.5 bg-indigo-900/40 text-indigo-300 rounded text-xs">{s}</span>
                        ))}
                      </div>
                    </td>
                    <td className="px-6 py-3 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button onClick={() => openEdit(c)} className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-gray-700 text-gray-200 hover:bg-gray-600 transition-colors">Modifier</button>
                        <button onClick={() => rotateSecret(c.clientId)} disabled={acting === c.clientId} className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-yellow-900/40 text-yellow-300 hover:bg-yellow-900/70 transition-colors disabled:opacity-50">Rotation secret</button>
                        <button onClick={() => deleteClient(c.clientId)} disabled={acting === c.clientId} className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-red-900/40 text-red-300 hover:bg-red-900/70 transition-colors disabled:opacity-50">Supprimer</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Create / Edit modal */}
      {(modal?.type === 'create' || modal?.type === 'edit') && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-800 rounded-2xl border border-gray-700 p-6 w-full max-w-md space-y-4">
            <h2 className="text-lg font-bold text-white">
              {modal.type === 'create' ? 'Nouvelle application' : 'Modifier l\'application'}
            </h2>
            <div className="space-y-3">
              <div>
                <label className="block text-xs text-gray-400 mb-1">Nom</label>
                <input value={formName} onChange={(e) => setFormName(e.target.value)} className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500" />
              </div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">Redirect URIs (une par ligne)</label>
                <textarea rows={3} value={formRedirects} onChange={(e) => setFormRedirects(e.target.value)} className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white text-sm font-mono focus:outline-none focus:ring-2 focus:ring-indigo-500" />
              </div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">Scopes autorisés (séparés par des espaces)</label>
                <input value={formScopes} onChange={(e) => setFormScopes(e.target.value)} className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500" />
              </div>
            </div>
            <div className="flex gap-3 pt-2">
              <button onClick={modal.type === 'create' ? handleCreate : handleEdit} className="flex-1 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-semibold rounded-lg transition-colors">
                {modal.type === 'create' ? 'Créer' : 'Enregistrer'}
              </button>
              <button onClick={() => setModal(null)} className="flex-1 py-2 bg-gray-700 hover:bg-gray-600 text-gray-200 text-sm font-semibold rounded-lg transition-colors">Annuler</button>
            </div>
          </div>
        </div>
      )}

      {/* New secret modal */}
      {modal?.type === 'secret' && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
          <div className="bg-gray-800 rounded-2xl border border-yellow-600 p-6 w-full max-w-md space-y-4">
            <h2 className="text-lg font-bold text-yellow-300">⚠️ Copiez ce secret maintenant</h2>
            <p className="text-sm text-gray-400">Ce secret ne sera plus jamais affiché. Conservez-le en lieu sûr.</p>
            <div>
              <p className="text-xs text-gray-500 mb-1">Client ID</p>
              <p className="font-mono text-sm text-white bg-gray-700 px-3 py-2 rounded-lg break-all">{modal.clientId}</p>
            </div>
            <div>
              <p className="text-xs text-gray-500 mb-1">Client Secret</p>
              <p className="font-mono text-sm text-yellow-200 bg-gray-700 px-3 py-2 rounded-lg break-all">{modal.secret}</p>
            </div>
            <button onClick={() => setModal(null)} className="w-full py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-semibold rounded-lg transition-colors">
              J'ai copié le secret
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
