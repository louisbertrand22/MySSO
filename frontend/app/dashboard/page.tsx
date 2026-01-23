'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/contexts/AuthContext';
import ConsentsManager from '@/components/ConsentsManager';
import { ApiService } from '@/lib/api';
import { validateUsername } from '@/lib/validation';

export default function DashboardPage() {
  const router = useRouter();
  const { user, accessToken, isLoading, logout, refreshAccessToken } = useAuth();
  const [editingUsername, setEditingUsername] = useState(false);
  const [newUsername, setNewUsername] = useState('');
  const [usernameError, setUsernameError] = useState('');
  const [usernameSaving, setUsernameSaving] = useState(false);

  useEffect(() => {
    if (!isLoading && !user) {
      router.push('/login');
    }
  }, [user, isLoading, router]);

  const handleLogout = async () => {
    await logout();
    router.push('/login');
  };

  const handleEditUsername = () => {
    setNewUsername(user?.username || '');
    setEditingUsername(true);
    setUsernameError('');
  };

  const handleCancelEdit = () => {
    setEditingUsername(false);
    setNewUsername('');
    setUsernameError('');
  };

  const handleSaveUsername = async () => {
    if (!accessToken) return;
    
    // Validate username
    const validation = validateUsername(newUsername);
    if (!validation.isValid) {
      setUsernameError(validation.error || 'Invalid username');
      return;
    }

    setUsernameSaving(true);
    setUsernameError('');

    try {
      await ApiService.updateProfile(accessToken, newUsername);
      // Refresh the access token to get the updated username
      await refreshAccessToken();
      setEditingUsername(false);
      setNewUsername('');
    } catch (error) {
      if (error instanceof Error) {
        setUsernameError(error.message);
      } else {
        setUsernameError('Failed to update username');
      }
    } finally {
      setUsernameSaving(false);
    }
  };

  if (isLoading) {
    return (
      <div className="flex-1 flex items-center justify-center bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 min-h-screen">
        <div className="text-center">
          <div className="inline-block animate-spin rounded-full h-16 w-16 border-4 border-indigo-400 border-t-indigo-600 shadow-lg"></div>
          <p className="mt-6 text-gray-200 font-semibold text-lg">Chargement de votre tableau de bord...</p>
        </div>
      </div>
    );
  }

  if (!user) {
    return null;
  }

  return (
    <div className="flex-1 flex flex-col min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900">
      <nav className="bg-gray-800/80 backdrop-blur-lg border-b border-gray-700/50 sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-gradient-to-br from-indigo-600 to-purple-600 rounded-xl flex items-center justify-center shadow-lg">
                  <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                </div>
                <h1 className="text-2xl font-bold bg-gradient-to-r from-indigo-400 to-purple-400 bg-clip-text text-transparent">Tableau de bord MySSO</h1>
              </div>
            </div>
            <div className="flex items-center">
              <button
                onClick={handleLogout}
                className="ml-4 px-6 py-2.5 border border-transparent rounded-xl shadow-lg text-sm font-semibold text-white bg-gradient-to-r from-indigo-600 to-purple-600 hover:from-indigo-700 hover:to-purple-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 transition-all duration-200 hover:shadow-xl"
              >
                Déconnexion
              </button>
            </div>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto py-8 sm:px-6 lg:px-8 w-full">
        <div className="px-4 py-6 sm:px-0 space-y-6">
          {/* User Information Card */}
          <div className="bg-gray-800/70 backdrop-blur-xl shadow-xl rounded-2xl overflow-hidden border border-gray-700/20 hover:shadow-2xl transition-all duration-300">
            <div className="px-6 py-5 sm:px-8 bg-gradient-to-r from-indigo-500/20 to-purple-500/20 border-b border-gray-700/50">
              <div className="flex items-center gap-3">
                <div className="w-12 h-12 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-xl flex items-center justify-center shadow-lg">
                  <svg className="w-7 h-7 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                  </svg>
                </div>
                <div>
                  <h3 className="text-xl leading-6 font-bold text-gray-100">
                    Informations utilisateur
                  </h3>
                  <p className="mt-1 text-sm text-gray-400">
                    Les détails de votre compte
                  </p>
                </div>
              </div>
            </div>
            <div className="divide-y divide-gray-700/50">
              <div className="px-6 py-5 sm:px-8 hover:bg-gray-700/30 transition-colors duration-200">
                <div className="sm:grid sm:grid-cols-3 sm:gap-4">
                  <dt className="text-sm font-semibold text-gray-400 flex items-center gap-2">
                    <svg className="w-5 h-5 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V8a2 2 0 00-2-2h-5m-4 0V5a2 2 0 114 0v1m-4 0a2 2 0 104 0m-5 8a2 2 0 100-4 2 2 0 000 4zm0 0c1.306 0 2.417.835 2.83 2M9 14a3.001 3.001 0 00-2.83 2M15 11h3m-3 4h2" />
                    </svg>
                    ID Utilisateur
                  </dt>
                  <dd className="mt-2 text-sm text-gray-200 sm:mt-0 sm:col-span-2 font-mono bg-gray-700/70 px-3 py-2 rounded-lg">
                    {user.id}
                  </dd>
                </div>
              </div>
              <div className="px-6 py-5 sm:px-8 hover:bg-gray-700/30 transition-colors duration-200">
                <div className="sm:grid sm:grid-cols-3 sm:gap-4">
                  <dt className="text-sm font-semibold text-gray-400 flex items-center gap-2">
                    <svg className="w-5 h-5 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                    </svg>
                    Adresse e-mail
                  </dt>
                  <dd className="mt-2 text-sm text-gray-200 sm:mt-0 sm:col-span-2 font-medium">
                    {user.email}
                  </dd>
                </div>
              </div>
              <div className="px-6 py-5 sm:px-8 hover:bg-gray-700/30 transition-colors duration-200">
                <div className="sm:grid sm:grid-cols-3 sm:gap-4">
                  <dt className="text-sm font-semibold text-gray-400 flex items-center gap-2">
                    <svg className="w-5 h-5 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                    </svg>
                    Nom d'utilisateur
                  </dt>
                  <dd className="mt-2 text-sm sm:mt-0 sm:col-span-2">
                    {editingUsername ? (
                      <div className="space-y-2">
                        <div className="flex gap-2">
                          <input
                            type="text"
                            value={newUsername}
                            onChange={(e) => setNewUsername(e.target.value)}
                            className="flex-1 px-4 py-2.5 border border-gray-600 bg-gray-700 text-gray-200 rounded-xl shadow-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-all duration-200"
                            placeholder="Entrez le nom d'utilisateur"
                            disabled={usernameSaving}
                          />
                          <button
                            onClick={handleSaveUsername}
                            disabled={usernameSaving}
                            className="px-5 py-2.5 bg-gradient-to-r from-indigo-600 to-purple-600 text-white rounded-xl hover:from-indigo-700 hover:to-purple-700 disabled:from-gray-400 disabled:to-gray-400 disabled:cursor-not-allowed font-semibold shadow-lg transition-all duration-200 hover:shadow-xl"
                          >
                            {usernameSaving ? 'Enregistrement...' : 'Enregistrer'}
                          </button>
                          <button
                            onClick={handleCancelEdit}
                            disabled={usernameSaving}
                            className="px-5 py-2.5 bg-gray-600 text-gray-200 rounded-xl hover:bg-gray-500 disabled:bg-gray-700 disabled:cursor-not-allowed font-semibold shadow transition-all duration-200"
                          >
                            Annuler
                          </button>
                        </div>
                        {usernameError && (
                          <p className="text-sm text-red-400 flex items-center gap-2">
                            <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                            </svg>
                            {usernameError}
                          </p>
                        )}
                      </div>
                    ) : (
                      <div className="flex items-center gap-3">
                        <span className="text-gray-200 font-medium">
                          {user.username || 'Non défini'}
                        </span>
                        <button
                          onClick={handleEditUsername}
                          className="text-indigo-400 hover:text-indigo-300 text-sm font-semibold flex items-center gap-1 hover:gap-2 transition-all duration-200"
                        >
                          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                          </svg>
                          {user.username ? 'Modifier' : 'Définir un nom d\'utilisateur'}
                        </button>
                      </div>
                    )}
                  </dd>
                </div>
              </div>
              <div className="px-6 py-5 sm:px-8 hover:bg-gray-700/30 transition-colors duration-200">
                <div className="sm:grid sm:grid-cols-3 sm:gap-4">
                  <dt className="text-sm font-semibold text-gray-400 flex items-center gap-2">
                    <svg className="w-5 h-5 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                    </svg>
                    Compte créé le
                  </dt>
                  <dd className="mt-2 text-sm text-gray-200 sm:mt-0 sm:col-span-2 font-medium">
                    {new Date(user.createdAt).toLocaleString()}
                  </dd>
                </div>
              </div>
            </div>
          </div>

          {/* Session Information Card */}
          <div className="bg-gray-800/70 backdrop-blur-xl shadow-xl rounded-2xl overflow-hidden border border-gray-700/20 hover:shadow-2xl transition-all duration-300">
            <div className="px-6 py-5 sm:px-8 bg-gradient-to-r from-green-500/20 to-emerald-500/20 border-b border-gray-700/50">
              <div className="flex items-center gap-3">
                <div className="w-12 h-12 bg-gradient-to-br from-green-500 to-emerald-600 rounded-xl flex items-center justify-center shadow-lg">
                  <svg className="w-7 h-7 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </div>
                <div>
                  <h3 className="text-xl leading-6 font-bold text-gray-100">
                    Informations de session
                  </h3>
                  <p className="mt-1 text-sm text-gray-400">
                    Statut de votre session actuelle
                  </p>
                </div>
              </div>
            </div>
            <div className="px-6 py-6 sm:px-8">
              <div className="flex items-center gap-4 p-4 bg-gradient-to-r from-green-900/30 to-emerald-900/30 rounded-xl border border-green-700">
                <div className="flex-shrink-0">
                  <div className="h-4 w-4 rounded-full bg-green-500 animate-pulse shadow-lg shadow-green-500/50"></div>
                </div>
                <div className="flex-1">
                  <p className="text-sm font-bold text-gray-100 flex items-center gap-2">
                    <svg className="w-5 h-5 text-green-400" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                    </svg>
                    Session active
                  </p>
                  <p className="text-sm text-gray-400 mt-1">Vous êtes actuellement connecté</p>
                </div>
              </div>
            </div>
          </div>

          {/* Authorized Applications Card */}
          <div className="bg-gray-800/70 backdrop-blur-xl shadow-xl rounded-2xl overflow-hidden border border-gray-700/20 hover:shadow-2xl transition-all duration-300">
            <div className="px-6 py-5 sm:px-8 bg-gradient-to-r from-blue-500/20 to-cyan-500/20 border-b border-gray-700/50">
              <div className="flex items-center gap-3">
                <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-cyan-600 rounded-xl flex items-center justify-center shadow-lg">
                  <svg className="w-7 h-7 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
                  </svg>
                </div>
                <div>
                  <h3 className="text-xl leading-6 font-bold text-gray-100">
                    Applications autorisées
                  </h3>
                  <p className="mt-1 text-sm text-gray-400">
                    Gérez les applications tierces qui ont accès à votre compte
                  </p>
                </div>
              </div>
            </div>
            <div className="px-6 py-5 sm:px-8">
              {accessToken ? (
                <ConsentsManager accessToken={accessToken} />
              ) : (
                <div className="text-center py-4 text-gray-400">
                  Chargement...
                </div>
              )}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
