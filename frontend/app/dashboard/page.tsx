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
      <div className="flex-1 flex items-center justify-center bg-gray-50">
        <div className="text-center">
          <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
          <p className="mt-4 text-gray-600">Loading...</p>
        </div>
      </div>
    );
  }

  if (!user) {
    return null;
  }

  return (
    <div className="flex-1 flex flex-col bg-gray-50">
      <nav className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center">
              <h1 className="text-2xl font-bold text-gray-900">MySSO Dashboard</h1>
            </div>
            <div className="flex items-center">
              <button
                onClick={handleLogout}
                className="ml-4 px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
              >
                Logout
              </button>
            </div>
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div className="px-4 py-6 sm:px-0">
          <div className="bg-white shadow overflow-hidden sm:rounded-lg">
            <div className="px-4 py-5 sm:px-6">
              <h3 className="text-lg leading-6 font-medium text-gray-900">
                User Information
              </h3>
              <p className="mt-1 max-w-2xl text-sm text-gray-500">
                Your account details
              </p>
            </div>
            <div className="border-t border-gray-200">
              <dl>
                <div className="bg-gray-50 px-4 py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
                  <dt className="text-sm font-medium text-gray-500">User ID</dt>
                  <dd className="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                    {user.id}
                  </dd>
                </div>
                <div className="bg-white px-4 py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
                  <dt className="text-sm font-medium text-gray-500">Email address</dt>
                  <dd className="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                    {user.email}
                  </dd>
                </div>
                <div className="bg-gray-50 px-4 py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
                  <dt className="text-sm font-medium text-gray-500">Username</dt>
                  <dd className="mt-1 text-sm sm:mt-0 sm:col-span-2">
                    {editingUsername ? (
                      <div className="space-y-2">
                        <div className="flex gap-2">
                          <input
                            type="text"
                            value={newUsername}
                            onChange={(e) => setNewUsername(e.target.value)}
                            className="flex-1 px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                            placeholder="Enter username"
                            disabled={usernameSaving}
                          />
                          <button
                            onClick={handleSaveUsername}
                            disabled={usernameSaving}
                            className="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:bg-gray-400 disabled:cursor-not-allowed"
                          >
                            {usernameSaving ? 'Saving...' : 'Save'}
                          </button>
                          <button
                            onClick={handleCancelEdit}
                            disabled={usernameSaving}
                            className="px-4 py-2 bg-gray-200 text-gray-700 rounded-md hover:bg-gray-300 disabled:bg-gray-100 disabled:cursor-not-allowed"
                          >
                            Cancel
                          </button>
                        </div>
                        {usernameError && (
                          <p className="text-sm text-red-600">{usernameError}</p>
                        )}
                      </div>
                    ) : (
                      <div className="flex items-center gap-2">
                        <span className="text-gray-900">
                          {user.username || 'Not set'}
                        </span>
                        <button
                          onClick={handleEditUsername}
                          className="text-indigo-600 hover:text-indigo-800 text-sm font-medium"
                        >
                          {user.username ? 'Edit' : 'Set username'}
                        </button>
                      </div>
                    )}
                  </dd>
                </div>
                <div className="bg-white px-4 py-5 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
                  <dt className="text-sm font-medium text-gray-500">Account created</dt>
                  <dd className="mt-1 text-sm text-gray-900 sm:mt-0 sm:col-span-2">
                    {new Date(user.createdAt).toLocaleString()}
                  </dd>
                </div>
              </dl>
            </div>
          </div>

          <div className="mt-8 bg-white shadow overflow-hidden sm:rounded-lg">
            <div className="px-4 py-5 sm:px-6">
              <h3 className="text-lg leading-6 font-medium text-gray-900">
                Session Information
              </h3>
              <p className="mt-1 max-w-2xl text-sm text-gray-500">
                Your current session status
              </p>
            </div>
            <div className="border-t border-gray-200 px-4 py-5 sm:px-6">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <div className="h-3 w-3 rounded-full bg-green-400"></div>
                </div>
                <div className="ml-3">
                  <p className="text-sm font-medium text-gray-900">Active Session</p>
                  <p className="text-sm text-gray-500">You are currently logged in</p>
                </div>
              </div>
            </div>
          </div>

          <div className="mt-8 bg-white shadow overflow-hidden sm:rounded-lg">
            <div className="px-4 py-5 sm:px-6">
              <h3 className="text-lg leading-6 font-medium text-gray-900">
                Authorized Applications
              </h3>
              <p className="mt-1 max-w-2xl text-sm text-gray-500">
                Manage third-party applications that have access to your account
              </p>
            </div>
            <div className="border-t border-gray-200 px-4 py-5 sm:px-6">
              {accessToken ? (
                <ConsentsManager accessToken={accessToken} />
              ) : (
                <div className="text-center py-4 text-gray-500">
                  Loading...
                </div>
              )}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
