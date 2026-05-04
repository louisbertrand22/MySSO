'use client';

import { useEffect } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import Link from 'next/link';
import { useAuth } from '@/contexts/AuthContext';

const NAV = [
  { href: '/admin', label: 'Tableau de bord', icon: '📊' },
  { href: '/admin/users', label: 'Utilisateurs', icon: '👥' },
  { href: '/admin/clients', label: 'Applications', icon: '🔐' },
  { href: '/admin/scopes', label: 'Scopes', icon: '🏷️' },
  { href: '/admin/audit', label: 'Journal d\'audit', icon: '📋' },
  { href: '/admin/settings', label: 'Paramètres', icon: '⚙️' },
];

export default function AdminLayout({ children }: { children: React.ReactNode }) {
  const { user, isLoading } = useAuth();
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    if (!isLoading) {
      if (!user) { router.push('/login'); return; }
      if (!user.scopes?.includes('admin')) { router.push('/dashboard'); }
    }
  }, [user, isLoading, router]);

  if (isLoading || !user?.scopes?.includes('admin')) {
    return (
      <div className="flex-1 flex items-center justify-center bg-gray-900 min-h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-4 border-indigo-400 border-t-indigo-600" />
      </div>
    );
  }

  return (
    <div className="flex min-h-screen bg-gray-900">
      {/* Sidebar */}
      <aside className="w-56 bg-gray-800 border-r border-gray-700 flex flex-col shrink-0">
        <div className="px-5 py-6 border-b border-gray-700">
          <p className="text-xs font-semibold text-indigo-400 uppercase tracking-widest">Admin Panel</p>
          <p className="mt-1 text-xs text-gray-500 truncate">{user.email}</p>
        </div>
        <nav className="flex-1 px-3 py-4 space-y-1">
          {NAV.map(({ href, label, icon }) => {
            const active = pathname === href;
            return (
              <Link
                key={href}
                href={href}
                className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                  active
                    ? 'bg-indigo-600 text-white'
                    : 'text-gray-400 hover:text-white hover:bg-gray-700'
                }`}
              >
                <span>{icon}</span>
                {label}
              </Link>
            );
          })}
        </nav>
        <div className="px-3 py-4 border-t border-gray-700">
          <Link
            href="/dashboard"
            className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-gray-400 hover:text-white hover:bg-gray-700 transition-colors"
          >
            <span>←</span> Retour au dashboard
          </Link>
        </div>
      </aside>

      {/* Content */}
      <main className="flex-1 overflow-auto">{children}</main>
    </div>
  );
}
