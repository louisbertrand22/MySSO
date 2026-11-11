'use client';

import { useEffect } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import Link from 'next/link';
import { useAuth } from '@/contexts/AuthContext';
import AppHeader from '@/components/AppHeader';
import { PageLoader } from '@/components/ui/Feedback';
import { AppsIcon, ChartIcon, ListIcon, SlidersIcon, TagIcon, UserIcon } from '@/components/ui/Icons';

const NAV = [
  { href: '/admin', label: 'Vue d’ensemble', icon: ChartIcon },
  { href: '/admin/users', label: 'Utilisateurs', icon: UserIcon },
  { href: '/admin/clients', label: 'Applications', icon: AppsIcon },
  { href: '/admin/scopes', label: 'Scopes', icon: TagIcon },
  { href: '/admin/audit', label: 'Journal', icon: ListIcon },
  { href: '/admin/settings', label: 'Paramètres', icon: SlidersIcon },
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
    return <PageLoader />;
  }

  return (
    <div className="flex flex-1 flex-col">
      <AppHeader>
        <nav aria-label="Administration" className="mx-auto flex max-w-6xl gap-1 overflow-x-auto px-5 sm:px-8">
          {NAV.map(({ href, label, icon: Icon }) => {
            const active = href === '/admin' ? pathname === href : pathname.startsWith(href);
            return (
              <Link
                key={href}
                href={href}
                aria-current={active ? 'page' : undefined}
                className={`flex items-center gap-2 whitespace-nowrap border-b-2 px-2.5 pb-2.5 pt-2 text-sm transition-colors ${
                  active ? 'border-accent font-medium text-fg' : 'border-transparent text-muted hover:border-line-strong hover:text-fg'
                }`}
              >
                <Icon size={16} />
                {label}
              </Link>
            );
          })}
        </nav>
      </AppHeader>
      <main id="main" className="mx-auto w-full max-w-6xl flex-1 px-5 pb-20 pt-8 sm:px-8">{children}</main>
    </div>
  );
}
