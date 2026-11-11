'use client';

import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { useAuth } from '@/contexts/AuthContext';
import { useTheme, type ThemePreference } from '@/contexts/ThemeContext';
import { Logo } from './Brand';
import { Segmented } from './ui/Field';
import { ChevronDownIcon, LogoutIcon, SlidersIcon, UserIcon } from './ui/Icons';

export function Avatar({ name, size = 28 }: { name: string; size?: number }) {
  return (
    <span
      className="grid shrink-0 place-items-center rounded-[7px] bg-accent-soft font-semibold text-accent-text"
      style={{ width: size, height: size, fontSize: size * 0.42 }}
      aria-hidden="true"
    >
      {name.charAt(0).toUpperCase()}
    </span>
  );
}

export const THEME_OPTIONS: { value: ThemePreference; label: string }[] = [
  { value: 'system', label: 'Système' },
  { value: 'light', label: 'Clair' },
  { value: 'dark', label: 'Sombre' },
];

function UserMenu() {
  const { user, logout } = useAuth();
  const { preference, setPreference } = useTheme();
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onClick = (e: MouseEvent) => {
      if (!ref.current?.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false);
    document.addEventListener('mousedown', onClick);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onClick);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  if (!user) return null;
  const name = user.username || user.email;

  const handleLogout = async () => {
    await logout();
    router.push('/login');
  };

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        aria-haspopup="menu"
        className="flex items-center gap-2 rounded-[var(--radius-control)] py-1 pl-1 pr-2 transition-colors hover:bg-surface-2"
      >
        <Avatar name={name} />
        <span className="hidden max-w-[160px] truncate text-sm font-medium sm:block">{name}</span>
        <ChevronDownIcon size={15} className={`text-subtle transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>

      {open && (
        <div role="menu" className="absolute right-0 top-[calc(100%+6px)] z-40 w-72 animate-enter rounded-[var(--radius-card)] border border-line bg-surface p-1.5 shadow-[var(--shadow-pop)]">
          <div className="px-2.5 pb-2.5 pt-2">
            <p className="truncate text-sm font-medium">{user.username || 'Mon compte'}</p>
            <p className="truncate text-[13px] text-muted">{user.email}</p>
          </div>
          <div className="border-t border-line px-2.5 py-3">
            <p className="mb-2 flex items-center gap-1.5 text-[13px] text-muted">
              <SlidersIcon size={14} /> Apparence
            </p>
            <Segmented label="Thème" value={preference} onChange={setPreference} options={THEME_OPTIONS} />
          </div>
          <div className="border-t border-line pt-1.5">
            <Link role="menuitem" href="/dashboard" onClick={() => setOpen(false)} className="flex items-center gap-2.5 rounded-md px-2.5 py-2 text-sm text-fg hover:bg-surface-2">
              <UserIcon size={16} className="text-muted" /> Mon compte
            </Link>
            <button role="menuitem" type="button" onClick={handleLogout} className="flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-sm text-fg hover:bg-surface-2">
              <LogoutIcon size={16} className="text-muted" /> Se déconnecter
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default function AppHeader({ children }: { children?: React.ReactNode }) {
  const { user } = useAuth();
  const isAdmin = user?.scopes?.includes('admin');
  const inAdmin = usePathname().startsWith('/admin');

  return (
    <header className="sticky top-0 z-30 border-b border-line bg-bg/85 backdrop-blur-md">
      <div className="mx-auto flex h-14 max-w-6xl items-center justify-between gap-4 px-5 sm:px-8">
        <div className="flex items-center gap-6">
          <Logo href="/dashboard" />
          {isAdmin && (
            <nav className="flex items-center gap-1 text-sm" aria-label="Espaces">
              {[
                { href: '/dashboard', label: 'Compte', active: !inAdmin },
                { href: '/admin', label: 'Administration', active: inAdmin },
              ].map((item) => (
                <Link
                  key={item.href}
                  href={item.href}
                  aria-current={item.active ? 'page' : undefined}
                  className={`rounded-md px-2.5 py-1.5 transition-colors ${item.active ? 'bg-surface-2 font-medium text-fg' : 'text-muted hover:bg-surface-2 hover:text-fg'}`}
                >
                  {item.label}
                </Link>
              ))}
            </nav>
          )}
        </div>
        <UserMenu />
      </div>
      {children}
    </header>
  );
}
