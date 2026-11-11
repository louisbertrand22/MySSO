'use client';

import { createContext, useCallback, useContext, useEffect, useState, ReactNode } from 'react';

export type ThemePreference = 'system' | 'light' | 'dark';

interface ThemeContextType {
  /** What the user picked */
  preference: ThemePreference;
  /** What is actually displayed */
  theme: 'light' | 'dark';
  setPreference: (preference: ThemePreference) => void;
}

const STORAGE_KEY = 'theme';
const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

/**
 * Runs before React hydrates (inlined in <head>) so the right theme is applied on first paint.
 * Kept as a string: it must not depend on any bundled code.
 */
export const themeInitScript = `(function(){try{var p=localStorage.getItem('${STORAGE_KEY}');var d=p==='dark'||((p===null||p==='system')&&window.matchMedia('(prefers-color-scheme: dark)').matches);document.documentElement.classList.toggle('dark',d);}catch(e){}})();`;

function systemTheme(): 'light' | 'dark' {
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function readPreference(): ThemePreference {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    return stored === 'light' || stored === 'dark' ? stored : 'system';
  } catch {
    return 'system';
  }
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  // Lazy init on the client; the inline script in <head> has already applied the right class
  const [preference, setPreferenceState] = useState<ThemePreference>(() =>
    typeof window === 'undefined' ? 'system' : readPreference()
  );
  const [theme, setTheme] = useState<'light' | 'dark'>(() =>
    typeof document !== 'undefined' && document.documentElement.classList.contains('dark') ? 'dark' : 'light'
  );

  const apply = useCallback((pref: ThemePreference) => {
    const resolved = pref === 'system' ? systemTheme() : pref;
    document.documentElement.classList.toggle('dark', resolved === 'dark');
    setTheme(resolved);
  }, []);

  // Follow the OS setting while the preference is "system"
  useEffect(() => {
    if (preference !== 'system') return;
    const media = window.matchMedia('(prefers-color-scheme: dark)');
    const onChange = () => apply('system');
    media.addEventListener('change', onChange);
    return () => media.removeEventListener('change', onChange);
  }, [preference, apply]);

  const setPreference = useCallback(
    (next: ThemePreference) => {
      try {
        if (next === 'system') localStorage.removeItem(STORAGE_KEY);
        else localStorage.setItem(STORAGE_KEY, next);
      } catch {
        // storage unavailable (private mode): the choice lasts for this page only
      }
      setPreferenceState(next);
      apply(next);
    },
    [apply]
  );

  return (
    <ThemeContext.Provider value={{ preference, theme, setPreference }}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme() {
  const context = useContext(ThemeContext);
  if (!context) throw new Error('useTheme must be used within a ThemeProvider');
  return context;
}
