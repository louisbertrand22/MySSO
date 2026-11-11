'use client';

import { useEffect } from 'react';
import { listenForInstallPrompt } from '@/lib/pwa';

/**
 * Registers the service worker (production only: in development it would cache
 * build assets that change on every save) and captures the install prompt.
 */
export default function PwaSetup() {
  useEffect(() => {
    const stop = listenForInstallPrompt();

    if ('serviceWorker' in navigator && process.env.NODE_ENV === 'production') {
      navigator.serviceWorker.register('/sw.js', { scope: '/' }).catch(() => {
        // Not fatal: the site works the same without it, only offline/install are affected
      });
    }

    return stop;
  }, []);

  return null;
}
