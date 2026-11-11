import type { MetadataRoute } from 'next';

/**
 * Web App Manifest, served by Next.js at /manifest.webmanifest.
 * Makes MySSO installable ("Ajouter à l'écran d'accueil") with its own icon and window.
 */
export default function manifest(): MetadataRoute.Manifest {
  return {
    id: '/',
    name: 'MySSO',
    short_name: 'MySSO',
    description: 'Un seul compte pour toutes vos applications : connexions, applications autorisées et sessions.',
    lang: 'fr',
    dir: 'ltr',
    start_url: '/dashboard?source=pwa',
    scope: '/',
    display: 'standalone',
    display_override: ['standalone', 'minimal-ui'],
    orientation: 'portrait',
    background_color: '#f9fafb',
    theme_color: '#1d8a63',
    categories: ['productivity', 'utilities', 'security'],
    icons: [
      { src: '/icons/icon-192.png', sizes: '192x192', type: 'image/png', purpose: 'any' },
      { src: '/icons/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'any' },
      { src: '/icons/icon-maskable-192.png', sizes: '192x192', type: 'image/png', purpose: 'maskable' },
      { src: '/icons/icon-maskable-512.png', sizes: '512x512', type: 'image/png', purpose: 'maskable' },
    ],
    shortcuts: [
      {
        name: 'Applications autorisées',
        short_name: 'Applications',
        url: '/dashboard?source=pwa#applications',
        icons: [{ src: '/icons/icon-192.png', sizes: '192x192', type: 'image/png' }],
      },
      {
        name: 'Sessions ouvertes',
        short_name: 'Sessions',
        url: '/dashboard?source=pwa#securite',
        icons: [{ src: '/icons/icon-192.png', sizes: '192x192', type: 'image/png' }],
      },
    ],
    screenshots: [
      { src: '/screenshots/mobile-dashboard.png', sizes: '780x1688', type: 'image/png', form_factor: 'narrow', label: 'Votre compte MySSO' },
      { src: '/screenshots/mobile-consent.png', sizes: '780x1688', type: 'image/png', form_factor: 'narrow', label: 'Autoriser une application' },
      { src: '/screenshots/desktop-dashboard.png', sizes: '1280x800', type: 'image/png', form_factor: 'wide', label: 'Votre compte MySSO' },
    ],
  };
}
