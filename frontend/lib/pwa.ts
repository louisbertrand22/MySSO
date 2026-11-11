'use client';

import { useSyncExternalStore } from 'react';

/**
 * Install state of the PWA, shared across the app.
 * `beforeinstallprompt` fires once, early, on page load: it is captured globally
 * (see PwaSetup) so the "Install" button works whichever page it is shown on.
 */
export type InstallState =
  | 'installed' // running as an installed app
  | 'available' // the browser can show its install dialog (Chrome, Edge, Android…)
  | 'ios' // iOS Safari: installation is manual (Share → Add to Home Screen)
  | 'unsupported'; // browser without install support (e.g. Firefox desktop)

interface BeforeInstallPromptEvent extends Event {
  prompt: () => Promise<void>;
  userChoice: Promise<{ outcome: 'accepted' | 'dismissed' }>;
}

let deferredPrompt: BeforeInstallPromptEvent | null = null;
let installedNow = false;
const listeners = new Set<() => void>();
const notify = () => listeners.forEach((l) => l());

function isStandalone(): boolean {
  return (
    window.matchMedia('(display-mode: standalone)').matches ||
    (navigator as Navigator & { standalone?: boolean }).standalone === true
  );
}

function isIos(): boolean {
  const ua = navigator.userAgent;
  // iPadOS reports itself as a Mac: detect it through touch support
  return /iPhone|iPad|iPod/.test(ua) || (ua.includes('Macintosh') && navigator.maxTouchPoints > 1);
}

function getState(): InstallState {
  if (installedNow || isStandalone()) return 'installed';
  if (deferredPrompt) return 'available';
  if (isIos()) return 'ios';
  return 'unsupported';
}

/** Called once from PwaSetup: captures the browser's install event. */
export function listenForInstallPrompt(): () => void {
  const onPrompt = (e: Event) => {
    e.preventDefault(); // keep it for our own button instead of the mini-infobar
    deferredPrompt = e as BeforeInstallPromptEvent;
    notify();
  };
  const onInstalled = () => {
    deferredPrompt = null;
    installedNow = true;
    notify();
  };
  window.addEventListener('beforeinstallprompt', onPrompt);
  window.addEventListener('appinstalled', onInstalled);
  return () => {
    window.removeEventListener('beforeinstallprompt', onPrompt);
    window.removeEventListener('appinstalled', onInstalled);
  };
}

/** Opens the browser's install dialog. Returns true if the user accepted. */
export async function promptInstall(): Promise<boolean> {
  if (!deferredPrompt) return false;
  const prompt = deferredPrompt;
  deferredPrompt = null; // a prompt event can only be used once
  await prompt.prompt();
  const { outcome } = await prompt.userChoice;
  if (outcome === 'accepted') installedNow = true;
  notify();
  return outcome === 'accepted';
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  const media = window.matchMedia('(display-mode: standalone)');
  media.addEventListener('change', listener);
  return () => {
    listeners.delete(listener);
    media.removeEventListener('change', listener);
  };
}

export function useInstallState(): InstallState {
  // Server render: "unsupported" (nothing shown) until the client knows better
  return useSyncExternalStore(subscribe, getState, () => 'unsupported');
}
