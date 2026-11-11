const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000';

export interface SafeRedirect {
  href: string;
  /** true when the target is on the API origin (needs a full page navigation) */
  external: boolean;
}

/**
 * Validate a `returnTo` value so it cannot be used as an open redirect.
 * Allowed: same-site paths ("/dashboard", not "//evil.com") and URLs on the API origin
 * (the OAuth /authorize endpoint). Anything else falls back to `fallback`.
 */
export function resolveReturnTo(returnTo: string | null, fallback = '/dashboard'): SafeRedirect {
  if (!returnTo) return { href: fallback, external: false };

  // Relative path: must start with a single "/" (no "//host" or "/\host")
  if (returnTo.startsWith('/') && !returnTo.startsWith('//') && !returnTo.startsWith('/\\')) {
    return { href: returnTo, external: false };
  }

  try {
    const target = new URL(returnTo);
    const api = new URL(API_URL);
    if (target.origin === api.origin) {
      return { href: target.toString(), external: true };
    }
  } catch {
    // not a valid absolute URL
  }

  return { href: fallback, external: false };
}
