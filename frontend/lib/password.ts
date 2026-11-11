/** Password policy shared by sign-up, password change and password reset. */
export const PASSWORD_RULES: { label: string; test: (p: string) => boolean; message: string }[] = [
  { label: '8 caractères minimum', test: (p) => p.length >= 8, message: 'Le mot de passe doit contenir au moins 8 caractères.' },
  { label: 'Une majuscule', test: (p) => /[A-Z]/.test(p), message: 'Le mot de passe doit contenir au moins une majuscule.' },
  { label: 'Une minuscule', test: (p) => /[a-z]/.test(p), message: 'Le mot de passe doit contenir au moins une minuscule.' },
  { label: 'Un chiffre', test: (p) => /[0-9]/.test(p), message: 'Le mot de passe doit contenir au moins un chiffre.' },
];

/** First unmet rule, or null when the password is acceptable */
export function passwordError(password: string): string | null {
  return PASSWORD_RULES.find((r) => !r.test(password))?.message ?? null;
}
