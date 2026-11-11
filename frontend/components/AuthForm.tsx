'use client';

import { useState, FormEvent, useEffect } from 'react';
import type { ReactNode } from 'react';
import { Field, Input, PasswordInput, Checkbox } from './ui/Field';
import { Button } from './ui/Button';
import { Alert } from './ui/Feedback';
import { CheckIcon } from './ui/Icons';
import { PASSWORD_RULES, passwordError } from '@/lib/password';

interface AuthFormProps {
  mode: 'login' | 'register';
  onSubmit: (email: string, password: string) => Promise<void>;
  error: string | null;
  /** Shown on the right of the password label (e.g. "Forgot password?") */
  passwordAside?: ReactNode;
}

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const SAVED_EMAIL_KEY = 'savedUsername';

export default function AuthForm({ mode, onSubmit, error, passwordAside }: AuthFormProps) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [emailError, setEmailError] = useState<string | null>(null);
  const [passwordErr, setPasswordErr] = useState<string | null>(null);
  const [confirmError, setConfirmError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [rememberMe, setRememberMe] = useState(false);

  useEffect(() => {
    if (mode !== 'login') return;
    try {
      const saved = localStorage.getItem(SAVED_EMAIL_KEY);
      if (saved) {
        setEmail(saved);
        setRememberMe(true);
      }
    } catch {
      // storage unavailable
    }
  }, [mode]);

  const validateEmail = () => {
    const message = !email ? 'Saisissez votre adresse e-mail.' : !EMAIL_REGEX.test(email) ? 'Cette adresse e-mail n’est pas valide.' : null;
    setEmailError(message);
    return !message;
  };

  const validatePassword = () => {
    const message = !password ? 'Saisissez votre mot de passe.' : mode === 'register' ? passwordError(password) : null;
    setPasswordErr(message);
    return !message;
  };

  const validateConfirm = () => {
    const message = mode === 'register' && password !== confirmPassword ? 'Les deux mots de passe sont différents.' : null;
    setConfirmError(message);
    return !message;
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    const ok = [validateEmail(), validatePassword(), validateConfirm()].every(Boolean);
    if (!ok) return;

    if (mode === 'login') {
      try {
        if (rememberMe) localStorage.setItem(SAVED_EMAIL_KEY, email);
        else localStorage.removeItem(SAVED_EMAIL_KEY);
      } catch {
        // storage unavailable
      }
    }

    setIsSubmitting(true);
    try {
      await onSubmit(email, password);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4" noValidate>
      {error && <Alert tone="danger">{error}</Alert>}

      <Field label="Adresse e-mail" error={emailError}>
        <Input
          name="email"
          type="email"
          autoComplete="email"
          inputMode="email"
          placeholder="vous@exemple.fr"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          onBlur={() => email && validateEmail()}
          autoFocus={!email}
        />
      </Field>

      <Field label="Mot de passe" error={passwordErr} aside={passwordAside}>
        <PasswordInput
          name="password"
          autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
          value={password}
          onChange={(e) => {
            setPassword(e.target.value);
            if (passwordErr) setPasswordErr(null);
          }}
          onBlur={() => password && validatePassword()}
        />
      </Field>

      {mode === 'register' && (
        <>
          <ul className="grid grid-cols-2 gap-x-3 gap-y-1.5 text-[13px]" aria-label="Règles du mot de passe">
            {PASSWORD_RULES.map((rule) => {
              const met = rule.test(password);
              return (
                <li key={rule.label} className={`flex items-center gap-1.5 transition-colors ${met ? 'text-accent-text' : 'text-subtle'}`}>
                  <CheckIcon size={14} className={met ? '' : 'opacity-40'} />
                  {rule.label}
                </li>
              );
            })}
          </ul>

          <Field label="Confirmer le mot de passe" error={confirmError}>
            <PasswordInput
              name="confirmPassword"
              autoComplete="new-password"
              value={confirmPassword}
              onChange={(e) => {
                setConfirmPassword(e.target.value);
                if (confirmError) setConfirmError(null);
              }}
              onBlur={() => confirmPassword && validateConfirm()}
            />
          </Field>
        </>
      )}

      {mode === 'login' && (
        <Checkbox label="Se souvenir de mon e-mail" checked={rememberMe} onChange={(e) => setRememberMe(e.target.checked)} />
      )}

      <Button type="submit" size="lg" className="w-full" loading={isSubmitting}>
        {mode === 'login' ? 'Se connecter' : 'Créer mon compte'}
      </Button>
    </form>
  );
}
