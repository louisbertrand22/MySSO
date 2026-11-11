'use client';

import { useState } from 'react';
import { ApiService } from '@/lib/api';
import { passwordError } from '@/lib/password';
import { Button } from './ui/Button';
import { Field, PasswordInput } from './ui/Field';
import { Alert } from './ui/Feedback';
import { useOverlay } from './ui/Overlays';

export default function ChangePasswordForm({ accessToken }: { accessToken: string }) {
  const { toast } = useOverlay();
  const [open, setOpen] = useState(false);
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);

  const close = () => {
    setOpen(false);
    setCurrentPassword('');
    setNewPassword('');
    setConfirmPassword('');
    setError('');
  };

  const validate = (): string | null => {
    if (!currentPassword) return 'Saisissez votre mot de passe actuel.';
    const policy = passwordError(newPassword);
    if (policy) return policy;
    if (newPassword !== confirmPassword) return 'Les deux mots de passe sont différents.';
    if (newPassword === currentPassword) return 'Le nouveau mot de passe doit être différent de l’actuel.';
    return null;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const validationError = validate();
    if (validationError) {
      setError(validationError);
      return;
    }
    setError('');
    setSaving(true);
    try {
      await ApiService.changePassword(accessToken, currentPassword, newPassword);
      toast('Mot de passe modifié.');
      close();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Le mot de passe n’a pas pu être modifié.');
    } finally {
      setSaving(false);
    }
  };

  if (!open) {
    return (
      <div className="flex items-center justify-between gap-4">
        <span className="tracking-[0.2em] text-muted" aria-label="Mot de passe masqué">••••••••••</span>
        <Button variant="secondary" size="sm" onClick={() => setOpen(true)}>Modifier</Button>
      </div>
    );
  }

  return (
    <form onSubmit={handleSubmit} className="max-w-sm space-y-3.5 animate-enter">
      {error && <Alert tone="danger">{error}</Alert>}
      <Field label="Mot de passe actuel">
        <PasswordInput autoComplete="current-password" autoFocus value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} />
      </Field>
      <Field label="Nouveau mot de passe" hint="8 caractères minimum, avec une majuscule, une minuscule et un chiffre.">
        <PasswordInput autoComplete="new-password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} />
      </Field>
      <Field label="Confirmer le nouveau mot de passe">
        <PasswordInput autoComplete="new-password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} />
      </Field>
      <div className="flex gap-2 pt-1">
        <Button type="submit" size="sm" loading={saving}>Enregistrer</Button>
        <Button variant="ghost" size="sm" onClick={close} disabled={saving}>Annuler</Button>
      </div>
    </form>
  );
}
