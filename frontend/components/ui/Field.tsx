'use client';

import { useId, useState, cloneElement, isValidElement } from 'react';
import type { InputHTMLAttributes, ReactElement, ReactNode, SelectHTMLAttributes, TextareaHTMLAttributes } from 'react';
import { EyeIcon, EyeOffIcon } from './Icons';

export const controlClasses =
  'block w-full rounded-[var(--radius-control)] border border-line bg-surface px-3 text-sm text-fg ' +
  'placeholder:text-subtle shadow-[var(--shadow-card)] transition-[border-color,box-shadow] duration-150 ' +
  'hover:border-line-strong focus:border-accent focus:outline-none focus:ring-[3px] focus:ring-accent/20 ' +
  'disabled:cursor-not-allowed disabled:opacity-60 aria-[invalid=true]:border-danger aria-[invalid=true]:focus:ring-danger/20';

interface FieldProps {
  label: string;
  hint?: ReactNode;
  error?: string | null;
  /** Element shown on the right of the label (e.g. "Forgot password?") */
  aside?: ReactNode;
  children: ReactElement<{ id?: string; 'aria-describedby'?: string; 'aria-invalid'?: boolean }>;
  className?: string;
}

/** Label + control + hint/error, wired together for screen readers. */
export function Field({ label, hint, error, aside, children, className = '' }: FieldProps) {
  const id = useId();
  const messageId = `${id}-msg`;
  const control = isValidElement(children)
    ? cloneElement(children, {
        id,
        'aria-describedby': hint || error ? messageId : undefined,
        'aria-invalid': error ? true : undefined,
      })
    : children;

  return (
    <div className={`space-y-1.5 ${className}`}>
      <div className="flex items-baseline justify-between gap-3">
        <label htmlFor={id} className="text-sm font-medium text-fg">{label}</label>
        {aside}
      </div>
      {control}
      {error ? (
        <p id={messageId} className="text-[13px] text-danger-text">{error}</p>
      ) : hint ? (
        <p id={messageId} className="text-[13px] text-muted">{hint}</p>
      ) : null}
    </div>
  );
}

export function Input({ className = '', ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={`${controlClasses} h-10 ${className}`} {...props} />;
}

export function PasswordInput({ className = '', ...props }: Omit<InputHTMLAttributes<HTMLInputElement>, 'type'>) {
  const [visible, setVisible] = useState(false);
  return (
    <div className="relative">
      <input type={visible ? 'text' : 'password'} className={`${controlClasses} h-10 pr-10 ${className}`} {...props} />
      <button
        type="button"
        onClick={() => setVisible((v) => !v)}
        className="absolute inset-y-0 right-0 grid w-10 place-items-center rounded-r-[var(--radius-control)] text-subtle transition-colors hover:text-fg"
        aria-label={visible ? 'Masquer le mot de passe' : 'Afficher le mot de passe'}
        tabIndex={-1}
      >
        {visible ? <EyeOffIcon size={17} /> : <EyeIcon size={17} />}
      </button>
    </div>
  );
}

export function Textarea({ className = '', ...props }: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea className={`${controlClasses} py-2 leading-relaxed ${className}`} {...props} />;
}

export function Select({ className = '', children, ...props }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select className={`${controlClasses} h-10 pr-8 ${className}`} {...props}>
      {children}
    </select>
  );
}

export function Checkbox({ label, ...props }: InputHTMLAttributes<HTMLInputElement> & { label: string }) {
  const id = useId();
  return (
    <label htmlFor={id} className="inline-flex cursor-pointer items-center gap-2 text-sm text-muted select-none">
      <input id={id} type="checkbox" className="size-4 rounded border-line-strong accent-[var(--accent)]" {...props} />
      {label}
    </label>
  );
}

/** Accessible on/off switch */
export function Switch({ checked, onChange, label, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: string; disabled?: boolean }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={`relative inline-flex h-6 w-10 shrink-0 items-center rounded-full transition-colors duration-200 disabled:opacity-50 ${checked ? 'bg-accent' : 'bg-line-strong'}`}
    >
      <span className={`inline-block size-5 rounded-full bg-white shadow-sm transition-transform duration-200 ${checked ? 'translate-x-[18px]' : 'translate-x-0.5'}`} />
    </button>
  );
}

/** Segmented control (radio group styled as buttons) */
export function Segmented<T extends string>({ value, onChange, options, label }: { value: T; onChange: (v: T) => void; options: { value: T; label: string }[]; label: string }) {
  return (
    <div role="radiogroup" aria-label={label} className="inline-flex rounded-[var(--radius-control)] border border-line bg-surface-2 p-0.5">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          role="radio"
          aria-checked={value === o.value}
          onClick={() => onChange(o.value)}
          className={`h-8 rounded-[6px] px-3 text-[13px] font-medium transition-colors ${
            value === o.value ? 'bg-surface text-fg shadow-[var(--shadow-card)]' : 'text-muted hover:text-fg'
          }`}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}
