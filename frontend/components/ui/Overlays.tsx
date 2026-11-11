'use client';

import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { Button } from './Button';
import { Input } from './Field';
import { AlertIcon, CheckIcon, XIcon } from './Icons';

/* ------------------------------------------------------------------ */
/* Dialog: native <dialog> (focus trap, Escape, backdrop for free)     */
/* ------------------------------------------------------------------ */

export function Dialog({
  open,
  onClose,
  title,
  description,
  children,
  footer,
  size = 'md',
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: ReactNode;
  children?: ReactNode;
  footer?: ReactNode;
  size?: 'md' | 'lg';
}) {
  const ref = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal();
    if (!open && dialog.open) dialog.close();
  }, [open]);

  return (
    <dialog
      ref={ref}
      onClose={onClose}
      onClick={(e) => {
        if (e.target === ref.current) onClose(); // click on backdrop
      }}
      className={`m-auto w-[calc(100%-2rem)] ${size === 'lg' ? 'max-w-xl' : 'max-w-md'} rounded-[var(--radius-card)] border border-line bg-surface p-0 text-fg shadow-[var(--shadow-pop)] open:animate-enter`}
    >
      {open && (
        <div className="space-y-5 p-6">
          <div className="flex items-start justify-between gap-4">
            <div className="space-y-1.5">
              <h2 className="text-base font-semibold">{title}</h2>
              {description && <div className="text-sm text-muted">{description}</div>}
            </div>
            <button type="button" onClick={onClose} className="-m-1 rounded-md p-1 text-subtle hover:bg-surface-2 hover:text-fg" aria-label="Fermer">
              <XIcon size={18} />
            </button>
          </div>
          {children}
          {footer && <div className="flex flex-col-reverse gap-2 pt-1 sm:flex-row sm:justify-end">{footer}</div>}
        </div>
      )}
    </dialog>
  );
}

/* ------------------------------------------------------------------ */
/* Confirm: promise-based replacement for window.confirm()             */
/* ------------------------------------------------------------------ */

interface ConfirmOptions {
  title: string;
  description?: ReactNode;
  confirmLabel?: string;
  tone?: 'default' | 'danger';
  /** If set, the user must type this exact text to enable the confirm button */
  requireText?: string;
}

type ConfirmFn = (options: ConfirmOptions) => Promise<boolean>;

/* ------------------------------------------------------------------ */
/* Toasts: short, non-blocking feedback (replaces window.alert())      */
/* ------------------------------------------------------------------ */

interface Toast {
  id: number;
  tone: 'success' | 'danger';
  message: string;
}

interface OverlayContextType {
  confirm: ConfirmFn;
  toast: (message: string, tone?: Toast['tone']) => void;
}

const OverlayContext = createContext<OverlayContextType | undefined>(undefined);

export function OverlayProvider({ children }: { children: ReactNode }) {
  const [pending, setPending] = useState<(ConfirmOptions & { resolve: (v: boolean) => void }) | null>(null);
  const [typed, setTyped] = useState('');
  const [toasts, setToasts] = useState<Toast[]>([]);
  const nextId = useRef(0);

  const confirm = useCallback<ConfirmFn>(
    (options) =>
      new Promise<boolean>((resolve) => {
        setTyped('');
        setPending({ ...options, resolve });
      }),
    []
  );

  const settle = (value: boolean) => {
    pending?.resolve(value);
    setPending(null);
  };

  const toast = useCallback((message: string, tone: Toast['tone'] = 'success') => {
    const id = ++nextId.current;
    setToasts((prev) => [...prev, { id, tone, message }]);
    setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), tone === 'danger' ? 6000 : 3500);
  }, []);

  const blocked = pending?.requireText !== undefined && typed !== pending.requireText;

  return (
    <OverlayContext.Provider value={{ confirm, toast }}>
      {children}

      <Dialog
        open={pending !== null}
        onClose={() => settle(false)}
        title={pending?.title ?? ''}
        description={pending?.description}
        footer={
          <>
            <Button variant="secondary" onClick={() => settle(false)}>Annuler</Button>
            <Button variant={pending?.tone === 'danger' ? 'danger' : 'primary'} disabled={blocked} onClick={() => settle(true)}>
              {pending?.confirmLabel ?? 'Confirmer'}
            </Button>
          </>
        }
      >
        {pending?.requireText !== undefined && (
          <div className="space-y-1.5">
            <label className="text-sm text-muted">
              Tapez <span className="font-mono text-fg">{pending.requireText}</span> pour confirmer
            </label>
            <Input value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" autoFocus />
          </div>
        )}
      </Dialog>

      <div aria-live="polite" className="pointer-events-none fixed inset-x-0 bottom-0 z-50 flex flex-col items-center gap-2 p-4 sm:items-end">
        {toasts.map((t) => (
          <div
            key={t.id}
            role={t.tone === 'danger' ? 'alert' : 'status'}
            className="pointer-events-auto flex max-w-sm animate-enter items-center gap-2.5 rounded-[var(--radius-control)] border border-line bg-surface px-3.5 py-2.5 text-sm shadow-[var(--shadow-pop)]"
          >
            {t.tone === 'success' ? (
              <CheckIcon size={16} className="shrink-0 text-accent-text" />
            ) : (
              <AlertIcon size={16} className="shrink-0 text-danger-text" />
            )}
            {t.message}
          </div>
        ))}
      </div>
    </OverlayContext.Provider>
  );
}

export function useOverlay() {
  const context = useContext(OverlayContext);
  if (!context) throw new Error('useOverlay must be used within an OverlayProvider');
  return context;
}
