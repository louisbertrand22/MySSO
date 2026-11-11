import type { ReactNode } from 'react';
import { Logo } from './Brand';

/**
 * Layout for every authentication screen (login, register, consent, errors…):
 * brand at the top, one focused card, quiet dotted background.
 */
export default function AuthShell({
  title,
  description,
  children,
  below,
  icon,
}: {
  title: ReactNode;
  description?: ReactNode;
  children: ReactNode;
  /** Content under the card (e.g. "No account? Sign up") */
  below?: ReactNode;
  /** Optional icon shown above the title for status screens */
  icon?: ReactNode;
}) {
  return (
    <div className="relative flex flex-1 flex-col bg-dots">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top,transparent_0%,var(--bg)_70%)]" aria-hidden="true" />
      <header className="relative px-5 pt-6 sm:px-8">
        <Logo />
      </header>
      <main id="main" className="relative flex flex-1 items-start justify-center px-4 pb-16 pt-10 sm:items-center sm:pt-6">
        <div className="w-full max-w-[400px] animate-enter">
          <div className="rounded-[var(--radius-card)] border border-line bg-surface p-6 shadow-[var(--shadow-pop)] sm:p-8">
            <div className="mb-6 space-y-2">
              {icon && <div className="mb-4">{icon}</div>}
              <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
              {description && <div className="text-sm text-muted">{description}</div>}
            </div>
            {children}
          </div>
          {below && <div className="mt-6 text-center text-sm text-muted">{below}</div>}
        </div>
      </main>
    </div>
  );
}

/** Round icon badge used on status screens (email sent, link expired…) */
export function StatusIcon({ tone, children }: { tone: 'accent' | 'danger' | 'warning' | 'neutral'; children: ReactNode }) {
  const tones = {
    accent: 'bg-accent-soft text-accent-text',
    danger: 'bg-danger-soft text-danger-text',
    warning: 'bg-warning-soft text-warning-text',
    neutral: 'bg-surface-2 text-muted',
  };
  return <div className={`grid size-11 place-items-center rounded-full ${tones[tone]}`}>{children}</div>;
}
