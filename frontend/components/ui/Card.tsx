import type { ReactNode } from 'react';

export function Card({ children, className = '', tone = 'default' }: { children: ReactNode; className?: string; tone?: 'default' | 'danger' }) {
  const border = tone === 'danger' ? 'border-danger/30' : 'border-line';
  return (
    <div className={`rounded-[var(--radius-card)] border ${border} bg-surface shadow-[var(--shadow-card)] ${className}`}>
      {children}
    </div>
  );
}

/**
 * A settings-style section: title + description on top, content below.
 * `id` makes it reachable from in-page navigation.
 */
export function Section({
  id,
  title,
  description,
  actions,
  children,
  tone = 'default',
}: {
  id?: string;
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  tone?: 'default' | 'danger';
}) {
  return (
    <section id={id} aria-labelledby={id ? `${id}-title` : undefined} className="scroll-mt-24">
      <Card tone={tone}>
        <header className="flex flex-wrap items-start justify-between gap-3 border-b border-line px-5 pb-4 pt-5 sm:px-6">
          <div className="min-w-0 space-y-1">
            <h2 id={id ? `${id}-title` : undefined} className={`text-[15px] font-semibold ${tone === 'danger' ? 'text-danger-text' : ''}`}>
              {title}
            </h2>
            {description && <p className="max-w-prose text-sm text-muted">{description}</p>}
          </div>
          {actions}
        </header>
        <div className="px-5 py-4 sm:px-6">{children}</div>
      </Card>
    </section>
  );
}

/** Row in a definition list (label on the left on wide screens) */
export function Row({ label, children, last }: { label: string; children: ReactNode; last?: boolean }) {
  return (
    <div className={`grid gap-1 py-3.5 sm:grid-cols-[180px_1fr] sm:gap-6 ${last ? '' : 'border-b border-line'}`}>
      <dt className="text-sm text-muted">{label}</dt>
      <dd className="min-w-0 text-sm">{children}</dd>
    </div>
  );
}

export function PageHeader({ title, description, actions }: { title: string; description?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-4">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        {description && <p className="text-sm text-muted">{description}</p>}
      </div>
      {actions}
    </div>
  );
}
