import type { ReactNode } from 'react';
import { AlertIcon, CheckIcon, InfoIcon } from './Icons';

export function Spinner({ size = 16, className = '' }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" className={`animate-spin ${className}`} aria-hidden="true">
      <circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" strokeOpacity="0.2" strokeWidth="2.5" />
      <path d="M21 12a9 9 0 0 0-9-9" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" />
    </svg>
  );
}

export function Skeleton({ className = '' }: { className?: string }) {
  return <div className={`animate-pulse rounded-md bg-surface-2 ${className}`} aria-hidden="true" />;
}

type Tone = 'info' | 'success' | 'warning' | 'danger';

const alertTones: Record<Tone, string> = {
  info: 'bg-surface-2 text-fg border-line',
  success: 'bg-success-soft text-success-text border-transparent',
  warning: 'bg-warning-soft text-warning-text border-transparent',
  danger: 'bg-danger-soft text-danger-text border-transparent',
};

export function Alert({ tone = 'info', title, children, className = '' }: { tone?: Tone; title?: string; children?: ReactNode; className?: string }) {
  const Icon = tone === 'success' ? CheckIcon : tone === 'info' ? InfoIcon : AlertIcon;
  return (
    <div role={tone === 'danger' ? 'alert' : 'status'} className={`flex gap-3 rounded-[var(--radius-control)] border px-3.5 py-3 text-sm ${alertTones[tone]} ${className}`}>
      <Icon size={18} className="mt-px shrink-0" />
      <div className="min-w-0 space-y-0.5">
        {title && <p className="font-medium">{title}</p>}
        {children && <div className={title ? 'opacity-90' : ''}>{children}</div>}
      </div>
    </div>
  );
}

type BadgeTone = 'neutral' | 'accent' | 'warning' | 'danger';

const badgeTones: Record<BadgeTone, string> = {
  neutral: 'bg-surface-2 text-muted',
  accent: 'bg-accent-soft text-accent-text',
  warning: 'bg-warning-soft text-warning-text',
  danger: 'bg-danger-soft text-danger-text',
};

export function Badge({ tone = 'neutral', mono, children }: { tone?: BadgeTone; mono?: boolean; children: ReactNode }) {
  return (
    <span className={`inline-flex items-center gap-1 rounded-[5px] px-1.5 py-0.5 text-xs font-medium leading-4 ${mono ? 'font-mono' : ''} ${badgeTones[tone]}`}>
      {children}
    </span>
  );
}

export function EmptyState({ icon, title, children, action }: { icon?: ReactNode; title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-start gap-3 py-8">
      {icon && <div className="grid size-10 place-items-center rounded-[var(--radius-control)] bg-surface-2 text-muted">{icon}</div>}
      <div className="space-y-1">
        <p className="font-medium">{title}</p>
        {children && <p className="max-w-prose text-sm text-muted">{children}</p>}
      </div>
      {action}
    </div>
  );
}

/** Centered loading state for a whole page */
export function PageLoader({ label = 'Chargement…' }: { label?: string }) {
  return (
    <div className="flex flex-1 items-center justify-center gap-3 py-24 text-sm text-muted" role="status">
      <Spinner />
      {label}
    </div>
  );
}
