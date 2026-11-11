import Link from 'next/link';
import type { ComponentProps, ButtonHTMLAttributes } from 'react';
import { Spinner } from './Feedback';

export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'danger-ghost';
export type ButtonSize = 'sm' | 'md' | 'lg';

const base =
  'inline-flex items-center justify-center gap-2 font-medium whitespace-nowrap select-none ' +
  'rounded-[var(--radius-control)] transition-[background-color,border-color,color,transform,box-shadow] duration-150 ' +
  'active:translate-y-px disabled:pointer-events-none disabled:opacity-50';

const variants: Record<ButtonVariant, string> = {
  primary: 'bg-accent text-accent-fg hover:bg-accent-hover shadow-[var(--shadow-card)]',
  secondary: 'bg-surface text-fg border border-line hover:bg-surface-2 hover:border-line-strong shadow-[var(--shadow-card)]',
  ghost: 'text-muted hover:text-fg hover:bg-surface-2',
  danger: 'bg-danger text-white hover:bg-danger-hover shadow-[var(--shadow-card)]',
  'danger-ghost': 'text-danger-text hover:bg-danger-soft',
};

const sizes: Record<ButtonSize, string> = {
  sm: 'h-8 px-3 text-[13px]',
  md: 'h-10 px-4 text-sm',
  lg: 'h-11 px-5 text-[15px]',
};

export function buttonClasses(variant: ButtonVariant = 'primary', size: ButtonSize = 'md', extra = '') {
  return `${base} ${variants[variant]} ${sizes[size]} ${extra}`;
}

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  loading?: boolean;
}

export function Button({ variant = 'primary', size = 'md', loading, disabled, className = '', children, type = 'button', ...props }: ButtonProps) {
  return (
    <button type={type} disabled={disabled || loading} className={buttonClasses(variant, size, className)} aria-busy={loading || undefined} {...props}>
      {loading && <Spinner size={14} />}
      {children}
    </button>
  );
}

type ButtonLinkProps = ComponentProps<typeof Link> & { variant?: ButtonVariant; size?: ButtonSize };

export function ButtonLink({ variant = 'primary', size = 'md', className = '', ...props }: ButtonLinkProps) {
  return <Link className={buttonClasses(variant, size, className)} {...props} />;
}

/** Plain inline text link in the accent colour */
export function TextLink({ className = '', ...props }: ComponentProps<typeof Link>) {
  return (
    <Link
      className={`font-medium text-accent-text underline-offset-4 decoration-1 hover:underline ${className}`}
      {...props}
    />
  );
}
