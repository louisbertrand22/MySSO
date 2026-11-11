import Link from 'next/link';

/** MySSO mark: a single ring opening onto a path (one identity, many doors). */
export function LogoMark({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      <rect width="32" height="32" rx="8.5" fill="var(--accent)" />
      <circle cx="16" cy="13" r="4.6" fill="none" stroke="var(--accent-fg)" strokeWidth="2.6" />
      <path d="M16 17.6V24.5" stroke="var(--accent-fg)" strokeWidth="2.6" strokeLinecap="round" />
    </svg>
  );
}

export function Logo({ href = '/', size = 28 }: { href?: string; size?: number }) {
  return (
    <Link href={href} className="inline-flex items-center gap-2.5 rounded-md font-semibold tracking-tight text-fg">
      <LogoMark size={size} />
      <span className="text-[15px]">MySSO</span>
    </Link>
  );
}
