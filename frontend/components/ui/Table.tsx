import type { ReactNode, ThHTMLAttributes, TdHTMLAttributes } from 'react';

// Full class names so Tailwind can detect them (no string interpolation)
const ALIGN = { left: 'text-left', right: 'text-right', center: 'text-center' } as const;

export function Table({ children }: { children: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-sm">{children}</table>
    </div>
  );
}

export function Th({ className = '', align = 'left', ...props }: ThHTMLAttributes<HTMLTableCellElement> & { align?: 'left' | 'right' | 'center' }) {
  return (
    <th
      scope="col"
      className={`whitespace-nowrap border-b border-line bg-surface-2/60 px-4 py-2.5 text-[12px] font-medium text-muted first:pl-5 last:pr-5 ${ALIGN[align]} ${className}`}
      {...props}
    />
  );
}

export function Td({ className = '', align = 'left', ...props }: TdHTMLAttributes<HTMLTableCellElement> & { align?: 'left' | 'right' | 'center' }) {
  return <td className={`border-b border-line px-4 py-3 align-middle first:pl-5 last:pr-5 ${ALIGN[align]} ${className}`} {...props} />;
}

/** Row hover + fade for disabled rows */
export function Tr({ children, muted, onClick, className = '' }: { children: ReactNode; muted?: boolean; onClick?: () => void; className?: string }) {
  return (
    <tr onClick={onClick} className={`transition-colors last:[&>td]:border-b-0 hover:bg-surface-2/50 ${muted ? 'opacity-55' : ''} ${onClick ? 'cursor-pointer' : ''} ${className}`}>
      {children}
    </tr>
  );
}
