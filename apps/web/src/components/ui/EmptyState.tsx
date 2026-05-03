import { clsx } from 'clsx';
import type { ReactNode } from 'react';

interface EmptyStateProps {
  icon?: ReactNode;
  title: string;
  description?: string;
  action?: ReactNode;
  className?: string;
}

/**
 * Friendly placeholder shown when a list/section has no data yet.
 *
 * Always pair with a clear `action` so users can do *something* — a link
 * to docs, a "Connect data source" button, or a way to seed demo data.
 */
export function EmptyState({ icon, title, description, action, className }: EmptyStateProps) {
  return (
    <div
      className={clsx(
        'flex flex-col items-center justify-center rounded-xl border border-dashed border-gray-800 bg-gray-900/30 px-6 py-12 text-center',
        className,
      )}
    >
      {icon && (
        <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-gray-800/60 text-blue-400">
          {icon}
        </div>
      )}
      <h3 className="text-base font-semibold text-gray-100">{title}</h3>
      {description && (
        <p className="mt-1 max-w-md text-sm text-gray-500">{description}</p>
      )}
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}
