import { clsx } from 'clsx';
import type { ReactNode } from 'react';

interface ErrorStateProps {
  title?: string;
  description?: string;
  error?: unknown;
  onRetry?: () => void;
  action?: ReactNode;
  className?: string;
}

function formatError(error: unknown): string | undefined {
  if (!error) return undefined;
  if (error instanceof Error) return error.message;
  if (typeof error === 'string') return error;
  try {
    return JSON.stringify(error);
  } catch {
    return String(error);
  }
}

/**
 * Surface a backend/network failure clearly so the analyst can act.
 *
 * Hides raw exceptions behind a friendly title, but exposes the
 * underlying message to power users when present (helpful for support).
 */
export function ErrorState({
  title = 'Something went wrong',
  description = "We couldn't load this view. Try again or check the service status.",
  error,
  onRetry,
  action,
  className,
}: ErrorStateProps) {
  const detail = formatError(error);

  return (
    <div
      className={clsx(
        'rounded-xl border border-red-500/30 bg-red-500/5 px-6 py-8 text-center',
        className,
      )}
      role="alert"
    >
      <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-red-500/15 text-red-400">
        <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={1.5}
            d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"
          />
        </svg>
      </div>
      <h3 className="text-base font-semibold text-red-200">{title}</h3>
      <p className="mx-auto mt-1 max-w-md text-sm text-red-300/70">{description}</p>
      {detail && (
        <pre className="mx-auto mt-4 max-w-xl overflow-x-auto rounded-md bg-black/30 px-3 py-2 text-left font-mono text-xs text-red-300/80">
          {detail}
        </pre>
      )}
      <div className="mt-5 flex items-center justify-center gap-3">
        {onRetry && (
          <button
            onClick={onRetry}
            className="rounded-md border border-red-500/40 bg-red-500/10 px-4 py-2 text-sm font-medium text-red-200 transition-colors hover:bg-red-500/20"
          >
            Retry
          </button>
        )}
        {action}
      </div>
    </div>
  );
}
