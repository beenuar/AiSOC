'use client';

/**
 * The banner a console surface shows when one of its requests failed.
 *
 * Replaces five hand-rolled amber `<div>`s that all said some variant of
 * "<X> API unreachable — showing demo <things>" while showing no things at
 * all. Three properties they lacked and this has:
 *
 * * **A retry that retries.** Every one of them was terminal: the operator's
 *   only recourse was a full page reload, which on a transient 503 is a
 *   disproportionate thing to have to discover.
 * * **`role="status"`.** The banner appears after mount in response to an
 *   async failure, so a screen-reader user otherwise gets no announcement that
 *   the list they are waiting on is never coming.
 * * **No heading element.** These sit between a page `<h1>` and section
 *   `<h2>`s, and introducing a heading here would break the document outline
 *   the axe-core WCAG AA gate checks.
 */

import { useState } from 'react';
import { clsx } from 'clsx';

export interface FailureBannerProps {
  /** Short noun phrase for what is unavailable, e.g. `'Connectors unavailable'`. */
  title: string;
  /** One sentence from `describeApiFailure` — what failed and what is on screen. */
  message: string;
  /**
   * Re-issues the request that failed. Usually SWR's `mutate`. Omitted only
   * where there is genuinely nothing to re-issue.
   */
  onRetry?: () => void | Promise<unknown>;
  className?: string;
}

export function FailureBanner({ title, message, onRetry, className }: FailureBannerProps) {
  const [retrying, setRetrying] = useState(false);

  const handleRetry = async () => {
    if (!onRetry || retrying) return;
    setRetrying(true);
    try {
      await onRetry();
    } finally {
      // The banner stays up if the retry fails again; the caller re-renders it
      // from the still-present error. Only the button returns to rest.
      setRetrying(false);
    }
  };

  return (
    <div
      role="status"
      className={clsx(
        'flex flex-wrap items-center gap-x-3 gap-y-2 rounded-md border border-amber-500/30 bg-amber-500/5 px-4 py-2 text-xs text-amber-200',
        className,
      )}
    >
      <span className="flex-1 min-w-[16rem]">
        <span className="font-semibold">{title}:</span> {message}
      </span>
      {onRetry && (
        <button
          type="button"
          onClick={() => void handleRetry()}
          disabled={retrying}
          className="shrink-0 rounded border border-amber-400/40 px-2 py-1 font-medium text-amber-100 transition-colors hover:bg-amber-400/10 disabled:opacity-60"
        >
          {retrying ? 'Retrying…' : 'Retry'}
        </button>
      )}
    </div>
  );
}
