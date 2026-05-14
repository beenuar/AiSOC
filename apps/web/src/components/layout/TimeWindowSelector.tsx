'use client';

import { useEffect, useRef, useState } from 'react';
import { clsx } from 'clsx';
import { useTimeWindow } from '@/components/layout/TimeWindowProvider';
import {
  TIME_WINDOWS,
  TIME_WINDOW_LONG_LABEL,
  TIME_WINDOW_SHORT_LABEL,
  type TimeWindow,
} from '@/lib/timeWindow';

interface TimeWindowSelectorProps {
  /**
   * Visual size. `'compact'` is meant for the TopBar (pill); `'full'` adds
   * a leading "Time window:" label and is meant for dashboards that want the
   * selector inline with their header.
   */
  variant?: 'compact' | 'full';
  /** Optional className for layout overrides at the call site. */
  className?: string;
}

/**
 * W4 — Global time-window selector.
 *
 * Renders a pill button + dropdown listing the four supported windows (1h /
 * 24h / 7d / 30d). Selection writes through `TimeWindowProvider.setWindow`,
 * so:
 *   - the choice persists to localStorage and to the user's preferences,
 *   - every consumer (`useTimeWindow()`) sees the update on the same tick.
 *
 * Keyboard model: ArrowUp/ArrowDown wraps through the four options,
 * Enter/Space selects, Escape closes. This matches the saved-views
 * dropdown's behaviour for consistency.
 */
export function TimeWindowSelector({
  variant = 'compact',
  className,
}: TimeWindowSelectorProps) {
  const { window: active, setWindow } = useTimeWindow();
  const [open, setOpen] = useState(false);
  const [highlight, setHighlight] = useState<number>(() =>
    Math.max(0, TIME_WINDOWS.indexOf(active)),
  );
  const buttonRef = useRef<HTMLButtonElement | null>(null);
  const menuRef = useRef<HTMLDivElement | null>(null);

  // Close on outside click / Esc — same pattern used by SavedViewsBar.
  useEffect(() => {
    if (!open) return;
    const onClick = (e: MouseEvent) => {
      const target = e.target as Node | null;
      if (
        target &&
        !buttonRef.current?.contains(target) &&
        !menuRef.current?.contains(target)
      ) {
        setOpen(false);
      }
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setOpen(false);
        buttonRef.current?.focus();
      }
    };
    document.addEventListener('mousedown', onClick);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onClick);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  // Keep keyboard highlight in sync with the active window each time we open.
  useEffect(() => {
    if (open) setHighlight(Math.max(0, TIME_WINDOWS.indexOf(active)));
  }, [open, active]);

  const handleSelect = (next: TimeWindow) => {
    setWindow(next);
    setOpen(false);
    buttonRef.current?.focus();
  };

  const onTriggerKey = (e: React.KeyboardEvent<HTMLButtonElement>) => {
    if (e.key === 'ArrowDown' || e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      setOpen(true);
    }
  };

  const onMenuKey = (e: React.KeyboardEvent<HTMLDivElement>) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setHighlight((h) => (h + 1) % TIME_WINDOWS.length);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setHighlight((h) => (h - 1 + TIME_WINDOWS.length) % TIME_WINDOWS.length);
    } else if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      handleSelect(TIME_WINDOWS[highlight]);
    } else if (e.key === 'Home') {
      e.preventDefault();
      setHighlight(0);
    } else if (e.key === 'End') {
      e.preventDefault();
      setHighlight(TIME_WINDOWS.length - 1);
    }
  };

  return (
    <div className={clsx('relative', className)}>
      <button
        ref={buttonRef}
        type="button"
        onClick={() => setOpen((o) => !o)}
        onKeyDown={onTriggerKey}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label={`Time window: ${TIME_WINDOW_LONG_LABEL[active]}`}
        className={clsx(
          'inline-flex items-center gap-1.5 rounded-md border border-surface-border bg-surface-card/60 text-fg-secondary transition-colors hover:border-brand-500/40 hover:bg-surface-card hover:text-fg-primary focus:border-brand-500/60 focus:outline-none focus:ring-2 focus:ring-brand-500/30',
          variant === 'compact' ? 'px-2.5 py-1 text-xs' : 'px-3 py-2 text-sm',
        )}
      >
        <svg
          className="h-3.5 w-3.5 text-fg-subtle"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          aria-hidden
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"
          />
        </svg>
        {variant === 'full' && (
          <span className="text-fg-muted">Window:</span>
        )}
        <span className="font-mono font-medium tabular-nums">
          {TIME_WINDOW_SHORT_LABEL[active]}
        </span>
        <svg
          className={clsx(
            'h-3 w-3 text-fg-subtle transition-transform',
            open && 'rotate-180',
          )}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          aria-hidden
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M19 9l-7 7-7-7"
          />
        </svg>
      </button>

      {open && (
        <div
          ref={menuRef}
          role="listbox"
          tabIndex={-1}
          aria-label="Select time window"
          onKeyDown={onMenuKey}
          className="absolute right-0 z-30 mt-1.5 min-w-[10rem] overflow-hidden rounded-md border border-surface-border bg-surface-raised shadow-lg ring-1 ring-black/5 focus:outline-none"
        >
          <ul className="py-1">
            {TIME_WINDOWS.map((w, idx) => {
              const isActive = w === active;
              const isHighlighted = idx === highlight;
              return (
                <li key={w}>
                  <button
                    type="button"
                    role="option"
                    aria-selected={isActive}
                    onClick={() => handleSelect(w)}
                    onMouseEnter={() => setHighlight(idx)}
                    className={clsx(
                      'flex w-full items-center justify-between gap-3 px-3 py-1.5 text-left text-sm transition-colors',
                      isHighlighted
                        ? 'bg-surface-hover text-fg-primary'
                        : 'text-fg-secondary',
                      isActive && 'font-semibold text-fg-primary',
                    )}
                  >
                    <span>{TIME_WINDOW_LONG_LABEL[w]}</span>
                    {isActive && (
                      <svg
                        className="h-3.5 w-3.5 text-brand-500"
                        fill="none"
                        viewBox="0 0 24 24"
                        stroke="currentColor"
                        aria-hidden
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M5 13l4 4L19 7"
                        />
                      </svg>
                    )}
                  </button>
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </div>
  );
}
