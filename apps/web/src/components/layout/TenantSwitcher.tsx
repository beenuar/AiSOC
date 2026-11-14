'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import { clsx } from 'clsx';
import { useTenant } from '@/components/layout/TenantProvider';

interface TenantSwitcherProps {
  className?: string;
}

/**
 * W5 — Tenant switcher.
 *
 * Renders the active tenant as a pill button and (for MSSP parents) lets the
 * operator flip to a child tenant. Selection delegates to
 * `TenantProvider.setTenant`, which:
 *   - writes the chosen tenant id to localStorage,
 *   - dispatches `aisoc:tenant-switched`,
 *   - reloads the page to flush every SWR cache and re-issue API calls with
 *     the new `X-Tenant-Id`.
 *
 * For standalone tenants we render a read-only pill (no chevron, no
 * dropdown) so the chrome still telegraphs the active tenant without
 * pretending switching is possible.
 */
export function TenantSwitcher({ className }: TenantSwitcherProps) {
  const { current, available, setTenant, loading, error } = useTenant();
  const [open, setOpen] = useState(false);
  const [filter, setFilter] = useState('');
  const buttonRef = useRef<HTMLButtonElement | null>(null);
  const menuRef = useRef<HTMLDivElement | null>(null);
  const filterInputRef = useRef<HTMLInputElement | null>(null);

  const canSwitch = available.length > 1;

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

  // Auto-focus the filter once the menu is shown — when there are more than
  // a handful of tenants, typing to filter is faster than mouse navigation.
  useEffect(() => {
    if (open && available.length > 6) {
      // next tick so the input is mounted
      const id = window.setTimeout(() => filterInputRef.current?.focus(), 0);
      return () => window.clearTimeout(id);
    }
  }, [open, available.length]);

  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return available;
    return available.filter(
      (t) =>
        t.name.toLowerCase().includes(q) || t.id.toLowerCase().includes(q),
    );
  }, [filter, available]);

  if (loading && !current) {
    return (
      <div
        className={clsx(
          'inline-flex items-center gap-1.5 rounded-md border border-surface-border bg-surface-card/40 px-2.5 py-1 text-xs text-fg-subtle',
          className,
        )}
        aria-label="Loading tenant"
      >
        <svg
          className="h-3.5 w-3.5 animate-spin"
          fill="none"
          viewBox="0 0 24 24"
          aria-hidden
        >
          <circle
            cx="12"
            cy="12"
            r="9"
            stroke="currentColor"
            strokeWidth="2.5"
            strokeOpacity="0.25"
          />
          <path
            d="M21 12a9 9 0 00-9-9"
            stroke="currentColor"
            strokeWidth="2.5"
            strokeLinecap="round"
          />
        </svg>
        Loading…
      </div>
    );
  }

  if (!current) {
    // Not authenticated, or `/tenants/me` failed without a fallback.
    return null;
  }

  // Standalone tenants get a read-only pill so the chrome still shows the
  // active org but doesn't suggest switching is possible.
  if (!canSwitch) {
    return (
      <div
        title={error ?? `Tenant: ${current.name}`}
        className={clsx(
          'inline-flex items-center gap-1.5 rounded-md border border-surface-border bg-surface-card/60 px-2.5 py-1 text-xs text-fg-secondary',
          className,
        )}
      >
        <TenantIcon />
        <span className="max-w-[10rem] truncate font-medium text-fg-primary">
          {current.name}
        </span>
      </div>
    );
  }

  return (
    <div className={clsx('relative', className)}>
      <button
        ref={buttonRef}
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label={`Active tenant: ${current.name}. Click to switch.`}
        className="inline-flex items-center gap-1.5 rounded-md border border-surface-border bg-surface-card/60 px-2.5 py-1 text-xs text-fg-secondary transition-colors hover:border-brand-500/40 hover:bg-surface-card hover:text-fg-primary focus:border-brand-500/60 focus:outline-none focus:ring-2 focus:ring-brand-500/30"
      >
        <TenantIcon />
        <span className="max-w-[10rem] truncate font-medium text-fg-primary">
          {current.name}
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
          role="dialog"
          aria-label="Switch tenant"
          className="absolute right-0 z-30 mt-1.5 w-72 overflow-hidden rounded-md border border-surface-border bg-surface-raised shadow-lg ring-1 ring-black/5"
        >
          <div className="border-b border-surface-border px-3 py-2 text-[10px] font-semibold uppercase tracking-wide text-fg-subtle">
            Switch tenant
            <span className="ml-2 text-fg-muted normal-case">
              · {available.length} available
            </span>
          </div>

          {available.length > 6 && (
            <div className="border-b border-surface-border px-2 py-2">
              <input
                ref={filterInputRef}
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                placeholder="Filter tenants…"
                className="w-full rounded-md border border-surface-border bg-surface-card px-2 py-1 text-sm text-fg-primary placeholder:text-fg-subtle focus:border-brand-500/60 focus:outline-none focus:ring-2 focus:ring-brand-500/30"
              />
            </div>
          )}

          <ul
            role="listbox"
            aria-label="Tenants"
            className="max-h-72 overflow-y-auto py-1"
          >
            {filtered.length === 0 && (
              <li className="px-3 py-2 text-sm text-fg-subtle">
                No tenants match “{filter}”.
              </li>
            )}
            {filtered.map((t) => {
              const isActive = t.id === current.id;
              return (
                <li key={t.id}>
                  <button
                    type="button"
                    role="option"
                    aria-selected={isActive}
                    disabled={isActive}
                    onClick={() => {
                      if (!isActive) setTenant(t.id);
                    }}
                    className={clsx(
                      'flex w-full items-center justify-between gap-3 px-3 py-2 text-left text-sm transition-colors',
                      isActive
                        ? 'cursor-default bg-surface-hover text-fg-primary'
                        : 'text-fg-secondary hover:bg-surface-hover hover:text-fg-primary',
                    )}
                  >
                    <span className="flex min-w-0 flex-col">
                      <span className="truncate font-medium">{t.name}</span>
                      <span className="truncate text-[10px] uppercase tracking-wide text-fg-subtle">
                        {t.role === 'parent'
                          ? 'MSSP parent'
                          : t.role === 'child'
                            ? 'Child tenant'
                            : 'Standalone'}
                      </span>
                    </span>
                    {isActive && (
                      <svg
                        className="h-3.5 w-3.5 flex-shrink-0 text-brand-500"
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

          {error && (
            <div className="border-t border-surface-border bg-rose-500/5 px-3 py-2 text-xs text-rose-300">
              {error}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function TenantIcon() {
  return (
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
        d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0H5m14 0h2m-2 0V9m-7 12V9m0 0h7M5 21h2m-2 0V9m0 0h7"
      />
    </svg>
  );
}
