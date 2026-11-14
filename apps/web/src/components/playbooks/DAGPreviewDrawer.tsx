'use client';

/**
 * DAGPreviewDrawer
 * ================
 * Right-side overlay drawer that renders a read-only DAG preview of a
 * playbook (used by the gallery for one-click "Preview" before forking
 * or editing). The PlaybookFlowCanvas pulls in @xyflow/react which is a
 * sizable dependency, so we lazy-load it here to keep the gallery's
 * initial bundle small.
 *
 * Props:
 *   playbook  – playbook to preview (null = drawer closed)
 *   onClose   – fires when the user dismisses the drawer
 *   onEdit    – optional handler for the "Edit" CTA (falls back to a
 *               <Link> to /playbooks/<id> when omitted)
 *   onFork    – optional handler for the "Fork" CTA (only shown when
 *               provided, e.g. for shipped packs)
 *   forking   – when true, disables the Fork CTA and shows a spinner
 */

import React, { Suspense, lazy, useEffect } from 'react';
import Link from 'next/link';
import type { Playbook } from './types';
import { isShippedPack, categoryOf, categoryLabel, categoryBadgeClass } from './packHelpers';

// Lazy-load the React Flow canvas — it pulls in @xyflow/react and
// playbook-step icons that we don't need until the drawer opens.
const PlaybookFlowCanvas = lazy(() =>
  import('./PlaybookFlowCanvas').then((m) => ({ default: m.PlaybookFlowCanvas })),
);

interface DAGPreviewDrawerProps {
  playbook: Playbook | null;
  onClose: () => void;
  onFork?: (pb: Playbook) => void | Promise<void>;
  forking?: boolean;
}

export function DAGPreviewDrawer({ playbook, onClose, onFork, forking }: DAGPreviewDrawerProps) {
  // Close on Escape
  useEffect(() => {
    if (!playbook) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [playbook, onClose]);

  if (!playbook) return null;

  const cat = categoryOf(playbook);
  const isPack = isShippedPack(playbook);
  const triggerLabel = describeTrigger(playbook.trigger);

  return (
    <div className="fixed inset-0 z-50 flex" role="dialog" aria-modal="true" aria-label="Playbook preview">
      {/* Backdrop */}
      <button
        type="button"
        onClick={onClose}
        aria-label="Close preview"
        className="flex-1 bg-black/60 backdrop-blur-sm"
      />

      {/* Drawer panel */}
      <aside className="w-full max-w-3xl bg-gray-950 border-l border-gray-800 shadow-2xl flex flex-col">
        {/* Header */}
        <header className="flex items-start justify-between gap-3 border-b border-gray-800 px-6 py-4">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 flex-wrap">
              {isPack && (
                <span
                  className="text-xs font-semibold px-2 py-0.5 rounded border border-purple-700/60 bg-purple-900/40 text-purple-200"
                  title="Shipped reference pack — read-only. Fork to customize."
                >
                  PACK
                </span>
              )}
              {cat && (
                <span className={`text-xs px-2 py-0.5 rounded border ${categoryBadgeClass(cat)}`}>
                  {categoryLabel(cat)}
                </span>
              )}
              <h2 className="text-base font-semibold text-white truncate">{playbook.name}</h2>
              <span className="text-xs text-gray-500">v{playbook.version}</span>
            </div>
            {playbook.description && (
              <p className="text-sm text-gray-400 mt-1.5">{playbook.description}</p>
            )}
            <div className="flex items-center gap-3 mt-2 text-xs text-gray-500">
              <span>{playbook.steps.length} steps</span>
              <span aria-hidden="true">·</span>
              <span>Trigger: {triggerLabel}</span>
              {playbook.author && (
                <>
                  <span aria-hidden="true">·</span>
                  <span>by {playbook.author}</span>
                </>
              )}
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close"
            className="text-gray-500 hover:text-gray-200 transition-colors text-xl leading-none px-2 py-1"
          >
            ×
          </button>
        </header>

        {/* DAG canvas — read-only */}
        <div className="flex-1 min-h-0 bg-gray-950">
          {playbook.steps.length === 0 ? (
            <div className="h-full flex items-center justify-center text-sm text-gray-600">
              This playbook has no steps yet.
            </div>
          ) : (
            <Suspense
              fallback={
                <div className="h-full flex items-center justify-center text-sm text-gray-600">
                  Loading DAG preview…
                </div>
              }
            >
              <PlaybookFlowCanvas
                steps={playbook.steps}
                selectedId={null}
                onSelectStep={() => undefined}
                readOnly
              />
            </Suspense>
          )}
        </div>

        {/* Action bar */}
        <footer className="border-t border-gray-800 px-6 py-3 flex items-center justify-between">
          <p className="text-xs text-gray-500">
            {isPack
              ? 'Fork to make a local copy you can edit and enable.'
              : 'Open in editor to modify steps.'}
          </p>
          <div className="flex items-center gap-2">
            {onFork && isPack && (
              <button
                onClick={() => onFork(playbook)}
                disabled={forking}
                className="px-3 py-1.5 rounded-md bg-purple-700 hover:bg-purple-600 text-white text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {forking ? 'Forking…' : 'Fork to my playbooks'}
              </button>
            )}
            <Link
              href={`/playbooks/${playbook.id}`}
              className="px-3 py-1.5 rounded-md border border-gray-700 text-gray-200 hover:bg-gray-800 text-sm font-medium transition-colors"
            >
              {isPack ? 'View source' : 'Open editor'}
            </Link>
          </div>
        </footer>
      </aside>
    </div>
  );
}

function describeTrigger(trigger: Playbook['trigger']): string {
  if (!trigger || !trigger.on) return 'manual';
  if (trigger.on === 'schedule' && trigger.cron) return `schedule (${trigger.cron})`;
  if (trigger.on === 'alert' && trigger.severity?.length) {
    return `alert (${trigger.severity.join(', ')})`;
  }
  return trigger.on;
}
