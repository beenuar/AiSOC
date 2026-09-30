'use client';

/**
 * Shared per-row action primitives for the Playbooks page.
 *
 * Extracted from PlaybooksView.tsx so the gallery can reuse them without a
 * circular import. The original behavior is preserved exactly (same fetch
 * URLs, same SWR cache keys, same UX).
 */

import React, { useState } from 'react';
import { mutate } from 'swr';
import type { Playbook } from './types';
import { apiFetch } from '@/lib/api';

/** Small toggle that flips Playbook.enabled via PUT /api/v1/playbooks/<id>. */
export function EnabledToggle({ playbook }: { playbook: Playbook }) {
  const [loading, setLoading] = useState(false);
  async function toggle() {
    setLoading(true);
    try {
      await apiFetch(`/api/v1/playbooks/${playbook.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !playbook.enabled }),
      });
      await mutate('/api/v1/playbooks');
    } finally {
      setLoading(false);
    }
  }
  return (
    <button
      onClick={toggle}
      disabled={loading}
      title={playbook.enabled ? 'Enabled — click to disable' : 'Disabled — click to enable'}
      aria-label={`${playbook.enabled ? 'Disable' : 'Enable'} ${playbook.name}`}
      aria-pressed={playbook.enabled}
      className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-1 focus:ring-offset-gray-900 disabled:opacity-50 ${
        playbook.enabled ? 'bg-green-600' : 'bg-gray-700'
      }`}
    >
      <span
        className={`inline-block h-3.5 w-3.5 rounded-full bg-white transition-transform ${
          playbook.enabled ? 'translate-x-4' : 'translate-x-1'
        }`}
      />
    </button>
  );
}

/** "Run" / dry-run button that POSTs to /api/v1/playbooks/<id>/run. */
export function RunButton({ playbook }: { playbook: Playbook }) {
  const [status, setStatus] = useState<'idle' | 'running' | 'done' | 'err'>('idle');
  async function run() {
    setStatus('running');
    try {
      const res = await apiFetch(`/api/v1/playbooks/${playbook.id}/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ context: {}, dry_run: true }),
      });
      if (!res.ok) throw new Error();
      setStatus('done');
    } catch {
      setStatus('err');
    }
    setTimeout(() => setStatus('idle'), 3000);
  }
  const label = { idle: 'Run', running: '…', done: 'OK', err: 'Err' }[status];
  const color = {
    idle:    'text-green-500 hover:text-green-400',
    running: 'text-yellow-500',
    done:    'text-green-400',
    err:     'text-red-400',
  }[status];
  return (
    <button
      onClick={run}
      disabled={status === 'running'}
      title="Dry run"
      aria-label={`Dry-run ${playbook.name}`}
      className={`text-xs px-2.5 py-1 rounded border border-gray-700 transition-colors ${color}`}
    >
      {label}
    </button>
  );
}

/** Delete a playbook (used only for user-created playbooks, not shipped packs). */
export async function deletePlaybook(id: string) {
  if (!confirm('Delete this playbook?')) return;
  await apiFetch(`/api/v1/playbooks/${id}`, { method: 'DELETE' });
  await mutate('/api/v1/playbooks');
}
