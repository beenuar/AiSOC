'use client';

/**
 * PlaybooksView
 * =============
 * /playbooks page — lists all playbooks with quick-run and edit actions.
 */

import React, { useState } from 'react';
import Link from 'next/link';
import useSWR, { mutate } from 'swr';
import type { Playbook } from './types';

const fetcher = (url: string) =>
  fetch(url).then((r) => {
    if (!r.ok) throw new Error('Failed to fetch');
    return r.json();
  });

const TRIGGER_COLORS: Record<string, string> = {
  alert:    'bg-red-900/40 text-red-300 border-red-800',
  case:     'bg-blue-900/40 text-blue-300 border-blue-800',
  manual:   'bg-gray-800 text-gray-400 border-gray-700',
  schedule: 'bg-purple-900/40 text-purple-300 border-purple-800',
};

function TriggerChip({ on }: { on: string }) {
  return (
    <span className={`text-xs px-2 py-0.5 rounded border ${TRIGGER_COLORS[on] ?? 'bg-gray-800 text-gray-400 border-gray-700'}`}>
      ⚡ {on}
    </span>
  );
}

function EnabledToggle({ playbook }: { playbook: Playbook }) {
  const [loading, setLoading] = useState(false);

  async function toggle() {
    setLoading(true);
    try {
      await fetch(`/api/v1/playbooks/${playbook.id}`, {
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
      className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none disabled:opacity-50 ${
        playbook.enabled ? 'bg-green-600' : 'bg-gray-700'
      }`}
      title={playbook.enabled ? 'Enabled — click to disable' : 'Disabled — click to enable'}
    >
      <span
        className={`inline-block h-3.5 w-3.5 rounded-full bg-white transition-transform ${
          playbook.enabled ? 'translate-x-4' : 'translate-x-1'
        }`}
      />
    </button>
  );
}

function RunButton({ playbook }: { playbook: Playbook }) {
  const [status, setStatus] = useState<'idle' | 'running' | 'done' | 'err'>('idle');

  async function run() {
    setStatus('running');
    try {
      const res = await fetch(`/api/v1/playbooks/${playbook.id}/run`, {
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

  const label = { idle: '▶', running: '…', done: '✓', err: '✕' }[status];
  const color = {
    idle: 'text-green-500 hover:text-green-400',
    running: 'text-yellow-500',
    done: 'text-green-400',
    err: 'text-red-400',
  }[status];

  return (
    <button
      onClick={run}
      disabled={status === 'running'}
      className={`text-xs px-2.5 py-1 rounded border border-gray-700 transition-colors ${color}`}
      title="Dry run"
    >
      {label}
    </button>
  );
}

async function deletePlaybook(id: string) {
  if (!confirm('Delete this playbook?')) return;
  await fetch(`/api/v1/playbooks/${id}`, { method: 'DELETE' });
  await mutate('/api/v1/playbooks');
}

export function PlaybooksView() {
  const { data, isLoading, error } = useSWR<Playbook[]>('/api/v1/playbooks', fetcher, {
    refreshInterval: 30000,
  });

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Playbooks</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Automated response workflows triggered by alerts and cases
          </p>
        </div>
        <Link
          href="/playbooks/new"
          className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium transition-colors"
        >
          + New Playbook
        </Link>
      </div>

      {/* Loading */}
      {isLoading && (
        <div className="text-gray-600 text-sm">Loading playbooks…</div>
      )}

      {/* Error */}
      {error && (
        <div className="bg-red-950/40 border border-red-900 rounded-lg px-4 py-3 text-red-400 text-sm">
          Failed to load playbooks. Is the agents service running?
        </div>
      )}

      {/* Empty state */}
      {!isLoading && !error && (!data || data.length === 0) && (
        <div className="flex flex-col items-center justify-center py-20 text-center">
          <div className="text-5xl mb-4">📋</div>
          <div className="text-lg font-medium text-gray-400 mb-2">No playbooks yet</div>
          <div className="text-sm text-gray-600 mb-6">
            Create a playbook to automate your SOC response workflows
          </div>
          <Link
            href="/playbooks/new"
            className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-sm transition-colors"
          >
            Create your first playbook
          </Link>
        </div>
      )}

      {/* Playbook list */}
      {data && data.length > 0 && (
        <div className="grid gap-3">
          {data.map((pb) => (
            <div
              key={pb.id}
              className={`bg-gray-900/60 border rounded-xl px-5 py-4 flex items-center gap-4 transition-colors ${
                pb.enabled
                  ? 'border-gray-800 hover:border-gray-700'
                  : 'border-gray-800/40 opacity-60'
              }`}
            >
              {/* Enable toggle */}
              <EnabledToggle playbook={pb} />

              {/* Info */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <Link
                    href={`/playbooks/${pb.id}`}
                    className="text-white font-medium hover:text-blue-300 transition-colors truncate"
                  >
                    {pb.name}
                  </Link>
                  <TriggerChip on={pb.trigger.on} />
                  {pb.tags.slice(0, 3).map((tag) => (
                    <span
                      key={tag}
                      className="text-xs px-1.5 py-0.5 rounded bg-gray-800 text-gray-500"
                    >
                      {tag}
                    </span>
                  ))}
                </div>
                {pb.description && (
                  <p className="text-sm text-gray-500 mt-0.5 truncate">
                    {pb.description}
                  </p>
                )}
                <div className="flex items-center gap-3 mt-1 text-xs text-gray-700">
                  <span>{pb.steps.length} steps</span>
                  <span>v{pb.version}</span>
                  {pb.author && <span>by {pb.author}</span>}
                </div>
              </div>

              {/* Actions */}
              <div className="flex items-center gap-2 flex-shrink-0">
                <RunButton playbook={pb} />
                <Link
                  href={`/playbooks/${pb.id}`}
                  className="text-xs px-2.5 py-1 rounded border border-gray-700 text-gray-400 hover:text-gray-200 hover:border-gray-600 transition-colors"
                >
                  Edit
                </Link>
                <button
                  onClick={() => deletePlaybook(pb.id)}
                  className="text-xs px-2.5 py-1 rounded border border-gray-800 text-gray-600 hover:text-red-400 hover:border-red-900 transition-colors"
                >
                  Delete
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
