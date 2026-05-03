'use client';

/**
 * PlaybooksView
 * =============
 * /playbooks page — lists all playbooks with quick-run/edit/delete,
 * a Run History tab, and a Community tab for browsing/installing community playbooks.
 */

import React, { useState, useCallback } from 'react';
import Link from 'next/link';
import useSWR, { mutate } from 'swr';
import clsx from 'clsx';
import type { Playbook, PlaybookRun } from './types';

const fetcher = (url: string) =>
  fetch(url).then((r) => {
    if (!r.ok) throw new Error('Failed to fetch');
    return r.json();
  });

/* ─────────────────────────── Chips ─────────────────────────── */

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

/* ─────────────────────────── Enable Toggle ─────────────────────────── */

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
      title={playbook.enabled ? 'Enabled — click to disable' : 'Disabled — click to enable'}
      className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none disabled:opacity-50 ${
        playbook.enabled ? 'bg-green-600' : 'bg-gray-700'
      }`}
    >
      <span className={`inline-block h-3.5 w-3.5 rounded-full bg-white transition-transform ${playbook.enabled ? 'translate-x-4' : 'translate-x-1'}`} />
    </button>
  );
}

/* ─────────────────────────── Run Button ─────────────────────────── */

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
      className={`text-xs px-2.5 py-1 rounded border border-gray-700 transition-colors ${color}`}
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

/* ─────────────────────────── Run History Tab ─────────────────────────── */

const STATUS_BADGE: Record<string, string> = {
  pending:   'bg-yellow-900/40 text-yellow-400 border-yellow-800',
  running:   'bg-blue-900/40 text-blue-400 border-blue-800',
  completed: 'bg-green-900/40 text-green-400 border-green-800',
  failed:    'bg-red-900/40 text-red-400 border-red-800',
  cancelled: 'bg-gray-800 text-gray-500 border-gray-700',
};

function RunHistoryTab() {
  const { data, isLoading, error } = useSWR<PlaybookRun[]>(
    '/api/v1/playbooks/runs?limit=100',
    fetcher,
    { refreshInterval: 10000 }
  );
  if (isLoading) return <div className="py-10 text-center text-gray-600 text-sm">Loading run history…</div>;
  if (error) return <div className="py-4 text-red-400 text-sm">Failed to load run history.</div>;
  if (!data || data.length === 0)
    return (
      <div className="flex flex-col items-center py-20 text-gray-700">
        <div className="text-4xl mb-3">📜</div>
        <div className="text-gray-500">No playbook runs yet. Trigger a dry run from the editor.</div>
      </div>
    );
  return (
    <div className="space-y-2">
      {data.map((run) => (
        <div key={run.run_id} className="bg-gray-900/60 border border-gray-800 rounded-xl px-5 py-3 flex items-center gap-4">
          <span className={`text-xs px-2 py-0.5 rounded border ${STATUS_BADGE[run.status] ?? 'bg-gray-800 text-gray-400 border-gray-700'}`}>
            {run.status}
          </span>
          <div className="flex-1 min-w-0">
            <div className="text-white text-sm font-medium truncate">{run.playbook_name}</div>
            <div className="flex items-center gap-3 mt-0.5 text-xs text-gray-600">
              <span className="font-mono">{run.run_id.slice(0, 12)}…</span>
              <span>{run.steps.length} steps</span>
              {run.dry_run && <span className="text-yellow-700 border border-yellow-900 px-1.5 rounded">dry run</span>}
              {run.started_at && <span>{new Date(run.started_at).toLocaleString()}</span>}
            </div>
          </div>
          {/* Step progress dots */}
          <div className="flex items-center gap-1">
            {run.steps.slice(0, 8).map((s) => {
              const dot =
                s.status === 'completed' ? 'bg-green-500' :
                s.status === 'failed'    ? 'bg-red-500' :
                s.status === 'running'   ? 'bg-blue-400 animate-pulse' :
                s.status === 'skipped'   ? 'bg-gray-700' : 'bg-gray-800';
              return <div key={s.step_id} className={`w-2 h-2 rounded-full ${dot}`} title={`${s.step_name}: ${s.status}`} />;
            })}
            {run.steps.length > 8 && <span className="text-xs text-gray-700">+{run.steps.length - 8}</span>}
          </div>
        </div>
      ))}
    </div>
  );
}

/* ─────────────────────────── Community Tab ─────────────────────────── */

interface CommunityPlaybook {
  id: string;
  name: string;
  description: string;
  author: string;
  tags: string[];
  install_count: number;
  rating: number;
  rating_count: number;
  status: string;
  submitted_at: string;
}

function CommunityPlaybooksTab() {
  const [search, setSearch] = useState('');
  const [sortBy, setSortBy] = useState<'install_count' | 'rating' | 'name'>('install_count');
  const [page, setPage] = useState(1);
  const [items, setItems] = useState<CommunityPlaybook[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitOpen, setSubmitOpen] = useState(false);
  const [submitJson, setSubmitJson] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [submitResult, setSubmitResult] = useState<string | null>(null);
  const PAGE_SIZE = 12;

  const load = useCallback(async (q: string, sort: string, p: number) => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams({ page: String(p), page_size: String(PAGE_SIZE), sort_by: sort });
      if (q) params.set('search', q);
      const res = await fetch(`/api/v1/community/playbooks?${params}`);
      const data = await res.json();
      setItems(data.items ?? []);
      setTotal(data.total ?? 0);
    } catch {
      setError('Failed to load community playbooks.');
    } finally {
      setLoading(false);
    }
  }, []);

  // Load on first render
  useState(() => { load(search, sortBy, page); });

  const handleSubmit = async () => {
    setSubmitting(true);
    setSubmitResult(null);
    try {
      let body: object;
      try {
        body = JSON.parse(submitJson);
      } catch {
        setSubmitResult('Invalid JSON. Please fix and retry.');
        return;
      }
      const res = await fetch('/api/v1/community/playbooks/submit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      setSubmitResult(res.ok ? `Submitted! ID: ${data.id} — Status: ${data.status}` : `Error: ${data.detail}`);
      if (res.ok) { setSubmitJson(''); load(search, sortBy, page); }
    } catch {
      setSubmitResult('Submission failed.');
    } finally {
      setSubmitting(false);
    }
  };

  const totalPages = Math.ceil(total / PAGE_SIZE);

  return (
    <div className="space-y-4">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex flex-1 min-w-[220px] gap-2">
          <input
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && load(search, sortBy, 1)}
            placeholder="Search community playbooks…"
            className="flex-1 rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-500 focus:border-zinc-500 focus:outline-none"
          />
          <button
            onClick={() => load(search, sortBy, 1)}
            className="rounded-lg bg-zinc-700 px-3 py-2 text-sm text-zinc-200 hover:bg-zinc-600 transition-colors"
          >
            Search
          </button>
        </div>

        <div className="flex gap-1 rounded-lg border border-zinc-700 bg-zinc-800 p-1">
          {(['install_count', 'rating', 'name'] as const).map((s) => (
            <button
              key={s}
              onClick={() => { setSortBy(s); load(search, s, 1); }}
              className={clsx(
                'rounded px-2.5 py-1.5 text-xs font-medium transition-colors',
                sortBy === s ? 'bg-zinc-600 text-zinc-100' : 'text-zinc-400 hover:text-zinc-200'
              )}
            >
              {s === 'install_count' ? 'Popular' : s === 'rating' ? 'Top Rated' : 'Name'}
            </button>
          ))}
        </div>

        <button
          onClick={() => setSubmitOpen(!submitOpen)}
          className="rounded-lg border border-blue-700/60 bg-blue-900/30 px-3 py-2 text-sm text-blue-300 hover:bg-blue-900/50 transition-colors"
        >
          + Submit Playbook
        </button>
      </div>

      {/* Submit panel */}
      {submitOpen && (
        <div className="rounded-xl border border-zinc-700/60 bg-zinc-800/60 p-4 space-y-3">
          <h3 className="text-sm font-semibold text-zinc-100">Submit a Community Playbook</h3>
          <p className="text-xs text-zinc-400">Paste your playbook definition as JSON. It will be reviewed before appearing in the catalog.</p>
          <textarea
            value={submitJson}
            onChange={(e) => setSubmitJson(e.target.value)}
            rows={8}
            placeholder={'{\n  "name": "My Playbook",\n  "description": "...",\n  "author": "you",\n  "steps": [...]\n}'}
            className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-xs font-mono text-zinc-200 focus:border-zinc-500 focus:outline-none resize-y"
          />
          {submitResult && (
            <p className={clsx('text-xs', submitResult.startsWith('Error') || submitResult.startsWith('Invalid') || submitResult.startsWith('Submission') ? 'text-red-400' : 'text-emerald-400')}>
              {submitResult}
            </p>
          )}
          <div className="flex gap-2">
            <button
              onClick={handleSubmit}
              disabled={submitting || !submitJson.trim()}
              className="rounded px-3 py-1.5 text-xs font-medium bg-blue-700 text-white hover:bg-blue-600 disabled:opacity-50 transition-colors"
            >
              {submitting ? 'Submitting…' : 'Submit for Review'}
            </button>
            <button
              onClick={() => { setSubmitOpen(false); setSubmitResult(null); }}
              className="rounded px-3 py-1.5 text-xs font-medium text-zinc-400 hover:text-zinc-200 transition-colors"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {loading && <div className="py-12 text-center text-sm text-zinc-500">Loading community playbooks…</div>}
      {error && <div className="rounded-lg border border-red-700/40 bg-red-900/20 p-4 text-sm text-red-300">{error}</div>}

      {!loading && !error && items.length === 0 && (
        <div className="flex flex-col items-center justify-center py-16 text-zinc-500 text-sm">
          <p>No community playbooks found.</p>
          <p className="text-xs mt-1">Be the first to submit one!</p>
        </div>
      )}

      {!loading && items.length > 0 && (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {items.map((pb) => (
            <CommunityPlaybookCard key={pb.id} playbook={pb} />
          ))}
        </div>
      )}

      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-2 pt-2">
          <button
            onClick={() => { setPage(page - 1); load(search, sortBy, page - 1); }}
            disabled={page <= 1}
            className="rounded px-3 py-1.5 text-sm text-zinc-400 hover:text-zinc-200 disabled:opacity-30"
          >
            ← Prev
          </button>
          <span className="text-sm text-zinc-500">Page {page} of {totalPages}</span>
          <button
            onClick={() => { setPage(page + 1); load(search, sortBy, page + 1); }}
            disabled={page >= totalPages}
            className="rounded px-3 py-1.5 text-sm text-zinc-400 hover:text-zinc-200 disabled:opacity-30"
          >
            Next →
          </button>
        </div>
      )}
    </div>
  );
}

function CommunityPlaybookCard({ playbook }: { playbook: CommunityPlaybook }) {
  const [installing, setInstalling] = useState(false);
  const [installed, setInstalled] = useState(false);

  const handleInstall = async () => {
    setInstalling(true);
    try {
      await fetch(`/api/v1/community/playbooks/${playbook.id}/install`, { method: 'POST' });
      setInstalled(true);
    } catch { /* ignore */ } finally {
      setInstalling(false);
    }
  };

  return (
    <div className="rounded-xl border border-zinc-700/60 bg-zinc-800/60 p-4 flex flex-col gap-3 hover:border-zinc-600 transition-colors">
      <div>
        <h3 className="text-sm font-semibold text-zinc-100 line-clamp-1">{playbook.name}</h3>
        <p className="text-xs text-zinc-400 mt-1 line-clamp-2">{playbook.description || 'No description.'}</p>
      </div>
      {playbook.tags.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {playbook.tags.slice(0, 4).map((t) => (
            <span key={t} className="rounded bg-zinc-700/50 px-1.5 py-0.5 text-xs text-zinc-400">{t}</span>
          ))}
        </div>
      )}
      <div className="flex items-center justify-between text-xs text-zinc-500 mt-auto pt-2 border-t border-zinc-700/40">
        <span>{playbook.install_count.toLocaleString()} installs</span>
        {playbook.rating > 0 && (
          <span className="text-yellow-400">★ {playbook.rating.toFixed(1)}</span>
        )}
        <button
          onClick={handleInstall}
          disabled={installing || installed}
          className={clsx(
            'rounded px-2.5 py-1 text-xs font-medium transition-colors',
            installed ? 'bg-emerald-900/40 text-emerald-300 cursor-default' : 'bg-zinc-700 text-zinc-200 hover:bg-zinc-600'
          )}
        >
          {installed ? '✓ Installed' : installing ? '…' : 'Install'}
        </button>
      </div>
    </div>
  );
}

/* ─────────────────────────── Main ─────────────────────────── */

export function PlaybooksView() {
  const [tab, setTab] = useState<'playbooks' | 'runs' | 'community'>('playbooks');
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

      {/* Tabs */}
      <div className="flex gap-1 border-b border-gray-800/60">
        <button
          onClick={() => setTab('playbooks')}
          className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 -mb-px ${tab === 'playbooks' ? 'border-blue-500 text-blue-300' : 'border-transparent text-gray-500 hover:text-gray-300'}`}
        >
          Playbooks ({data?.length ?? '…'})
        </button>
        <button
          onClick={() => setTab('runs')}
          className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 -mb-px ${tab === 'runs' ? 'border-blue-500 text-blue-300' : 'border-transparent text-gray-500 hover:text-gray-300'}`}
        >
          Run History
        </button>
        <button
          onClick={() => setTab('community')}
          className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 -mb-px ${tab === 'community' ? 'border-blue-500 text-blue-300' : 'border-transparent text-gray-500 hover:text-gray-300'}`}
        >
          🌐 Community
        </button>
      </div>

      {/* Run History */}
      {tab === 'runs' && <RunHistoryTab />}

      {/* Community */}
      {tab === 'community' && <CommunityPlaybooksTab />}

      {/* Playbooks list */}
      {tab === 'playbooks' && (
        <>
          {isLoading && <div className="text-gray-600 text-sm">Loading playbooks…</div>}

          {error && (
            <div className="bg-red-950/40 border border-red-900 rounded-lg px-4 py-3 text-red-400 text-sm">
              Failed to load playbooks. Is the agents service running?
            </div>
          )}

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

          {data && data.length > 0 && (
            <div className="grid gap-3">
              {data.map((pb) => (
                <div
                  key={pb.id}
                  className={`bg-gray-900/60 border rounded-xl px-5 py-4 flex items-center gap-4 transition-colors ${
                    pb.enabled ? 'border-gray-800 hover:border-gray-700' : 'border-gray-800/40 opacity-60'
                  }`}
                >
                  <EnabledToggle playbook={pb} />
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
                        <span key={tag} className="text-xs px-1.5 py-0.5 rounded bg-gray-800 text-gray-500">
                          {tag}
                        </span>
                      ))}
                    </div>
                    {pb.description && (
                      <p className="text-sm text-gray-500 mt-0.5 truncate">{pb.description}</p>
                    )}
                    <div className="flex items-center gap-3 mt-1 text-xs text-gray-700">
                      <span>{pb.steps.length} steps</span>
                      <span>v{pb.version}</span>
                      {pb.author && <span>by {pb.author}</span>}
                    </div>
                  </div>
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
        </>
      )}
    </div>
  );
}
