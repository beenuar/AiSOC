'use client';

/**
 * PlaybooksView
 * =============
 * /playbooks page — lists all playbooks with quick-run/edit/delete,
 * a Run History tab, and a Community tab for browsing/installing community playbooks.
 *
 * WS-F3: SavedViewsBar wired to the Playbooks tab so analysts can save and
 * recall filter presets (source, category, MITRE tactic, severity, integration,
 * and search query).
 *
 * Author: Beenu <beenu@cyble.com>
 */

import React, { useState, useCallback, useEffect } from 'react';
import Link from 'next/link';
import useSWR from 'swr';
import clsx from 'clsx';
import type { Playbook, PlaybookRun } from './types';
import { PlaybooksGallery, type PlaybookGalleryFilters } from './PlaybooksGallery';
import { EmptyState, EmptyStateIcons } from '@/components/ui/EmptyState';
import { SavedViewsBar } from '@/components/saved-views/SavedViewsBar';

/** Filter snapshot stored by the backend as a saved-view preset. */
type PlaybookFilterSnapshot = PlaybookGalleryFilters;

const DEFAULT_PLAYBOOK_FILTERS: PlaybookFilterSnapshot = {
  source: 'all',
  category: 'all',
  mitreTactic: 'all',
  severity: 'all',
  integration: 'all',
  search: '',
};

const fetcher = (url: string) =>
  fetch(url).then((r) => {
    if (!r.ok) throw new Error('Failed to fetch');
    return r.json();
  });

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
  if (error) return (
    <div className="rounded-md border border-amber-500/30 bg-amber-500/5 px-4 py-2 text-xs text-amber-200">
      Run history unavailable — the agents service may be offline.
    </div>
  );
  if (!data || data.length === 0)
    // WS-F5 — fresh tenants haven't run anything yet; nudge toward the editor.
    return (
      <EmptyState
        icon={EmptyStateIcons.ledger}
        title="No playbook runs yet"
        description="Run history shows up after you trigger a playbook — either manually from the editor's dry-run button, or automatically when an alert matches a playbook trigger."
        className="bg-transparent py-12"
      />
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
              {run.started_at && <span suppressHydrationWarning>{new Date(run.started_at).toLocaleString()}</span>}
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
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setItems(data.items ?? []);
      setTotal(data.total ?? 0);
    } catch {
      setError('Failed to load community playbooks.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(search, sortBy, page); }, []);

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
      if (!res.ok && res.headers.get('content-type')?.includes('json')) {
        const err = await res.json();
        setSubmitResult(`Error: ${err.detail ?? res.statusText}`);
        return;
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
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
      {error && (
          <div className="rounded-md border border-amber-500/30 bg-amber-500/5 px-4 py-2 text-xs text-amber-200">
            {error}
          </div>
        )}

      {!loading && !error && items.length === 0 && (
        // WS-F5 — community playbooks come from the marketplace index. If
        // search is active we treat it as a filter-miss; otherwise it's an
        // index-not-built state.
        <EmptyState
          icon={EmptyStateIcons.search}
          title={search ? 'No community playbooks match your search' : 'No community playbooks indexed yet'}
          description={
            search
              ? 'Try a different search term, or browse the full catalog by clearing the search.'
              : 'Run `pnpm marketplace:build` to regenerate the community index, or check that /marketplace/index.json is being served.'
          }
          action={
            search ? (
              <button
                onClick={() => { setSearch(''); load('', sortBy, 1); }}
                className="text-xs px-3 py-1.5 rounded-md border border-blue-500/40 bg-blue-500/10 text-blue-300 hover:bg-blue-500/20 transition-colors"
              >
                Clear search
              </button>
            ) : undefined
          }
          className="bg-transparent py-12"
        />
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
          <span className="text-yellow-400">{playbook.rating.toFixed(1)} rating</span>
        )}
        <button
          onClick={handleInstall}
          disabled={installing || installed}
          className={clsx(
            'rounded px-2.5 py-1 text-xs font-medium transition-colors',
            installed ? 'bg-emerald-900/40 text-emerald-300 cursor-default' : 'bg-zinc-700 text-zinc-200 hover:bg-zinc-600'
          )}
        >
          {installed ? 'Installed' : installing ? '…' : 'Install'}
        </button>
      </div>
    </div>
  );
}

/* ─────────────────────────── Mock Data ─────────────────────────── */

const MOCK_PLAYBOOKS: Playbook[] = [
  {
    id: 'pb-001', name: 'Phishing Triage', description: 'Automated triage for phishing alerts — extracts IOCs, checks reputation, and escalates confirmed threats.',
    version: '1.3', tags: ['phishing', 'email', 'triage'], author: 'soc-team',
    trigger: { on: 'alert', severity: ['high', 'critical'], tags: ['phishing'] },
    steps: [], enabled: true, created_at: '2026-04-15T10:00:00Z', updated_at: '2026-05-01T08:30:00Z',
  },
  {
    id: 'pb-002', name: 'Endpoint Isolation', description: 'Isolates a compromised endpoint via EDR API, creates a case, and notifies the IR channel.',
    version: '2.0', tags: ['edr', 'isolation', 'response'], author: 'ir-lead',
    trigger: { on: 'manual' },
    steps: [], enabled: true, created_at: '2026-03-20T14:00:00Z', updated_at: '2026-04-28T16:00:00Z',
  },
  {
    id: 'pb-003', name: 'Identity Compromise', description: 'Responds to suspicious identity events — resets credentials, revokes sessions, and enriches with threat intel.',
    version: '1.1', tags: ['identity', 'iam', 'credential-reset'], author: 'soc-team',
    trigger: { on: 'alert', severity: ['critical'], tags: ['identity'] },
    steps: [], enabled: true, created_at: '2026-04-01T09:00:00Z', updated_at: '2026-05-04T12:00:00Z',
  },
  {
    id: 'pb-004', name: 'Cloud IAM Audit', description: 'Periodic audit of IAM roles and policies across AWS, GCP, and Azure — flags over-privileged accounts.',
    version: '1.0', tags: ['cloud', 'iam', 'audit'], author: 'cloud-sec',
    trigger: { on: 'schedule', cron: '0 6 * * 1' },
    steps: [], enabled: false, created_at: '2026-02-10T11:00:00Z', updated_at: '2026-04-20T15:00:00Z',
  },
];

/* ─────────────────────────── Main ─────────────────────────── */

export function PlaybooksView() {
  const [tab, setTab] = useState<'playbooks' | 'runs' | 'community'>('playbooks');
  const { data, isLoading, error } = useSWR<Playbook[]>('/api/v1/playbooks', fetcher, {
    refreshInterval: 30000,
    fallbackData: MOCK_PLAYBOOKS,
  });

  // WS-F3: track the active filter snapshot so SavedViewsBar can capture it,
  // and force-remount PlaybooksGallery when a preset is applied so the gallery
  // picks up the new initial state without requiring full controlled-prop surgery.
  const [galleryFilters, setGalleryFilters] = useState<PlaybookFilterSnapshot>(DEFAULT_PLAYBOOK_FILTERS);
  const [galleryKey, setGalleryKey] = useState(0);

  function handleApplyView(filters: PlaybookFilterSnapshot) {
    setGalleryFilters(filters);
    setGalleryKey((k) => k + 1);
  }

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
          Community
        </button>
      </div>

      {/* Run History */}
      {tab === 'runs' && <RunHistoryTab />}

      {/* Community */}
      {tab === 'community' && <CommunityPlaybooksTab />}

      {/* Playbooks list */}
      {tab === 'playbooks' && (
        <>
          {/* WS-F3: saved-view presets for the playbooks list */}
          <SavedViewsBar<PlaybookFilterSnapshot>
            viewType="playbooks"
            filters={galleryFilters}
            onApply={handleApplyView}
          />

          {isLoading && <div className="text-gray-600 text-sm">Loading playbooks…</div>}

          {error && (
            <div className="rounded-md border border-amber-500/30 bg-amber-500/5 px-4 py-2 text-xs text-amber-200">
              Agents API unreachable — showing demo playbooks so you can explore the workflow.
            </div>
          )}

          {!isLoading && !error && (!data || data.length === 0) && (
            // WS-F5 — first-run experience. Push toward both "create your own"
            // and "browse the community" so analysts don't have to start from
            // a blank YAML file.
            <EmptyState
              icon={EmptyStateIcons.ledger}
              title="No playbooks yet"
              description="Playbooks automate your SOC response — isolate hosts, enrich IOCs, page on-call, post to Slack. Start from a community template or write your own from scratch."
              action={
                <div className="flex items-center gap-2">
                  <Link
                    href="/playbooks/new"
                    className="px-3 py-1.5 rounded-md bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium transition-colors"
                  >
                    Create your first playbook
                  </Link>
                  <button
                    onClick={() => setTab('community')}
                    className="text-xs px-3 py-1.5 rounded-md border border-zinc-700 bg-zinc-800/40 text-zinc-300 hover:bg-zinc-800 transition-colors"
                  >
                    Browse community
                  </button>
                </div>
              }
              className="bg-transparent py-16"
            />
          )}

          {/* key forces remount when a saved preset is applied, seeding gallery
              state from the preset's filter snapshot without full prop-drilling. */}
          {data && data.length > 0 && (
            <PlaybooksGallery
              key={galleryKey}
              playbooks={data}
              initialFilters={galleryFilters}
            />
          )}
        </>
      )}
    </div>
  );
}
