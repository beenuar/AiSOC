'use client';

/**
 * Advanced Data Explorer (Phase C1).
 *
 * One investigation surface across the populated event lake, identity
 * (effective permissions), config/graph and threat intel — so an analyst
 * answers "who touched this, with what access, and is the IP known-bad?"
 * without context-switching between four tools or a separate SIEM.
 *
 * It builds on the existing primitives shipped earlier in the roadmap:
 *   - the ClickHouse event lake (`/api/v1/lake/sql` + `/lake/schema`, Phase A1),
 *   - the natural-language query translator (`/api/v1/nl-query/translate`),
 *   - identity effective-permissions and threat-intel deep links.
 *
 * The first surface (Events) is fully interactive here: type a question in
 * plain English, we translate it to SQL against the lake, run it, and render a
 * BI-like table. A raw-SQL escape hatch is always available. The other sources
 * are presented as one-click pivots into their dedicated surfaces, keeping this
 * a single entry point without duplicating those workbenches.
 */

import { useCallback, useMemo, useState } from 'react';
import toast from 'react-hot-toast';
import {
  lakeApi,
  nlQueryApi,
  type LakeQueryResponse,
} from '@/lib/api';
import { EmptyState } from '@/components/ui/EmptyState';
import { ErrorState } from '@/components/ui/ErrorState';
import { Skeleton } from '@/components/ui/Skeleton';

// ─── Sources ──────────────────────────────────────────────────────────────────

type SourceId = 'events' | 'identity' | 'graph' | 'intel';

interface SourceDef {
  id: SourceId;
  label: string;
  description: string;
  /** Sources other than `events` deep-link into their dedicated surface. */
  pivotHref?: string;
}

const SOURCES: SourceDef[] = [
  {
    id: 'events',
    label: 'Events (lake)',
    description: 'Query the ClickHouse event lake in plain English or SQL.',
  },
  {
    id: 'identity',
    label: 'Identity',
    description: 'Effective permissions for a principal across your IdPs and clouds.',
    pivotHref: '/identity',
  },
  {
    id: 'graph',
    label: 'Config / Graph',
    description: 'Walk the entity graph and cloud posture.',
    pivotHref: '/graph',
  },
  {
    id: 'intel',
    label: 'Threat intel',
    description: 'Look up an IOC across your enabled feeds.',
    pivotHref: '/detection',
  },
];

const EXAMPLE_QUESTIONS = [
  'Show critical events in the last 24 hours',
  'Count events by connector type today',
  'Which users triggered the most alerts this week',
];

// ─── View ───────────────────────────────────────────────────────────────────

export function ExploreView() {
  const [source, setSource] = useState<SourceId>('events');

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-6 p-6">
      <header className="flex flex-col gap-1">
        <h1 className="text-2xl font-semibold text-slate-100">Data Explorer</h1>
        <p className="text-sm text-slate-400">
          One investigation surface across events, identity, config and intel — no SIEM context-switch.
        </p>
      </header>

      <nav aria-label="Explorer sources" className="flex flex-wrap gap-2">
        {SOURCES.map((s) => (
          <button
            key={s.id}
            type="button"
            aria-pressed={source === s.id}
            onClick={() => setSource(s.id)}
            className={
              source === s.id
                ? 'rounded-lg border border-sky-500 bg-sky-500/10 px-3 py-2 text-sm font-medium text-sky-300'
                : 'rounded-lg border border-slate-700 bg-slate-800/40 px-3 py-2 text-sm text-slate-300 hover:border-slate-500'
            }
          >
            {s.label}
          </button>
        ))}
      </nav>

      {source === 'events' ? (
        <EventsExplorer />
      ) : (
        <PivotCard source={SOURCES.find((s) => s.id === source)!} />
      )}
    </div>
  );
}

function PivotCard({ source }: { source: SourceDef }) {
  return (
    <div className="rounded-xl border border-slate-700 bg-slate-800/40 p-6">
      <h2 className="text-lg font-medium text-slate-100">{source.label}</h2>
      <p className="mt-1 text-sm text-slate-400">{source.description}</p>
      {source.pivotHref ? (
        <a
          href={source.pivotHref}
          className="mt-4 inline-block rounded-lg bg-sky-600 px-4 py-2 text-sm font-medium text-white hover:bg-sky-500"
        >
          Open {source.label}
        </a>
      ) : null}
    </div>
  );
}

// ─── Events explorer (interactive) ────────────────────────────────────────────

function EventsExplorer() {
  const [question, setQuestion] = useState('');
  const [sql, setSql] = useState('SELECT event_time, severity, connector_type, user_name\nFROM raw_events\nORDER BY event_time DESC\nLIMIT 100');
  const [result, setResult] = useState<LakeQueryResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [translating, setTranslating] = useState(false);
  const [running, setRunning] = useState(false);

  const runSql = useCallback(async (query: string) => {
    setRunning(true);
    setError(null);
    try {
      const res = await lakeApi.sql({ sql: query, row_cap: 100 });
      setResult(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Query failed');
      setResult(null);
    } finally {
      setRunning(false);
    }
  }, []);

  const translateAndRun = useCallback(
    async (q: string) => {
      const trimmed = q.trim();
      if (!trimmed) return;
      setTranslating(true);
      setError(null);
      try {
        const res = await nlQueryApi.translate({ question: trimmed });
        // The lake speaks SQL; the translator returns an ES|QL/SPL/KQL triple
        // plus, for lake questions, a SQL rendering we surface in the editor.
        const generated = res.esql?.trim() || sql;
        setSql(generated);
        await runSql(generated);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Translation failed');
        toast.error('Could not translate that question');
      } finally {
        setTranslating(false);
      }
    },
    [runSql, sql],
  );

  return (
    <div className="flex flex-col gap-4">
      <form
        className="flex flex-col gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          void translateAndRun(question);
        }}
      >
        <label htmlFor="explore-nl" className="text-sm font-medium text-slate-300">
          Ask in plain English
        </label>
        <div className="flex gap-2">
          <input
            id="explore-nl"
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            placeholder="e.g. show critical events in the last 24 hours"
            className="flex-1 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500"
          />
          <button
            type="submit"
            disabled={translating || running}
            className="rounded-lg bg-sky-600 px-4 py-2 text-sm font-medium text-white hover:bg-sky-500 disabled:opacity-50"
          >
            {translating ? 'Translating…' : 'Ask'}
          </button>
        </div>
        <div className="flex flex-wrap gap-2">
          {EXAMPLE_QUESTIONS.map((q) => (
            <button
              key={q}
              type="button"
              onClick={() => {
                setQuestion(q);
                void translateAndRun(q);
              }}
              className="rounded-full border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:border-slate-500"
            >
              {q}
            </button>
          ))}
        </div>
      </form>

      <div className="flex flex-col gap-2">
        <label htmlFor="explore-sql" className="text-sm font-medium text-slate-300">
          SQL
        </label>
        <textarea
          id="explore-sql"
          value={sql}
          onChange={(e) => setSql(e.target.value)}
          rows={5}
          spellCheck={false}
          className="w-full rounded-lg border border-slate-700 bg-slate-900 p-3 font-mono text-xs text-slate-100"
        />
        <div>
          <button
            type="button"
            disabled={running}
            onClick={() => void runSql(sql)}
            className="rounded-lg bg-slate-700 px-4 py-2 text-sm font-medium text-slate-100 hover:bg-slate-600 disabled:opacity-50"
          >
            {running ? 'Running…' : 'Run query'}
          </button>
        </div>
      </div>

      <ResultsPanel result={result} error={error} loading={running} onRetry={() => void runSql(sql)} />
    </div>
  );
}

function ResultsPanel({
  result,
  error,
  loading,
  onRetry,
}: {
  result: LakeQueryResponse | null;
  error: string | null;
  loading: boolean;
  onRetry: () => void;
}) {
  const rows = useMemo(() => result?.rows ?? [], [result]);

  if (loading && !result) {
    return <Skeleton className="h-48 w-full rounded-lg" />;
  }
  if (error) {
    return <ErrorState title="Query failed" description={error} onRetry={onRetry} />;
  }
  if (!result) {
    return (
      <EmptyState
        title="Run a query to explore your data"
        description="Ask a question above or write SQL against the event lake."
      />
    );
  }
  if (rows.length === 0) {
    return <EmptyState title="No rows" description="The query ran but returned no rows." />;
  }

  return (
    <div className="flex flex-col gap-2">
      <p className="text-xs text-slate-500" aria-live="polite">
        {result.row_count} row{result.row_count === 1 ? '' : 's'} · {result.elapsed_ms}ms · tables:{' '}
        {result.referenced_tables.join(', ') || '—'}
      </p>
      <div className="overflow-x-auto rounded-lg border border-slate-700">
        <table className="min-w-full divide-y divide-slate-700 text-left text-xs">
          <thead className="bg-slate-800/60">
            <tr>
              {result.columns.map((col) => (
                <th key={col} scope="col" className="px-3 py-2 font-medium text-slate-300">
                  {col}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {rows.map((row, ri) => (
              <tr key={ri} className="hover:bg-slate-800/40">
                {row.map((cell, ci) => (
                  <td key={ci} className="px-3 py-2 font-mono text-slate-200">
                    {formatCell(cell)}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function formatCell(cell: unknown): string {
  if (cell === null || cell === undefined) return '—';
  if (typeof cell === 'object') return JSON.stringify(cell);
  return String(cell);
}
