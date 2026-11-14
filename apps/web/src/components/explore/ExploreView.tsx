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
 *   - the natural-language query runner (`/api/v1/nl-query/execute`),
 *   - identity effective-permissions and threat-intel deep links.
 *
 * The first surface (Events) is fully interactive here: type a question in
 * plain English, the API translates and runs it against your SIEM or the
 * lake, and this renders the rows **beside the exact query that produced
 * them**. A raw-SQL escape hatch is always available. The other sources
 * are presented as one-click pivots into their dedicated surfaces, keeping this
 * a single entry point without duplicating those workbenches.
 */

import { Fragment, useCallback, useMemo, useState } from 'react';
import toast from 'react-hot-toast';
import {
  lakeApi,
  nlQueryApi,
  type LakeQueryResponse,
  type NlQueryExecuteResponse,
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
//
// Wave 2, Phase 5.3 — "the explorer that shows its query".
//
// What this used to do, and why it could not have worked
// -------------------------------------------------------
// It called `/nl-query/translate`, which runs nothing and returns an
// ES|QL/SPL/KQL triple, then posted `res.esql` to `/lake/sql`. The lake
// speaks SQL. Those are different languages, so a plain-English question
// either errored or — worse — matched something other than what was asked.
//
// `/nl-query/execute` has shipped the whole capability all along: it runs
// against the tenant's Elasticsearch connector when one is configured and
// against AiSOC's own lake otherwise, compiling the question to SQL with
// **bound parameters**, and it reports which store answered and which
// filters the lake could not honour. The console was bound to the wrong
// endpoint, which is the "exists but nothing calls it" family.
//
// Showing the query is not decoration
// -----------------------------------
// The ES|QL translation is *not* what ran for a lake execution, so
// displaying it beside lake rows would be a query that did not produce them
// — an analyst checking whether their question was understood would be
// reading the wrong artefact. The response now carries the exact text sent
// to the store, its language, and the bound values kept **separate from the
// text**: interpolating them for display would both misreport what ran and
// re-introduce string-building in a path the compiler exists to avoid.

/** Column names the cross-filters bind to, in preference order. */
const ENTITY_COLUMNS: Record<EntityFacet, readonly string[]> = {
  user: ['user_name', 'user', 'actor', 'principal', 'username'],
  host: ['host_name', 'host', 'device', 'hostname', 'asset'],
  resource: ['resource', 'resource_name', 'target', 'object'],
};

type EntityFacet = 'user' | 'host' | 'resource';

const FACET_LABEL: Record<EntityFacet, string> = {
  user: 'User',
  host: 'Host',
  resource: 'Resource',
};

const TIME_RANGES = [
  { hours: 1, label: 'Last hour' },
  { hours: 24, label: 'Last 24 hours' },
  { hours: 168, label: 'Last 7 days' },
  { hours: 720, label: 'Last 30 days' },
];

/** The first column present in `columns` for a facet, or null. */
function columnFor(facet: EntityFacet, columns: string[]): string | null {
  const lowered = columns.map((c) => c.toLowerCase());
  for (const candidate of ENTITY_COLUMNS[facet]) {
    const index = lowered.indexOf(candidate);
    if (index >= 0) return columns[index];
  }
  return null;
}

function toCsv(columns: string[], rows: unknown[][]): string {
  const escape = (value: unknown): string => {
    if (value === null || value === undefined) return '';
    const text = typeof value === 'object' ? JSON.stringify(value) : String(value);
    // RFC 4180: quote when the value carries a delimiter, a quote or a
    // newline, and double any embedded quote. A value starting with `=`,
    // `+`, `-` or `@` is prefixed with an apostrophe, because a spreadsheet
    // treats it as a formula — and these cells hold attacker-controlled
    // strings lifted from logs.
    const guarded = /^[=+\-@\t\r]/.test(text) ? `'${text}` : text;
    return /[",\n\r]/.test(guarded) ? `"${guarded.replace(/"/g, '""')}"` : guarded;
  };
  return [columns.map(escape).join(','), ...rows.map((row) => row.map(escape).join(','))].join('\n');
}

function EventsExplorer() {
  const [question, setQuestion] = useState('');
  const [hours, setHours] = useState(24);
  const [sql, setSql] = useState(
    'SELECT event_time, severity, connector_type, user_name\nFROM raw_events\nORDER BY event_time DESC\nLIMIT 100',
  );
  const [answer, setAnswer] = useState<NlQueryExecuteResponse | null>(null);
  const [rawResult, setRawResult] = useState<LakeQueryResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [facetFilters, setFacetFilters] = useState<Partial<Record<EntityFacet, string>>>({});

  const runSql = useCallback(async (query: string) => {
    setRunning(true);
    setError(null);
    try {
      const res = await lakeApi.sql({ sql: query, row_cap: 100 });
      setRawResult(res);
      // A hand-written SQL run and a translated one are different answers;
      // keeping a stale translation on screen beside new rows would claim
      // the question produced them.
      setAnswer(null);
      setFacetFilters({});
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Query failed');
      setRawResult(null);
    } finally {
      setRunning(false);
    }
  }, []);

  const ask = useCallback(
    async (q: string) => {
      const trimmed = q.trim();
      if (!trimmed) return;
      setRunning(true);
      setError(null);
      try {
        const res = await nlQueryApi.execute({
          question: trimmed,
          time_range_hours: hours,
          max_rows: 500,
        });
        setAnswer(res);
        setRawResult(null);
        setFacetFilters({});
        if (res.executed_query && res.executed_query_language === 'sql') {
          // Keep the editor in step with what ran, so "Run query" re-runs
          // the same thing rather than whatever was last typed.
          setSql(res.executed_query);
        }
        if (res.execution_error) {
          toast.error('The query ran into an error — see the panel below');
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Could not run that question');
        setAnswer(null);
        toast.error('Could not run that question');
      } finally {
        setRunning(false);
      }
    },
    [hours],
  );

  const columns = answer?.result?.columns ?? rawResult?.columns ?? [];
  const allRows = useMemo<unknown[][]>(
    () => (answer?.result?.rows as unknown[][] | undefined) ?? rawResult?.rows ?? [],
    [answer, rawResult],
  );

  const availableFacets = useMemo(
    () =>
      (Object.keys(FACET_LABEL) as EntityFacet[])
        .map((facet) => ({ facet, column: columnFor(facet, columns) }))
        .filter((entry): entry is { facet: EntityFacet; column: string } => entry.column !== null),
    [columns],
  );

  const rows = useMemo(() => {
    const active = availableFacets.filter(({ facet }) => facetFilters[facet]);
    if (active.length === 0) return allRows;
    return allRows.filter((row) =>
      active.every(({ facet, column }) => {
        const index = columns.indexOf(column);
        return index >= 0 && String(row[index] ?? '') === facetFilters[facet];
      }),
    );
  }, [allRows, availableFacets, facetFilters, columns]);

  const exportCsv = useCallback(() => {
    // Exports what is on screen, filters included — an export that silently
    // differed from the table would be a second answer to the same question.
    const blob = new Blob([toCsv(columns, rows)], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `aisoc-explore-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '')}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  }, [columns, rows]);

  return (
    <div className="flex flex-col gap-4">
      <form
        className="flex flex-col gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          void ask(question);
        }}
      >
        <label htmlFor="explore-nl" className="text-sm font-medium text-slate-300">
          Ask in plain English
        </label>
        <div className="flex flex-wrap gap-2">
          <input
            id="explore-nl"
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            placeholder="e.g. show critical events in the last 24 hours"
            className="min-w-[16rem] flex-1 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500"
          />
          <select
            aria-label="Time range"
            value={hours}
            onChange={(e) => setHours(Number(e.target.value))}
            className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100"
          >
            {TIME_RANGES.map((range) => (
              <option key={range.hours} value={range.hours}>
                {range.label}
              </option>
            ))}
          </select>
          <button
            type="submit"
            disabled={running}
            className="rounded-lg bg-sky-600 px-4 py-2 text-sm font-medium text-white hover:bg-sky-500 disabled:opacity-50"
          >
            {running ? 'Running…' : 'Ask'}
          </button>
        </div>
        <div className="flex flex-wrap gap-2">
          {EXAMPLE_QUESTIONS.map((q) => (
            <button
              key={q}
              type="button"
              onClick={() => {
                setQuestion(q);
                void ask(q);
              }}
              className="rounded-full border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:border-slate-500"
            >
              {q}
            </button>
          ))}
        </div>
      </form>

      {answer ? <QueryDisclosure answer={answer} /> : null}

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

      {availableFacets.length > 0 && allRows.length > 0 ? (
        <CrossFilters
          facets={availableFacets}
          columns={columns}
          rows={allRows}
          active={facetFilters}
          onChange={setFacetFilters}
        />
      ) : null}

      <ResultsPanel
        columns={columns}
        rows={rows}
        totalBeforeFilter={allRows.length}
        meta={
          answer
            ? {
                rowCount: answer.result?.total_rows ?? answer.result?.rows.length ?? 0,
                tookMs: answer.result?.took_ms ?? null,
                tables: [],
              }
            : rawResult
              ? {
                  rowCount: rawResult.row_count,
                  tookMs: rawResult.elapsed_ms,
                  tables: rawResult.referenced_tables,
                }
              : null
        }
        error={error ?? answer?.execution_error ?? null}
        loading={running}
        onRetry={() => void runSql(sql)}
        onExport={exportCsv}
        facets={availableFacets}
        activeFilters={facetFilters}
        onFacetClick={(facet, value) => setFacetFilters((f) => ({ ...f, [facet]: value }))}
      />
    </div>
  );
}

// ─── The query, shown ─────────────────────────────────────────────────────────

function QueryDisclosure({ answer }: { answer: NlQueryExecuteResponse }) {
  const store =
    answer.executed_against === 'elasticsearch'
      ? 'your connected Elasticsearch'
      : answer.executed_against === 'lake'
        ? "AiSOC's event lake"
        : null;

  return (
    <div data-testid="query-disclosure" className="rounded-lg border border-slate-700 bg-slate-900/60 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-sm font-medium text-slate-200">The query that ran</h3>
        <div className="flex flex-wrap items-center gap-2 text-xs">
          {store ? (
            <span className="rounded bg-slate-800 px-2 py-0.5 text-slate-300">against {store}</span>
          ) : (
            // Not a guess: an execution that never reached a store has no
            // "nothing matched" to report, and saying so is the difference
            // between an empty result and an unanswered question.
            <span className="rounded bg-amber-500/10 px-2 py-0.5 text-amber-300 ring-1 ring-amber-500/30">
              no store was reached
            </span>
          )}
          <span className="rounded bg-slate-800 px-2 py-0.5 uppercase text-slate-400">
            {answer.executed_query_language ?? 'unknown'}
          </span>
          <span
            className={
              answer.engine === 'llm'
                ? 'rounded bg-violet-500/10 px-2 py-0.5 text-violet-300 ring-1 ring-violet-500/30'
                : 'rounded bg-slate-800 px-2 py-0.5 text-slate-400'
            }
          >
            {answer.engine === 'llm' ? 'model-assisted translation' : 'deterministic translation'}
          </span>
        </div>
      </div>

      {answer.executed_query ? (
        <pre className="mt-3 overflow-x-auto rounded bg-slate-950 p-3 font-mono text-xs text-slate-200">
          {answer.executed_query}
        </pre>
      ) : (
        <p className="mt-3 text-xs text-amber-300">
          No query was sent to a store, so there is nothing to show here.
        </p>
      )}

      {Object.keys(answer.executed_query_params).length > 0 ? (
        <div className="mt-3">
          <p className="text-xs text-slate-400">
            Bound values. These are sent separately from the text above, so no
            value is ever part of the query.
          </p>
          <dl className="mt-1 grid grid-cols-[auto,1fr] gap-x-3 gap-y-1 font-mono text-xs">
            {Object.entries(answer.executed_query_params).map(([key, value]) => (
              <Fragment key={key}>
                <dt className="text-slate-500">{key}</dt>
                <dd className="truncate text-slate-200">{formatCell(value)}</dd>
              </Fragment>
            ))}
          </dl>
        </div>
      ) : null}

      {answer.unsupported_filters.length > 0 ? (
        <p
          data-testid="unsupported-filters"
          className="mt-3 rounded border border-amber-500/40 bg-amber-500/5 p-2 text-xs text-amber-200"
        >
          These parts of your question were not applied:{' '}
          <span className="font-mono">{answer.unsupported_filters.join(', ')}</span>. The rows
          below are therefore broader than what you asked for, not narrower.
        </p>
      ) : null}

      {answer.explanation ? (
        <p className="mt-3 text-xs text-slate-400">{answer.explanation}</p>
      ) : null}
    </div>
  );
}

// ─── Cross-filters ────────────────────────────────────────────────────────────

function CrossFilters({
  facets,
  columns,
  rows,
  active,
  onChange,
}: {
  facets: { facet: EntityFacet; column: string }[];
  columns: string[];
  rows: unknown[][];
  active: Partial<Record<EntityFacet, string>>;
  onChange: (next: Partial<Record<EntityFacet, string>>) => void;
}) {
  return (
    <div data-testid="cross-filters" className="flex flex-wrap items-end gap-3">
      {facets.map(({ facet, column }) => {
        const index = columns.indexOf(column);
        const values = Array.from(
          new Set(rows.map((row) => String(row[index] ?? '')).filter((v) => v !== '' && v !== 'null')),
        ).sort();
        return (
          <label key={facet} className="text-xs text-slate-400">
            <span className="mb-1 block">
              {FACET_LABEL[facet]} <span className="font-mono text-slate-600">({column})</span>
            </span>
            <select
              aria-label={`Filter by ${FACET_LABEL[facet].toLowerCase()}`}
              value={active[facet] ?? ''}
              onChange={(e) => onChange({ ...active, [facet]: e.target.value || undefined })}
              className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-xs text-slate-200"
            >
              <option value="">All ({values.length})</option>
              {values.slice(0, 200).map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </label>
        );
      })}
      {Object.values(active).some(Boolean) ? (
        <button
          type="button"
          onClick={() => onChange({})}
          className="rounded border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:border-slate-500"
        >
          Clear filters
        </button>
      ) : null}
    </div>
  );
}

// ─── Results ──────────────────────────────────────────────────────────────────

function ResultsPanel({
  columns,
  rows,
  totalBeforeFilter,
  meta,
  error,
  loading,
  onRetry,
  onExport,
  facets,
  activeFilters,
  onFacetClick,
}: {
  columns: string[];
  rows: unknown[][];
  totalBeforeFilter: number;
  meta: { rowCount: number; tookMs: number | null; tables: string[] } | null;
  error: string | null;
  loading: boolean;
  onRetry: () => void;
  onExport: () => void;
  facets: { facet: EntityFacet; column: string }[];
  activeFilters: Partial<Record<EntityFacet, string>>;
  onFacetClick: (facet: EntityFacet, value: string) => void;
}) {
  if (loading && columns.length === 0) {
    return <Skeleton className="h-48 w-full rounded-lg" />;
  }
  if (error) {
    return <ErrorState title="Query failed" description={error} onRetry={onRetry} />;
  }
  if (meta === null) {
    return (
      <EmptyState
        title="Run a query to explore your data"
        description="Ask a question above or write SQL against the event lake."
      />
    );
  }
  if (totalBeforeFilter === 0) {
    return <EmptyState title="No rows" description="The query ran but returned no rows." />;
  }
  if (rows.length === 0) {
    // Distinct from "no rows": the query matched, the filters did not. An
    // operator who cannot tell these apart re-runs a query that worked.
    return (
      <EmptyState
        title="No rows match these filters"
        description={`The query returned ${totalBeforeFilter} row${totalBeforeFilter === 1 ? '' : 's'}; your cross-filters exclude all of them.`}
      />
    );
  }

  const facetIndex = new Map(facets.map(({ facet, column }) => [columns.indexOf(column), facet]));
  const entityValue = Object.entries(activeFilters).find(([, value]) => Boolean(value));

  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs text-slate-500" aria-live="polite">
          {rows.length === totalBeforeFilter
            ? `${meta.rowCount} row${meta.rowCount === 1 ? '' : 's'}`
            : `${rows.length} of ${totalBeforeFilter} rows after filtering`}
          {meta.tookMs !== null ? ` · ${meta.tookMs}ms` : ''}
          {meta.tables.length > 0 ? ` · tables: ${meta.tables.join(', ')}` : ''}
        </p>
        <div className="flex gap-2">
          {entityValue ? (
            <a
              href={`/graph?entity=${encodeURIComponent(entityValue[1] as string)}`}
              className="rounded border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:border-slate-500"
            >
              Open in graph
            </a>
          ) : null}
          <button
            type="button"
            onClick={onExport}
            className="rounded border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:border-slate-500"
          >
            Export CSV
          </button>
        </div>
      </div>
      <div className="overflow-x-auto rounded-lg border border-slate-700">
        <table className="min-w-full divide-y divide-slate-700 text-left text-xs">
          <thead className="bg-slate-800/60">
            <tr>
              {columns.map((col) => (
                <th key={col} scope="col" className="px-3 py-2 font-medium text-slate-300">
                  {col}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {rows.map((row, ri) => (
              <tr key={ri} className="hover:bg-slate-800/40">
                {row.map((cell, ci) => {
                  const facet = facetIndex.get(ci);
                  const text = formatCell(cell);
                  return (
                    <td key={ci} className="px-3 py-2 font-mono text-slate-200">
                      {facet && text !== '—' ? (
                        <button
                          type="button"
                          onClick={() => onFacetClick(facet, text)}
                          className="underline decoration-dotted underline-offset-2 hover:text-sky-300"
                          title={`Filter to this ${FACET_LABEL[facet].toLowerCase()}`}
                        >
                          {text}
                        </button>
                      ) : (
                        text
                      )}
                    </td>
                  );
                })}
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
