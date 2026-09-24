'use client';

/**
 * Federated SIEM search.
 *
 * `/api/v1/federated/backends` and `/api/v1/federated/search` have existed
 * server-side for some time — the API decrypts each tenant's own connector
 * credentials, fans one `UnifiedQuery` out to Splunk / Sentinel / Elastic /
 * QRadar in parallel, and merges the rows. Until now `apps/web` had no client
 * for either, so the capability was reachable only from the SDK.
 *
 * The design constraint that shapes this whole view is the endpoint's
 * per-source isolation: it never fails the call because one backend is slow,
 * 401s or 5xxs. It returns `sources[]`, a verdict per backend. A UI that
 * renders only the merged rows throws that away, and the analyst cannot tell
 * "Sentinel has nothing" from "Sentinel did not answer" — which are opposite
 * conclusions during an incident. So the verdict strip is not a detail panel
 * here; it renders above the rows, always, including when every backend
 * failed and there are no rows at all.
 */

import { useCallback, useMemo, useState } from 'react';
import useSWR from 'swr';
import Link from 'next/link';
import { clsx } from 'clsx';
import {
  FEDERATED_OPERATORS,
  FederatedSearchDisabledError,
  federatedApi,
  type FederatedBackend,
  type FederatedIndicator,
  type FederatedOperator,
  type FederatedRow,
  type FederatedSearchResponse,
  type FederatedSourceVerdict,
} from '@/lib/api';
import { EmptyState } from '@/components/ui/EmptyState';
import { ErrorState } from '@/components/ui/ErrorState';
import { pivotPathForValue, pivotableFields } from './pivot';

const TIME_WINDOWS: ReadonlyArray<{ label: string; seconds: number }> = [
  { label: '15 minutes', seconds: 15 * 60 },
  { label: '1 hour', seconds: 60 * 60 },
  { label: '4 hours', seconds: 4 * 60 * 60 },
  { label: '24 hours', seconds: 24 * 60 * 60 },
  { label: '7 days', seconds: 7 * 24 * 60 * 60 },
];

const ROW_LIMITS = [50, 100, 250, 500, 1000] as const;

/** Vendor labels. Anything unknown falls through to the raw type. */
const BACKEND_LABELS: Record<string, string> = {
  splunk: 'Splunk',
  microsoft_sentinel: 'Microsoft Sentinel',
  elastic: 'Elastic',
  qradar: 'IBM QRadar',
};

function backendLabel(connectorType: string): string {
  return BACKEND_LABELS[connectorType] ?? connectorType;
}

/**
 * Connector `health_status` is free-form on the wire. Only map the values the
 * backend is known to emit and render anything else verbatim — inventing a
 * green dot for a status we do not recognise is the same class of mistake as
 * inventing a row count.
 */
const HEALTH_STYLES: Record<string, { dot: string; label: string }> = {
  healthy: { dot: 'bg-green-500', label: 'Reachable' },
  degraded: { dot: 'bg-yellow-500', label: 'Degraded' },
  failed: { dot: 'bg-red-500', label: 'Failing' },
  unknown: { dot: 'bg-gray-500', label: 'Not yet polled' },
};

function healthStyle(status: string) {
  return HEALTH_STYLES[status] ?? { dot: 'bg-gray-500', label: status };
}

interface IndicatorDraft extends FederatedIndicator {
  /** Stable key so React does not reorder inputs when a row is removed. */
  id: string;
  value: string;
}

let indicatorSeq = 0;
function newIndicator(): IndicatorDraft {
  indicatorSeq += 1;
  return { id: `ind-${indicatorSeq}`, field: '', operator: 'eq', value: '' };
}

// ─── Backend picker ───────────────────────────────────────────────────────────

function BackendPicker({
  backends,
  selected,
  onToggle,
  onSelectAll,
}: {
  backends: FederatedBackend[];
  selected: Set<string>;
  onToggle: (id: string) => void;
  onSelectAll: (all: boolean) => void;
}) {
  const allSelected = selected.size === 0 || selected.size === backends.length;

  return (
    <fieldset className="rounded-xl border border-gray-800/60 bg-gray-900/40 p-4">
      <legend className="px-1 text-xs font-medium uppercase tracking-wider text-gray-500">
        Backends to query
      </legend>
      <div className="mb-3 flex items-center justify-between">
        <p className="text-xs text-gray-500">
          {backends.length} federated-capable {backends.length === 1 ? 'connector' : 'connectors'}{' '}
          enabled for this tenant.
        </p>
        <button
          type="button"
          onClick={() => onSelectAll(!allSelected)}
          className="text-xs text-blue-400 underline underline-offset-2 hover:text-blue-300"
        >
          {allSelected ? 'Clear selection' : 'Select all'}
        </button>
      </div>
      <ul className="grid gap-2 sm:grid-cols-2">
        {backends.map((b) => {
          const health = healthStyle(b.health_status);
          const checked = selected.size === 0 || selected.has(b.connector_id);
          return (
            <li key={b.connector_id}>
              <label
                className={clsx(
                  'flex cursor-pointer items-center gap-3 rounded-lg border px-3 py-2 transition-colors',
                  checked
                    ? 'border-blue-500/50 bg-blue-500/5'
                    : 'border-gray-800/60 bg-gray-900/40 hover:border-gray-700',
                )}
              >
                <input
                  type="checkbox"
                  className="h-4 w-4 rounded border-gray-600 bg-gray-800 text-blue-500"
                  checked={checked}
                  onChange={() => onToggle(b.connector_id)}
                />
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm text-gray-200">{b.name}</span>
                  <span className="block text-[11px] text-gray-500">
                    {backendLabel(b.connector_type)}
                  </span>
                </span>
                <span className="flex shrink-0 items-center gap-1.5" title={`Connector health: ${b.health_status}`}>
                  <span className={clsx('h-1.5 w-1.5 rounded-full', health.dot)} />
                  <span className="text-[11px] text-gray-400">{health.label}</span>
                </span>
              </label>
            </li>
          );
        })}
      </ul>
      <p className="mt-3 text-[11px] text-gray-600">
        Health is the connector&apos;s last recorded poll status, not a live probe. A
        backend that is reachable for ingest can still fail this query — the
        per-backend result below is the authoritative answer.
      </p>
    </fieldset>
  );
}

// ─── Per-backend verdict strip ────────────────────────────────────────────────

function SourceVerdictCard({ verdict }: { verdict: FederatedSourceVerdict }) {
  const tone =
    verdict.status === 'ok'
      ? 'border-green-500/30 bg-green-500/5'
      : verdict.status === 'unsupported'
        ? 'border-gray-700 bg-gray-900/40'
        : 'border-red-500/30 bg-red-500/5';

  const statusLabel =
    verdict.status === 'ok'
      ? 'Answered'
      : verdict.status === 'unsupported'
        ? 'Not supported'
        : 'Failed';

  return (
    <li
      className={clsx('rounded-lg border px-3 py-2.5', tone)}
      data-testid={`source-verdict-${verdict.connector_id}`}
    >
      <div className="flex items-baseline justify-between gap-2">
        <span className="truncate text-sm font-medium text-gray-200">
          {verdict.connector_name}
        </span>
        <span
          className={clsx(
            'shrink-0 text-[11px] font-medium',
            verdict.status === 'ok' ? 'text-green-300' : verdict.status === 'error' ? 'text-red-300' : 'text-gray-400',
          )}
        >
          {statusLabel}
        </span>
      </div>
      <div className="mt-1 flex items-center gap-3 text-[11px] text-gray-500">
        <span>{backendLabel(verdict.connector_type)}</span>
        {/* Row count is only meaningful for a backend that answered. Printing
            "0 rows" for one that failed reads as "nothing matched". */}
        {verdict.status === 'ok' && (
          <span>
            {verdict.row_count} {verdict.row_count === 1 ? 'row' : 'rows'}
          </span>
        )}
        <span>{verdict.duration_ms} ms</span>
      </div>
      {verdict.error && (
        <p className="mt-1.5 break-words text-[11px] text-red-300/90">{verdict.error}</p>
      )}
    </li>
  );
}

function SourceVerdictStrip({ sources }: { sources: FederatedSourceVerdict[] }) {
  const answered = sources.filter((s) => s.status === 'ok').length;
  const failed = sources.filter((s) => s.status === 'error').length;

  return (
    <section aria-labelledby="fed-sources-heading">
      <div className="mb-2 flex items-baseline justify-between">
        <h2 id="fed-sources-heading" className="text-sm font-medium text-gray-300">
          Per-backend result
        </h2>
        <p className="text-xs text-gray-500">
          {`${answered} of ${sources.length} answered`}
          {failed > 0 ? `, ${failed} failed` : ''}
        </p>
      </div>
      {failed > 0 && (
        <p
          role="status"
          className="mb-2 rounded-lg border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-xs text-amber-200"
        >
          Results below are partial. {failed} of {sources.length} backends did not
          answer, so an absence of rows from those sources is not evidence of an
          absence of activity.
        </p>
      )}
      <ul className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
        {sources.map((s) => (
          <SourceVerdictCard key={s.connector_id} verdict={s} />
        ))}
      </ul>
    </section>
  );
}

// ─── Result rows ──────────────────────────────────────────────────────────────

function renderCell(value: unknown): string {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function ResultRow({ row, index }: { row: FederatedRow; index: number }) {
  const [expanded, setExpanded] = useState(false);
  const source = row._aisoc_source;
  const { _aisoc_source: _omit, ...fields } = row;
  void _omit;

  const pivots = pivotableFields(fields);

  return (
    <li className="rounded-lg border border-gray-800/60 bg-gray-900/40">
      <div className="flex items-start gap-3 px-3 py-2.5">
        <span className="mt-0.5 shrink-0 font-mono text-[11px] text-gray-600">
          {index + 1}
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
            {source && (
              <span className="rounded border border-gray-700/60 bg-gray-800/60 px-1.5 py-0.5 text-[10px] text-gray-300">
                {source.connector_name}
              </span>
            )}
            {Object.entries(fields)
              .slice(0, 4)
              .map(([k, v]) => (
                <span key={k} className="truncate text-xs text-gray-300">
                  <span className="text-gray-500">{k}=</span>
                  <span className="font-mono">{renderCell(v)}</span>
                </span>
              ))}
          </div>
          {pivots.length > 0 && (
            <div className="mt-1.5 flex flex-wrap items-center gap-2">
              {pivots.map((p) => (
                <Link
                  key={`${p.type}:${p.value}`}
                  href={pivotPathForValue(p.type, p.value)}
                  className="rounded border border-gray-700/60 bg-gray-800/40 px-1.5 py-0.5 text-[10px] text-blue-300 hover:border-blue-500/50 hover:text-blue-200"
                >
                  {`Pivot ${p.type}: ${p.value}`}
                </Link>
              ))}
            </div>
          )}
        </div>
        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          aria-expanded={expanded}
          className="shrink-0 rounded border border-gray-700/60 px-2 py-0.5 text-[11px] text-gray-400 hover:border-gray-600 hover:text-gray-200"
        >
          {expanded ? 'Hide' : 'Raw'}
        </button>
      </div>
      {expanded && (
        <pre className="overflow-x-auto border-t border-gray-800/60 px-3 py-2 text-[11px] text-gray-400">
          {JSON.stringify(fields, null, 2)}
        </pre>
      )}
    </li>
  );
}

// ─── Main view ────────────────────────────────────────────────────────────────

export function FederatedSearchView() {
  const {
    data: backendsData,
    error: backendsError,
    isLoading: backendsLoading,
    mutate: refetchBackends,
  } = useSWR('federated-backends', () => federatedApi.listBackends(), {
    revalidateOnFocus: false,
    shouldRetryOnError: false,
  });

  const backends = useMemo(() => backendsData?.backends ?? [], [backendsData]);

  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [freeText, setFreeText] = useState('');
  const [indicators, setIndicators] = useState<IndicatorDraft[]>([]);
  const [sinceSeconds, setSinceSeconds] = useState(3600);
  const [limit, setLimit] = useState<number>(100);

  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<FederatedSearchResponse | null>(null);
  const [runError, setRunError] = useState<unknown>(null);
  /** Echo of the query that produced `result`, so the header cannot drift. */
  const [ranAt, setRanAt] = useState<string | null>(null);

  const cleanedIndicators = useMemo(
    () =>
      indicators
        .filter((i) => i.field.trim() !== '' && String(i.value).trim() !== '')
        .map<FederatedIndicator>((i) => ({
          field: i.field.trim(),
          operator: i.operator,
          // `in` is the one operator the server requires a list for.
          value:
            i.operator === 'in'
              ? String(i.value)
                  .split(',')
                  .map((v) => v.trim())
                  .filter(Boolean)
              : i.value,
        }))
        .filter((i) => (i.operator === 'in' ? (i.value as unknown[]).length > 0 : true)),
    [indicators],
  );

  // Mirrors the server's own 422 precondition, so the analyst is told before
  // the round-trip rather than after it.
  const canRun = freeText.trim() !== '' || cleanedIndicators.length > 0;

  const toggleBackend = useCallback(
    (id: string) => {
      setSelected((prev) => {
        // An empty set means "all", which is also what the API does when
        // `connector_ids` is omitted. Unticking one of an implicit-all
        // selection has to materialise the rest first or it would read as
        // "select only this one".
        const base = prev.size === 0 ? new Set(backends.map((b) => b.connector_id)) : new Set(prev);
        if (base.has(id)) base.delete(id);
        else base.add(id);
        return base;
      });
    },
    [backends],
  );

  const selectAll = useCallback(
    (all: boolean) => setSelected(all ? new Set() : new Set(['__none__'])),
    [],
  );

  const run = useCallback(async () => {
    if (!canRun || running) return;
    setRunning(true);
    setRunError(null);
    try {
      const chosen = [...selected].filter((id) => id !== '__none__');
      const response = await federatedApi.search({
        free_text: freeText.trim(),
        indicators: cleanedIndicators,
        since_seconds: sinceSeconds,
        limit,
        // Omit entirely to mean "every enabled backend" — sending [] would be
        // an explicit empty subset, which is not the same request.
        connector_ids: chosen.length > 0 && chosen.length < backends.length ? chosen : null,
      });
      setResult(response);
      setRanAt(new Date().toISOString());
    } catch (err) {
      setRunError(err);
      setResult(null);
    } finally {
      setRunning(false);
    }
  }, [canRun, running, selected, freeText, cleanedIndicators, sinceSeconds, limit, backends.length]);

  // ── Feature disabled ────────────────────────────────────────────────────────
  if (backendsError instanceof FederatedSearchDisabledError) {
    return (
      <EmptyState
        title="Federated search is turned off on this deployment"
        description="Set AISOC_FEATURE_FED_SEARCH=true on the API service to enable cross-SIEM search. No query is sent while it is disabled."
      />
    );
  }

  if (backendsError) {
    return (
      <ErrorState
        title="Could not list federated backends"
        description="The API did not return the connector list, so there is nothing to query against yet."
        error={backendsError}
        onRetry={() => {
          void refetchBackends();
        }}
      />
    );
  }

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-xl font-semibold text-gray-100">Federated search</h1>
        <p className="mt-1 text-sm text-gray-500">
          One query, fanned out in parallel to every SIEM this tenant has connected,
          using that tenant&apos;s own stored credentials. Each backend answers
          independently.
        </p>
      </header>

      {backendsLoading ? (
        <div className="h-32 animate-pulse rounded-xl bg-gray-800/30" />
      ) : backends.length === 0 ? (
        <EmptyState
          title="No SIEM connectors are connected"
          description="Federated search queries Splunk, Microsoft Sentinel, Elastic and QRadar connectors. Connect and enable at least one to search across them."
          action={
            <Link
              href="/connectors"
              className="text-sm text-blue-400 underline underline-offset-2 hover:text-blue-300"
            >
              Connect a SIEM
            </Link>
          }
        />
      ) : (
        <>
          <BackendPicker
            backends={backends}
            selected={selected}
            onToggle={toggleBackend}
            onSelectAll={selectAll}
          />

          <form
            className="space-y-4 rounded-xl border border-gray-800/60 bg-gray-900/40 p-4"
            onSubmit={(e) => {
              e.preventDefault();
              void run();
            }}
          >
            <div>
              <label htmlFor="fed-free-text" className="mb-1.5 block text-xs font-medium uppercase tracking-wider text-gray-500">
                Search text
              </label>
              <input
                id="fed-free-text"
                type="text"
                value={freeText}
                onChange={(e) => setFreeText(e.target.value)}
                placeholder="e.g. failed logon, or an indicator like 10.0.0.7"
                className="w-full rounded-lg border border-gray-700 bg-gray-950/60 px-3 py-2 text-sm text-gray-100 placeholder:text-gray-600 focus:border-blue-500 focus:outline-none"
              />
              <p className="mt-1 text-[11px] text-gray-600">
                Translated per backend into SPL, KQL, ES|QL or AQL. You never write
                vendor query syntax here.
              </p>
            </div>

            <div>
              <div className="mb-1.5 flex items-center justify-between">
                <span className="text-xs font-medium uppercase tracking-wider text-gray-500">
                  Field filters
                </span>
                <button
                  type="button"
                  onClick={() => setIndicators((prev) => [...prev, newIndicator()])}
                  className="text-xs text-blue-400 underline underline-offset-2 hover:text-blue-300"
                >
                  Add filter
                </button>
              </div>
              {indicators.length === 0 ? (
                <p className="text-[11px] text-gray-600">
                  Optional. Filters are AND-joined with each other and with the
                  search text above.
                </p>
              ) : (
                <ul className="space-y-2">
                  {indicators.map((ind, idx) => (
                    <li key={ind.id} className="flex flex-wrap items-center gap-2">
                      <input
                        aria-label={`Filter ${idx + 1} field`}
                        type="text"
                        value={ind.field}
                        placeholder="field"
                        onChange={(e) =>
                          setIndicators((prev) =>
                            prev.map((p) => (p.id === ind.id ? { ...p, field: e.target.value } : p)),
                          )
                        }
                        className="min-w-0 flex-1 rounded-lg border border-gray-700 bg-gray-950/60 px-2.5 py-1.5 text-sm text-gray-100 placeholder:text-gray-600 focus:border-blue-500 focus:outline-none"
                      />
                      <select
                        aria-label={`Filter ${idx + 1} operator`}
                        value={ind.operator}
                        onChange={(e) =>
                          setIndicators((prev) =>
                            prev.map((p) =>
                              p.id === ind.id
                                ? { ...p, operator: e.target.value as FederatedOperator }
                                : p,
                            ),
                          )
                        }
                        className="rounded-lg border border-gray-700 bg-gray-950/60 px-2 py-1.5 text-sm text-gray-100 focus:border-blue-500 focus:outline-none"
                      >
                        {FEDERATED_OPERATORS.map((op) => (
                          <option key={op} value={op}>
                            {op}
                          </option>
                        ))}
                      </select>
                      <input
                        aria-label={`Filter ${idx + 1} value`}
                        type="text"
                        value={String(ind.value)}
                        placeholder={ind.operator === 'in' ? 'a, b, c' : 'value'}
                        onChange={(e) =>
                          setIndicators((prev) =>
                            prev.map((p) => (p.id === ind.id ? { ...p, value: e.target.value } : p)),
                          )
                        }
                        className="min-w-0 flex-1 rounded-lg border border-gray-700 bg-gray-950/60 px-2.5 py-1.5 text-sm text-gray-100 placeholder:text-gray-600 focus:border-blue-500 focus:outline-none"
                      />
                      <button
                        type="button"
                        aria-label={`Remove filter ${idx + 1}`}
                        onClick={() => setIndicators((prev) => prev.filter((p) => p.id !== ind.id))}
                        className="rounded border border-gray-700/60 px-2 py-1 text-xs text-gray-400 hover:border-red-500/50 hover:text-red-300"
                      >
                        Remove
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <div className="flex flex-wrap items-end gap-4">
              <div>
                <label htmlFor="fed-window" className="mb-1.5 block text-xs font-medium uppercase tracking-wider text-gray-500">
                  Time window
                </label>
                <select
                  id="fed-window"
                  value={sinceSeconds}
                  onChange={(e) => setSinceSeconds(Number(e.target.value))}
                  className="rounded-lg border border-gray-700 bg-gray-950/60 px-2.5 py-1.5 text-sm text-gray-100 focus:border-blue-500 focus:outline-none"
                >
                  {TIME_WINDOWS.map((w) => (
                    <option key={w.seconds} value={w.seconds}>
                      Last {w.label}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label htmlFor="fed-limit" className="mb-1.5 block text-xs font-medium uppercase tracking-wider text-gray-500">
                  Row cap
                </label>
                <select
                  id="fed-limit"
                  value={limit}
                  onChange={(e) => setLimit(Number(e.target.value))}
                  className="rounded-lg border border-gray-700 bg-gray-950/60 px-2.5 py-1.5 text-sm text-gray-100 focus:border-blue-500 focus:outline-none"
                >
                  {ROW_LIMITS.map((l) => (
                    <option key={l} value={l}>
                      {l} rows
                    </option>
                  ))}
                </select>
              </div>
              <button
                type="submit"
                disabled={!canRun || running}
                className={clsx(
                  'rounded-lg px-4 py-2 text-sm font-medium transition-colors',
                  canRun && !running
                    ? 'bg-blue-600 text-white hover:bg-blue-500'
                    : 'cursor-not-allowed bg-gray-800 text-gray-500',
                )}
              >
                {running ? 'Searching…' : 'Run federated search'}
              </button>
              {!canRun && (
                <p className="text-[11px] text-gray-600">
                  Enter search text or at least one field filter.
                </p>
              )}
            </div>
          </form>

          {runError != null && (
            <ErrorState
              title="Federated search failed"
              description="The request did not reach the backends. No partial results are shown."
              error={runError}
              onRetry={() => {
                void run();
              }}
            />
          )}

          {result && (
            <div className="space-y-4">
              <SourceVerdictStrip sources={result.sources} />

              <section aria-labelledby="fed-rows-heading">
                <div className="mb-2 flex items-baseline justify-between">
                  <h2 id="fed-rows-heading" className="text-sm font-medium text-gray-300">
                    Merged rows
                  </h2>
                  <p className="text-xs text-gray-500">
                    {`${result.row_count} ${result.row_count === 1 ? 'row' : 'rows'}`}
                    {ranAt ? ` · ${new Date(ranAt).toLocaleTimeString()}` : ''}
                  </p>
                </div>
                {result.truncated && (
                  <p
                    role="status"
                    className="mb-2 rounded-lg border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-xs text-amber-200"
                  >
                    Capped at {limit} rows after merging. Narrow the window or add a
                    filter to see the rest.
                  </p>
                )}
                {result.rows.length === 0 ? (
                  <EmptyState
                    title={
                      result.sources.some((s) => s.status === 'ok')
                        ? 'No matching events'
                        : 'No backend returned results'
                    }
                    description={
                      result.sources.some((s) => s.status === 'ok')
                        ? 'At least one backend answered and matched nothing in this window.'
                        : 'Every backend failed or was skipped. The per-backend result above carries each failure.'
                    }
                  />
                ) : (
                  <ul className="space-y-2">
                    {result.rows.map((row, i) => (
                      <ResultRow key={i} row={row} index={i} />
                    ))}
                  </ul>
                )}
              </section>
            </div>
          )}
        </>
      )}
    </div>
  );
}
