'use client';

/**
 * Cost dashboard — WS-H1.
 *
 * Renders the deterministic snapshot returned by
 * ``GET /api/v1/costs/dashboard?window_days=N`` as an admin-facing page that
 * answers four questions at a glance:
 *
 *   1. Where is the LLM money going? (headline KPIs + daily sparkline)
 *   2. Which models are eating the budget? (per-model breakdown table)
 *   3. Which investigations are the most expensive? (top-cost cases)
 *   4. How much SOC activity am I getting for that money? (action counts)
 *
 * A dedicated BYOK savings panel labels itself as "active" or "neutral"
 * based on the runtime LLM provider, so operators running a local model see
 * imputed savings vs a hosted alternative without us claiming billing-grade
 * accuracy.
 *
 * Every dollar on this page is one of three things and says which:
 *
 *   measured    the gateway reported it. Real money. A measured $0.00 — what
 *               a local model costs — is a value, not a gap.
 *   estimate    re-priced from a public list price. Always prefixed "~" and
 *               labelled, never merged into a measured figure.
 *   —           not measured. Rendered as an em dash with the reason, never
 *               as $0.00.
 *
 * The last case is why the counts exist. Before them the page could not tell
 * "the agents spent nothing" from "nobody recorded what the agents spent",
 * and rendered the first: a free AI-SOC, on a tracker that was pricing a
 * gateway alias against a hosted table it does not appear in.
 *
 * Styling intentionally mirrors `components/reports/ExecutiveDigest.tsx` so
 * the two admin reports feel like siblings (same Card, KpiCard, Stat
 * primitives, same dark-on-violet hero band).
 */

import { useMemo, useState } from 'react';
import useSWR from 'swr';

import { costsApi, type CostDashboard } from '@/lib/api';

const WINDOW_PRESETS: { label: string; days: number }[] = [
  { label: 'Last 7 days', days: 7 },
  { label: 'Last 14 days', days: 14 },
  { label: 'Last 30 days', days: 30 },
  { label: 'Last 90 days', days: 90 },
];

function fmtUsd(value: number | null | undefined): string {
  if (value === null || value === undefined) return '—';
  // Sub-cent precision for BYOK / per-call values, but cap at $0.01 floor so
  // we don't render literal "$0.0001" all over the dashboard.
  if (value === 0) return '$0.00';
  if (value < 0.01) return '<$0.01';
  if (value < 1000) return `$${value.toFixed(2)}`;
  if (value < 1_000_000) return `$${(value / 1000).toFixed(2)}k`;
  return `$${(value / 1_000_000).toFixed(2)}M`;
}

/**
 * A measured amount, an estimate, or an em dash — decided by the count.
 *
 * Every spend cell on this page goes through here so none can quietly print
 * `$0.00` for a figure nobody measured. `measuredCount` is the same contract
 * the MTTR tiles use: a sum over zero rows is not a sum.
 */
function fmtSpend(
  measured: number | null | undefined,
  measuredCount: number,
  estimated?: number | null,
  estimatedCount?: number,
): string {
  if (measuredCount > 0) return fmtUsd(measured);
  if ((estimatedCount ?? 0) > 0) return `~${fmtUsd(estimated)}`;
  return '—';
}

/** The words under a spend cell explaining which of the three it is. */
function spendProvenance(
  measuredCount: number,
  estimatedCount: number,
  unpricedCount: number,
): string {
  if (measuredCount > 0) {
    const suffix = estimatedCount > 0 ? `, ${estimatedCount} estimated` : '';
    return `measured over ${measuredCount} call${measuredCount === 1 ? '' : 's'}${suffix}`;
  }
  if (estimatedCount > 0) {
    return `list-price estimate over ${estimatedCount} call${estimatedCount === 1 ? '' : 's'} — not billed`;
  }
  if (unpricedCount > 0) {
    return `not measured · ${unpricedCount} call${unpricedCount === 1 ? '' : 's'} the gateway did not price`;
  }
  return 'not measured';
}

function fmtNumber(value: number | null | undefined): string {
  if (value === null || value === undefined) return '—';
  if (value < 1000) return value.toLocaleString();
  if (value < 1_000_000) return `${(value / 1000).toFixed(1)}k`;
  return `${(value / 1_000_000).toFixed(2)}M`;
}

function fmtMs(value: number | null | undefined): string {
  if (value === null || value === undefined) return '—';
  if (value < 1000) return `${Math.round(value)}ms`;
  return `${(value / 1000).toFixed(1)}s`;
}

function fmtDate(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  } catch {
    return iso;
  }
}

export function CostDashboardView() {
  const [days, setDays] = useState<number>(30);

  const { data, error, isLoading, mutate } = useSWR<CostDashboard>(
    ['cost-dashboard', days],
    () => costsApi.dashboard({ window_days: days }),
    {
      revalidateOnFocus: false,
      shouldRetryOnError: false,
      errorRetryCount: 0,
    },
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Cost Dashboard</h1>
          <p className="mt-1 text-sm text-gray-400">
            LLM spend, automation activity, and BYOK savings for the current tenant. Spend figures
            are what the LLM gateway reported it charged. Anything it could not price is shown as
            an estimate or as not measured — never as zero.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <label htmlFor="cost-window" className="sr-only">
            Reporting window
          </label>
          <select
            id="cost-window"
            value={days}
            onChange={(e) => setDays(Number(e.target.value))}
            className="rounded border border-gray-600 bg-gray-800 px-3 py-1.5 text-sm text-white"
          >
            {WINDOW_PRESETS.map((p) => (
              <option key={p.days} value={p.days}>
                {p.label}
              </option>
            ))}
          </select>
          <button
            type="button"
            onClick={() => mutate()}
            className="rounded border border-gray-600 bg-gray-800 px-3 py-1.5 text-sm text-gray-200 hover:bg-gray-700"
          >
            Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-md border border-red-500/30 bg-red-500/10 px-4 py-2 text-sm text-red-200">
          Failed to load cost dashboard: {error instanceof Error ? error.message : String(error)}
        </div>
      )}

      {isLoading && !data && (
        <div className="rounded-xl border border-gray-700 bg-gray-900 p-6 text-sm text-gray-400">
          Computing cost snapshot…
        </div>
      )}

      {data && <DashboardBody data={data} />}
    </div>
  );
}

function DashboardBody({ data }: { data: CostDashboard }) {
  return (
    <>
      <PeriodHero data={data} />
      <Headline data={data} />
      <DailySpend data={data} />
      <ModelTable data={data} />
      <CasesAndActions data={data} />
      <ByokPanel data={data} />
    </>
  );
}

function PeriodHero({ data }: { data: CostDashboard }) {
  const { period, headline } = data;
  // Build a short qualitative summary so operators don't have to read the
  // KPI strip to understand the period at a glance.
  const summary = useMemo(() => {
    if (headline.total_calls === 0) {
      return 'No LLM calls recorded in this window.';
    }
    const runsLabel = headline.total_runs === 1 ? 'investigation' : 'investigations';
    const callsLabel = headline.total_calls === 1 ? 'call' : 'calls';
    const tokens = fmtNumber(headline.total_tokens);
    const volume = `${headline.total_calls.toLocaleString()} ${callsLabel} (${tokens} tokens) across ${headline.total_runs.toLocaleString()} ${runsLabel}`;

    // The sentence used to open with a dollar figure unconditionally. When
    // nothing has been measured there is no figure to open with, and saying
    // "$0.00 of LLM spend" about an unmeasured window is the whole defect in
    // one sentence.
    if (headline.measured_call_count === 0) {
      if (headline.estimated_call_count > 0) {
        return `${volume}. Spend was not measured — the gateway reported no cost — but ${fmtUsd(headline.estimated_cost_usd)} is the list price for the models involved.`;
      }
      return `${volume}. Spend is not measured: no call in this window reported a cost, and nothing here has a published price to estimate from.`;
    }

    const perRun = headline.avg_cost_per_run_usd;
    const cost = fmtUsd(headline.total_cost_usd);
    const unmeasured =
      headline.estimated_call_count + headline.unpriced_call_count > 0
        ? ` ${(headline.estimated_call_count + headline.unpriced_call_count).toLocaleString()} further calls were not billed by the gateway.`
        : '';
    if (perRun === null) {
      return `${cost} of measured LLM spend across ${volume}.${unmeasured}`;
    }
    return `${cost} of measured LLM spend across ${volume}, averaging ${fmtUsd(perRun)} per run.${unmeasured}`;
  }, [headline]);

  return (
    <section className="rounded-xl border border-violet-500/30 bg-violet-950/20 p-5">
      <p className="text-xs uppercase tracking-wide text-violet-300">Reporting period</p>
      <p className="mt-1 text-lg font-semibold text-white">{period.label}</p>
      <p className="mt-3 text-sm leading-relaxed text-gray-200">{summary}</p>
      <p className="mt-2 text-xs text-gray-500">
        {fmtDate(period.start)} → {fmtDate(period.end)} · {period.window_days}-day window
      </p>
    </section>
  );
}

function Headline({ data }: { data: CostDashboard }) {
  const { headline } = data;
  return (
    <section className="grid grid-cols-2 gap-4 sm:grid-cols-4" data-testid="cost-headline">
      <KpiCard
        label="Measured LLM spend"
        value={fmtSpend(
          headline.total_cost_usd,
          headline.measured_call_count,
          headline.estimated_cost_usd,
          headline.estimated_call_count,
        )}
        sub={spendProvenance(
          headline.measured_call_count,
          headline.estimated_call_count,
          headline.unpriced_call_count,
        )}
      />
      <KpiCard label="Tokens consumed" value={fmtNumber(headline.total_tokens)} sub="prompt + completion" />
      <KpiCard label="Investigation runs" value={fmtNumber(headline.total_runs)} sub={`${data.action_counts.length} distinct actions`} />
      <KpiCard
        label="Avg cost / run"
        value={headline.measured_call_count > 0 ? fmtUsd(headline.avg_cost_per_run_usd) : '—'}
        sub={
          headline.measured_call_count === 0
            ? 'not measured'
            : headline.total_runs === 0
              ? 'no completed runs yet'
              : 'rolling window mean of measured spend'
        }
      />
    </section>
  );
}

function DailySpend({ data }: { data: CostDashboard }) {
  const { daily_costs } = data;
  const max = useMemo(
    () => daily_costs.reduce((acc, b) => (b.total_cost_usd > acc ? b.total_cost_usd : acc), 0),
    [daily_costs],
  );

  // A day with calls but nothing measured draws no bar, which is honest only
  // if the reader is told why — otherwise a flat chart reads as a free week.
  const unmeasuredDays = daily_costs.filter((b) => b.measured_call_count === 0 && b.call_count > 0).length;

  return (
    <Card title="Daily measured LLM spend" subtitle="One bar per UTC day in the window — bars are scaled to the peak day">
      {daily_costs.length === 0 ? (
        <p className="text-sm text-gray-500">No LLM activity recorded for this window.</p>
      ) : (
        <div data-testid="daily-spend">
          <div className="flex h-32 items-end gap-1">
            {daily_costs.map((bucket) => {
              const pct = max > 0 ? (bucket.total_cost_usd / max) * 100 : 0;
              const spend = fmtSpend(
                bucket.total_cost_usd,
                bucket.measured_call_count,
                bucket.estimated_cost_usd,
                bucket.estimated_call_count,
              );
              return (
                <div
                  key={bucket.day}
                  className="group relative flex h-full flex-1 flex-col justify-end"
                  title={`${fmtDate(bucket.day)}: ${spend} · ${fmtNumber(bucket.call_count)} calls · ${fmtNumber(bucket.total_tokens)} tokens · ${spendProvenance(bucket.measured_call_count, bucket.estimated_call_count, bucket.unpriced_call_count)}`}
                >
                  <div
                    className="rounded-t bg-violet-500/70 transition-colors group-hover:bg-violet-400"
                    style={{ height: `${Math.max(pct, bucket.total_cost_usd > 0 ? 2 : 0)}%` }}
                  />
                </div>
              );
            })}
          </div>
          <div className="mt-2 flex justify-between text-xs text-gray-500">
            <span>{fmtDate(daily_costs[0]!.day)}</span>
            <span>peak {max > 0 ? fmtUsd(max) : '—'}</span>
            <span>{fmtDate(daily_costs[daily_costs.length - 1]!.day)}</span>
          </div>
          {unmeasuredDays > 0 && (
            <p className="mt-2 text-xs text-amber-300/80" data-testid="daily-spend-unmeasured">
              {unmeasuredDays} day{unmeasuredDays === 1 ? '' : 's'} in this window had LLM calls whose
              cost was not measured — those days draw no bar, which is not the same as costing nothing.
            </p>
          )}
        </div>
      )}
    </Card>
  );
}

function ModelTable({ data }: { data: CostDashboard }) {
  const { by_model } = data;
  return (
    <Card
      title="Spend by model"
      subtitle="Measured cost vs imputed list price, per model. An alias row shows what the gateway resolved it to."
    >
      {by_model.length === 0 ? (
        <p className="text-sm text-gray-500">No per-model rows recorded for this window.</p>
      ) : (
        <div className="overflow-x-auto" data-testid="model-table">
          <table className="w-full min-w-[800px] text-left text-sm">
            <thead>
              <tr className="border-b border-gray-700 text-xs uppercase tracking-wide text-gray-500">
                <th className="py-2 pr-4 font-medium">Model</th>
                <th className="py-2 pr-4 font-medium text-right">Calls</th>
                <th className="py-2 pr-4 font-medium text-right">Prompt tokens</th>
                <th className="py-2 pr-4 font-medium text-right">Completion tokens</th>
                <th className="py-2 pr-4 font-medium text-right">Measured</th>
                <th className="py-2 pr-4 font-medium text-right">Imputed (list)</th>
                <th className="py-2 font-medium text-right">Avg latency</th>
              </tr>
            </thead>
            <tbody>
              {by_model.map((m) => (
                <tr key={m.model} className="border-b border-gray-800/80">
                  <td className="py-2.5 pr-4 font-mono text-xs text-gray-100">
                    {m.model}
                    {m.resolved_model && (
                      <span className="block text-[10px] text-gray-500">→ {m.resolved_model}</span>
                    )}
                  </td>
                  <td className="py-2.5 pr-4 text-right text-gray-200 tabular-nums">
                    {fmtNumber(m.calls)}
                  </td>
                  <td className="py-2.5 pr-4 text-right text-gray-300 tabular-nums">
                    {fmtNumber(m.total_prompt_tokens)}
                  </td>
                  <td className="py-2.5 pr-4 text-right text-gray-300 tabular-nums">
                    {fmtNumber(m.total_completion_tokens)}
                  </td>
                  <td className="py-2.5 pr-4 text-right text-white tabular-nums">
                    {fmtSpend(
                      m.total_cost_usd,
                      m.measured_call_count,
                      m.estimated_cost_usd,
                      m.estimated_call_count,
                    )}
                    <span className="block text-[10px] font-normal text-gray-500">
                      {spendProvenance(
                        m.measured_call_count,
                        m.estimated_call_count,
                        m.unpriced_call_count,
                      )}
                    </span>
                  </td>
                  <td className="py-2.5 pr-4 text-right text-gray-400 tabular-nums">
                    {!m.imputed_is_estimable ? '—' : fmtUsd(m.imputed_public_cost_usd)}
                    {m.unpriced_tokens > 0 && (
                      <span className="block text-[10px] text-gray-500">
                        {!m.imputed_is_estimable ? 'no published price' : `excludes ${fmtNumber(m.unpriced_tokens)} unpriced tokens`}
                      </span>
                    )}
                  </td>
                  <td className="py-2.5 text-right text-gray-400 tabular-nums">
                    {fmtMs(m.avg_latency_ms)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

function CasesAndActions({ data }: { data: CostDashboard }) {
  return (
    <section className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <Card title="Top-cost investigations" subtitle="Cases ranked by measured LLM spend in the window">
        {data.top_cases.length === 0 ? (
          <p className="text-sm text-gray-500">No case-attributed runs recorded for this window.</p>
        ) : (
          <ul className="divide-y divide-gray-800" data-testid="top-cases">
            {data.top_cases.map((c) => (
              <li key={c.case_id} className="flex items-center justify-between gap-3 py-2 text-sm">
                <span className="truncate font-mono text-xs text-gray-200">{c.case_id}</span>
                <span className="flex items-center gap-3">
                  <span className="text-xs text-gray-500 tabular-nums">
                    {fmtNumber(c.runs)} runs · {fmtNumber(c.total_tokens)} tokens
                  </span>
                  <span className="w-20 text-right text-white tabular-nums">
                    {fmtSpend(
                      c.total_cost_usd,
                      c.measured_call_count,
                      c.estimated_cost_usd,
                      c.estimated_call_count,
                    )}
                  </span>
                </span>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card title="Top SOC actions" subtitle="Most-frequent audit-log actions (proxy for automation throughput)">
        {data.action_counts.length === 0 ? (
          <p className="text-sm text-gray-500">No audit events recorded for this window.</p>
        ) : (
          <ul className="divide-y divide-gray-800" data-testid="action-counts">
            {data.action_counts.map((a) => (
              <li key={a.action} className="flex items-center justify-between py-2 text-sm">
                <span className="font-mono text-xs text-gray-200">{a.action}</span>
                <span className="text-white tabular-nums">{fmtNumber(a.count)}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </section>
  );
}

function ByokPanel({ data }: { data: CostDashboard }) {
  const { byok_savings: b } = data;
  const accent = b.is_byok_active
    ? 'border-emerald-500/30 bg-emerald-950/20'
    : 'border-gray-700 bg-gray-900';
  const badge = b.is_byok_active
    ? { text: 'BYOK active', cls: 'bg-emerald-500/20 text-emerald-200' }
    : { text: 'Hosted provider', cls: 'bg-gray-700/60 text-gray-300' };

  return (
    <section
      className={`rounded-xl border p-5 ${accent}`}
      data-testid="byok-panel"
      data-byok={b.is_byok_active ? 'active' : 'inactive'}
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-xs uppercase tracking-wide text-gray-400">BYOK savings</p>
          <p className="mt-1 text-lg font-semibold text-white">
            {!b.imputed_is_estimable
              ? 'Not estimable — no model in this window has a published list price'
              : b.is_byok_active
                ? `~${fmtUsd(b.savings_usd)} saved by running your own model`
                : `Hosted via ${b.provider} — no local-model savings to attribute`}
          </p>
        </div>
        <span className={`rounded-full px-3 py-1 text-xs font-medium ${badge.cls}`}>{badge.text}</span>
      </div>
      <dl className="mt-4 grid grid-cols-1 gap-4 text-sm sm:grid-cols-3">
        <Stat
          label="Measured cost"
          value={b.recorded_is_measured ? fmtUsd(b.recorded_cost_usd) : '—'}
          hint={b.recorded_is_measured ? 'reported by the gateway' : 'not measured'}
        />
        <Stat
          label="Imputed list-price cost"
          value={!b.imputed_is_estimable ? '—' : `~${fmtUsd(b.imputed_public_cost_usd)}`}
          hint={
            !b.imputed_is_estimable
              ? 'no published price for these models'
              : b.unpriced_tokens > 0
                ? `estimate · excludes ${fmtNumber(b.unpriced_tokens)} unpriced tokens`
                : 'estimate'
          }
        />
        <Stat
          label="Estimated savings"
          value={!b.imputed_is_estimable ? '—' : `~${fmtUsd(b.savings_usd)}`}
          hint={!b.imputed_is_estimable ? 'not estimable' : 'estimate'}
          accent={b.is_byok_active && b.imputed_is_estimable ? 'text-emerald-300' : 'text-gray-300'}
        />
      </dl>
      <p className="mt-4 text-xs text-gray-500">
        Imputed cost re-prices prompt + completion tokens against each model&apos;s public list price,
        and only for models that have one — there is no default rate, so a model nobody publishes a
        price for contributes nothing here rather than a guess. Savings approximate what an equivalent
        hosted call would have cost; they are an estimate, not a billing-grade figure.
      </p>
    </section>
  );
}

// ── Local primitives (mirror ExecutiveDigest for visual consistency) ───────

function Card({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-xl border border-gray-700 bg-gray-900 p-5">
      <div className="mb-4">
        <h2 className="text-base font-semibold text-white">{title}</h2>
        {subtitle && <p className="mt-0.5 text-xs text-gray-500">{subtitle}</p>}
      </div>
      {children}
    </div>
  );
}

function KpiCard({
  label,
  value,
  sub,
}: {
  label: string;
  value: number | string;
  sub?: string;
}) {
  return (
    <div className="rounded-lg border border-gray-700 bg-gray-800 p-4">
      <p className="text-xs text-gray-400">{label}</p>
      <p className="mt-1 text-2xl font-semibold text-white tabular-nums">{value}</p>
      {sub && <p className="mt-1 text-xs text-gray-500">{sub}</p>}
    </div>
  );
}

function Stat({
  label,
  value,
  accent,
  hint,
}: {
  label: string;
  value: number | string;
  accent?: string;
  hint?: string;
}) {
  return (
    <div>
      <dt className="text-xs text-gray-500">{label}</dt>
      <dd className={`mt-1 text-xl font-semibold tabular-nums ${accent ?? 'text-white'}`}>{value}</dd>
      {hint && <p className="mt-0.5 text-[10px] text-gray-500">{hint}</p>}
    </div>
  );
}
