'use client';

/**
 * What the agents actually did, and what it cost.
 *
 * `GET /api/v1/costs/dashboard` joins `aisoc_run_costs` to `investigation_runs`
 * — real recorded token counts and spend from real runs, not a projection. The
 * client existed (`costsApi.dashboard`) and was used only by the admin cost
 * page; the throughput reading it supports belongs next to pipeline health,
 * because "the agents triaged nothing today" and "the agents cost nothing
 * today" are the same row of data read two ways.
 *
 * `total_runs` is investigation runs, not alerts triaged. The panel labels it
 * as runs. Calling it "alerts triaged" would be a different measurement than
 * the one the endpoint makes.
 */

import useSWR from 'swr';
import { costsApi } from '@/lib/api';
import { EmptyState } from '@/components/ui/EmptyState';
import { ErrorState } from '@/components/ui/ErrorState';

const WINDOW_DAYS = 7;

function formatUsd(value: number): string {
  if (!Number.isFinite(value)) return '—';
  return value < 1 ? `$${value.toFixed(4)}` : `$${value.toFixed(2)}`;
}

function formatCompact(value: number): string {
  if (!Number.isFinite(value)) return '—';
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)}M`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(1)}k`;
  return value.toLocaleString();
}

export function AgentThroughputPanel() {
  const { data, error, isLoading, mutate } = useSWR(
    `ops-agent-cost:${WINDOW_DAYS}`,
    () => costsApi.dashboard({ window_days: WINDOW_DAYS }),
    { refreshInterval: 120_000, revalidateOnFocus: false },
  );

  const headline = data?.headline;
  const byModel = data?.by_model ?? [];
  const maxModelCost = Math.max(...byModel.map((m) => m.total_cost_usd), 0.0001);
  // A bar can only be drawn from a measured figure. Scaling an unmeasured
  // zero still draws nothing, but the label beside it would have read
  // "$0.00" — a claim the panel has no basis for.
  //
  // A *missing* count is treated as zero, i.e. not measured. This is the
  // opposite of what the MTTR tiles do with a missing sample count, and
  // deliberately so: an older API that omits a sample size still sent a real
  // mean, whereas an older API that omits these counts sent a figure we now
  // know was a list-price guess keyed on a gateway alias. Rendering the
  // familiar number is the safe default there and the unsafe one here.
  const measuredCalls = headline?.measured_call_count ?? 0;
  const estimatedCalls = headline?.estimated_call_count ?? 0;
  const anyMeasured = measuredCalls > 0;

  return (
    <section
      aria-labelledby="ops-agent-heading"
      className="rounded-xl border border-gray-800/60 bg-gray-900/40"
    >
      <div className="px-4 py-3">
        <h2 id="ops-agent-heading" className="text-sm font-medium text-gray-300">
          Agent throughput and spend
        </h2>
        <p className="mt-0.5 text-[11px] text-gray-500">
          Recorded token usage from the last {WINDOW_DAYS} days of investigation runs.
        </p>
      </div>

      {isLoading && !data ? (
        <div className="m-4 h-28 animate-pulse rounded bg-gray-800/40" />
      ) : error ? (
        <ErrorState
          title="Agent telemetry unavailable"
          error={error}
          onRetry={() => {
            void mutate();
          }}
          className="m-4"
        />
      ) : !headline || headline.total_runs === 0 ? (
        <EmptyState
          title="No agent runs in this window"
          description={`Nothing has been investigated in the last ${WINDOW_DAYS} days, so there is no token usage to report.`}
          className="m-4"
        />
      ) : (
        <div className="space-y-4 px-4 pb-4">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Stat label="Runs" value={headline.total_runs.toLocaleString()} />
            <Stat label="LLM calls" value={formatCompact(headline.total_calls)} />
            <Stat label="Tokens" value={formatCompact(headline.total_tokens)} />
            <Stat
              label="Measured spend"
              value={anyMeasured ? formatUsd(headline.total_cost_usd) : '—'}
            />
          </div>

          {/* Only render the derived per-run figure the server computed. When
              it is null the server had no basis for it, and dividing here
              would invent one. */}
          {anyMeasured && headline.avg_cost_per_run_usd != null ? (
            <p className="text-[11px] text-gray-500">
              {`${formatUsd(headline.avg_cost_per_run_usd)} per run on average, measured over ${measuredCalls.toLocaleString()} calls.`}
            </p>
          ) : (
            <p className="text-[11px] text-gray-500">
              {estimatedCalls > 0
                ? `Spend not measured — the gateway reported no cost. List price for the models involved is ~${formatUsd(headline.estimated_cost_usd)}.`
                : 'Spend not measured: no call in this window reported a cost.'}
            </p>
          )}

          {byModel.length > 0 && (
            <div>
              <p className="mb-2 text-[11px] uppercase tracking-wider text-gray-500">
                By model
              </p>
              <ul className="space-y-2">
                {byModel.map((m) => (
                  <li key={m.model}>
                    <div className="mb-1 flex items-baseline justify-between gap-3">
                      <span className="truncate font-mono text-[11px] text-gray-300">
                        {m.model}
                      </span>
                      <span className="shrink-0 text-[11px] text-gray-500">
                        {`${m.runs} runs · ${
                          (m.measured_call_count ?? 0) > 0
                            ? formatUsd(m.total_cost_usd)
                            : (m.estimated_call_count ?? 0) > 0
                              ? `~${formatUsd(m.estimated_cost_usd)} est.`
                              : 'cost not measured'
                        }`}
                      </span>
                    </div>
                    {anyMeasured && (
                      <div className="h-1 rounded-full bg-gray-800">
                        <div
                          className="h-1 rounded-full bg-indigo-500/60"
                          style={{
                            width: `${Math.round((m.total_cost_usd / maxModelCost) * 100)}%`,
                          }}
                        />
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </section>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-[11px] uppercase tracking-wider text-gray-500">{label}</p>
      <p className="text-xl font-semibold text-gray-100">{value}</p>
    </div>
  );
}
