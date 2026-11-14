'use client';

/**
 * Executive weekly digest panel — WS-G2.
 *
 * Renders the deterministic snapshot returned by
 * `GET /api/v1/reports/digest/weekly?format=json` as an interactive dashboard,
 * and exposes a "Print / Save as PDF" action that fetches the print-ready HTML
 * variant (with the user's auth token) and opens it in a new tab. The browser's
 * native "Save as PDF" then produces the board-ready document — no server-side
 * PDF dependency required.
 */

import { useCallback, useMemo, useState } from 'react';
import useSWR from 'swr';

import { reportsApi, type ExecutiveDigest as ExecutiveDigestPayload } from '@/lib/api';

const PERIOD_PRESETS: { label: string; days: number }[] = [
  { label: 'Last 7 days', days: 7 },
  { label: 'Last 14 days', days: 14 },
  { label: 'Last 30 days', days: 30 },
];

const SEVERITY_ORDER: Array<keyof ExecutiveDigestPayload['alerts']['severity']> = [
  'critical',
  'high',
  'medium',
  'low',
  'info',
];

const SEVERITY_TEXT: Record<string, string> = {
  critical: 'text-red-300',
  high: 'text-orange-300',
  medium: 'text-yellow-300',
  low: 'text-blue-300',
  info: 'text-gray-300',
};

const RECOMMENDATION_ACCENT: Record<string, string> = {
  critical: 'border-red-500/40 bg-red-500/10 text-red-100',
  warning: 'border-amber-500/40 bg-amber-500/10 text-amber-100',
  info: 'border-sky-500/40 bg-sky-500/10 text-sky-100',
};

function fmtHours(hours: number | null | undefined): string {
  if (hours === null || hours === undefined) return '—';
  if (hours < 1) return `${Math.round(hours * 60)}m`;
  if (hours < 24) return `${hours.toFixed(1)}h`;
  const days = hours / 24;
  return `${days.toFixed(1)}d`;
}

function fmtDateTime(iso: string): string {
  try {
    return new Date(iso).toLocaleString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: 'numeric',
      minute: '2-digit',
    });
  } catch {
    return iso;
  }
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

function fmtDelta(delta: number): string {
  if (delta === 0) return '±0';
  return delta > 0 ? `+${delta}` : `${delta}`;
}

function deltaClass(delta: number): string {
  if (delta === 0) return 'text-gray-500';
  // For tactic counts: positive (more activity) is concerning, negative (less) is good.
  return delta > 0 ? 'text-amber-300' : 'text-emerald-300';
}

function periodWindow(days: number): { period_start: string; period_end: string } {
  const end = new Date();
  const start = new Date(end.getTime() - days * 24 * 60 * 60 * 1000);
  return {
    period_start: start.toISOString(),
    period_end: end.toISOString(),
  };
}

export function ExecutiveDigest() {
  const [days, setDays] = useState<number>(7);
  const [printing, setPrinting] = useState(false);
  const [printError, setPrintError] = useState<string | null>(null);

  const params = useMemo(() => periodWindow(days), [days]);

  const { data, error, isLoading, mutate } = useSWR<ExecutiveDigestPayload>(
    ['executive-digest', params.period_start, params.period_end],
    () => reportsApi.weeklyDigest(params),
    {
      revalidateOnFocus: false,
      shouldRetryOnError: false,
      errorRetryCount: 0,
    },
  );

  const handlePrint = useCallback(async () => {
    setPrintError(null);
    setPrinting(true);
    try {
      const html = await reportsApi.weeklyDigestHtml(params);
      const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      // Open in a new tab so the user can hit Cmd/Ctrl+P or use the system print dialog.
      const win = window.open(url, '_blank', 'noopener,noreferrer');
      if (!win) {
        setPrintError('Pop-up blocked — allow pop-ups for this site to open the printable digest.');
      }
      // Defer revoke so the new tab has time to load. 60 seconds is a generous safety net.
      setTimeout(() => URL.revokeObjectURL(url), 60_000);
    } catch (err) {
      setPrintError(err instanceof Error ? err.message : 'Failed to load printable digest.');
    } finally {
      setPrinting(false);
    }
  }, [params]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Executive Digest</h1>
          <p className="mt-1 text-sm text-gray-400">
            Board-ready weekly snapshot of SOC posture, MTT performance, and tuning recommendations.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <select
            value={days}
            onChange={(e) => setDays(Number(e.target.value))}
            className="rounded border border-gray-600 bg-gray-800 px-3 py-1.5 text-sm text-white"
          >
            {PERIOD_PRESETS.map((p) => (
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
          <button
            type="button"
            onClick={handlePrint}
            disabled={printing || !data}
            className="rounded bg-violet-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-violet-500 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {printing ? 'Loading…' : 'Print / Save as PDF'}
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-md border border-red-500/30 bg-red-500/10 px-4 py-2 text-sm text-red-200">
          Failed to load digest: {error instanceof Error ? error.message : String(error)}
        </div>
      )}
      {printError && (
        <div className="rounded-md border border-amber-500/30 bg-amber-500/10 px-4 py-2 text-sm text-amber-200">
          {printError}
        </div>
      )}

      {isLoading && !data && (
        <div className="rounded-xl border border-gray-700 bg-gray-900 p-6 text-sm text-gray-400">
          Computing digest…
        </div>
      )}

      {data && <DigestBody digest={data} />}
    </div>
  );
}

function DigestBody({ digest }: { digest: ExecutiveDigestPayload }) {
  return (
    <>
      {/* Period + headline */}
      <section className="rounded-xl border border-violet-500/30 bg-violet-950/20 p-5">
        <p className="text-xs uppercase tracking-wide text-violet-300">Reporting period</p>
        <p className="mt-1 text-lg font-semibold text-white">{digest.period.label}</p>
        <p className="mt-3 text-sm leading-relaxed text-gray-200">{digest.headline}</p>
        <p className="mt-2 text-xs text-gray-500">
          {fmtDateTime(digest.period.start)} → {fmtDateTime(digest.period.end)}
        </p>
      </section>

      {/* KPI strip */}
      <section className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <KpiCard label="New alerts" value={digest.alerts.new} sub={`${digest.alerts.total} total in window`} />
        <KpiCard
          label="Open alerts"
          value={digest.alerts.open_at_period_end}
          sub={`${digest.alerts.resolved} resolved this period`}
        />
        <KpiCard
          label="Cases opened"
          value={digest.cases.opened}
          sub={`${digest.cases.closed} closed · ${digest.cases.sla_breached} SLA breaches`}
        />
        <KpiCard
          label="Mean MTTR"
          value={fmtHours(digest.mtt.mttr_hours)}
          sub={`MTTD ${fmtHours(digest.mtt.mttd_hours)} · MTTC ${fmtHours(digest.mtt.mttc_hours)}`}
        />
      </section>

      {/* Severity split + automation */}
      <section className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card title="Alerts by severity" subtitle="Distribution of alerts created in the window">
          <div className="space-y-2">
            {SEVERITY_ORDER.map((sev) => {
              const count = digest.alerts.severity[sev] ?? 0;
              const pct = digest.alerts.total > 0 ? (count / digest.alerts.total) * 100 : 0;
              return (
                <div key={sev} className="flex items-center gap-3 text-sm">
                  <span className={`w-20 capitalize ${SEVERITY_TEXT[sev]}`}>{sev}</span>
                  <div className="h-2 flex-1 overflow-hidden rounded-full bg-gray-800">
                    <div
                      className="h-full rounded-full bg-violet-500"
                      style={{ width: `${Math.min(100, Math.max(0, pct))}%` }}
                    />
                  </div>
                  <span className="w-14 text-right text-gray-200 tabular-nums">{count}</span>
                </div>
              );
            })}
          </div>
        </Card>

        <Card title="Automation" subtitle="Remediation gate decisions in the window">
          <dl className="grid grid-cols-2 gap-4 text-sm">
            <Stat label="Total decisions" value={digest.automation.total_decisions} />
            <Stat label="Auto-executed" value={digest.automation.auto_executed} accent="text-emerald-300" />
            <Stat label="Escalated" value={digest.automation.escalated} accent="text-amber-300" />
            <Stat label="Review pending" value={digest.automation.review_pending} accent="text-sky-300" />
          </dl>
          <p className="mt-4 text-xs text-gray-500">
            {digest.automation.total_decisions === 0
              ? 'No remediation decisions logged this period.'
              : `${
                  Math.round(
                    (digest.automation.auto_executed / Math.max(1, digest.automation.total_decisions)) * 1000,
                  ) / 10
                }% of decisions executed without analyst intervention.`}
          </p>
        </Card>
      </section>

      {/* Top tactics + top sources */}
      <section className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card title="Top MITRE tactics" subtitle="Vs. prior comparable window">
          {digest.top_tactics.length === 0 ? (
            <p className="text-sm text-gray-500">No tactic-tagged alerts in this window.</p>
          ) : (
            <ul className="divide-y divide-gray-800">
              {digest.top_tactics.map((t) => (
                <li key={t.tactic} className="flex items-center justify-between py-2 text-sm">
                  <span className="text-gray-200">{t.tactic}</span>
                  <span className="flex items-center gap-3">
                    <span className="text-white tabular-nums">{t.count}</span>
                    <span className={`text-xs tabular-nums ${deltaClass(t.delta_from_prior)}`}>
                      {fmtDelta(t.delta_from_prior)}
                    </span>
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="Top alert sources" subtitle="Connectors driving the most volume">
          {digest.top_sources.length === 0 ? (
            <p className="text-sm text-gray-500">No connector-tagged alerts in this window.</p>
          ) : (
            <ul className="divide-y divide-gray-800">
              {digest.top_sources.map((s) => (
                <li key={s.connector_type} className="flex items-center justify-between py-2 text-sm">
                  <span className="text-gray-200">{s.connector_type}</span>
                  <span className="text-white tabular-nums">{s.count}</span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </section>

      {/* High-risk alerts */}
      <Card
        title="Highest-risk alerts"
        subtitle="Top alerts ranked by AI score and severity in the window"
      >
        {digest.high_risk_alerts.length === 0 ? (
          <p className="text-sm text-gray-500">No high-risk alerts surfaced this period.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[640px] text-left text-sm">
              <thead>
                <tr className="border-b border-gray-700 text-xs uppercase tracking-wide text-gray-500">
                  <th className="py-2 pr-4 font-medium">Title</th>
                  <th className="py-2 pr-4 font-medium">Severity</th>
                  <th className="py-2 pr-4 font-medium">AI score</th>
                  <th className="py-2 pr-4 font-medium">Tactics</th>
                  <th className="py-2 font-medium">Event time</th>
                </tr>
              </thead>
              <tbody>
                {digest.high_risk_alerts.map((a) => (
                  <tr key={a.alert_id} className="border-b border-gray-800/80">
                    <td className="py-2.5 pr-4 text-gray-100">{a.title || a.alert_id}</td>
                    <td className={`py-2.5 pr-4 capitalize ${SEVERITY_TEXT[a.severity] ?? 'text-gray-300'}`}>
                      {a.severity}
                    </td>
                    <td className="py-2.5 pr-4 text-gray-200 tabular-nums">
                      {a.ai_score === null || a.ai_score === undefined
                        ? '—'
                        : a.ai_score.toFixed(2)}
                    </td>
                    <td className="py-2.5 pr-4 text-gray-400">
                      {a.mitre_tactics.length === 0 ? '—' : a.mitre_tactics.join(', ')}
                    </td>
                    <td className="py-2.5 text-gray-400">{fmtDate(a.event_time)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Recommendations */}
      <Card
        title="Recommendations"
        subtitle="Auto-generated, deterministic guidance based on this window's signals"
      >
        {digest.recommendations.length === 0 ? (
          <p className="text-sm text-gray-500">No recommendations triggered for this period.</p>
        ) : (
          <ul className="space-y-3">
            {digest.recommendations.map((r, idx) => (
              <li
                key={`${r.title}-${idx}`}
                className={`rounded-lg border p-4 ${
                  RECOMMENDATION_ACCENT[r.severity] ?? RECOMMENDATION_ACCENT.info
                }`}
              >
                <p className="text-sm font-semibold">{r.title}</p>
                <p className="mt-1 text-sm leading-relaxed opacity-90">{r.body}</p>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </>
  );
}

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
}: {
  label: string;
  value: number | string;
  accent?: string;
}) {
  return (
    <div>
      <dt className="text-xs text-gray-500">{label}</dt>
      <dd className={`mt-1 text-xl font-semibold tabular-nums ${accent ?? 'text-white'}`}>{value}</dd>
    </div>
  );
}
