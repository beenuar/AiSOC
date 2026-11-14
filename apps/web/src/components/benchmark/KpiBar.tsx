import clsx from 'clsx';
import type { EvalReport } from './BenchmarkResults';

/**
 * 2026 published KPI bar — the buyer-side scoring rubric AiSOC commits to.
 * Mirrors `DEFAULT_KPI_BAR_TARGETS` in `services/api/app/services/sla.py`
 * and the four metrics surfaced in the in-app SLA dashboard
 * (`apps/web/src/components/sla/SLADashboard.tsx`).
 *
 * MTTD/MTTR are tenant-runtime metrics, surfaced inside the product rather
 * than on the public scoreboard. The four metrics below are the ones we can
 * report from the open synthetic harness without needing a live tenant.
 */
interface KpiTarget {
  id: string;
  label: string;
  target: string;
  /**
   * Live observed number from the eval report when available, else "n/a".
   */
  observed?: string;
  observedPasses?: boolean;
  blurb: string;
}

function fmtPct(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

function buildTargets(report: EvalReport): KpiTarget[] {
  const alertReduction = report.suites.alert_reduction;
  const mitre = report.suites.mitre_accuracy;

  // Alert-to-incident ratio is derived from the alert-reduction suite:
  // 1,000 fabricated alerts compress to N incidents → ratio = 1000 / N.
  const alertsIn = (alertReduction?.details?.alerts_in as number | undefined) ?? 1000;
  const incidentsOut = alertReduction?.details?.incidents_out as number | undefined;
  const ratio = incidentsOut && incidentsOut > 0 ? alertsIn / incidentsOut : undefined;
  const ratioObserved = ratio ? `${ratio.toFixed(1)}:1` : undefined;
  const ratioPasses = typeof ratio === 'number' ? ratio >= 50 : undefined;

  // MITRE technique tagging: per-template macro is the closest published
  // proxy on the open harness. The in-tenant SLA dashboard uses the live
  // `mitre_technique_tagging_min_pct` from `tenant_sla_summary`.
  const macro = mitre?.per_template;
  const macroValue = macro?.value;
  const macroPasses = typeof macroValue === 'number' ? macroValue >= 0.85 : undefined;

  return [
    {
      id: 'fp_rate',
      label: 'False-positive rate',
      target: '≤ 5%',
      blurb:
        "A live tenant metric from `services/api`'s SLA service — surfaced in the in-app SLA dashboard, not on the public harness. The harness can't measure FP rate against synthetic data.",
    },
    {
      id: 'a2i_ratio',
      label: 'Alert-to-incident ratio',
      target: '≥ 50:1',
      observed: ratioObserved,
      observedPasses: ratioPasses,
      blurb:
        'Derived from the alert-reduction suite: a 1,000-alert noisy stream is fed through the in-harness fusion grouping, and the ratio is 1,000 ÷ incidents_out.',
    },
    {
      id: 'mitre_t',
      label: 'MITRE technique tagging',
      target: '≥ 85%',
      observed: typeof macroValue === 'number' ? fmtPct(macroValue) : undefined,
      observedPasses: macroPasses,
      blurb:
        'Per-template macro accuracy across 55 incident templates is the closest open-harness proxy. In-tenant data uses the live ECS technique-tag rate.',
    },
    {
      id: 'mitre_st',
      label: 'MITRE sub-technique tagging',
      target: '≥ 60%',
      blurb:
        'Live tenant metric. The synthetic harness labels at the tactic level; sub-technique coverage is reported from live detection content in the in-app SLA dashboard.',
    },
  ];
}

interface KpiBarProps {
  report: EvalReport;
}

export function KpiBar({ report }: KpiBarProps) {
  const targets = buildTargets(report);
  return (
    <div className="rounded-2xl border border-white/10 bg-white/[0.02] p-6">
      <div className="flex flex-wrap items-baseline justify-between gap-3">
        <div>
          <h3 className="text-lg font-semibold tracking-tight text-white">
            2026 published KPI bar
          </h3>
          <p className="mt-1 max-w-2xl text-sm text-gray-400">
            The four buyer-side targets AiSOC commits to. The two derivable
            from the open harness are checked live below; the other two are
            tenant-runtime metrics surfaced in the in-app SLA dashboard.
          </p>
        </div>
        <a
          href="https://github.com/beenuar/AiSOC/blob/main/services/api/app/services/sla.py"
          target="_blank"
          rel="noreferrer"
          className="text-xs text-gray-500 underline decoration-dotted hover:text-gray-300"
        >
          Source: services/api/app/services/sla.py
        </a>
      </div>
      <dl className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {targets.map((t) => {
          const hasLive = typeof t.observed === 'string';
          const passes = t.observedPasses;
          return (
            <div
              key={t.id}
              className="rounded-lg border border-white/5 bg-black/20 p-4"
            >
              <dt className="text-[11px] font-semibold uppercase tracking-wider text-gray-500">
                {t.label}
              </dt>
              <dd className="mt-1 flex items-baseline gap-2">
                <span className="font-mono text-xl font-semibold tabular-nums text-white">
                  {t.target}
                </span>
                {hasLive && (
                  <span
                    className={clsx(
                      'inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-semibold',
                      passes === false
                        ? 'border-rose-500/30 bg-rose-500/10 text-rose-300'
                        : passes
                          ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
                          : 'border-white/10 bg-white/[0.03] text-gray-400',
                    )}
                  >
                    <span
                      className={clsx(
                        'h-1.5 w-1.5 rounded-full',
                        passes === false
                          ? 'bg-rose-400'
                          : passes
                            ? 'bg-emerald-400'
                            : 'bg-gray-400',
                      )}
                    />
                    Live: {t.observed}
                  </span>
                )}
                {!hasLive && (
                  <span className="text-[10px] uppercase tracking-wider text-gray-600">
                    in-app
                  </span>
                )}
              </dd>
              <p className="mt-2 text-xs leading-relaxed text-gray-500">
                {t.blurb}
              </p>
            </div>
          );
        })}
      </dl>
    </div>
  );
}
