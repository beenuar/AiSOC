import clsx from 'clsx';

type Kind = 'measurement' | 'self-consistency';

interface PerTemplateBlock {
  metric: string;
  value: number;
  target: number;
  passed: boolean;
  template_count: number;
  failing_templates: string[];
}

interface SuiteBlock {
  metric: string;
  value: number;
  target: number;
  passed: boolean;
  duration_ms?: number;
  details?: Record<string, unknown>;
  per_template?: PerTemplateBlock;
}

export interface EvalReport {
  generated_at: string;
  dataset: string;
  suites: Record<string, SuiteBlock>;
  telemetry?: {
    present?: boolean;
    events?: number;
    sources?: Record<string, number>;
    incidents_with_telemetry?: number;
    path?: string;
  };
  all_passed: boolean;
  /** Source URL we actually fetched, for the "verify yourself" link. */
  _source?: string;
  /** Set when the live fetch failed and we fell back to the snapshot below. */
  _stale?: boolean;
}

/**
 * Snapshot fallback used when the live fetch from the `eval-results` branch
 * fails (e.g. the branch hasn't been initialized yet, or the build runs
 * offline). Numbers are hand-copied from a recent `scripts/run_evals.py`
 * run on `main`. The pass/fail gates in `services/agents/tests/test_*.py`
 * are the source of truth — if they pass, the headline "≥ target" claim
 * still holds even if these exact percentages lag a commit or two.
 */
const SNAPSHOT_REPORT: EvalReport = {
  generated_at: '2026-05-06T04:32:09.258436+00:00',
  dataset: 'synthetic_incidents.json (200 cases, deterministic)',
  all_passed: true,
  suites: {
    mitre_accuracy: {
      metric: 'accuracy',
      value: 0.97,
      target: 0.8,
      passed: true,
      details: { incidents: 200, correct: 194, f1: 0.7712 },
      per_template: {
        metric: 'macro_accuracy',
        value: 0.9636,
        target: 0.8,
        passed: true,
        template_count: 55,
        failing_templates: ['outlook-auto-forward-rule', 'compromised-ci-runner'],
      },
    },
    alert_reduction: {
      metric: 'reduction_ratio',
      value: 0.753,
      target: 0.7,
      passed: true,
      details: {
        alerts_in: 1000,
        incidents_out: 247,
        storm_incidents: 16,
      },
    },
    investigation_completeness: {
      metric: 'mean_keyword_coverage',
      value: 0.9425,
      target: 0.85,
      passed: true,
      details: { incidents: 200, fully_covered: 134, fully_covered_pct: 0.67 },
      per_template: {
        metric: 'macro_completeness',
        value: 0.9429,
        target: 0.8,
        passed: true,
        template_count: 55,
        failing_templates: [],
      },
    },
    response_quality: {
      metric: 'mean_rubric_score',
      value: 1.0,
      target: 0.8,
      passed: true,
      details: { incidents: 200 },
      per_template: {
        metric: 'macro_score',
        value: 1.0,
        target: 0.75,
        passed: true,
        template_count: 55,
        failing_templates: [],
      },
    },
  },
  telemetry: {
    present: true,
    events: 361,
    incidents_with_telemetry: 200,
    path: 'services/agents/tests/eval_data/synthetic_telemetry.jsonl',
  },
};

const LATEST_URL =
  'https://raw.githubusercontent.com/beenuar/AiSOC/eval-results/eval/results/latest.json';

/**
 * Server-side fetch of the most recent `eval_report.json` published by the
 * `p1-eval` job in `.github/workflows/ci.yml`. The job writes
 * `eval/results/<sha>.json` and `eval/results/latest.json` on the
 * `eval-results` branch on every successful main-branch run.
 *
 * We use Next.js fetch revalidation so the page stays fresh between pushes
 * without rebuilding the site. On failure we transparently fall back to the
 * hand-copied `SNAPSHOT_REPORT` and flag the response as stale.
 */
export async function fetchLatestEvalReport(): Promise<EvalReport> {
  try {
    const res = await fetch(LATEST_URL, {
      // Re-fetch every 5 minutes; CI publishes on every main-branch push.
      next: { revalidate: 300 },
    });
    if (!res.ok) {
      throw new Error(`status ${res.status}`);
    }
    const data = (await res.json()) as EvalReport;
    return { ...data, _source: LATEST_URL };
  } catch {
    return { ...SNAPSHOT_REPORT, _source: LATEST_URL, _stale: true };
  }
}

interface SuiteCard {
  id: string;
  name: string;
  metricLabel: string;
  blurb: string;
  kind: Kind;
}

const SUITE_META: Record<string, SuiteCard> = {
  alert_reduction: {
    id: 'alert_reduction',
    name: 'Alert reduction',
    metricLabel: 'Reduction ratio',
    kind: 'measurement',
    blurb:
      "A 1,000-alert noisy stream (duplicates, near-duplicates, rule storms, low-score chatter) is fed into an in-harness re-implementation of the production Tier 1 / 2 / 3 grouping rules — same logic, no DB-backed dedup or ML scorer. The number is whatever the code produces; a regression in the grouping rules moves it.",
  },
  mitre_accuracy: {
    id: 'mitre_accuracy',
    name: 'MITRE tactic accuracy',
    metricLabel: 'Tactic accuracy (per-case)',
    kind: 'self-consistency',
    blurb:
      'Each synthetic incident is generated with a labeled tactic and a description written to include keywords the hand-curated extractor recognizes. The headline number mostly checks that dataset and extractor agree — useful as a regression sentinel for the extractor, not a measure of LLM agent accuracy.',
  },
  investigation_completeness: {
    id: 'investigation_completeness',
    name: 'Investigation completeness',
    metricLabel: 'Mean keyword coverage',
    kind: 'self-consistency',
    blurb:
      "The simulator wraps each incident's description in a Markdown report; the judge then looks for evidence keywords drawn from that same description. Close to a string-copy tautology — it confirms the report template includes the description and the judge can find keywords inside it. Catches template breakage, not LLM quality.",
  },
  response_quality: {
    id: 'response_quality',
    name: 'Response-plan quality',
    metricLabel: 'Mean rubric score',
    kind: 'self-consistency',
    blurb:
      'The synthesizer embeds the expected MITRE techniques and first evidence keyword directly into the templated plan, then a 5-criterion rubric checks for them. By construction the score is ~1.000. Catches a broken templating pipeline; it is not a grade of LLM-written plans.',
  },
};

const KIND_LABEL: Record<Kind, { label: string; classes: string }> = {
  measurement: {
    label: 'Real measurement',
    classes: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200',
  },
  'self-consistency': {
    label: 'Substrate self-consistency',
    classes: 'border-amber-500/30 bg-amber-500/10 text-amber-200',
  },
};

function formatPercent(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

function formatTarget(value: number): string {
  return `≥${(value * 100).toFixed(0)}%`;
}

function suiteDetailRows(
  id: string,
  suite: SuiteBlock,
): { label: string; value: string }[] {
  const d = suite.details ?? {};
  const rows: { label: string; value: string }[] = [];
  if (id === 'alert_reduction') {
    if (typeof d.alerts_in === 'number') rows.push({ label: 'Alerts in', value: String(d.alerts_in) });
    if (typeof d.incidents_out === 'number')
      rows.push({ label: 'Incidents out', value: String(d.incidents_out) });
    if (typeof d.storm_incidents === 'number')
      rows.push({ label: 'Storms', value: String(d.storm_incidents) });
  } else if (id === 'mitre_accuracy') {
    if (typeof d.incidents === 'number') rows.push({ label: 'Incidents', value: String(d.incidents) });
    if (typeof d.correct === 'number') rows.push({ label: 'Correct', value: String(d.correct) });
    if (typeof d.f1 === 'number') rows.push({ label: 'F1 (per-case)', value: d.f1.toFixed(2) });
  } else if (id === 'investigation_completeness') {
    if (typeof d.incidents === 'number') rows.push({ label: 'Incidents', value: String(d.incidents) });
    if (typeof d.fully_covered === 'number' && typeof d.fully_covered_pct === 'number') {
      rows.push({
        label: 'Fully covered',
        value: `${d.fully_covered} (${(d.fully_covered_pct * 100).toFixed(0)}%)`,
      });
    }
    rows.push({ label: 'Judge', value: 'Offline keyword' });
  } else if (id === 'response_quality') {
    if (typeof d.incidents === 'number') rows.push({ label: 'Incidents', value: String(d.incidents) });
    rows.push({ label: 'Criteria', value: '5 (all hit by template)' });
    rows.push({ label: 'Judge', value: 'Offline keyword' });
  }
  return rows;
}

interface BenchmarkResultsProps {
  report: EvalReport;
}

export function BenchmarkResults({ report }: BenchmarkResultsProps) {
  const orderedIds: string[] = [
    'alert_reduction',
    'mitre_accuracy',
    'investigation_completeness',
    'response_quality',
  ];

  return (
    <div className="grid gap-4 md:grid-cols-2">
      {orderedIds.map((id) => {
        const suite = report.suites[id];
        const meta = SUITE_META[id];
        if (!suite || !meta) return null;
        const passed = suite.passed;
        const headroom = ((suite.value - suite.target) * 100).toFixed(1);
        const kind = KIND_LABEL[meta.kind];
        const details = suiteDetailRows(id, suite);
        const perTemplate = suite.per_template;
        return (
          <div
            key={id}
            className="group relative overflow-hidden rounded-xl border border-white/10 bg-white/[0.02] p-6 transition-colors hover:border-white/20"
          >
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="text-xs uppercase tracking-wider text-gray-500">
                  {meta.metricLabel}
                </p>
                <h3 className="mt-1 text-base font-semibold text-white">
                  {meta.name}
                </h3>
              </div>
              <span
                className={clsx(
                  'inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium',
                  passed
                    ? 'border border-emerald-500/20 bg-emerald-500/10 text-emerald-300'
                    : 'border border-rose-500/20 bg-rose-500/10 text-rose-300',
                )}
              >
                <span
                  className={clsx(
                    'h-1.5 w-1.5 rounded-full',
                    passed ? 'bg-emerald-400' : 'bg-rose-400',
                  )}
                />
                {passed ? 'Pass' : 'Fail'}
              </span>
            </div>

            <div className="mt-5 flex items-baseline gap-2">
              <span className="font-mono text-4xl font-semibold tabular-nums text-white">
                {formatPercent(suite.value)}
              </span>
              <span className="text-xs text-gray-500">
                target {formatTarget(suite.target)}
              </span>
            </div>
            <div className="mt-1 text-xs text-gray-500">
              {passed ? `+${headroom} pts above gate` : `${headroom} pts below gate`}
            </div>

            <span
              className={clsx(
                'mt-4 inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider',
                kind.classes,
              )}
            >
              {kind.label}
            </span>

            <p className="mt-3 text-sm leading-relaxed text-gray-400">
              {meta.blurb}
            </p>

            {perTemplate && (
              <div className="mt-4 rounded-lg border border-white/5 bg-black/20 p-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <p className="text-[10px] font-semibold uppercase tracking-wider text-gray-500">
                      Per-template macro
                    </p>
                    <p className="mt-0.5 text-xs text-gray-400">
                      Equal-weight average across {perTemplate.template_count} distinct
                      incident templates &mdash; surfaces a single weak template that the
                      per-case mean would mask.
                    </p>
                  </div>
                  <div className="text-right">
                    <span className="font-mono text-base font-semibold tabular-nums text-white">
                      {formatPercent(perTemplate.value)}
                    </span>
                    <p className="mt-0.5 text-[10px] text-gray-500">
                      target {formatTarget(perTemplate.target)}
                    </p>
                  </div>
                </div>
                {perTemplate.failing_templates.length > 0 && (
                  <p className="mt-2 text-[11px] text-amber-300/80">
                    Regressions:{' '}
                    <span className="font-mono">
                      {perTemplate.failing_templates.join(', ')}
                    </span>
                  </p>
                )}
              </div>
            )}

            {details.length > 0 && (
              <div className="mt-5 flex flex-wrap gap-x-6 gap-y-2 border-t border-white/5 pt-4 text-xs">
                {details.map((d) => (
                  <div key={d.label}>
                    <dt className="text-gray-500">{d.label}</dt>
                    <dd className="mt-0.5 font-mono tabular-nums text-gray-200">
                      {d.value}
                    </dd>
                  </div>
                ))}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
