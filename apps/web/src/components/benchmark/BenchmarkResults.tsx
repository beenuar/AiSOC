import clsx from 'clsx';

interface SuiteRow {
  id: string;
  name: string;
  metric: string;
  value: number;
  display: string;
  target: number;
  targetDisplay: string;
  blurb: string;
  /** corpus / sub-metrics surfaced beneath the headline number */
  details: { label: string; value: string }[];
}

/**
 * Snapshot of the latest run on `main`. Keep these aligned with
 * `eval_report.json` produced by `scripts/run_evals.py`. The doc note on the
 * page explains that the live page in the wild can be wired to the
 * `eval-results` branch later; for v0 of the public benchmark page we hardcode
 * the most-recent passing snapshot so visitors see real numbers without a
 * round-trip.
 */
const SUITES: SuiteRow[] = [
  {
    id: 'mitre_accuracy',
    name: 'MITRE accuracy',
    metric: 'Tactic accuracy',
    value: 0.97,
    display: '97.0%',
    target: 0.8,
    targetDisplay: '≥80%',
    blurb:
      'Per-incident accuracy of inferred MITRE ATT&CK tactic across 200 deterministic synthetic incidents covering all 14 tactics and the top 50 techniques.',
    details: [
      { label: 'Incidents', value: '200' },
      { label: 'Correct', value: '194' },
      { label: 'Macro F1', value: '0.78' },
    ],
  },
  {
    id: 'alert_reduction',
    name: 'Alert reduction',
    metric: 'Reduction ratio',
    value: 0.753,
    display: '75.3%',
    target: 0.7,
    targetDisplay: '≥70%',
    blurb:
      'Three-tier fusion (signature + entity-window + storm-collapse) applied to 1,000 noisy alerts. Honest measurement; no marketing math.',
    details: [
      { label: 'Alerts in', value: '1,000' },
      { label: 'Incidents out', value: '247' },
      { label: 'Storms', value: '16' },
    ],
  },
  {
    id: 'investigation_completeness',
    name: 'Investigation completeness',
    metric: 'Mean keyword coverage',
    value: 0.943,
    display: '94.3%',
    target: 0.85,
    targetDisplay: '≥85%',
    blurb:
      'Fraction of expected evidence keywords (entities, IOCs, MITRE tags, severity cues) that appear in the agent\'s narrative report per incident.',
    details: [
      { label: 'Incidents', value: '200' },
      { label: 'Fully covered', value: '134 (67%)' },
      { label: 'Method', value: 'Deterministic extractor' },
    ],
  },
  {
    id: 'response_quality',
    name: 'Response quality',
    metric: 'Mean rubric score',
    value: 1.0,
    display: '100%',
    target: 0.8,
    targetDisplay: '≥80%',
    blurb:
      "Five-criterion rubric (action aligned, severity-aware, MITRE-aligned, evidence-grounded, actionable) scored offline so the gate doesn't depend on a paid LLM.",
    details: [
      { label: 'Incidents', value: '200' },
      { label: 'Criteria', value: '5 of 5 perfect' },
      { label: 'Judge', value: 'Offline keyword' },
    ],
  },
];

export function BenchmarkResults() {
  return (
    <div className="grid gap-4 md:grid-cols-2">
      {SUITES.map((suite) => {
        const passed = suite.value >= suite.target;
        const headroom = ((suite.value - suite.target) * 100).toFixed(1);
        return (
          <div
            key={suite.id}
            className="group relative overflow-hidden rounded-xl border border-white/10 bg-white/[0.02] p-6 transition-colors hover:border-white/20"
          >
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="text-xs uppercase tracking-wider text-gray-500">
                  {suite.metric}
                </p>
                <h3 className="mt-1 text-base font-semibold text-white">
                  {suite.name}
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
                {suite.display}
              </span>
              <span className="text-xs text-gray-500">
                target {suite.targetDisplay}
              </span>
            </div>
            <div className="mt-1 text-xs text-gray-500">
              {passed ? `+${headroom} pts above gate` : `${headroom} pts below gate`}
            </div>

            <p className="mt-4 text-sm leading-relaxed text-gray-400">
              {suite.blurb}
            </p>

            <div className="mt-5 flex flex-wrap gap-x-6 gap-y-2 border-t border-white/5 pt-4 text-xs">
              {suite.details.map((d) => (
                <div key={d.label}>
                  <dt className="text-gray-500">{d.label}</dt>
                  <dd className="mt-0.5 font-mono tabular-nums text-gray-200">
                    {d.value}
                  </dd>
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}
