import clsx from 'clsx';

type Kind = 'measurement' | 'self-consistency';

interface SuiteRow {
  id: string;
  name: string;
  metric: string;
  value: number;
  display: string;
  target: number;
  targetDisplay: string;
  /** What this number represents in plain English. */
  blurb: string;
  /**
   * Whether this suite measures real behavior (e.g. fusion logic) or merely
   * the internal consistency of the substrate (template + judge agree on
   * each other). The card uses this to label the gate honestly.
   */
  kind: Kind;
  /** corpus / sub-metrics surfaced beneath the headline number */
  details: { label: string; value: string }[];
}

/**
 * Snapshot of the latest run on `main`. Keep these aligned with
 * `eval_report.json` produced by `scripts/run_evals.py`.
 *
 * The blurbs deliberately avoid "agent accuracy" framing. The harness is
 * deterministic substrate code (no LLM calls), and three of the four metrics
 * mostly verify that the substrate is internally consistent (template + judge
 * agree on each other). We label that explicitly rather than letting a casual
 * reader assume the LangGraph agent is being graded.
 */
const SUITES: SuiteRow[] = [
  {
    id: 'alert_reduction',
    name: 'Alert reduction',
    metric: 'Reduction ratio',
    value: 0.753,
    display: '75.3%',
    target: 0.7,
    targetDisplay: '≥70%',
    kind: 'measurement',
    blurb:
      "A 1,000-alert noisy stream (duplicates, near-duplicates, rule storms, low-score chatter) is fed into the real fusion pipeline (Tier 1 / 2 / 3). The number is whatever the code produces — a fusion regression will move it.",
    details: [
      { label: 'Alerts in', value: '1,000' },
      { label: 'Incidents out', value: '247' },
      { label: 'Storms', value: '16' },
    ],
  },
  {
    id: 'mitre_accuracy',
    name: 'MITRE tactic accuracy',
    metric: 'Tactic accuracy',
    value: 0.97,
    display: '97.0%',
    target: 0.8,
    targetDisplay: '≥80%',
    kind: 'self-consistency',
    blurb:
      'Each synthetic incident is generated with a labeled tactic and a description written to include keywords the hand-curated extractor recognizes. The 97% mostly checks that dataset and extractor agree — useful as a regression sentinel for the extractor, not a measure of LLM agent accuracy.',
    details: [
      { label: 'Incidents', value: '200' },
      { label: 'Correct', value: '194' },
      { label: 'Macro F1', value: '0.78' },
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
    kind: 'self-consistency',
    blurb:
      "The simulator wraps each incident's description in a Markdown report; the judge then looks for evidence keywords drawn from that same description. Close to a string-copy tautology — it confirms the report template includes the description and the judge can find keywords inside it. Catches template breakage, not LLM quality.",
    details: [
      { label: 'Incidents', value: '200' },
      { label: 'Fully covered', value: '134 (67%)' },
      { label: 'Judge', value: 'Offline keyword' },
    ],
  },
  {
    id: 'response_quality',
    name: 'Response-plan quality',
    metric: 'Mean rubric score',
    value: 1.0,
    display: '100%',
    target: 0.8,
    targetDisplay: '≥80%',
    kind: 'self-consistency',
    blurb:
      "The synthesizer embeds the expected MITRE techniques and first evidence keyword directly into the templated plan, then a 5-criterion rubric checks for them. By construction the score is ~1.000. Catches a broken templating pipeline; it is not a grade of LLM-written plans.",
    details: [
      { label: 'Incidents', value: '200' },
      { label: 'Criteria', value: '5 (all hit by template)' },
      { label: 'Judge', value: 'Offline keyword' },
    ],
  },
];

const KIND_LABEL: Record<Kind, { label: string; classes: string }> = {
  measurement: {
    label: 'Real measurement',
    classes:
      'border-emerald-500/30 bg-emerald-500/10 text-emerald-200',
  },
  'self-consistency': {
    label: 'Substrate self-consistency',
    classes: 'border-amber-500/30 bg-amber-500/10 text-amber-200',
  },
};

export function BenchmarkResults() {
  return (
    <div className="grid gap-4 md:grid-cols-2">
      {SUITES.map((suite) => {
        const passed = suite.value >= suite.target;
        const headroom = ((suite.value - suite.target) * 100).toFixed(1);
        const kind = KIND_LABEL[suite.kind];
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

            <span
              className={clsx(
                'mt-4 inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider',
                kind.classes,
              )}
            >
              {kind.label}
            </span>

            <p className="mt-3 text-sm leading-relaxed text-gray-400">
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
