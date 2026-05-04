import type { Metadata } from 'next';
import Link from 'next/link';
import { LandingNav } from '@/components/landing/LandingNav';
import { Footer } from '@/components/landing/Footer';
import { BenchmarkResults } from '@/components/benchmark/BenchmarkResults';
import { ComparisonTable } from '@/components/benchmark/ComparisonTable';

export const metadata: Metadata = {
  title: 'Public Eval Harness — AiSOC',
  description:
    "AiSOC's open, reproducible regression harness. 200 deterministic synthetic incidents, four CI gates over the substrate (extractors, fusion, templates, judges). Honest about what it measures — and what it doesn't.",
  alternates: { canonical: '/benchmark' },
  openGraph: {
    title: 'AiSOC Public Eval Harness',
    description:
      'A regression-gate harness over the AiSOC substrate. Open dataset, open harness, CI-enforced. This is not an LLM-agent leaderboard, and we say so on the page.',
    type: 'article',
  },
};

const REPRODUCE_SNIPPET = `git clone https://github.com/beenuar/AiSOC && cd AiSOC
python3 scripts/run_evals.py`;

const EXPECTED_OUTPUT = `============================================================================
  AiSOC Pillar-1 Eval - 200-incident synthetic benchmark
============================================================================
  [PASS] mitre_accuracy               accuracy               0.970  (target >= 0.80)
  [PASS] alert_reduction              reduction_ratio        0.753  (target >= 0.70)
  [PASS] investigation_completeness   mean_keyword_coverage  0.943  (target >= 0.85)
  [PASS] response_quality             mean_rubric_score      1.000  (target >= 0.80)
============================================================================
  ALL GATES PASSED`;

export default function BenchmarkPage() {
  return (
    <main className="relative min-h-screen overflow-x-hidden bg-surface-base text-white">
      <LandingNav />

      <section className="relative px-6 pt-32 pb-20">
        <div className="mx-auto max-w-4xl">
          <div className="mb-3 flex items-center gap-2">
            <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-3 py-1 text-xs font-medium text-emerald-300">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
              Live, reproducible
            </span>
            <span className="text-xs text-gray-500">Updated on every commit to main</span>
          </div>
          <h1 className="text-4xl font-bold tracking-tight md:text-5xl">
            Public eval harness
          </h1>
          <p className="mt-4 max-w-3xl text-lg text-gray-400">
            An <span className="text-white">open, deterministic regression harness</span>{' '}
            over the AiSOC substrate &mdash; the keyword extractors, the fusion
            pipeline, the report and response templates, and the offline judges
            that grade them. The dataset, the harness, and the CI gate are all
            in the repo. You can reproduce every number on this page in under
            10 seconds on a laptop.
          </p>

          <div className="mt-5 max-w-3xl rounded-lg border border-amber-500/20 bg-amber-500/[0.04] p-4 text-sm text-amber-100/80">
            <strong className="text-amber-200">Read this first:</strong>{' '}
            this harness does <em>not</em> exercise the live LLM agent. It runs
            deterministic substrate code against synthetic data so we can gate
            every commit in milliseconds. Three of the four metrics measure
            <em> internal consistency </em> of that substrate, not agent
            accuracy. We explain exactly what each suite measures &mdash; and
            doesn&apos;t &mdash; below.
          </div>

          <div className="mt-8 flex flex-wrap gap-3">
            <a
              href="https://github.com/beenuar/AiSOC/blob/main/services/agents/tests/eval_data/synthetic_incidents.json"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-2 rounded-md border border-white/10 bg-white/[0.03] px-4 py-2 text-sm font-medium text-gray-300 transition hover:border-white/20 hover:bg-white/[0.06] hover:text-white"
            >
              View dataset
              <svg
                viewBox="0 0 20 20"
                className="h-3.5 w-3.5"
                fill="currentColor"
                aria-hidden="true"
              >
                <path d="M5.22 14.78a.75.75 0 001.06 0l7.22-7.22v3.69a.75.75 0 001.5 0v-5.5a.75.75 0 00-.75-.75h-5.5a.75.75 0 000 1.5h3.69L5.22 13.72a.75.75 0 000 1.06z" />
              </svg>
            </a>
            <a
              href="https://github.com/beenuar/AiSOC/tree/main/services/agents/tests"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-2 rounded-md border border-white/10 bg-white/[0.03] px-4 py-2 text-sm font-medium text-gray-300 transition hover:border-white/20 hover:bg-white/[0.06] hover:text-white"
            >
              View harness
              <svg
                viewBox="0 0 20 20"
                className="h-3.5 w-3.5"
                fill="currentColor"
                aria-hidden="true"
              >
                <path d="M5.22 14.78a.75.75 0 001.06 0l7.22-7.22v3.69a.75.75 0 001.5 0v-5.5a.75.75 0 00-.75-.75h-5.5a.75.75 0 000 1.5h3.69L5.22 13.72a.75.75 0 000 1.06z" />
              </svg>
            </a>
            <a
              href="https://github.com/beenuar/AiSOC/actions/workflows/ci.yml"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-2 rounded-md bg-brand-500 px-4 py-2 text-sm font-semibold text-white shadow-glow-sm transition hover:bg-brand-400"
            >
              Latest CI run
              <svg
                viewBox="0 0 20 20"
                className="h-3.5 w-3.5"
                fill="currentColor"
                aria-hidden="true"
              >
                <path d="M5.22 14.78a.75.75 0 001.06 0l7.22-7.22v3.69a.75.75 0 001.5 0v-5.5a.75.75 0 00-.75-.75h-5.5a.75.75 0 000 1.5h3.69L5.22 13.72a.75.75 0 000 1.06z" />
              </svg>
            </a>
          </div>
        </div>
      </section>

      <section className="px-6 pb-20">
        <div className="mx-auto max-w-5xl">
          <h2 className="text-2xl font-semibold tracking-tight">Latest results</h2>
          <p className="mt-2 max-w-3xl text-sm text-gray-400">
            Four metrics, four CI gates. Every gate is a hard fail in CI &mdash; a
            regression blocks the build. The numbers below come from the most
            recent successful run on <code className="text-gray-300">main</code>.
            Click a card for what the metric actually measures and what it does
            <em> not</em>.
          </p>
          <div className="mt-8">
            <BenchmarkResults />
          </div>
        </div>
      </section>

      <section className="px-6 pb-20">
        <div className="mx-auto max-w-4xl">
          <h2 className="text-2xl font-semibold tracking-tight">
            What each suite actually measures
          </h2>
          <p className="mt-2 max-w-3xl text-sm text-gray-400">
            We took a hard look at the harness and tightened the language so
            the marketing matches the code. Here&apos;s the honest breakdown:
          </p>
          <div className="mt-6 space-y-4 text-sm">
            <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/[0.03] p-5">
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="text-base font-semibold text-white">
                  Alert reduction (75.3%)
                </h3>
                <span className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-emerald-200">
                  Real measurement
                </span>
              </div>
              <p className="mt-2 text-gray-300">
                A 1,000-alert noisy stream with duplicates, near-duplicates,
                rule-storms, and benign chatter is fabricated deterministically,
                then passed through the actual fusion pipeline (Tier 1 / 2 / 3
                merge windows, score floor). The reduction ratio is whatever
                the real code emits. This is a legitimate measurement of the
                fusion logic, and a fusion regression will move the number.
              </p>
            </div>

            <div className="rounded-lg border border-amber-500/20 bg-amber-500/[0.03] p-5">
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="text-base font-semibold text-white">
                  MITRE tactic accuracy (97.0%)
                </h3>
                <span className="rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-amber-200">
                  Substrate self-consistency
                </span>
              </div>
              <p className="mt-2 text-gray-300">
                Each synthetic incident is generated with a tactic label, and
                its description is written to include keywords that the
                hand-curated extractor recognizes. The 97% is therefore largely
                a check that the dataset and the extractor agree with each
                other &mdash; not the accuracy of the LLM agent. It is
                <em> still useful </em>: a regression in the extractor (a
                misnamed tactic, a typo in the keyword table, a lost tactic)
                will cause the gate to fail. Treat it as a regression sentinel
                for the substrate, not a leaderboard score.
              </p>
            </div>

            <div className="rounded-lg border border-amber-500/20 bg-amber-500/[0.03] p-5">
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="text-base font-semibold text-white">
                  Investigation completeness (94.3%)
                </h3>
                <span className="rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-amber-200">
                  Substrate self-consistency
                </span>
              </div>
              <p className="mt-2 text-gray-300">
                The simulator wraps the incident description in a Markdown
                report, and the judge looks for evidence keywords inside it.
                Because those evidence keywords are drawn from the description,
                the score is close to a string-copy tautology &mdash; it
                confirms the report template includes the description, and the
                judge can find keywords in it. It catches drops in the report
                template (e.g. someone omits the Summary section) but does not
                grade an actual LLM-written investigation.
              </p>
            </div>

            <div className="rounded-lg border border-amber-500/20 bg-amber-500/[0.03] p-5">
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="text-base font-semibold text-white">
                  Response-plan quality (1.000)
                </h3>
                <span className="rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-amber-200">
                  Substrate self-consistency
                </span>
              </div>
              <p className="mt-2 text-gray-300">
                The synthesizer embeds the expected MITRE techniques and the
                first evidence keyword directly into the templated plan, then
                the rubric judge checks for them. By construction the score is
                ~1.000. This catches a broken templating pipeline (e.g. the
                synthesizer stops emitting the action class) but is not a
                grade of LLM output. We&apos;re calling it out so that
                &ldquo;1.000&rdquo; is read correctly: it&apos;s green, not
                impressive.
              </p>
            </div>
          </div>
          <p className="mt-6 max-w-3xl text-sm text-gray-500">
            The next harness milestone is <strong className="text-gray-300">
            online evals</strong>: nightly runs that drive the real LangGraph
            agent against the same dataset, with an LLM-as-judge gated by
            <code className="text-gray-300"> OPENAI_API_KEY</code>. That&apos;s
            where actual agent accuracy gets measured. Tracking issue:{' '}
            <a
              className="underline decoration-dotted hover:text-gray-300"
              href="https://github.com/beenuar/AiSOC/issues"
              target="_blank"
              rel="noreferrer"
            >
              github.com/beenuar/AiSOC/issues
            </a>.
          </p>
        </div>
      </section>

      <section className="px-6 pb-20">
        <div className="mx-auto max-w-4xl rounded-2xl border border-white/10 bg-white/[0.02] p-8">
          <h2 className="text-2xl font-semibold tracking-tight">
            Reproduce these numbers
          </h2>
          <p className="mt-2 text-sm text-gray-400">
            No Docker, no API key, no GPU, no LLM call. The harness is
            deterministic and runs in roughly 25&nbsp;ms.
          </p>
          <pre className="mt-5 overflow-x-auto rounded-lg border border-white/5 bg-black/40 p-4 text-sm leading-relaxed text-gray-200">
            <code>{REPRODUCE_SNIPPET}</code>
          </pre>
          <p className="mt-5 text-sm text-gray-400">Expected output:</p>
          <pre className="mt-2 overflow-x-auto rounded-lg border border-white/5 bg-black/40 p-4 text-xs leading-relaxed text-gray-300">
            <code>{EXPECTED_OUTPUT}</code>
          </pre>
          <p className="mt-5 text-sm text-gray-400">
            For machine-readable output, pass <code className="text-gray-300">--json</code>{' '}
            or <code className="text-gray-300">--ci --out report.json</code> (the latter
            also exits non-zero on regression).
          </p>
        </div>
      </section>

      <section className="px-6 pb-20">
        <div className="mx-auto max-w-5xl">
          <h2 className="text-2xl font-semibold tracking-tight">
            Honest comparison vs vendors
          </h2>
          <p className="mt-2 max-w-3xl text-sm text-gray-400">
            We measure what we ship and label it for what it is. Where a
            vendor publishes a number, we cite it. Where a vendor doesn&apos;t,
            we mark it absent. No marketing math.
          </p>
          <div className="mt-6">
            <ComparisonTable />
          </div>
          <p className="mt-6 max-w-3xl text-sm text-gray-500">
            <strong className="text-gray-300">Why this matters: </strong>
            a regulated bank cannot deploy a vendor whose agent is a black-box
            cloud service. They can deploy AiSOC. Their auditor reviews the
            same dataset, the same harness, and the same CI numbers we publish
            here &mdash; including this candid breakdown of which suites
            measure substrate health vs agent quality.
          </p>
        </div>
      </section>

      <section className="px-6 pb-20">
        <div className="mx-auto max-w-4xl">
          <h2 className="text-2xl font-semibold tracking-tight">What this is not</h2>
          <p className="mt-2 text-sm text-gray-400">
            We&apos;re allergic to overclaiming. A few honest caveats up front:
          </p>
          <ul className="mt-5 space-y-3 text-sm text-gray-400">
            <li className="rounded-lg border border-white/5 bg-white/[0.02] p-4">
              <strong className="text-gray-200">No LLM agent runs here.</strong>{' '}
              The harness exercises deterministic substrate code &mdash;
              extractors, fusion, templates, keyword judges. The live LangGraph
              orchestrator (<code className="text-gray-300">services/agents/app/investigator/</code>)
              is not invoked. An online eval that does invoke it nightly is on
              the Phase-1 roadmap.
            </li>
            <li className="rounded-lg border border-white/5 bg-white/[0.02] p-4">
              <strong className="text-gray-200">The dataset is synthetic.</strong>{' '}
              200 incidents flag substrate regressions but don&apos;t claim
              production parity. Real customer benchmarks will be opt-in and
              federated.
            </li>
            <li className="rounded-lg border border-white/5 bg-white/[0.02] p-4">
              <strong className="text-gray-200">The judges are keyword-based.</strong>{' '}
              They can be gamed by template-stuffing. In several suites the
              templates already include the keywords the judge looks for, so
              those suites mostly verify the templates haven&apos;t broken
              &mdash; not that an agent answered well. The full LLM-as-judge
              variant is the follow-up.
            </li>
            <li className="rounded-lg border border-white/5 bg-white/[0.02] p-4">
              <strong className="text-gray-200">
                &ldquo;Public benchmark&rdquo; means the harness, not a
                third-party leaderboard.
              </strong>{' '}
              No outside body grades AiSOC. The value is that the dataset, the
              code, and the gates are all open and CI-enforced &mdash; you can
              run, audit, and break the harness yourself.
            </li>
          </ul>
        </div>
      </section>

      <section className="px-6 pb-24">
        <div className="mx-auto max-w-4xl rounded-2xl border border-brand-500/20 bg-gradient-to-br from-brand-500/10 to-transparent p-8 text-center">
          <h2 className="text-2xl font-semibold tracking-tight">
            Help us harden the harness
          </h2>
          <p className="mx-auto mt-3 max-w-2xl text-sm text-gray-400">
            Spot a tactic the extractor misses, a fusion miss, a tautological
            judge, or a rubric weakness? File a PR with a fixture and the
            gate will lock the regression in for everyone forever &mdash; or
            help us land the online LLM-as-judge variant.
          </p>
          <div className="mt-6 flex flex-wrap justify-center gap-3">
            <a
              href="https://github.com/beenuar/AiSOC/blob/main/CONTRIBUTING.md"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-2 rounded-md bg-brand-500 px-4 py-2 text-sm font-semibold text-white shadow-glow-sm transition hover:bg-brand-400"
            >
              Contributing guide
            </a>
            <Link
              href="/"
              className="inline-flex items-center gap-2 rounded-md border border-white/10 bg-white/[0.03] px-4 py-2 text-sm font-medium text-gray-300 transition hover:border-white/20 hover:bg-white/[0.06] hover:text-white"
            >
              Back to AiSOC
            </Link>
          </div>
        </div>
      </section>

      <Footer />
    </main>
  );
}
