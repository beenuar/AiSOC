import type { Metadata } from 'next';
import Link from 'next/link';
import { LandingNav } from '@/components/landing/LandingNav';
import { Footer } from '@/components/landing/Footer';
import { BenchmarkResults } from '@/components/benchmark/BenchmarkResults';
import { ComparisonTable } from '@/components/benchmark/ComparisonTable';

export const metadata: Metadata = {
  title: 'Public Benchmark — AiSOC',
  description:
    "AiSOC's open, reproducible Pillar-1 evaluation suite. 200 deterministic incidents, four eval gates, every number measurable on your laptop in seconds.",
  alternates: { canonical: '/benchmark' },
  openGraph: {
    title: 'AiSOC Public Benchmark',
    description:
      'The only AI SOC where the agent accuracy is published, reproducible, and auditable. 200-incident benchmark, four CI-gated suites, all numbers in the open.',
    type: 'article',
  },
};

const REPRODUCE_SNIPPET = `git clone https://github.com/cyble-inc/AiSOC && cd AiSOC
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
            Public benchmark
          </h1>
          <p className="mt-4 max-w-3xl text-lg text-gray-400">
            The only AI SOC where the agent's accuracy is{' '}
            <span className="text-white">published, reproducible, and auditable</span>.
            Closed-source vendors publish marketing claims. AiSOC publishes the
            benchmark, the dataset, the harness, and the CI gate. You can reproduce
            every number on this page in under 10 seconds on a laptop.
          </p>

          <div className="mt-8 flex flex-wrap gap-3">
            <a
              href="https://github.com/cyble-inc/AiSOC/blob/main/services/agents/tests/eval_data/synthetic_incidents.json"
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
              href="https://github.com/cyble-inc/AiSOC/tree/main/services/agents/tests"
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
              href="https://github.com/cyble-inc/AiSOC/actions/workflows/ci.yml"
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
            Four metrics, four CI gates. Every gate is a hard fail in CI — a
            regression blocks the build. The numbers below are pulled from the
            most recent successful run on <code className="text-gray-300">main</code>.
          </p>
          <div className="mt-8">
            <BenchmarkResults />
          </div>
        </div>
      </section>

      <section className="px-6 pb-20">
        <div className="mx-auto max-w-4xl rounded-2xl border border-white/10 bg-white/[0.02] p-8">
          <h2 className="text-2xl font-semibold tracking-tight">
            Reproduce these numbers
          </h2>
          <p className="mt-2 text-sm text-gray-400">
            No Docker, no API key, no GPU, no LLM call. The benchmark harness is
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
            We measure what we ship. Where a vendor publishes a number, we cite
            it. Where a vendor doesn't, we mark it absent. No marketing math.
          </p>
          <div className="mt-6">
            <ComparisonTable />
          </div>
          <p className="mt-6 max-w-3xl text-sm text-gray-500">
            <strong className="text-gray-300">Why this matters: </strong>
            a regulated bank cannot deploy a vendor whose agent is a black-box
            cloud service. They can deploy AiSOC. Their auditor reviews the same
            dataset, the same harness, and the same CI numbers we publish here.
          </p>
        </div>
      </section>

      <section className="px-6 pb-20">
        <div className="mx-auto max-w-4xl">
          <h2 className="text-2xl font-semibold tracking-tight">What this is not</h2>
          <p className="mt-2 text-sm text-gray-400">
            We're allergic to overclaiming. A few honest caveats up front:
          </p>
          <ul className="mt-5 space-y-3 text-sm text-gray-400">
            <li className="rounded-lg border border-white/5 bg-white/[0.02] p-4">
              <strong className="text-gray-200">The harness is offline.</strong>{' '}
              It uses deterministic extractors and templated synthesis — not the
              live LLM pipeline. We do this so the gate is fast and cheap enough
              to run on every commit. A nightly online eval (LLM-as-judge,
              full agent orchestrator) is on the Phase-1 roadmap.
            </li>
            <li className="rounded-lg border border-white/5 bg-white/[0.02] p-4">
              <strong className="text-gray-200">The dataset is synthetic.</strong>{' '}
              200 incidents flag major regressions but don't claim production
              parity. Real customer benchmarks will be opt-in and federated.
            </li>
            <li className="rounded-lg border border-white/5 bg-white/[0.02] p-4">
              <strong className="text-gray-200">The judge is keyword-based.</strong>{' '}
              It can be gamed by template-stuffing. The full LLM-as-judge variant
              is a follow-up. The keyword judge nonetheless catches the most
              common failure modes (omitted evidence, mis-aligned containment
              action, severity drift).
            </li>
          </ul>
        </div>
      </section>

      <section className="px-6 pb-24">
        <div className="mx-auto max-w-4xl rounded-2xl border border-brand-500/20 bg-gradient-to-br from-brand-500/10 to-transparent p-8 text-center">
          <h2 className="text-2xl font-semibold tracking-tight">
            Help us move the numbers
          </h2>
          <p className="mx-auto mt-3 max-w-2xl text-sm text-gray-400">
            Find a tactic the extractor misses, a fusion miss, or a rubric weakness?
            File a PR with a fixture and the gate will lock the regression in for
            everyone forever.
          </p>
          <div className="mt-6 flex flex-wrap justify-center gap-3">
            <a
              href="https://github.com/cyble-inc/AiSOC/blob/main/CONTRIBUTING.md"
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
