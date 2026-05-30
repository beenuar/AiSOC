import type { Metadata } from 'next';
import Link from 'next/link';
import { LandingNav } from '@/components/landing/LandingNav';
import { Footer } from '@/components/landing/Footer';
import {
  BenchmarkResults,
  fetchLatestEvalReport,
} from '@/components/benchmark/BenchmarkResults';
import { ComparisonTable } from '@/components/benchmark/ComparisonTable';
import { KpiBar } from '@/components/benchmark/KpiBar';
import { CommunitySubmissions } from '@/components/benchmark/CommunitySubmissions';
import { docs } from '@/lib/docs';

export const metadata: Metadata = {
  title: 'Public benchmark scoreboard',
  description:
    'A reproducible regression harness over the AiSOC substrate. Four CI gates over a 200-incident synthetic dataset (MITRE / completeness / response quality) plus a 1,000-alert noisy stream (alert reduction). Per-template macros, per-case means, alert-reduction %, the 2026 KPI bar, and a fixed-dataset community leaderboard. The page documents what each metric measures and what it does not.',
  alternates: { canonical: '/benchmark' },
  openGraph: {
    title: 'AiSOC public benchmark scoreboard',
    description:
      'Regression-gate harness over the AiSOC substrate plus a fixed-dataset community leaderboard. Open dataset, open harness, CI-enforced.',
    type: 'article',
  },
};

const REPRODUCE_SNIPPET = `git clone https://github.com/beenuar/AiSOC && cd AiSOC
python3 scripts/run_evals.py --json --out report.json`;

function fmtPct(value: number | undefined, digits = 1): string {
  if (typeof value !== 'number') return 'n/a';
  return `${(value * 100).toFixed(digits)}%`;
}

function fmtScore(value: number | undefined, digits = 3): string {
  if (typeof value !== 'number') return 'n/a';
  return value.toFixed(digits);
}

function generatedAtLabel(iso: string | undefined): string {
  if (!iso) return 'unknown';
  try {
    const d = new Date(iso);
    return `${d.toISOString().slice(0, 16).replace('T', ' ')} UTC`;
  } catch {
    return iso;
  }
}

export default async function BenchmarkPage() {
  const report = await fetchLatestEvalReport();
  const ar = report.suites.alert_reduction;
  const mt = report.suites.mitre_accuracy;
  const ic = report.suites.investigation_completeness;
  const rq = report.suites.response_quality;
  const expectedOutput = `============================================================================
  AiSOC Pillar-1 Eval - 200-incident synthetic benchmark
============================================================================
  [${mt?.passed ? 'PASS' : 'FAIL'}] mitre_accuracy               accuracy               ${fmtScore(mt?.value)}  (target >= ${fmtScore(mt?.target, 2)})
  [${ar?.passed ? 'PASS' : 'FAIL'}] alert_reduction              reduction_ratio        ${fmtScore(ar?.value)}  (target >= ${fmtScore(ar?.target, 2)})
  [${ic?.passed ? 'PASS' : 'FAIL'}] investigation_completeness   mean_keyword_coverage  ${fmtScore(ic?.value)}  (target >= ${fmtScore(ic?.target, 2)})
  [${rq?.passed ? 'PASS' : 'FAIL'}] response_quality             mean_rubric_score      ${fmtScore(rq?.value)}  (target >= ${fmtScore(rq?.target, 2)})
============================================================================
  ${report.all_passed ? 'ALL GATES PASSED' : 'ONE OR MORE GATES FAILED'}`;

  return (
    <main className="relative min-h-screen overflow-x-hidden bg-surface-base text-white">
      <LandingNav />

      <section className="relative px-6 pt-32 pb-20">
        <div className="mx-auto max-w-4xl">
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-3 py-1 text-xs font-medium text-emerald-300">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
              Reproducible
            </span>
            {report._stale ? (
              <span className="inline-flex items-center gap-1.5 rounded-full border border-amber-500/30 bg-amber-500/10 px-3 py-1 text-xs font-medium text-amber-200">
                <span className="h-1.5 w-1.5 rounded-full bg-amber-400" />
                Snapshot fallback
              </span>
            ) : (
              <span className="inline-flex items-center gap-1.5 rounded-full border border-brand-500/30 bg-brand-500/10 px-3 py-1 text-xs font-medium text-brand-300">
                <span className="h-1.5 w-1.5 rounded-full bg-brand-400" />
                Live from main
              </span>
            )}
            <span className="text-xs text-gray-500">
              Last run {generatedAtLabel(report.generated_at)} · refreshes every push
            </span>
          </div>
          <h1 className="text-4xl font-bold tracking-tight md:text-5xl">
            Public benchmark scoreboard
          </h1>
          <p className="mt-4 max-w-3xl text-lg text-gray-400">
            A deterministic regression harness over the AiSOC substrate &mdash;
            the keyword extractors, the in-harness fusion grouping (a faithful
            re-implementation of the production Tier 1/2/3 logic in{' '}
            <code className="text-gray-300">services/fusion</code>, minus the
            DB-backed dedup and ML scoring), the report and response
            templates, and the offline judges that grade them. The dataset,
            the harness, and the CI gate are in the repo. The numbers on this
            page are pulled from{' '}
            <code className="text-gray-300">eval/results/latest.json</code> on
            the <code className="text-gray-300">eval-results</code> branch
            and refresh on every push to <code className="text-gray-300">main</code>.
          </p>

          <div className="mt-5 max-w-3xl rounded-lg border border-amber-500/20 bg-amber-500/[0.04] p-4 text-sm text-amber-100/80">
            <span className="font-semibold text-amber-200">Read this first:</span>{' '}
            the harness does not exercise the live LLM agent. It runs
            deterministic substrate code against synthetic data so the CI gate
            can run in milliseconds. Three of the four metrics measure internal
            consistency of that substrate, not agent accuracy. The sections
            below describe what each suite measures and what it does not.
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
              className="inline-flex items-center gap-2 rounded-md bg-brand-500 px-4 py-2 text-sm font-semibold text-white transition hover:bg-brand-400"
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
          <p className="mt-4 text-xs text-gray-500">
            This page is the live snapshot of the latest CI run. For the
            append-only weekly history (substrate and wet-eval rows side-by-side
            with a MITRE-accuracy trend chart), see the{' '}
            <a
              href={docs('benchmark')}
              target="_blank"
              rel="noreferrer"
              className="underline decoration-dotted hover:text-gray-300"
            >
              public scoreboard
            </a>{' '}
            in the docs.
          </p>
        </div>
      </section>

      <section className="px-6 pb-20">
        <div className="mx-auto max-w-5xl">
          <KpiBar report={report} />
        </div>
      </section>

      <section className="px-6 pb-20">
        <div className="mx-auto max-w-5xl">
          <h2 className="text-2xl font-semibold tracking-tight">Latest results</h2>
          <p className="mt-2 max-w-3xl text-sm text-gray-400">
            Four metrics, four CI gates. A regression on any gate blocks the
            build. Each card shows the per-case mean and, where applicable, the
            per-template macro &mdash; an equal-weight average across 55
            distinct incident templates that surfaces a single weak template
            the per-case mean would mask. Numbers come from{' '}
            <code className="text-gray-300">latest.json</code> on the most
            recent successful run on <code className="text-gray-300">main</code>.
          </p>
          <div className="mt-8">
            <BenchmarkResults report={report} />
          </div>
        </div>
      </section>

      <section className="px-6 pb-20">
        <div className="mx-auto max-w-4xl">
          <h2 className="text-2xl font-semibold tracking-tight">
            What each suite measures
          </h2>
          <div className="mt-6 space-y-4 text-sm">
            <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/[0.03] p-5">
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="text-base font-semibold text-white">
                  Alert reduction ({fmtPct(ar?.value)})
                </h3>
                <span className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-emerald-200">
                  Real measurement
                </span>
              </div>
              <p className="mt-2 text-gray-300">
                A 1,000-alert noisy stream with duplicates, near-duplicates,
                rule-storms, and benign chatter is fabricated deterministically,
                then passed through{' '}
                <code className="text-gray-300">fuse_alerts</code> &mdash; an
                in-harness re-implementation of the same Tier 1 / 2 / 3 merge
                windows and score floor that the production fusion service
                runs. The grouping logic is identical; the harness skips the
                DB-backed deduplicator and ML scorer that ride on top in
                production. The reduction ratio is whatever the harness code
                emits. This is a legitimate measurement of the grouping logic,
                and a regression in those rules will move the number.
              </p>
            </div>

            <div className="rounded-lg border border-amber-500/20 bg-amber-500/[0.03] p-5">
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="text-base font-semibold text-white">
                  MITRE tactic accuracy ({fmtPct(mt?.value)})
                </h3>
                <span className="rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-amber-200">
                  Substrate self-consistency
                </span>
              </div>
              <p className="mt-2 text-gray-300">
                Each synthetic incident is generated with a tactic label, and
                its description is written to include keywords that the
                hand-curated extractor recognises. The 97% is therefore largely
                a check that the dataset and the extractor agree with each
                other, not a measure of LLM-agent accuracy. The gate still has
                value as a regression sentinel: a misnamed tactic, a typo in
                the keyword table, or a lost tactic will fail it.
              </p>
            </div>

            <div className="rounded-lg border border-amber-500/20 bg-amber-500/[0.03] p-5">
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="text-base font-semibold text-white">
                  Investigation completeness ({fmtPct(ic?.value)})
                </h3>
                <span className="rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-amber-200">
                  Substrate self-consistency
                </span>
              </div>
              <p className="mt-2 text-gray-300">
                The simulator wraps the incident description in a Markdown
                report, and the judge looks for evidence keywords inside it.
                Those evidence keywords are drawn from the description, so the
                gate confirms that the report template includes the description
                and that the judge can find the keywords. It catches drops in
                the report template (for example a missing Summary section)
                but does not grade an LLM-written investigation.
              </p>
            </div>

            <div className="rounded-lg border border-amber-500/20 bg-amber-500/[0.03] p-5">
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="text-base font-semibold text-white">
                  Response-plan quality ({fmtScore(rq?.value)})
                </h3>
                <span className="rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-amber-200">
                  Substrate self-consistency
                </span>
              </div>
              <p className="mt-2 text-gray-300">
                The synthesiser embeds the expected MITRE techniques and the
                first evidence keyword directly into the templated plan, and
                the rubric judge checks for them. The score is ~1.000 by
                construction. This catches a broken templating pipeline (for
                example, the synthesiser silently dropping an action class) but
                is not a grade of LLM output. The 1.000 is a green
                regression-gate signal, not a quality measurement.
              </p>
            </div>
          </div>
          <p className="mt-6 max-w-3xl text-sm text-gray-500">
            The next milestone is an online eval: nightly runs that drive the
            real LangGraph agent against the same dataset, with an
            LLM-as-judge gated by{' '}
            <code className="text-gray-300">OPENAI_API_KEY</code>. That is the
            run where actual agent accuracy is measured. Tracking issue:{' '}
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
            <code>{expectedOutput}</code>
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
            Comparison to other AI SOC offerings
          </h2>
          <p className="mt-2 max-w-3xl text-sm text-gray-400">
            Where a vendor publishes a number or a verifiable capability, it
            is cited. Where a vendor does not, the row is marked absent.
          </p>
          <div className="mt-6">
            <ComparisonTable />
          </div>
          <p className="mt-6 max-w-3xl text-sm text-gray-500">
            A self-hostable, MIT-licensed agent with a published regression
            harness can be reviewed directly by an auditor. Vendor cloud
            agents typically cannot be reviewed at the same level.
          </p>
        </div>
      </section>

      <section className="px-6 pb-20">
        <div className="mx-auto max-w-4xl">
          <h2 className="text-2xl font-semibold tracking-tight">What this is not</h2>
          <ul className="mt-5 space-y-3 text-sm text-gray-400">
            <li className="rounded-lg border border-white/5 bg-white/[0.02] p-4">
              <span className="font-semibold text-gray-200">No LLM agent runs here.</span>{' '}
              The harness exercises deterministic substrate code: extractors,
              fusion, templates, and keyword judges. The live LangGraph
              orchestrator (<code className="text-gray-300">services/agents/app/investigator/</code>)
              is not invoked. An online eval that drives it nightly is on the
              roadmap.
            </li>
            <li className="rounded-lg border border-white/5 bg-white/[0.02] p-4">
              <span className="font-semibold text-gray-200">The dataset is synthetic.</span>{' '}
              200 incidents are enough to flag substrate regressions but not
              enough to claim production parity. Federated, opt-in
              real-customer evaluation is on the roadmap.
            </li>
            <li className="rounded-lg border border-white/5 bg-white/[0.02] p-4">
              <span className="font-semibold text-gray-200">The judges are keyword-based.</span>{' '}
              They can be gamed by template-stuffing. In three of the four
              suites the templates already include the keywords the judge
              looks for, which is why those suites are labelled substrate
              self-consistency rather than agent quality. The LLM-as-judge
              variant is the follow-up.
            </li>
            <li className="rounded-lg border border-white/5 bg-white/[0.02] p-4">
              <span className="font-semibold text-gray-200">
                &ldquo;Public eval harness&rdquo; means this harness, not a
                third-party leaderboard.
              </span>{' '}
              No outside body grades AiSOC. The dataset, the code, and the
              gates are open and CI-enforced, and anyone can run, audit, or
              extend the harness.
            </li>
          </ul>
        </div>
      </section>

      <section className="px-6 pb-20">
        <div className="mx-auto max-w-5xl">
          <CommunitySubmissions />
        </div>
      </section>

      <section className="px-6 pb-24">
        <div className="mx-auto max-w-4xl rounded-2xl border border-brand-500/20 bg-surface-card p-8 text-center">
          <h2 className="text-2xl font-semibold tracking-tight">
            Contributing to the harness
          </h2>
          <p className="mx-auto mt-3 max-w-2xl text-sm text-gray-400">
            New fixtures for missed tactics or fusion edge cases, replacements
            for tautological judges, and the online LLM-as-judge variant are
            all in scope for contributions.
          </p>
          <div className="mt-6 flex flex-wrap justify-center gap-3">
            <a
              href={docs('contributing/guidelines')}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-2 rounded-md bg-brand-500 px-4 py-2 text-sm font-semibold text-white transition hover:bg-brand-400"
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
