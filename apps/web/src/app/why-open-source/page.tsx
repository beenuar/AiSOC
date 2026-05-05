import type { Metadata } from 'next';
import Link from 'next/link';
import { LandingNav } from '@/components/landing/LandingNav';
import { Footer } from '@/components/landing/Footer';

export const metadata: Metadata = {
  title: 'Why AiSOC is open source',
  description:
    'AiSOC is MIT-licensed and self-hostable, with the agent loop and prompt templates in the repo. This page explains why that posture matters for regulated buyers and what the trade-offs are.',
  alternates: { canonical: '/why-open-source' },
  openGraph: {
    title: 'Why AiSOC is open source — AiSOC',
    description:
      'AiSOC is MIT-licensed and self-hostable. The agent loop and prompts are in the repo, and a 200-incident eval harness runs in CI.',
    type: 'article',
  },
};

const PILLARS = [
  {
    label: 'Investigation Ledger',
    href: 'https://github.com/beenuar/AiSOC#investigation-ledger',
    body: 'Every prompt, tool call, evidence citation, and decision the agent emits is written to a durable, queryable, replayable ledger. The ledger stores the literal LLM input and output, not a summary.',
  },
  {
    label: 'Public eval harness',
    href: '/benchmark',
    body: 'A 200-incident eval suite runs on every PR targeting main / develop. Four CI gates: one real measurement (alert reduction, against a separately generated 1,000-alert noisy stream) and three substrate self-consistency checks (MITRE tactic, completeness, response quality, against the 200-incident dataset). The harness, the dataset, the rubric, and historical results are in the repo. The benchmark page documents what each metric measures and what it does not.',
  },
  {
    label: 'MIT, end-to-end',
    href: 'https://github.com/beenuar/AiSOC/blob/main/LICENSE',
    body: 'No CLA, no SSPL, no BSL conversion clause, no open-core with the agent in a private repo. The licence permits audit, fork, air-gapped deployment, and building a competing product.',
  },
] as const;

const ARTEFACTS = [
  {
    title: 'A per-investigation event stream',
    body: 'Each investigation can be exported as a JSON event stream listing the steps the agent took: prompts issued, models used, tokens spent, evidence rows cited, and actions executed, in order, with hashes. An auditor reads the events directly rather than relying on a vendor summary.',
  },
  {
    title: 'A reproducible eval harness',
    body: 'Cloning the repo and running `python3 scripts/run_evals.py` produces the same alert-reduction ratio, MITRE-tactic gate, completeness coverage, and response-quality score that the CI gate produces. The benchmark page documents which numbers are real measurements of the substrate and which are self-consistency gates that would need an online LLM-as-judge run to be called agent accuracy.',
  },
  {
    title: 'Source code for the agent',
    body: 'The orchestrator, planner, prompt templates, tool registry, response policy, and rubric — the components that reason over incident data — are in this repo under MIT. They can be diffed, patched, and shipped as a fork.',
  },
] as const;

type Contrast = {
  label: string;
  points: readonly string[];
  accent?: boolean;
};

const CONTRASTS: readonly Contrast[] = [
  {
    label: 'Closed-source AI SOC vendor',
    points: [
      'Agent runs in vendor cloud. Incident data leaves the buyer network for inference.',
      'Prompts and policy are proprietary. Buyers cannot audit how the agent reasons or what it tells the model about a case.',
      'Accuracy claims come from internal evaluation. No reproducible eval harness, no public CI gate, no historical regression record.',
      'No fork right. Model, policy, and pricing changes are vendor-controlled.',
    ],
  },
  {
    label: 'Open-core with proprietary agent',
    points: [
      'The dashboard is open. The agent component is in a private repo.',
      'License is typically SSPL or BSL with a CLA, which permits future relicensing of the project.',
      'The eval harness is internal. The score is published; the dataset and rubric are not.',
      'Self-hosting is permitted on paper but typically supported only for the open shell, not the agent.',
    ],
  },
  {
    label: 'AiSOC',
    points: [
      'Agent runs on the buyer infrastructure. Incident data, by default, does not leave the buyer network.',
      'Every prompt, response, tool call, and decision is written to the Investigation Ledger and replayable per case.',
      'Substrate behaviour is gated in CI on every PR targeting main / develop. The dataset, harness, rubric, and historical numbers are in the repo and reproducible. The benchmark page is explicit about which metrics measure the substrate and which would need an online LLM-as-judge run to be called agent accuracy.',
      'MIT, no CLA. Forks are permanent.',
    ],
    accent: true,
  },
];

const NON_REGULATED_REASONS = [
  {
    title: 'Operator agency over the agent',
    body: 'If a hosted LLM provider changes a model and detection behaviour shifts, the operator decides whether to ship the change. With a closed agent, that decision is made by the vendor.',
  },
  {
    title: 'License is permanent',
    body: 'MIT means a deployed version stays available indefinitely. No relicensing event, no new tier gating existing features, no community-edition deprecation. Pinning a commit gives operational independence.',
  },
  {
    title: 'Plugins are source code',
    body: 'Plugins, detections, playbooks, and prompts are source code in the same repo. A Python or Go plugin written against the typed SDK ships with the rest of the stack.',
  },
] as const;

export default function WhyOpenSourcePage() {
  return (
    <main className="relative min-h-screen overflow-x-hidden bg-surface-base text-white">
      <LandingNav />

      <section className="relative px-6 pt-32 pb-16">
        <div className="mx-auto max-w-3xl">
          <div className="mb-3 flex items-center gap-2">
            <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-3 py-1 text-xs font-medium text-emerald-300">
              MIT-licensed
            </span>
            <span className="text-xs text-gray-500">~7 min read</span>
          </div>
          <h1 className="text-4xl font-bold tracking-tight md:text-5xl">
            Why AiSOC is open source.
          </h1>
          <p className="mt-5 text-lg leading-relaxed text-gray-400">
            AiSOC is MIT-licensed and self-hostable. The agent loop, prompt
            templates, and eval harness are in this repo. This page describes
            what that posture means in practice — for buyers in regulated
            industries and for everyone else — and is explicit about the
            trade-offs.
          </p>
        </div>
      </section>

      <section className="px-6 pb-16">
        <div className="mx-auto max-w-3xl space-y-6 text-base leading-relaxed text-gray-300">
          <h2 className="pt-2 text-2xl font-semibold tracking-tight text-white">
            The compliance problem with closed-source AI SOCs
          </h2>
          <p>
            Closed-source AI SOC products typically ask a regulated buyer to
            accept three things at once: incident data leaves the buyer
            network for inference in vendor cloud, the agent prompts and
            policy are not visible outside the vendor, and the accuracy
            numbers cannot be reproduced by the buyer or their auditor.
          </p>
          <p>
            The third item is the one that compounds the other two. A number
            that the buyer cannot reproduce is hard to defend in a SOC 2,
            ISO 27001, or DORA review. In practice this often results in the
            AI SOC being deployed for non-regulated tenants and a manual
            triage queue being kept for regulated ones.
          </p>
          <p>
            AiSOC takes the opposite approach: the agent is in the repo, the
            substrate eval is a CI gate, data stays in the buyer network by
            default, and the MIT licence is permanent.
          </p>
        </div>
      </section>

      <section className="px-6 pb-16">
        <div className="mx-auto max-w-5xl">
          <h2 className="text-2xl font-semibold tracking-tight">
            What auditable means in this project
          </h2>
          <p className="mt-3 max-w-3xl text-sm text-gray-400">
            Three concrete artefacts the project ships. Each one corresponds
            to a question a regulated buyer or their auditor will ask.
          </p>
          <div className="mt-8 grid gap-4 md:grid-cols-3">
            {PILLARS.map((p) => {
              const external = p.href.startsWith('http');
              const Inner = (
                <div className="group h-full rounded-2xl border border-white/10 bg-white/[0.02] p-6 transition hover:border-white/20 hover:bg-white/[0.04]">
                  <div className="text-xs font-semibold uppercase tracking-wider text-emerald-300">
                    {p.label}
                  </div>
                  <p className="mt-3 text-sm leading-relaxed text-gray-300">
                    {p.body}
                  </p>
                  <div className="mt-4 inline-flex items-center gap-1 text-xs font-medium text-gray-400 group-hover:text-white">
                    Open
                    <svg
                      viewBox="0 0 20 20"
                      className="h-3 w-3"
                      fill="currentColor"
                      aria-hidden="true"
                    >
                      <path d="M5.22 14.78a.75.75 0 001.06 0l7.22-7.22v3.69a.75.75 0 001.5 0v-5.5a.75.75 0 00-.75-.75h-5.5a.75.75 0 000 1.5h3.69L5.22 13.72a.75.75 0 000 1.06z" />
                    </svg>
                  </div>
                </div>
              );
              return external ? (
                <a key={p.label} href={p.href} target="_blank" rel="noreferrer">
                  {Inner}
                </a>
              ) : (
                <Link key={p.label} href={p.href}>
                  {Inner}
                </Link>
              );
            })}
          </div>
        </div>
      </section>

      <section className="px-6 pb-16">
        <div className="mx-auto max-w-3xl space-y-6 text-base leading-relaxed text-gray-300">
          <h2 className="pt-2 text-2xl font-semibold tracking-tight text-white">
            Three artefacts an auditor can review
          </h2>
          <p>
            Every other claim on this page reduces to one of these. If the
            three are not reviewable on day one of a deployment review, the
            agent is not actually auditable end-to-end.
          </p>
          <div className="mt-2 space-y-3">
            {ARTEFACTS.map((a, i) => (
              <div
                key={a.title}
                className="rounded-2xl border border-white/10 bg-white/[0.02] p-6"
              >
                <div className="flex items-start gap-4">
                  <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-white/10 bg-white/5 font-mono text-sm text-gray-300">
                    {String(i + 1).padStart(2, '0')}
                  </div>
                  <div>
                    <h3 className="text-base font-semibold text-white">
                      {a.title}
                    </h3>
                    <p className="mt-2 text-sm leading-relaxed text-gray-400">
                      {a.body}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="px-6 pb-16">
        <div className="mx-auto max-w-5xl">
          <h2 className="text-2xl font-semibold tracking-tight">
            How AiSOC differs from the common patterns
          </h2>
          <p className="mt-3 max-w-3xl text-sm text-gray-400">
            The two non-AiSOC columns describe common patterns in the AI SOC
            market, not specific vendors. Counter-examples are welcome via
            issue or pull request.
          </p>
          <div className="mt-8 grid gap-4 lg:grid-cols-3">
            {CONTRASTS.map((c) => (
              <div
                key={c.label}
                className={
                  c.accent
                    ? 'rounded-2xl border border-brand-500/30 bg-brand-500/[0.06] p-6'
                    : 'rounded-2xl border border-white/10 bg-white/[0.02] p-6'
                }
              >
                <div
                  className={
                    c.accent
                      ? 'text-xs font-semibold uppercase tracking-wider text-brand-300'
                      : 'text-xs font-semibold uppercase tracking-wider text-gray-500'
                  }
                >
                  {c.label}
                </div>
                <ul className="mt-4 space-y-2.5 text-sm leading-relaxed text-gray-300">
                  {c.points.map((pt) => (
                    <li key={pt} className="flex gap-2">
                      <span
                        className={
                          c.accent
                            ? 'mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-brand-400'
                            : 'mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-gray-500'
                        }
                      />
                      <span>{pt}</span>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="px-6 pb-16">
        <div className="mx-auto max-w-3xl space-y-6 text-base leading-relaxed text-gray-300">
          <h2 className="pt-2 text-2xl font-semibold tracking-tight text-white">
            What the licence does and does not allow
          </h2>
          <p>
            Open source is overloaded as a term. AiSOC ships under MIT with no
            CLA, and the project commitment is to keep the core under MIT.
            What that means in practice:
          </p>
          <ul className="space-y-3">
            <li className="rounded-lg border border-white/5 bg-white/[0.02] p-4">
              <span className="font-semibold text-gray-200">No CLA.</span>{' '}
              Contributors keep copyright on their patches. The project does
              not collect an irrevocable licence to relicense under SSPL,
              BSL, or a proprietary EULA at a later date.
            </li>
            <li className="rounded-lg border border-white/5 bg-white/[0.02] p-4">
              <span className="font-semibold text-gray-200">No telemetry.</span>{' '}
              Self-hosted deployments emit no analytics back to the project.
              The only network calls AiSOC initiates are the ones the
              operator configured (LLM provider, threat intelligence feed,
              integrations).
            </li>
            <li className="rounded-lg border border-white/5 bg-white/[0.02] p-4">
              <span className="font-semibold text-gray-200">
                The agent is in the open repo.
              </span>{' '}
              The orchestrator, planner, prompt templates, tool registry,
              response policy, and rubric — the components that reason over
              incident data — are in this repo. There is no separate
              enterprise agent.
            </li>
            <li className="rounded-lg border border-white/5 bg-white/[0.02] p-4">
              <span className="font-semibold text-gray-200">
                Fork rights are permanent.
              </span>{' '}
              If a future release changes a model choice, default policy, or
              UX in a way an operator does not want, the previous commit
              remains a valid deployment.
            </li>
          </ul>
        </div>
      </section>

      <section className="px-6 pb-16">
        <div className="mx-auto max-w-5xl">
          <h2 className="text-2xl font-semibold tracking-tight">
            Reasons that apply outside regulated environments
          </h2>
          <p className="mt-3 max-w-3xl text-sm text-gray-400">
            The compliance story is the most legible reason to choose an
            auditable, MIT-licensed agent, but the same structural properties
            apply to teams that are not in a regulated industry.
          </p>
          <div className="mt-8 grid gap-4 md:grid-cols-3">
            {NON_REGULATED_REASONS.map((r) => (
              <div
                key={r.title}
                className="rounded-2xl border border-white/10 bg-white/[0.02] p-6"
              >
                <h3 className="text-base font-semibold text-white">
                  {r.title}
                </h3>
                <p className="mt-3 text-sm leading-relaxed text-gray-400">
                  {r.body}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="px-6 pb-16">
        <div className="mx-auto max-w-3xl space-y-6 text-base leading-relaxed text-gray-300">
          <h2 className="pt-2 text-2xl font-semibold tracking-tight text-white">
            Trade-offs and limitations
          </h2>
          <p>
            A few things this project is explicit about:
          </p>
          <ul className="space-y-3">
            <li className="rounded-lg border border-white/5 bg-white/[0.02] p-4">
              <span className="font-semibold text-gray-200">
                AiSOC does not claim better agent accuracy than every vendor.
              </span>{' '}
              The project ships a public, reproducible eval harness over the
              substrate. The{' '}
              <Link href="/benchmark" className="text-brand-300 underline">
                eval harness page
              </Link>{' '}
              is explicit about which metrics measure real substrate
              behaviour (alert reduction) and which are substrate
              self-consistency gates (MITRE tactic, completeness, response
              quality). The relevant property is that the harness exists and
              is reproducible, not that any specific number beats a vendor
              claim.
            </li>
            <li className="rounded-lg border border-white/5 bg-white/[0.02] p-4">
              <span className="font-semibold text-gray-200">
                Self-hosting has an operational cost.
              </span>{' '}
              Operators run Postgres, Redis, ClickHouse, and an LLM endpoint.
              The{' '}
              <code className="text-gray-300">pnpm aisoc:demo</code> command
              and one-click deploy buttons shorten the on-ramp, but the
              stack is operated by the deployer.
            </li>
            <li className="rounded-lg border border-white/5 bg-white/[0.02] p-4">
              <span className="font-semibold text-gray-200">
                Bring-your-own LLM means bring-your-own trust boundary.
              </span>{' '}
              The agent sends prompts to whichever LLM endpoint is
              configured. The Investigation Ledger logs every prompt, so
              what leaves the network is auditable, but the trust boundary
              is the configured LLM provider, not AiSOC. A future
              local-inference mode is on the roadmap.
            </li>
          </ul>
        </div>
      </section>

      <section className="px-6 pb-24">
        <div className="mx-auto max-w-4xl rounded-2xl border border-brand-500/20 bg-surface-card p-8 text-center">
          <h2 className="text-2xl font-semibold tracking-tight">
            Verify it directly
          </h2>
          <p className="mx-auto mt-3 max-w-2xl text-sm text-gray-400">
            Three artefacts, each reproducible in under a minute: a
            pre-seeded investigation with the ledger visible, the eval
            harness on a local machine, and the agent source on GitHub.
            None require a signup.
          </p>
          <div className="mt-6 flex flex-wrap justify-center gap-3">
            <a
              href="https://tryaisoc.com/cases/INC-001?tab=ledger"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-2 rounded-md bg-brand-500 px-4 py-2 text-sm font-semibold text-white transition hover:bg-brand-400"
            >
              Open the demo
              <svg
                viewBox="0 0 20 20"
                className="h-3.5 w-3.5"
                fill="currentColor"
                aria-hidden="true"
              >
                <path d="M5.22 14.78a.75.75 0 001.06 0l7.22-7.22v3.69a.75.75 0 001.5 0v-5.5a.75.75 0 00-.75-.75h-5.5a.75.75 0 000 1.5h3.69L5.22 13.72a.75.75 0 000 1.06z" />
              </svg>
            </a>
            <Link
              href="/benchmark"
              className="inline-flex items-center gap-2 rounded-md border border-white/10 bg-white/[0.03] px-4 py-2 text-sm font-medium text-gray-300 transition hover:border-white/20 hover:bg-white/[0.06] hover:text-white"
            >
              Read the eval harness
            </Link>
            <a
              href="https://github.com/beenuar/AiSOC"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-2 rounded-md border border-white/10 bg-white/[0.03] px-4 py-2 text-sm font-medium text-gray-300 transition hover:border-white/20 hover:bg-white/[0.06] hover:text-white"
            >
              View the agent source
            </a>
          </div>
        </div>
      </section>

      <Footer />
    </main>
  );
}
