import type { Metadata } from 'next';
import Link from 'next/link';
import { LandingNav } from '@/components/landing/LandingNav';
import { Footer } from '@/components/landing/Footer';

export const metadata: Metadata = {
  title: 'Why open source — the AI SOC your auditor will approve',
  description:
    'A regulated bank cannot deploy a SOC whose agent is a black-box cloud service. They can deploy AiSOC. Here is the structural argument for why MIT-licensed, self-hosted, auditable AI is the only AI SOC posture that survives a compliance review.',
  alternates: { canonical: '/why-open-source' },
  openGraph: {
    title: 'The AI SOC your auditor will approve — AiSOC',
    description:
      'Why MIT-licensed, self-hosted, auditable AI is the only AI SOC posture a regulated buyer can ship. The structural argument, in writing.',
    type: 'article',
  },
};

const PILLARS = [
  {
    label: 'Investigation Ledger',
    href: 'https://github.com/beenuar/AiSOC#investigation-ledger',
    body: 'Every prompt, every tool call, every evidence citation, every decision the agent makes is written to a durable, queryable, replayable ledger. Not summarised. Not redacted. The literal LLM I/O.',
  },
  {
    label: 'Public benchmark',
    href: '/benchmark',
    body: 'A 200-incident MITRE suite runs on every commit. Four CI gates. The harness, the dataset, the rubric, and the historical results are all in the repo. Reproduce them on your laptop.',
  },
  {
    label: 'MIT, end-to-end',
    href: 'https://github.com/beenuar/AiSOC/blob/main/LICENSE',
    body: 'No CLA. No SSPL. No BSL conversion clause. No "open core" with the agent gated behind a contract. Audit it, fork it, run it air-gapped, build a competitor — the licence permits all of it.',
  },
] as const;

const ARTEFACTS = [
  {
    title: 'A signed event stream per investigation',
    body: "Hand your auditor a JSON file. They read every step the agent took, every prompt issued, every model used, every token spent, every evidence row cited, every action executed, in order, with hashes. They don't have to trust us. They read the events.",
  },
  {
    title: 'A reproducible accuracy number',
    body: 'Your auditor clones the repo and runs `python3 scripts/run_evals.py`. They get the same MITRE accuracy, alert reduction ratio, completeness coverage, and response-quality score we publish. The CI gate is the source of truth, not the marketing site.',
  },
  {
    title: 'Source code for the agent itself',
    body: "Not the SDK. Not the integration shim. The orchestrator, the planner, the prompt templates, the tool registry, the response policy, the rubric — the entire agent that touches your incident data is in this repo, MIT licensed. You can diff it, patch it, and ship that fork.",
  },
] as const;

type Contrast = {
  label: string;
  points: readonly string[];
  accent?: boolean;
};

const CONTRASTS: readonly Contrast[] = [
  {
    label: 'Black-box AI SOC vendor',
    points: [
      'Agent runs in vendor cloud. Your incident data leaves your network for inference.',
      'Prompts and policy are proprietary. You cannot audit how the agent reasons or what it tells the model about your case.',
      'Accuracy claims are marketing. No reproducible harness, no public CI gate, no historical regression record.',
      'No fork right. If the vendor changes the model, the policy, or the price, you have one option: comply.',
    ],
  },
  {
    label: 'Open-core with proprietary agent',
    points: [
      'The dashboard is open. The agent is not. The thing you actually need to audit is in a private repo.',
      'License is SSPL or BSL with a CLA. You "own" your fork until the next licence flip.',
      'The benchmark is internal. You see the score. You cannot see the dataset or rerun the harness.',
      'Self-hosting is technically allowed and operationally hostile.',
    ],
  },
  {
    label: 'AiSOC',
    points: [
      'Agent runs on your infrastructure. Your incident data, by default, never leaves your network.',
      'Every prompt, response, tool call, and decision is in the Investigation Ledger and replayable forever.',
      'Accuracy is a CI gate. The dataset, the harness, the rubric, and the latest numbers are all public and reproducible in seconds.',
      'MIT, no CLA. Fork it, patch the prompts, ship it. We do not have the legal right to take that away.',
    ],
    accent: true,
  },
];

const NON_REGULATED_REASONS = [
  {
    title: 'You keep agency over the agent',
    body: "When an LLM vendor changes a model and your detection tone shifts overnight, you want to be the one who decides whether to ship the change. With a closed agent, that decision was made for you weeks ago.",
  },
  {
    title: 'No rug pull, ever',
    body: "MIT means the version you ran today is yours forever. No relicense. No 'AI features now in the paid tier'. No 'open-source community edition' deprecation. Fork the commit and you are operationally independent.",
  },
  {
    title: 'Real extension, not "extensible"',
    body: 'Plugins, detections, playbooks, and prompts are all source code in the same repo. You write a Python or Go plugin against a typed SDK and it ships with the rest of the stack. No SaaS extensibility tax.',
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
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
              MIT-licensed, structurally
            </span>
            <span className="text-xs text-gray-500">~7 min read</span>
          </div>
          <h1 className="text-4xl font-bold tracking-tight md:text-5xl">
            The AI SOC your auditor will approve.
          </h1>
          <p className="mt-5 text-lg leading-relaxed text-gray-400">
            A CISO at a regulated bank cannot deploy a SOC whose agent is a
            black-box cloud service. They can deploy AiSOC. The argument below
            explains why that distinction is not a feature comparison — it is a
            structural property of the licence and the architecture, and it is
            the reason AiSOC exists.
          </p>
        </div>
      </section>

      <section className="px-6 pb-16">
        <div className="mx-auto max-w-3xl space-y-6 text-base leading-relaxed text-gray-300">
          <h2 className="pt-2 text-2xl font-semibold tracking-tight text-white">
            The problem the AI SOC market gave compliance teams
          </h2>
          <p>
            Every closed-source AI SOC vendor on the market today asks a
            regulated buyer to do three things simultaneously: ship their
            incident data to a vendor cloud for inference, trust an opaque
            policy that no one outside the vendor can read, and accept an
            accuracy number that no one outside the vendor can reproduce.
          </p>
          <p>
            That is a stack of three independent compliance problems, and the
            third — the unverifiable accuracy claim — is the one that
            quietly poisons the other two. If you cannot reproduce the
            number, you cannot defend the deployment in an audit. If you
            cannot defend it in an audit, you cannot get the deployment
            approved. Most teams end up with a tactical workaround: AI SOC for
            non-sensitive tenants, a manual triage queue for the regulated
            ones, and a slow, awkward conversation with their auditor every
            quarter about whether the line should hold.
          </p>
          <p>
            AiSOC is the answer to that conversation: an AI SOC where the
            agent itself is in the repo, the accuracy is a CI gate, the data
            stays in your network, and the licence cannot be retracted.
          </p>
        </div>
      </section>

      <section className="px-6 pb-16">
        <div className="mx-auto max-w-5xl">
          <h2 className="text-2xl font-semibold tracking-tight">
            What &ldquo;auditable&rdquo; actually means here
          </h2>
          <p className="mt-3 max-w-3xl text-sm text-gray-400">
            Three concrete artefacts. They are the entire pitch. Everything
            else is downstream.
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
            Three things you can hand your auditor
          </h2>
          <p>
            Every other claim on this page reduces to one of these. If your
            auditor cannot read all three on the first day of the deployment
            review, the AI SOC is not auditable; it is just AI-shaped.
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
            What the alternatives ask you to accept
          </h2>
          <p className="mt-3 max-w-3xl text-sm text-gray-400">
            We mark trade-offs honestly. The two non-AiSOC columns describe
            the dominant patterns in the AI SOC market today, not any
            specific vendor. If you have an example that does not fit, we
            want to hear about it.
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
            What MIT actually means here
          </h2>
          <p>
            &ldquo;Open source&rdquo; is overloaded. A meaningful number of
            self-described open-source security products today ship under
            licences that grant the cosmetic benefit of source-available code
            and reserve the rights that matter. We picked MIT, no CLA, and
            committed to keeping the core MIT in the README, on purpose.
          </p>
          <ul className="space-y-3">
            <li className="rounded-lg border border-white/5 bg-white/[0.02] p-4">
              <strong className="text-gray-200">No CLA.</strong>{' '}
              Contributors keep copyright on their patches. We do not collect
              an irrevocable licence to relicense the project tomorrow under
              SSPL, BSL, or a proprietary EULA. This is the line most
              &ldquo;open core&rdquo; projects cross first.
            </li>
            <li className="rounded-lg border border-white/5 bg-white/[0.02] p-4">
              <strong className="text-gray-200">No telemetry.</strong>{' '}
              Self-hosted deployments emit no analytics back to Cyble.
              Detection tuning, agent decisions, and operator behaviour stay
              on your boxes. The only network calls AiSOC initiates are the
              ones you configured: your LLM provider, your TI feed, your
              integrations.
            </li>
            <li className="rounded-lg border border-white/5 bg-white/[0.02] p-4">
              <strong className="text-gray-200">
                No agent gated behind a paid tier.
              </strong>{' '}
              The orchestrator, the planner, the prompt templates, the tool
              registry, the response policy, the rubric — every component
              that reasons over your incident data — is in this repo. There
              is no &ldquo;enterprise agent&rdquo; we are saving for a future
              SKU. The agent is the project.
            </li>
            <li className="rounded-lg border border-white/5 bg-white/[0.02] p-4">
              <strong className="text-gray-200">Fork rights are real.</strong>{' '}
              If we ship a release tomorrow that you do not like — a model
              choice, a default policy, a UX change — you have the legal and
              practical right to take the previous commit and run it
              indefinitely. We can ask you to upstream improvements. We
              cannot make you accept a downgrade.
            </li>
          </ul>
        </div>
      </section>

      <section className="px-6 pb-16">
        <div className="mx-auto max-w-5xl">
          <h2 className="text-2xl font-semibold tracking-tight">
            What this means if you are not in a regulated industry
          </h2>
          <p className="mt-3 max-w-3xl text-sm text-gray-400">
            The compliance story is the most legible one, but it is not the
            only one. Even if your auditor never reviews the SOC, the same
            structural properties give you operator agency that closed-source
            AI SOCs cannot match.
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
            What we will not claim
          </h2>
          <p>
            AiSOC is not a finished product, and overclaiming would defeat
            the point of writing this page. A few things we are explicit
            about:
          </p>
          <ul className="space-y-3">
            <li className="rounded-lg border border-white/5 bg-white/[0.02] p-4">
              <strong className="text-gray-200">
                We do not claim better accuracy than every vendor.
              </strong>{' '}
              We claim measurable accuracy. Anyone who reads the benchmark
              page can see exactly where we are. The gap between &ldquo;we
              measure ours; they don&rsquo;t publish theirs&rdquo; is the
              part that matters to a regulated buyer.
            </li>
            <li className="rounded-lg border border-white/5 bg-white/[0.02] p-4">
              <strong className="text-gray-200">
                Self-hosting is operationally real, not free.
              </strong>{' '}
              You run Postgres, Redis, ClickHouse, an LLM endpoint. We
              shipped <code className="text-gray-300">pnpm aisoc:demo</code>{' '}
              and one-click deploy buttons to make the on-ramp short, but
              this is your stack and you operate it.
            </li>
            <li className="rounded-lg border border-white/5 bg-white/[0.02] p-4">
              <strong className="text-gray-200">
                Bring-your-own LLM means bring-your-own trust boundary.
              </strong>{' '}
              The agent will, by default, send prompts to whatever LLM
              endpoint you configure. The Investigation Ledger logs every
              prompt so you can audit what left the network, but the trust
              boundary is the LLM you point at, not AiSOC. A future air-gap
              mode using local inference is on the roadmap; today, you pick
              the model.
            </li>
          </ul>
        </div>
      </section>

      <section className="px-6 pb-24">
        <div className="mx-auto max-w-4xl rounded-2xl border border-brand-500/20 bg-gradient-to-br from-brand-500/10 to-transparent p-8 text-center">
          <h2 className="text-2xl font-semibold tracking-tight">
            See it before you trust it
          </h2>
          <p className="mx-auto mt-3 max-w-2xl text-sm text-gray-400">
            Three artefacts, all reproducible in under a minute: a live
            investigation with the full ledger open, the public benchmark on
            your laptop, and the agent source on GitHub. None of them
            require a signup.
          </p>
          <div className="mt-6 flex flex-wrap justify-center gap-3">
            <a
              href="https://demo.aisoc.dev/cases/INC-001?tab=ledger"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-2 rounded-md bg-brand-500 px-4 py-2 text-sm font-semibold text-white shadow-glow-sm transition hover:bg-brand-400"
            >
              Try the live demo
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
              Read the benchmark
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
