'use client';

/**
 * "FAQ" — `faq` section from §6.14 of the brief.
 *
 * Hand-rolled accordion (no Radix dependency yet) that satisfies the
 * brief's a11y contract:
 *
 *   - Each row is a `<button>` inside a `<dt>`, exposing `aria-expanded`
 *     and `aria-controls`. The associated `<dd>` carries the matching
 *     `id` and `role="region"`.
 *   - Keyboard: Tab/Shift-Tab between rows, Enter or Space toggles,
 *     focus-visible ring on the trigger.
 *   - Animation: only the body gets a height transition, so the click
 *     stays snappy on slower devices. The chevron rotates 180°. Under
 *     `prefers-reduced-motion` both transitions are dropped via
 *     `motion-reduce:` utilities.
 *
 * All eight Q/A pairs are lifted verbatim from `landing-page-content.md`.
 */

import { useId, useState } from 'react';
import { ChevronDown } from 'lucide-react';
import { cn } from '@/lib/utils';
import { CONNECTOR_COUNT } from '@/data/connectorCount';

interface QA {
  q: string;
  a: string;
}

const FAQS: ReadonlyArray<QA> = [
  {
    q: 'Is AiSOC really open source?',
    a:
      'Yes — the agent, the connectors, the detection rules, the benchmark dataset, and every piece of infrastructure code are MIT-licensed. There is no private fork.',
  },
  {
    q: 'What does the agent need to call out to?',
    a:
      'By default the Triage and Hunt agents call an LLM provider you configure (OpenAI, Anthropic, Azure, Bedrock, or a private LiteLLM gateway). Set AISOC_AIRGAPPED=true and the platform refuses every outbound call; an Ollama sidecar runs a local model in-cluster.',
  },
  {
    q: 'Where does my data live?',
    a:
      'Self-host: wherever you point Postgres, ClickHouse, and Redis. Managed: EU, US, or India region you pick at signup. Sovereign: a single-tenant VPC you control. The connector vault encrypts secrets with Fernet AES-128-CBC + HMAC-SHA256.',
  },
  {
    q: 'Can the agent take real-world action without a human?',
    a:
      'Only inside the maturity tier you configure. L0 keeps the agent advisory only; L2 (the production default) lets it run reversible containment actions; L4 allows whitelisted closed-loop actions. Every action class is gated against blast radius.',
  },
  {
    q: 'How is AiSOC kept secure and up to date?',
    a:
      'Every pull request runs a CI-gated security audit (pip-audit + pnpm audit) that blocks the merge on any unresolved CVE, alongside CodeQL static analysis. Dependencies are kept current — the cryptography floor was recently raised to 44.0.1 to clear CVE-2024-12797, and detection-loop lookups are tenant-scoped so cross-tenant reads are impossible. The audit policy lives in scripts/security_audit.py.',
  },
  {
    q: 'How is this benchmarked?',
    a:
      'Five pytest suites in services/agents/tests/ run on every PR. Three are substrate self-consistency gates; the fourth is a real measurement against a fixed 1,000-alert noisy stream; the fifth is a coverage gate on the synthetic telemetry corpus. The methodology page documents what each suite measures and what it does not.',
  },
  {
    q: 'How do connectors work?',
    a:
      `Each connector is a Python class that declares a schema, tests its credentials, polls on a schedule, and normalises events into OCSF. ${CONNECTOR_COUNT} ship in the box. The plugin SDKs (Python, TypeScript, Go) let you author your own in roughly 50 lines.`,
  },
  {
    q: 'What runs in production today?',
    a:
      'Beta deployments through reference partners and an internal demo on tryaisoc.com. The managed waitlist at tryaisoc.com is the route for hosted customers.',
  },
  {
    q: 'Why not just use an existing AI SOC vendor?',
    a:
      "Use whichever tools fit your risk and procurement model. AiSOC's contribution is making the agent itself open, the decisions step-by-step auditable, and the benchmark reproducible — three guarantees closed-source platforms typically do not offer.",
  },
];

function FaqRow({
  qa,
  index,
  idBase,
}: {
  qa: QA;
  index: number;
  idBase: string;
}) {
  const [open, setOpen] = useState(false);
  const buttonId = `${idBase}-q-${index}`;
  const panelId = `${idBase}-a-${index}`;

  return (
    <div className="border-b border-velvet-border last:border-b-0">
      <dt>
        <button
          id={buttonId}
          type="button"
          aria-expanded={open}
          aria-controls={panelId}
          onClick={() => setOpen((prev) => !prev)}
          className="flex w-full items-start justify-between gap-4 py-5 text-left transition-colors duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-velvet-emerald-mint focus-visible:ring-offset-2 focus-visible:ring-offset-velvet-surface-base sm:py-6"
        >
          <span className="text-base font-semibold text-velvet-content-primary sm:text-lg">
            {qa.q}
          </span>
          <ChevronDown
            className={cn(
              'mt-1 h-5 w-5 flex-none text-velvet-content-tertiary transition-transform duration-300 ease-landing-out-quart motion-reduce:transition-none',
              open && 'rotate-180 text-velvet-emerald-mint',
            )}
            aria-hidden="true"
          />
        </button>
      </dt>
      <dd
        id={panelId}
        role="region"
        aria-labelledby={buttonId}
        hidden={!open}
        className={cn(
          'overflow-hidden text-sm leading-relaxed text-velvet-content-secondary sm:text-base',
          open && 'pb-5 sm:pb-6',
        )}
      >
        {qa.a}
      </dd>
    </div>
  );
}

export function Faq() {
  const idBase = useId();

  return (
    <section
      id="faq"
      aria-labelledby="faq-heading"
      className="relative py-20 sm:py-24 lg:py-28"
    >
      <div className="mx-auto max-w-3xl px-4 sm:px-6 lg:px-8">
        <div className="text-center">
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-velvet-emerald-mint">
            Questions, asked honestly
          </p>
          <h2
            id="faq-heading"
            className="font-velvet-display font-normal mt-3 text-3xl tracking-tight text-velvet-content-primary sm:text-4xl lg:text-[40px] lg:leading-[1.15] lg:tracking-[-0.015em]"
          >
            Frequently asked.
          </h2>
        </div>

        <dl className="mt-12 lg:mt-14">
          {FAQS.map((qa, idx) => (
            <FaqRow key={qa.q} qa={qa} index={idx} idBase={idBase} />
          ))}
        </dl>
      </div>
    </section>
  );
}
