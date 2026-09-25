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
 * The answers were originally lifted verbatim from `landing-page-content.md`
 * and four had gone stale or false against the tree: a data-residency answer
 * naming managed regions, a security answer quoting a dependency floor three
 * major versions behind the one the services declare, a benchmark answer
 * calling the retracted alert-reduction suite "a real measurement", and a
 * "what runs in production today" answer asserting beta deployments through
 * reference partners — an adopter claim nothing in this repository supports.
 * They are rewritten against the tree, and the two questions a reader of an
 * open-source SOC actually opens the page with (does it need a key, and how
 * good is the model it ships with) are answered first.
 *
 * `faqJsonLd` in `apps/web/src/app/page.tsx` publishes the same pairs to
 * crawlers. The two must be changed together or the page and its structured
 * data disagree about the product.
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
    q: 'Do I need an API key to try it?',
    a:
      'No. The core profile brings up 14 services with no credentials of any kind: it generates its own secrets, creates an administrator, runs a local model behind the gateway so triage is real rather than stubbed, and polls the public CISA Known Exploited Vulnerabilities catalogue so the first thing you see is real threat intelligence.',
  },
  {
    q: 'How good is the model that ships with it?',
    a:
      'It is a 3B quantized model sized for CPU inference, and the difference from a frontier model is visible. In a measured run of 19 auto-triages on a core stack, 7 returned schema-valid output and 12 did not; the 12 fell back to the deterministic path and the Investigation Rail shows which path produced the verdict it is displaying. Point the gateway at a hosted provider and that changes — but no hosted provider has ever been exercised in this repository, so those rows read "not measured" rather than zero.',
  },
  {
    q: 'What does the agent call out to?',
    a:
      'Nothing, on a default install: the model runs beside the console and no prompt leaves the machine. Point the gateway at OpenAI, Anthropic, Azure or Bedrock by setting three variables in .env. Set AISOC_AIRGAPPED=true and the platform refuses every outbound call.',
  },
  {
    q: 'Where does my data live?',
    a:
      'Wherever you point Postgres, Kafka and Redis, because that is the whole deployment. Connector credentials are encrypted at rest with Fernet AES-128-CBC + HMAC-SHA256. Tenant isolation is enforced at the query layer in every store and by row-level security on 83 Postgres tables, with services connecting as a DML-only role so those policies actually apply to them.',
  },
  {
    q: 'Can the agent take real-world action without a human?',
    a:
      'No. An action is proposed, approved by someone who holds the required permission and who is not the person who requested it, executed, and then verified by probing the vendor rather than by reading an HTTP 200. Risk, reversibility and approval tier are declared per capability, and a capability whose effect cannot be verified is not eligible for automatic execution. Without vendor credentials an executor returns "simulated" and says so.',
  },
  {
    q: 'How is AiSOC kept secure and up to date?',
    a:
      'Every pull request runs a CI-gated security audit (pip-audit + pnpm audit) that blocks the merge on any unresolved CVE, alongside CodeQL static analysis with a gate that fails on an open alert at any severity and refuses to pass on an analysis that belongs to a different commit. The audit policy lives in scripts/security_audit.py.',
  },
  {
    q: 'How is this benchmarked?',
    a:
      'Carefully, and with the labels attached. Only MITRE-tactic accuracy measures the live agent, and the per-pull-request run grades it with the deterministic tier and no model behind it. The other published figures are substrate self-consistency gates over a fixed synthetic corpus — they measure the harness, not the agent, and every surface that quotes them says so. The methodology page documents what each suite measures and what it does not.',
  },
  {
    q: 'How do connectors work?',
    a:
      `Each connector is a Python class that declares a schema, tests its credentials, polls on a schedule, and normalises events into OCSF. ${CONNECTOR_COUNT} ship in the box. The plugin SDKs (Python, TypeScript, Go) let you author your own in roughly 50 lines.`,
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
