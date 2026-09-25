/**
 * "What it looks like running" — the screenshot section.
 *
 * This replaces `DemoEmbed`, which rendered a hand-authored mock of the
 * Investigation Ledger: a named ransomware family, a 0.93 confidence, a
 * $0.084 spend against a named hosted model, "4 hosts · 2 users", all of it
 * invented and none of it labelled as such. A marketing surface asserting
 * measurements the product never produced is the exact shape this repository
 * has a standing rule against, and it was the only place on the site that
 * claimed to show the console.
 *
 * Every image below is a capture of a running CORE stack. The manifest beside
 * them (`apps/web/public/screenshots/README.md`) records, per file, what was
 * observed and what was authored, and the captions here are written against
 * it. The distinction that matters, stated once in the section lede and kept
 * out of no caption: the *security events* were written by hand and pushed
 * through the documented ingest API — normalization, detection, promotion,
 * correlation and triage were performed by the running services, and no row
 * was seeded. The CISA KEV catalogue is neither ours nor synthetic. Nothing
 * here is a real intrusion and no caption may imply one.
 *
 * Two of the four figures are deliberately empty or degraded. They are the
 * argument, not an omission: a console that reports "API 503" instead of
 * drawing a graph it does not have is the difference being sold.
 *
 * Server component. No `'use client'`, no animation library, no state — the
 * previous section shipped framer-motion and a BorderBeam to animate a
 * fiction. Four `next/image` tags cost the route nothing at runtime.
 */

import Image from 'next/image';
import Link from 'next/link';
import { ArrowUpRight } from 'lucide-react';
import { docs } from '@/lib/docs';

const MANIFEST_URL =
  'https://github.com/beenuar/AiSOC/blob/main/apps/web/public/screenshots/README.md';

interface Shot {
  src: string;
  alt: string;
  /** The console route the capture was taken on, shown in the frame chrome. */
  route: string;
}

function Frame({ shot, priority = false }: { shot: Shot; priority?: boolean }) {
  return (
    <div className="overflow-hidden rounded-xl border border-velvet-border bg-velvet-surface-raised/70 shadow-[0_24px_60px_-28px_rgba(15,23,42,0.85)]">
      <div className="flex items-center gap-2.5 border-b border-velvet-border/80 px-3 py-2">
        <span className="flex gap-1.5" aria-hidden="true">
          <span className="h-2 w-2 rounded-full bg-velvet-content-tertiary/40" />
          <span className="h-2 w-2 rounded-full bg-velvet-content-tertiary/40" />
          <span className="h-2 w-2 rounded-full bg-velvet-content-tertiary/40" />
        </span>
        <span className="truncate font-mono text-[10.5px] text-velvet-content-tertiary">
          {shot.route}
        </span>
      </div>
      <Image
        src={shot.src}
        alt={shot.alt}
        width={1440}
        height={900}
        priority={priority}
        sizes="(min-width: 1024px) 60vw, 100vw"
        className="h-auto w-full"
      />
    </div>
  );
}

function Caption({
  kicker,
  title,
  children,
  provenance,
}: {
  kicker: string;
  title: string;
  children: React.ReactNode;
  provenance: string;
}) {
  return (
    <figcaption className="max-w-md">
      <p className="font-mono text-[10.5px] uppercase tracking-[0.16em] text-velvet-emerald-mint">
        {kicker}
      </p>
      <h3 className="font-velvet-display mt-2.5 text-xl font-normal leading-snug text-velvet-content-primary sm:text-2xl">
        {title}
      </h3>
      <p className="mt-3 text-sm leading-relaxed text-velvet-content-secondary">
        {children}
      </p>
      <p className="mt-3 border-l border-velvet-border pl-3 text-xs leading-relaxed text-velvet-content-tertiary">
        {provenance}
      </p>
    </figcaption>
  );
}

export function ProductTour() {
  return (
    <section
      id="product"
      aria-labelledby="product-heading"
      className="relative border-y border-velvet-border/60 py-20 sm:py-24 lg:py-28"
    >
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="max-w-3xl">
          <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-velvet-emerald-mint">
            What it looks like running
          </p>
          <h2
            id="product-heading"
            className="font-velvet-display mt-3 text-3xl font-normal tracking-tight text-velvet-content-primary sm:text-4xl lg:text-[40px] lg:leading-[1.12] lg:tracking-[-0.015em]"
          >
            Captures from a stack anyone can bring up.
          </h2>
          <p className="mt-5 text-base leading-relaxed text-velvet-content-secondary sm:text-lg">
            These are photographs of the console, not design comps. The stack
            was brought up with <code className="font-mono text-[0.9em] text-velvet-content-primary">make up</code>{' '}
            and fed through the documented ingest API. The security events in it
            were authored to be representative; everything downstream of
            them — normalization, detection, promotion, correlation and
            triage — is the product doing its job on a machine with no
            credentials configured. No row was seeded, and none of this is a
            real intrusion.
          </p>
          <Link
            href={MANIFEST_URL}
            target="_blank"
            rel="noreferrer"
            className="mt-5 inline-flex items-center gap-1.5 text-sm font-medium text-velvet-sapphire-soft underline decoration-velvet-sapphire/40 underline-offset-4 transition-colors duration-200 hover:text-velvet-content-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-velvet-sapphire-soft focus-visible:ring-offset-2 focus-visible:ring-offset-velvet-surface-base"
          >
            What is real in each shot, file by file
            <ArrowUpRight className="h-3.5 w-3.5" aria-hidden="true" />
          </Link>
        </div>

        {/* Anchor figure: caption left, wide frame right. */}
        <figure className="mt-14 grid items-center gap-8 lg:mt-20 lg:grid-cols-[minmax(0,0.78fr)_minmax(0,1.6fr)] lg:gap-14">
          <Caption
            kicker="Automated triage"
            title="A verdict you can read, from a model on your own machine."
            provenance="The bundled llama3.2:3b-instruct-q4_K_M answered through the local gateway. Verdict, confidence and rationale are reproduced exactly as the console rendered them. Groundedness says not assessed because this run did not score it — a different fact from zero."
          >
            The rail shows the disposition, the confidence out of 100, and the
            model&rsquo;s own reasoning verbatim. Token counts and latency land
            in the Investigation Ledger next to the prompt that produced them.
            Cost on this path is genuinely nothing, because the model is running
            beside the console rather than behind somebody&rsquo;s API key.
          </Caption>
          <Frame
            priority
            shot={{
              src: '/screenshots/ai-triage-verdict.png',
              route: 'localhost:3000/alerts',
              alt: 'The AiSOC alerts queue with the Investigation Rail open on an alert, showing an automated triage verdict of true positive at confidence 80 out of 100, groundedness not assessed, and the local model rationale in full.',
            }}
          />
        </figure>

        {/* Two figures, deliberately unequal, captions beneath. */}
        {/*
          `lg:items-end` rather than the default stretch: the two frames are
          the same 1440x900 capture in columns of different widths, so they
          render at different heights. Bottom-aligning the pair makes the
          offset read as composition instead of as a caption that failed to
          line up.
        */}
        <div className="mt-16 grid gap-10 lg:mt-24 lg:grid-cols-[minmax(0,1.12fr)_minmax(0,0.88fr)] lg:items-end lg:gap-12">
          <figure>
            <Frame
              shot={{
                src: '/screenshots/threat-intel-kev.png',
                route: 'localhost:3000/threat-intel',
                alt: 'The AiSOC Threat Intelligence page listing CVE entries sourced from the CISA Known Exploited Vulnerabilities catalogue, with 1,725 indicators collected and 100 shown.',
              }}
            />
            <div className="mt-6">
              <Caption
                kicker="Real data, minute one"
                title="1,725 live CISA KEV entries, with no account anywhere."
                provenance="Fetched from the public Known Exploited Vulnerabilities catalogue at capture time. Not ours, not synthetic, unmodified. The page states the catalogue size and the page length as two separate numbers because they are two separate numbers."
              >
                A keyless, authoritative feed ships in the core profile, so the
                first thing a fresh install shows is real threat intelligence
                rather than a placeholder or an empty table.
              </Caption>
            </div>
          </figure>

          <figure>
            <Frame
              shot={{
                src: '/screenshots/attack-graph-core-degraded.png',
                route: 'localhost:3000/graph',
                alt: 'The AiSOC Attack Graph page reporting that it could not load the view, naming the failure as API 503 Service Unavailable on /api/v1/graph, with a retry button.',
              }}
            />
            <div className="mt-6">
              <Caption
                kicker="When a backend is missing"
                title="It names the failure instead of drawing a graph."
                provenance="Genuinely degraded, not staged. The entity graph is a full-profile service, so on a core stack there is nothing behind this route — and the console says which call failed and with what status."
              >
                The old behaviour across this console was to fall back to
                plausible invented data, which an operator cannot tell from the
                real thing. Every one of those fallbacks was removed.
              </Caption>
            </div>
          </figure>
        </div>

        {/* Mirrored: frame left, caption right. */}
        <figure className="mt-16 grid items-center gap-8 lg:mt-24 lg:grid-cols-[minmax(0,1.6fr)_minmax(0,0.78fr)] lg:gap-14">
          <Frame
            shot={{
              src: '/screenshots/soc-operations.png',
              route: 'localhost:3000/dashboards/operations',
              alt: 'The AiSOC SOC operations dashboard against a tenant with no connectors, stating that nothing is feeding the pipeline yet so an empty alert queue is expected, with every pipeline stage reporting its backlog and error rate.',
            }}
          />
          <Caption
            kicker="An honest zero"
            title="Nothing connected yet, and the dashboard says exactly that."
            provenance="A genuinely empty tenant. Every panel here is driven by a live API response; where a figure has not been measured the console prints not measured rather than a confident 0."
          >
            Pipeline health is reported independently of whether anything is
            being found, so &ldquo;quiet&rdquo; and &ldquo;broken&rdquo; are
            never the same picture. An unmeasured mean reads as unmeasured, and
            every average travels with the number of rows it averaged.
          </Caption>
        </figure>

        <p className="mt-14 max-w-2xl text-sm leading-relaxed text-velvet-content-tertiary lg:mt-16">
          Twelve more captures, including the connector catalogue, the hunt
          workbench and the playbook step palette, are in the repository
          alongside the manifest that says what each one contains.{' '}
          <Link
            href={docs('architecture')}
            className="font-medium text-velvet-content-secondary underline decoration-velvet-border underline-offset-4 transition-colors duration-200 hover:text-velvet-content-primary"
          >
            The architecture page follows a single event through all eleven
            steps of this path
          </Link>
          , and links the code for each one.
        </p>
      </div>
    </section>
  );
}
