/**
 * "What this does not do yet" — the limits section.
 *
 * Replaces `Testimonials`, which headlined "What teams say after their first
 * month" over an empty state offering to onboard reference partners "through
 * Q2 2026" — a window that had already closed. That is the same shape as the
 * "Design partners" block removed from this page earlier: an empty state that
 * asserts a programme nothing in the repository supports. Deleting it left a
 * gap where social proof would go, and the honest thing to put there is the
 * opposite of social proof.
 *
 * Every line below is a limitation stated against the artefact that measures
 * it, because a claim a reader can falsify in ten minutes costs more than the
 * claim was worth:
 *
 *   - the 7-of-19 local-model figure and "no hosted provider has ever been
 *     exercised" are from `apps/docs/docs/architecture.md` §8;
 *   - the substrate-versus-live benchmark split is from the scoreboard's own
 *     `_readme` and `apps/docs/docs/benchmark.md`;
 *   - the unpublished-packages state is from `release.yml` and README;
 *   - profile membership is from the deployment-profile table;
 *   - `simulated` versus `executed` is from `services/actions`.
 *
 * Server component, no animation. A section arguing for plain speech should
 * not arrive on a meteor shower, which is what the block it replaces did.
 */

import Link from 'next/link';
import { docs } from '@/lib/docs';

interface Limit {
  title: string;
  body: React.ReactNode;
}

const LIMITS: ReadonlyArray<Limit> = [
  {
    title: 'The bundled model is small, and it shows.',
    body: (
      <>
        It is a 3B quantized model chosen to run on a CPU. In a measured run of
        19 auto-triages on a core stack,{' '}
        <strong className="font-semibold text-velvet-content-primary">
          7 returned schema-valid output and 12 did not
        </strong>
        . The 12 fell back to the deterministic path, logged that they had, and
        the rail shows which path produced the verdict it is displaying — it
        never invents one. Point a hosted provider at the gateway and that
        ratio changes; the local default is what you get for nothing.
      </>
    ),
  },
  {
    title: 'No hosted provider has ever been exercised here.',
    body: (
      <>
        There is no funded key in this repository. Per-model rows therefore read{' '}
        <em className="not-italic text-velvet-content-primary">not measured</em>{' '}
        rather than zero, because a zero would say the model was graded and
        failed. The local path is measured. The hosted path is configured and
        untested. Those are different claims and are kept apart.
      </>
    ),
  },
  {
    title: 'Most published benchmark numbers grade the harness, not the agent.',
    body: (
      <>
        Only MITRE-tactic accuracy measures the live agent, and the per-pull-request
        run uses the deterministic tier with no model behind it. The rest are
        substrate self-consistency gates and are labelled as such on every
        surface that quotes them.
      </>
    ),
  },
  {
    title: 'The packages are built on every tag and published nowhere.',
    body: (
      <>
        All eight npm and PyPI artefacts are built and packed by the release
        workflow so the pipeline cannot rot, but the upload is blocked on
        registry credentials — an account action, not a code change. Install
        from source until that is resolved.
      </>
    ),
  },
  {
    title: 'The core profile is not the whole product.',
    body: (
      <>
        The event lake, the entity graph, full-text search and scheduled
        connectors belong to the full profile. On a core stack the pages that
        need them report which call failed rather than drawing something
        plausible — the degraded graph view further up this page is one.
      </>
    ),
  },
  {
    title: 'Nothing reaches a vendor without a human and a credential.',
    body: (
      <>
        An action is proposed, approved by someone holding the right permission
        who is not the person who requested it, executed, and then verified
        against the vendor. Without vendor credentials an executor returns{' '}
        <code className="font-mono text-[0.9em] text-velvet-content-primary">
          simulated
        </code>{' '}
        and says so.
      </>
    ),
  },
];

export function HonestLimits() {
  return (
    <section
      id="limits"
      aria-labelledby="limits-heading"
      className="relative py-20 sm:py-24 lg:py-28"
    >
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="grid gap-12 lg:grid-cols-[minmax(0,0.62fr)_minmax(0,1fr)] lg:gap-20">
          <div className="lg:sticky lg:top-28 lg:self-start">
            <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-velvet-emerald-mint">
              Stated before you find it
            </p>
            <h2
              id="limits-heading"
              className="font-velvet-display mt-3 text-3xl font-normal tracking-tight text-velvet-content-primary sm:text-4xl lg:text-[40px] lg:leading-[1.12] lg:tracking-[-0.015em]"
            >
              What this does not do yet.
            </h2>
            <p className="mt-5 max-w-md text-base leading-relaxed text-velvet-content-secondary">
              There are no customer logos on this page, and no quotes, because
              there is nothing to quote. What there is instead is the list a
              vendor would make you discover during the evaluation.
            </p>
            <Link
              href={docs('benchmark')}
              className="mt-5 inline-flex text-sm font-medium text-velvet-sapphire-soft underline decoration-velvet-sapphire/40 underline-offset-4 transition-colors duration-200 hover:text-velvet-content-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-velvet-sapphire-soft focus-visible:ring-offset-2 focus-visible:ring-offset-velvet-surface-base"
            >
              How each published number is measured
            </Link>
          </div>

          <dl className="divide-y divide-velvet-border border-t border-velvet-border">
            {LIMITS.map((limit) => (
              <div key={limit.title} className="py-6 sm:py-7">
                <dt className="font-velvet-display text-base font-normal leading-snug text-velvet-content-primary sm:text-lg">
                  {limit.title}
                </dt>
                <dd className="mt-2.5 text-sm leading-relaxed text-velvet-content-secondary">
                  {limit.body}
                </dd>
              </div>
            ))}
          </dl>
        </div>
      </div>
    </section>
  );
}
