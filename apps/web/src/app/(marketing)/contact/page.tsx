import type { Metadata } from 'next';
import Link from 'next/link';

/**
 * `/contact` — channel directory.
 *
 * We deliberately do NOT ship a form. A buyer-side request to talk to us
 * almost always falls into one of four categories (managed waitlist,
 * sovereign / air-gap quote, security disclosure, community help) and
 * each routes to a different channel. A single contact form would funnel
 * them all into the same inbox and slow every reply down.
 */

export const metadata: Metadata = {
  title: 'Contact — AiSOC',
  description:
    'How to reach AiSOC: managed waitlist, sovereign / air-gap deployment quotes, security disclosures, and community support — each via the channel that gets the fastest reply.',
  alternates: { canonical: '/contact' },
  openGraph: {
    title: 'Contact AiSOC',
    description:
      'Managed waitlist · sovereign deploy · security disclosures · community.',
    type: 'article',
  },
};

interface ContactChannel {
  heading: string;
  body: string;
  cta: { label: string; href: string };
}

const CHANNELS: ContactChannel[] = [
  {
    heading: 'Managed waitlist',
    body:
      "You'd rather we host AiSOC than run it yourself. We open new managed-tier seats in waves; the waitlist tells you where you are in the queue.",
    cta: { label: 'Join the waitlist', href: '/waitlist' },
  },
  {
    heading: 'Sovereign or air-gap deployment',
    body:
      'You want AiSOC inside your VPC, an air-gapped network, or a sovereign-cloud region with custom data-residency requirements. We quote these individually.',
    cta: {
      label: 'hello@tryaisoc.com',
      href: 'mailto:hello@tryaisoc.com?subject=AiSOC%20sovereign%20deployment',
    },
  },
  {
    heading: 'Security disclosure',
    body:
      'You found a vulnerability. SECURITY.md spells out PGP keys and the disclosure window we commit to. Please do not file a public issue first.',
    cta: {
      label: 'Read SECURITY.md',
      href: 'https://github.com/beenuar/AiSOC/blob/main/SECURITY.md',
    },
  },
  {
    heading: 'Community + bug reports',
    body:
      'You hit something while self-hosting and want a second pair of eyes. GitHub Issues is the fastest route; the Discord works for general chat.',
    cta: {
      label: 'github.com/beenuar/AiSOC/issues',
      href: 'https://github.com/beenuar/AiSOC/issues',
    },
  },
  {
    heading: 'Press + speaking',
    body:
      'You want a quote, a podcast guest, or a conference talk. We are happy to help — just give us a few days of notice.',
    cta: { label: 'press@tryaisoc.com', href: 'mailto:press@tryaisoc.com' },
  },
];

export default function ContactPage() {
  return (
    <main
      data-theme="dark"
      className="relative min-h-screen overflow-x-hidden bg-surface-base text-fg-primary"
    >
      <section className="px-6 pt-32 pb-12">
        <div className="mx-auto max-w-3xl">
          <span className="text-xs font-semibold uppercase tracking-wider text-brand-300">
            Contact
          </span>
          <h1 className="mt-3 text-4xl font-bold tracking-tight text-white md:text-5xl">
            Pick the channel that gets you the fastest reply.
          </h1>
          <p className="mt-5 text-base leading-relaxed text-gray-400">
            Different conversations live on different rails — we keep
            the security disclosure inbox quiet, the waitlist inbox
            high-volume, and the press inbox shallow on purpose.
          </p>
        </div>
      </section>

      <section className="px-6 pb-16">
        <div className="mx-auto max-w-3xl">
          <ul className="grid gap-3 sm:grid-cols-2">
            {CHANNELS.map((channel) => (
              <li
                key={channel.heading}
                className="flex flex-col gap-3 rounded-xl border border-white/10 bg-white/[0.02] p-5"
              >
                <h2 className="text-base font-semibold text-white">
                  {channel.heading}
                </h2>
                <p className="text-sm leading-relaxed text-gray-400">
                  {channel.body}
                </p>
                <div className="mt-auto pt-2">
                  {channel.cta.href.startsWith('http') ||
                  channel.cta.href.startsWith('mailto:') ? (
                    <a
                      href={channel.cta.href}
                      target={
                        channel.cta.href.startsWith('http')
                          ? '_blank'
                          : undefined
                      }
                      rel={
                        channel.cta.href.startsWith('http')
                          ? 'noreferrer'
                          : undefined
                      }
                      className="inline-flex items-center gap-1.5 text-sm font-medium text-brand-300 underline decoration-brand-500/40 underline-offset-2 hover:text-brand-200"
                    >
                      {channel.cta.label}
                    </a>
                  ) : (
                    <Link
                      href={channel.cta.href}
                      className="inline-flex items-center gap-1.5 text-sm font-medium text-brand-300 underline decoration-brand-500/40 underline-offset-2 hover:text-brand-200"
                    >
                      {channel.cta.label}
                    </Link>
                  )}
                </div>
              </li>
            ))}
          </ul>
        </div>
      </section>

    </main>
  );
}
