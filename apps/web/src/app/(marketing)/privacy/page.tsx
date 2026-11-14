import type { Metadata } from 'next';

/**
 * `/privacy` — privacy policy.
 *
 * Split into two halves: the open-source self-hosted distribution (where we
 * collect nothing because we never see the bytes) and the managed waitlist
 * + marketing site at tryaisoc.com (where we do collect identity and
 * traffic data and need to say so). Last-updated date is checked into the
 * page so a reader can match it against a specific commit.
 */

export const metadata: Metadata = {
  title: 'Privacy — AiSOC',
  description:
    'What we collect, why we collect it, and how to delete it — split between the self-hosted distribution (nothing) and the managed waitlist + marketing site (identity, traffic, and waitlist data).',
  alternates: { canonical: '/privacy' },
  openGraph: {
    title: 'AiSOC privacy policy',
    description:
      'Self-hosted: we never see your data. Managed waitlist: identity + traffic + waitlist data. No third-party ad networks.',
    type: 'article',
  },
};

const LAST_UPDATED = '2026-06-28';

const SECTIONS: Array<{ heading: string; body: string[] }> = [
  {
    heading: 'Self-hosted distribution',
    body: [
      'The MIT-licensed AiSOC distribution runs entirely inside your environment. There is no phone-home, no telemetry endpoint, no opt-in analytics SDK, and no anonymous usage report shipped from your cluster back to us. When `AISOC_AIRGAPPED=true` the platform refuses to make outbound calls of any kind — including to LLM providers — so an air-gapped deployment can demonstrate the no-egress property by inspecting its own network.',
      'You configure your own LLM provider (OpenAI, Anthropic, Azure, Bedrock, or a private gateway). Their privacy policy governs the prompts you choose to send them — we are not a party to that traffic.',
    ],
  },
  {
    heading: 'Marketing site (tryaisoc.com)',
    body: [
      'Like every static site, our hosting provider records standard HTTP access logs (IP, user-agent, requested path, referrer, timestamp). We retain these for up to 30 days for abuse mitigation and then discard them. We do not run third-party ad networks, do not embed cross-site trackers, and do not sell or share access logs.',
      'When you sign the managed waitlist we collect the fields you submit (work email, name, company, optional notes) and store them for the explicit purpose of contacting you about onboarding. We do not enrich, resell, or share that data. To delete your waitlist record, email privacy@tryaisoc.com from the address you signed up with and we will remove it within 14 days.',
    ],
  },
  {
    heading: 'Managed tier (when live)',
    body: [
      'The managed tier is on waitlist; once it ships, this section will spell out exactly what data we host on your behalf, the region you can pin it to, the encryption-at-rest configuration, the backup retention window, and the data-deletion SLA. Until then there is no managed customer data in our possession.',
    ],
  },
  {
    heading: 'Children',
    body: [
      'AiSOC is a B2B security product. We do not direct it at children under 16 and do not knowingly collect data from them.',
    ],
  },
  {
    heading: 'Contact',
    body: [
      'Privacy questions and deletion requests: privacy@tryaisoc.com. Security disclosures: security@tryaisoc.com (see SECURITY.md for PGP keys and the disclosure window). General contact: hello@tryaisoc.com.',
    ],
  },
];

export default function PrivacyPage() {
  return (
    <main
      data-theme="dark"
      className="relative min-h-screen overflow-x-hidden bg-surface-base text-fg-primary"
    >
      <section className="px-6 pt-32 pb-16">
        <div className="mx-auto max-w-3xl">
          <span className="text-xs font-semibold uppercase tracking-wider text-brand-300">
            Privacy policy
          </span>
          <h1 className="mt-3 text-4xl font-bold tracking-tight text-white md:text-5xl">
            What we collect. Why. How to delete it.
          </h1>
          <p className="mt-3 text-xs text-gray-500">Last updated: {LAST_UPDATED}</p>

          <div className="mt-10 space-y-10">
            {SECTIONS.map((section) => (
              <section key={section.heading}>
                <h2 className="text-xl font-semibold text-white">
                  {section.heading}
                </h2>
                <div className="mt-3 space-y-3 text-sm leading-relaxed text-gray-300">
                  {section.body.map((para, idx) => (
                    <p key={idx}>{para}</p>
                  ))}
                </div>
              </section>
            ))}
          </div>
        </div>
      </section>

    </main>
  );
}
