'use client';

/**
 * "Plug in everything" — `connectors` section from §6.8 of the brief.
 *
 * Layout:
 *   - Section header (eyebrow + H2 + sub-head + category chips)
 *   - Two stacked `Marquee` rows of connector pills (top: left-to-right,
 *     bottom: right-to-left). The pills are drawn from a 24-name sample
 *     of the real `_CONNECTOR_CLASSES` registry; the full catalogue is
 *     69 today.
 *   - Code callout with a "Write a connector in 50 lines" snippet
 *     mirroring the BaseConnector pattern used in the registry.
 *
 * Connectors are decorative; the marquees pause on hover/focus and
 * collapse to a static row under `prefers-reduced-motion`.
 */

import Link from 'next/link';
import { ArrowRight } from 'lucide-react';
import { Marquee } from '@/components/magicui/Marquee';
import { cn } from '@/lib/utils';

interface ConnectorPill {
  name: string;
  category: 'EDR' | 'SIEM' | 'Cloud' | 'IAM' | 'SaaS' | 'VCS' | 'Network';
}

const CONNECTOR_SAMPLE: ReadonlyArray<ConnectorPill> = [
  { name: 'CrowdStrike Falcon', category: 'EDR' },
  { name: 'SentinelOne', category: 'EDR' },
  { name: 'Microsoft Defender', category: 'EDR' },
  { name: 'Cortex XDR', category: 'EDR' },
  { name: 'Splunk', category: 'SIEM' },
  { name: 'Microsoft Sentinel', category: 'SIEM' },
  { name: 'Elastic', category: 'SIEM' },
  { name: 'Sumo Logic', category: 'SIEM' },
  { name: 'AWS CloudTrail', category: 'Cloud' },
  { name: 'AWS GuardDuty', category: 'Cloud' },
  { name: 'Azure Activity', category: 'Cloud' },
  { name: 'GCP SCC', category: 'Cloud' },
  { name: 'Okta', category: 'IAM' },
  { name: 'Azure Entra', category: 'IAM' },
  { name: 'Duo Security', category: 'IAM' },
  { name: 'OnePassword', category: 'IAM' },
  { name: 'Google Workspace', category: 'SaaS' },
  { name: 'M365 Audit', category: 'SaaS' },
  { name: 'Slack', category: 'SaaS' },
  { name: 'Salesforce', category: 'SaaS' },
  { name: 'GitHub', category: 'VCS' },
  { name: 'GitLab', category: 'VCS' },
  { name: 'Cloudflare', category: 'Network' },
  { name: 'Cisco Umbrella', category: 'Network' },
];

const TOP_ROW = CONNECTOR_SAMPLE.slice(0, 12);
const BOTTOM_ROW = CONNECTOR_SAMPLE.slice(12);

const CATEGORY_LABELS: ReadonlyArray<ConnectorPill['category']> = [
  'EDR',
  'SIEM',
  'Cloud',
  'IAM',
  'SaaS',
  'VCS',
  'Network',
];

const CATEGORY_COLOR: Record<ConnectorPill['category'], string> = {
  EDR: 'bg-velvet-ruby/10 text-velvet-ruby-soft ring-velvet-ruby/30',
  SIEM: 'bg-velvet-emerald/10 text-velvet-emerald-mint ring-velvet-emerald/30',
  Cloud: 'bg-velvet-emerald-mint/10 text-velvet-emerald-mint ring-status-live/30',
  IAM: 'bg-velvet-sapphire/10 text-velvet-sapphire-soft ring-velvet-sapphire/30',
  SaaS: 'bg-velvet-warning/10 text-velvet-warning ring-velvet-warning/30',
  VCS: 'bg-velvet-warning/10 text-velvet-warning ring-velvet-warning/30',
  Network: 'bg-velvet-content-tertiary/10 text-velvet-content-secondary ring-velvet-border',
};

function Pill({ pill }: { pill: ConnectorPill }) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-2 rounded-full border border-velvet-border bg-velvet-surface-raised/70 px-3 py-1.5 text-xs font-medium text-velvet-content-primary backdrop-blur-sm shadow-[0_1px_0_rgba(255,255,255,0.04)_inset]',
        'transition-colors duration-200 ease-landing-out-quart hover:border-velvet-emerald/40',
      )}
    >
      <span
        aria-hidden="true"
        className={cn(
          'inline-flex h-1.5 w-1.5 rounded-full',
          CATEGORY_COLOR[pill.category].replace(/text-[^\s]+/g, '').replace(/ring-[^\s]+/g, '').replace(/\/\d+/g, ''),
        )}
      />
      {pill.name}
      <span
        className={cn(
          'rounded-full px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-[0.06em] ring-1 ring-inset',
          CATEGORY_COLOR[pill.category],
        )}
      >
        {pill.category}
      </span>
    </span>
  );
}

const SNIPPET = `from app.connectors.base import BaseConnector, ConnectorSchema, Field

class MyConnector(BaseConnector):
    connector_id = "my-saas"
    connector_category = "saas"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            name=cls.connector_id,
            label="My SaaS",
            category=cls.connector_category,
            fields=[
                Field("api_url", "text", required=True),
                Field("api_token", "secret", required=True, secret=True),
            ],
            default_poll_interval_seconds=300,
        )`;

export function ConnectorsMarquee() {
  return (
    <section
      id="connectors"
      aria-labelledby="connectors-heading"
      className="relative py-20 sm:py-24 lg:py-28"
    >
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-3xl text-center">
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-velvet-emerald-mint">
            Plug in everything
          </p>
          <h2
            id="connectors-heading"
            className="font-velvet-display font-normal mt-3 text-3xl tracking-tight text-velvet-content-primary sm:text-4xl lg:text-[40px] lg:leading-[1.15] lg:tracking-[-0.015em]"
          >
            69 connectors. 6,998 detections. 62 playbook packs.
          </h2>
          <p className="mt-4 text-base leading-relaxed text-velvet-content-secondary sm:text-lg">
            Every connector renders a schema-driven form, encrypts its
            secrets at the application layer, and starts polling on a
            per-instance schedule. When the catalogue doesn&apos;t have what
            you need, write your own — the plugin SDKs are MIT and the
            marketplace ships your manifest on the next index build.
          </p>
        </div>

        <ul className="mx-auto mt-8 flex max-w-3xl flex-wrap items-center justify-center gap-2">
          {CATEGORY_LABELS.map((category) => (
            <li key={category}>
              <span
                className={cn(
                  'inline-flex items-center rounded-full px-3 py-1 text-xs font-semibold uppercase tracking-[0.1em] ring-1 ring-inset',
                  CATEGORY_COLOR[category],
                )}
              >
                {category}
              </span>
            </li>
          ))}
        </ul>

        <p className="mt-10 text-center text-xs font-semibold uppercase tracking-[0.18em] text-velvet-content-tertiary">
          A small sample
        </p>

        <div className="relative mt-4 space-y-3">
          <div
            aria-hidden="true"
            className="pointer-events-none absolute inset-y-0 left-0 z-10 w-12 bg-gradient-to-r from-velvet-surface-base to-transparent sm:w-24"
          />
          <div
            aria-hidden="true"
            className="pointer-events-none absolute inset-y-0 right-0 z-10 w-12 bg-gradient-to-l from-velvet-surface-base to-transparent sm:w-24"
          />
          <Marquee>
            {TOP_ROW.map((pill) => (
              <Pill key={pill.name} pill={pill} />
            ))}
          </Marquee>
          <Marquee reverse>
            {BOTTOM_ROW.map((pill) => (
              <Pill key={pill.name} pill={pill} />
            ))}
          </Marquee>
        </div>

        <div className="mx-auto mt-16 max-w-5xl">
          <div className="grid gap-6 lg:grid-cols-[1fr_1.5fr] lg:items-center">
            <div>
              <h3 className="font-velvet-display font-normal text-2xl tracking-tight text-velvet-content-primary sm:text-3xl">
                Write a connector in 50 lines.
              </h3>
              <p className="mt-3 text-sm leading-relaxed text-velvet-content-secondary">
                Each connector is a Python class that declares a schema,
                tests its credentials, polls on a schedule, and normalises
                events into OCSF. The plugin SDKs ship for Python,
                TypeScript, and Go.
              </p>
              <Link
                href="https://github.com/beenuar/AiSOC#readme"
                className="group mt-5 inline-flex items-center gap-1 text-sm font-semibold text-velvet-emerald-mint transition-colors duration-200 hover:text-velvet-emerald-mint focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-velvet-emerald-mint focus-visible:ring-offset-2 focus-visible:ring-offset-velvet-surface-base"
              >
                Read the connector SDK
                <ArrowRight
                  className="h-3.5 w-3.5 transition-transform duration-200 group-hover:translate-x-0.5 motion-reduce:transition-none motion-reduce:group-hover:translate-x-0"
                  aria-hidden="true"
                />
              </Link>
            </div>
            <pre
              aria-label="Example Python connector"
              className="overflow-x-auto rounded-2xl border border-velvet-border bg-velvet-surface-raised/80 p-5 font-mono text-[12px] leading-relaxed text-velvet-content-secondary shadow-[0_18px_48px_-32px_rgba(15,23,42,0.7)]"
            >
              <code>{SNIPPET}</code>
            </pre>
          </div>
        </div>
      </div>
    </section>
  );
}
