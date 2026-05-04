import React from 'react';
import clsx from 'clsx';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';
import styles from './index.module.css';

function HomepageHeader() {
  const { siteConfig } = useDocusaurusContext();
  return (
    <header className={clsx('hero hero--primary', styles.heroBanner)}>
      <div className="container">
        <h1 className="hero__title">{siteConfig.title}</h1>
        <p className="hero__subtitle">{siteConfig.tagline}</p>
        <div className={styles.buttons}>
          <Link
            className="button button--secondary button--lg"
            to="/docs/intro">
            Get Started →
          </Link>
          <Link
            className="button button--outline button--secondary button--lg"
            href="https://github.com/beenuar/aisoc">
            GitHub
          </Link>
        </div>
      </div>
    </header>
  );
}

// Top three features lead with the structural moat: auditable agent decisions,
// the public benchmark that proves them, and the MIT/self-host posture that
// makes both meaningful in regulated environments. The remaining capability
// list follows so visitors see we ship the substrate too — but the headline
// reason to pick AiSOC over a closed-source competitor sits in rows 1–3.
const FEATURES = [
  {
    title: '🔎 Auditable agent decisions',
    description:
      'Every prompt, tool call, and rationale the agent emits is persisted to the investigation ledger and replayable step-by-step in the case workspace.',
  },
  {
    title: '📊 Public MITRE benchmark',
    description:
      '200-incident eval suite covering MITRE ATT&CK accuracy, alert reduction, investigation completeness, and response quality. Numbers are CI-gated and reproducible on your laptop.',
  },
  {
    title: '🆓 MIT-licensed, self-hostable',
    description:
      'Read the code, audit the prompts, run the agent on your own data. No CLA, no telemetry, no calls home — your auditor can review every line.',
  },
  {
    title: '🔍 LangGraph multi-agent investigation',
    description:
      'Recon → forensic → responder → reporter graph for automated root-cause analysis, triage, and case enrichment.',
  },
  {
    title: '📋 Playbook engine',
    description:
      'Visual React Flow editor with 12+ starter templates for automated, human-gated response actions.',
  },
  {
    title: '🧠 UEBA',
    description:
      'Per-user Welford online baselines, Z-score anomaly scoring, and Kafka-integrated anomaly publishing.',
  },
  {
    title: '🍯 Honeytokens',
    description:
      'HMAC-SHA256 signed deceptive credentials (URL, file, AWS key, email) with first-touch webhook alerting.',
  },
  {
    title: '🟣 Purple Team',
    description:
      'Atomic Red Team YAML parser + Caldera executor, ATT&CK coverage heatmap, and tabletop sessions.',
  },
  {
    title: '⚡ Real-time fusion',
    description:
      'Kafka spine with sub-second alert ingestion, Bloom-filter dedup on 10M+ IOCs, ML scoring (LightGBM + Isolation Forest).',
  },
  {
    title: '🕸️ Attack graph',
    description:
      'Neo4j entity graph with attack-path reconstruction and blast-radius gating on automated actions.',
  },
  {
    title: '🛡️ Detection engineering',
    description:
      'Sigma over OpenSearch + ClickHouse, YARA, KQL/EQL — community catalog with one-click install.',
  },
  {
    title: '🏛️ Enterprise governance',
    description:
      'SAML 2.0 + OIDC SSO, multi-tenant Postgres RLS, granular RBAC, and immutable audit log.',
  },
  {
    title: '📊 Compliance dashboards',
    description:
      'SOC 2, ISO 27001, NIST CSF, PCI-DSS, HIPAA, DORA evidence with MTTD/MTTR/MTTC SLA tracking.',
  },
  {
    title: '🔌 Plugin ecosystem',
    description:
      'Python and TypeScript SDKs, Ed25519-signed publishing, and a community marketplace.',
  },
  {
    title: '🚀 Cloud-native',
    description:
      'Helm charts, Docker Compose, OpenTelemetry traces/metrics/logs, and PostgreSQL backup with KMS encryption.',
  },
];

// Comparison rows are written as visitor-actionable claims, not marketing
// gloss. We anchor each row to a concrete capability ("Agent decisions are
// auditable line-by-line") so the table can be defended in a sales call.
// Ordering is intentional: the top three rows are the ones a CISO at a
// regulated org will use to disqualify closed-source SOCs first.
type CompareCell = { kind: 'yes' | 'no' | 'caveat'; label: string };

const COMPARE_HEADERS = [
  'Capability',
  'AiSOC',
  'Wazuh',
  'Splunk Enterprise Security',
  'Anvilogic',
  'Prophet Security',
] as const;

const COMPARE_ROWS: ReadonlyArray<{ feature: string; cells: CompareCell[] }> = [
  {
    feature: 'Open-source (MIT) and self-hostable',
    cells: [
      { kind: 'yes', label: 'Yes — MIT' },
      { kind: 'yes', label: 'Yes — GPLv2' },
      { kind: 'no', label: 'No' },
      { kind: 'no', label: 'Cloud-only' },
      { kind: 'no', label: 'Cloud-only' },
    ],
  },
  {
    feature: 'Agent decisions are auditable line-by-line',
    cells: [
      { kind: 'yes', label: 'Yes — full ledger + replay' },
      { kind: 'caveat', label: 'No agent layer' },
      { kind: 'no', label: 'Black-box ML' },
      { kind: 'no', label: 'Black-box agent' },
      { kind: 'no', label: 'Black-box agent' },
    ],
  },
  {
    feature: 'Detection accuracy is publicly benchmarked',
    cells: [
      { kind: 'yes', label: '200-case suite, CI-gated' },
      { kind: 'no', label: 'Not published' },
      { kind: 'no', label: 'Not published' },
      { kind: 'caveat', label: 'Vendor-claimed only' },
      { kind: 'caveat', label: 'Vendor-claimed only' },
    ],
  },
  {
    feature: 'Native AI investigation agent',
    cells: [
      { kind: 'yes', label: 'LangGraph multi-agent' },
      { kind: 'no', label: 'No' },
      { kind: 'caveat', label: 'Splunk AI Assistant add-on' },
      { kind: 'yes', label: 'Closed-source' },
      { kind: 'yes', label: 'Closed-source' },
    ],
  },
  {
    feature: 'MITRE ATT&CK heatmap + purple-team emulation',
    cells: [
      { kind: 'yes', label: 'Built-in' },
      { kind: 'caveat', label: 'Partial' },
      { kind: 'caveat', label: 'Premium add-on' },
      { kind: 'yes', label: 'Yes' },
      { kind: 'caveat', label: 'Limited' },
    ],
  },
  {
    feature: 'Plugin SDK (Python + Go) + community marketplace',
    cells: [
      { kind: 'yes', label: 'Both SDKs, MIT' },
      { kind: 'caveat', label: 'Wodles only' },
      { kind: 'yes', label: 'Splunkbase' },
      { kind: 'no', label: 'Vendor-only' },
      { kind: 'no', label: 'Vendor-only' },
    ],
  },
  {
    feature: 'Compliance evidence (SOC2 / ISO / NIST / DORA)',
    cells: [
      { kind: 'yes', label: 'Built-in dashboards' },
      { kind: 'no', label: 'No' },
      { kind: 'yes', label: 'Premium add-on' },
      { kind: 'caveat', label: 'Reporting only' },
      { kind: 'caveat', label: 'Reporting only' },
    ],
  },
];

function compareCellClass(cell: CompareCell): string {
  switch (cell.kind) {
    case 'yes':
      return styles.compareYes;
    case 'no':
      return styles.compareNo;
    case 'caveat':
      return styles.compareCaveat;
  }
}

function ComparisonTable() {
  return (
    <div className="container margin-vert--xl">
      <h2 className={styles.sectionTitle}>Why AiSOC vs. the alternatives</h2>
      <p className={styles.sectionLede}>
        The structural moat: open-source, self-hostable, with every agent decision
        auditable end-to-end. Closed-source AI SOCs run on someone else&apos;s
        infrastructure and ship a black-box agent — neither survives a serious
        compliance review.
      </p>
      <div className={styles.compareWrap}>
        <table className={styles.compareTable}>
          <thead>
            <tr>
              {COMPARE_HEADERS.map((header, idx) => (
                <th
                  key={header}
                  className={idx === 1 ? styles.aisocCol : undefined}>
                  {header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {COMPARE_ROWS.map((row) => (
              <tr key={row.feature}>
                <td>{row.feature}</td>
                {row.cells.map((cell, idx) => (
                  <td
                    key={idx}
                    className={clsx(
                      idx === 0 ? styles.aisocCell : undefined,
                      compareCellClass(cell),
                    )}>
                    {cell.label}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className={styles.compareNote}>
        Numbers and capability claims are sourced from each vendor&apos;s public
        documentation as of 2026.{' '}
        <Link to="/docs/intro">Verify ours →</Link>
      </p>
    </div>
  );
}

export default function Home(): React.JSX.Element {
  const { siteConfig } = useDocusaurusContext();
  return (
    <Layout
      title={siteConfig.title}
      description="The auditable AI SOC — every agent decision logged, replayable, and benchmarked publicly. MIT-licensed, self-hostable, with built-in UEBA, honeytokens, purple-team emulation, and SOC 2 / ISO 27001 / NIST CSF compliance.">
      <HomepageHeader />
      <main>
        <ComparisonTable />
        <div className="container margin-vert--xl">
          <h2 className={styles.sectionTitle}>What you get out of the box</h2>
          <p className={styles.sectionLede}>
            The trust trio leads — auditable agent, public benchmark, MIT
            license — backed by the full SOC substrate underneath.
          </p>
          <div className="row">
            {FEATURES.map(({ title, description }) => (
              <div key={title} className="col col--4 margin-bottom--lg">
                <div className="padding-horiz--md">
                  <h3>{title}</h3>
                  <p>{description}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </main>
    </Layout>
  );
}
