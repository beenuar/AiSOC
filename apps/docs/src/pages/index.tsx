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
            Get started
          </Link>
          <Link
            className="button button--outline button--secondary button--lg"
            href="https://github.com/beenuar/AiSOC">
            GitHub
          </Link>
        </div>
      </div>
    </header>
  );
}

// Feature list. The first three rows describe the properties most relevant to a
// regulated buyer (auditable agent, published eval harness, license posture);
// the rest enumerate the substrate capabilities that ship in the box.
const FEATURES = [
  {
    title: 'Auditable agent decisions',
    description:
      'Every prompt, tool call, and rationale the agent emits is persisted to the investigation ledger and replayable step-by-step in the case workspace.',
  },
  {
    title: 'Public eval harness',
    description:
      '200-incident, CI-gated regression harness over the AiSOC substrate (extractors, fusion, templates, judges). Reproducible on a laptop in seconds. The page describes what each metric measures and what it does not.',
  },
  {
    title: 'MIT-licensed, self-hostable',
    description:
      'The code, prompts, and templates are in the repo. No CLA, no telemetry, no calls home.',
  },
  {
    title: 'LangGraph multi-agent investigation',
    description:
      'Recon, forensic, responder, and reporter agents wired through a LangGraph orchestrator for triage and case enrichment.',
  },
  {
    title: 'Playbook engine',
    description:
      'Visual React Flow editor with 12 starter templates for automated, human-gated response actions.',
  },
  {
    title: 'UEBA',
    description:
      'Per-user Welford online baselines, Z-score anomaly scoring, and Kafka-integrated anomaly publishing.',
  },
  {
    title: 'Honeytokens',
    description:
      'HMAC-SHA256 signed deceptive credentials (URL, file, AWS key, email) with first-touch webhook alerting.',
  },
  {
    title: 'Purple Team',
    description:
      'Atomic Red Team YAML parser, Caldera executor, ATT&CK coverage heatmap, and tabletop sessions.',
  },
  {
    title: 'Real-time fusion',
    description:
      'Kafka spine with sub-second alert ingestion, Bloom-filter dedup on 10M+ IOCs, ML scoring (LightGBM + Isolation Forest).',
  },
  {
    title: 'Attack graph',
    description:
      'Neo4j entity graph with attack-path reconstruction and blast-radius gating on automated actions.',
  },
  {
    title: 'Detection engineering',
    description:
      'Sigma over OpenSearch and ClickHouse, YARA, KQL/EQL — community catalog with one-click install.',
  },
  {
    title: 'Enterprise governance',
    description:
      'SAML 2.0 and OIDC SSO, multi-tenant Postgres RLS, granular RBAC, and immutable audit log.',
  },
  {
    title: 'Compliance dashboards',
    description:
      'SOC 2, ISO 27001, NIST CSF, PCI-DSS, HIPAA, and DORA evidence with MTTD/MTTR/MTTC SLA tracking.',
  },
  {
    title: 'Plugin ecosystem',
    description:
      'Python and TypeScript SDKs, Ed25519-signed publishing, and a community marketplace.',
  },
  {
    title: 'Deployment',
    description:
      'Helm charts, Docker Compose, OpenTelemetry traces/metrics/logs, and PostgreSQL backup with KMS encryption.',
  },
];

// Comparison rows are concrete, defensible capability claims. Each row maps to
// something a buyer can verify in the repo or in vendor documentation.
type CompareCell = { kind: 'yes' | 'no' | 'caveat'; label: string };

const COMPARE_HEADERS = [
  'Capability',
  'AiSOC',
  'Wazuh',
  'Splunk Enterprise Security',
  'Closed-source AI SOC',
] as const;

const COMPARE_ROWS: ReadonlyArray<{ feature: string; cells: CompareCell[] }> = [
  {
    feature: 'Open-source (MIT) and self-hostable',
    cells: [
      { kind: 'yes', label: 'Yes — MIT' },
      { kind: 'yes', label: 'Yes — GPLv2' },
      { kind: 'no', label: 'No' },
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
    ],
  },
  {
    feature: 'Substrate has a public regression-gate harness',
    cells: [
      { kind: 'yes', label: '200-case suite, CI-gated' },
      { kind: 'no', label: 'Not published' },
      { kind: 'no', label: 'Not published' },
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
    ],
  },
  {
    feature: 'MITRE ATT&CK heatmap + purple-team emulation',
    cells: [
      { kind: 'yes', label: 'Built-in' },
      { kind: 'caveat', label: 'Partial' },
      { kind: 'caveat', label: 'Premium add-on' },
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
    ],
  },
  {
    feature: 'Compliance evidence (SOC2 / ISO / NIST / DORA)',
    cells: [
      { kind: 'yes', label: 'Built-in dashboards' },
      { kind: 'no', label: 'No' },
      { kind: 'yes', label: 'Premium add-on' },
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
      <h2 className={styles.sectionTitle}>How AiSOC compares</h2>
      <p className={styles.sectionLede}>
        AiSOC is open-source and self-hostable, and every agent decision is
        recorded in the investigation ledger. Closed-source AI SOCs run on
        vendor infrastructure and do not expose the agent loop, which makes
        them harder to review under SOC 2, ISO 27001, or DORA controls.
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
        Capability claims for other vendors are sourced from their public
        documentation as of 2026. AiSOC&apos;s claims map directly to code in
        this repository — see <Link to="/docs/intro">the docs</Link>.
      </p>
    </div>
  );
}

export default function Home(): React.JSX.Element {
  const { siteConfig } = useDocusaurusContext();
  return (
    <Layout
      title={siteConfig.title}
      description="An open-source AI SOC platform. Agent decisions are recorded in an investigation ledger and a public eval harness is run on every PR targeting main / develop. MIT-licensed and self-hostable, with built-in UEBA, honeytokens, purple-team emulation, and SOC 2 / ISO 27001 / NIST CSF compliance reporting.">
      <HomepageHeader />
      <main>
        <ComparisonTable />
        <div className="container margin-vert--xl">
          <h2 className={styles.sectionTitle}>What ships in the box</h2>
          <p className={styles.sectionLede}>
            The first three rows describe the properties most relevant to a
            regulated buyer. The remainder enumerate the SOC substrate.
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
