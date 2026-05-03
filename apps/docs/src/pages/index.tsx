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

const FEATURES = [
  {
    title: '🔍 AI Investigation',
    description:
      'LangGraph multi-agent workflows for automated root-cause analysis, triage, and case enrichment.',
  },
  {
    title: '📋 Playbook Engine',
    description:
      'Visual React Flow editor with 12+ starter templates for automated, auditable response actions.',
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
    title: '⚡ Real-time Fusion',
    description:
      'Kafka spine with sub-second alert ingestion, Bloom-filter dedup on 10M+ IOCs, ML scoring (LightGBM + Isolation Forest).',
  },
  {
    title: '🕸️ Attack Graph',
    description:
      'Neo4j entity graph with attack-path reconstruction and blast-radius gating on automated actions.',
  },
  {
    title: '🛡️ Detection Engineering',
    description:
      'Sigma over OpenSearch + ClickHouse, YARA, KQL/EQL — community catalog with one-click install.',
  },
  {
    title: '🏛️ Enterprise Governance',
    description:
      'SAML 2.0 + OIDC SSO, multi-tenant Postgres RLS, granular RBAC, and immutable audit log.',
  },
  {
    title: '📊 Compliance Dashboards',
    description:
      'SOC 2, ISO 27001, NIST CSF, PCI-DSS, HIPAA, DORA evidence with MTTD/MTTR/MTTC SLA tracking.',
  },
  {
    title: '🔌 Plugin Ecosystem',
    description:
      'Python and TypeScript SDKs, Ed25519-signed publishing, and a community marketplace.',
  },
  {
    title: '🚀 Cloud-Native',
    description:
      'Helm charts, Docker Compose, OpenTelemetry traces/metrics/logs, and PostgreSQL backup with KMS encryption.',
  },
];

export default function Home(): React.JSX.Element {
  const { siteConfig } = useDocusaurusContext();
  return (
    <Layout
      title={siteConfig.title}
      description="Open-source AI SOC — autonomous detection, investigation, and response with UEBA, honeytokens, purple-team emulation, and SOC 2 / ISO 27001 / NIST CSF compliance.">
      <HomepageHeader />
      <main>
        <div className="container margin-vert--xl">
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
