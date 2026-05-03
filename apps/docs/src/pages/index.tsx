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

export default function Home(): React.JSX.Element {
  const { siteConfig } = useDocusaurusContext();
  return (
    <Layout
      title={siteConfig.title}
      description="Open-source AI Security Operations Center">
      <HomepageHeader />
      <main>
        <div className="container margin-vert--xl">
          <div className="row">
            {[
              {
                title: '🔍 AI Investigation',
                description:
                  'LangGraph-powered multi-agent workflows for automated root-cause analysis and triage.',
              },
              {
                title: '📋 Playbook Engine',
                description:
                  'Visual React Flow editor with 12+ starter templates for automated response.',
              },
              {
                title: '🔌 Plugin SDK',
                description:
                  'Build custom enrichers, actions, and connectors in Python or Go.',
              },
            ].map(({ title, description }) => (
              <div key={title} className="col col--4">
                <div className="text--center padding-horiz--md margin-bottom--lg">
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
