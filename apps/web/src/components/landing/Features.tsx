'use client';

import { motion } from 'framer-motion';

const FEATURES = [
  {
    title: 'Real-time correlation',
    description:
      'Stream events from any source through Kafka, fuse them with ML and rule-based detectors, and surface alerts in under 200ms.',
    icon: (
      <path d="M4 4h16v4H4zM4 10h10v4H4zM4 16h16v4H4z" />
    ),
    accent: 'from-brand-500/20 to-brand-500/0',
  },
  {
    title: 'Autonomous triage',
    description:
      'Agentic copilot enriches alerts with threat intel, identity context, and host telemetry — and explains every decision it makes.',
    icon: (
      <path d="M12 2l3 7h7l-5.5 4.5L18 21l-6-4-6 4 1.5-7.5L2 9h7z" />
    ),
    accent: 'from-amber-500/20 to-amber-500/0',
  },
  {
    title: 'MITRE ATT&CK native',
    description:
      'Detection rules, alerts, and the heatmap all map back to ATT&CK techniques. See coverage gaps in the same view as live attacks.',
    icon: (
      <path d="M3 3h7v7H3zm11 0h7v4h-7zm0 6h7v12h-7zm-11 4h7v8H3z" />
    ),
    accent: 'from-emerald-500/20 to-emerald-500/0',
  },
  {
    title: 'Attack graph that thinks',
    description:
      'Cross-source paths between identities, hosts, and assets. Pivot from any node into the hunter or open a case in one click.',
    icon: (
      <path d="M5 5a3 3 0 116 0 3 3 0 01-6 0zm8 14a3 3 0 116 0 3 3 0 01-6 0zM7.5 8l5 8" />
    ),
    accent: 'from-fuchsia-500/20 to-fuchsia-500/0',
  },
  {
    title: 'Detection-as-code',
    description:
      'Author Sigma, KQL, EQL, or YAML rules in the inline editor. Test against historical data, version with git, deploy in seconds.',
    icon: (
      <path d="M8 9l-5 3 5 3M16 9l5 3-5 3M14 5l-4 14" />
    ),
    accent: 'from-cyan-500/20 to-cyan-500/0',
  },
  {
    title: 'Connectors for everything',
    description:
      'Cloud trails, EDR, identity, network, SaaS — bring your own source. The connector framework abstracts ingest, schema, and rate limits.',
    icon: (
      <path d="M4 6h16v4H4zM4 14h10v4H4zM18 14h2v4h-2z" />
    ),
    accent: 'from-violet-500/20 to-violet-500/0',
  },
];

export function Features() {
  return (
    <section id="features" className="relative py-24 md:py-32">
      <div className="mx-auto max-w-7xl px-6">
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-100px' }}
          transition={{ duration: 0.5 }}
          className="mx-auto max-w-2xl text-center"
        >
          <span className="text-xs font-semibold uppercase tracking-wider text-brand-300">
            Platform
          </span>
          <h2 className="mt-3 text-4xl font-bold tracking-tight text-white md:text-5xl">
            A SOC that ships with batteries included
          </h2>
          <p className="mt-4 text-lg text-gray-400">
            Every layer — ingest, detection, analysis, response — is built to be inspected,
            extended, and run in your own environment.
          </p>
        </motion.div>

        <div className="mt-16 grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
          {FEATURES.map((feature, i) => (
            <motion.div
              key={feature.title}
              initial={{ opacity: 0, y: 16 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: '-80px' }}
              transition={{ duration: 0.4, delay: i * 0.04 }}
              className="group relative overflow-hidden rounded-2xl border border-white/5 bg-surface-card/50 p-6 transition hover:border-white/15 hover:bg-surface-card"
            >
              <div
                className={`pointer-events-none absolute -right-12 -top-12 h-32 w-32 rounded-full bg-gradient-to-br ${feature.accent} opacity-0 blur-2xl transition-opacity group-hover:opacity-100`}
              />
              <div className="relative">
                <div className="inline-flex h-11 w-11 items-center justify-center rounded-lg border border-white/10 bg-white/[0.04] text-brand-300">
                  <svg
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.6"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    className="h-5 w-5"
                  >
                    {feature.icon}
                  </svg>
                </div>
                <h3 className="mt-5 text-lg font-semibold text-white">{feature.title}</h3>
                <p className="mt-2 text-sm leading-relaxed text-gray-400">{feature.description}</p>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}
