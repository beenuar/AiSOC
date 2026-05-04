'use client';

import { motion } from 'framer-motion';

const FEATURES = [
  {
    title: 'Streaming correlation',
    description:
      'Events flow through Kafka into rule- and ML-based detectors. Latency depends on deployment size; on the demo stack alerts typically surface in well under a second.',
    icon: (
      <path d="M4 4h16v4H4zM4 10h10v4H4zM4 16h16v4H4z" />
    ),
  },
  {
    title: 'Agent-assisted triage',
    description:
      'The copilot enriches alerts with threat intel, identity context and host telemetry, and records the prompts and rationale behind each decision.',
    icon: (
      <path d="M12 2l3 7h7l-5.5 4.5L18 21l-6-4-6 4 1.5-7.5L2 9h7z" />
    ),
  },
  {
    title: 'MITRE ATT&CK mapping',
    description:
      'Detection rules, alerts and the coverage heatmap reference ATT&CK techniques, so coverage gaps show up alongside live activity.',
    icon: (
      <path d="M3 3h7v7H3zm11 0h7v4h-7zm0 6h7v12h-7zm-11 4h7v8H3z" />
    ),
  },
  {
    title: 'Attack graph',
    description:
      'A graph view links identities, hosts and assets, with pivots into the hunter and case views.',
    icon: (
      <path d="M5 5a3 3 0 116 0 3 3 0 01-6 0zm8 14a3 3 0 116 0 3 3 0 01-6 0zM7.5 8l5 8" />
    ),
  },
  {
    title: 'Detection-as-code',
    description:
      'Sigma, KQL, EQL and YAML rules can be authored in the inline editor, tested against historical data and version-controlled in Git.',
    icon: (
      <path d="M8 9l-5 3 5 3M16 9l5 3-5 3M14 5l-4 14" />
    ),
  },
  {
    title: 'Pluggable connectors',
    description:
      'A connector framework handles ingest, schema mapping and rate limits for cloud trails, EDR, identity, network and SaaS sources.',
    icon: (
      <path d="M4 6h16v4H4zM4 14h10v4H4zM18 14h2v4h-2z" />
    ),
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
            What is in the box
          </h2>
          <p className="mt-4 text-lg text-gray-400">
            Ingest, detection, analysis and response are separate services that can be inspected,
            extended and run in your own environment.
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
