'use client';

import { motion } from 'framer-motion';

const LAYERS = [
  {
    label: 'Sources',
    items: ['Cloud trails', 'EDR', 'Identity', 'Network', 'SaaS APIs', 'Custom'],
    tone: 'border-brand-500/30 bg-brand-500/5 text-brand-100',
  },
  {
    label: 'Ingest',
    items: ['Kafka topics', 'Connector framework', 'Schema normalisation'],
    tone: 'border-cyan-500/30 bg-cyan-500/5 text-cyan-100',
  },
  {
    label: 'Detect & enrich',
    items: ['Sigma / KQL / EQL', 'ML correlator', 'Threat intel', 'Identity graph'],
    tone: 'border-amber-500/30 bg-amber-500/5 text-amber-100',
  },
  {
    label: 'Reason',
    items: ['Agentic copilot', 'Attack graph', 'MITRE mapper', 'Case builder'],
    tone: 'border-fuchsia-500/30 bg-fuchsia-500/5 text-fuchsia-100',
  },
  {
    label: 'Respond',
    items: ['Playbooks', 'Connector actions', 'Webhooks', 'Audit trail'],
    tone: 'border-emerald-500/30 bg-emerald-500/5 text-emerald-100',
  },
];

const STORES = [
  { name: 'PostgreSQL', use: 'metadata' },
  { name: 'ClickHouse', use: 'events' },
  { name: 'OpenSearch', use: 'search' },
  { name: 'Neo4j', use: 'graph' },
  { name: 'Qdrant', use: 'embeddings' },
  { name: 'Redis', use: 'cache' },
];

export function Architecture() {
  return (
    <section id="architecture" className="relative py-24 md:py-32">
      <div className="absolute inset-x-0 top-0 -z-10 h-px bg-gradient-to-r from-transparent via-white/10 to-transparent" />
      <div className="mx-auto max-w-7xl px-6">
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-100px' }}
          transition={{ duration: 0.5 }}
          className="mx-auto max-w-2xl text-center"
        >
          <span className="text-xs font-semibold uppercase tracking-wider text-brand-300">
            How it works
          </span>
          <h2 className="mt-3 text-4xl font-bold tracking-tight text-white md:text-5xl">
            One pipeline, end to end
          </h2>
          <p className="mt-4 text-lg text-gray-400">
            Every box is a service you can swap, scale, or replace. No black boxes, no licenses,
            no per-seat traps.
          </p>
        </motion.div>

        {/* Pipeline */}
        <div className="mt-16 grid grid-cols-1 gap-3 lg:grid-cols-5">
          {LAYERS.map((layer, i) => (
            <motion.div
              key={layer.label}
              initial={{ opacity: 0, y: 12 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: '-80px' }}
              transition={{ duration: 0.4, delay: i * 0.06 }}
              className={`relative rounded-xl border bg-surface-card/40 p-4 ${layer.tone}`}
            >
              <div className="text-[10px] font-bold uppercase tracking-widest opacity-80">
                Stage {i + 1}
              </div>
              <div className="mt-1 text-base font-semibold text-white">{layer.label}</div>
              <ul className="mt-3 space-y-1 text-xs text-gray-300">
                {layer.items.map((item) => (
                  <li key={item} className="flex items-center gap-2">
                    <span className="h-1 w-1 rounded-full bg-current opacity-60" />
                    {item}
                  </li>
                ))}
              </ul>
              {i < LAYERS.length - 1 && (
                <div className="absolute -right-3 top-1/2 hidden h-px w-6 -translate-y-1/2 bg-gradient-to-r from-white/30 to-transparent lg:block" />
              )}
            </motion.div>
          ))}
        </div>

        {/* Storage tier */}
        <div className="mt-10 rounded-2xl border border-white/5 bg-surface-card/40 p-6">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-xs font-semibold uppercase tracking-wider text-gray-400">
                Storage tier
              </div>
              <div className="mt-1 text-sm text-gray-300">
                Polyglot persistence — pick the right store for each workload.
              </div>
            </div>
            <span className="hidden text-xs text-gray-500 md:block">
              All open source, all containerised
            </span>
          </div>
          <div className="mt-5 flex flex-wrap gap-2">
            {STORES.map((s) => (
              <span
                key={s.name}
                className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.04] px-3 py-1.5 text-xs"
              >
                <span className="font-mono font-semibold text-white">{s.name}</span>
                <span className="text-gray-500">·</span>
                <span className="text-gray-400">{s.use}</span>
              </span>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
