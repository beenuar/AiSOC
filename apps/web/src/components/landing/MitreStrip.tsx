'use client';

import { motion } from 'framer-motion';

// A compact MITRE-coverage band. Not a real heatmap (the console has the real
// thing) — this is an at-a-glance proof-of-coverage strip for marketing.
const TACTICS = [
  { id: 'TA0001', name: 'Initial Access', covered: 9, total: 11 },
  { id: 'TA0002', name: 'Execution', covered: 12, total: 14 },
  { id: 'TA0003', name: 'Persistence', covered: 14, total: 19 },
  { id: 'TA0004', name: 'Priv. Escalation', covered: 11, total: 13 },
  { id: 'TA0005', name: 'Defense Evasion', covered: 27, total: 42 },
  { id: 'TA0006', name: 'Credential Access', covered: 14, total: 17 },
  { id: 'TA0007', name: 'Discovery', covered: 19, total: 30 },
  { id: 'TA0008', name: 'Lateral Movement', covered: 8, total: 9 },
  { id: 'TA0009', name: 'Collection', covered: 10, total: 17 },
  { id: 'TA0011', name: 'C&C', covered: 12, total: 16 },
  { id: 'TA0010', name: 'Exfiltration', covered: 7, total: 9 },
  { id: 'TA0040', name: 'Impact', covered: 10, total: 13 },
];

function toneFor(ratio: number) {
  if (ratio >= 0.85) return 'bg-emerald-500/30 border-emerald-400/40';
  if (ratio >= 0.65) return 'bg-amber-500/25 border-amber-400/40';
  if (ratio >= 0.45) return 'bg-orange-500/25 border-orange-400/40';
  return 'bg-rose-500/25 border-rose-400/40';
}

export function MitreStrip() {
  return (
    <section id="mitre" className="relative py-24">
      <div className="mx-auto max-w-7xl px-6">
        <div className="grid grid-cols-1 gap-10 lg:grid-cols-[1fr_1.4fr] lg:items-center">
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: '-100px' }}
            transition={{ duration: 0.5 }}
          >
            <span className="text-xs font-semibold uppercase tracking-wider text-brand-300">
              MITRE ATT&CK
            </span>
            <h2 className="mt-3 text-3xl font-bold tracking-tight text-white md:text-4xl">
              Coverage you can prove
            </h2>
            <p className="mt-4 text-lg text-gray-400">
              Every detection rule and every alert ties back to ATT&CK techniques. The full heatmap
              lives inside the console — this strip is just the headline.
            </p>
            <div className="mt-6 flex flex-wrap gap-3 text-xs">
              <Legend tone="bg-emerald-500/30 border-emerald-400/40" label="≥ 85% covered" />
              <Legend tone="bg-amber-500/25 border-amber-400/40" label="65-84%" />
              <Legend tone="bg-orange-500/25 border-orange-400/40" label="45-64%" />
              <Legend tone="bg-rose-500/25 border-rose-400/40" label="< 45%" />
            </div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 16 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: '-100px' }}
            transition={{ duration: 0.5, delay: 0.1 }}
            className="rounded-2xl border border-white/5 bg-surface-card/50 p-5"
          >
            <div className="grid grid-cols-3 gap-2 sm:grid-cols-4 lg:grid-cols-3 xl:grid-cols-4">
              {TACTICS.map((t) => {
                const ratio = t.covered / t.total;
                return (
                  <div
                    key={t.id}
                    className={`relative overflow-hidden rounded-lg border p-3 ${toneFor(ratio)}`}
                  >
                    <div className="font-mono text-[10px] uppercase tracking-wider text-white/70">
                      {t.id}
                    </div>
                    <div className="mt-1 text-sm font-semibold text-white">{t.name}</div>
                    <div className="mt-2 flex items-baseline gap-1.5 text-xs text-white/80">
                      <span className="font-mono text-base font-bold text-white">
                        {t.covered}
                      </span>
                      <span className="text-white/50">/ {t.total}</span>
                    </div>
                    <div className="mt-2 h-1 overflow-hidden rounded-full bg-white/10">
                      <div
                        className="h-full bg-white/70"
                        style={{ width: `${Math.round(ratio * 100)}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
}

function Legend({ tone, label }: { tone: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-2 text-gray-400">
      <span className={`h-3 w-3 rounded border ${tone}`} />
      {label}
    </span>
  );
}
