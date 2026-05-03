'use client';

import { motion } from 'framer-motion';

const PILLARS = [
  {
    title: 'MIT licensed',
    body: 'Use it in production, fork it, sell services around it. No CLA, no telemetry, no calls home.',
  },
  {
    title: 'Self-hosted by default',
    body: 'docker compose up gets you the full stack on your own hardware. Managed cloud is optional, never required.',
  },
  {
    title: 'Auditable end-to-end',
    body: 'Every detection, every copilot decision, every connector action is logged with inputs, prompts, and rationale.',
  },
  {
    title: 'Backed by Cyble',
    body: 'Maintained by the threat intelligence team at Cyble. Security disclosures get a fast, real, human response.',
  },
];

export function OpenSource() {
  return (
    <section id="open-source" className="relative py-24 md:py-32">
      <div className="mx-auto max-w-7xl px-6">
        <div className="relative overflow-hidden rounded-3xl border border-white/10 bg-gradient-to-br from-surface-card to-surface-base p-8 md:p-12">
          {/* Soft glow */}
          <div className="pointer-events-none absolute -right-32 -top-32 h-96 w-96 rounded-full bg-brand-500/10 blur-3xl" />
          <div className="pointer-events-none absolute -bottom-32 -left-32 h-96 w-96 rounded-full bg-amber-500/10 blur-3xl" />

          <div className="relative grid grid-cols-1 gap-10 lg:grid-cols-[1.1fr_1fr] lg:items-start">
            <motion.div
              initial={{ opacity: 0, y: 16 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: '-100px' }}
              transition={{ duration: 0.5 }}
            >
              <span className="text-xs font-semibold uppercase tracking-wider text-brand-300">
                Open source · MIT
              </span>
              <h2 className="mt-3 text-3xl font-bold tracking-tight text-white md:text-5xl">
                Built in the open. Owned by you.
              </h2>
              <p className="mt-5 max-w-xl text-lg leading-relaxed text-gray-400">
                AiSOC is the SOC platform we wished existed — modern, AI-native, and free. No
                runtime fees. No vendor lock-in. No artificial gates between &ldquo;community&rdquo;
                and &ldquo;enterprise&rdquo; editions.
              </p>

              <div className="mt-8 flex flex-wrap gap-3">
                <a
                  href="https://github.com/beenuar/AiSOC"
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-2 rounded-lg bg-white px-5 py-3 text-sm font-semibold text-gray-900 transition hover:bg-gray-100"
                >
                  <svg viewBox="0 0 24 24" className="h-4 w-4" aria-hidden="true" fill="currentColor">
                    <path d="M12 .5C5.65.5.5 5.65.5 12c0 5.08 3.29 9.39 7.86 10.91.58.11.79-.25.79-.56 0-.28-.01-1.02-.02-2-3.2.69-3.88-1.54-3.88-1.54-.52-1.32-1.27-1.67-1.27-1.67-1.04-.71.08-.69.08-.69 1.15.08 1.76 1.18 1.76 1.18 1.02 1.75 2.68 1.24 3.34.95.1-.74.4-1.24.73-1.53-2.55-.29-5.24-1.28-5.24-5.69 0-1.26.45-2.29 1.18-3.1-.12-.29-.51-1.46.11-3.05 0 0 .96-.31 3.15 1.18a10.9 10.9 0 015.74 0c2.19-1.49 3.15-1.18 3.15-1.18.62 1.59.23 2.76.11 3.05.74.81 1.18 1.84 1.18 3.1 0 4.42-2.7 5.39-5.27 5.68.41.36.78 1.06.78 2.14 0 1.55-.01 2.79-.01 3.17 0 .31.21.68.8.56C20.21 21.39 23.5 17.08 23.5 12 23.5 5.65 18.35.5 12 .5z" />
                  </svg>
                  github.com/beenuar/AiSOC
                </a>
                <a
                  href="https://github.com/beenuar/AiSOC#quickstart"
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-2 rounded-lg border border-white/15 bg-white/[0.04] px-5 py-3 text-sm font-semibold text-gray-200 transition hover:border-white/30 hover:bg-white/[0.08]"
                >
                  Quickstart
                  <svg viewBox="0 0 20 20" className="h-3.5 w-3.5" fill="currentColor" aria-hidden="true">
                    <path d="M7.05 4.05a1 1 0 011.41 0l5 5a1 1 0 010 1.41l-5 5a1 1 0 11-1.41-1.41L11.09 10 7.05 5.46a1 1 0 010-1.41z" />
                  </svg>
                </a>
              </div>

              {/* Quickstart code */}
              <div className="mt-8 overflow-hidden rounded-xl border border-white/10 bg-black/40 font-mono text-xs">
                <div className="flex items-center gap-2 border-b border-white/5 px-4 py-2 text-[10px] uppercase tracking-wider text-gray-500">
                  <span className="h-2 w-2 rounded-full bg-rose-400/70" />
                  <span className="h-2 w-2 rounded-full bg-amber-400/70" />
                  <span className="h-2 w-2 rounded-full bg-emerald-400/70" />
                  <span className="ml-2">terminal</span>
                </div>
                <pre className="overflow-x-auto px-4 py-3 text-gray-300">
                  <span className="text-gray-500">$ </span>
                  <span className="text-emerald-300">git clone</span> https://github.com/beenuar/AiSOC{'\n'}
                  <span className="text-gray-500">$ </span>
                  <span className="text-emerald-300">cd</span> aisoc && <span className="text-emerald-300">make</span> up{'\n'}
                  <span className="text-gray-500">$ </span>
                  <span className="text-emerald-300">pnpm</span> seed:demo{'\n'}
                  <span className="text-brand-300">›</span> Console ready at{' '}
                  <span className="underline">http://localhost:3000</span>
                </pre>
              </div>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 16 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: '-100px' }}
              transition={{ duration: 0.5, delay: 0.1 }}
              className="grid grid-cols-1 gap-3 sm:grid-cols-2"
            >
              {PILLARS.map((p) => (
                <div
                  key={p.title}
                  className="rounded-xl border border-white/5 bg-white/[0.02] p-5 backdrop-blur"
                >
                  <div className="flex items-center gap-2">
                    <span className="inline-flex h-6 w-6 items-center justify-center rounded-md bg-brand-500/20 text-brand-200">
                      <svg
                        viewBox="0 0 20 20"
                        className="h-3.5 w-3.5"
                        fill="currentColor"
                        aria-hidden="true"
                      >
                        <path d="M7.629 14.571l-3.2-3.2a1 1 0 111.414-1.414l2.493 2.493 6.493-6.493a1 1 0 011.414 1.414l-7.2 7.2a1 1 0 01-1.414 0z" />
                      </svg>
                    </span>
                    <h3 className="text-sm font-semibold text-white">{p.title}</h3>
                  </div>
                  <p className="mt-2 text-sm leading-relaxed text-gray-400">{p.body}</p>
                </div>
              ))}
            </motion.div>
          </div>
        </div>
      </div>
    </section>
  );
}
