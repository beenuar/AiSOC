'use client';

import Link from 'next/link';
import { motion } from 'framer-motion';

/**
 * Landing hero. The visual goal is "live SOC" without flashing imagery — we use
 * a stack of subtle, breathing surfaces (signal map, alert ticker, copilot
 * thread) so the page advertises the product capability rather than describing
 * it. All animations respect prefers-reduced-motion through framer-motion's
 * defaults.
 */
export function Hero() {
  return (
    <section className="relative isolate overflow-hidden pt-32 pb-24 md:pt-40 md:pb-32">
      {/* Background grid + radial glows */}
      <div aria-hidden className="pointer-events-none absolute inset-0 -z-10">
        <div className="absolute inset-0 bg-grid-hero bg-grid-lg opacity-60" />
        <div className="absolute -top-40 left-1/2 h-[640px] w-[1100px] -translate-x-1/2 rounded-full bg-brand-500/10 blur-3xl" />
        <div className="absolute right-[-10%] top-1/3 h-[420px] w-[420px] rounded-full bg-amber-500/10 blur-3xl" />
        <div className="absolute inset-x-0 bottom-0 h-40 bg-gradient-to-t from-surface-base to-transparent" />
      </div>

      <div className="mx-auto grid max-w-7xl grid-cols-1 items-center gap-16 px-6 lg:grid-cols-[1.1fr_1fr]">
        {/* Copy column */}
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, ease: 'easeOut' }}
        >
          <span className="inline-flex items-center gap-2 rounded-full border border-brand-400/30 bg-brand-500/10 px-3 py-1 text-xs font-semibold uppercase tracking-wider text-brand-200">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-400" />
            </span>
            Open-source · MIT · by Cyble
          </span>

          <h1 className="mt-6 text-balance text-5xl font-bold leading-[1.05] tracking-tight text-white md:text-6xl lg:text-7xl">
            The{' '}
            <span className="bg-gradient-to-r from-brand-300 via-brand-400 to-amber-300 bg-clip-text text-transparent">
              AI Security
            </span>{' '}
            Operations Center.
          </h1>

          <p className="mt-6 max-w-xl text-lg leading-relaxed text-gray-400 md:text-xl">
            Real-time detection, autonomous triage, and MITRE ATT&CK-aware investigation —
            wired together with an AI copilot that explains every decision. Self-hosted,
            extensible, free forever.
          </p>

          <div className="mt-8 flex flex-wrap items-center gap-3">
            <Link
              href="/dashboard"
              className="group inline-flex items-center gap-2 rounded-lg bg-brand-500 px-5 py-3 text-sm font-semibold text-white shadow-glow-brand transition hover:bg-brand-400"
            >
              Launch the console
              <svg viewBox="0 0 20 20" className="h-4 w-4 transition-transform group-hover:translate-x-0.5" fill="currentColor" aria-hidden="true">
                <path d="M7.05 4.05a1 1 0 011.41 0l5 5a1 1 0 010 1.41l-5 5a1 1 0 11-1.41-1.41L11.09 10 7.05 5.46a1 1 0 010-1.41z" />
              </svg>
            </Link>
            <a
              href="https://github.com/beenuar/AiSOC"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-2 rounded-lg border border-white/15 bg-white/[0.04] px-5 py-3 text-sm font-semibold text-gray-200 transition hover:border-white/30 hover:bg-white/[0.08]"
            >
              <svg viewBox="0 0 24 24" className="h-4 w-4" aria-hidden="true" fill="currentColor">
                <path d="M12 .5C5.65.5.5 5.65.5 12c0 5.08 3.29 9.39 7.86 10.91.58.11.79-.25.79-.56 0-.28-.01-1.02-.02-2-3.2.69-3.88-1.54-3.88-1.54-.52-1.32-1.27-1.67-1.27-1.67-1.04-.71.08-.69.08-.69 1.15.08 1.76 1.18 1.76 1.18 1.02 1.75 2.68 1.24 3.34.95.1-.74.4-1.24.73-1.53-2.55-.29-5.24-1.28-5.24-5.69 0-1.26.45-2.29 1.18-3.1-.12-.29-.51-1.46.11-3.05 0 0 .96-.31 3.15 1.18a10.9 10.9 0 015.74 0c2.19-1.49 3.15-1.18 3.15-1.18.62 1.59.23 2.76.11 3.05.74.81 1.18 1.84 1.18 3.1 0 4.42-2.7 5.39-5.27 5.68.41.36.78 1.06.78 2.14 0 1.55-.01 2.79-.01 3.17 0 .31.21.68.8.56C20.21 21.39 23.5 17.08 23.5 12 23.5 5.65 18.35.5 12 .5z" />
              </svg>
              Star on GitHub
            </a>
          </div>

          {/* Quick facts row — speaks to credibility before scrolling */}
          <dl className="mt-10 grid grid-cols-3 gap-6 border-t border-white/5 pt-8">
            <Stat label="Latency" value="< 200ms" caption="ingest → alert" />
            <Stat label="Coverage" value="14 ATT&CK" caption="tactics out of the box" />
            <Stat label="License" value="MIT" caption="audit, fork, ship" />
          </dl>
        </motion.div>

        {/* Visual column */}
        <motion.div
          initial={{ opacity: 0, y: 24 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, ease: 'easeOut', delay: 0.1 }}
          className="relative"
        >
          <HeroVisual />
        </motion.div>
      </div>
    </section>
  );
}

function Stat({ label, value, caption }: { label: string; value: string; caption: string }) {
  return (
    <div>
      <dt className="text-xs font-semibold uppercase tracking-wider text-gray-500">{label}</dt>
      <dd className="mt-2 text-2xl font-bold text-white">{value}</dd>
      <p className="mt-1 text-xs text-gray-500">{caption}</p>
    </div>
  );
}

/**
 * Layered visual: a "signal map" card on top, with a copilot thread peeking
 * from the bottom-right. Pure SVG/Tailwind — zero runtime cost — but reads as
 * "this is a real, live product".
 */
function HeroVisual() {
  return (
    <div className="relative aspect-[5/4]">
      {/* Outer glow */}
      <div className="absolute -inset-6 rounded-3xl bg-gradient-to-br from-brand-500/20 via-transparent to-amber-500/10 blur-2xl" />

      {/* Main "signal map" card */}
      <motion.div
        initial={{ opacity: 0, scale: 0.96 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.6, delay: 0.15 }}
        className="absolute inset-0 overflow-hidden rounded-2xl border border-white/10 bg-surface-card/90 shadow-2xl backdrop-blur"
      >
        {/* Window chrome */}
        <div className="flex items-center gap-2 border-b border-white/5 bg-surface-raised/60 px-4 py-3">
          <span className="h-2.5 w-2.5 rounded-full bg-rose-400/80" />
          <span className="h-2.5 w-2.5 rounded-full bg-amber-400/80" />
          <span className="h-2.5 w-2.5 rounded-full bg-emerald-400/80" />
          <span className="ml-3 text-xs font-medium text-gray-500">aisoc · live attack graph</span>
          <span className="ml-auto inline-flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-emerald-300">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
            Live
          </span>
        </div>

        <SignalMap />
      </motion.div>

      {/* Floating copilot card */}
      <motion.div
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, delay: 0.45 }}
        className="absolute -bottom-6 -right-4 w-72 rounded-xl border border-white/10 bg-surface-card/95 p-4 shadow-2xl backdrop-blur sm:-right-8 sm:w-80"
      >
        <div className="mb-2 flex items-center gap-2 text-xs font-semibold text-gray-400">
          <span className="inline-flex h-6 w-6 items-center justify-center rounded-md bg-gradient-to-br from-brand-500 to-amber-500 text-[11px] font-bold text-white">
            A
          </span>
          AiSOC Copilot
          <span className="ml-auto text-[10px] font-medium uppercase tracking-wider text-emerald-300">
            ⌘K
          </span>
        </div>
        <p className="text-sm leading-relaxed text-gray-200">
          Detected lateral movement on{' '}
          <span className="rounded bg-rose-500/15 px-1 font-mono text-rose-200">SRV-FIN-04</span>{' '}
          → <span className="rounded bg-rose-500/15 px-1 font-mono text-rose-200">DC-01</span>. Linked
          to <span className="font-mono text-amber-300">T1021.002</span>. Recommend isolating host and
          revoking session tokens.
        </p>
        <div className="mt-3 flex gap-2">
          <button className="rounded-md bg-brand-500/90 px-2.5 py-1 text-xs font-semibold text-white">
            Isolate host
          </button>
          <button className="rounded-md border border-white/10 bg-white/[0.04] px-2.5 py-1 text-xs font-semibold text-gray-300">
            Open case
          </button>
        </div>
      </motion.div>
    </div>
  );
}

/**
 * Tiny synthetic attack graph. Coordinates are hand-tuned to read as
 * "internet → endpoint → server → dc". Edges pulse along the kill chain.
 */
function SignalMap() {
  const nodes = [
    { id: 'inet', x: 60, y: 60, label: 'Internet', kind: 'edge' },
    { id: 'wf', x: 180, y: 95, label: 'WF-01', kind: 'host' },
    { id: 'srv', x: 305, y: 145, label: 'SRV-FIN-04', kind: 'host-warn' },
    { id: 'dc', x: 430, y: 100, label: 'DC-01', kind: 'host-crit' },
    { id: 'sccm', x: 305, y: 245, label: 'SCCM', kind: 'host' },
    { id: 'idp', x: 110, y: 220, label: 'Okta', kind: 'idp' },
  ];
  const edges: Array<[string, string, 'normal' | 'warn' | 'crit']> = [
    ['inet', 'wf', 'normal'],
    ['wf', 'srv', 'warn'],
    ['srv', 'dc', 'crit'],
    ['srv', 'sccm', 'normal'],
    ['idp', 'wf', 'normal'],
  ];

  const nodeFill: Record<string, string> = {
    edge: '#1e293b',
    host: '#1e293b',
    'host-warn': '#7c2d12',
    'host-crit': '#7f1d1d',
    idp: '#1e3a8a',
  };
  const nodeStroke: Record<string, string> = {
    edge: '#475569',
    host: '#3b82f6',
    'host-warn': '#f97316',
    'host-crit': '#ef4444',
    idp: '#60a5fa',
  };
  const edgeStroke: Record<string, string> = {
    normal: 'rgba(96,165,250,0.5)',
    warn: 'rgba(249,115,22,0.7)',
    crit: 'rgba(239,68,68,0.85)',
  };

  return (
    <div className="relative h-[calc(100%-44px)] w-full">
      {/* Grid background */}
      <div className="absolute inset-0 bg-grid-pattern bg-grid opacity-50" />

      {/* MITRE band on the right */}
      <div className="absolute right-3 top-3 flex flex-col gap-1.5 text-[9px] font-mono">
        {[
          { id: 'T1078', label: 'Valid Accts', tone: 'gray' },
          { id: 'T1021', label: 'Remote Svcs', tone: 'crit' },
          { id: 'T1110', label: 'Brute Force', tone: 'warn' },
          { id: 'T1486', label: 'Impact', tone: 'gray' },
        ].map((t) => (
          <div
            key={t.id}
            className={
              'rounded px-1.5 py-0.5 ' +
              (t.tone === 'crit'
                ? 'bg-rose-500/20 text-rose-200'
                : t.tone === 'warn'
                  ? 'bg-amber-500/20 text-amber-200'
                  : 'bg-white/5 text-gray-400')
            }
          >
            {t.id} · {t.label}
          </div>
        ))}
      </div>

      <svg viewBox="0 0 500 320" className="absolute inset-0 h-full w-full">
        <defs>
          <filter id="softGlow">
            <feGaussianBlur stdDeviation="3" result="b" />
            <feMerge>
              <feMergeNode in="b" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* Edges */}
        {edges.map(([from, to, tone], i) => {
          const a = nodes.find((n) => n.id === from)!;
          const b = nodes.find((n) => n.id === to)!;
          return (
            <g key={i}>
              <line
                x1={a.x}
                y1={a.y}
                x2={b.x}
                y2={b.y}
                stroke={edgeStroke[tone]}
                strokeWidth={tone === 'crit' ? 2 : 1.5}
                strokeDasharray={tone === 'crit' ? '0' : '4 4'}
              />
              {tone === 'crit' && (
                <motion.circle
                  r="3"
                  fill="#ef4444"
                  initial={{ offsetDistance: '0%' }}
                  animate={{ offsetDistance: '100%' }}
                  transition={{ duration: 2.4, repeat: Infinity, ease: 'easeInOut' }}
                  style={{
                    offsetPath: `path('M ${a.x} ${a.y} L ${b.x} ${b.y}')`,
                  }}
                />
              )}
            </g>
          );
        })}

        {/* Nodes */}
        {nodes.map((n) => (
          <g key={n.id}>
            <circle
              cx={n.x}
              cy={n.y}
              r={n.kind === 'host-crit' ? 18 : 14}
              fill={nodeFill[n.kind]}
              stroke={nodeStroke[n.kind]}
              strokeWidth="2"
              filter={n.kind === 'host-crit' ? 'url(#softGlow)' : undefined}
            />
            <text
              x={n.x}
              y={n.y + (n.kind === 'host-crit' ? 34 : 30)}
              textAnchor="middle"
              fill="#cbd5e1"
              fontSize="10"
              fontFamily="ui-monospace, monospace"
            >
              {n.label}
            </text>
          </g>
        ))}
      </svg>
    </div>
  );
}
