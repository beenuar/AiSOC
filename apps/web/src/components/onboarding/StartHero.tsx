'use client';

import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { useState } from 'react';
import { motion } from 'framer-motion';
import toast from 'react-hot-toast';
import { authApi } from '@/lib/api';
import { demoDeeplink } from '@/lib/demoMode';

/**
 * Onboarding hero for the AiSOC root (`/`).
 *
 * Implements the three CTAs from `aisoc_v1.0__buyer-value_plan` WS-A2:
 *
 *   1. Try the demo       → silently logs in with the demo credentials and
 *                           deeplinks to the in-flight LockBit ransomware
 *                           investigation (`/cases/INC-RT-001?tab=ledger`).
 *                           If the API rejects login (clean self-host that
 *                           hasn't seeded yet), surface a friendly toast that
 *                           points the operator at `pnpm seed:demo`.
 *
 *   2. Connect first source → routes to `/onboarding`, the existing connector
 *                             gallery. New self-hosters get a guided
 *                             "click and connect" flow with an encrypted
 *                             credential vault.
 *
 *   3. Skip & explore     → routes to `/dashboard?welcome=1`. The querystring
 *                           triggers a one-time empty-state coach card so a
 *                           cold dashboard doesn't feel broken.
 *
 * Why these three specifically? The plan calls out a "stopwatch
 * clone-to-investigation ≤ 5 min on clean Mac" acceptance criterion. The first
 * CTA collapses that to a single click. The second is the path for operators
 * who arrived with their own data. The third is the "let me poke around"
 * escape hatch that respects the buyer's time.
 */
export function StartHero() {
  const router = useRouter();
  const [demoBusy, setDemoBusy] = useState(false);

  const handleTryDemo = async () => {
    if (demoBusy) return;
    setDemoBusy(true);
    const target = demoDeeplink();

    // The default seed credentials live in the README and `seed_demo.py`.
    // We attempt login silently; on failure we keep the user on the
    // landing page and explain how to seed. We do NOT redirect to /login
    // because the empty error state on a fresh self-host is more
    // informative than a generic password prompt.
    const email = process.env.NEXT_PUBLIC_DEMO_AUTOLOGIN_EMAIL?.trim() || 'demo@aisoc.dev';
    const password = process.env.NEXT_PUBLIC_DEMO_AUTOLOGIN_PASSWORD?.trim() || 'aisoc-demo';

    try {
      if (!authApi.isAuthenticated()) {
        await authApi.login(email, password);
      }
      router.push(target);
    } catch (err) {
      const detail = err instanceof Error ? err.message : 'Login failed';
      toast.error(
        `Could not auto-load the demo (${detail}). Run "pnpm seed:demo" or sign in via /login.`,
        { duration: 6000 },
      );
    } finally {
      setDemoBusy(false);
    }
  };

  return (
    <section className="relative isolate overflow-hidden pt-32 pb-20 md:pt-40 md:pb-28">
      <div className="mx-auto grid max-w-7xl grid-cols-1 items-center gap-16 px-6 lg:grid-cols-[1.1fr_1fr]">
        {/* Copy column */}
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, ease: 'easeOut' }}
        >
          <span className="inline-flex items-center gap-2 rounded-full border border-brand-400/30 bg-brand-500/10 px-3 py-1 text-xs font-semibold uppercase tracking-wider text-brand-200">
            Open-source · MIT · self-hostable
          </span>

          <h1 className="mt-6 text-balance text-5xl font-bold leading-[1.05] tracking-tight text-white md:text-6xl lg:text-7xl">
            Start triaging in 3 minutes.
          </h1>

          <p className="mt-6 max-w-xl text-lg leading-relaxed text-gray-300 md:text-xl">
            AiSOC ships a 200-incident eval harness, a pre-seeded LockBit 3.0
            investigation, and 26 click-and-connect security sources. Pick how
            you want to start — every option lands you in a working SOC, not a
            blank dashboard.
          </p>

          {/* Three primary CTAs */}
          <div className="mt-10 grid gap-3 sm:grid-cols-3">
            <button
              type="button"
              onClick={handleTryDemo}
              disabled={demoBusy}
              data-testid="cta-try-demo"
              className="group flex flex-col items-start gap-2 rounded-xl border border-brand-400/30 bg-brand-500/15 p-5 text-left transition hover:border-brand-300/60 hover:bg-brand-500/25 disabled:cursor-progress disabled:opacity-70"
            >
              <span className="inline-flex h-8 w-8 items-center justify-center rounded-lg bg-brand-500/30 text-base">
                ⚡
              </span>
              <span className="text-base font-semibold text-white">
                {demoBusy ? 'Loading demo…' : 'Try the demo'}
              </span>
              <span className="text-xs leading-relaxed text-gray-300">
                Auto-loads the seed and drops you into a live ransomware case.
              </span>
            </button>

            <Link
              href="/onboarding"
              data-testid="cta-connect-source"
              className="group flex flex-col items-start gap-2 rounded-xl border border-white/10 bg-white/[0.04] p-5 text-left transition hover:border-white/30 hover:bg-white/[0.08]"
            >
              <span className="inline-flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-500/20 text-base">
                ⚙
              </span>
              <span className="text-base font-semibold text-white">
                Connect first source
              </span>
              <span className="text-xs leading-relaxed text-gray-300">
                Pick from 50 connectors — EDR, SIEM, cloud, IAM. Credentials
                stay encrypted.
              </span>
            </Link>

            <Link
              href="/dashboard?welcome=1"
              data-testid="cta-skip"
              className="group flex flex-col items-start gap-2 rounded-xl border border-white/10 bg-white/[0.04] p-5 text-left transition hover:border-white/30 hover:bg-white/[0.08]"
            >
              <span className="inline-flex h-8 w-8 items-center justify-center rounded-lg bg-white/10 text-base">
                →
              </span>
              <span className="text-base font-semibold text-white">
                Skip &amp; explore
              </span>
              <span className="text-xs leading-relaxed text-gray-300">
                Open the console as-is. We&apos;ll show inline coaching where
                things are quiet.
              </span>
            </Link>
          </div>

          <p className="mt-4 text-xs text-gray-500">
            Already have an account? <Link href="/login" className="font-semibold text-brand-300 hover:text-brand-200">Sign in</Link>.
          </p>

          <dl className="mt-12 grid grid-cols-4 gap-5 border-t border-white/5 pt-8">
            <Stat label="Connectors" value="26" caption="EDR, SIEM, cloud, IAM, SaaS" />
            <Stat label="Agent decisions" value="Ledger" caption="prompt + tool + rationale per step" />
            <Stat label="Eval harness" value="200 cases" caption="runs in CI on every PR to main" />
            <Stat label="License" value="MIT" caption="audit, fork, self-host" />
          </dl>
        </motion.div>

        {/* Visual column — same hero card as the legacy landing page so we
            don't lose the recognisable look of the docs/screenshots while we
            iterate. The copilot tooltip is updated to mirror INC-RT-001. */}
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
  // Caption is wrapped inside the `<dd>` so the surrounding `<dl>` stays
  // structurally valid (axe's `definition-list` rule rejects any direct
  // child of the `<dl>`'s div-wrapper that isn't `<dt>`/`<dd>`). Same
  // visual layout as before.
  return (
    <div>
      <dt className="text-xs font-semibold uppercase tracking-wider text-gray-500">{label}</dt>
      <dd className="mt-2 text-2xl font-bold text-white">
        {value}
        <span className="mt-1 block text-xs font-normal text-gray-500">{caption}</span>
      </dd>
    </div>
  );
}

/**
 * Layered visual: an attack-graph card with a copilot thread peeking from the
 * bottom-right. Pure SVG/Tailwind. The graph nodes mirror the seeded
 * `INC-RT-001` LockBit scenario so the visual is consistent with the demo
 * deeplink ("WF-04 → SRV-FIN-04 → DC-01 → backup").
 */
function HeroVisual() {
  return (
    <div className="relative aspect-[5/4]">
      <motion.div
        initial={{ opacity: 0, scale: 0.96 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.6, delay: 0.15 }}
        className="absolute inset-0 overflow-hidden rounded-2xl border border-white/10 bg-surface-card/90 shadow-2xl backdrop-blur"
      >
        <div className="flex items-center gap-2 border-b border-white/5 bg-surface-raised/60 px-4 py-3">
          <span className="h-2.5 w-2.5 rounded-full bg-rose-400/80" />
          <span className="h-2.5 w-2.5 rounded-full bg-amber-400/80" />
          <span className="h-2.5 w-2.5 rounded-full bg-emerald-400/80" />
          <span className="ml-3 text-xs font-medium text-gray-500">aisoc · INC-RT-001 · live</span>
          <span className="ml-auto inline-flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-rose-300">
            <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-rose-400" />
            In-flight
          </span>
        </div>
        <SignalMap />
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, delay: 0.45 }}
        className="absolute -bottom-6 -right-4 w-72 rounded-xl border border-white/10 bg-surface-card/95 p-4 shadow-2xl backdrop-blur sm:-right-8 sm:w-80"
      >
        <div className="mb-2 flex items-center gap-2 text-xs font-semibold text-gray-400">
          <span className="inline-flex h-6 w-6 items-center justify-center rounded-md bg-brand-500 text-[11px] font-bold text-white">A</span>
          AiSOC Agent
          <span className="ml-auto text-[10px] font-medium uppercase tracking-wider text-emerald-300">streaming</span>
        </div>
        <p className="text-sm leading-relaxed text-gray-200">
          LockBit 3.0 detector fired on{' '}
          <span className="rounded bg-rose-500/15 px-1 font-mono text-rose-200">SRV-FIN-04</span>{' '}
          — ~12k files encrypting. Mapped to{' '}
          <span className="font-mono text-amber-300">T1486</span>. Containment ready for approval.
        </p>
        <div className="mt-3 flex gap-2">
          <button className="rounded-md bg-rose-500/90 px-2.5 py-1 text-xs font-semibold text-white">Isolate host</button>
          <button className="rounded-md border border-white/10 bg-white/[0.04] px-2.5 py-1 text-xs font-semibold text-gray-300">View ledger</button>
        </div>
      </motion.div>
    </div>
  );
}

function SignalMap() {
  const nodes = [
    { id: 'inet', x: 60, y: 60, label: 'Internet', kind: 'edge' },
    { id: 'wf', x: 180, y: 95, label: 'WF-04', kind: 'host' },
    { id: 'srv', x: 305, y: 145, label: 'SRV-FIN-04', kind: 'host-crit' },
    { id: 'dc', x: 430, y: 100, label: 'DC-01', kind: 'host-warn' },
    { id: 'bkp', x: 305, y: 245, label: 'Backup', kind: 'host-warn' },
    { id: 'idp', x: 110, y: 220, label: 'Okta', kind: 'idp' },
  ];
  const edges: Array<[string, string, 'normal' | 'warn' | 'crit']> = [
    ['inet', 'wf', 'normal'],
    ['wf', 'srv', 'crit'],
    ['srv', 'dc', 'warn'],
    ['srv', 'bkp', 'warn'],
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
      <div className="absolute right-3 top-3 flex flex-col gap-1.5 text-[9px] font-mono">
        {[
          { id: 'T1078', label: 'Valid Accts', tone: 'gray' },
          { id: 'T1021', label: 'Remote Svcs', tone: 'warn' },
          { id: 'T1486', label: 'Impact', tone: 'crit' },
          { id: 'T1490', label: 'Inhibit Recovery', tone: 'warn' },
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
            </g>
          );
        })}
        {nodes.map((n) => (
          <g key={n.id}>
            <circle
              cx={n.x}
              cy={n.y}
              r={n.kind === 'host-crit' ? 18 : 14}
              fill={nodeFill[n.kind]}
              stroke={nodeStroke[n.kind]}
              strokeWidth="2"
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
