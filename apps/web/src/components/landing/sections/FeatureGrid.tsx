'use client';

/**
 * Three feature deep-dive grids — `features` section from §6.7 of the
 * brief.
 *
 *   Grid 1 — Detect & Investigate (6 tiles)
 *   Grid 2 — Hunt & Respond       (6 tiles)
 *   Grid 3 — Operate at scale     (6 tiles)
 *
 * Layout is 3-up at ≥1024 px, 2-up at ≥640 px, single column on phone.
 * Each tile gets a Lucide icon, a one-line title, and a single-sentence
 * body — copy lifted verbatim from `landing-page-content.md`.
 *
 * Reveal: per-grid header staggers in first, then each tile fades up at
 * 60 ms intervals when its row enters the viewport. The `once: true`
 * viewport keeps a re-scrolled section from re-firing the animation.
 */

import { motion, useReducedMotion } from 'framer-motion';
import {
  AlertOctagon,
  Boxes,
  CalendarClock,
  ClipboardList,
  CloudCog,
  Code2,
  DollarSign,
  FileCog,
  KeyRound,
  Network,
  PlugZap,
  Receipt,
  ScrollText,
  ShieldHalf,
  Sigma,
  Telescope,
  TerminalSquare,
  Workflow,
} from 'lucide-react';
import type { ComponentType, SVGProps } from 'react';
import { cn } from '@/lib/utils';
import { CONNECTOR_COUNT } from '@/data/connectorCount';

interface Tile {
  icon: ComponentType<SVGProps<SVGSVGElement>>;
  title: string;
  body: string;
}

interface FeatureBlock {
  id: 'detect' | 'hunt' | 'operate';
  title: string;
  tiles: ReadonlyArray<Tile>;
}

const BLOCKS: ReadonlyArray<FeatureBlock> = [
  {
    id: 'detect',
    title: 'Detect & investigate',
    tiles: [
      {
        icon: Sigma,
        title: 'Fusion engine.',
        body: 'Real-time dedup, ML scoring, per-alert confidence.',
      },
      {
        icon: AlertOctagon,
        title: 'Entity-risk rollup (RBA).',
        body: 'Time-decayed risk per user, host, IP, domain — 50:1 alert-to-incident.',
      },
      {
        icon: FileCog,
        title: 'Native detections.',
        body: '6,998 YAML rules across cloud, endpoint, identity, network, application, and data-exfil.',
      },
      {
        icon: ScrollText,
        title: 'Investigation Ledger.',
        body: 'Replayable, step-by-step record of every agent decision per case.',
      },
      {
        icon: Network,
        title: 'Attack-chain timeline.',
        body: 'Cytoscape over the Neo4j subgraph — see the path, not just the alerts.',
      },
      {
        icon: KeyRound,
        title: 'Effective permissions.',
        body: 'What a principal can actually do across AWS, Azure, GCP, Okta, Google Workspace.',
      },
    ],
  },
  {
    id: 'hunt',
    title: 'Hunt & respond',
    tiles: [
      {
        icon: Telescope,
        title: 'NL hunt at /hunt.',
        body: 'Ask in English. Get ES|QL, KQL, and SPL back.',
      },
      {
        icon: CalendarClock,
        title: 'Hunt-as-Code (YAML).',
        body: 'Hypothesis-driven, MITRE-tagged hunts on a cron.',
      },
      {
        icon: Workflow,
        title: 'Response planner.',
        body: 'Containment → eradication → recovery, dry-run by default.',
      },
      {
        icon: ClipboardList,
        title: 'ChatOps approvals.',
        body: 'Slack Block Kit + Teams Adaptive Cards, HMAC signed.',
      },
      {
        icon: ShieldHalf,
        title: 'L0–L4 maturity dial.',
        body: 'One per-tenant setting governs every action class. Auditable.',
      },
      {
        icon: CloudCog,
        title: 'SOAR exec.',
        body: 'Blast-radius gated playbook execution with full rollback.',
      },
    ],
  },
  {
    id: 'operate',
    title: 'Operate at scale',
    tiles: [
      {
        icon: PlugZap,
        title: `${CONNECTOR_COUNT} click-and-connect connectors.`,
        body: 'EDR · SIEM · cloud · IAM · SaaS · VCS · network.',
      },
      {
        icon: Boxes,
        title: 'Marketplace.',
        body: '7,117 community items — detections, playbooks, plugins.',
      },
      {
        icon: Code2,
        title: 'Plugin SDKs.',
        body: 'Python, TypeScript, Go — build a connector in 50 lines.',
      },
      {
        icon: DollarSign,
        title: 'MCP server.',
        body: 'Use AiSOC from Claude, Cursor, Continue, Cody — 13 tools.',
      },
      {
        icon: TerminalSquare,
        title: 'Cursor extension.',
        body: 'Investigate alerts without leaving your editor.',
      },
      {
        icon: Receipt,
        title: 'Cost telemetry.',
        body: 'Per-call tokens and USD captured in the run ledger.',
      },
    ],
  },
];

function FeatureTile({
  tile,
  index,
  reduced,
}: {
  tile: Tile;
  index: number;
  reduced: boolean | null;
}) {
  const Icon = tile.icon;
  return (
    <motion.li
      initial={reduced ? false : { opacity: 0, y: 12 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '-15%' }}
      transition={{
        duration: 0.45,
        ease: [0.16, 1, 0.3, 1],
        delay: (index % 6) * 0.06,
      }}
      className={cn(
        'group relative flex flex-col gap-2 rounded-xl border border-velvet-border bg-velvet-surface-raised/60 p-5 backdrop-blur-sm',
        'transition-[border-color,transform] duration-300 ease-landing-out-quart hover:-translate-y-0.5 hover:border-velvet-emerald/40',
      )}
    >
      <span
        aria-hidden="true"
        className="inline-flex h-9 w-9 items-center justify-center rounded-lg bg-velvet-emerald/10 text-velvet-emerald-mint ring-1 ring-inset ring-velvet-emerald/30"
      >
        <Icon className="h-4 w-4" />
      </span>
      <h3 className="font-velvet-display font-normal mt-1 text-sm text-velvet-content-primary">{tile.title}</h3>
      <p className="text-xs leading-relaxed text-velvet-content-secondary">{tile.body}</p>
    </motion.li>
  );
}

export function FeatureGrid() {
  const prefersReducedMotion = useReducedMotion();

  return (
    <section
      id="features"
      aria-labelledby="features-heading"
      className="relative py-20 sm:py-24 lg:py-28"
    >
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <h2
          id="features-heading"
          className="font-velvet-display font-normal sr-only"
        >
          Feature deep-dive
        </h2>
        <div className="space-y-16 lg:space-y-20">
          {BLOCKS.map((block, blockIdx) => (
            <div key={block.id} aria-labelledby={`features-${block.id}`}>
              <motion.h3
                id={`features-${block.id}`}
                initial={prefersReducedMotion ? false : { opacity: 0, y: 10 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, margin: '-20%' }}
                transition={{ duration: 0.45, ease: [0.16, 1, 0.3, 1] }}
                className="text-2xl font-bold tracking-tight text-velvet-content-primary sm:text-3xl"
              >
                {block.title}
              </motion.h3>
              <ul className="mt-6 grid gap-3 sm:grid-cols-2 sm:gap-4 lg:grid-cols-3">
                {block.tiles.map((tile, idx) => (
                  <FeatureTile
                    key={`${block.id}-${tile.title}-${blockIdx}-${idx}`}
                    tile={tile}
                    index={idx}
                    reduced={prefersReducedMotion}
                  />
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
