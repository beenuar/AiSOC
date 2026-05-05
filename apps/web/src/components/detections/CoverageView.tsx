'use client';

import { useMemo, useState } from 'react';
import useSWR from 'swr';
import clsx from 'clsx';

import {
  OTHER_TACTIC,
  TACTICS,
  type Tactic,
  tacticsFor,
} from '@/lib/mitreTactics';

// ── Types ────────────────────────────────────────────────────────────────────

interface MitreCoverage {
  techniques: Record<string, number>;
  unique_techniques: number;
  total_with_mitre: number;
  by_tier?: Record<string, Record<string, number>>;
}

interface MarketplaceStats {
  total: number;
  detections: number;
  detections_by_tier?: Record<string, number>;
  quarantined?: number;
}

interface MarketplaceIndex {
  version: string;
  generated: string;
  stats?: MarketplaceStats;
  mitre_coverage?: MitreCoverage;
}

type TierFilter = 'all' | 'stable' | 'imported' | 'community';

const TIER_LABEL: Record<Exclude<TierFilter, 'all'>, string> = {
  stable: 'Native',
  imported: 'Imported',
  community: 'Community',
};

const TIER_COLOR: Record<Exclude<TierFilter, 'all'>, string> = {
  stable: 'bg-emerald-500',
  imported: 'bg-sky-500',
  community: 'bg-amber-500',
};

// ── Data fetching ───────────────────────────────────────────────────────────

const fetcher = (url: string) =>
  fetch(url, { cache: 'no-store' }).then((r) => {
    if (!r.ok) throw new Error(`Failed to load ${url}: ${r.status}`);
    return r.json();
  });

// ── Component ───────────────────────────────────────────────────────────────

export function CoverageView() {
  const { data, error, isLoading } = useSWR<MarketplaceIndex>(
    '/marketplace/index.json',
    fetcher,
    { revalidateOnFocus: false },
  );

  const [tierFilter, setTierFilter] = useState<TierFilter>('all');

  const matrix = useMemo(() => {
    if (!data?.mitre_coverage) return null;
    return buildMatrix(data.mitre_coverage, tierFilter);
  }, [data, tierFilter]);

  if (isLoading) {
    return (
      <div className="p-8 text-sm text-gray-400">Loading coverage…</div>
    );
  }

  if (error || !data?.mitre_coverage || !matrix) {
    return (
      <div className="p-8">
        <h1 className="text-2xl font-bold text-white">MITRE ATT&CK coverage</h1>
        <p className="mt-3 text-sm text-rose-300">
          Could not load <code>marketplace/index.json</code>. Run{' '}
          <code className="rounded bg-black/40 px-1.5 py-0.5">
            python3 scripts/build_marketplace.py
          </code>{' '}
          to generate it.
        </p>
      </div>
    );
  }

  const { stats } = data;

  return (
    <div className="p-6 lg:p-8">
      <header className="mb-6">
        <h1 className="text-2xl font-bold text-white">MITRE ATT&CK coverage</h1>
        <p className="mt-2 max-w-3xl text-sm text-gray-400">
          Live coverage matrix derived from <code>marketplace/index.json</code>.
          Counts reflect detection rules and playbooks with at least one
          mapped MITRE technique. Sub-techniques inherit their parent tactic.
        </p>
      </header>

      <Summary
        coverage={data.mitre_coverage}
        stats={stats}
        matrix={matrix}
        tierFilter={tierFilter}
      />

      <TierFilterBar value={tierFilter} onChange={setTierFilter} />

      <Legend />

      <Matrix matrix={matrix} />
    </div>
  );
}

// ── Summary cards ───────────────────────────────────────────────────────────

function Summary({
  coverage,
  stats,
  matrix,
  tierFilter,
}: {
  coverage: MitreCoverage;
  stats?: MarketplaceStats;
  matrix: BuiltMatrix;
  tierFilter: TierFilter;
}) {
  const detTotal = stats?.detections ?? 0;
  const detByTier = stats?.detections_by_tier ?? {};
  const quarantined = stats?.quarantined ?? 0;

  const techShown = matrix.tactics.reduce(
    (acc, col) => acc + col.techniques.length,
    0,
  );

  return (
    <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
      <Card label="Techniques covered" value={coverage.unique_techniques}>
        {tierFilter === 'all'
          ? 'across all tiers'
          : `in ${TIER_LABEL[tierFilter]} tier (${techShown} shown)`}
      </Card>

      <Card label="Rules with MITRE" value={coverage.total_with_mitre}>
        of {detTotal} detection rules
      </Card>

      <Card
        label="Detection rules"
        value={detTotal}
        breakdown={
          <div className="mt-2 space-y-0.5 text-[11px] text-gray-400">
            {Object.entries(detByTier).map(([tier, count]) => (
              <div key={tier} className="flex items-center gap-1.5">
                <span
                  className={clsx(
                    'h-1.5 w-1.5 rounded-full',
                    tierColorFor(tier),
                  )}
                />
                <span className="capitalize">{tier}</span>
                <span className="font-mono">{count}</span>
              </div>
            ))}
          </div>
        }
      />

      <Card label="Quarantined" value={quarantined}>
        imported rules disabled until translated
      </Card>
    </div>
  );
}

function Card({
  label,
  value,
  children,
  breakdown,
}: {
  label: string;
  value: number;
  children?: React.ReactNode;
  breakdown?: React.ReactNode;
}) {
  return (
    <div className="rounded-lg border border-white/10 bg-surface-card/40 p-4">
      <div className="text-[11px] font-semibold uppercase tracking-wider text-gray-400">
        {label}
      </div>
      <div className="mt-1 font-mono text-3xl font-bold text-white">{value}</div>
      {children ? (
        <div className="mt-1 text-xs text-gray-500">{children}</div>
      ) : null}
      {breakdown}
    </div>
  );
}

// ── Filter bar ──────────────────────────────────────────────────────────────

function TierFilterBar({
  value,
  onChange,
}: {
  value: TierFilter;
  onChange: (next: TierFilter) => void;
}) {
  const opts: { id: TierFilter; label: string }[] = [
    { id: 'all', label: 'All tiers' },
    { id: 'stable', label: 'Native (stable)' },
    { id: 'imported', label: 'Imported' },
    { id: 'community', label: 'Community' },
  ];
  return (
    <div className="mb-4 flex flex-wrap gap-2">
      {opts.map((opt) => (
        <button
          key={opt.id}
          type="button"
          onClick={() => onChange(opt.id)}
          className={clsx(
            'rounded-full border px-3 py-1 text-xs font-medium transition-colors',
            value === opt.id
              ? 'border-brand-300/60 bg-brand-500/20 text-white'
              : 'border-white/10 bg-surface-card/40 text-gray-300 hover:bg-white/5',
          )}
        >
          {opt.label}
        </button>
      ))}
    </div>
  );
}

// ── Legend ──────────────────────────────────────────────────────────────────

function Legend() {
  return (
    <div className="mb-4 flex flex-wrap items-center gap-4 text-[11px] text-gray-400">
      <span>Heatmap intensity = number of rules covering the technique:</span>
      <span className="inline-flex items-center gap-1.5">
        <span className="h-3 w-3 rounded border border-white/10 bg-emerald-500/15" />
        1 rule
      </span>
      <span className="inline-flex items-center gap-1.5">
        <span className="h-3 w-3 rounded border border-white/10 bg-emerald-500/35" />
        2-4
      </span>
      <span className="inline-flex items-center gap-1.5">
        <span className="h-3 w-3 rounded border border-white/10 bg-emerald-500/55" />
        5-9
      </span>
      <span className="inline-flex items-center gap-1.5">
        <span className="h-3 w-3 rounded border border-white/10 bg-emerald-500/80" />
        10+
      </span>
    </div>
  );
}

// ── Matrix ──────────────────────────────────────────────────────────────────

function Matrix({ matrix }: { matrix: BuiltMatrix }) {
  if (matrix.tactics.length === 0) {
    return (
      <div className="rounded-lg border border-white/10 bg-surface-card/40 p-6 text-sm text-gray-400">
        No techniques covered for this tier yet.
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <div
        className="grid auto-cols-[minmax(180px,1fr)] grid-flow-col gap-2"
        style={{ gridAutoColumns: 'minmax(180px, 1fr)' }}
      >
        {matrix.tactics.map((col) => (
          <TacticColumn key={col.tactic.id} column={col} />
        ))}
      </div>
    </div>
  );
}

function TacticColumn({ column }: { column: BuiltTactic }) {
  return (
    <div className="flex flex-col gap-1.5 rounded-lg border border-white/10 bg-surface-card/30 p-2.5">
      <div className="px-1 pb-1.5">
        <div className="font-mono text-[10px] uppercase tracking-wider text-gray-500">
          {column.tactic.id}
        </div>
        <div className="text-xs font-semibold text-white">
          {column.tactic.name}
        </div>
        <div className="mt-0.5 text-[10px] text-gray-500">
          {column.techniques.length} technique
          {column.techniques.length === 1 ? '' : 's'}
        </div>
      </div>
      <div className="flex flex-col gap-1">
        {column.techniques.map((tech) => (
          <TechniqueCell key={tech.id} technique={tech} />
        ))}
      </div>
    </div>
  );
}

function TechniqueCell({ technique }: { technique: BuiltTechnique }) {
  const intensity = intensityClass(technique.total);
  return (
    <a
      href={`https://attack.mitre.org/techniques/${technique.id.replace('.', '/')}/`}
      target="_blank"
      rel="noopener noreferrer"
      className={clsx(
        'block rounded border px-2 py-1.5 transition-colors hover:border-brand-300/60',
        'border-white/10',
        intensity,
      )}
      title={`${technique.id} — ${technique.total} rule${
        technique.total === 1 ? '' : 's'
      }`}
    >
      <div className="flex items-baseline justify-between gap-2">
        <span className="font-mono text-[11px] font-medium text-white/90">
          {technique.id}
        </span>
        <span className="font-mono text-[11px] text-white">
          {technique.total}
        </span>
      </div>
      {technique.byTier.length > 0 ? (
        <div className="mt-1 flex h-1 overflow-hidden rounded-full bg-white/5">
          {technique.byTier.map(({ tier, count }) => {
            const pct = (count / technique.total) * 100;
            return (
              <span
                key={tier}
                className={clsx('h-full', tierColorFor(tier))}
                style={{ width: `${pct}%` }}
              />
            );
          })}
        </div>
      ) : null}
    </a>
  );
}

// ── Matrix building ─────────────────────────────────────────────────────────

interface BuiltTechnique {
  id: string;
  total: number;
  byTier: { tier: string; count: number }[];
}

interface BuiltTactic {
  tactic: Tactic;
  techniques: BuiltTechnique[];
}

interface BuiltMatrix {
  tactics: BuiltTactic[];
}

function buildMatrix(
  coverage: MitreCoverage,
  tierFilter: TierFilter,
): BuiltMatrix {
  // Collect technique → counts (filtered by tier).
  const techniqueTotals: Record<string, number> = {};
  const techniqueByTier: Record<string, Record<string, number>> = {};

  if (tierFilter === 'all') {
    for (const [tech, count] of Object.entries(coverage.techniques)) {
      techniqueTotals[tech] = count;
    }
    for (const [tier, perTechnique] of Object.entries(
      coverage.by_tier ?? {},
    )) {
      for (const [tech, count] of Object.entries(perTechnique)) {
        techniqueByTier[tech] = techniqueByTier[tech] ?? {};
        techniqueByTier[tech][tier] = (techniqueByTier[tech][tier] ?? 0) + count;
      }
    }
  } else {
    const slice = coverage.by_tier?.[tierFilter] ?? {};
    for (const [tech, count] of Object.entries(slice)) {
      techniqueTotals[tech] = count;
      techniqueByTier[tech] = { [tierFilter]: count };
    }
  }

  // Group by tactic.
  const byTactic = new Map<string, BuiltTechnique[]>();
  for (const [tech, total] of Object.entries(techniqueTotals)) {
    const tactics = tacticsFor(tech);
    const built: BuiltTechnique = {
      id: tech,
      total,
      byTier: Object.entries(techniqueByTier[tech] ?? {})
        .map(([tier, count]) => ({ tier, count }))
        .sort((a, b) => b.count - a.count),
    };
    for (const tacticId of tactics) {
      const list = byTactic.get(tacticId) ?? [];
      list.push(built);
      byTactic.set(tacticId, list);
    }
  }

  // Order tactics in standard kill-chain order; append "Other" if present.
  const orderedTactics: BuiltTactic[] = [];
  for (const tactic of TACTICS) {
    const techniques = byTactic.get(tactic.id);
    if (!techniques || techniques.length === 0) continue;
    techniques.sort((a, b) => b.total - a.total || a.id.localeCompare(b.id));
    orderedTactics.push({ tactic, techniques });
  }
  const other = byTactic.get(OTHER_TACTIC.id);
  if (other && other.length > 0) {
    other.sort((a, b) => b.total - a.total || a.id.localeCompare(b.id));
    orderedTactics.push({ tactic: OTHER_TACTIC, techniques: other });
  }

  return { tactics: orderedTactics };
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function intensityClass(count: number): string {
  if (count >= 10) return 'bg-emerald-500/80';
  if (count >= 5) return 'bg-emerald-500/55';
  if (count >= 2) return 'bg-emerald-500/35';
  return 'bg-emerald-500/15';
}

function tierColorFor(tier: string): string {
  if (tier === 'stable') return TIER_COLOR.stable;
  if (tier === 'imported') return TIER_COLOR.imported;
  if (tier === 'community') return TIER_COLOR.community;
  // beta, unknown
  return 'bg-violet-500';
}
