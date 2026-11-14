'use client';

/**
 * PlaybooksGallery
 * ================
 * Faceted gallery for the /playbooks "All" tab. Surfaces the 50+ shipped
 * reference packs alongside any user-created playbooks with:
 *
 *   • Source filter pills      ("All" / "Shipped Packs" / "Custom")
 *   • Category facet chips     (account-takeover, ransomware, …)
 *   • MITRE tactic filter      (Initial Access, Lateral Movement, …)
 *   • Severity filter          (info / low / medium / high / critical)
 *   • Integration filter       (EDR, IAM, Ticketing, SIEM, …)
 *   • Free-text search         (matches name, description, tags)
 *   • Per-row PACK badge       (purple) + colored category badge
 *   • One-click "Preview"      (read-only DAG drawer)
 *   • One-click "Fork"         (clones a pack into a user-owned playbook)
 *   • "Edit" / "Delete"        (existing flow for custom playbooks)
 *
 * The gallery is driven entirely from the existing `GET /api/v1/playbooks`
 * payload — no new backend endpoints required. See packHelpers.ts for the
 * pack-detection heuristic, MITRE/severity/integration helpers, and forking.
 */

import React, { useMemo, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { mutate } from 'swr';
import clsx from 'clsx';

import type { Playbook } from './types';
import {
  PACK_CATEGORIES,
  MITRE_TACTICS,
  SEVERITY_LEVELS,
  INTEGRATION_TYPES,
  type PackCategory,
  type PlaybookSource,
  type MitreTactic,
  type SeverityLevel,
  type IntegrationType,
  isShippedPack,
  categoryOf,
  categoryLabel,
  categoryBadgeClass,
  mitreTacticsOf,
  severitiesOf,
  integrationsOf,
  filterPlaybooks,
  countBySource,
  countByCategory,
  forkPlaybook,
} from './packHelpers';
import { DAGPreviewDrawer } from './DAGPreviewDrawer';
import { EnabledToggle, RunButton, deletePlaybook } from './rowActions';

const TRIGGER_COLORS: Record<string, string> = {
  alert:    'bg-red-900/40 text-red-300 border-red-800',
  case:     'bg-blue-900/40 text-blue-300 border-blue-800',
  manual:   'bg-gray-800 text-gray-400 border-gray-700',
  schedule: 'bg-purple-900/40 text-purple-300 border-purple-800',
};

/** Filter snapshot that can be saved as a named preset via SavedViewsBar. */
export interface PlaybookGalleryFilters {
  source: PlaybookSource;
  category: PackCategory | 'all';
  mitreTactic: MitreTactic | 'all';
  severity: SeverityLevel | 'all';
  integration: IntegrationType | 'all';
  search: string;
}

interface PlaybooksGalleryProps {
  playbooks: Playbook[];
  /** Pre-seed local filter state from a saved view preset. */
  initialFilters?: Partial<PlaybookGalleryFilters>;
}

export function PlaybooksGallery({ playbooks, initialFilters }: PlaybooksGalleryProps) {
  const router = useRouter();
  const [source, setSource] = useState<PlaybookSource>(initialFilters?.source ?? 'all');
  const [category, setCategory] = useState<PackCategory | 'all'>(initialFilters?.category ?? 'all');
  const [mitreTactic, setMitreTactic] = useState<MitreTactic | 'all'>(initialFilters?.mitreTactic ?? 'all');
  const [severity, setSeverity] = useState<SeverityLevel | 'all'>(initialFilters?.severity ?? 'all');
  const [integration, setIntegration] = useState<IntegrationType | 'all'>(initialFilters?.integration ?? 'all');
  const [search, setSearch] = useState(initialFilters?.search ?? '');
  const [previewing, setPreviewing] = useState<Playbook | null>(null);
  const [forkingId, setForkingId] = useState<string | null>(null);
  const [forkError, setForkError] = useState<string | null>(null);

  const sourceCounts = useMemo(() => countBySource(playbooks), [playbooks]);
  const categoryCounts = useMemo(() => countByCategory(playbooks), [playbooks]);

  // Counts for MITRE tactics across current source+category selection (before tactic filter)
  const mitreCounts = useMemo(() => {
    const pre = playbooks.filter((pb) => {
      const isPack = isShippedPack(pb);
      if (source === 'pack' && !isPack) return false;
      if (source === 'custom' && isPack) return false;
      if (category !== 'all' && categoryOf(pb) !== category) return false;
      return true;
    });
    const counts: Record<MitreTactic, number> = {} as Record<MitreTactic, number>;
    for (const t of MITRE_TACTICS) counts[t] = 0;
    for (const pb of pre) {
      for (const t of mitreTacticsOf(pb)) counts[t]++;
    }
    return counts;
  }, [playbooks, source, category]);

  // Counts for severity levels
  const severityCounts = useMemo(() => {
    const pre = playbooks.filter((pb) => {
      const isPack = isShippedPack(pb);
      if (source === 'pack' && !isPack) return false;
      if (source === 'custom' && isPack) return false;
      if (category !== 'all' && categoryOf(pb) !== category) return false;
      if (mitreTactic !== 'all' && !mitreTacticsOf(pb).includes(mitreTactic)) return false;
      return true;
    });
    const counts: Record<SeverityLevel, number> = {} as Record<SeverityLevel, number>;
    for (const s of SEVERITY_LEVELS) counts[s] = 0;
    for (const pb of pre) {
      for (const s of severitiesOf(pb)) counts[s]++;
    }
    return counts;
  }, [playbooks, source, category, mitreTactic]);

  // Counts for integration types
  const integrationCounts = useMemo(() => {
    const pre = playbooks.filter((pb) => {
      const isPack = isShippedPack(pb);
      if (source === 'pack' && !isPack) return false;
      if (source === 'custom' && isPack) return false;
      if (category !== 'all' && categoryOf(pb) !== category) return false;
      if (mitreTactic !== 'all' && !mitreTacticsOf(pb).includes(mitreTactic)) return false;
      if (severity !== 'all' && !severitiesOf(pb).includes(severity)) return false;
      return true;
    });
    const counts: Record<IntegrationType, number> = {} as Record<IntegrationType, number>;
    for (const i of INTEGRATION_TYPES) counts[i] = 0;
    for (const pb of pre) {
      for (const i of integrationsOf(pb)) counts[i]++;
    }
    return counts;
  }, [playbooks, source, category, mitreTactic, severity]);

  const filtered = useMemo(
    () => filterPlaybooks(playbooks, { source, category, mitreTactic, severity, integration, search }),
    [playbooks, source, category, mitreTactic, severity, integration, search],
  );

  // The category facet only meaningfully applies to packs.
  const showCategoryRow = source !== 'custom';

  // Reset downstream filters when source changes.
  function handleSetSource(s: PlaybookSource) {
    setSource(s);
    setCategory('all');
    setMitreTactic('all');
    setSeverity('all');
    setIntegration('all');
  }

  const hasActiveFilters =
    category !== 'all' ||
    mitreTactic !== 'all' ||
    severity !== 'all' ||
    integration !== 'all' ||
    search !== '';

  function clearAllFilters() {
    setCategory('all');
    setMitreTactic('all');
    setSeverity('all');
    setIntegration('all');
    setSearch('');
  }

  async function handleFork(pb: Playbook) {
    setForkError(null);
    setForkingId(pb.id);
    try {
      const created = await forkPlaybook(pb);
      // Refresh the gallery list so the fork shows up under "Custom".
      await mutate('/api/v1/playbooks');
      // Drop the user into the editor for their fresh fork.
      setPreviewing(null);
      router.push(`/playbooks/${created.id}`);
    } catch (e) {
      setForkError(e instanceof Error ? e.message : 'Fork failed.');
    } finally {
      setForkingId(null);
    }
  }

  return (
    <div className="space-y-4">
      {/* Toolbar — search + source pills */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex flex-1 min-w-[220px] gap-2">
          <input
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search playbooks by name, tag, description…"
            aria-label="Search playbooks"
            className="flex-1 rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-sm text-gray-100 placeholder-gray-500 focus:border-blue-500 focus:outline-none"
          />
        </div>

        <div
          className="flex gap-1 rounded-lg border border-gray-700 bg-gray-900 p-1"
          role="tablist"
          aria-label="Playbook source"
        >
          <SourcePill
            label="All"
            count={sourceCounts.all}
            active={source === 'all'}
            onClick={() => handleSetSource('all')}
          />
          <SourcePill
            label="Shipped Packs"
            count={sourceCounts.pack}
            active={source === 'pack'}
            onClick={() => handleSetSource('pack')}
            tone="pack"
          />
          <SourcePill
            label="Custom"
            count={sourceCounts.custom}
            active={source === 'custom'}
            onClick={() => handleSetSource('custom')}
          />
        </div>

        {hasActiveFilters && (
          <button
            onClick={clearAllFilters}
            className="text-xs text-gray-500 hover:text-red-400 transition-colors px-2 py-1 rounded border border-gray-800 hover:border-red-900"
          >
            Clear filters
          </button>
        )}
      </div>

      {/* Category facet (only when a category is meaningful) */}
      {showCategoryRow && (
        <div className="flex flex-wrap items-center gap-2" aria-label="Filter by category">
          <span className="text-xs text-gray-600 w-16 shrink-0">Category</span>
          <CategoryPill
            label="All"
            active={category === 'all'}
            onClick={() => setCategory('all')}
          />
          {PACK_CATEGORIES.map((cat) => {
            const n = categoryCounts[cat];
            if (n === 0) return null;
            return (
              <CategoryPill
                key={cat}
                label={`${categoryLabel(cat)} (${n})`}
                active={category === cat}
                onClick={() => setCategory(cat)}
                tone={cat}
              />
            );
          })}
        </div>
      )}

      {/* MITRE Tactic filter */}
      <div className="flex flex-wrap items-center gap-2" aria-label="Filter by MITRE tactic">
        <span className="text-xs text-gray-600 w-16 shrink-0">MITRE</span>
        <FacetPill
          label="All"
          active={mitreTactic === 'all'}
          onClick={() => setMitreTactic('all')}
        />
        {MITRE_TACTICS.map((tactic) => {
          const n = mitreCounts[tactic];
          if (n === 0) return null;
          return (
            <FacetPill
              key={tactic}
              label={`${tactic} (${n})`}
              active={mitreTactic === tactic}
              onClick={() => setMitreTactic(tactic)}
              activeClass="bg-red-900/40 text-red-300 border-red-800"
            />
          );
        })}
      </div>

      {/* Severity filter */}
      <div className="flex flex-wrap items-center gap-2" aria-label="Filter by severity">
        <span className="text-xs text-gray-600 w-16 shrink-0">Severity</span>
        <FacetPill
          label="All"
          active={severity === 'all'}
          onClick={() => setSeverity('all')}
        />
        {SEVERITY_LEVELS.map((sev) => {
          const n = severityCounts[sev];
          if (n === 0) return null;
          const COLOR_MAP: Record<SeverityLevel, string> = {
            info:     'bg-blue-900/40 text-blue-300 border-blue-800',
            low:      'bg-gray-800/60 text-gray-300 border-gray-600',
            medium:   'bg-yellow-900/40 text-yellow-300 border-yellow-800',
            high:     'bg-orange-900/40 text-orange-300 border-orange-800',
            critical: 'bg-red-900/60 text-red-200 border-red-700',
          };
          return (
            <FacetPill
              key={sev}
              label={`${sev} (${n})`}
              active={severity === sev}
              onClick={() => setSeverity(sev)}
              activeClass={COLOR_MAP[sev]}
            />
          );
        })}
      </div>

      {/* Integration filter */}
      <div className="flex flex-wrap items-center gap-2" aria-label="Filter by integration">
        <span className="text-xs text-gray-600 w-16 shrink-0">Uses</span>
        <FacetPill
          label="All"
          active={integration === 'all'}
          onClick={() => setIntegration('all')}
        />
        {INTEGRATION_TYPES.map((intType) => {
          const n = integrationCounts[intType];
          if (n === 0) return null;
          return (
            <FacetPill
              key={intType}
              label={`${intType} (${n})`}
              active={integration === intType}
              onClick={() => setIntegration(intType)}
              activeClass="bg-teal-900/40 text-teal-300 border-teal-800"
            />
          );
        })}
      </div>

      {forkError && (
        <div
          role="alert"
          className="rounded-md border border-red-500/30 bg-red-500/5 px-4 py-2 text-xs text-red-200"
        >
          {forkError}
        </div>
      )}

      {/* Empty state */}
      {filtered.length === 0 && (
        <div className="flex flex-col items-center justify-center py-20 text-center">
          <div className="text-lg font-medium text-gray-400 mb-2">No matching playbooks</div>
          <div className="text-sm text-gray-600 mb-6">
            Try clearing your filters, or create a new playbook from scratch.
          </div>
          <Link
            href="/playbooks/new"
            className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-sm transition-colors"
          >
            Create a playbook
          </Link>
        </div>
      )}

      {/* List */}
      {filtered.length > 0 && (
        <div className="grid gap-3">
          {filtered.map((pb) => (
            <PlaybookRow
              key={pb.id}
              playbook={pb}
              forking={forkingId === pb.id}
              onPreview={() => setPreviewing(pb)}
              onFork={() => handleFork(pb)}
            />
          ))}
        </div>
      )}

      <DAGPreviewDrawer
        playbook={previewing}
        onClose={() => setPreviewing(null)}
        onFork={(pb) => handleFork(pb)}
        forking={forkingId !== null}
      />
    </div>
  );
}

/* ─────────────────────────── Generic facet pill ─────────────────────────── */

function FacetPill({
  label,
  active,
  onClick,
  activeClass,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
  activeClass?: string;
}) {
  return (
    <button
      onClick={onClick}
      className={clsx(
        'rounded-full px-3 py-0.5 text-xs font-medium border transition-colors',
        active
          ? activeClass ?? 'bg-blue-900/40 text-blue-200 border-blue-700'
          : 'border-gray-800 text-gray-500 hover:text-gray-300 hover:border-gray-700',
      )}
    >
      {label}
    </button>
  );
}

/* ─────────────────────────── Source / Category pills ─────────────────────────── */

function SourcePill({
  label,
  count,
  active,
  onClick,
  tone,
}: {
  label: string;
  count: number;
  active: boolean;
  onClick: () => void;
  tone?: 'pack';
}) {
  return (
    <button
      role="tab"
      aria-selected={active}
      onClick={onClick}
      className={clsx(
        'rounded px-2.5 py-1.5 text-xs font-medium transition-colors',
        active
          ? tone === 'pack'
            ? 'bg-purple-700 text-white'
            : 'bg-blue-600 text-white'
          : 'text-gray-400 hover:text-gray-200',
      )}
    >
      {label} ({count})
    </button>
  );
}

function CategoryPill({
  label,
  active,
  onClick,
  tone,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
  tone?: PackCategory;
}) {
  const activeClasses = tone ? categoryBadgeClass(tone) : 'bg-blue-900/40 text-blue-200 border-blue-700';
  return (
    <button
      onClick={onClick}
      className={clsx(
        'rounded-full px-3 py-1 text-xs font-medium border transition-colors',
        active ? activeClasses : 'border-gray-800 text-gray-500 hover:text-gray-300 hover:border-gray-700',
      )}
    >
      {label}
    </button>
  );
}

/* ─────────────────────────── Row ─────────────────────────── */

function PlaybookRow({
  playbook,
  forking,
  onPreview,
  onFork,
}: {
  playbook: Playbook;
  forking: boolean;
  onPreview: () => void;
  onFork: () => void;
}) {
  const isPack = isShippedPack(playbook);
  const cat = categoryOf(playbook);
  const triggerOn = playbook.trigger?.on ?? 'manual';
  const tactics = mitreTacticsOf(playbook);
  const sevs = severitiesOf(playbook);
  const integrations = integrationsOf(playbook);

  const SEVERITY_MINI: Record<SeverityLevel, string> = {
    info:     'bg-blue-900/40 text-blue-400 border-blue-800',
    low:      'bg-gray-800/60 text-gray-400 border-gray-700',
    medium:   'bg-yellow-900/40 text-yellow-400 border-yellow-800',
    high:     'bg-orange-900/40 text-orange-400 border-orange-800',
    critical: 'bg-red-900/50 text-red-300 border-red-800',
  };

  return (
    <div
      className={clsx(
        'bg-gray-900/60 border rounded-xl px-5 py-4 flex items-center gap-4 transition-colors',
        playbook.enabled ? 'border-gray-800 hover:border-gray-700' : 'border-gray-800/40 opacity-70',
      )}
    >
      <EnabledToggle playbook={playbook} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          {isPack && (
            <span
              className="text-[10px] font-semibold tracking-wide px-1.5 py-0.5 rounded border border-purple-700/60 bg-purple-900/40 text-purple-200"
              title="Shipped reference pack — fork to customize."
            >
              PACK
            </span>
          )}
          {cat && (
            <span
              className={`text-[10px] px-1.5 py-0.5 rounded border ${categoryBadgeClass(cat)}`}
              title={`Category: ${categoryLabel(cat)}`}
            >
              {categoryLabel(cat)}
            </span>
          )}
          <Link
            href={`/playbooks/${playbook.id}`}
            className="text-white font-medium hover:text-blue-300 transition-colors truncate"
          >
            {playbook.name}
          </Link>
          <span
            className={`text-xs px-2 py-0.5 rounded border ${
              TRIGGER_COLORS[triggerOn] ?? TRIGGER_COLORS.manual
            }`}
          >
            {triggerOn}
          </span>
          {!playbook.enabled && (
            <span className="text-xs px-1.5 py-0.5 rounded border border-gray-700 text-gray-500">
              disabled
            </span>
          )}
        </div>
        {playbook.description && (
          <p className="text-sm text-gray-500 mt-0.5 line-clamp-2">{playbook.description}</p>
        )}
        <div className="flex items-center gap-3 mt-1 text-xs text-gray-700">
          <span>{playbook.steps.length} steps</span>
          <span>v{playbook.version}</span>
          {playbook.author && <span>by {playbook.author}</span>}
        </div>
        {/* MITRE tactics + severity chips */}
        {(tactics.length > 0 || sevs.length > 0 || integrations.length > 0) && (
          <div className="flex flex-wrap items-center gap-1.5 mt-1.5">
            {tactics.slice(0, 3).map((t) => (
              <span
                key={t}
                className="text-[9px] px-1.5 py-0.5 rounded border border-red-900/60 bg-red-950/40 text-red-400"
                title={`MITRE tactic: ${t}`}
              >
                {t}
              </span>
            ))}
            {tactics.length > 3 && (
              <span className="text-[9px] text-gray-600">+{tactics.length - 3} more</span>
            )}
            {sevs.map((s) => (
              <span
                key={s}
                className={`text-[9px] px-1.5 py-0.5 rounded border ${SEVERITY_MINI[s]}`}
                title={`Trigger severity: ${s}`}
              >
                {s}
              </span>
            ))}
            {integrations.slice(0, 2).map((i) => (
              <span
                key={i}
                className="text-[9px] px-1.5 py-0.5 rounded border border-teal-900/60 bg-teal-950/40 text-teal-400"
                title={`Integration: ${i}`}
              >
                {i}
              </span>
            ))}
            {integrations.length > 2 && (
              <span className="text-[9px] text-gray-600">+{integrations.length - 2} integrations</span>
            )}
          </div>
        )}
      </div>
      <div className="flex items-center gap-2 flex-shrink-0">
        <RunButton playbook={playbook} />
        <button
          onClick={onPreview}
          aria-label={`Preview DAG for ${playbook.name}`}
          className="text-xs px-2.5 py-1 rounded border border-gray-700 text-gray-300 hover:text-blue-300 hover:border-blue-800 transition-colors"
        >
          Preview
        </button>
        {isPack ? (
          <button
            onClick={onFork}
            disabled={forking}
            aria-label={`Fork ${playbook.name}`}
            className="text-xs px-2.5 py-1 rounded bg-purple-700 hover:bg-purple-600 text-white transition-colors disabled:opacity-50"
          >
            {forking ? 'Forking…' : 'Fork'}
          </button>
        ) : (
          <>
            <Link
              href={`/playbooks/${playbook.id}`}
              className="text-xs px-2.5 py-1 rounded border border-gray-700 text-gray-400 hover:text-gray-200 hover:border-gray-600 transition-colors"
            >
              Edit
            </Link>
            <button
              onClick={() => deletePlaybook(playbook.id)}
              className="text-xs px-2.5 py-1 rounded border border-gray-800 text-gray-600 hover:text-red-400 hover:border-red-900 transition-colors"
              aria-label={`Delete ${playbook.name}`}
            >
              Delete
            </button>
          </>
        )}
      </div>
    </div>
  );
}
