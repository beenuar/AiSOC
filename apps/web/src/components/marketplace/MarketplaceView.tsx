'use client';

import { useCallback, useMemo, useState } from 'react';
import useSWR from 'swr';
import clsx from 'clsx';
import { EmptyState, EmptyStateIcons } from '@/components/ui/EmptyState';
import { ErrorState } from '@/components/ui/ErrorState';

// ── Types ────────────────────────────────────────────────────────────────────

export interface MarketplaceItem {
  id: string;
  type: 'playbook' | 'detection' | 'plugin';
  name: string;
  description: string;
  version: string;
  author: string;
  tags: string[];
  severity?: 'low' | 'medium' | 'high' | 'critical';
  // community stats (populated when the install API is wired up)
  install_count?: number;
  rating?: number;
  rating_count?: number;
  // provenance
  verified?: boolean;
  source?:
    | 'core'
    | 'community'
    | 'sigmahq'
    | 'mitre-car'
    | 'splunk-security-content'
    | 'chronicle-detection-rules'
    | string;
  tier?: 'stable' | 'beta' | 'imported' | 'community';
  enabled?: boolean;
  quarantine_reason?: string;
  provenance?: {
    source?: string | null;
    source_id?: string | null;
    source_commit?: string | null;
    license?: string | null;
    license_url?: string | null;
    imported_at?: string | null;
    upstream_path?: string | null;
  };
  path?: string;
  // playbook-specific
  trigger?: string;
  steps?: number;
  // detection-specific
  category?: string;
  log_source?: string;
  playbook?: string;
  // plugin-specific
  plugin_type?: string;
  license?: string;
  homepage?: string;
  min_aisoc_version?: string;
  sdks?: string[];
  // shared
  mitre_techniques?: string[];
}

interface MitreCoverage {
  techniques: Record<string, number>;
  unique_techniques: number;
  total_with_mitre: number;
  by_tier?: Record<string, Record<string, number>>;
}

interface MarketplaceStats {
  total: number;
  playbooks: number;
  detections: number;
  plugins: number;
  verified: number;
  community: number;
  by_tier?: Record<string, number>;
  detections_by_tier?: Record<string, number>;
  quarantined?: number;
}

interface MarketplaceIndex {
  version: string;
  generated: string;
  items: MarketplaceItem[];
  stats?: MarketplaceStats;
  mitre_coverage?: MitreCoverage;
}

interface InstalledRecord {
  id: string;
  type: 'detection' | 'playbook' | 'plugin';
  name: string;
  version: string;
  content_sha256: string;
  installed_at: string;
  installed_by: string;
}

interface InstalledResponse {
  total: number;
  items: InstalledRecord[];
}

// Composite key for the installed-items set: "<type>:<id>"
function installedKey(type: string, id: string): string {
  return `${type}:${id}`;
}

// ── Constants ─────────────────────────────────────────────────────────────────

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-900/40 text-red-300 border-red-700/60',
  high:     'bg-orange-900/40 text-orange-300 border-orange-700/60',
  medium:   'bg-yellow-900/40 text-yellow-300 border-yellow-700/60',
  low:      'bg-blue-900/40 text-blue-300 border-blue-700/60',
  info:     'bg-slate-900/40 text-slate-300 border-slate-700/60',
};

const TYPE_COLORS: Record<string, string> = {
  playbook:  'bg-purple-900/40 text-purple-300 border-purple-700/60',
  detection: 'bg-cyan-900/40 text-cyan-300 border-cyan-700/60',
  plugin:    'bg-emerald-900/40 text-emerald-300 border-emerald-700/60',
};

const fetcher = async (url: string) => {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const text = await r.text();
  try {
    return JSON.parse(text);
  } catch {
    throw new Error('Invalid JSON');
  }
};

// ── Sub-components ────────────────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity?: string }) {
  if (!severity) return null;
  return (
    <span
      className={clsx(
        'inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-semibold uppercase tracking-wide',
        SEVERITY_COLORS[severity] ?? 'bg-zinc-700 text-zinc-300 border-zinc-600'
      )}
    >
      {severity}
    </span>
  );
}

function TypeBadge({ type }: { type: string }) {
  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-xs font-medium',
        TYPE_COLORS[type] ?? 'bg-zinc-700 text-zinc-300 border-zinc-600'
      )}
    >
      {type.charAt(0).toUpperCase() + type.slice(1)}
    </span>
  );
}

function VerifiedBadge() {
  return (
    <span
      title="Verified by AiSOC team"
      className="inline-flex items-center gap-0.5 rounded border border-emerald-700/60 bg-emerald-900/30 px-1.5 py-0.5 text-xs font-medium text-emerald-300"
    >
      Verified
    </span>
  );
}

function CommunityBadge() {
  return (
    <span
      title="Community contribution"
      className="inline-flex items-center gap-0.5 rounded border border-blue-700/60 bg-blue-900/30 px-1.5 py-0.5 text-xs font-medium text-blue-300"
    >
      Community
    </span>
  );
}

function StarRating({ rating, count }: { rating: number; count: number }) {
  const full = Math.floor(rating);
  const half = rating - full >= 0.5;

  return (
    <span className="inline-flex items-center gap-1 text-xs text-zinc-400">
      <span className="text-yellow-400">
        {'★'.repeat(full)}
        {half ? '½' : ''}
        {'☆'.repeat(5 - full - (half ? 1 : 0))}
      </span>
      <span className="text-zinc-500">
        {rating.toFixed(1)} ({count})
      </span>
    </span>
  );
}

function MitreTechniquesRow({ ids }: { ids: string[] }) {
  if (!ids || ids.length === 0) return null;
  const head = ids.slice(0, 3);
  const rest = ids.length - head.length;
  return (
    <div
      className="flex flex-wrap items-center gap-1"
      title={`Maps to MITRE ATT&CK techniques: ${ids.join(', ')}`}
    >
      <span className="text-[10px] uppercase tracking-wide text-zinc-500">
        ATT&amp;CK
      </span>
      {head.map((tid) => (
        <a
          key={tid}
          href={`https://attack.mitre.org/techniques/${tid.replace('.', '/')}/`}
          target="_blank"
          rel="noopener noreferrer"
          className="rounded border border-rose-700/60 bg-rose-900/30 px-1.5 py-0.5 text-[11px] font-mono font-medium text-rose-200 hover:bg-rose-900/50"
        >
          {tid}
        </a>
      ))}
      {rest > 0 && (
        <span className="rounded bg-zinc-700/60 px-1.5 py-0.5 text-[11px] text-zinc-400">
          +{rest}
        </span>
      )}
    </div>
  );
}

interface InstallButtonProps {
  item: MarketplaceItem;
  installed: boolean;
  busy: boolean;
  onInstall: (item: MarketplaceItem) => void | Promise<void>;
  onUninstall: (item: MarketplaceItem) => void | Promise<void>;
}

function InstallButton({ item, installed, busy, onInstall, onUninstall }: InstallButtonProps) {
  if (installed) {
    // Allow operators to back out of an install; visible affordance, not destructive
    // since marketplace items are already on disk – we just clear the per-tenant flag.
    return (
      <div className="flex items-center gap-1">
        <span
          className="rounded bg-emerald-900/40 px-2 py-1 text-xs font-medium text-emerald-300"
          title="Enabled for this tenant"
        >
          Installed
        </span>
        <button
          onClick={() => onUninstall(item)}
          disabled={busy}
          title="Remove from this tenant"
          className="rounded px-1.5 py-1 text-xs text-zinc-400 hover:text-rose-300 disabled:opacity-50"
        >
          {busy ? '…' : '×'}
        </button>
      </div>
    );
  }

  return (
    <button
      onClick={() => onInstall(item)}
      disabled={busy}
      className="rounded bg-zinc-700 px-2 py-1 text-xs font-medium text-zinc-200 transition-colors hover:bg-zinc-600 disabled:opacity-60"
    >
      {busy ? '…' : 'Install'}
    </button>
  );
}

function SdkChips({ sdks }: { sdks?: string[] }) {
  if (!sdks || sdks.length === 0) return null;
  return (
    <span
      className="inline-flex items-center gap-1"
      title={`Reference implementations available: ${sdks.join(', ')}`}
    >
      {sdks.includes('python') && (
        <span className="rounded border border-yellow-700/60 bg-yellow-900/30 px-1.5 py-0.5 text-[10px] font-mono uppercase text-yellow-300">
          Py
        </span>
      )}
      {sdks.includes('go') && (
        <span className="rounded border border-sky-700/60 bg-sky-900/30 px-1.5 py-0.5 text-[10px] font-mono uppercase text-sky-300">
          Go
        </span>
      )}
    </span>
  );
}

interface ItemCardProps {
  item: MarketplaceItem;
  installed: boolean;
  busy: boolean;
  onInstall: (item: MarketplaceItem) => void | Promise<void>;
  onUninstall: (item: MarketplaceItem) => void | Promise<void>;
}

function ItemCard({ item, installed, busy, onInstall, onUninstall }: ItemCardProps) {
  return (
    <div className="flex flex-col gap-3 rounded-xl border border-zinc-700/60 bg-zinc-800/60 p-4 hover:border-zinc-600 transition-colors">
      {/* Header */}
      <div className="flex items-start justify-between gap-2">
        <h3 className="text-sm font-semibold text-zinc-100 leading-snug line-clamp-2">
          {item.name}
        </h3>
        <div className="flex shrink-0 flex-wrap gap-1 justify-end">
          <TypeBadge type={item.type} />
          {item.source === 'community' ? <CommunityBadge /> : item.verified && <VerifiedBadge />}
        </div>
      </div>

      {/* Description */}
      <p className="text-xs text-zinc-400 leading-relaxed line-clamp-3">
        {item.description}
      </p>

      {/* MITRE techniques (detections + playbooks) */}
      {item.mitre_techniques && item.mitre_techniques.length > 0 && (
        <MitreTechniquesRow ids={item.mitre_techniques} />
      )}

      {/* Rating + install count */}
      {(item.rating || item.install_count) && (
        <div className="flex items-center justify-between gap-2">
          {item.rating !== undefined && item.rating > 0 ? (
            <StarRating rating={item.rating} count={item.rating_count ?? 0} />
          ) : (
            <span className="text-xs text-zinc-600">No ratings yet</span>
          )}
          {item.install_count !== undefined && (
            <span className="text-xs text-zinc-500">
              {item.install_count.toLocaleString()} installs
            </span>
          )}
        </div>
      )}

      {/* Metadata row */}
      <div className="flex flex-wrap items-center gap-2 mt-auto pt-2 border-t border-zinc-700/40">
        {item.severity && <SeverityBadge severity={item.severity} />}

        {item.type === 'playbook' && item.trigger && (
          <span className="text-xs text-zinc-500">
            trigger: <span className="text-zinc-300">{item.trigger}</span>
          </span>
        )}
        {item.type === 'playbook' && item.steps !== undefined && (
          <span className="text-xs text-zinc-500">{item.steps} steps</span>
        )}
        {item.type === 'detection' && item.category && (
          <span className="text-xs text-zinc-500">{item.category}</span>
        )}
        {item.type === 'detection' && item.log_source && (
          <span className="text-xs text-zinc-500">via {item.log_source}</span>
        )}
        {item.type === 'plugin' && item.plugin_type && (
          <span className="text-xs text-zinc-500">{item.plugin_type}</span>
        )}
        {item.type === 'plugin' && <SdkChips sdks={item.sdks} />}

        <span className="text-xs text-zinc-600">v{item.version}</span>
        <div className="ml-auto">
          <InstallButton
            item={item}
            installed={installed}
            busy={busy}
            onInstall={onInstall}
            onUninstall={onUninstall}
          />
        </div>
      </div>

      {/* Tags */}
      {item.tags && item.tags.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {item.tags.slice(0, 4).map((tag) => (
            <span
              key={tag}
              className="rounded bg-zinc-700/60 px-1.5 py-0.5 text-xs text-zinc-400"
            >
              {tag}
            </span>
          ))}
          {item.tags.length > 4 && (
            <span className="rounded bg-zinc-700/60 px-1.5 py-0.5 text-xs text-zinc-500">
              +{item.tags.length - 4}
            </span>
          )}
        </div>
      )}
    </div>
  );
}

// ── Main Component ────────────────────────────────────────────────────────────

type SortOption = 'name' | 'install_count' | 'rating' | 'newest';
type SourceFilter = 'all' | 'core' | 'community';
type SdkFilter = 'all' | 'python' | 'go' | 'both';
// stable = native AiSOC content, hand-authored with fixture tests
// beta   = working but not fully covered (e.g. Tier-2 plugin stubs)
// imported = upstream content (SigmaHQ, Splunk Security Content, Chronicle, MITRE CAR)
//            parsed and provenance-tagged but not fixture-tested per AiSOC's bar
// community = third-party contributions
type TierFilter = 'all' | 'stable' | 'beta' | 'imported' | 'community';

// Fetch the installed-set, but treat 401/404 as "not signed in / API offline"
// so the marketplace stays usable in static demos and unauthenticated previews.
async function fetchInstalled(url: string): Promise<InstalledResponse | null> {
  const res = await fetch(url, { credentials: 'include' });
  if (res.status === 401 || res.status === 404) return null;
  if (!res.ok) throw new Error(`installed: HTTP ${res.status}`);
  return (await res.json()) as InstalledResponse;
}

export function MarketplaceView() {
  const { data, error, isLoading } = useSWR<MarketplaceIndex>(
    '/marketplace/index.json',
    fetcher,
    {
      shouldRetryOnError: false,
      errorRetryCount: 1,
      revalidateOnFocus: false,
    }
  );

  const {
    data: installedData,
    mutate: refreshInstalled,
  } = useSWR<InstalledResponse | null>(
    '/api/v1/marketplace/installed',
    fetchInstalled,
    {
      revalidateOnFocus: false,
      shouldRetryOnError: false,
    }
  );

  // Locally-tracked install state; the SWR data above is the source of truth
  // when the API is reachable, but optimistic toggles live here for snappier UX.
  const [localInstalled, setLocalInstalled] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState<Set<string>>(new Set());
  const [actionError, setActionError] = useState<string | null>(null);

  const installedSet = useMemo(() => {
    const set = new Set<string>(localInstalled);
    if (installedData?.items) {
      for (const r of installedData.items) {
        set.add(installedKey(r.type, r.id));
      }
    }
    return set;
  }, [installedData, localInstalled]);

  const setBusyKey = useCallback((key: string, on: boolean) => {
    setBusy((prev) => {
      const next = new Set(prev);
      if (on) next.add(key);
      else next.delete(key);
      return next;
    });
  }, []);

  const handleInstall = useCallback(
    async (item: MarketplaceItem) => {
      const key = installedKey(item.type, item.id);
      setActionError(null);
      setBusyKey(key, true);
      // Optimistic mark so the UI flips immediately even when API is offline.
      setLocalInstalled((prev) => {
        const next = new Set(prev);
        next.add(key);
        return next;
      });
      try {
        const res = await fetch('/api/v1/marketplace/install', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ type: item.type, id: item.id }),
        });
        if (!res.ok && res.status !== 401 && res.status !== 404) {
          throw new Error(`install: HTTP ${res.status}`);
        }
        await refreshInstalled();
      } catch (err) {
        // Roll the optimistic flag back; surface a one-line toast.
        setLocalInstalled((prev) => {
          const next = new Set(prev);
          next.delete(key);
          return next;
        });
        setActionError(
          err instanceof Error
            ? `Could not install ${item.id}: ${err.message}`
            : `Could not install ${item.id}.`,
        );
      } finally {
        setBusyKey(key, false);
      }
    },
    [refreshInstalled, setBusyKey],
  );

  const handleUninstall = useCallback(
    async (item: MarketplaceItem) => {
      const key = installedKey(item.type, item.id);
      setActionError(null);
      setBusyKey(key, true);
      setLocalInstalled((prev) => {
        const next = new Set(prev);
        next.delete(key);
        return next;
      });
      try {
        const url = `/api/v1/marketplace/install?type=${encodeURIComponent(
          item.type,
        )}&id=${encodeURIComponent(item.id)}`;
        const res = await fetch(url, { method: 'DELETE', credentials: 'include' });
        if (!res.ok && res.status !== 401 && res.status !== 404) {
          throw new Error(`uninstall: HTTP ${res.status}`);
        }
        await refreshInstalled();
      } catch (err) {
        setLocalInstalled((prev) => {
          const next = new Set(prev);
          next.add(key);
          return next;
        });
        setActionError(
          err instanceof Error
            ? `Could not uninstall ${item.id}: ${err.message}`
            : `Could not uninstall ${item.id}.`,
        );
      } finally {
        setBusyKey(key, false);
      }
    },
    [refreshInstalled, setBusyKey],
  );

  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState<'all' | 'playbook' | 'detection' | 'plugin'>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [sourceFilter, setSourceFilter] = useState<SourceFilter>('all');
  const [sdkFilter, setSdkFilter] = useState<SdkFilter>('all');
  // Default to stable so that a working `cloudflare-waf` doesn't look identical
  // to a 5,937-rule pile of imported Sigma content. Users opt in to imported
  // content explicitly via the chip.
  const [tierFilter, setTierFilter] = useState<TierFilter>('stable');
  const [mitreFilter, setMitreFilter] = useState<string>('all');
  const [sortBy, setSortBy] = useState<SortOption>('name');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc');

  // Build distinct, sorted MITRE technique list (with item counts) for the filter.
  const mitreOptions = useMemo(() => {
    if (!data?.items) return [] as { id: string; count: number }[];
    const byId = new Map<string, number>();
    for (const it of data.items) {
      for (const tid of it.mitre_techniques ?? []) {
        byId.set(tid, (byId.get(tid) ?? 0) + 1);
      }
    }
    return Array.from(byId.entries())
      .map(([id, count]) => ({ id, count }))
      .sort((a, b) => a.id.localeCompare(b.id));
  }, [data]);

  // Distinct content categories (detection.category + playbook.category) for filter.
  const categoryOptions = useMemo(() => {
    if (!data?.items) return [] as string[];
    const set = new Set<string>();
    for (const it of data.items) {
      if (it.category) set.add(it.category);
    }
    return Array.from(set).sort();
  }, [data]);

  // Counts per tier so chips can show "Stable (865)" etc. — helps users
  // understand at a glance that imported content dwarfs native content.
  const tierCounts = useMemo(() => {
    const counts: Record<TierFilter, number> = {
      all: 0,
      stable: 0,
      beta: 0,
      imported: 0,
      community: 0,
    };
    if (!data?.items) return counts;
    counts.all = data.items.length;
    for (const it of data.items) {
      const tier = (it.tier ?? 'stable') as TierFilter;
      if (tier in counts) counts[tier]++;
    }
    return counts;
  }, [data]);

  const items = useMemo(() => {
    if (!data?.items) return [];

    const filtered = data.items.filter((item) => {
      if (typeFilter !== 'all' && item.type !== typeFilter) return false;
      if (severityFilter !== 'all' && item.severity !== severityFilter) return false;
      if (categoryFilter !== 'all' && item.category !== categoryFilter) return false;
      if (sourceFilter !== 'all' && (item.source ?? 'core') !== sourceFilter) return false;
      if (tierFilter !== 'all') {
        // Items with no explicit tier are treated as `stable` so existing
        // hand-curated content (Cloudflare WAF, native detection rules)
        // surfaces by default without requiring a backfill of every entry.
        const itemTier = item.tier ?? 'stable';
        if (itemTier !== tierFilter) return false;
      }
      if (mitreFilter !== 'all' && !(item.mitre_techniques ?? []).includes(mitreFilter)) return false;
      if (sdkFilter !== 'all') {
        if (item.type !== 'plugin') return false;
        const sdks = item.sdks ?? [];
        if (sdkFilter === 'both' && !(sdks.includes('python') && sdks.includes('go'))) {
          return false;
        }
        if ((sdkFilter === 'python' || sdkFilter === 'go') && !sdks.includes(sdkFilter)) {
          return false;
        }
      }
      if (search) {
        const q = search.toLowerCase();
        return (
          item.name.toLowerCase().includes(q) ||
          item.description.toLowerCase().includes(q) ||
          (item.tags ?? []).some((t) => t.toLowerCase().includes(q)) ||
          (item.mitre_techniques ?? []).some((m) => m.toLowerCase().includes(q)) ||
          item.id.toLowerCase().includes(q)
        );
      }
      return true;
    });

    filtered.sort((a, b) => {
      let va: number | string = 0;
      let vb: number | string = 0;
      if (sortBy === 'name') {
        va = a.name.toLowerCase();
        vb = b.name.toLowerCase();
      } else if (sortBy === 'install_count') {
        va = a.install_count ?? 0;
        vb = b.install_count ?? 0;
      } else if (sortBy === 'rating') {
        va = a.rating ?? 0;
        vb = b.rating ?? 0;
      }
      if (va < vb) return sortOrder === 'asc' ? -1 : 1;
      if (va > vb) return sortOrder === 'asc' ? 1 : -1;
      // Stable secondary sort by id
      const ida = a.id.toLowerCase();
      const idb = b.id.toLowerCase();
      if (ida < idb) return -1;
      if (ida > idb) return 1;
      return 0;
    });

    return filtered;
  }, [
    data,
    search,
    typeFilter,
    severityFilter,
    categoryFilter,
    sourceFilter,
    sdkFilter,
    tierFilter,
    mitreFilter,
    sortBy,
    sortOrder,
  ]);

  const stats = useMemo(() => {
    if (!data?.items) return null;
    if (data.stats) return data.stats;
    return {
      total:      data.items.length,
      playbooks:  data.items.filter((i) => i.type === 'playbook').length,
      detections: data.items.filter((i) => i.type === 'detection').length,
      plugins:    data.items.filter((i) => i.type === 'plugin').length,
      verified:   data.items.filter((i) => i.verified).length,
      community:  data.items.filter((i) => i.source === 'community').length,
    };
  }, [data]);

  const toggleSort = (field: SortOption) => {
    if (sortBy === field) {
      setSortOrder((o) => (o === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortBy(field);
      setSortOrder(field === 'name' ? 'asc' : 'desc');
    }
  };

  const clearFilters = () => {
    setSearch('');
    setTypeFilter('all');
    setSeverityFilter('all');
    setCategoryFilter('all');
    setSourceFilter('all');
    setSdkFilter('all');
    // Reset tier to its default (`stable`) rather than `all` so users land
    // back on the curated view, not on 6,000+ rules.
    setTierFilter('stable');
    setMitreFilter('all');
  };

  return (
    <div className="flex h-full flex-col gap-6 p-6">
      {/* Page Header */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-[280px] flex-1">
          <h1 className="text-2xl font-bold text-zinc-100">Marketplace</h1>
          <p className="mt-1 text-sm text-zinc-400">
            Browse and install detection rules, response playbooks, and plugins shipped with AiSOC. Every entry is generated directly from the
            repo&rsquo;s <code className="text-zinc-300">detections/</code>,{' '}
            <code className="text-zinc-300">playbooks/</code> and{' '}
            <code className="text-zinc-300">plugins/</code> trees, so what you see here is what your AiSOC instance has on disk.
          </p>
        </div>
        {installedSet.size > 0 && (
          <span
            className="self-start rounded-full bg-emerald-900/40 px-3 py-1 text-xs font-medium text-emerald-300"
            title="Items enabled for the current tenant"
          >
            {installedSet.size} installed
          </span>
        )}
      </div>

      {actionError && (
        <div
          role="alert"
          className="flex items-start justify-between gap-3 rounded-lg border border-rose-700/40 bg-rose-900/20 px-4 py-2 text-sm text-rose-200"
        >
          <span>{actionError}</span>
          <button
            onClick={() => setActionError(null)}
            className="text-rose-400 hover:text-rose-200"
            aria-label="Dismiss"
          >
            ×
          </button>
        </div>
      )}

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-6">
          {[
            { label: 'Total',       value: stats.total,      color: 'text-zinc-100' },
            { label: 'Playbooks',   value: stats.playbooks,  color: 'text-purple-300' },
            { label: 'Detections',  value: stats.detections, color: 'text-cyan-300' },
            { label: 'Plugins',     value: stats.plugins,    color: 'text-emerald-300' },
            { label: 'Verified',    value: stats.verified,   color: 'text-emerald-400' },
            { label: 'Community',   value: stats.community,  color: 'text-blue-300' },
          ].map(({ label, value, color }) => (
            <div
              key={label}
              className="rounded-xl border border-zinc-700/60 bg-zinc-800/60 p-4 text-center"
            >
              <p className={clsx('text-3xl font-bold tabular-nums', color)}>{value}</p>
              <p className="mt-1 text-xs text-zinc-500">{label}</p>
            </div>
          ))}
        </div>
      )}

      {/* Search + primary filter chips */}
      <div className="flex flex-wrap items-center gap-3">
        <input
          type="search"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search by name, description, tag, MITRE ID, or item ID…"
          className="flex-1 min-w-[240px] rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-500 focus:border-zinc-500 focus:outline-none"
        />

        {/* Type filter */}
        <div className="flex gap-1 rounded-lg border border-zinc-700 bg-zinc-800 p-1">
          {(['all', 'playbook', 'detection', 'plugin'] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTypeFilter(t)}
              className={clsx(
                'rounded px-2.5 py-1.5 text-xs font-medium transition-colors capitalize',
                typeFilter === t ? 'bg-zinc-600 text-zinc-100' : 'text-zinc-400 hover:text-zinc-200'
              )}
            >
              {t === 'all' ? 'All' : `${t.charAt(0).toUpperCase() + t.slice(1)}s`}
            </button>
          ))}
        </div>

        {/* Source filter (core vs community) */}
        <div className="flex gap-1 rounded-lg border border-zinc-700 bg-zinc-800 p-1">
          {(['all', 'core', 'community'] as const).map((s) => (
            <button
              key={s}
              onClick={() => setSourceFilter(s)}
              className={clsx(
                'rounded px-2.5 py-1.5 text-xs font-medium transition-colors capitalize',
                sourceFilter === s ? 'bg-zinc-600 text-zinc-100' : 'text-zinc-400 hover:text-zinc-200'
              )}
            >
              {s === 'all' ? 'All sources' : s}
            </button>
          ))}
        </div>

        {/* Tier filter — defaults to `stable` so working integrations and
            hand-authored detections don't get drowned in imported Sigma
            content. Users opt into imported/beta/community explicitly. */}
        <div
          className="flex gap-1 rounded-lg border border-zinc-700 bg-zinc-800 p-1"
          title="Stable = native AiSOC content. Imported = upstream rules (SigmaHQ, Splunk, Chronicle, CAR), parseable but not fixture-tested. Beta = working but partial. Community = third-party."
        >
          {(['all', 'stable', 'beta', 'imported', 'community'] as const).map((t) => {
            const count = tierCounts[t];
            const label = t === 'all' ? 'All tiers' : t.charAt(0).toUpperCase() + t.slice(1);
            return (
              <button
                key={t}
                onClick={() => setTierFilter(t)}
                className={clsx(
                  'rounded px-2.5 py-1.5 text-xs font-medium transition-colors',
                  tierFilter === t ? 'bg-zinc-600 text-zinc-100' : 'text-zinc-400 hover:text-zinc-200'
                )}
              >
                {label}
                {count > 0 && <span className="ml-1 text-zinc-500">({count})</span>}
              </button>
            );
          })}
        </div>
      </div>

      {/* Secondary filters: severity, category, MITRE, SDK */}
      <div className="flex flex-wrap items-center gap-3 -mt-3">
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-300 focus:border-zinc-500 focus:outline-none"
        >
          <option value="all">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>

        {categoryOptions.length > 0 && (
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-300 focus:border-zinc-500 focus:outline-none"
          >
            <option value="all">All categories</option>
            {categoryOptions.map((c) => (
              <option key={c} value={c}>{c}</option>
            ))}
          </select>
        )}

        {/* MITRE technique filter - the headline new filter the plan asks for */}
        {mitreOptions.length > 0 && (
          <select
            value={mitreFilter}
            onChange={(e) => setMitreFilter(e.target.value)}
            className="rounded-lg border border-rose-800/60 bg-rose-900/20 px-3 py-2 text-sm text-rose-200 focus:border-rose-600 focus:outline-none"
            title="Filter by MITRE ATT&CK technique"
          >
            <option value="all">
              MITRE ATT&amp;CK ({mitreOptions.length} techniques)
            </option>
            {mitreOptions.map((m) => (
              <option key={m.id} value={m.id}>
                {m.id} ({m.count})
              </option>
            ))}
          </select>
        )}

        {/* SDK filter (only meaningful when type=plugin or all) */}
        <select
          value={sdkFilter}
          onChange={(e) => setSdkFilter(e.target.value as SdkFilter)}
          className="rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-300 focus:border-zinc-500 focus:outline-none"
          title="Filter plugins by SDK availability"
        >
          <option value="all">Any SDK</option>
          <option value="both">Plugins: Python + Go</option>
          <option value="python">Plugins: Python only</option>
          <option value="go">Plugins: Go only</option>
        </select>

        <a
          href="https://github.com/beenuar/AiSOC/blob/main/CONTRIBUTING.md#community-marketplace"
          target="_blank"
          rel="noopener noreferrer"
          className="ml-auto rounded-lg border border-blue-700/60 bg-blue-900/20 px-3 py-1.5 text-xs font-medium text-blue-300 hover:bg-blue-900/40"
        >
          + Contribute to the marketplace
        </a>
      </div>

      {/* Sort bar */}
      <div className="flex items-center gap-2 -mt-3">
        <span className="text-xs text-zinc-500">Sort by:</span>
        {(['name', 'install_count', 'rating'] as SortOption[]).map((field) => (
          <button
            key={field}
            onClick={() => toggleSort(field)}
            className={clsx(
              'text-xs px-2 py-1 rounded transition-colors',
              sortBy === field ? 'text-zinc-100 bg-zinc-700' : 'text-zinc-400 hover:text-zinc-200'
            )}
          >
            {field === 'install_count' ? 'Installs' : field === 'rating' ? 'Rating' : 'Name'}
            {sortBy === field && (sortOrder === 'desc' ? ' ↓' : ' ↑')}
          </button>
        ))}
        <span className="ml-auto text-xs text-zinc-500">
          Showing {items.length} of {data?.items.length ?? 0}
        </span>
      </div>

      {/* Grid */}
      {isLoading && (
        <div className="flex items-center justify-center py-20 text-zinc-500">
          Loading marketplace…
        </div>
      )}

      {error && (
        <ErrorState
          title="Couldn't load marketplace"
          description="Make sure /marketplace/index.json is served as a static file. Run `pnpm marketplace:build` to regenerate it."
          error={error}
        />
      )}

      {!isLoading && !error && items.length === 0 && (
        // WS-F5 — marketplace ships with a non-empty index by default, so
        // the only realistic empty state here is a filter-miss.
        <EmptyState
          icon={EmptyStateIcons.search}
          title="No marketplace items match your filters"
          description="Try a different category or clear your filters to see all 50+ playbooks, detections, and plugins."
          action={
            <button
              onClick={clearFilters}
              className="text-xs px-3 py-1.5 rounded-md border border-blue-500/40 bg-blue-500/10 text-blue-300 hover:bg-blue-500/20 transition-colors"
            >
              Clear filters
            </button>
          }
          className="bg-transparent py-12"
        />
      )}

      {!isLoading && !error && items.length > 0 && (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 pb-6">
          {items.map((item) => {
            const key = installedKey(item.type, item.id);
            return (
              <ItemCard
                key={key}
                item={item}
                installed={installedSet.has(key)}
                busy={busy.has(key)}
                onInstall={handleInstall}
                onUninstall={handleUninstall}
              />
            );
          })}
        </div>
      )}
    </div>
  );
}
