'use client';

import { useState, useMemo } from 'react';
import useSWR from 'swr';
import clsx from 'clsx';

// ── Types ────────────────────────────────────────────────────────────────────

interface MarketplaceItem {
  id: string;
  type: 'playbook' | 'detection' | 'plugin';
  name: string;
  description: string;
  version: string;
  author: string;
  tags: string[];
  severity?: 'low' | 'medium' | 'high' | 'critical';
  // community stats
  install_count?: number;
  rating?: number;
  rating_count?: number;
  verified?: boolean;
  // playbook-specific
  trigger?: string;
  steps?: number;
  // detection-specific
  category?: string;
  // plugin-specific
  plugin_type?: string;
}

interface MarketplaceIndex {
  version: string;
  generated: string;
  items: MarketplaceItem[];
}

// ── Constants ─────────────────────────────────────────────────────────────────

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-900/40 text-red-300 border-red-700/60',
  high:     'bg-orange-900/40 text-orange-300 border-orange-700/60',
  medium:   'bg-yellow-900/40 text-yellow-300 border-yellow-700/60',
  low:      'bg-blue-900/40 text-blue-300 border-blue-700/60',
};

const TYPE_COLORS: Record<string, string> = {
  playbook:  'bg-purple-900/40 text-purple-300 border-purple-700/60',
  detection: 'bg-cyan-900/40 text-cyan-300 border-cyan-700/60',
  plugin:    'bg-emerald-900/40 text-emerald-300 border-emerald-700/60',
};

const TYPE_ICONS: Record<string, string> = {
  playbook:  '⚡',
  detection: '🔍',
  plugin:    '🔌',
};

const fetcher = (url: string) => fetch(url).then((r) => r.json());

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
      {TYPE_ICONS[type] ?? '📦'} {type.charAt(0).toUpperCase() + type.slice(1)}
    </span>
  );
}

function VerifiedBadge() {
  return (
    <span
      title="Verified by AiSOC team"
      className="inline-flex items-center gap-0.5 rounded border border-emerald-700/60 bg-emerald-900/30 px-1.5 py-0.5 text-xs font-medium text-emerald-300"
    >
      ✓ Verified
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

function InstallButton({ item }: { item: MarketplaceItem }) {
  const [installing, setInstalling] = useState(false);
  const [installed, setInstalled] = useState(false);

  const handleInstall = async () => {
    setInstalling(true);
    try {
      const endpoint =
        item.type === 'plugin'
          ? `/api/v1/community/plugins/${item.id}/install`
          : item.type === 'detection'
          ? `/api/v1/community/detections/${item.id}/install`
          : `/api/v1/community/playbooks/${item.id}/install`;

      await fetch(endpoint, { method: 'POST' });
      setInstalled(true);
    } catch {
      // silently ignore for now
    } finally {
      setInstalling(false);
    }
  };

  return (
    <button
      onClick={handleInstall}
      disabled={installing || installed}
      className={clsx(
        'rounded px-2 py-1 text-xs font-medium transition-colors',
        installed
          ? 'bg-emerald-900/40 text-emerald-300 cursor-default'
          : 'bg-zinc-700 text-zinc-200 hover:bg-zinc-600'
      )}
    >
      {installed ? '✓ Installed' : installing ? '…' : 'Install'}
    </button>
  );
}

function ItemCard({ item, sortBy }: { item: MarketplaceItem; sortBy: string }) {
  return (
    <div className="flex flex-col gap-3 rounded-xl border border-zinc-700/60 bg-zinc-800/60 p-4 hover:border-zinc-600 transition-colors">
      {/* Header */}
      <div className="flex items-start justify-between gap-2">
        <h3 className="text-sm font-semibold text-zinc-100 leading-snug line-clamp-2">
          {item.name}
        </h3>
        <div className="flex shrink-0 flex-wrap gap-1 justify-end">
          <TypeBadge type={item.type} />
          {item.verified && <VerifiedBadge />}
        </div>
      </div>

      {/* Description */}
      <p className="text-xs text-zinc-400 leading-relaxed line-clamp-3">
        {item.description}
      </p>

      {/* Rating + install count */}
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
        {item.type === 'plugin' && item.plugin_type && (
          <span className="text-xs text-zinc-500">{item.plugin_type}</span>
        )}

        <span className="text-xs text-zinc-600">v{item.version}</span>
        <div className="ml-auto">
          <InstallButton item={item} />
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

export function MarketplaceView() {
  const { data, error, isLoading } = useSWR<MarketplaceIndex>(
    '/marketplace/index.json',
    fetcher
  );

  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState<'all' | 'playbook' | 'detection' | 'plugin'>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');
  const [sortBy, setSortBy] = useState<SortOption>('install_count');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');

  const categories = useMemo(() => {
    if (!data?.items) return [];
    const cats = new Set(data.items.flatMap((i) => i.tags ?? []));
    return Array.from(cats).sort();
  }, [data]);

  const items = useMemo(() => {
    if (!data?.items) return [];

    let filtered = data.items.filter((item) => {
      if (typeFilter !== 'all' && item.type !== typeFilter) return false;
      if (severityFilter !== 'all' && item.severity !== severityFilter) return false;
      if (categoryFilter !== 'all' && !(item.tags ?? []).includes(categoryFilter)) return false;
      if (search) {
        const q = search.toLowerCase();
        return (
          item.name.toLowerCase().includes(q) ||
          item.description.toLowerCase().includes(q) ||
          (item.tags ?? []).some((t) => t.toLowerCase().includes(q))
        );
      }
      return true;
    });

    // Sort
    filtered.sort((a, b) => {
      let va: number | string, vb: number | string;
      if (sortBy === 'name') {
        va = a.name.toLowerCase();
        vb = b.name.toLowerCase();
      } else if (sortBy === 'install_count') {
        va = a.install_count ?? 0;
        vb = b.install_count ?? 0;
      } else if (sortBy === 'rating') {
        va = a.rating ?? 0;
        vb = b.rating ?? 0;
      } else {
        va = 0;
        vb = 0;
      }
      if (va < vb) return sortOrder === 'asc' ? -1 : 1;
      if (va > vb) return sortOrder === 'asc' ? 1 : -1;
      return 0;
    });

    return filtered;
  }, [data, search, typeFilter, severityFilter, categoryFilter, sortBy, sortOrder]);

  const stats = useMemo(() => {
    if (!data?.items) return null;
    return {
      total:      data.items.length,
      playbooks:  data.items.filter((i) => i.type === 'playbook').length,
      detections: data.items.filter((i) => i.type === 'detection').length,
      plugins:    data.items.filter((i) => i.type === 'plugin').length,
      verified:   data.items.filter((i) => i.verified).length,
    };
  }, [data]);

  const toggleSort = (field: SortOption) => {
    if (sortBy === field) {
      setSortOrder((o) => (o === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortBy(field);
      setSortOrder('desc');
    }
  };

  return (
    <div className="flex h-full flex-col gap-6 p-6">
      {/* Page Header */}
      <div>
        <h1 className="text-2xl font-bold text-zinc-100">Marketplace</h1>
        <p className="mt-1 text-sm text-zinc-400">
          Browse and install community-contributed playbooks, detection rules, and plugins for your SOC.
        </p>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
          {[
            { label: 'Total',       value: stats.total,      color: 'text-zinc-100' },
            { label: 'Playbooks',   value: stats.playbooks,  color: 'text-purple-300' },
            { label: 'Detections',  value: stats.detections, color: 'text-cyan-300' },
            { label: 'Plugins',     value: stats.plugins,    color: 'text-emerald-300' },
            { label: 'Verified',    value: stats.verified,   color: 'text-emerald-400' },
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

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <input
          type="search"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search by name, description, or tag…"
          className="flex-1 min-w-[200px] rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-500 focus:border-zinc-500 focus:outline-none"
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
              {t === 'all' ? 'All' : `${TYPE_ICONS[t]} ${t.charAt(0).toUpperCase() + t.slice(1)}s`}
            </button>
          ))}
        </div>

        {/* Severity filter */}
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-300 focus:border-zinc-500 focus:outline-none"
        >
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>

        {/* Category filter */}
        {categories.length > 0 && (
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-300 focus:border-zinc-500 focus:outline-none"
          >
            <option value="all">All Categories</option>
            {categories.map((c) => (
              <option key={c} value={c}>{c}</option>
            ))}
          </select>
        )}
      </div>

      {/* Sort bar */}
      <div className="flex items-center gap-2 -mt-3">
        <span className="text-xs text-zinc-500">Sort by:</span>
        {(['install_count', 'rating', 'name'] as SortOption[]).map((field) => (
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
        <div className="rounded-lg border border-red-700/40 bg-red-900/20 p-4 text-sm text-red-300">
          Failed to load marketplace data. Make sure{' '}
          <code className="text-red-200">/marketplace/index.json</code> is served
          as a static file.
        </div>
      )}

      {!isLoading && !error && items.length === 0 && (
        <div className="flex flex-col items-center justify-center py-20 text-zinc-500">
          <p className="text-sm">No items match your filters.</p>
          <button
            onClick={() => {
              setSearch('');
              setTypeFilter('all');
              setSeverityFilter('all');
              setCategoryFilter('all');
            }}
            className="mt-2 text-xs text-zinc-400 underline hover:text-zinc-200"
          >
            Clear filters
          </button>
        </div>
      )}

      {!isLoading && !error && items.length > 0 && (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 pb-6">
          {items.map((item) => (
            <ItemCard key={item.id} item={item} sortBy={sortBy} />
          ))}
        </div>
      )}
    </div>
  );
}
