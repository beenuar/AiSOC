'use client';

import { useState, useMemo } from 'react';
import clsx from 'clsx';

// ── Types ─────────────────────────────────────────────────────────────────────

interface DetectionRule {
  id: string;
  name: string;
  description: string;
  author: string;
  logsource_category?: string;
  logsource_product?: string;
  level?: 'informational' | 'low' | 'medium' | 'high' | 'critical';
  tags?: string[];
  install_count: number;
  rating: number;
  rating_count: number;
  status: string;
  submitted_at: string;
}

interface DetectionListResponse {
  items: DetectionRule[];
  total: number;
  page: number;
  page_size: number;
}

// ── Constants ─────────────────────────────────────────────────────────────────

const LEVEL_COLORS: Record<string, string> = {
  critical:      'bg-red-900/40 text-red-300 border-red-700/60',
  high:          'bg-orange-900/40 text-orange-300 border-orange-700/60',
  medium:        'bg-yellow-900/40 text-yellow-300 border-yellow-700/60',
  low:           'bg-blue-900/40 text-blue-300 border-blue-700/60',
  informational: 'bg-zinc-700/60 text-zinc-400 border-zinc-600',
};

const PAGE_SIZE = 24;

// ── Sub-components ────────────────────────────────────────────────────────────

function LevelBadge({ level }: { level?: string }) {
  if (!level) return null;
  return (
    <span
      className={clsx(
        'inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-semibold uppercase tracking-wide',
        LEVEL_COLORS[level] ?? 'bg-zinc-700 text-zinc-300 border-zinc-600'
      )}
    >
      {level}
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

function DetectionCard({ rule }: { rule: DetectionRule }) {
  const [installing, setInstalling] = useState(false);
  const [installed, setInstalled] = useState(false);
  const [detail, setDetail] = useState<string | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);

  const handleInstall = async (e: React.MouseEvent) => {
    e.stopPropagation();
    setInstalling(true);
    try {
      await fetch(`/api/v1/community/detections/${rule.id}/install`, { method: 'POST' });
      setInstalled(true);
    } catch {
      // ignore
    } finally {
      setInstalling(false);
    }
  };

  const toggleDetail = async () => {
    if (detail !== null) {
      setDetail(null);
      return;
    }
    setLoadingDetail(true);
    try {
      const res = await fetch(`/api/v1/community/detections/${rule.id}`);
      const data = await res.json();
      setDetail(data.sigma_yaml ?? 'No content available');
    } catch {
      setDetail('Failed to load rule content.');
    } finally {
      setLoadingDetail(false);
    }
  };

  return (
    <div
      className="flex flex-col gap-3 rounded-xl border border-zinc-700/60 bg-zinc-800/60 p-4 hover:border-zinc-600 transition-colors cursor-pointer"
      onClick={toggleDetail}
    >
      {/* Header */}
      <div className="flex items-start justify-between gap-2">
        <h3 className="text-sm font-semibold text-zinc-100 leading-snug line-clamp-2 flex-1">
          {rule.name}
        </h3>
        <LevelBadge level={rule.level} />
      </div>

      {/* Description */}
      <p className="text-xs text-zinc-400 leading-relaxed line-clamp-3">
        {rule.description || 'No description provided.'}
      </p>

      {/* Metadata */}
      <div className="flex items-center gap-3 text-xs text-zinc-500">
        {rule.logsource_product && (
          <span className="rounded bg-zinc-700/60 px-1.5 py-0.5 text-zinc-300">
            {rule.logsource_product}
          </span>
        )}
        {rule.logsource_category && (
          <span className="rounded bg-zinc-700/60 px-1.5 py-0.5 text-zinc-400">
            {rule.logsource_category}
          </span>
        )}
      </div>

      {/* Rating + installs */}
      <div className="flex items-center justify-between">
        {rule.rating > 0 ? (
          <StarRating rating={rule.rating} count={rule.rating_count} />
        ) : (
          <span className="text-xs text-zinc-600">No ratings</span>
        )}
        <span className="text-xs text-zinc-500">{rule.install_count.toLocaleString()} installs</span>
      </div>

      {/* Tags */}
      {rule.tags && rule.tags.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {rule.tags.slice(0, 5).map((t) => (
            <span key={t} className="rounded bg-zinc-700/50 px-1.5 py-0.5 text-xs text-zinc-400">
              {t}
            </span>
          ))}
          {rule.tags.length > 5 && (
            <span className="text-xs text-zinc-600">+{rule.tags.length - 5}</span>
          )}
        </div>
      )}

      {/* Install button */}
      <div className="flex items-center justify-between pt-2 border-t border-zinc-700/40">
        <span className="text-xs text-zinc-600">by {rule.author}</span>
        <button
          onClick={handleInstall}
          disabled={installing || installed}
          className={clsx(
            'rounded px-2.5 py-1 text-xs font-medium transition-colors',
            installed
              ? 'bg-emerald-900/40 text-emerald-300 cursor-default'
              : 'bg-zinc-700 text-zinc-200 hover:bg-zinc-600'
          )}
        >
          {installed ? '✓ Installed' : installing ? '…' : 'Install Rule'}
        </button>
      </div>

      {/* Expandable YAML */}
      {(loadingDetail || detail !== null) && (
        <div
          className="mt-1 rounded-lg bg-zinc-900 p-3 text-xs font-mono text-zinc-300 overflow-auto max-h-64 whitespace-pre"
          onClick={(e) => e.stopPropagation()}
        >
          {loadingDetail ? 'Loading…' : detail}
        </div>
      )}
    </div>
  );
}

// ── Main Component ────────────────────────────────────────────────────────────

export function DetectionCatalog() {
  const [search, setSearch] = useState('');
  const [productFilter, setProductFilter] = useState('all');
  const [levelFilter, setLevelFilter] = useState('all');
  const [sortBy, setSortBy] = useState<'install_count' | 'rating' | 'name'>('install_count');
  const [page, setPage] = useState(1);
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [fetched, setFetched] = useState(false);

  const loadRules = async (
    q: string,
    product: string,
    level: string,
    sort: string,
    p: number
  ) => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams({
        page: String(p),
        page_size: String(PAGE_SIZE),
        sort_by: sort,
      });
      if (q) params.set('search', q);
      if (product !== 'all') params.set('logsource_product', product);
      if (level !== 'all') params.set('level', level);

      const res = await fetch(`/api/v1/community/detections?${params}`);
      const data: DetectionListResponse = await res.json();
      setRules(data.items ?? []);
      setTotal(data.total ?? 0);
      setFetched(true);
    } catch {
      setError('Failed to load detection catalog.');
    } finally {
      setLoading(false);
    }
  };

  // Load on first render
  useState(() => {
    loadRules(search, productFilter, levelFilter, sortBy, page);
  });

  const handleSearch = () => {
    setPage(1);
    loadRules(search, productFilter, levelFilter, sortBy, 1);
  };

  const handleFilterChange = (newProduct: string, newLevel: string, newSort: typeof sortBy) => {
    setProductFilter(newProduct);
    setLevelFilter(newLevel);
    setSortBy(newSort);
    setPage(1);
    loadRules(search, newProduct, newLevel, newSort, 1);
  };

  const totalPages = Math.ceil(total / PAGE_SIZE);

  const PRODUCTS = ['windows', 'linux', 'macos', 'aws', 'azure', 'gcp', 'okta', 'office365'];

  return (
    <div className="flex h-full flex-col gap-6 p-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-zinc-100">Detection Catalog</h1>
          <p className="mt-1 text-sm text-zinc-400">
            Browse and install community Sigma detection rules for your SOC.
          </p>
        </div>
        <div className="text-sm text-zinc-500">
          {total > 0 && <span>{total.toLocaleString()} rules</span>}
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex flex-1 min-w-[240px] gap-2">
          <input
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
            placeholder="Search rules…"
            className="flex-1 rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-500 focus:border-zinc-500 focus:outline-none"
          />
          <button
            onClick={handleSearch}
            className="rounded-lg bg-zinc-700 px-3 py-2 text-sm text-zinc-200 hover:bg-zinc-600 transition-colors"
          >
            Search
          </button>
        </div>

        <select
          value={productFilter}
          onChange={(e) => handleFilterChange(e.target.value, levelFilter, sortBy)}
          className="rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-300 focus:border-zinc-500 focus:outline-none"
        >
          <option value="all">All Products</option>
          {PRODUCTS.map((p) => (
            <option key={p} value={p}>{p.charAt(0).toUpperCase() + p.slice(1)}</option>
          ))}
        </select>

        <select
          value={levelFilter}
          onChange={(e) => handleFilterChange(productFilter, e.target.value, sortBy)}
          className="rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-300 focus:border-zinc-500 focus:outline-none"
        >
          <option value="all">All Levels</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="informational">Informational</option>
        </select>

        <div className="flex gap-1 rounded-lg border border-zinc-700 bg-zinc-800 p-1">
          {(['install_count', 'rating', 'name'] as const).map((s) => (
            <button
              key={s}
              onClick={() => handleFilterChange(productFilter, levelFilter, s)}
              className={clsx(
                'rounded px-2.5 py-1.5 text-xs font-medium transition-colors',
                sortBy === s ? 'bg-zinc-600 text-zinc-100' : 'text-zinc-400 hover:text-zinc-200'
              )}
            >
              {s === 'install_count' ? 'Popular' : s === 'rating' ? 'Top Rated' : 'Name'}
            </button>
          ))}
        </div>
      </div>

      {/* Content */}
      {loading && (
        <div className="flex items-center justify-center py-20 text-zinc-500">
          Loading detection catalog…
        </div>
      )}

      {error && (
        <div className="rounded-lg border border-red-700/40 bg-red-900/20 p-4 text-sm text-red-300">
          {error}
        </div>
      )}

      {!loading && !error && fetched && rules.length === 0 && (
        <div className="flex flex-col items-center justify-center py-20 text-zinc-500">
          <p className="text-sm">No detection rules found.</p>
          <p className="text-xs mt-1">
            Publish rules with{' '}
            <code className="text-zinc-400">aisoc detection validate &amp;&amp; aisoc detection publish</code>
          </p>
        </div>
      )}

      {!loading && rules.length > 0 && (
        <>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
            {rules.map((rule) => (
              <DetectionCard key={rule.id} rule={rule} />
            ))}
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-center gap-2 pt-4">
              <button
                onClick={() => {
                  const newPage = page - 1;
                  setPage(newPage);
                  loadRules(search, productFilter, levelFilter, sortBy, newPage);
                }}
                disabled={page <= 1}
                className="rounded px-3 py-1.5 text-sm text-zinc-400 hover:text-zinc-200 disabled:opacity-30"
              >
                ← Prev
              </button>
              <span className="text-sm text-zinc-500">
                Page {page} of {totalPages}
              </span>
              <button
                onClick={() => {
                  const newPage = page + 1;
                  setPage(newPage);
                  loadRules(search, productFilter, levelFilter, sortBy, newPage);
                }}
                disabled={page >= totalPages}
                className="rounded px-3 py-1.5 text-sm text-zinc-400 hover:text-zinc-200 disabled:opacity-30"
              >
                Next →
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
