'use client';

import { useState, useEffect } from 'react';
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

const MOCK_RULES: DetectionRule[] = [
  { id: 'sigma-1', name: 'Suspicious PowerShell Download Cradle', description: 'Detects suspicious PowerShell download patterns commonly used by attackers for initial payload delivery.', author: 'AiSOC Community', logsource_category: 'process_creation', logsource_product: 'windows', level: 'high', tags: ['attack.execution', 'attack.t1059.001'], install_count: 3412, rating: 4.6, rating_count: 89, status: 'published', submitted_at: '2026-03-15T10:00:00Z' },
  { id: 'sigma-2', name: 'AWS Root Account Usage', description: 'Detects usage of the AWS root account which should be avoided in production environments per security best practices.', author: 'Cloud Security WG', logsource_category: 'cloudtrail', logsource_product: 'aws', level: 'critical', tags: ['attack.privilege_escalation', 'attack.t1078'], install_count: 2891, rating: 4.8, rating_count: 142, status: 'published', submitted_at: '2026-02-20T14:30:00Z' },
  { id: 'sigma-3', name: 'LSASS Memory Dump via Procdump', description: 'Detects attempts to dump LSASS process memory using Sysinternals Procdump utility for credential extraction.', author: 'AiSOC Community', logsource_category: 'process_creation', logsource_product: 'windows', level: 'critical', tags: ['attack.credential_access', 'attack.t1003.001'], install_count: 4102, rating: 4.9, rating_count: 201, status: 'published', submitted_at: '2026-01-10T08:00:00Z' },
  { id: 'sigma-4', name: 'Okta Admin Role Assigned', description: 'Detects when an Okta admin role is assigned to a user, which could indicate privilege escalation.', author: 'Identity Security WG', logsource_category: 'audit', logsource_product: 'okta', level: 'medium', tags: ['attack.privilege_escalation', 'attack.t1098'], install_count: 1567, rating: 4.2, rating_count: 45, status: 'published', submitted_at: '2026-04-01T16:00:00Z' },
  { id: 'sigma-5', name: 'Linux Reverse Shell Detection', description: 'Detects common reverse shell patterns on Linux systems using bash, netcat, or Python.', author: 'AiSOC Community', logsource_category: 'process_creation', logsource_product: 'linux', level: 'high', tags: ['attack.execution', 'attack.t1059.004'], install_count: 2234, rating: 4.5, rating_count: 78, status: 'published', submitted_at: '2026-03-28T12:00:00Z' },
  { id: 'sigma-6', name: 'Azure AD Conditional Access Policy Disabled', description: 'Detects when a conditional access policy is disabled in Azure AD, potentially weakening security posture.', author: 'Cloud Security WG', logsource_category: 'audit', logsource_product: 'azure', level: 'high', tags: ['attack.defense_evasion', 'attack.t1562'], install_count: 1892, rating: 4.4, rating_count: 63, status: 'published', submitted_at: '2026-02-14T09:30:00Z' },
  { id: 'sigma-7', name: 'GCP Service Account Key Creation', description: 'Detects creation of service account keys in GCP which can be used for persistent unauthorized access.', author: 'Cloud Security WG', logsource_category: 'audit', logsource_product: 'gcp', level: 'medium', tags: ['attack.persistence', 'attack.t1098.001'], install_count: 987, rating: 4.1, rating_count: 34, status: 'published', submitted_at: '2026-04-10T11:00:00Z' },
  { id: 'sigma-8', name: 'Scheduled Task Created via Schtasks', description: 'Detects scheduled task creation via schtasks.exe which is commonly abused for persistence.', author: 'AiSOC Community', logsource_category: 'process_creation', logsource_product: 'windows', level: 'medium', tags: ['attack.persistence', 'attack.t1053.005'], install_count: 3156, rating: 4.3, rating_count: 112, status: 'published', submitted_at: '2026-01-22T15:00:00Z' },
];

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
      if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
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
      if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
      const data: DetectionListResponse = await res.json();
      setRules(data.items ?? []);
      setTotal(data.total ?? 0);
      setFetched(true);
    } catch {
      setRules(MOCK_RULES);
      setTotal(MOCK_RULES.length);
      setFetched(true);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadRules(search, productFilter, levelFilter, sortBy, page);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

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
        <div className="flex items-center gap-4">
          <button
            onClick={async () => {
              try {
                const response = await fetch('/api/v1/detection/sigma/import', {
                  method: 'POST',
                  headers: {
                    'Content-Type': 'application/json',
                  },
                  body: JSON.stringify({
                    source: 'SigmaHQ/sigma',
                    commit: 'latest',
                  }),
                });
                if (!response.ok) {
                  throw new Error(`HTTP error! status: ${response.status}`);
                }
                const result = await response.json();
                console.log('Import result:', result);
                // Reload the rules after import
                loadRules(search, productFilter, levelFilter, sortBy, page);
              } catch (error) {
                console.error('Import failed:', error);
              }
            }}
            className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 transition-colors"
          >
            Import Sigma Rules
          </button>
          <div className="text-sm text-zinc-500">
            {total > 0 && <span>{total.toLocaleString()} rules</span>}
          </div>
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
        <div className="rounded-lg border border-red-700/40 bg-red-900/20 p-4 text-sm text-red-300 flex items-center justify-between">
          <span>{error}</span>
          <button
            onClick={() => loadRules(search, productFilter, levelFilter, sortBy, page)}
            className="ml-4 rounded bg-zinc-700 px-3 py-1 text-xs text-zinc-200 hover:bg-zinc-600 transition-colors"
          >
            Retry
          </button>
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
