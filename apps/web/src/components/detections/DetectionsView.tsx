'use client';

import { useMemo, useState } from 'react';
import Link from 'next/link';
import useSWR from 'swr';
import { clsx } from 'clsx';
import { formatDistanceToNow } from 'date-fns';
import toast from 'react-hot-toast';
import {
  detectionApi,
  type DetectionLanguage,
  type DetectionRule,
} from '@/lib/api';
import { Skeleton } from '@/components/ui/Skeleton';
import { ErrorState } from '@/components/ui/ErrorState';
import { EmptyState } from '@/components/ui/EmptyState';
import { ContributorLeaderboard } from './ContributorLeaderboard';
import { MitreRuleHeatmap } from './MitreRuleHeatmap';
import { ConfidenceTrends } from './ConfidenceTrends';
import { DriftInbox } from './DriftInbox';

// ─── Demo fallback ────────────────────────────────────────────────────────────

// Deterministic base — no Date.now() to avoid SSR hydration mismatches.
const MOCK_BASE = new Date('2026-05-06T12:00:00Z').getTime();
const ago = (mins: number) => new Date(MOCK_BASE - mins * 60 * 1000).toISOString();

const SAMPLE_SIGMA = `title: Suspicious PowerShell Encoded Command
id: aisoc-rule-001
status: experimental
description: Flags powershell.exe spawning with -EncodedCommand
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: '-EncodedCommand'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059.001
`;

const SAMPLE_KQL = `// Impossible travel
SigninLogs
| where ResultType == 0
| extend lat = todouble(LocationDetails.geoCoordinates.latitude),
         lon = todouble(LocationDetails.geoCoordinates.longitude)
| order by UserPrincipalName, TimeGenerated asc
| serialize
| extend prevLat = prev(lat), prevLon = prev(lon), prevTime = prev(TimeGenerated)
| where (datetime_diff('minute', TimeGenerated, prevTime)) between (1 .. 240)
| extend km = geo_distance_2points(prevLon, prevLat, lon, lat) / 1000
| where km / (datetime_diff('minute', TimeGenerated, prevTime) / 60.0) > 900
| project TimeGenerated, UserPrincipalName, km, IPAddress
`;

const SAMPLE_EQL = `sequence by aws.account.id with maxspan=1h
  [iam where event.action == "CreateAccessKey"]
  [aws where event.module == "guardduty" and event.severity >= 7]
`;

const DEMO_RULES: DetectionRule[] = [
  {
    id: 'rule-001',
    name: 'Suspicious PowerShell Encoded Command',
    description:
      'Flags powershell.exe spawning with -EncodedCommand, a common LOLBin tradecraft used to evade content filters.',
    language: 'sigma',
    body: SAMPLE_SIGMA,
    enabled: true,
    severity: 'high',
    tags: ['windows', 'lolbin', 'powershell'],
    mitre: ['T1059.001', 'T1027'],
    createdAt: ago(60 * 24 * 14),
    updatedAt: ago(60 * 6),
    lastTriggeredAt: ago(38),
    hitCount: 42,
  },
  {
    id: 'rule-002',
    name: 'Impossible Travel — Same User',
    description:
      'Detects identity sign-ins from two geographies within a window that is physically impossible to traverse.',
    language: 'kql',
    body: SAMPLE_KQL,
    enabled: true,
    severity: 'medium',
    tags: ['identity', 'authn'],
    mitre: ['T1078'],
    createdAt: ago(60 * 24 * 30),
    updatedAt: ago(60 * 24 * 2),
    lastTriggeredAt: ago(60 * 7),
    hitCount: 12,
  },
  {
    id: 'rule-003',
    name: 'AWS GuardDuty High-Severity Finding',
    description:
      'Forwards GuardDuty findings of severity 7+ into AiSOC as alerts and links them to the affected resource.',
    language: 'eql',
    body: SAMPLE_EQL,
    enabled: false,
    severity: 'critical',
    tags: ['aws', 'cloud'],
    mitre: ['T1078.004', 'T1110'],
    createdAt: ago(60 * 24 * 5),
    updatedAt: ago(60 * 24 * 1),
    hitCount: 0,
  },
];

const LANG_LABEL: Record<DetectionLanguage, string> = {
  sigma: 'Sigma',
  yara: 'YARA',
  kql: 'KQL',
  eql: 'EQL',
  lucene: 'Lucene',
  regex: 'Regex',
};

const LANG_BADGE: Record<DetectionLanguage, string> = {
  sigma: 'bg-blue-500/10 text-blue-300 ring-blue-500/30',
  yara: 'bg-purple-500/10 text-purple-300 ring-purple-500/30',
  kql: 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/30',
  eql: 'bg-amber-500/10 text-amber-300 ring-amber-500/30',
  lucene: 'bg-cyan-500/10 text-cyan-300 ring-cyan-500/30',
  regex: 'bg-pink-500/10 text-pink-300 ring-pink-500/30',
};

const SEVERITY_BADGE: Record<string, string> = {
  critical: 'bg-red-500/10 text-red-300 ring-red-500/40',
  high: 'bg-orange-500/10 text-orange-300 ring-orange-500/40',
  medium: 'bg-yellow-500/10 text-yellow-300 ring-yellow-500/40',
  low: 'bg-blue-500/10 text-blue-300 ring-blue-500/40',
};

// ─── Tabs ────────────────────────────────────────────────────────────────────

type DetectionsTab = 'rules' | 'coverage' | 'confidence' | 'drift';

const TABS: { id: DetectionsTab; label: string; description: string }[] = [
  {
    id: 'rules',
    label: 'Rules',
    description: 'Author, tune, and operate the active rule library.',
  },
  {
    id: 'coverage',
    label: 'Coverage',
    description:
      'Rule-centric MITRE ATT&CK heatmap — see what kill-chain stages are well covered and where the tuning gaps are.',
  },
  {
    id: 'confidence',
    label: 'Confidence',
    description:
      'How trustworthy is your rule library? Distribution, per-tactic averages, and the rules dragging the average down.',
  },
  {
    id: 'drift',
    label: 'Drift',
    description:
      'Rules that need attention: noisy false-positive rates, low confidence, or stale ones that have stopped firing.',
  },
];

// ─── Component ────────────────────────────────────────────────────────────────

export function DetectionsView() {
  const { data, error, isLoading, mutate } = useSWR(
    'detection:rules',
    () => detectionApi.list(),
    { revalidateOnFocus: false, shouldRetryOnError: false },
  );

  const useFallback = !!error;
  // Memoise so `useMemo(filtered)` and selection helpers don't see a fresh
  // array reference on every render — important because we feed `rules`
  // into a downstream useMemo dep array.
  const rules = useMemo<DetectionRule[]>(
    () => data?.rules ?? (useFallback ? DEMO_RULES : []),
    [data, useFallback],
  );

  const [tab, setTab] = useState<DetectionsTab>('rules');
  const [search, setSearch] = useState('');
  const [language, setLanguage] = useState<DetectionLanguage | 'all'>('all');
  const [enabledFilter, setEnabledFilter] = useState<'all' | 'on' | 'off'>(
    'all',
  );

  // Selection state for bulk operations. We keep it as a Set so we can
  // do O(1) `has()` checks while rendering each rule card.
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkPending, setBulkPending] = useState(false);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return rules.filter((r) => {
      if (language !== 'all' && r.language !== language) return false;
      if (enabledFilter === 'on' && !r.enabled) return false;
      if (enabledFilter === 'off' && r.enabled) return false;
      if (!q) return true;
      const hay = [
        r.name,
        r.description ?? '',
        ...(r.tags ?? []),
        ...(r.mitre ?? []),
      ]
        .join(' ')
        .toLowerCase();
      return hay.includes(q);
    });
  }, [rules, search, language, enabledFilter]);

  // ─── Selection helpers ─────────────────────────────────────────────────────

  const toggleSelected = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const allFilteredSelected =
    filtered.length > 0 && filtered.every((r) => selected.has(r.id));

  const toggleSelectAll = () => {
    setSelected((prev) => {
      if (allFilteredSelected) {
        const next = new Set(prev);
        for (const r of filtered) next.delete(r.id);
        return next;
      }
      const next = new Set(prev);
      for (const r of filtered) next.add(r.id);
      return next;
    });
  };

  const clearSelection = () => setSelected(new Set());

  // ─── Mutations ─────────────────────────────────────────────────────────────

  const toggleEnabled = async (rule: DetectionRule) => {
    const next = !rule.enabled;
    // Optimistic
    mutate(
      (curr) =>
        curr
          ? {
              ...curr,
              rules: curr.rules.map((r) =>
                r.id === rule.id ? { ...r, enabled: next } : r,
              ),
            }
          : curr,
      { revalidate: false },
    );

    try {
      if (!useFallback) {
        await detectionApi.update(rule.id, { enabled: next });
      }
      toast.success(next ? 'Rule enabled' : 'Rule disabled');
      mutate();
    } catch (err) {
      console.warn('Toggle failed', err);
      toast.error('Could not update rule');
      mutate(); // Re-fetch to revert
    }
  };

  const runBulkToggle = async (enabled: boolean) => {
    const ids = Array.from(selected);
    if (ids.length === 0) return;

    if (useFallback) {
      // Demo mode — apply optimistically with no backend round-trip.
      mutate(
        (curr) =>
          curr
            ? {
                ...curr,
                rules: curr.rules.map((r) =>
                  selected.has(r.id) ? { ...r, enabled } : r,
                ),
              }
            : curr,
        { revalidate: false },
      );
      toast.success(
        `${ids.length} rule${ids.length === 1 ? '' : 's'} ${enabled ? 'enabled' : 'disabled'} (demo)`,
      );
      clearSelection();
      return;
    }

    setBulkPending(true);
    // Optimistic update — flip enabled state in-memory so the UI reflects the
    // intent immediately. We re-fetch on completion to reconcile against
    // anything the backend skipped.
    mutate(
      (curr) =>
        curr
          ? {
              ...curr,
              rules: curr.rules.map((r) =>
                selected.has(r.id) ? { ...r, enabled } : r,
              ),
            }
          : curr,
      { revalidate: false },
    );

    try {
      const result = await detectionApi.bulkToggle(ids, enabled);
      const updatedCount = result.updated;
      const skippedCount = result.skipped.length;
      if (updatedCount > 0) {
        toast.success(
          `${updatedCount} rule${updatedCount === 1 ? '' : 's'} ${enabled ? 'enabled' : 'disabled'}` +
            (skippedCount > 0
              ? ` — ${skippedCount} built-in or unknown skipped`
              : ''),
        );
      } else if (skippedCount > 0) {
        toast(
          `No rules updated — ${skippedCount} were built-in or unknown.`,
          { icon: 'ℹ️' },
        );
      }
      clearSelection();
      mutate();
    } catch (err) {
      console.warn('Bulk toggle failed', err);
      toast.error('Could not update rules');
      mutate(); // Re-fetch to revert
    } finally {
      setBulkPending(false);
    }
  };

  // ─── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-gray-100">
            Detection rules
          </h1>
          <p className="mt-1 max-w-2xl text-sm text-gray-500">
            {TABS.find((t) => t.id === tab)?.description ??
              'Author, test, and operate detection logic across log sources.'}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Link
            href="/detection/proposals"
            className="inline-flex items-center justify-center gap-2 rounded-md border border-gray-800 px-3 py-2 text-sm text-gray-300 hover:bg-gray-800"
          >
            Proposals
          </Link>
          <Link
            href="/detection/new"
            className="inline-flex items-center justify-center gap-2 rounded-md bg-blue-500 px-4 py-2 text-sm font-medium text-white shadow-sm transition-colors hover:bg-blue-600"
          >
            <svg
              className="h-4 w-4"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth={2}
            >
              <path d="M12 5v14M5 12h14" strokeLinecap="round" />
            </svg>
            New rule
          </Link>
        </div>
      </div>

      {/* Tabs */}
      <div
        className="flex gap-1 rounded-md border border-gray-800 bg-gray-950 p-0.5 text-sm"
        role="tablist"
        aria-label="Detection management views"
      >
        {TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            role="tab"
            aria-selected={tab === t.id}
            onClick={() => {
              setTab(t.id);
              if (t.id !== 'rules') clearSelection();
            }}
            className={clsx(
              'flex-1 rounded px-3 py-1.5 transition-colors sm:flex-none sm:min-w-[7rem]',
              tab === t.id
                ? 'bg-gray-800 text-gray-100'
                : 'text-gray-400 hover:text-gray-200',
            )}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Demo banner */}
      {useFallback && (
        <div className="rounded-md border border-amber-500/30 bg-amber-500/5 px-4 py-2 text-xs text-amber-200">
          Detection API unreachable — showing curated demo rules so you can
          explore the workflow.
        </div>
      )}

      {tab === 'rules' && (
        <>
          {/* Filters */}
          <div className="flex flex-col gap-3 rounded-lg border border-gray-800 bg-gray-900/40 p-3 lg:flex-row lg:items-center">
            <div className="relative flex-1">
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search by name, tag, or technique (T1059, lolbin, identity)…"
                className="w-full rounded-md border border-gray-800 bg-gray-950 px-9 py-2 text-sm text-gray-200 placeholder-gray-600 outline-none transition-colors focus:border-blue-500/60 focus:ring-1 focus:ring-blue-500/40"
              />
              <svg
                className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth={2}
              >
                <circle cx="11" cy="11" r="7" />
                <path d="m20 20-3.5-3.5" strokeLinecap="round" />
              </svg>
            </div>

            <select
              value={language}
              onChange={(e) =>
                setLanguage(e.target.value as DetectionLanguage | 'all')
              }
              className="rounded-md border border-gray-800 bg-gray-950 px-3 py-2 text-sm text-gray-300 outline-none focus:border-blue-500/60"
            >
              <option value="all">All languages</option>
              <option value="sigma">Sigma</option>
              <option value="yara">YARA</option>
              <option value="kql">KQL</option>
              <option value="eql">EQL</option>
              <option value="lucene">Lucene</option>
              <option value="regex">Regex</option>
            </select>

            <div className="inline-flex rounded-md border border-gray-800 bg-gray-950 p-0.5 text-xs">
              {(['all', 'on', 'off'] as const).map((opt) => (
                <button
                  key={opt}
                  type="button"
                  onClick={() => setEnabledFilter(opt)}
                  className={clsx(
                    'rounded px-3 py-1.5 transition-colors',
                    enabledFilter === opt
                      ? 'bg-gray-800 text-gray-100'
                      : 'text-gray-400 hover:text-gray-200',
                  )}
                >
                  {opt === 'all' ? 'All' : opt === 'on' ? 'Enabled' : 'Disabled'}
                </button>
              ))}
            </div>
          </div>

          {/* Bulk action bar — appears when rules are selected. */}
          {selected.size > 0 && (
            <div
              className="flex flex-wrap items-center gap-3 rounded-md border border-blue-500/30 bg-blue-500/5 px-4 py-2.5 text-sm"
              role="toolbar"
              aria-label="Bulk rule actions"
            >
              <span className="text-blue-200">
                <span className="font-mono font-semibold">{selected.size}</span>{' '}
                rule{selected.size === 1 ? '' : 's'} selected
              </span>
              <div className="ml-auto flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => runBulkToggle(true)}
                  disabled={bulkPending}
                  className="rounded-md bg-emerald-500 px-3 py-1.5 text-xs font-medium text-white shadow-sm transition-colors hover:bg-emerald-600 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  Enable
                </button>
                <button
                  type="button"
                  onClick={() => runBulkToggle(false)}
                  disabled={bulkPending}
                  className="rounded-md bg-gray-700 px-3 py-1.5 text-xs font-medium text-gray-100 transition-colors hover:bg-gray-600 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  Disable
                </button>
                <button
                  type="button"
                  onClick={clearSelection}
                  disabled={bulkPending}
                  className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:bg-gray-800 disabled:opacity-60"
                >
                  Clear
                </button>
              </div>
            </div>
          )}

          {/* Body */}
          {isLoading ? (
            <div className="space-y-3">
              {[0, 1, 2].map((i) => (
                <Skeleton key={i} className="h-24 w-full" />
              ))}
            </div>
          ) : filtered.length === 0 ? (
            rules.length === 0 ? (
              <EmptyState
                title="No detection rules yet"
                description="Author your first detection in Sigma, KQL, or EQL — or import the AiSOC starter pack to bootstrap coverage across the MITRE ATT&CK matrix."
                action={
                  <div className="flex flex-wrap items-center gap-2">
                    <Link
                      href="/detection/new"
                      className="rounded-md bg-blue-500 px-4 py-2 text-sm font-medium text-white hover:bg-blue-600"
                    >
                      Create a rule
                    </Link>
                    <button
                      type="button"
                      disabled
                      title="Starter pack import is planned for v1.1"
                      className="rounded-md border border-gray-700 px-4 py-2 text-sm text-gray-500 cursor-not-allowed select-none"
                    >
                      Import starter pack
                    </button>
                    <span className="text-xs font-medium rounded-full bg-amber-500/15 text-amber-400 border border-amber-500/30 px-2 py-0.5">
                      Planned for v1.1
                    </span>
                  </div>
                }
              />
            ) : (
              <EmptyState
                title="No rules match your filters"
                description="Try clearing the search, switching language, or showing all enabled states."
                action={
                  <button
                    type="button"
                    onClick={() => {
                      setSearch('');
                      setLanguage('all');
                      setEnabledFilter('all');
                    }}
                    className="rounded-md border border-gray-700 px-4 py-2 text-sm text-gray-300 hover:bg-gray-800"
                  >
                    Clear filters
                  </button>
                }
              />
            )
          ) : (
            <>
              {/* Select-all header — small horizontal strip above the list */}
              <div className="flex items-center gap-2 px-1 text-xs text-gray-500">
                <input
                  type="checkbox"
                  checked={allFilteredSelected}
                  onChange={toggleSelectAll}
                  aria-label={
                    allFilteredSelected
                      ? 'Deselect all visible rules'
                      : 'Select all visible rules'
                  }
                  className="h-3.5 w-3.5 cursor-pointer rounded border-gray-700 bg-gray-950 accent-blue-500"
                />
                <span>
                  {allFilteredSelected
                    ? `All ${filtered.length} visible rule${filtered.length === 1 ? '' : 's'} selected`
                    : `Select all ${filtered.length} visible rule${filtered.length === 1 ? '' : 's'}`}
                </span>
              </div>
              <ul className="space-y-3">
                {filtered.map((rule) => (
                  <li key={rule.id}>
                    <RuleCard
                      rule={rule}
                      selected={selected.has(rule.id)}
                      onSelect={() => toggleSelected(rule.id)}
                      onToggle={() => toggleEnabled(rule)}
                    />
                  </li>
                ))}
              </ul>
            </>
          )}

          {/* Footer / errors */}
          {error && !useFallback && (
            <ErrorState
              title="Couldn't load detection rules"
              description="The detection service didn't respond. We've shown the local demo set instead."
              error={error}
              onRetry={() => mutate()}
            />
          )}

          {/* Contributor leaderboard */}
          <ContributorLeaderboard />
        </>
      )}

      {tab === 'coverage' && <MitreRuleHeatmap />}

      {tab === 'confidence' && <ConfidenceTrends />}

      {tab === 'drift' && <DriftInbox />}
    </div>
  );
}

// ─── Sub-components ───────────────────────────────────────────────────────────

interface RuleCardProps {
  rule: DetectionRule;
  selected: boolean;
  onSelect: () => void;
  onToggle: () => void;
}

function RuleCard({ rule, selected, onSelect, onToggle }: RuleCardProps) {
  return (
    <Link
      href={`/detection/${rule.id}`}
      className={clsx(
        'group block rounded-lg border bg-gray-900/40 p-4 transition-colors',
        selected
          ? 'border-blue-500/50 bg-blue-500/5 hover:bg-blue-500/10'
          : 'border-gray-800 hover:border-gray-700 hover:bg-gray-900/70',
      )}
    >
      <div className="flex items-start gap-4">
        {/* Selection checkbox + status dot stacked */}
        <div className="mt-1 flex flex-col items-center gap-2">
          <input
            type="checkbox"
            checked={selected}
            onClick={(e) => {
              // Don't navigate to the rule detail page on checkbox click.
              e.preventDefault();
              e.stopPropagation();
              onSelect();
            }}
            onChange={() => {
              // Click handler does the work; keep onChange to satisfy React.
            }}
            aria-label={`Select rule ${rule.name}`}
            className="h-3.5 w-3.5 cursor-pointer rounded border-gray-700 bg-gray-950 accent-blue-500"
          />
          <span
            className={clsx(
              'inline-flex h-2.5 w-2.5 rounded-full',
              rule.enabled
                ? 'bg-emerald-400 shadow-[0_0_0_3px_rgba(52,211,153,0.18)]'
                : 'bg-gray-600',
            )}
          />
        </div>

        {/* Body */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <h3 className="truncate text-sm font-semibold text-gray-100 group-hover:text-blue-300">
              {rule.name}
            </h3>
            <span
              className={clsx(
                'rounded-md px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide ring-1',
                LANG_BADGE[rule.language],
              )}
            >
              {LANG_LABEL[rule.language]}
            </span>
            {rule.severity && (
              <span
                className={clsx(
                  'rounded-md px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide ring-1',
                  SEVERITY_BADGE[rule.severity] ?? 'bg-gray-800 text-gray-300',
                )}
              >
                {rule.severity}
              </span>
            )}
          </div>

          {rule.description && (
            <p className="mt-1 text-sm text-gray-400 line-clamp-2">
              {rule.description}
            </p>
          )}

          <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-gray-500">
            {rule.mitre?.slice(0, 4).map((id) => (
              <span
                key={id}
                className="rounded-md bg-gray-800/60 px-1.5 py-0.5 font-mono text-[11px] text-gray-300"
              >
                {id}
              </span>
            ))}
            {rule.tags?.slice(0, 5).map((tag) => (
              <span
                key={tag}
                className="rounded-full bg-gray-800/40 px-2 py-0.5 text-[11px] text-gray-400"
              >
                #{tag}
              </span>
            ))}
          </div>
        </div>

        {/* Right meta + toggle */}
        <div className="flex flex-col items-end gap-2">
          <div className="text-right text-xs text-gray-500">
            <div>
              <span className="font-mono text-gray-300">
                {rule.hitCount ?? 0}
              </span>{' '}
              hits
            </div>
            <div className="mt-0.5" suppressHydrationWarning>
              {rule.lastTriggeredAt
                ? `last fired ${formatDistanceToNow(new Date(rule.lastTriggeredAt), { addSuffix: true })}`
                : 'no recent hits'}
            </div>
          </div>
          <Toggle enabled={rule.enabled} onChange={onToggle} />
        </div>
      </div>
    </Link>
  );
}

interface ToggleProps {
  enabled: boolean;
  onChange: () => void;
}

function Toggle({ enabled, onChange }: ToggleProps) {
  return (
    <button
      type="button"
      onClick={(e) => {
        e.preventDefault();
        e.stopPropagation();
        onChange();
      }}
      role="switch"
      aria-checked={enabled}
      aria-label={enabled ? 'Disable rule' : 'Enable rule'}
      className={clsx(
        'relative inline-flex h-5 w-9 items-center rounded-full transition-colors',
        enabled ? 'bg-emerald-500/70' : 'bg-gray-700',
      )}
    >
      <span
        className={clsx(
          'inline-block h-4 w-4 transform rounded-full bg-white shadow-sm transition-transform',
          enabled ? 'translate-x-4' : 'translate-x-0.5',
        )}
      />
    </button>
  );
}
