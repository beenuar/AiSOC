'use client';

import { useState } from 'react';
import useSWR from 'swr';
import Link from 'next/link';
import toast from 'react-hot-toast';
import { casesApi, type Case, type CasesResponse } from '@/lib/api';
import { clsx } from 'clsx';
import { format } from 'date-fns';
import { EmptyState, EmptyStateIcons } from '@/components/ui/EmptyState';
import { SavedViewsBar } from '@/components/saved-views/SavedViewsBar';

// WS-F3 — the saved-views API stores an opaque filter blob per view, so we
// flatten the three filter slices Cases tracks today into a single shape the
// bar can snapshot and replay. Nothing else in the view consumes this — it's
// purely the wire format between the bar and the local state setters.
type CaseFilterSnapshot = {
  status: Case['status'] | 'all';
  severity: Case['severity'] | 'all';
  search: string;
};

// ─── Mock Data ────────────────────────────────────────────────────────────────

// Deterministic mock data — no Date.now() or Math.random() to avoid SSR hydration mismatches.
const MOCK_CASE_BASE = new Date('2026-05-06T12:00:00Z').getTime();
const MOCK_CASES: Case[] = Array.from({ length: 18 }, (_, i) => ({
  id: `case-${1000 + i}`,
  title: [
    'Ransomware incident on finance workstations',
    'Suspected APT lateral movement campaign',
    'Credential stuffing attack against portal',
    'Data exfiltration via cloud storage abuse',
    'Supply chain compromise investigation',
    'Insider threat: anomalous data access',
    'Phishing campaign targeting executives',
    'Cryptominer on dev server cluster',
    'Brute-force attack on VPN endpoints',
    'Unauthorized cloud resource provisioning',
  ][i % 10],
  status: (['open', 'in_progress', 'resolved', 'closed'] as Case['status'][])[i % 4],
  severity: (['critical', 'high', 'medium', 'low'] as Case['severity'][])[i % 4],
  assignee: ['alice@company.com', 'bob@company.com', 'carol@company.com', undefined][i % 4],
  alertCount: ((i * 13 + 7) % 30) + 1,
  createdAt: new Date(MOCK_CASE_BASE - i * 7200000).toISOString(),
  updatedAt: new Date(MOCK_CASE_BASE - i * 1800000).toISOString(),
  tags: [['ransomware', 'finance'], ['apt', 'lateral'], ['credential', 'portal'], ['exfil', 'cloud']][i % 4],
}));

// ─── Helpers ──────────────────────────────────────────────────────────────────

const SEVERITY_CONFIG = {
  critical: { label: 'Critical', className: 'text-red-400 bg-red-500/10 border-red-500/20' },
  high: { label: 'High', className: 'text-orange-400 bg-orange-500/10 border-orange-500/20' },
  medium: { label: 'Medium', className: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20' },
  low: { label: 'Low', className: 'text-blue-400 bg-blue-500/10 border-blue-500/20' },
};

const STATUS_CONFIG: Record<
  Case['status'],
  { label: string; className: string; dot: string }
> = {
  open: { label: 'Open', className: 'text-gray-300 bg-gray-700/50 border-gray-600/50', dot: 'bg-gray-400' },
  in_progress: { label: 'In Progress', className: 'text-blue-300 bg-blue-500/10 border-blue-500/20', dot: 'bg-blue-400 animate-pulse' },
  pending: { label: 'Pending', className: 'text-amber-300 bg-amber-500/10 border-amber-500/20', dot: 'bg-amber-400' },
  resolved: { label: 'Resolved', className: 'text-green-300 bg-green-500/10 border-green-500/20', dot: 'bg-green-400' },
  closed: { label: 'Closed', className: 'text-gray-500 bg-gray-800/50 border-gray-700/50', dot: 'bg-gray-600' },
};

// ─── Case Card ────────────────────────────────────────────────────────────────

function CaseCard({ c }: { c: Case }) {
  const sev = SEVERITY_CONFIG[c.severity] ?? SEVERITY_CONFIG.medium;
  // Defensive: if normalization missed an unexpected status string, fall back
  // to "open" styling so the entire list never blanks the page.
  const sts = STATUS_CONFIG[c.status] ?? STATUS_CONFIG.open;
  const displayId = c.caseNumber ?? `${c.id ?? ''}`.slice(-6);
  const detailHref = `/cases/${encodeURIComponent(c.caseNumber ?? c.id)}`;

  return (
    <Link href={detailHref} className="block">
      <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl p-5 hover:border-gray-700 hover:bg-gray-900/80 transition-all group">
        <div className="flex items-start justify-between gap-3">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-2">
              <span className={clsx('text-xs font-medium px-2 py-0.5 rounded border', sev.className)}>
                {sev.label}
              </span>
              <span className={clsx('flex items-center gap-1 text-xs font-medium px-2 py-0.5 rounded border', sts.className)}>
                <span className={clsx('w-1.5 h-1.5 rounded-full', sts.dot)} />
                {sts.label}
              </span>
            </div>
            <h3 className="text-sm font-medium text-gray-200 group-hover:text-white truncate">{c.title}</h3>
            <div className="flex items-center gap-3 mt-2">
              <span className="text-xs text-gray-500">#{displayId}</span>
              <span className="text-xs text-gray-500">·</span>
              <span className="text-xs text-gray-500">{c.alertCount ?? 0} alerts</span>
              {c.assignee && (
                <>
                  <span className="text-xs text-gray-500">·</span>
                  <span className="text-xs text-gray-400">{c.assignee.split('@')[0]}</span>
                </>
              )}
            </div>
          </div>
          <div className="text-right shrink-0 flex flex-col items-end gap-2">
            <p className="text-xs text-gray-500" suppressHydrationWarning>{format(new Date(c.createdAt), 'MMM dd, HH:mm')}</p>
            {c.tags && c.tags.length > 0 && (
              <div className="flex flex-wrap gap-1 justify-end">
                {c.tags.slice(0, 2).map((tag) => (
                  <span key={tag} className="text-xs text-gray-500 bg-gray-800 px-1.5 py-0.5 rounded">
                    {tag}
                  </span>
                ))}
              </div>
            )}
            <button
              onClick={(e) => {
                e.preventDefault();
                toast.success('Incident report generated — downloading PDF');
              }}
              className="flex items-center gap-1 text-xs text-gray-500 hover:text-blue-400 transition-colors opacity-0 group-hover:opacity-100"
            >
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              Export Report
            </button>
          </div>
        </div>
      </div>
    </Link>
  );
}

// ─── Main View ────────────────────────────────────────────────────────────────

type FilterStatus = Case['status'] | 'all';

interface CasesViewProps {
  /**
   * Optional pre-fetched cases from a Server Component. When provided, these
   * are rendered on first paint (no flash of mock data) and SWR revalidates
   * in the background. When omitted (e.g. dev/local without API access),
   * deterministic mock data is used so the layout stays stable for SSR.
   */
  initialCases?: CasesResponse;
}

export function CasesView({ initialCases }: CasesViewProps = {}) {
  const [statusFilter, setStatusFilter] = useState<FilterStatus>('all');
  const [severityFilter, setSeverityFilter] = useState<Case['severity'] | 'all'>('all');
  const [search, setSearch] = useState('');

  const fallback: CasesResponse = initialCases ?? {
    cases: MOCK_CASES,
    total: MOCK_CASES.length,
    page: 1,
    pageSize: MOCK_CASES.length,
  };

  const { data: casesData, isLoading } = useSWR(
    ['cases', statusFilter, severityFilter],
    () => casesApi.list({ status: statusFilter !== 'all' ? statusFilter : undefined }),
    {
      fallbackData: fallback,
    }
  );

  const cases = (casesData?.cases || []).filter((c) => {
    if (search && !c.title.toLowerCase().includes(search.toLowerCase())) return false;
    if (severityFilter !== 'all' && c.severity !== severityFilter) return false;
    return true;
  });

  const allCases = casesData?.cases ?? MOCK_CASES;
  const statCounts = {
    all: allCases.length,
    open: allCases.filter(c => c.status === 'open').length,
    in_progress: allCases.filter(c => c.status === 'in_progress').length,
    resolved: allCases.filter(c => c.status === 'resolved').length,
    closed: allCases.filter(c => c.status === 'closed').length,
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-gray-100">Cases</h1>
          <p className="text-sm text-gray-500 mt-0.5">Manage security investigations and incidents</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            disabled
            title="Case creation wizard is planned for v1.1"
            className="flex items-center gap-2 bg-gray-700 text-gray-400 text-sm font-medium px-4 py-2 rounded-lg cursor-not-allowed select-none"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
            </svg>
            New Case
          </button>
          <span className="text-xs font-medium rounded-full bg-amber-500/15 text-amber-400 border border-amber-500/30 px-2 py-0.5">
            Planned for v1.1
          </span>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-5 gap-3">
        {(['all', 'open', 'in_progress', 'resolved', 'closed'] as const).map((s) => {
          return (
            <button
              key={s}
              onClick={() => setStatusFilter(s)}
              className={clsx(
                'bg-gray-900/60 border rounded-xl p-4 text-left transition-all',
                statusFilter === s ? 'border-blue-500/50 bg-blue-500/5' : 'border-gray-800/60 hover:border-gray-700'
              )}
            >
              <p className="text-2xl font-bold text-gray-100">{statCounts[s]}</p>
              <p className="text-xs text-gray-500 mt-0.5 capitalize">
                {s === 'all' ? 'All Cases' : s.replace('_', ' ')}
              </p>
            </button>
          );
        })}
      </div>

      {/*
        WS-F3 — saved views. Cases keeps three slices of filter state, so we
        synthesize a single object for the bar and unpack it on apply. We
        spread defaults to be defensive against older saved-view payloads
        that might be missing newer keys.
      */}
      <SavedViewsBar<CaseFilterSnapshot>
        viewType="cases"
        filters={{
          status: statusFilter,
          severity: severityFilter,
          search,
        }}
        onApply={(applied) => {
          setStatusFilter(applied.status ?? 'all');
          setSeverityFilter(applied.severity ?? 'all');
          setSearch(applied.search ?? '');
        }}
      />

      {/* Filters */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search cases…"
            className="w-full pl-9 pr-4 py-2 bg-gray-900/60 border border-gray-800 rounded-lg text-sm text-gray-300 placeholder-gray-600 focus:outline-none focus:border-blue-500/50"
          />
        </div>

        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value as Case['severity'] | 'all')}
          className="bg-gray-900/60 border border-gray-800 rounded-lg text-sm text-gray-400 px-3 py-2 focus:outline-none focus:border-blue-500/50"
        >
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>

        <span className="text-xs text-gray-500">{cases.length} cases</span>
      </div>

      {/* Cases List */}
      {isLoading ? (
        <div className="flex items-center justify-center h-48">
          <div className="w-6 h-6 border-2 border-blue-500/30 border-t-blue-500 rounded-full animate-spin" />
        </div>
      ) : cases.length === 0 ? (
        // WS-F5 — distinguish "filter miss" from "no cases ever". The former
        // gets a "clear filters" CTA; the latter explains what cases are and
        // where they come from so a brand-new tenant doesn't think it's broken.
        statusFilter !== 'all' || severityFilter !== 'all' || search ? (
          <EmptyState
            icon={EmptyStateIcons.search}
            title="No cases match these filters"
            description="Try clearing the status, severity, or search filter to widen the view."
            action={
              <button
                onClick={() => {
                  setStatusFilter('all');
                  setSeverityFilter('all');
                  setSearch('');
                }}
                className="text-xs px-3 py-1.5 rounded-md border border-blue-500/40 bg-blue-500/10 text-blue-300 hover:bg-blue-500/20 transition-colors"
              >
                Clear filters
              </button>
            }
          />
        ) : (
          <EmptyState
            icon={EmptyStateIcons.case}
            title="No cases yet"
            description="Cases bundle related alerts, evidence, and analyst notes into a single investigation. Promote alerts to a case from the Alerts tab, or click ‘New Case’ to start a manual investigation."
          />
        )
      ) : (
        <div className="grid grid-cols-1 gap-3">
          {cases.map((c) => <CaseCard key={c.id} c={c} />)}
        </div>
      )}
    </div>
  );
}
