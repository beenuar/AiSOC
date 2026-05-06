'use client';

import { useState } from 'react';
import useSWR from 'swr';
import Link from 'next/link';
import { casesApi, type Case } from '@/lib/api';
import { clsx } from 'clsx';
import { format } from 'date-fns';

// ─── Mock Data ────────────────────────────────────────────────────────────────

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
  alertCount: Math.floor(Math.random() * 30) + 1,
  createdAt: new Date(Date.now() - i * 7200000).toISOString(),
  updatedAt: new Date(Date.now() - i * 1800000).toISOString(),
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
  const sev = SEVERITY_CONFIG[c.severity];
  const sts = STATUS_CONFIG[c.status];

  return (
    <Link href={`/cases/${c.id}`} className="block">
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
              <span className="text-xs text-gray-500">#{c.id.slice(-6)}</span>
              <span className="text-xs text-gray-500">·</span>
              <span className="text-xs text-gray-500">{c.alertCount} alerts</span>
              {c.assignee && (
                <>
                  <span className="text-xs text-gray-500">·</span>
                  <span className="text-xs text-gray-400">{c.assignee.split('@')[0]}</span>
                </>
              )}
            </div>
          </div>
          <div className="text-right shrink-0">
            <p className="text-xs text-gray-500">{format(new Date(c.createdAt), 'MMM dd, HH:mm')}</p>
            {c.tags && c.tags.length > 0 && (
              <div className="flex flex-wrap gap-1 mt-2 justify-end">
                {c.tags.slice(0, 2).map((tag) => (
                  <span key={tag} className="text-xs text-gray-500 bg-gray-800 px-1.5 py-0.5 rounded">
                    {tag}
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </Link>
  );
}

// ─── Main View ────────────────────────────────────────────────────────────────

type FilterStatus = Case['status'] | 'all';

export function CasesView() {
  const [statusFilter, setStatusFilter] = useState<FilterStatus>('all');
  const [severityFilter, setSeverityFilter] = useState<Case['severity'] | 'all'>('all');
  const [search, setSearch] = useState('');

  const { data: casesData, isLoading } = useSWR(
    ['cases', statusFilter, severityFilter],
    () => casesApi.list({ status: statusFilter !== 'all' ? statusFilter : undefined }),
    {
      fallbackData: {
        cases: MOCK_CASES,
        total: MOCK_CASES.length,
        page: 1,
        pageSize: MOCK_CASES.length,
      },
    }
  );

  const cases = (casesData?.cases || []).filter((c) => {
    if (search && !c.title.toLowerCase().includes(search.toLowerCase())) return false;
    if (severityFilter !== 'all' && c.severity !== severityFilter) return false;
    return true;
  });

  const statCounts = {
    all: MOCK_CASES.length,
    open: MOCK_CASES.filter(c => c.status === 'open').length,
    in_progress: MOCK_CASES.filter(c => c.status === 'in_progress').length,
    resolved: MOCK_CASES.filter(c => c.status === 'resolved').length,
    closed: MOCK_CASES.filter(c => c.status === 'closed').length,
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-gray-100">Cases</h1>
          <p className="text-sm text-gray-500 mt-0.5">Manage security investigations and incidents</p>
        </div>
        <button className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors">
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          New Case
        </button>
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
        <div className="flex flex-col items-center justify-center h-48 text-gray-600">
          <p className="text-sm">No cases found</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-3">
          {cases.map((c) => <CaseCard key={c.id} c={c} />)}
        </div>
      )}
    </div>
  );
}
