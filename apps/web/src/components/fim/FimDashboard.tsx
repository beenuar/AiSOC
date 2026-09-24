'use client';

import { useState } from 'react';
import useSWR from 'swr';
import toast from 'react-hot-toast';
import type { FimEventsPage, FimSummary } from '@/lib/osquery-api';
import { getFimEvents, getFimSummary } from '@/lib/osquery-api';
import { FimSummaryCards } from './FimSummaryCards';
import { FimEventsTable } from './FimEventsTable';

// Deliberately *not* `NEXT_PUBLIC_TENANT_ID`. `services/osquery-tls` types its
// tenant as a plain string and enrols nodes under the literal "default" when no
// `X-AiSOC-Tenant` header is supplied, so this surface is keyed on that
// service's own convention rather than on the platform tenant UUID the rest of
// the console uses. Reading the shared env var here would send a UUID that
// matches no enrolled node. The two tenancy models need reconciling in
// osquery-tls; until then this is pinned so it cannot drift silently.
const TENANT_ID = 'default';

const PAGE_SIZE = 25;

const ACTION_OPTIONS = [
  { label: 'All Actions', value: '' },
  { label: 'Created', value: 'CREATED' },
  { label: 'Deleted', value: 'DELETED' },
  { label: 'Updated', value: 'UPDATED' },
  { label: 'Attributes Modified', value: 'ATTRIBUTES_MODIFIED' },
];

const SINCE_OPTIONS = [
  { label: 'Last 1 hour', value: '1h' },
  { label: 'Last 6 hours', value: '6h' },
  { label: 'Last 24 hours', value: '24h' },
  { label: 'Last 7 days', value: '7d' },
  { label: 'All time', value: '' },
];

function sinceToISO(value: string): string | undefined {
  if (!value) return undefined;
  const now = new Date();
  const map: Record<string, number> = {
    '1h': 60,
    '6h': 360,
    '24h': 1440,
    '7d': 10080,
  };
  const minutes = map[value] ?? 0;
  if (!minutes) return undefined;
  return new Date(now.getTime() - minutes * 60_000).toISOString();
}

export function FimDashboard() {
  const [page, setPage] = useState(1);
  const [action, setAction] = useState('');
  const [pathPrefix, setPathPrefix] = useState('');
  const [since, setSince] = useState('24h');

  const sinceISO = sinceToISO(since);

  // Events feed
  const eventsKey = [
    'fim-events',
    TENANT_ID,
    page,
    action,
    pathPrefix,
    sinceISO,
  ];
  const {
    data: eventsData,
    error: eventsError,
    isLoading: eventsLoading,
  } = useSWR<FimEventsPage>(
    eventsKey,
    () =>
      getFimEvents({
        tenant_id: TENANT_ID,
        page,
        page_size: PAGE_SIZE,
        action: action || undefined,
        path_prefix: pathPrefix || undefined,
        since: sinceISO,
      }),
    {
      onError: () => toast.error('Failed to load FIM events'),
      refreshInterval: 30_000,
    },
  );

  // Summary cards
  const summaryKey = ['fim-summary', TENANT_ID, sinceISO];
  const {
    data: summaryData,
    error: summaryError,
    isLoading: summaryLoading,
  } = useSWR<FimSummary>(
    summaryKey,
    () => getFimSummary({ tenant_id: TENANT_ID, since: sinceISO }),
    {
      onError: () => toast.error('Failed to load FIM summary'),
      refreshInterval: 60_000,
    },
  );

  function handleActionChange(v: string) {
    setAction(v);
    setPage(1);
  }
  function handleSinceChange(v: string) {
    setSince(v);
    setPage(1);
  }
  function handlePathChange(v: string) {
    setPathPrefix(v);
    setPage(1);
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-1">
        <h1 className="text-xl font-bold text-gray-900">
          File Integrity Monitoring
        </h1>
        <p className="text-sm text-gray-500">
          Real-time osquery <code className="font-mono">file_events</code>{' '}
          telemetry for your fleet.
        </p>
      </div>

      {/* Filter bar */}
      <div className="flex flex-wrap items-end gap-3 rounded-xl border border-gray-200 bg-white p-4 shadow-sm">
        {/* Time window */}
        <div className="flex flex-col gap-1">
          <label className="text-xs font-medium text-gray-500">Time window</label>
          <select
            value={since}
            onChange={(e) => handleSinceChange(e.target.value)}
            className="rounded-md border border-gray-300 bg-white px-3 py-1.5 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          >
            {SINCE_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </div>

        {/* Action filter */}
        <div className="flex flex-col gap-1">
          <label className="text-xs font-medium text-gray-500">Action</label>
          <select
            value={action}
            onChange={(e) => handleActionChange(e.target.value)}
            className="rounded-md border border-gray-300 bg-white px-3 py-1.5 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          >
            {ACTION_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </div>

        {/* Path prefix */}
        <div className="flex flex-col gap-1 flex-1 min-w-[180px]">
          <label className="text-xs font-medium text-gray-500">
            Path prefix
          </label>
          <input
            type="text"
            value={pathPrefix}
            onChange={(e) => handlePathChange(e.target.value)}
            placeholder="/etc/, /home/, C:\\…"
            className="rounded-md border border-gray-300 px-3 py-1.5 text-sm shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          />
        </div>
      </div>

      {/* Summary cards */}
      {summaryError ? (
        <ErrorBanner message="Could not load FIM summary." />
      ) : summaryLoading ? (
        <SkeletonCards />
      ) : summaryData ? (
        <FimSummaryCards summary={summaryData} />
      ) : null}

      {/* Events table */}
      <div>
        <h2 className="mb-3 text-sm font-semibold text-gray-700">
          Event Log
        </h2>
        {eventsError ? (
          <ErrorBanner message="Could not load FIM events." />
        ) : eventsLoading ? (
          <SkeletonTable />
        ) : eventsData ? (
          <FimEventsTable
            events={eventsData.events}
            total={eventsData.total}
            page={eventsData.page}
            pageSize={PAGE_SIZE}
            onPageChange={setPage}
          />
        ) : null}
      </div>
    </div>
  );
}

function ErrorBanner({ message }: { message: string }) {
  return (
    <div className="rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
      {message}
    </div>
  );
}

function SkeletonCards() {
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 animate-pulse">
      {[...Array(4)].map((_, i) => (
        <div
          key={i}
          className="h-20 rounded-xl border border-gray-200 bg-gray-100"
        />
      ))}
    </div>
  );
}

function SkeletonTable() {
  return (
    <div className="animate-pulse space-y-2">
      <div className="h-10 rounded-lg bg-gray-100" />
      {[...Array(6)].map((_, i) => (
        <div key={i} className="h-8 rounded bg-gray-50" />
      ))}
    </div>
  );
}
