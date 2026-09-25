'use client';

/**
 * Top-level Connectors page.
 *
 * Owns the SWR cache for `connectorsApi.list()` and renders three sub-views
 * depending on state:
 *
 *   - loading  → skeleton tiles
 *   - error    → `FailureBanner` with retry, over an explicitly-unknown list
 *   - data     → header stats + `ConnectorInstanceList` + add-connector modal
 *
 * `DEMO_CONNECTORS` is gated behind `demoFallback`, so it populates the hosted
 * demo and is `undefined` everywhere else. The error banner used to say
 * "showing demo instances so you can explore the interface" regardless — on a
 * self-hosted deployment that sentence described a list that was empty, above
 * four stat tiles reading a confident zero. Both now say the estate is
 * unknown, which is the only true statement available when the request failed.
 */

import { useMemo, useState } from 'react';
import useSWR from 'swr';
import toast from 'react-hot-toast';
import { clsx } from 'clsx';

import {
  connectorsApi,
  type Connector,
  type ConnectorHealthSummary,
} from '@/lib/api';
import { AddConnectorModal } from './AddConnectorModal';
import { ConnectorInstanceList } from './ConnectorInstanceList';
import { InboxTokensPanel } from './InboxTokensPanel';
import { demoFallback } from '@/lib/demoFallback';
import { FailureBanner } from '@/components/ui/FailureBanner';
import { describeApiFailure } from '@/lib/failure';

const DEMO_CONNECTORS: Connector[] = [
  {
    id: 'conn-001', name: 'CrowdStrike Falcon', type: 'crowdstrike',
    status: 'active', enabled: true,
    config: {}, alertCount: 4231, alertsIngested: 4231,
    lastSync: '2026-05-06T12:30:00Z',
    createdAt: '2026-03-15T10:00:00Z', updatedAt: '2026-05-06T12:30:00Z',
  },
  {
    id: 'conn-002', name: 'Microsoft Sentinel', type: 'microsoft_sentinel',
    status: 'active', enabled: true,
    config: {}, alertCount: 2847, alertsIngested: 2847,
    lastSync: '2026-05-06T12:28:00Z',
    createdAt: '2026-03-20T14:00:00Z', updatedAt: '2026-05-06T12:28:00Z',
  },
  {
    id: 'conn-003', name: 'Splunk Enterprise', type: 'splunk',
    status: 'active', enabled: true,
    config: {}, alertCount: 1893, alertsIngested: 1893,
    lastSync: '2026-05-06T12:25:00Z',
    createdAt: '2026-04-01T09:00:00Z', updatedAt: '2026-05-06T12:25:00Z',
  },
  {
    id: 'conn-004', name: 'AWS Security Hub', type: 'aws_security_hub',
    status: 'error', enabled: true,
    config: {}, alertCount: 567, alertsIngested: 567,
    lastSync: '2026-05-06T08:15:00Z',
    createdAt: '2026-04-10T11:00:00Z', updatedAt: '2026-05-06T08:15:00Z',
  },
  {
    id: 'conn-005', name: 'Okta SSO', type: 'okta',
    status: 'active', enabled: false,
    config: {}, alertCount: 0, alertsIngested: 0,
    createdAt: '2026-04-20T16:00:00Z', updatedAt: '2026-04-20T16:00:00Z',
  },
];

export function ConnectorsView() {
  const [modalOpen, setModalOpen] = useState(false);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [testResults, setTestResults] = useState<Record<string, boolean | undefined>>({});

  const { data, error, isLoading, mutate } = useSWR(
    'connectors',
    () => connectorsApi.list(),
    {
      revalidateOnFocus: false,
      fallbackData: demoFallback({ connectors: DEMO_CONNECTORS, total: DEMO_CONNECTORS.length }),
    },
  );

  // Health summary is a separate endpoint so the empty/error case is silent —
  // we just fall back to the locally-derived stats. SWR keys are namespaced so
  // the two queries don't fight over the cache.
  const { data: healthSummary } = useSWR<ConnectorHealthSummary | null>(
    'connectors:health',
    async () => {
      try {
        return await connectorsApi.health();
      } catch {
        return null;
      }
    },
    { revalidateOnFocus: false, refreshInterval: 60_000 },
  );

  const connectors: Connector[] = useMemo(() => data?.connectors ?? [], [data]);

  const localStats = useMemo(() => {
    const active = connectors.filter((c) => c.status === 'active').length;
    const errored = connectors.filter((c) => c.status === 'error').length;
    const totalEvents = connectors.reduce(
      (sum, c) => sum + (c.alertCount ?? c.alertsIngested ?? 0),
      0,
    );
    const driftedRecently = connectors.filter((c) => {
      if (!c.lastSchemaDriftAt) return false;
      return Date.now() - new Date(c.lastSchemaDriftAt).getTime() < 24 * 60 * 60 * 1000;
    }).length;
    const totalDropped = connectors.reduce(
      (sum, c) => sum + (c.eventsDropped ?? 0),
      0,
    );
    return { active, errored, totalEvents, driftedRecently, totalDropped };
  }, [connectors]);

  // Prefer backend-aggregated stats when the API is reachable so the tile
  // matches the source of truth (the schema-drift sentinel runs server-side).
  const stats = useMemo(() => {
    if (healthSummary) {
      return {
        active: healthSummary.healthy,
        errored: healthSummary.unhealthy,
        totalEvents: healthSummary.totalEventsIngested,
        driftedRecently: healthSummary.driftedRecently,
        totalDropped: healthSummary.totalEventsDropped,
      };
    }
    return localStats;
  }, [healthSummary, localStats]);

  // `localStats` is derived from a list that is `[]` whenever the request
  // failed, so with no health summary to fall back on every tile reads a
  // confident zero — "Total Connectors 0", "Errors 0" — on a tenant whose
  // connectors the console simply could not read. Zero connectors and unknown
  // connectors are opposite findings and both were rendered identically.
  const countsUnknown = !!error && !healthSummary;

  // ─── Actions ──────────────────────────────────────────────────────────────

  const handleTest = async (id: string) => {
    setTestingId(id);
    setTestResults((prev) => ({ ...prev, [id]: undefined }));
    try {
      const result = await connectorsApi.test(id);
      setTestResults((prev) => ({ ...prev, [id]: result.success }));
      if (result.success) {
        toast.success(result.message ?? 'Connection test passed');
      } else {
        toast.error(result.error ?? result.message ?? 'Connection test failed');
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Test request failed';
      setTestResults((prev) => ({ ...prev, [id]: false }));
      toast.error(msg);
    } finally {
      setTestingId(null);
    }
  };

  const handleDelete = async (connector: Connector) => {
    // Browser confirm is intentional — destructive, infrequent, and we don't
    // yet have a shared confirmation dialog component. Worth revisiting once
    // we add one to `components/ui/`.
    const ok = window.confirm(
      `Delete connector "${connector.name}"? This stops polling and removes its credentials. Already-ingested alerts are preserved.`,
    );
    if (!ok) return;

    try {
      await connectorsApi.delete(connector.id);
      toast.success(`Removed ${connector.name}`);
      mutate();
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to delete connector';
      toast.error(msg);
    }
  };

  const handleConfigure = (_connector: Connector) => {
    // Inline edit dialog ships in a follow-up. For now, surface a hint so
    // operators don't think the button is broken — the modal already covers
    // create + test, which is the high-value path for v1.
    toast('Connector editing UI is coming soon. Delete + re-add for now.', {
      icon: '🔧',
    });
  };

  const handleCreated = () => {
    mutate();
  };

  // ─── Render ───────────────────────────────────────────────────────────────

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-semibold text-gray-100">Connectors</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Security tool integrations and data source management
          </p>
        </div>
        <button
          type="button"
          onClick={() => setModalOpen(true)}
          className="bg-blue-600 hover:bg-blue-500 text-white text-sm px-4 py-2 rounded-lg transition-colors flex items-center gap-2"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          Add Connector
        </button>
      </div>

      {/* Stats — render even with zero connectors so the layout is stable
          between empty/populated states. The drift/dropped tiles only render
          when the schema-drift sentinel has actually fired so a clean tenant
          keeps a calm 4-tile layout. */}
      <div
        className={clsx(
          'grid grid-cols-2 gap-3',
          stats.driftedRecently > 0 || stats.totalDropped > 0
            ? 'md:grid-cols-6'
            : 'md:grid-cols-4',
        )}
      >
        {[
          {
            label: 'Total Connectors',
            value: healthSummary?.total ?? connectors.length,
            color: 'text-blue-400',
            show: true,
          },
          { label: 'Active', value: stats.active, color: 'text-green-400', show: true },
          { label: 'Errors', value: stats.errored, color: 'text-red-400', show: true },
          {
            label: 'Events Ingested',
            value: stats.totalEvents.toLocaleString(),
            color: 'text-purple-400',
            show: true,
          },
          {
            label: 'Schema Drift (24h)',
            value: stats.driftedRecently,
            color: 'text-amber-400',
            show: stats.driftedRecently > 0,
            tooltip:
              healthSummary?.lastDriftAt
                ? `Most recent drift: ${new Date(healthSummary.lastDriftAt).toLocaleString()}`
                : undefined,
          },
          {
            label: 'Events Dropped',
            value: stats.totalDropped.toLocaleString(),
            color: 'text-cyan-400',
            show: stats.totalDropped > 0,
            tooltip: 'Filtered out by pre-ingest pipeline rules',
          },
        ]
          .filter((stat) => stat.show)
          .map((stat) => (
            <div
              key={stat.label}
              title={stat.tooltip}
              className="bg-gray-900/60 border border-gray-800/60 rounded-xl p-4"
            >
              <p
                className={clsx(
                  'text-2xl font-bold mb-1',
                  countsUnknown ? 'text-gray-600' : stat.color,
                )}
              >
                {countsUnknown ? '—' : stat.value}
              </p>
              <p className="text-xs text-gray-500">{stat.label}</p>
              {countsUnknown && <p className="text-[10px] text-gray-600 mt-0.5">not measured</p>}
            </div>
          ))}
      </div>

      {/* Body */}
      {error && (
        <FailureBanner
          title="Connectors unavailable"
          message={describeApiFailure(error, {
            subject: 'connector list',
            service: 'connectors service',
          })}
          onRetry={() => mutate()}
        />
      )}
      {(
        <ConnectorInstanceList
          connectors={connectors}
          failed={!!error}
          isLoading={isLoading && !data}
          testingId={testingId}
          testResults={testResults}
          onTest={handleTest}
          onAdd={() => setModalOpen(true)}
          onConfigure={handleConfigure}
          onDelete={handleDelete}
        />
      )}

      {/* Universal capture (push) — collapsed by default. Sits below the
          poll-based connector list so the catalog stays the primary path
          and "push for everything else" is one click away. */}
      <InboxTokensPanel />

      {/* Add modal */}
      <AddConnectorModal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        onCreated={handleCreated}
      />
    </div>
  );
}
