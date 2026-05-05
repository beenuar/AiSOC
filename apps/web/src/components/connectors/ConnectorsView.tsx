'use client';

/**
 * Top-level Connectors page.
 *
 * Owns the SWR cache for `connectorsApi.list()` and renders three sub-views
 * depending on state:
 *
 *   - loading  → skeleton tiles
 *   - error    → `ErrorState` with retry
 *   - data     → header stats + `ConnectorInstanceList` + add-connector modal
 *
 * Mock data is intentionally gone — the modal can spin up real instances
 * against the backend, so dogfooding the empty state is now both more
 * informative and one click from being populated.
 */

import { useMemo, useState } from 'react';
import useSWR from 'swr';
import toast from 'react-hot-toast';
import { clsx } from 'clsx';

import { connectorsApi, type Connector } from '@/lib/api';
import { ErrorState } from '@/components/ui/ErrorState';
import { AddConnectorModal } from './AddConnectorModal';
import { ConnectorInstanceList } from './ConnectorInstanceList';

export function ConnectorsView() {
  const [modalOpen, setModalOpen] = useState(false);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [testResults, setTestResults] = useState<Record<string, boolean | undefined>>({});

  const { data, error, isLoading, mutate } = useSWR(
    'connectors',
    () => connectorsApi.list(),
    { revalidateOnFocus: false },
  );

  const connectors: Connector[] = useMemo(() => data?.connectors ?? [], [data]);

  const stats = useMemo(() => {
    const active = connectors.filter((c) => c.status === 'active').length;
    const errored = connectors.filter((c) => c.status === 'error').length;
    const totalEvents = connectors.reduce(
      (sum, c) => sum + (c.alertCount ?? c.alertsIngested ?? 0),
      0,
    );
    return { active, errored, totalEvents };
  }, [connectors]);

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
          between empty/populated states. */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: 'Total Connectors', value: connectors.length, color: 'text-blue-400' },
          { label: 'Active', value: stats.active, color: 'text-green-400' },
          { label: 'Errors', value: stats.errored, color: 'text-red-400' },
          {
            label: 'Events Ingested',
            value: stats.totalEvents.toLocaleString(),
            color: 'text-purple-400',
          },
        ].map((stat) => (
          <div
            key={stat.label}
            className="bg-gray-900/60 border border-gray-800/60 rounded-xl p-4"
          >
            <p className={clsx('text-2xl font-bold mb-1', stat.color)}>{stat.value}</p>
            <p className="text-xs text-gray-500">{stat.label}</p>
          </div>
        ))}
      </div>

      {/* Body */}
      {error ? (
        <ErrorState
          title="Could not load connectors"
          description="The API returned an error while fetching your connector instances. The connectors service may still be starting up."
          error={error}
          onRetry={() => mutate()}
        />
      ) : (
        <ConnectorInstanceList
          connectors={connectors}
          isLoading={isLoading && !data}
          testingId={testingId}
          testResults={testResults}
          onTest={handleTest}
          onAdd={() => setModalOpen(true)}
          onConfigure={handleConfigure}
          onDelete={handleDelete}
        />
      )}

      {/* Add modal */}
      <AddConnectorModal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        onCreated={handleCreated}
      />
    </div>
  );
}
