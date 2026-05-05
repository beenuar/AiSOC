'use client';

/**
 * Grid of saved connector instances with per-card actions.
 *
 * The list itself is purely presentational — the parent (`ConnectorsView`)
 * owns data fetching and mutation so SWR cache invalidation lives in one
 * place. This component only knows how to render a `Connector[]` and emit
 * action callbacks (test, delete) when the operator clicks a row.
 *
 * Layout follows the rest of the AiSOC dashboard: 3-up grid on wide
 * screens, with a trailing "Add Connector" tile that the parent wires to
 * the `AddConnectorModal`. Empty state replaces the grid entirely so a
 * fresh tenant gets a useful onboarding nudge instead of just the
 * dashed placeholder card.
 */

import { clsx } from 'clsx';
import { EmptyState } from '@/components/ui/EmptyState';
import { SkeletonCard } from '@/components/ui/Skeleton';
import type { Connector } from '@/lib/api';

const CONNECTOR_LABELS: Record<string, string> = {
  crowdstrike: 'CS',
  splunk: 'SPL',
  aws_security_hub: 'AWS',
  okta: 'OKT',
  microsoft_sentinel: 'SNT',
  azure_entra: 'AZE',
  azure_activity: 'AZA',
  azure_defender: 'AZD',
  gcp_cloud_audit: 'GCP',
  gcp_scc: 'SCC',
  m365_audit: 'M365',
  google_workspace: 'GWS',
  cloudflare: 'CF',
  github: 'GH',
};

const STATUS_CONFIG: Record<
  Connector['status'],
  { label: string; color: string; dot: string }
> = {
  active: {
    label: 'Active',
    color: 'text-green-400 bg-green-500/10 border-green-500/20',
    dot: 'bg-green-400',
  },
  inactive: {
    label: 'Inactive',
    color: 'text-gray-400 bg-gray-500/10 border-gray-500/20',
    dot: 'bg-gray-500',
  },
  error: {
    label: 'Error',
    color: 'text-red-400 bg-red-500/10 border-red-500/20',
    dot: 'bg-red-400',
  },
  configuring: {
    label: 'Configuring',
    color: 'text-amber-300 bg-amber-500/10 border-amber-500/20',
    dot: 'bg-amber-400',
  },
};

function formatLastSync(ts?: string): string {
  if (!ts) return 'never';
  const diff = Date.now() - new Date(ts).getTime();
  if (Number.isNaN(diff)) return 'never';
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function abbreviateType(type: string): string {
  if (CONNECTOR_LABELS[type]) return CONNECTOR_LABELS[type];
  // Fall back to the first 3 letters of the connector type so unknown
  // connectors still get a readable badge instead of "GEN".
  return type.slice(0, 3).toUpperCase();
}

// ─── Card ────────────────────────────────────────────────────────────────────

interface ConnectorCardProps {
  connector: Connector;
  testing: boolean;
  /** `true` = last test passed, `false` = failed, `undefined` = idle. */
  testResult: boolean | undefined;
  onTest: (id: string) => void;
  onConfigure?: (connector: Connector) => void;
  onDelete?: (connector: Connector) => void;
}

function ConnectorCard({
  connector,
  testing,
  testResult,
  onTest,
  onConfigure,
  onDelete,
}: ConnectorCardProps) {
  const statusCfg = STATUS_CONFIG[connector.status] ?? STATUS_CONFIG.configuring;
  const alertCount = connector.alertCount ?? connector.alertsIngested ?? 0;

  return (
    <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl p-5 hover:border-gray-700/60 transition-colors flex flex-col">
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-3 min-w-0">
          <div className="w-10 h-10 bg-gray-800 rounded-xl flex items-center justify-center text-[10px] font-semibold uppercase tracking-wider text-gray-400 flex-shrink-0">
            {abbreviateType(connector.type)}
          </div>
          <div className="min-w-0">
            <h3 className="text-sm font-medium text-gray-200 truncate">{connector.name}</h3>
            <p className="text-xs text-gray-500 truncate">{connector.type}</p>
          </div>
        </div>
        <span
          className={clsx(
            'text-xs px-2 py-0.5 rounded-full border flex items-center gap-1 flex-shrink-0',
            statusCfg.color,
          )}
          title={connector.errorMessage}
        >
          <span className={clsx('w-1.5 h-1.5 rounded-full', statusCfg.dot)} />
          {statusCfg.label}
        </span>
      </div>

      {connector.description && (
        <p className="text-xs text-gray-500 mb-4 line-clamp-2">{connector.description}</p>
      )}

      <div className="grid grid-cols-2 gap-2 mb-4">
        <div className="bg-gray-800/60 rounded-lg p-2">
          <p className="text-xs text-gray-500">Events ingested</p>
          <p className="text-sm font-medium text-gray-300">
            {alertCount.toLocaleString()}
          </p>
        </div>
        <div className="bg-gray-800/60 rounded-lg p-2">
          <p className="text-xs text-gray-500">Last sync</p>
          <p className="text-sm font-medium text-gray-300">
            {formatLastSync(connector.lastSync)}
          </p>
        </div>
      </div>

      <div className="mt-auto flex items-center gap-2">
        <button
          type="button"
          onClick={() => onTest(connector.id)}
          disabled={testing}
          className="flex-1 text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-2 rounded-lg transition-colors disabled:opacity-60 flex items-center justify-center gap-2"
        >
          {testing && (
            <span className="animate-spin w-3 h-3 border-2 border-blue-400 border-t-transparent rounded-full" />
          )}
          Test
        </button>
        <button
          type="button"
          onClick={() => onConfigure?.(connector)}
          className="flex-1 text-xs bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 px-3 py-2 rounded-lg transition-colors border border-blue-500/20"
        >
          Configure
        </button>
        {onDelete && (
          <button
            type="button"
            onClick={() => onDelete(connector)}
            aria-label={`Delete ${connector.name}`}
            className="text-xs text-gray-500 hover:text-red-400 px-2 py-2 rounded-lg transition-colors"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={1.8}
                d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6M1 7h22M9 7V4a1 1 0 011-1h4a1 1 0 011 1v3"
              />
            </svg>
          </button>
        )}
      </div>

      {testResult !== undefined && (
        <p
          className={clsx(
            'mt-3 text-xs',
            testResult ? 'text-green-400' : 'text-red-400',
          )}
        >
          {testResult ? '✓ Connection successful' : '✗ Connection failed'}
        </p>
      )}
    </div>
  );
}

// ─── List ────────────────────────────────────────────────────────────────────

export interface ConnectorInstanceListProps {
  connectors: Connector[];
  isLoading?: boolean;
  testingId?: string | null;
  testResults?: Record<string, boolean | undefined>;
  onTest: (id: string) => void;
  onAdd: () => void;
  onConfigure?: (connector: Connector) => void;
  onDelete?: (connector: Connector) => void;
}

export function ConnectorInstanceList({
  connectors,
  isLoading,
  testingId,
  testResults,
  onTest,
  onAdd,
  onConfigure,
  onDelete,
}: ConnectorInstanceListProps) {
  if (isLoading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        <SkeletonCard />
        <SkeletonCard />
        <SkeletonCard />
      </div>
    );
  }

  if (connectors.length === 0) {
    return (
      <EmptyState
        icon={
          <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={1.5}
              d="M13.5 21v-7.5a.75.75 0 01.75-.75h3a.75.75 0 01.75.75V21m-4.5 0H2.36m11.14 0H18m0 0h3.64m-1.39 0V9.349m-16.5 11.65V9.35m0 0a3.001 3.001 0 003.75-.615A2.993 2.993 0 009.75 9.75c.896 0 1.7-.393 2.25-1.016a2.993 2.993 0 002.25 1.016c.896 0 1.7-.393 2.25-1.016a3.001 3.001 0 003.75.614m-16.5 0a3.004 3.004 0 01-.621-4.72L4.318 3.44A1.5 1.5 0 015.378 3h13.243a1.5 1.5 0 011.06.44l1.19 1.189a3 3 0 01-.621 4.72m-13.5 8.65h3.75a.75.75 0 00.75-.75V13.5a.75.75 0 00-.75-.75H6.75a.75.75 0 00-.75.75v3.75c0 .415.336.75.75.75z"
            />
          </svg>
        }
        title="No connectors yet"
        description="Connect your first security tool to start ingesting alerts. Credentials are encrypted at rest with the AiSOC vault."
        action={
          <button
            type="button"
            onClick={onAdd}
            className="bg-blue-600 hover:bg-blue-500 text-white text-sm px-4 py-2 rounded-lg transition-colors flex items-center gap-2"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
            </svg>
            Add your first connector
          </button>
        }
      />
    );
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
      {connectors.map((connector) => (
        <ConnectorCard
          key={connector.id}
          connector={connector}
          testing={testingId === connector.id}
          testResult={testResults?.[connector.id]}
          onTest={onTest}
          onConfigure={onConfigure}
          onDelete={onDelete}
        />
      ))}

      {/* Trailing "add new" tile so adding a second/third connector is one
          click without having to scroll back to the page header. */}
      <button
        type="button"
        onClick={onAdd}
        className="bg-gray-900/30 border border-dashed border-gray-700/60 rounded-xl p-5 flex flex-col items-center justify-center gap-3 hover:border-gray-600/60 hover:bg-gray-900/50 transition-colors text-left"
      >
        <div className="w-10 h-10 bg-gray-800/60 rounded-xl flex items-center justify-center text-gray-500">
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
        </div>
        <div className="text-center">
          <p className="text-sm text-gray-300">Add Connector</p>
          <p className="text-xs text-gray-600 mt-0.5">Connect a new security tool</p>
        </div>
      </button>
    </div>
  );
}
