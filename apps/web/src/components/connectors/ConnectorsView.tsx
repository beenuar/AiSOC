'use client';

import { useState } from 'react';
import useSWR from 'swr';
import { connectorsApi, type Connector } from '@/lib/api';
import { clsx } from 'clsx';

// ─── Mock Data ────────────────────────────────────────────────────────────────

const MOCK_CONNECTORS: Connector[] = [
  {
    id: 'conn-crowdstrike',
    name: 'CrowdStrike Falcon',
    type: 'crowdstrike',
    status: 'active',
    enabled: true,
    lastSync: new Date(Date.now() - 300000).toISOString(),
    alertCount: 1247,
    config: { baseUrl: 'https://api.crowdstrike.com', clientId: 'abc123' },
    description: 'CrowdStrike Falcon endpoint detection and response',
  },
  {
    id: 'conn-splunk',
    name: 'Splunk SIEM',
    type: 'splunk',
    status: 'active',
    enabled: true,
    lastSync: new Date(Date.now() - 600000).toISOString(),
    alertCount: 3891,
    config: { host: 'splunk.internal', port: 8089 },
    description: 'Splunk Enterprise SIEM correlation search alerts',
  },
  {
    id: 'conn-aws',
    name: 'AWS Security Hub',
    type: 'aws',
    status: 'active',
    enabled: true,
    lastSync: new Date(Date.now() - 120000).toISOString(),
    alertCount: 562,
    config: { region: 'us-east-1', accountId: '123456789012' },
    description: 'AWS Security Hub findings from GuardDuty, Inspector, and Macie',
  },
  {
    id: 'conn-okta',
    name: 'Okta Identity',
    type: 'okta',
    status: 'error',
    enabled: true,
    lastSync: new Date(Date.now() - 7200000).toISOString(),
    alertCount: 89,
    config: { domain: 'company.okta.com' },
    description: 'Okta identity provider suspicious sign-in events',
  },
  {
    id: 'conn-sentinel',
    name: 'Microsoft Sentinel',
    type: 'sentinel',
    status: 'inactive',
    enabled: false,
    lastSync: new Date(Date.now() - 86400000).toISOString(),
    alertCount: 0,
    config: { workspaceId: 'ws-abc-123', subscriptionId: 'sub-xyz-456' },
    description: 'Microsoft Sentinel cloud-native SIEM',
  },
];

const CONNECTOR_ICONS: Record<string, string> = {
  crowdstrike: '🦅',
  splunk: '🔭',
  aws: '☁️',
  okta: '🔐',
  sentinel: '🛡️',
  custom: '⚙️',
};

const STATUS_CONFIG = {
  active: { label: 'Active', color: 'text-green-400 bg-green-500/10 border-green-500/20', dot: 'bg-green-400' },
  inactive: { label: 'Inactive', color: 'text-gray-400 bg-gray-500/10 border-gray-500/20', dot: 'bg-gray-500' },
  error: { label: 'Error', color: 'text-red-400 bg-red-500/10 border-red-500/20', dot: 'bg-red-400' },
};

function formatLastSync(ts: string) {
  const diff = Date.now() - new Date(ts).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

// ─── Connector Card ───────────────────────────────────────────────────────────

function ConnectorCard({ connector, onTest }: { connector: Connector; onTest: (id: string) => void }) {
  const statusCfg = STATUS_CONFIG[connector.status];

  return (
    <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl p-5 hover:border-gray-700/60 transition-colors">
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-gray-800 rounded-xl flex items-center justify-center text-xl">
            {CONNECTOR_ICONS[connector.type] || '⚙️'}
          </div>
          <div>
            <h3 className="text-sm font-medium text-gray-200">{connector.name}</h3>
            <p className="text-xs text-gray-500 capitalize">{connector.type}</p>
          </div>
        </div>
        <span className={clsx('text-xs px-2 py-0.5 rounded-full border flex items-center gap-1', statusCfg.color)}>
          <span className={clsx('w-1.5 h-1.5 rounded-full', statusCfg.dot)} />
          {statusCfg.label}
        </span>
      </div>

      <p className="text-xs text-gray-500 mb-4">{connector.description}</p>

      <div className="grid grid-cols-2 gap-2 mb-4">
        <div className="bg-gray-800/60 rounded-lg p-2">
          <p className="text-xs text-gray-500">Alerts fetched</p>
          <p className="text-sm font-medium text-gray-300">{connector.alertCount.toLocaleString()}</p>
        </div>
        <div className="bg-gray-800/60 rounded-lg p-2">
          <p className="text-xs text-gray-500">Last sync</p>
          <p className="text-sm font-medium text-gray-300">{formatLastSync(connector.lastSync)}</p>
        </div>
      </div>

      <div className="flex items-center gap-2">
        <button
          onClick={() => onTest(connector.id)}
          className="flex-1 text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-2 rounded-lg transition-colors"
        >
          Test Connection
        </button>
        <button className="flex-1 text-xs bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 px-3 py-2 rounded-lg transition-colors border border-blue-500/20">
          Configure
        </button>
      </div>
    </div>
  );
}

// ─── Main View ────────────────────────────────────────────────────────────────

export function ConnectorsView() {
  const [testingId, setTestingId] = useState<string | null>(null);
  const [testResults, setTestResults] = useState<Record<string, boolean | null>>({});

  const { data: connData, isLoading } = useSWR(
    'connectors',
    () => connectorsApi.list(),
    { fallbackData: { connectors: MOCK_CONNECTORS, total: MOCK_CONNECTORS.length } }
  );

  const connectors = connData?.connectors || MOCK_CONNECTORS;

  const handleTest = async (id: string) => {
    setTestingId(id);
    setTestResults(prev => ({ ...prev, [id]: null }));
    try {
      const result = await connectorsApi.test(id);
      setTestResults(prev => ({ ...prev, [id]: result.success }));
    } catch {
      setTestResults(prev => ({ ...prev, [id]: false }));
    } finally {
      setTestingId(null);
    }
  };

  const activeCount = connectors.filter(c => c.status === 'active').length;
  const errorCount = connectors.filter(c => c.status === 'error').length;
  const totalAlerts = connectors.reduce((sum, c) => sum + c.alertCount, 0);

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
        <button className="bg-blue-600 hover:bg-blue-500 text-white text-sm px-4 py-2 rounded-lg transition-colors flex items-center gap-2">
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          Add Connector
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Total Connectors', value: connectors.length, color: 'text-blue-400', icon: '🔌' },
          { label: 'Active', value: activeCount, color: 'text-green-400', icon: '✅' },
          { label: 'Errors', value: errorCount, color: 'text-red-400', icon: '⚠️' },
          { label: 'Total Alerts', value: totalAlerts.toLocaleString(), color: 'text-purple-400', icon: '📊' },
        ].map((stat) => (
          <div key={stat.label} className="bg-gray-900/60 border border-gray-800/60 rounded-xl p-4">
            <div className="flex items-center gap-2 mb-1">
              <span>{stat.icon}</span>
              <p className={clsx('text-2xl font-bold', stat.color)}>{stat.value}</p>
            </div>
            <p className="text-xs text-gray-500">{stat.label}</p>
          </div>
        ))}
      </div>

      {/* Connector Grid */}
      {isLoading ? (
        <div className="flex items-center justify-center h-32 text-gray-600">
          <div className="animate-spin w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full" />
        </div>
      ) : (
        <div className="grid grid-cols-3 gap-4">
          {connectors.map((connector) => (
            <ConnectorCard
              key={connector.id}
              connector={connector}
              onTest={handleTest}
            />
          ))}

          {/* Add New Card */}
          <div className="bg-gray-900/30 border border-dashed border-gray-700/60 rounded-xl p-5 flex flex-col items-center justify-center gap-3 hover:border-gray-600/60 transition-colors cursor-pointer">
            <div className="w-10 h-10 bg-gray-800/60 rounded-xl flex items-center justify-center text-gray-500">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
              </svg>
            </div>
            <div className="text-center">
              <p className="text-sm text-gray-500">Add Connector</p>
              <p className="text-xs text-gray-600 mt-0.5">Connect a new security tool</p>
            </div>
          </div>
        </div>
      )}

      {/* Test Results Notifications */}
      {Object.entries(testResults).filter(([, v]) => v !== null).length > 0 && (
        <div className="space-y-2">
          {Object.entries(testResults).map(([id, success]) => {
            if (success === null) return null;
            const conn = connectors.find(c => c.id === id);
            if (!conn) return null;
            return (
              <div
                key={id}
                className={clsx(
                  'text-sm px-4 py-2 rounded-lg border flex items-center gap-2',
                  success
                    ? 'text-green-400 bg-green-500/10 border-green-500/20'
                    : 'text-red-400 bg-red-500/10 border-red-500/20'
                )}
              >
                <span>{success ? '✓' : '✗'}</span>
                <span>{conn.name}: {success ? 'Connection successful' : 'Connection failed'}</span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
