'use client';

import { useState } from 'react';
import { clsx } from 'clsx';
import { EmptyState, EmptyStateIcons } from '@/components/ui/EmptyState';

type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';
type AssetType = 'domain' | 'ip' | 'cert' | 'subdomain' | 'service';

interface Asset {
  id: string;
  asset: string;
  type: AssetType;
  status: 'healthy' | 'warning' | 'critical';
  risk: RiskLevel;
  lastSeen: string;
}

interface Certificate {
  id: string;
  domain: string;
  issuer: string;
  expiryDate: string;
  daysRemaining: number;
  status: 'valid' | 'expiring' | 'expired';
}

const RISK_CONFIG: Record<RiskLevel, { label: string; className: string }> = {
  critical: { label: 'Critical', className: 'text-red-400 bg-red-500/10 border-red-500/20' },
  high: { label: 'High', className: 'text-orange-400 bg-orange-500/10 border-orange-500/20' },
  medium: { label: 'Medium', className: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20' },
  low: { label: 'Low', className: 'text-blue-400 bg-blue-500/10 border-blue-500/20' },
  info: { label: 'Info', className: 'text-gray-400 bg-gray-500/10 border-gray-500/20' },
};

const STATUS_COLOR: Record<Asset['status'], string> = {
  healthy: 'text-green-400 bg-green-500/10 border-green-500/20',
  warning: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
  critical: 'text-red-400 bg-red-500/10 border-red-500/20',
};

const CERT_STATUS_COLOR: Record<Certificate['status'], string> = {
  valid: 'text-green-400 bg-green-500/10 border-green-500/20',
  expiring: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
  expired: 'text-red-400 bg-red-500/10 border-red-500/20',
};

const TYPE_LABELS: Record<AssetType, string> = {
  domain: 'Domain',
  ip: 'IP Address',
  cert: 'Certificate',
  subdomain: 'Subdomain',
  service: 'Service',
};

const MOCK_ASSETS: Asset[] = [
  { id: 'a1', asset: 'corp.example.com', type: 'domain', status: 'healthy', risk: 'low', lastSeen: '2 min ago' },
  { id: 'a2', asset: 'api.corp.example.com', type: 'subdomain', status: 'warning', risk: 'medium', lastSeen: '5 min ago' },
  { id: 'a3', asset: '203.0.113.42', type: 'ip', status: 'critical', risk: 'critical', lastSeen: '1 min ago' },
  { id: 'a4', asset: 'staging.example.com', type: 'subdomain', status: 'warning', risk: 'high', lastSeen: '12 min ago' },
  { id: 'a5', asset: 'mail.corp.example.com', type: 'service', status: 'healthy', risk: 'low', lastSeen: '3 min ago' },
  { id: 'a6', asset: '198.51.100.17', type: 'ip', status: 'healthy', risk: 'info', lastSeen: '8 min ago' },
  { id: 'a7', asset: 'dev.internal.example.com', type: 'subdomain', status: 'critical', risk: 'high', lastSeen: '1 min ago' },
  { id: 'a8', asset: 'vpn.corp.example.com', type: 'service', status: 'healthy', risk: 'medium', lastSeen: '4 min ago' },
  { id: 'a9', asset: 'cdn.example.com', type: 'domain', status: 'healthy', risk: 'low', lastSeen: '6 min ago' },
  { id: 'a10', asset: '192.0.2.88', type: 'ip', status: 'warning', risk: 'medium', lastSeen: '15 min ago' },
];

const MOCK_CERTIFICATES: Certificate[] = [
  { id: 'c1', domain: 'corp.example.com', issuer: "Let's Encrypt", expiryDate: '2026-08-14', daysRemaining: 99, status: 'valid' },
  { id: 'c2', domain: 'api.corp.example.com', issuer: 'DigiCert', expiryDate: '2026-05-21', daysRemaining: 14, status: 'expiring' },
  { id: 'c3', domain: 'staging.example.com', issuer: "Let's Encrypt", expiryDate: '2026-05-03', daysRemaining: -4, status: 'expired' },
  { id: 'c4', domain: 'mail.corp.example.com', issuer: 'Sectigo', expiryDate: '2027-01-10', daysRemaining: 248, status: 'valid' },
  { id: 'c5', domain: 'vpn.corp.example.com', issuer: 'DigiCert', expiryDate: '2026-06-01', daysRemaining: 25, status: 'expiring' },
  { id: 'c6', domain: 'dev.internal.example.com', issuer: 'Self-Signed', expiryDate: '2026-05-09', daysRemaining: 2, status: 'expiring' },
];

const SUMMARY = {
  totalAssets: MOCK_ASSETS.length,
  exposedServices: MOCK_ASSETS.filter((a) => a.status === 'critical' || a.status === 'warning').length,
  certIssues: MOCK_CERTIFICATES.filter((c) => c.status !== 'valid').length,
  riskScore: 72,
};

export function EASMView() {
  const [assetFilter, setAssetFilter] = useState<Asset['status'] | 'all'>('all');

  const filteredAssets = assetFilter === 'all'
    ? MOCK_ASSETS
    : MOCK_ASSETS.filter((a) => a.status === assetFilter);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-semibold text-gray-100">External Attack Surface Management</h1>
        <p className="text-sm text-gray-500 mt-0.5">Monitor external assets, exposed services, and certificate health</p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Total Assets', value: SUMMARY.totalAssets, color: 'text-blue-400' },
          { label: 'Exposed Services', value: SUMMARY.exposedServices, color: 'text-amber-400' },
          { label: 'Certificate Issues', value: SUMMARY.certIssues, color: 'text-red-400' },
          { label: 'Risk Score', value: `${SUMMARY.riskScore}/100`, color: SUMMARY.riskScore >= 70 ? 'text-amber-400' : 'text-green-400' },
        ].map((card) => (
          <div key={card.label} className="bg-gray-900/60 border border-gray-800/60 rounded-xl p-4">
            <p className={clsx('text-2xl font-bold', card.color)}>{card.value}</p>
            <p className="text-xs text-gray-500 mt-0.5">{card.label}</p>
          </div>
        ))}
      </div>

      {/* Asset Discovery Table */}
      <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-800/60 flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-gray-200">Asset Discovery</h2>
            <p className="text-xs text-gray-500 mt-0.5">{filteredAssets.length} assets found</p>
          </div>
          <div className="flex gap-2">
            {(['all', 'healthy', 'warning', 'critical'] as const).map((f) => (
              <button
                key={f}
                onClick={() => setAssetFilter(f)}
                className={clsx(
                  'text-xs px-3 py-1 rounded-lg border transition-colors',
                  assetFilter === f
                    ? 'bg-blue-600/15 text-blue-300 border-blue-600/30'
                    : 'text-gray-400 border-gray-800 hover:border-gray-700'
                )}
              >
                {f === 'all' ? 'All' : f.charAt(0).toUpperCase() + f.slice(1)}
              </button>
            ))}
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800/40">
                <th className="text-left text-xs font-medium text-gray-500 px-5 py-3">Asset</th>
                <th className="text-left text-xs font-medium text-gray-500 px-5 py-3">Type</th>
                <th className="text-left text-xs font-medium text-gray-500 px-5 py-3">Status</th>
                <th className="text-left text-xs font-medium text-gray-500 px-5 py-3">Risk</th>
                <th className="text-left text-xs font-medium text-gray-500 px-5 py-3">Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {filteredAssets.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-0">
                    <EmptyState
                      icon={EmptyStateIcons.shield}
                      title="No assets match this filter"
                      description="Try selecting a different status filter or view all assets."
                      action={
                        <button
                          type="button"
                          onClick={() => setAssetFilter('all')}
                          className="rounded-lg bg-gray-800 px-4 py-2 text-sm text-gray-200 hover:bg-gray-700 transition-colors"
                        >
                          Show all assets
                        </button>
                      }
                    />
                  </td>
                </tr>
              ) : (
                filteredAssets.map((asset) => (
                  <tr key={asset.id} className="border-b border-gray-800/30 hover:bg-gray-800/30 transition-colors">
                    <td className="px-5 py-3">
                      <span className="text-gray-200 font-mono text-xs">{asset.asset}</span>
                    </td>
                    <td className="px-5 py-3 text-gray-400 text-xs">{TYPE_LABELS[asset.type]}</td>
                    <td className="px-5 py-3">
                      <span className={clsx('text-xs font-medium px-2 py-0.5 rounded border', STATUS_COLOR[asset.status])}>
                        {asset.status.charAt(0).toUpperCase() + asset.status.slice(1)}
                      </span>
                    </td>
                    <td className="px-5 py-3">
                      <span className={clsx('text-xs font-medium px-2 py-0.5 rounded border', RISK_CONFIG[asset.risk].className)}>
                        {RISK_CONFIG[asset.risk].label}
                      </span>
                    </td>
                    <td className="px-5 py-3 text-xs text-gray-500">{asset.lastSeen}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Certificate Monitor */}
      <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-800/60">
          <h2 className="text-sm font-semibold text-gray-200">Certificate Monitor</h2>
          <p className="text-xs text-gray-500 mt-0.5">Track TLS certificate health and expiry dates</p>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800/40">
                <th className="text-left text-xs font-medium text-gray-500 px-5 py-3">Domain</th>
                <th className="text-left text-xs font-medium text-gray-500 px-5 py-3">Issuer</th>
                <th className="text-left text-xs font-medium text-gray-500 px-5 py-3">Expiry Date</th>
                <th className="text-left text-xs font-medium text-gray-500 px-5 py-3">Days Remaining</th>
                <th className="text-left text-xs font-medium text-gray-500 px-5 py-3">Status</th>
              </tr>
            </thead>
            <tbody>
              {MOCK_CERTIFICATES.map((cert) => (
                <tr key={cert.id} className="border-b border-gray-800/30 hover:bg-gray-800/30 transition-colors">
                  <td className="px-5 py-3">
                    <span className="text-gray-200 font-mono text-xs">{cert.domain}</span>
                  </td>
                  <td className="px-5 py-3 text-gray-400 text-xs">{cert.issuer}</td>
                  <td className="px-5 py-3 text-gray-400 text-xs">{cert.expiryDate}</td>
                  <td className="px-5 py-3">
                    <span className={clsx(
                      'text-xs font-medium',
                      cert.daysRemaining <= 0 ? 'text-red-400' :
                      cert.daysRemaining <= 30 ? 'text-amber-400' :
                      'text-green-400'
                    )}>
                      {cert.daysRemaining <= 0 ? `${Math.abs(cert.daysRemaining)}d overdue` : `${cert.daysRemaining}d`}
                    </span>
                  </td>
                  <td className="px-5 py-3">
                    <span className={clsx('text-xs font-medium px-2 py-0.5 rounded border', CERT_STATUS_COLOR[cert.status])}>
                      {cert.status.charAt(0).toUpperCase() + cert.status.slice(1)}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
