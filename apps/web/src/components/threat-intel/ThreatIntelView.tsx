'use client';

import { useState } from 'react';
import {
  threatIntelApi,
  type AlertSeverity,
  type IndicatorType,
  type ThreatIndicator,
} from '@/lib/api';
import { clsx } from 'clsx';
import { format } from 'date-fns';

// ─── Mock Data ────────────────────────────────────────────────────────────────

const MOCK_INDICATORS: ThreatIndicator[] = [
  {
    id: 'ioc-001',
    type: 'ip',
    value: '185.220.101.45',
    confidence: 95,
    severity: 'critical',
    tags: ['tor-exit', 'ransomware-c2', 'known-bad'],
    sources: ['AbuseIPDB', 'VirusTotal', 'GreyNoise'],
    firstSeen: '2024-01-15T10:00:00Z',
    lastSeen: new Date(Date.now() - 3600000).toISOString(),
    description: 'Tor exit node with ransomware C2 activity',
    country: 'DE',
    malicious: true,
  },
  {
    id: 'ioc-002',
    type: 'domain',
    value: 'malicious-update-cdn.ru',
    confidence: 88,
    severity: 'high',
    tags: ['phishing', 'credential-harvest'],
    sources: ['VirusTotal'],
    firstSeen: '2024-02-01T00:00:00Z',
    lastSeen: new Date(Date.now() - 7200000).toISOString(),
    description: 'Phishing domain mimicking software update CDN',
    malicious: true,
  },
  {
    id: 'ioc-003',
    type: 'hash',
    value: 'a1b2c3d4e5f6789012345678901234567890abcd',
    confidence: 99,
    severity: 'critical',
    tags: ['malware', 'ransomware', 'lockbit'],
    sources: ['VirusTotal', 'Hybrid Analysis'],
    firstSeen: '2024-01-28T00:00:00Z',
    lastSeen: new Date(Date.now() - 1800000).toISOString(),
    description: 'LockBit 3.0 ransomware payload hash',
    malicious: true,
  },
  {
    id: 'ioc-004',
    type: 'url',
    value: 'https://cdn.legit-looking.xyz/payload.exe',
    confidence: 76,
    severity: 'high',
    tags: ['dropper', 'malware-distribution'],
    sources: ['URLScan', 'VirusTotal'],
    firstSeen: '2024-02-10T00:00:00Z',
    lastSeen: new Date(Date.now() - 14400000).toISOString(),
    description: 'Malware distribution URL hosting dropper',
    malicious: true,
  },
  {
    id: 'ioc-005',
    type: 'ip',
    value: '45.33.32.156',
    confidence: 62,
    severity: 'medium',
    tags: ['scanner', 'reconnaissance'],
    sources: ['GreyNoise', 'Shodan'],
    firstSeen: '2024-01-20T00:00:00Z',
    lastSeen: new Date(Date.now() - 86400000).toISOString(),
    description: 'Known internet scanner with anomalous activity',
    country: 'US',
    malicious: false,
  },
];

// ─── Type badges ──────────────────────────────────────────────────────────────

const TYPE_CONFIG: Record<IndicatorType, { label: string; color: string }> = {
  ip: { label: 'IP', color: 'text-purple-400 bg-purple-500/10 border-purple-500/20' },
  domain: { label: 'Domain', color: 'text-blue-400 bg-blue-500/10 border-blue-500/20' },
  hash: { label: 'Hash', color: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20' },
  url: { label: 'URL', color: 'text-orange-400 bg-orange-500/10 border-orange-500/20' },
  email: { label: 'Email', color: 'text-green-400 bg-green-500/10 border-green-500/20' },
};

const SEVERITY_CONFIG: Record<AlertSeverity, string> = {
  critical: 'text-red-400 bg-red-500/10 border-red-500/20',
  high: 'text-orange-400 bg-orange-500/10 border-orange-500/20',
  medium: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
  low: 'text-blue-400 bg-blue-500/10 border-blue-500/20',
  info: 'text-slate-400 bg-slate-500/10 border-slate-500/20',
};

// ─── Lookup Form ──────────────────────────────────────────────────────────────

function LookupForm() {
  const [query, setQuery] = useState('');
  const [result, setResult] = useState<ThreatIndicator | null>(null);
  const [isLooking, setIsLooking] = useState(false);
  const [notFound, setNotFound] = useState(false);

  const handleLookup = async () => {
    if (!query.trim()) return;
    setIsLooking(true);
    setNotFound(false);
    setResult(null);
    try {
      const r = await threatIntelApi.lookup(query.trim());
      setResult(r);
    } catch {
      setNotFound(true);
    } finally {
      setIsLooking(false);
    }
  };

  return (
    <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl p-5">
      <h3 className="text-sm font-medium text-gray-300 mb-3">IOC Lookup</h3>
      <div className="flex gap-2">
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleLookup()}
          placeholder="Enter IP, domain, hash, or URL…"
          className="flex-1 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-300 placeholder-gray-600 px-3 py-2 focus:outline-none focus:border-blue-500/50"
        />
        <button
          onClick={handleLookup}
          disabled={isLooking || !query.trim()}
          className="bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-sm px-4 py-2 rounded-lg transition-colors"
        >
          {isLooking ? 'Looking up…' : 'Lookup'}
        </button>
      </div>

      {notFound && (
        <div className="mt-3 flex items-center gap-2 text-sm text-green-400 bg-green-500/10 border border-green-500/20 rounded-lg px-3 py-2">
          <span className="text-[10px] font-semibold uppercase tracking-wider">clean</span>
          <span>No threat indicators found for this IOC</span>
        </div>
      )}

      {result && (
        <div className="mt-3 bg-red-500/5 border border-red-500/20 rounded-lg p-3 space-y-2">
          <div className="flex items-center gap-2">
            <span className="text-red-400 font-medium text-sm">Malicious indicator</span>
            <span className="text-xs text-gray-500">Confidence: {result.confidence}%</span>
          </div>
          {result.description ? (
            <p className="text-xs text-gray-400">{result.description}</p>
          ) : null}
          <div className="flex flex-wrap gap-1">
            {(result.tags ?? []).map((t) => (
              <span key={t} className="text-xs bg-gray-800 text-gray-400 px-1.5 py-0.5 rounded">{t}</span>
            ))}
          </div>
          <div className="text-xs text-gray-500">
            Sources: {result.sources.join(', ')}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── IOC Row ──────────────────────────────────────────────────────────────────

function IOCRow({ ioc }: { ioc: ThreatIndicator }) {
  const typeCfg = TYPE_CONFIG[ioc.type] || TYPE_CONFIG.ip;

  return (
    <div className="flex items-center gap-4 py-3 border-b border-gray-800/60 last:border-0 hover:bg-gray-800/20 px-4 -mx-4 transition-colors rounded-lg">
      <span className={clsx('text-xs font-medium px-2 py-0.5 rounded border shrink-0', typeCfg.color)}>
        {typeCfg.label}
      </span>

      <div className="flex-1 min-w-0">
        <p className="text-sm font-mono text-gray-300 truncate">{ioc.value}</p>
        <p className="text-xs text-gray-600 mt-0.5 truncate">{ioc.description ?? ''}</p>
      </div>

      <span className={clsx('text-xs font-medium px-2 py-0.5 rounded border shrink-0', SEVERITY_CONFIG[ioc.severity])}>
        {ioc.severity}
      </span>

      <div className="text-right shrink-0">
        <div className="flex items-center gap-1 justify-end">
          <span className="text-xs text-gray-500">Confidence:</span>
          <span className={clsx(
            'text-xs font-medium',
            ioc.confidence >= 80 ? 'text-red-400' : ioc.confidence >= 60 ? 'text-yellow-400' : 'text-gray-400'
          )}>
            {ioc.confidence}%
          </span>
        </div>
        <p className="text-xs text-gray-600 mt-0.5">
          {ioc.lastSeen || ioc.firstSeen
            ? format(new Date(ioc.lastSeen ?? ioc.firstSeen ?? 0), 'MMM dd HH:mm')
            : '—'}
        </p>
      </div>

      <div className="flex flex-wrap gap-1 max-w-32 shrink-0">
        {ioc.sources.slice(0, 2).map((src) => (
          <span key={src} className="text-xs bg-gray-800 text-gray-500 px-1.5 py-0.5 rounded">
            {src}
          </span>
        ))}
      </div>
    </div>
  );
}

// ─── Main View ────────────────────────────────────────────────────────────────

export function ThreatIntelView() {
  const [typeFilter, setTypeFilter] = useState<ThreatIndicator['type'] | 'all'>('all');
  const [search, setSearch] = useState('');

  const indicators = MOCK_INDICATORS.filter((ioc) => {
    if (typeFilter !== 'all' && ioc.type !== typeFilter) return false;
    if (
      search &&
      !ioc.value.toLowerCase().includes(search.toLowerCase()) &&
      !(ioc.description ?? '').toLowerCase().includes(search.toLowerCase())
    ) {
      return false;
    }
    return true;
  });

  const typeCounts = {
    all: MOCK_INDICATORS.length,
    ip: MOCK_INDICATORS.filter(i => i.type === 'ip').length,
    domain: MOCK_INDICATORS.filter(i => i.type === 'domain').length,
    hash: MOCK_INDICATORS.filter(i => i.type === 'hash').length,
    url: MOCK_INDICATORS.filter(i => i.type === 'url').length,
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div>
        <h1 className="text-xl font-semibold text-gray-100">Threat Intelligence</h1>
        <p className="text-sm text-gray-500 mt-0.5">
          Indicators of compromise aggregated from multiple intel feeds
        </p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Total IOCs', value: MOCK_INDICATORS.length, color: 'text-blue-400' },
          { label: 'Malicious', value: MOCK_INDICATORS.filter(i => i.malicious).length, color: 'text-red-400' },
          { label: 'High Confidence', value: MOCK_INDICATORS.filter(i => i.confidence >= 80).length, color: 'text-orange-400' },
          { label: 'Added Today', value: 3, color: 'text-green-400' },
        ].map((stat) => (
          <div key={stat.label} className="bg-gray-900/60 border border-gray-800/60 rounded-xl p-4">
            <p className={clsx('text-2xl font-bold mb-1', stat.color)}>{stat.value}</p>
            <p className="text-xs text-gray-500">{stat.label}</p>
          </div>
        ))}
      </div>

      {/* Lookup */}
      <LookupForm />

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
            placeholder="Search indicators…"
            className="w-full pl-9 pr-4 py-2 bg-gray-900/60 border border-gray-800 rounded-lg text-sm text-gray-300 placeholder-gray-600 focus:outline-none focus:border-blue-500/50"
          />
        </div>

        <div className="flex gap-1">
          {(['all', 'ip', 'domain', 'hash', 'url'] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTypeFilter(t)}
              className={clsx(
                'text-xs px-3 py-1.5 rounded-lg transition-colors',
                typeFilter === t
                  ? 'bg-blue-600 text-white'
                  : 'text-gray-400 bg-gray-800/60 hover:bg-gray-800'
              )}
            >
              {t === 'all' ? 'All' : t.toUpperCase()} ({typeCounts[t] ?? 0})
            </button>
          ))}
        </div>
      </div>

      {/* IOC List */}
      <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-medium text-gray-300">Indicators of Compromise</h3>
          <span className="text-xs text-gray-500">{indicators.length} indicators</span>
        </div>
        {indicators.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-32 text-gray-600">
            <p className="text-sm">No indicators found</p>
          </div>
        ) : (
          <div>
            {indicators.map((ioc) => <IOCRow key={ioc.id} ioc={ioc} />)}
          </div>
        )}
      </div>
    </div>
  );
}
