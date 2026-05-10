'use client';

import { useState } from 'react';
import { clsx } from 'clsx';
import toast from 'react-hot-toast';
import { EmptyState, EmptyStateIcons } from '@/components/ui/EmptyState';

interface AlertRule {
  name: string;
  alertsFired: number;
  tpCount: number;
  fpCount: number;
  autoTune: boolean;
  suggestedAction: string;
}

const INITIAL_RULES: AlertRule[] = [
  { name: 'Suspicious PowerShell Execution',    alertsFired: 342,  tpCount: 298, fpCount: 44,  autoTune: true,  suggestedAction: 'Exclude signed scripts from known admin hosts' },
  { name: 'Failed Login Brute Force',           alertsFired: 1205, tpCount: 180, fpCount: 1025, autoTune: false, suggestedAction: 'Raise threshold from 5 to 15 failed attempts' },
  { name: 'Unusual Outbound DNS Volume',        alertsFired: 87,   tpCount: 72,  fpCount: 15,  autoTune: true,  suggestedAction: 'Whitelist internal DNS forwarders' },
  { name: 'Lateral Movement via SMB',           alertsFired: 156,  tpCount: 134, fpCount: 22,  autoTune: true,  suggestedAction: 'Exclude domain controller-to-DC traffic' },
  { name: 'New Service Installation',           alertsFired: 523,  tpCount: 45,  fpCount: 478, autoTune: false, suggestedAction: 'Filter SCCM and Intune deployment agents' },
  { name: 'Anomalous Cloud API Call',           alertsFired: 211,  tpCount: 189, fpCount: 22,  autoTune: true,  suggestedAction: 'Baseline CI/CD service accounts' },
  { name: 'Registry Run Key Modification',      alertsFired: 94,   tpCount: 81,  fpCount: 13,  autoTune: false, suggestedAction: 'Add GPO-deployed software to allowlist' },
  { name: 'Potential Data Exfiltration',         alertsFired: 38,   tpCount: 35,  fpCount: 3,   autoTune: true,  suggestedAction: 'No changes recommended — low FP rate' },
  { name: 'Cleartext Credential in Logs',       alertsFired: 678,  tpCount: 102, fpCount: 576, autoTune: false, suggestedAction: 'Suppress alerts from log-rotation jobs' },
  { name: 'TLS Certificate Anomaly',            alertsFired: 145,  tpCount: 120, fpCount: 25,  autoTune: true,  suggestedAction: 'Exclude internal CA-issued certs' },
];

export default function NoiseTuningView() {
  const [rules, setRules] = useState(INITIAL_RULES);
  const [search, setSearch] = useState('');

  const filteredRules = search.trim()
    ? rules.filter((r) => r.name.toLowerCase().includes(search.toLowerCase()))
    : rules;

  const totalVerdicts = rules.reduce((s, r) => s + r.alertsFired, 0);
  const totalFP = rules.reduce((s, r) => s + r.fpCount, 0);
  const fpRate = ((totalFP / totalVerdicts) * 100).toFixed(1);
  const autoTunedCount = rules.filter((r) => r.autoTune).length;
  const noiseReduction = 34;

  const summaryCards = [
    { label: 'Total Verdicts This Month', value: totalVerdicts.toLocaleString() },
    { label: 'FP Rate',                   value: `${fpRate}%` },
    { label: 'Auto-Tuned Rules',          value: autoTunedCount },
    { label: 'Noise Reduction',           value: `${noiseReduction}%` },
  ];

  function toggleAutoTune(index: number) {
    setRules((prev) =>
      prev.map((r, i) => (i === index ? { ...r, autoTune: !r.autoTune } : r)),
    );
  }

  function ruleFpRate(r: AlertRule) {
    return r.alertsFired > 0 ? (r.fpCount / r.alertsFired) * 100 : 0;
  }

  return (
    <div className="space-y-8 p-6 max-w-7xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold text-white">Alert Noise Tuning</h1>
        <p className="text-gray-400 mt-1">Reduce false positives and optimize detection signal-to-noise ratio</p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {summaryCards.map((c) => (
          <div key={c.label} className="rounded-xl border border-gray-800/60 bg-gray-900/40 p-4">
            <p className="text-xs text-gray-400 uppercase tracking-wider">{c.label}</p>
            <p className="mt-1 text-2xl font-semibold text-white">{c.value}</p>
          </div>
        ))}
      </div>

      {/* Noise Trend Placeholder */}
      <div className="rounded-xl border border-gray-800/60 bg-gray-900/40 p-6">
        <h2 className="text-lg font-semibold text-white mb-4">Noise Trend</h2>
        <div className="h-48 rounded-lg bg-gray-800/50 border border-gray-700/50 flex items-center justify-center">
          <div className="text-center">
            <div className="flex items-center justify-center gap-1 mb-2">
              {[40, 55, 35, 60, 45, 30, 25, 38, 20, 28, 18, 22].map((h, i) => (
                <div
                  key={i}
                  className="w-6 rounded-t bg-gradient-to-t from-blue-600/80 to-blue-400/60"
                  style={{ height: `${h * 1.5}px` }}
                />
              ))}
            </div>
            <p className="text-sm text-gray-500">Monthly noise trend — FP volume declining</p>
          </div>
        </div>
      </div>

      {/* Rules Table */}
      <div className="rounded-xl border border-gray-800/60 bg-gray-900/40 overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-800/60 flex flex-wrap items-center gap-3">
          <h2 className="text-lg font-semibold text-white flex-1 min-w-0">Alert Rules</h2>
          <input
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search rules…"
            className="w-56 rounded-lg border border-gray-700 bg-gray-800/60 px-3 py-1.5 text-sm text-gray-200 placeholder-gray-500 focus:border-blue-500 focus:outline-none"
          />
          <button
            onClick={() => toast.success('Tuning recommendations applied to 3 rules')}
            className="text-sm px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white transition-colors"
          >
            Apply Tuning
          </button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800/60 text-left text-gray-400">
                <th className="px-5 py-3 font-medium">Rule Name</th>
                <th className="px-5 py-3 font-medium text-right">Alerts Fired</th>
                <th className="px-5 py-3 font-medium text-right">TP</th>
                <th className="px-5 py-3 font-medium text-right">FP</th>
                <th className="px-5 py-3 font-medium text-right">FP Rate</th>
                <th className="px-5 py-3 font-medium text-center">Auto-Tune</th>
                <th className="px-5 py-3 font-medium">Suggested Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredRules.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-0">
                    <EmptyState
                      icon={<EmptyStateIcons.Search />}
                      title="No rules match your search"
                      description="Try a different rule name or clear the search field."
                      action={
                        <button
                          type="button"
                          onClick={() => setSearch('')}
                          className="rounded-lg bg-gray-800 px-4 py-2 text-sm text-gray-200 hover:bg-gray-700 transition-colors"
                        >
                          Clear search
                        </button>
                      }
                    />
                  </td>
                </tr>
              ) : (
                filteredRules.map((r, i) => {
                  const fp = ruleFpRate(r);
                  const originalIndex = rules.indexOf(r);
                  return (
                    <tr key={r.name} className="border-b border-gray-800/40 hover:bg-gray-800/30 transition-colors">
                      <td className="px-5 py-3 font-medium text-white">{r.name}</td>
                      <td className="px-5 py-3 text-right text-gray-300">{r.alertsFired.toLocaleString()}</td>
                      <td className="px-5 py-3 text-right text-gray-300">{r.tpCount}</td>
                      <td className="px-5 py-3 text-right text-gray-300">{r.fpCount}</td>
                      <td
                        className={clsx(
                          'px-5 py-3 text-right font-medium',
                          fp >= 70 ? 'text-red-400' : fp >= 30 ? 'text-amber-400' : 'text-green-400',
                        )}
                      >
                        {fp.toFixed(1)}%
                      </td>
                      <td className="px-5 py-3 text-center">
                        <button
                          onClick={() => toggleAutoTune(originalIndex)}
                          className={clsx(
                            'relative inline-flex h-5 w-9 items-center rounded-full transition-colors',
                            r.autoTune ? 'bg-blue-600' : 'bg-gray-600',
                          )}
                        >
                          <span
                            className={clsx(
                              'inline-block h-3.5 w-3.5 rounded-full bg-white transition-transform',
                              r.autoTune ? 'translate-x-4.5' : 'translate-x-0.5',
                            )}
                          />
                        </button>
                      </td>
                      <td className="px-5 py-3 text-gray-400 max-w-xs truncate">{r.suggestedAction}</td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
