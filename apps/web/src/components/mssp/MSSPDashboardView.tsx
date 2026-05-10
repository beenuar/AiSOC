'use client';

import { useState } from 'react';
import { clsx } from 'clsx';
import toast from 'react-hot-toast';
import { EmptyState, EmptyStateIcons } from '@/components/ui/EmptyState';

interface Tenant {
  name: string;
  activeAlerts: number;
  openCases: number;
  mttd: number;
  mttr: number;
  riskScore: number;
  slaStatus: 'compliant' | 'warning' | 'breach';
  arr: number;
  analystAllocation: number;
}

const TENANTS: Tenant[] = [
  { name: 'Acme Financial',     activeAlerts: 12, openCases: 3,  mttd: 4.2,  mttr: 28,  riskScore: 72, slaStatus: 'compliant', arr: 185000, analystAllocation: 2 },
  { name: 'GlobalRetail Corp',  activeAlerts: 47, openCases: 11, mttd: 8.7,  mttr: 65,  riskScore: 89, slaStatus: 'breach',    arr: 320000, analystAllocation: 4 },
  { name: 'MedSecure Health',   activeAlerts: 8,  openCases: 2,  mttd: 3.1,  mttr: 19,  riskScore: 45, slaStatus: 'compliant', arr: 140000, analystAllocation: 1 },
  { name: 'NovaTech Industries',activeAlerts: 23, openCases: 6,  mttd: 6.5,  mttr: 42,  riskScore: 78, slaStatus: 'warning',   arr: 260000, analystAllocation: 3 },
  { name: 'Pinnacle Energy',    activeAlerts: 5,  openCases: 1,  mttd: 2.8,  mttr: 15,  riskScore: 31, slaStatus: 'compliant', arr: 110000, analystAllocation: 1 },
  { name: 'Stratos Logistics',  activeAlerts: 31, openCases: 8,  mttd: 7.9,  mttr: 55,  riskScore: 84, slaStatus: 'warning',   arr: 275000, analystAllocation: 3 },
];

const SLA_STYLES: Record<Tenant['slaStatus'], { bg: string; text: string; label: string }> = {
  compliant: { bg: 'bg-green-500/20', text: 'text-green-400', label: 'Compliant' },
  warning:   { bg: 'bg-amber-500/20', text: 'text-amber-400', label: 'Warning' },
  breach:    { bg: 'bg-red-500/20',   text: 'text-red-400',   label: 'Breach' },
};

function kpiCards(tenants: Tenant[]) {
  const totalTenants = tenants.length;
  const totalOpenCases = tenants.reduce((s, t) => s + t.openCases, 0);
  const avgMTTD = tenants.reduce((s, t) => s + t.mttd, 0) / totalTenants;
  const avgMTTR = tenants.reduce((s, t) => s + t.mttr, 0) / totalTenants;
  const compliant = tenants.filter((t) => t.slaStatus === 'compliant').length;
  const slaCompliance = Math.round((compliant / totalTenants) * 100);
  const totalARR = tenants.reduce((s, t) => s + t.arr, 0);

  return [
    { label: 'Total Tenants',    value: totalTenants },
    { label: 'Total Open Cases', value: totalOpenCases },
    { label: 'Avg MTTD',         value: `${avgMTTD.toFixed(1)} min` },
    { label: 'Avg MTTR',         value: `${avgMTTR.toFixed(0)} min` },
    { label: 'SLA Compliance',   value: `${slaCompliance}%` },
    { label: 'Total ARR',        value: `$${(totalARR / 1000).toFixed(0)}K` },
  ];
}

type SLAFilter = 'all' | 'compliant' | 'warning' | 'breach';

export default function MSSPDashboardView() {
  const [tenants] = useState(TENANTS);
  const [slaFilter, setSlaFilter] = useState<SLAFilter>('all');
  const cards = kpiCards(tenants);

  const filteredTenants = slaFilter === 'all' ? tenants : tenants.filter((t) => t.slaStatus === slaFilter);

  return (
    <div className="space-y-8 p-6 max-w-7xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold text-white">MSSP Executive Dashboard</h1>
        <p className="text-gray-400 mt-1">Cross-tenant security operations overview</p>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {cards.map((c) => (
          <div key={c.label} className="rounded-xl border border-gray-800/60 bg-gray-900/40 p-4">
            <p className="text-xs text-gray-400 uppercase tracking-wider">{c.label}</p>
            <p className="mt-1 text-2xl font-semibold text-white">{c.value}</p>
          </div>
        ))}
      </div>

      {/* Tenant Table */}
      <div className="rounded-xl border border-gray-800/60 bg-gray-900/40 overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-800/60 flex flex-wrap items-center justify-between gap-3">
          <h2 className="text-lg font-semibold text-white">Tenant Overview</h2>
          <div className="flex items-center gap-3">
            <span className="text-xs font-medium uppercase tracking-wider text-gray-500">SLA</span>
            {(['all', 'compliant', 'warning', 'breach'] as SLAFilter[]).map((f) => (
              <button
                key={f}
                onClick={() => setSlaFilter(f)}
                className={clsx(
                  'rounded-md px-2.5 py-1 text-xs font-medium capitalize transition',
                  slaFilter === f ? 'bg-white/10 text-white' : 'text-gray-500 hover:text-gray-300',
                )}
              >
                {f}
              </button>
            ))}
            <button
              onClick={() => toast.success('Report exported for all tenants')}
              className="text-sm px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white transition-colors"
            >
              Export Report
            </button>
          </div>
        </div>
        {filteredTenants.length === 0 ? (
          <EmptyState
            icon={<EmptyStateIcons.Shield />}
            title="No tenants match this SLA filter"
            description="Try a different status filter to view tenants."
            action={
              <button
                type="button"
                onClick={() => setSlaFilter('all')}
                className="rounded-lg bg-gray-800 px-4 py-2 text-sm text-gray-200 hover:bg-gray-700 transition-colors"
              >
                Show all tenants
              </button>
            }
          />
        ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800/60 text-left text-gray-400">
                <th className="px-5 py-3 font-medium">Tenant</th>
                <th className="px-5 py-3 font-medium text-right">Active Alerts</th>
                <th className="px-5 py-3 font-medium text-right">Open Cases</th>
                <th className="px-5 py-3 font-medium text-right">MTTD (min)</th>
                <th className="px-5 py-3 font-medium text-right">MTTR (min)</th>
                <th className="px-5 py-3 font-medium text-right">Risk Score</th>
                <th className="px-5 py-3 font-medium text-right">ARR</th>
                <th className="px-5 py-3 font-medium text-right">Analysts</th>
                <th className="px-5 py-3 font-medium text-center">SLA Status</th>
              </tr>
            </thead>
            <tbody>
              {filteredTenants.map((t) => {
                const sla = SLA_STYLES[t.slaStatus];
                return (
                  <tr key={t.name} className="border-b border-gray-800/40 hover:bg-gray-800/30 transition-colors">
                    <td className="px-5 py-3 font-medium text-white">{t.name}</td>
                    <td className="px-5 py-3 text-right text-gray-300">{t.activeAlerts}</td>
                    <td className="px-5 py-3 text-right text-gray-300">{t.openCases}</td>
                    <td className="px-5 py-3 text-right text-gray-300">{t.mttd.toFixed(1)}</td>
                    <td className="px-5 py-3 text-right text-gray-300">{t.mttr}</td>
                    <td className={clsx('px-5 py-3 text-right font-medium', t.riskScore >= 80 ? 'text-red-400' : t.riskScore >= 60 ? 'text-amber-400' : 'text-green-400')}>
                      {t.riskScore}
                    </td>
                    <td className="px-5 py-3 text-right text-gray-300">${(t.arr / 1000).toFixed(0)}K</td>
                    <td className="px-5 py-3 text-right text-gray-300">{t.analystAllocation}</td>
                    <td className="px-5 py-3 text-center">
                      <span className={clsx('inline-block px-2.5 py-0.5 rounded-full text-xs font-medium', sla.bg, sla.text)}>
                        {sla.label}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        )}
      </div>
    </div>
  );
}
