'use client';

import { useState } from 'react';
import { clsx } from 'clsx';
import toast from 'react-hot-toast';
import { EmptyState, EmptyStateIcons } from '@/components/ui/EmptyState';

const SHIFT_START = '2026-05-07T06:00:00Z';
const SHIFT_END = '2026-05-07T18:00:00Z';

interface HandoffItem {
  id: string;
  priority: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  type: 'alert' | 'case';
  status: string;
  assignedTo: string;
  notes: string;
}

const PRIORITY_CONFIG = {
  critical: { label: 'Critical', className: 'text-red-400 bg-red-500/10 border-red-500/20' },
  high: { label: 'High', className: 'text-orange-400 bg-orange-500/10 border-orange-500/20' },
  medium: { label: 'Medium', className: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20' },
  low: { label: 'Low', className: 'text-blue-400 bg-blue-500/10 border-blue-500/20' },
};

const MOCK_HANDOFF_ITEMS: HandoffItem[] = [
  { id: 'ALR-4201', priority: 'critical', title: 'Ransomware beacon detected on FIN-WS-07', type: 'alert', status: 'Investigating', assignedTo: 'alice', notes: 'Host isolated, awaiting forensic image' },
  { id: 'CASE-1042', priority: 'high', title: 'Lateral movement — domain admin credentials', type: 'case', status: 'In Progress', assignedTo: 'bob', notes: 'Credential rotation started, 3 hosts remain' },
  { id: 'ALR-4198', priority: 'high', title: 'Exfil over DNS to suspicious TLD', type: 'alert', status: 'Triaged', assignedTo: 'alice', notes: 'DNS sinkhole active, reviewing PCAP' },
  { id: 'ALR-4205', priority: 'medium', title: 'Brute-force against VPN gateway', type: 'alert', status: 'Monitoring', assignedTo: 'carol', notes: 'Rate limiting applied, source geo: RU' },
  { id: 'CASE-1039', priority: 'medium', title: 'Phishing wave targeting engineering', type: 'case', status: 'Pending Response', assignedTo: 'bob', notes: 'Awaiting HR confirmation on affected users' },
  { id: 'ALR-4210', priority: 'medium', title: 'Anomalous S3 bucket access pattern', type: 'alert', status: 'Triaged', assignedTo: 'carol', notes: 'Likely automated scanner, needs second look' },
  { id: 'ALR-4212', priority: 'low', title: 'Failed MFA attempts — service account', type: 'alert', status: 'Open', assignedTo: 'unassigned', notes: 'May be misconfigured CI pipeline' },
  { id: 'ALR-4215', priority: 'low', title: 'Certificate expiry warning — api.corp.io', type: 'alert', status: 'Open', assignedTo: 'unassigned', notes: 'Expires in 7 days, renewal ticket created' },
];

const SHIFT_SUMMARY = {
  alertsTriaged: 34,
  casesOpened: 3,
  escalations: 2,
  autoResolved: 18,
};

type PriorityFilter = HandoffItem['priority'] | 'all';

export function ShiftsView() {
  const [items] = useState(MOCK_HANDOFF_ITEMS);
  const [priorityFilter, setPriorityFilter] = useState<PriorityFilter>('all');

  const filteredItems = priorityFilter === 'all'
    ? items
    : items.filter((item) => item.priority === priorityFilter);

  const handleGenerateReport = () => {
    toast.success('Handoff report generated');
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-gray-100">Shift Handoff</h1>
          <p className="text-sm text-gray-500 mt-0.5">Review open items and hand off to the next shift</p>
        </div>
        <button
          onClick={handleGenerateReport}
          className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
          Generate Handoff Report
        </button>
      </div>

      {/* Current Shift Status */}
      <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl p-5">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-2.5 h-2.5 rounded-full bg-green-400 animate-pulse" />
          <h2 className="text-sm font-semibold text-gray-200">Active Shift</h2>
        </div>
        <div className="grid grid-cols-4 gap-4">
          <div>
            <p className="text-xs text-gray-500">Analyst On Duty</p>
            <p className="text-sm font-medium text-gray-200 mt-0.5">Alice Chen</p>
          </div>
          <div>
            <p className="text-xs text-gray-500">Shift Start</p>
            <p className="text-sm font-medium text-gray-200 mt-0.5">{new Date(SHIFT_START).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</p>
          </div>
          <div>
            <p className="text-xs text-gray-500">Shift End</p>
            <p className="text-sm font-medium text-gray-200 mt-0.5">{new Date(SHIFT_END).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</p>
          </div>
          <div>
            <p className="text-xs text-gray-500">Hours Remaining</p>
            <p className="text-sm font-medium text-amber-400 mt-0.5">4h 12m</p>
          </div>
        </div>
      </div>

      {/* Shift Summary */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Alerts Triaged', value: SHIFT_SUMMARY.alertsTriaged, color: 'text-blue-400' },
          { label: 'Cases Opened', value: SHIFT_SUMMARY.casesOpened, color: 'text-orange-400' },
          { label: 'Escalations', value: SHIFT_SUMMARY.escalations, color: 'text-red-400' },
          { label: 'Auto-Resolved', value: SHIFT_SUMMARY.autoResolved, color: 'text-green-400' },
        ].map((stat) => (
          <div key={stat.label} className="bg-gray-900/60 border border-gray-800/60 rounded-xl p-4">
            <p className={clsx('text-2xl font-bold', stat.color)}>{stat.value}</p>
            <p className="text-xs text-gray-500 mt-0.5">{stat.label}</p>
          </div>
        ))}
      </div>

      {/* Open Handoff Items */}
      <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-800/60 flex flex-wrap items-center gap-3">
          <div className="flex-1 min-w-0">
            <h2 className="text-sm font-semibold text-gray-200">Open Handoff Items</h2>
            <p className="text-xs text-gray-500 mt-0.5">{filteredItems.length} items require attention from the incoming shift</p>
          </div>
          <div className="flex gap-2">
            {(['all', 'critical', 'high', 'medium', 'low'] as const).map((f) => (
              <button
                key={f}
                onClick={() => setPriorityFilter(f)}
                className={clsx(
                  'text-xs px-3 py-1 rounded-lg border transition-colors capitalize',
                  priorityFilter === f
                    ? 'bg-blue-600/15 text-blue-300 border-blue-600/30'
                    : 'text-gray-400 border-gray-800 hover:border-gray-700',
                )}
              >
                {f === 'all' ? 'All' : PRIORITY_CONFIG[f].label}
              </button>
            ))}
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800/40">
                <th className="text-left text-xs font-medium text-gray-500 px-5 py-3">Priority</th>
                <th className="text-left text-xs font-medium text-gray-500 px-5 py-3">Alert / Case</th>
                <th className="text-left text-xs font-medium text-gray-500 px-5 py-3">Status</th>
                <th className="text-left text-xs font-medium text-gray-500 px-5 py-3">Assigned To</th>
                <th className="text-left text-xs font-medium text-gray-500 px-5 py-3">Notes</th>
              </tr>
            </thead>
            <tbody>
              {filteredItems.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-0">
                    <EmptyState
                      icon={EmptyStateIcons.search}
                      title="No items match this priority"
                      description="Try selecting a different priority level or view all open handoff items."
                      action={
                        <button
                          type="button"
                          onClick={() => setPriorityFilter('all')}
                          className="rounded-lg bg-gray-800 px-4 py-2 text-sm text-gray-200 hover:bg-gray-700 transition-colors"
                        >
                          Show all items
                        </button>
                      }
                    />
                  </td>
                </tr>
              ) : (
                filteredItems.map((item) => {
                  const prio = PRIORITY_CONFIG[item.priority];
                  return (
                    <tr key={item.id} className="border-b border-gray-800/30 hover:bg-gray-800/30 transition-colors">
                      <td className="px-5 py-3">
                        <span className={clsx('text-xs font-medium px-2 py-0.5 rounded border', prio.className)}>
                          {prio.label}
                        </span>
                      </td>
                      <td className="px-5 py-3">
                        <div>
                          <span className="text-gray-200 font-medium">{item.id}</span>
                          <span className="text-gray-500 ml-2 text-xs">({item.type})</span>
                        </div>
                        <p className="text-xs text-gray-400 mt-0.5 truncate max-w-xs">{item.title}</p>
                      </td>
                      <td className="px-5 py-3 text-gray-300">{item.status}</td>
                      <td className="px-5 py-3">
                        <span className={clsx('text-sm', item.assignedTo === 'unassigned' ? 'text-gray-600 italic' : 'text-gray-300')}>
                          {item.assignedTo}
                        </span>
                      </td>
                      <td className="px-5 py-3 text-xs text-gray-400 max-w-xs truncate">{item.notes}</td>
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
