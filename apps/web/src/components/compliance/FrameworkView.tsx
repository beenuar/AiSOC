'use client';

import useSWR, { mutate } from 'swr';
import { useState } from 'react';
import { ComplianceHeatmap } from './ComplianceHeatmap';

interface Evidence {
  id: string;
  control_id: string;
  evidence_type: string;
  title: string;
  description: string | null;
  status: string;
  collected_at: string;
}

interface Control {
  id: string;
  framework: string;
  control_id: string;
  category: string;
  title: string;
  description: string | null;
}

interface ControlWithEvidence {
  control: Control;
  evidence: Evidence[];
  latest_status: string;
}

interface FrameworkSummary {
  total: number;
  collected: number;
  review: number;
  approved: number;
  rejected: number;
  missing: number;
  pct: number;
}

interface FrameworkData {
  framework: string;
  framework_name: string;
  summary: FrameworkSummary;
  controls: ControlWithEvidence[];
}

const STATUS_BADGE: Record<string, string> = {
  approved: 'bg-green-900 text-green-300',
  collected: 'bg-blue-900 text-blue-300',
  review: 'bg-yellow-900 text-yellow-300',
  rejected: 'bg-red-900 text-red-300',
  missing: 'bg-gray-800 text-gray-400',
};

const fetcher = (url: string) =>
  fetch(url).then((r) => {
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  });

interface Props {
  framework: string;
}

type Tab = 'controls' | 'heatmap';

export function FrameworkView({ framework }: Props) {
  const dashKey = `/api/v1/compliance/${framework}`;
  const { data, error, isLoading } = useSWR<FrameworkData>(dashKey, fetcher, {
    refreshInterval: 30_000,
  });

  const [collecting, setCollecting] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<Tab>('controls');
  const [filterStatus, setFilterStatus] = useState<string>('all');

  async function handleCollect() {
    setCollecting(true);
    try {
      const res = await fetch(`/api/v1/compliance/${framework}/collect`, {
        method: 'POST',
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      await mutate(dashKey);
      await mutate(`/api/v1/compliance/${framework}/heatmap`);
    } finally {
      setCollecting(false);
    }
  }

  async function handleExport() {
    setExporting(true);
    try {
      const res = await fetch(`/api/v1/compliance/${framework}/export`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const exportData = await res.json();

      const html = buildExportHtml(exportData);
      const win = window.open('', '_blank');
      if (win) {
        win.document.write(html);
        win.document.close();
      }
    } finally {
      setExporting(false);
    }
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64 text-gray-400">
        Loading compliance data…
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="p-6 text-red-400">
        Failed to load compliance data for <code>{framework}</code>.
      </div>
    );
  }

  const { summary, controls, framework_name } = data;

  const filtered =
    filterStatus === 'all'
      ? controls
      : controls.filter((c) => c.latest_status === filterStatus);

  const pctBar = Math.min(100, summary.pct);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">{framework_name}</h1>
          <p className="text-gray-400 text-sm mt-1">
            Compliance evidence dashboard
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={handleCollect}
            disabled={collecting}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm rounded-md font-medium transition-colors"
          >
            {collecting ? 'Collecting…' : 'Auto-collect Evidence'}
          </button>
          <button
            onClick={handleExport}
            disabled={exporting}
            className="px-4 py-2 bg-gray-700 hover:bg-gray-600 disabled:opacity-50 text-white text-sm rounded-md font-medium transition-colors"
          >
            {exporting ? 'Exporting…' : 'Export PDF'}
          </button>
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {[
          { label: 'Total Controls', value: summary.total, color: 'text-white' },
          { label: 'Approved', value: summary.approved, color: 'text-green-400' },
          { label: 'Collected', value: summary.collected, color: 'text-blue-400' },
          { label: 'In Review', value: summary.review, color: 'text-yellow-400' },
          { label: 'Rejected', value: summary.rejected, color: 'text-red-400' },
          { label: 'Missing', value: summary.missing, color: 'text-gray-400' },
        ].map(({ label, value, color }) => (
          <div
            key={label}
            className="bg-gray-800 border border-gray-700 rounded-lg p-3 text-center"
          >
            <div className={`text-2xl font-bold ${color}`}>{value}</div>
            <div className="text-gray-400 text-xs mt-1">{label}</div>
          </div>
        ))}
      </div>

      {/* Progress bar */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
        <div className="flex justify-between text-sm mb-2">
          <span className="text-gray-300">Evidence collected</span>
          <span className="text-white font-semibold">{summary.pct}%</span>
        </div>
        <div className="w-full bg-gray-700 rounded-full h-3">
          <div
            className="h-3 rounded-full bg-gradient-to-r from-blue-600 to-green-500 transition-all"
            style={{ width: `${pctBar}%` }}
          />
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-gray-700">
        {(['controls', 'heatmap'] as Tab[]).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 text-sm font-medium capitalize transition-colors ${
              activeTab === tab
                ? 'border-b-2 border-blue-500 text-blue-400'
                : 'text-gray-400 hover:text-gray-200'
            }`}
          >
            {tab === 'heatmap' ? 'Category Heatmap' : 'Controls'}
          </button>
        ))}
      </div>

      {activeTab === 'heatmap' && <ComplianceHeatmap framework={framework} />}

      {activeTab === 'controls' && (
        <>
          {/* Filter */}
          <div className="flex items-center gap-3">
            <span className="text-gray-400 text-sm">Filter:</span>
            {['all', 'missing', 'collected', 'review', 'approved', 'rejected'].map(
              (s) => (
                <button
                  key={s}
                  onClick={() => setFilterStatus(s)}
                  className={`px-3 py-1 rounded-md text-xs font-medium capitalize transition-colors ${
                    filterStatus === s
                      ? 'bg-blue-600 text-white'
                      : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
                  }`}
                >
                  {s}
                </button>
              )
            )}
          </div>

          {/* Controls list */}
          <div className="space-y-2">
            {filtered.length === 0 && (
              <div className="text-gray-400 text-sm py-8 text-center">
                No controls match the current filter.
              </div>
            )}
            {filtered.map((cwev) => {
              const isExpanded = expandedId === cwev.control.id;
              return (
                <div
                  key={cwev.control.id}
                  className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden"
                >
                  <button
                    onClick={() =>
                      setExpandedId(isExpanded ? null : cwev.control.id)
                    }
                    className="w-full flex items-start gap-3 p-4 text-left hover:bg-gray-750 transition-colors"
                  >
                    <div className="flex-shrink-0 mt-0.5">
                      <span
                        className={`inline-block px-2 py-0.5 rounded text-xs font-mono font-medium ${
                          STATUS_BADGE[cwev.latest_status] ??
                          'bg-gray-700 text-gray-300'
                        }`}
                      >
                        {cwev.latest_status}
                      </span>
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-gray-500 font-mono">
                          {cwev.control.control_id}
                        </span>
                        <span className="text-xs text-gray-600">·</span>
                        <span className="text-xs text-gray-500">
                          {cwev.control.category}
                        </span>
                      </div>
                      <div className="text-white text-sm font-medium mt-0.5">
                        {cwev.control.title}
                      </div>
                    </div>
                    <div className="flex-shrink-0 text-gray-500 text-xs">
                      {cwev.evidence.length} evidence
                    </div>
                    <span className="flex-shrink-0 text-gray-500">
                      {isExpanded ? '▲' : '▼'}
                    </span>
                  </button>

                  {isExpanded && (
                    <div className="border-t border-gray-700 p-4 space-y-3">
                      {cwev.control.description && (
                        <p className="text-gray-300 text-sm">
                          {cwev.control.description}
                        </p>
                      )}
                      {cwev.evidence.length === 0 ? (
                        <p className="text-gray-500 text-sm italic">
                          No evidence collected yet.
                        </p>
                      ) : (
                        <div className="space-y-2">
                          {cwev.evidence.map((ev) => (
                            <div
                              key={ev.id}
                              className="bg-gray-900 rounded-md p-3 border border-gray-700"
                            >
                              <div className="flex items-center justify-between mb-1">
                                <span className="text-white text-xs font-medium">
                                  {ev.title}
                                </span>
                                <span
                                  className={`text-xs px-2 py-0.5 rounded ${
                                    STATUS_BADGE[ev.status] ??
                                    'bg-gray-700 text-gray-300'
                                  }`}
                                >
                                  {ev.status}
                                </span>
                              </div>
                              {ev.description && (
                                <p className="text-gray-400 text-xs">
                                  {ev.description}
                                </p>
                              )}
                              <div className="text-gray-600 text-xs mt-1">
                                {ev.evidence_type} ·{' '}
                                {new Date(ev.collected_at).toLocaleString()}
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// PDF export HTML builder
// ---------------------------------------------------------------------------
function buildExportHtml(data: {
  report_type: string;
  framework_name: string;
  generated_at: string;
  summary: FrameworkSummary;
  controls: Array<{
    control_id: string;
    category: string;
    title: string;
    description: string | null;
    evidence: Array<{
      type: string;
      title: string;
      description: string | null;
      status: string;
      collected_at: string;
    }>;
    latest_status: string;
  }>;
}): string {
  const rows = data.controls
    .map(
      (ctrl) => `
      <tr>
        <td style="padding:6px;border:1px solid #ddd;font-family:monospace;font-size:12px">${ctrl.control_id}</td>
        <td style="padding:6px;border:1px solid #ddd;font-size:12px">${ctrl.category}</td>
        <td style="padding:6px;border:1px solid #ddd;font-size:12px">${ctrl.title}</td>
        <td style="padding:6px;border:1px solid #ddd;font-size:12px">${ctrl.latest_status}</td>
        <td style="padding:6px;border:1px solid #ddd;font-size:11px">${ctrl.evidence.map((e) => `${e.title} (${e.status})`).join('; ') || '—'}</td>
      </tr>`
    )
    .join('');

  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>${data.report_type}</title>
  <style>
    body { font-family: Arial, sans-serif; padding: 24px; color: #111; }
    h1 { font-size: 20px; margin-bottom: 4px; }
    .sub { color: #666; font-size: 13px; margin-bottom: 20px; }
    .summary { display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }
    .stat { background: #f5f5f5; border: 1px solid #ddd; border-radius: 6px; padding: 10px 16px; text-align: center; }
    .stat .val { font-size: 22px; font-weight: bold; }
    .stat .lbl { font-size: 11px; color: #666; }
    table { width: 100%; border-collapse: collapse; font-size: 12px; }
    th { background: #f0f0f0; padding: 6px; border: 1px solid #ddd; text-align: left; font-size: 12px; }
    @media print { body { padding: 0; } }
  </style>
</head>
<body>
  <h1>${data.report_type}</h1>
  <div class="sub">Generated ${new Date(data.generated_at).toLocaleString()}</div>
  <div class="summary">
    ${Object.entries(data.summary)
      .map(([k, v]) => `<div class="stat"><div class="val">${v}</div><div class="lbl">${k}</div></div>`)
      .join('')}
  </div>
  <table>
    <thead><tr><th>Control ID</th><th>Category</th><th>Title</th><th>Status</th><th>Evidence</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>
</body>
</html>`;
}
