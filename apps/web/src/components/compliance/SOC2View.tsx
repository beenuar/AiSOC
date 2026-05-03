'use client';

import { useState } from 'react';
import useSWR from 'swr';

interface ControlOut {
  id: string;
  framework: string;
  control_id: string;
  category: string;
  title: string;
  description: string | null;
}

interface EvidenceOut {
  id: string;
  control_id: string;
  evidence_type: string;
  title: string;
  description: string | null;
  status: string;
  collected_at: string;
}

interface ControlWithEvidence {
  control: ControlOut;
  evidence: EvidenceOut[];
  latest_status: string;
}

interface SOC2Summary {
  total: number;
  collected: number;
  review: number;
  approved: number;
  rejected: number;
  pct: number;
}

interface SOC2Response {
  summary: SOC2Summary;
  controls: ControlWithEvidence[];
}

const fetcher = (url: string) =>
  fetch(url, { credentials: 'include' }).then((r) => {
    if (!r.ok) throw new Error('Failed to fetch');
    return r.json();
  });

const STATUS_STYLES: Record<string, string> = {
  collected: 'bg-green-100 text-green-800 border-green-200',
  approved: 'bg-emerald-100 text-emerald-800 border-emerald-200',
  review: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  rejected: 'bg-red-100 text-red-800 border-red-200',
  missing: 'bg-gray-100 text-gray-600 border-gray-200',
};

const STATUS_DOT: Record<string, string> = {
  collected: 'bg-green-400',
  approved: 'bg-emerald-500',
  review: 'bg-yellow-400',
  rejected: 'bg-red-400',
  missing: 'bg-gray-300',
};

function StatusBadge({ status }: { status: string }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium border ${STATUS_STYLES[status] ?? STATUS_STYLES.missing}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${STATUS_DOT[status] ?? STATUS_DOT.missing}`} />
      {status}
    </span>
  );
}

function SummaryCard({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="bg-white rounded-lg border border-gray-200 p-4">
      <p className="text-sm text-gray-500">{label}</p>
      <p className={`text-3xl font-bold mt-1 ${color}`}>{value}</p>
    </div>
  );
}

export function SOC2View() {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [collecting, setCollecting] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [categoryFilter, setCategoryFilter] = useState('');

  const { data, error, isLoading, mutate } = useSWR<SOC2Response>(
    '/api/v1/compliance/soc2',
    fetcher,
    { revalidateOnFocus: false }
  );

  const handleCollect = async () => {
    setCollecting(true);
    try {
      await fetch('/api/v1/compliance/soc2/collect', {
        method: 'POST',
        credentials: 'include',
      });
      await mutate();
    } finally {
      setCollecting(false);
    }
  };

  const handleExport = async () => {
    setExporting(true);
    try {
      const res = await fetch('/api/v1/compliance/soc2/export', { credentials: 'include' });
      const json = await res.json();
      // Generate a printable HTML page for PDF export
      const html = buildPDFHtml(json);
      const win = window.open('', '_blank');
      if (win) {
        win.document.write(html);
        win.document.close();
        win.focus();
        setTimeout(() => win.print(), 500);
      }
    } finally {
      setExporting(false);
    }
  };

  const categories = data
    ? [...new Set(data.controls.map((c) => c.control.category))]
    : [];

  const filtered = data?.controls.filter(
    (c) => !categoryFilter || c.control.category === categoryFilter
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">SOC 2 Evidence Dashboard</h1>
          <p className="text-sm text-gray-500 mt-1">
            Trust Services Criteria — auto-collected from platform activity
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={handleCollect}
            disabled={collecting}
            className="px-4 py-2 text-sm font-medium bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:opacity-50 transition-colors"
          >
            {collecting ? 'Collecting…' : '↻ Collect Evidence'}
          </button>
          <button
            onClick={handleExport}
            disabled={exporting || !data}
            className="px-4 py-2 text-sm font-medium bg-white border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 disabled:opacity-50 transition-colors"
          >
            {exporting ? 'Generating…' : '⬇ Export PDF'}
          </button>
        </div>
      </div>

      {/* Summary cards */}
      {data && (
        <>
          {/* Readiness gauge */}
          <div className="bg-white rounded-xl border border-gray-200 p-6">
            <div className="flex items-center justify-between mb-3">
              <span className="font-semibold text-gray-900">Overall Readiness</span>
              <span className="text-2xl font-bold text-indigo-600">{data.summary.pct}%</span>
            </div>
            <div className="w-full bg-gray-100 rounded-full h-3">
              <div
                className="h-3 rounded-full bg-gradient-to-r from-indigo-500 to-green-500 transition-all duration-700"
                style={{ width: `${data.summary.pct}%` }}
              />
            </div>
            <p className="text-xs text-gray-400 mt-2">
              {data.summary.collected + data.summary.approved} of {data.summary.total} controls have evidence
            </p>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <SummaryCard label="Total Controls" value={data.summary.total} color="text-gray-900" />
            <SummaryCard label="Collected" value={data.summary.collected} color="text-green-600" />
            <SummaryCard label="Needs Review" value={data.summary.review} color="text-yellow-600" />
            <SummaryCard label="Approved" value={data.summary.approved} color="text-emerald-600" />
          </div>
        </>
      )}

      {/* Category filter */}
      {categories.length > 0 && (
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => setCategoryFilter('')}
            className={`px-3 py-1.5 text-xs rounded-full border transition-colors ${
              !categoryFilter
                ? 'bg-indigo-50 border-indigo-300 text-indigo-700'
                : 'bg-white border-gray-200 text-gray-600 hover:border-gray-300'
            }`}
          >
            All
          </button>
          {categories.map((cat) => (
            <button
              key={cat}
              onClick={() => setCategoryFilter(cat === categoryFilter ? '' : cat)}
              className={`px-3 py-1.5 text-xs rounded-full border transition-colors ${
                categoryFilter === cat
                  ? 'bg-indigo-50 border-indigo-300 text-indigo-700'
                  : 'bg-white border-gray-200 text-gray-600 hover:border-gray-300'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>
      )}

      {/* Loading / error states */}
      {isLoading && (
        <div className="bg-white rounded-xl border border-gray-200 p-12 text-center text-gray-400 text-sm">
          Loading compliance data…
        </div>
      )}
      {error && (
        <div className="bg-red-50 rounded-xl border border-red-200 p-6 text-center text-red-600 text-sm">
          Failed to load SOC 2 data. Ensure evidence has been collected.
        </div>
      )}

      {/* Controls list */}
      {filtered && filtered.length > 0 && (
        <div className="space-y-2">
          {filtered.map((item) => (
            <div
              key={item.control.id}
              className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden"
            >
              <button
                className="w-full text-left px-5 py-4 flex items-start gap-4 hover:bg-gray-50 transition-colors"
                onClick={() =>
                  setExpandedId(expandedId === item.control.id ? null : item.control.id)
                }
              >
                <div className="flex-shrink-0 w-16 text-center">
                  <span className="text-xs font-mono font-bold text-indigo-600">
                    {item.control.control_id}
                  </span>
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-semibold text-gray-900">{item.control.title}</p>
                  <p className="text-xs text-gray-400 mt-0.5">{item.control.category}</p>
                </div>
                <StatusBadge status={item.latest_status} />
                <span className="text-gray-400 text-xs ml-2">
                  {expandedId === item.control.id ? '▲' : '▼'}
                </span>
              </button>

              {expandedId === item.control.id && (
                <div className="px-5 pb-5 border-t border-gray-100 bg-gray-50">
                  {item.control.description && (
                    <p className="text-sm text-gray-600 mt-3 mb-4">{item.control.description}</p>
                  )}
                  <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">
                    Evidence ({item.evidence.length})
                  </h4>
                  {item.evidence.length === 0 ? (
                    <p className="text-sm text-gray-400 italic">
                      No evidence collected yet. Click "Collect Evidence" to auto-gather.
                    </p>
                  ) : (
                    <div className="space-y-2">
                      {item.evidence.map((ev) => (
                        <div
                          key={ev.id}
                          className="bg-white rounded-lg border border-gray-200 p-3 flex items-start gap-3"
                        >
                          <div className="flex-1">
                            <p className="text-sm font-medium text-gray-800">{ev.title}</p>
                            {ev.description && (
                              <p className="text-xs text-gray-500 mt-0.5">{ev.description}</p>
                            )}
                            <p className="text-xs text-gray-400 mt-1">
                              {new Date(ev.collected_at).toLocaleString()} · {ev.evidence_type}
                            </p>
                          </div>
                          <StatusBadge status={ev.status} />
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {!isLoading && !error && data && data.controls.length === 0 && (
        <div className="bg-white rounded-xl border border-gray-200 p-12 text-center">
          <p className="text-gray-500 text-sm mb-4">No SOC 2 controls found in the database.</p>
          <button
            onClick={handleCollect}
            className="px-4 py-2 text-sm font-medium bg-indigo-600 text-white rounded-lg hover:bg-indigo-700"
          >
            Collect Evidence Now
          </button>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// PDF export helper — generates a printable HTML document
// ---------------------------------------------------------------------------

function buildPDFHtml(data: any): string {
  const controlRows = (data.controls ?? [])
    .map(
      (c: any) => `
    <tr>
      <td class="ctrl-id">${c.control_id}</td>
      <td>${c.title}</td>
      <td>${c.category}</td>
      <td class="status-${c.latest_status}">${c.latest_status}</td>
      <td>${(c.evidence ?? []).map((e: any) => e.title).join('<br/>')}</td>
    </tr>`
    )
    .join('');

  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>SOC 2 Evidence Report</title>
  <style>
    body { font-family: Arial, sans-serif; font-size: 12px; color: #111; margin: 2cm; }
    h1 { font-size: 20px; margin-bottom: 4px; }
    .meta { color: #555; font-size: 11px; margin-bottom: 24px; }
    .summary { display: flex; gap: 24px; margin-bottom: 24px; }
    .summary-item { border: 1px solid #ddd; border-radius: 8px; padding: 12px 20px; }
    .summary-item .val { font-size: 28px; font-weight: bold; }
    .summary-item .lbl { font-size: 11px; color: #666; }
    table { width: 100%; border-collapse: collapse; }
    th { background: #f0f0f0; text-align: left; padding: 8px; font-size: 11px; }
    td { padding: 7px 8px; border-bottom: 1px solid #eee; vertical-align: top; font-size: 11px; }
    .ctrl-id { font-family: monospace; font-weight: bold; color: #4f46e5; }
    .status-collected { color: #16a34a; font-weight: 600; }
    .status-approved { color: #059669; font-weight: 600; }
    .status-review { color: #d97706; font-weight: 600; }
    .status-rejected { color: #dc2626; font-weight: 600; }
    .status-missing { color: #9ca3af; }
    @media print { body { margin: 1cm; } }
  </style>
</head>
<body>
  <h1>SOC 2 Type I Evidence Report</h1>
  <p class="meta">Generated: ${data.generated_at} · Tenant: ${data.tenant_id}</p>
  <div class="summary">
    <div class="summary-item"><div class="val">${data.summary?.pct ?? 0}%</div><div class="lbl">Readiness</div></div>
    <div class="summary-item"><div class="val">${data.summary?.total ?? 0}</div><div class="lbl">Total Controls</div></div>
    <div class="summary-item"><div class="val">${data.summary?.collected ?? 0}</div><div class="lbl">Collected</div></div>
    <div class="summary-item"><div class="val">${data.summary?.review ?? 0}</div><div class="lbl">Needs Review</div></div>
    <div class="summary-item"><div class="val">${data.summary?.approved ?? 0}</div><div class="lbl">Approved</div></div>
  </div>
  <table>
    <thead>
      <tr>
        <th>Control</th>
        <th>Title</th>
        <th>Category</th>
        <th>Status</th>
        <th>Evidence</th>
      </tr>
    </thead>
    <tbody>${controlRows}</tbody>
  </table>
</body>
</html>`;
}
