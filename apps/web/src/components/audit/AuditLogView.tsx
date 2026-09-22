'use client';

import { useState, useCallback } from 'react';
import useSWR from 'swr';
import toast from 'react-hot-toast';
import { EmptyState, EmptyStateIcons } from '@/components/ui/EmptyState';
import { ErrorState } from '@/components/ui/ErrorState';
import { auditApi, ApiError, type AuditExportFilters } from '@/lib/api';
import { demoFallback } from '@/lib/demoFallback';

interface AuditEvent {
  id: string;
  tenant_id: string;
  actor_id: string | null;
  actor_email: string | null;
  actor_ip: string | null;
  action: string;
  resource: string | null;
  resource_id: string | null;
  changes: Record<string, unknown> | null;
  created_at: string;
}

interface AuditListResponse {
  items: AuditEvent[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

const fetcher = async (url: string) => {
  const r = await fetch(url, { credentials: 'include' });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const text = await r.text();
  try { return JSON.parse(text); } catch { throw new Error('Invalid JSON'); }
};

const MOCK_AUDIT: AuditListResponse = {
  items: [
    { id: '1', tenant_id: 't1', actor_id: 'u1', actor_email: 'admin@acme.io', actor_ip: '10.0.1.12', action: 'cases:create', resource: 'case', resource_id: 'c-0001abcd', changes: { title: 'Suspicious lateral movement' }, created_at: new Date(Date.now() - 300_000).toISOString() },
    { id: '2', tenant_id: 't1', actor_id: 'u2', actor_email: 'analyst@acme.io', actor_ip: '10.0.1.15', action: 'alerts:update', resource: 'alert', resource_id: 'a-0042efgh', changes: { status: ['open', 'acknowledged'] }, created_at: new Date(Date.now() - 900_000).toISOString() },
    { id: '3', tenant_id: 't1', actor_id: null, actor_email: null, actor_ip: null, action: 'playbooks:execute', resource: 'playbook', resource_id: 'pb-isolate', changes: { trigger: 'auto' }, created_at: new Date(Date.now() - 1_800_000).toISOString() },
    { id: '4', tenant_id: 't1', actor_id: 'u1', actor_email: 'admin@acme.io', actor_ip: '10.0.1.12', action: 'detections:create', resource: 'detection_rule', resource_id: 'dr-00091234', changes: { name: 'Brute-force SSH' }, created_at: new Date(Date.now() - 3_600_000).toISOString() },
    { id: '5', tenant_id: 't1', actor_id: 'u3', actor_email: 'soc-lead@acme.io', actor_ip: '10.0.2.5', action: 'connectors:update', resource: 'connector', resource_id: 'cn-sentinel', changes: { enabled: true }, created_at: new Date(Date.now() - 7_200_000).toISOString() },
    { id: '6', tenant_id: 't1', actor_id: 'u1', actor_email: 'admin@acme.io', actor_ip: '10.0.1.12', action: 'roles:create', resource: 'role', resource_id: 'role-jr-analyst', changes: { name: 'Junior Analyst' }, created_at: new Date(Date.now() - 10_800_000).toISOString() },
    { id: '7', tenant_id: 't1', actor_id: 'u2', actor_email: 'analyst@acme.io', actor_ip: '10.0.1.15', action: 'cases:update', resource: 'case', resource_id: 'c-0001abcd', changes: { status: ['open', 'in_progress'] }, created_at: new Date(Date.now() - 14_400_000).toISOString() },
    { id: '8', tenant_id: 't1', actor_id: 'u1', actor_email: 'admin@acme.io', actor_ip: '10.0.1.12', action: 'auth:api_key_create', resource: 'api_key', resource_id: 'ak-00abc', changes: null, created_at: new Date(Date.now() - 21_600_000).toISOString() },
    { id: '9', tenant_id: 't1', actor_id: null, actor_email: null, actor_ip: null, action: 'alerts:create', resource: 'alert', resource_id: 'a-0099xyz', changes: { severity: 'critical' }, created_at: new Date(Date.now() - 28_800_000).toISOString() },
    { id: '10', tenant_id: 't1', actor_id: 'u3', actor_email: 'soc-lead@acme.io', actor_ip: '10.0.2.5', action: 'cases:delete', resource: 'case', resource_id: 'c-test-0001', changes: null, created_at: new Date(Date.now() - 36_000_000).toISOString() },
  ],
  total: 10,
  page: 1,
  page_size: 50,
  total_pages: 1,
};

const ACTION_COLORS: Record<string, string> = {
  create: 'bg-green-500/20 text-green-300',
  update: 'bg-blue-500/20 text-blue-300',
  delete: 'bg-red-500/20 text-red-300',
  execute: 'bg-yellow-500/20 text-yellow-300',
};

function actionBadge(action: string): string {
  for (const [verb, cls] of Object.entries(ACTION_COLORS)) {
    if (action.includes(verb)) return cls;
  }
  return 'bg-gray-700 text-gray-300';
}

export function AuditLogView() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [actionFilter, setActionFilter] = useState('');
  const [resourceFilter, setResourceFilter] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  // WS-H3 — export-bundle UX state. We model the two formats as a single
  // exclusive lock so the analyst can't double-fire CSV + HTML and end up
  // with two browser save dialogs racing each other.
  const [exporting, setExporting] = useState<'csv' | 'html' | null>(null);

  const params = new URLSearchParams({ page: String(page), page_size: '50' });
  if (search) params.set('search', search);
  if (actionFilter) params.set('action', actionFilter);
  if (resourceFilter) params.set('resource', resourceFilter);

  const { data: raw, error, isLoading } = useSWR<AuditListResponse>(
    `/api/v1/audit?${params}`,
    fetcher,
    {
      refreshInterval: 30_000,
      fallbackData: demoFallback(MOCK_AUDIT),
      shouldRetryOnError: false,
      errorRetryCount: 0,
      revalidateOnFocus: false,
    }
  );
  const isValid = raw && Array.isArray(raw.items) && typeof raw.total === 'number';
  // An unexpected response shape used to fall through to fabricated entries
  // regardless of demo mode, so a malformed payload produced a plausible
  // audit trail. An audit log is the one surface that must never show events
  // that did not happen.
  const emptyAudit: AuditListResponse = { items: [], total: 0, page: 1, page_size: 0, total_pages: 0 };
  const data = isValid ? raw : (demoFallback(MOCK_AUDIT) ?? emptyAudit);

  const handleSearch = useCallback((e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
  }, []);

  // Build the filter payload once so CSV and HTML stay in lock-step with the
  // table. We deliberately send only the filter knobs the export endpoint
  // understands — page/page_size are list-view concerns, not export ones.
  const buildExportFilters = useCallback((): AuditExportFilters => {
    const filters: AuditExportFilters = {};
    if (search) filters.search = search;
    if (actionFilter) filters.action = actionFilter;
    if (resourceFilter) filters.resource = resourceFilter;
    return filters;
  }, [search, actionFilter, resourceFilter]);

  /**
   * Trigger a CSV download of the (filtered) audit trail. We go through fetch
   * (rather than a plain anchor href) so we can attach the bearer token,
   * surface a toast on auth failure, and disable the button while the
   * server is streaming.
   */
  const handleExportCsv = useCallback(async () => {
    if (exporting) return;
    setExporting('csv');
    try {
      const { body, filename } = await auditApi.exportCsv(buildExportFilters());
      const blob = new Blob([body], { type: 'text/csv;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      toast.success(`Exported ${filename}`);
    } catch (e) {
      const msg = e instanceof ApiError
        ? `Couldn't export audit log (HTTP ${e.status}). ${e.status === 403 ? 'Your role lacks audit_log:read.' : 'Try again.'}`
        : "Couldn't export audit log. Try again.";
      toast.error(msg);
    } finally {
      setExporting(null);
    }
  }, [buildExportFilters, exporting]);

  /**
   * Open the print-ready HTML bundle in a new tab. The browser's native
   * "Save as PDF" produces the compliance binder — same pattern as the
   * weekly digest report (WS-G2). No server-side weasyprint required.
   */
  const handleExportHtml = useCallback(async () => {
    if (exporting) return;
    setExporting('html');
    try {
      const { html } = await auditApi.exportHtml(buildExportFilters());
      // Pop into a new tab via Blob URL — survives strict-CSP environments
      // better than document.write, and gives the user a real file:// style
      // experience for the print dialog.
      const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const win = window.open(url, '_blank', 'noopener,noreferrer');
      if (!win) {
        toast.error('Pop-up blocked — allow pop-ups to view the export.');
      } else {
        // Give the new tab time to load before we revoke; revoking
        // immediately can null out the contents on slower browsers.
        setTimeout(() => URL.revokeObjectURL(url), 30_000);
        toast.success('Opened audit-log export. Use your browser to save as PDF.');
      }
    } catch (e) {
      const msg = e instanceof ApiError
        ? `Couldn't open audit export (HTTP ${e.status}). ${e.status === 403 ? 'Your role lacks audit_log:read.' : 'Try again.'}`
        : "Couldn't open audit export. Try again.";
      toast.error(msg);
    } finally {
      setExporting(null);
    }
  }, [buildExportFilters, exporting]);

  const exportDisabled = exporting !== null || (data?.items.length ?? 0) === 0;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold">Audit Log</h1>
          <p className="text-sm text-gray-400 mt-1">
            Immutable record of all platform actions
          </p>
        </div>
        <div className="flex items-center gap-3">
          {data && (
            <span className="text-sm text-gray-500">
              {data.total.toLocaleString()} total events
            </span>
          )}
          {/* WS-H3 — compliance bundle exports. Both buttons honour the
             current filter set so an analyst can scope a binder to e.g.
             "all role grants in the last week" without server-side gymnastics. */}
          <div
            className="flex items-center gap-2"
            role="group"
            aria-label="Export audit log"
          >
            <button
              type="button"
              onClick={handleExportCsv}
              disabled={exportDisabled}
              title={
                exportDisabled && (data?.items.length ?? 0) === 0
                  ? 'Nothing to export with the current filters'
                  : 'Download the filtered audit trail as RFC 4180 CSV'
              }
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-gray-600 bg-gray-800 text-gray-200 hover:bg-gray-700 hover:border-gray-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors focus:outline-none focus:ring-2 focus:ring-indigo-500"
            >
              <svg
                xmlns="http://www.w3.org/2000/svg"
                viewBox="0 0 20 20"
                fill="currentColor"
                className="w-4 h-4"
                aria-hidden="true"
              >
                <path
                  fillRule="evenodd"
                  d="M10 3a.75.75 0 01.75.75v8.69l2.72-2.72a.75.75 0 111.06 1.06l-4 4a.75.75 0 01-1.06 0l-4-4a.75.75 0 011.06-1.06l2.72 2.72V3.75A.75.75 0 0110 3zM3.75 14a.75.75 0 01.75.75V16h11v-1.25a.75.75 0 011.5 0V16a1.5 1.5 0 01-1.5 1.5h-11A1.5 1.5 0 013 16v-1.25a.75.75 0 01.75-.75z"
                  clipRule="evenodd"
                />
              </svg>
              {exporting === 'csv' ? 'Exporting…' : 'Export CSV'}
            </button>
            <button
              type="button"
              onClick={handleExportHtml}
              disabled={exportDisabled}
              title={
                exportDisabled && (data?.items.length ?? 0) === 0
                  ? 'Nothing to export with the current filters'
                  : 'Open a print-ready HTML bundle (use browser to Save as PDF)'
              }
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-indigo-500/40 bg-indigo-500/10 text-indigo-200 hover:bg-indigo-500/20 disabled:opacity-50 disabled:cursor-not-allowed transition-colors focus:outline-none focus:ring-2 focus:ring-indigo-500"
            >
              <svg
                xmlns="http://www.w3.org/2000/svg"
                viewBox="0 0 20 20"
                fill="currentColor"
                className="w-4 h-4"
                aria-hidden="true"
              >
                <path d="M5 4a2 2 0 00-2 2v1h14V6a2 2 0 00-2-2H5z" />
                <path
                  fillRule="evenodd"
                  d="M3 9h14v5a2 2 0 01-2 2H5a2 2 0 01-2-2V9zm4 2a1 1 0 100 2h6a1 1 0 100-2H7z"
                  clipRule="evenodd"
                />
              </svg>
              {exporting === 'html' ? 'Opening…' : 'Export PDF (HTML)'}
            </button>
          </div>
        </div>
      </div>

      {/* Filters */}
      <form
        onSubmit={handleSearch}
        className="flex flex-wrap gap-3 bg-gray-800/50 p-4 rounded-lg border border-gray-700 shadow-sm"
      >
        <input
          type="text"
          placeholder="Search email or action…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="flex-1 min-w-48 rounded-md border border-gray-600 bg-gray-900 text-gray-200 px-3 py-2 text-sm placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
        />
        <select
          value={actionFilter}
          onChange={(e) => { setActionFilter(e.target.value); setPage(1); }}
          className="rounded-md border border-gray-600 bg-gray-900 text-gray-200 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
        >
          <option value="">All actions</option>
          <option value="cases:">Cases</option>
          <option value="alerts:">Alerts</option>
          <option value="playbooks:">Playbooks</option>
          <option value="detections:">Detections</option>
          <option value="connectors:">Connectors</option>
          <option value="roles:">Roles</option>
          <option value="auth:">Auth</option>
        </select>
        <select
          value={resourceFilter}
          onChange={(e) => { setResourceFilter(e.target.value); setPage(1); }}
          className="rounded-md border border-gray-600 bg-gray-900 text-gray-200 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
        >
          <option value="">All resources</option>
          <option value="case">case</option>
          <option value="alert">alert</option>
          <option value="playbook">playbook</option>
          <option value="detection_rule">detection_rule</option>
          <option value="connector">connector</option>
          <option value="role">role</option>
          <option value="api_key">api_key</option>
        </select>
        <button
          type="submit"
          className="px-4 py-2 text-sm font-medium bg-indigo-600 text-white rounded-md hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500"
        >
          Search
        </button>
      </form>

      {/* Table */}
      <div className="bg-gray-800/50 rounded-lg border border-gray-700 shadow-sm overflow-hidden">
        {error && !data && (
          <div className="p-4">
            <ErrorState
              title="Couldn't load audit log"
              description="The audit log service didn't respond. Check the API or try again."
              error={error}
            />
          </div>
        )}
        {data && data.items.length === 0 && !isLoading && (
          // WS-F5 — audit log is *required* by SOC2/HIPAA so a true "empty"
          // tenant is rare. Most empty paths here are filter-misses; surface
          // a clear path back to the unfiltered view.
          <div className="p-4">
            {search || actionFilter || resourceFilter ? (
              <EmptyState
                icon={EmptyStateIcons.search}
                title="No audit events match these filters"
                description="Try widening the search, clearing the action/resource filter, or jumping to a different time window."
                action={
                  <button
                    onClick={() => {
                      setSearch('');
                      setActionFilter('');
                      setResourceFilter('');
                      setPage(1);
                    }}
                    className="text-xs px-3 py-1.5 rounded-md border border-indigo-500/40 bg-indigo-500/10 text-indigo-300 hover:bg-indigo-500/20 transition-colors"
                  >
                    Clear filters
                  </button>
                }
                className="bg-transparent py-8"
              />
            ) : (
              <EmptyState
                icon={EmptyStateIcons.audit}
                title="No audit events yet"
                description="Every authenticated action — case updates, rule edits, connector changes, role grants — is logged here. Events will start appearing as analysts use the platform."
                className="bg-transparent py-8"
              />
            )}
          </div>
        )}
        {data && data.items.length > 0 && (
          <table className="min-w-full divide-y divide-gray-700 text-sm">
            <thead className="bg-gray-900/60">
              <tr>
                <th className="px-4 py-3 text-left font-medium text-gray-400">
                  Timestamp
                </th>
                <th className="px-4 py-3 text-left font-medium text-gray-400">
                  Actor
                </th>
                <th className="px-4 py-3 text-left font-medium text-gray-400">
                  Action
                </th>
                <th className="px-4 py-3 text-left font-medium text-gray-400">
                  Resource
                </th>
                <th className="px-4 py-3 text-left font-medium text-gray-400">
                  IP
                </th>
                <th className="px-4 py-3 text-left font-medium text-gray-400">
                  Details
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700/50">
              {data.items.map((event) => (
                <>
                  <tr
                    key={event.id}
                    className="hover:bg-gray-700/40 cursor-pointer"
                    onClick={() =>
                      setExpandedId(expandedId === event.id ? null : event.id)
                    }
                  >
                    <td className="px-4 py-3 text-gray-500 whitespace-nowrap" suppressHydrationWarning>
                      {new Date(event.created_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-3">
                      <span className="font-medium text-gray-200">
                        {event.actor_email ?? 'system'}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${actionBadge(
                          event.action
                        )}`}
                      >
                        {event.action}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-gray-300">
                      {event.resource ?? '—'}
                      {event.resource_id && (
                        <span className="ml-1 text-gray-400 text-xs">
                          #{event.resource_id.slice(0, 8)}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-gray-400">
                      {event.actor_ip ?? '—'}
                    </td>
                    <td className="px-4 py-3 text-indigo-500 text-xs">
                      {expandedId === event.id ? '▲ hide' : '▼ show'}
                    </td>
                  </tr>
                  {expandedId === event.id && (
                    <tr key={`${event.id}-expanded`} className="bg-gray-900/40">
                      <td colSpan={6} className="px-4 py-3">
                        <pre className="text-xs text-gray-300 whitespace-pre-wrap">
                          {JSON.stringify(
                            {
                              id: event.id,
                              actor_id: event.actor_id,
                              changes: event.changes,
                            },
                            null,
                            2
                          )}
                        </pre>
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Pagination */}
      {data && data.total_pages > 1 && (
        <div className="flex items-center justify-between">
          <p className="text-sm text-gray-500">
            Page {data.page} of {data.total_pages}
          </p>
          <div className="flex gap-2">
            <button
              disabled={page <= 1}
              onClick={() => setPage((p) => p - 1)}
              className="px-3 py-1.5 text-sm border border-gray-600 text-gray-300 rounded-md disabled:opacity-40 hover:bg-gray-700"
            >
              Previous
            </button>
            <button
              disabled={page >= data.total_pages}
              onClick={() => setPage((p) => p + 1)}
              className="px-3 py-1.5 text-sm border border-gray-600 text-gray-300 rounded-md disabled:opacity-40 hover:bg-gray-700"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
