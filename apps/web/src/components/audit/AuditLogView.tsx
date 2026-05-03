'use client';

import { useState, useCallback } from 'react';
import useSWR from 'swr';

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

const fetcher = (url: string) =>
  fetch(url, { credentials: 'include' }).then((r) => {
    if (!r.ok) throw new Error('Failed to fetch');
    return r.json();
  });

const ACTION_COLORS: Record<string, string> = {
  create: 'bg-green-100 text-green-800',
  update: 'bg-blue-100 text-blue-800',
  delete: 'bg-red-100 text-red-800',
};

function actionBadge(action: string): string {
  for (const [verb, cls] of Object.entries(ACTION_COLORS)) {
    if (action.includes(verb)) return cls;
  }
  return 'bg-gray-100 text-gray-700';
}

export function AuditLogView() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [actionFilter, setActionFilter] = useState('');
  const [resourceFilter, setResourceFilter] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const params = new URLSearchParams({ page: String(page), page_size: '50' });
  if (search) params.set('search', search);
  if (actionFilter) params.set('action', actionFilter);
  if (resourceFilter) params.set('resource', resourceFilter);

  const { data, error, isLoading } = useSWR<AuditListResponse>(
    `/api/v1/audit?${params}`,
    fetcher,
    { refreshInterval: 30_000 }
  );

  const handleSearch = useCallback((e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
  }, []);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Audit Log</h1>
          <p className="text-sm text-gray-500 mt-1">
            Immutable record of all platform actions
          </p>
        </div>
        {data && (
          <span className="text-sm text-gray-500">
            {data.total.toLocaleString()} total events
          </span>
        )}
      </div>

      {/* Filters */}
      <form
        onSubmit={handleSearch}
        className="flex flex-wrap gap-3 bg-white p-4 rounded-lg border border-gray-200 shadow-sm"
      >
        <input
          type="text"
          placeholder="Search email or action…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="flex-1 min-w-48 rounded-md border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
        />
        <select
          value={actionFilter}
          onChange={(e) => { setActionFilter(e.target.value); setPage(1); }}
          className="rounded-md border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
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
          className="rounded-md border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
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
      <div className="bg-white rounded-lg border border-gray-200 shadow-sm overflow-hidden">
        {isLoading && (
          <div className="p-8 text-center text-gray-500 text-sm">Loading…</div>
        )}
        {error && (
          <div className="p-8 text-center text-red-500 text-sm">
            Failed to load audit log.
          </div>
        )}
        {data && data.items.length === 0 && !isLoading && (
          <div className="p-8 text-center text-gray-400 text-sm">
            No audit events found.
          </div>
        )}
        {data && data.items.length > 0 && (
          <table className="min-w-full divide-y divide-gray-200 text-sm">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-4 py-3 text-left font-medium text-gray-600">
                  Timestamp
                </th>
                <th className="px-4 py-3 text-left font-medium text-gray-600">
                  Actor
                </th>
                <th className="px-4 py-3 text-left font-medium text-gray-600">
                  Action
                </th>
                <th className="px-4 py-3 text-left font-medium text-gray-600">
                  Resource
                </th>
                <th className="px-4 py-3 text-left font-medium text-gray-600">
                  IP
                </th>
                <th className="px-4 py-3 text-left font-medium text-gray-600">
                  Details
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {data.items.map((event) => (
                <>
                  <tr
                    key={event.id}
                    className="hover:bg-gray-50 cursor-pointer"
                    onClick={() =>
                      setExpandedId(expandedId === event.id ? null : event.id)
                    }
                  >
                    <td className="px-4 py-3 text-gray-500 whitespace-nowrap">
                      {new Date(event.created_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-3">
                      <span className="font-medium text-gray-900">
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
                    <td className="px-4 py-3 text-gray-600">
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
                    <tr key={`${event.id}-expanded`} className="bg-gray-50">
                      <td colSpan={6} className="px-4 py-3">
                        <pre className="text-xs text-gray-700 whitespace-pre-wrap">
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
              className="px-3 py-1.5 text-sm border rounded-md disabled:opacity-40 hover:bg-gray-50"
            >
              Previous
            </button>
            <button
              disabled={page >= data.total_pages}
              onClick={() => setPage((p) => p + 1)}
              className="px-3 py-1.5 text-sm border rounded-md disabled:opacity-40 hover:bg-gray-50"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
