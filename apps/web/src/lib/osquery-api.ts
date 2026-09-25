/**
 * Typed HTTP client for the osquery-tls service.
 *
 * All requests are issued to `/api/v1/osquery/*` — Next.js proxies that
 * to OSQUERY_TLS_HOST via the rewrite in next.config.js.
 *
 * Tenancy: the service resolves the tenant from the caller's credential
 * (`app/security/tenant_scope.py`), and a `tenant_id` parameter only narrows
 * *within* that scope. This client therefore sends the session bearer token
 * and does **not** send a tenant — there is no tenant the console could name
 * that the credential does not already imply, and the one it used to name was
 * the literal `'default'`, which that module lists as a placeholder meaning
 * "the caller did not name a tenant".
 */

import { AUTH_TOKEN_KEY } from '@/lib/api';

const OSQUERY_BASE =
  (process.env.NEXT_PUBLIC_OSQUERY_TLS_URL ?? '') + '/api/v1/osquery';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface FimEvent {
  id: number;
  tenant_id: string;
  node_key: string;
  hostname: string | null;
  target_path: string;
  action: 'CREATED' | 'DELETED' | 'UPDATED' | 'ATTRIBUTES_MODIFIED' | string;
  md5: string | null;
  sha256: string | null;
  pid: number | null;
  ppid: number | null;
  process_name: string | null;
  username: string | null;
  event_time: string; // ISO-8601
  ingested_at: string; // ISO-8601
}

export interface FimEventsPage {
  events: FimEvent[];
  total: number;
  page: number;
  page_size: number;
}

export interface FimActionCount {
  action: string;
  count: number;
}

export interface FimPathCount {
  target_path: string;
  count: number;
}

export interface FimSummary {
  total_events: number;
  by_action: FimActionCount[];
  top_paths: FimPathCount[];
  active_nodes: number;
}

export interface FimEventsParams {
  page?: number;
  page_size?: number;
  action?: string;
  path_prefix?: string;
  hostname?: string;
  since?: string; // ISO-8601
}

export interface FimSummaryParams {
  since?: string; // ISO-8601
}

/** Wire shape of `GET /fim/events`. The service paginates by offset/limit. */
interface FimEventPageWire {
  total: number;
  offset: number;
  limit: number;
  items: FimEvent[];
}

// ─── API helpers ─────────────────────────────────────────────────────────────

async function get<T>(path: string, params?: Record<string, string | number | undefined>): Promise<T> {
  const url = new URL(`${OSQUERY_BASE}${path}`, window.location.origin);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined) url.searchParams.set(k, String(v));
    }
  }
  const headers: Record<string, string> = {};
  // Without this the service resolves an empty principal and refuses the read
  // with a 403, because `require_console_or_service_auth` has nothing to scope
  // by. The page has never sent it.
  const token =
    typeof window !== 'undefined' ? window.localStorage.getItem(AUTH_TOKEN_KEY) : null;
  if (token) headers.Authorization = `Bearer ${token}`;

  const res = await fetch(url.toString(), { headers });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`osquery-api ${res.status}: ${text}`);
  }
  return res.json() as Promise<T>;
}

// ─── FIM endpoints ────────────────────────────────────────────────────────────

export async function getFimEvents(params: FimEventsParams = {}): Promise<FimEventsPage> {
  const { page = 1, page_size = 100, ...rest } = params;
  // `page`/`page_size` were sent as-is to an endpoint that declares
  // `offset`/`limit`, so FastAPI dropped both: every page rendered the same
  // first 100 rows while the pager counted upward.
  const wire = await get<FimEventPageWire>('/fim/events', {
    ...rest,
    limit: page_size,
    offset: (page - 1) * page_size,
  });
  return {
    events: wire.items,
    total: wire.total,
    page,
    page_size,
  };
}

export function getFimSummary(params: FimSummaryParams = {}): Promise<FimSummary> {
  return get<FimSummary>('/fim/summary', { ...params });
}
