/**
 * Typed HTTP client for the osquery-tls service.
 *
 * All requests are issued to `/api/v1/osquery/*` — Next.js proxies that
 * to OSQUERY_TLS_HOST via the rewrite in next.config.js.
 */

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
  tenant_id: string;
  page?: number;
  page_size?: number;
  action?: string;
  path_prefix?: string;
  node_key?: string;
  since?: string; // ISO-8601
}

export interface FimSummaryParams {
  tenant_id: string;
  since?: string; // ISO-8601
}

// ─── API helpers ─────────────────────────────────────────────────────────────

async function get<T>(path: string, params?: Record<string, string | number | undefined>): Promise<T> {
  const url = new URL(`${OSQUERY_BASE}${path}`, window.location.origin);
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined) url.searchParams.set(k, String(v));
    }
  }
  const res = await fetch(url.toString());
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`osquery-api ${res.status}: ${text}`);
  }
  return res.json() as Promise<T>;
}

// ─── FIM endpoints ────────────────────────────────────────────────────────────

export function getFimEvents(params: FimEventsParams): Promise<FimEventsPage> {
  const { tenant_id, ...rest } = params;
  return get<FimEventsPage>('/fim/events', { tenant_id, ...rest });
}

export function getFimSummary(params: FimSummaryParams): Promise<FimSummary> {
  return get<FimSummary>('/fim/summary', { ...params });
}
