/**
 * AiSOC API Client
 *
 * Typed HTTP client that talks to the Core API service and a few sibling
 * microservices (agents, fusion, threatintel, enrichment).
 *
 * Conventions:
 *   - Every public function returns a typed `Promise<T>`. Callers should
 *     wrap with SWR / React Query for caching + retries.
 *   - Errors are thrown as native `Error` with the HTTP status + body so
 *     UI components can catch and render `<ErrorState error={e} />`.
 *   - Base URLs default to "" (same-origin) so the browser hits whatever
 *     host it loaded the page from. Next.js `rewrites()` then proxies the
 *     `/api/v1/*`, `/api/v1/contextual/*`, `/ws/*` and `/sse` paths to the
 *     right downstream service. This makes the bundle host-agnostic — the
 *     same image works on `localhost:3000`, behind nginx, or behind a
 *     Cloudflare Tunnel pointed at `tryaisoc.com`.
 *   - `NEXT_PUBLIC_*_URL` env vars are still honoured if you want to bypass
 *     the proxy (e.g. point the bundle at a different API origin during
 *     local debugging).
 */

/**
 * Returns `url` unchanged when running server-side or when `url` is already
 * same-origin. In the browser, if `url` is cross-origin relative to the page,
 * we fall back to `''` (same-origin) so Next.js rewrites can proxy the request.
 *
 * This prevents a misconfigured NEXT_PUBLIC_*_URL (e.g. pointing directly at
 * api.tryaisoc.com) from bypassing the proxy and triggering CORS blocks.
 */
function safeBase(url: string): string {
  if (!url) return '';
  if (typeof window === 'undefined') return url; // SSR — let Next.js rewrites decide
  try {
    const envOrigin = new URL(url).origin;
    if (envOrigin !== window.location.origin) {
      // Cross-origin base detected. Fall back to same-origin so the Next.js
      // rewrite proxy can handle the request without CORS issues.
      return '';
    }
  } catch {
    // Relative URL or invalid — use as-is (same-origin path is fine)
  }
  return url;
}

const API_BASE = safeBase(process.env.NEXT_PUBLIC_API_URL || '');
const AGENTS_BASE = safeBase(process.env.NEXT_PUBLIC_AGENTS_URL || '');
const ACTIONS_BASE = safeBase(process.env.NEXT_PUBLIC_ACTIONS_URL || '');
const FUSION_BASE = safeBase(process.env.NEXT_PUBLIC_FUSION_URL || '');
const THREATINTEL_BASE = safeBase(process.env.NEXT_PUBLIC_THREATINTEL_URL || '');
const ENRICHMENT_BASE = safeBase(process.env.NEXT_PUBLIC_ENRICHMENT_URL || '');
const REALTIME_BASE = safeBase(process.env.NEXT_PUBLIC_REALTIME_URL || '');
const WS_BASE = process.env.NEXT_PUBLIC_WS_URL || ''; // WS handled separately by wsOrigin()

/**
 * Compute the WebSocket origin at call time.
 *
 * If the bundle was built with `NEXT_PUBLIC_WS_URL` set, use that verbatim.
 * Otherwise, derive `wss://<current-host>` from `window.location` so the WS
 * connection lands on the same host the page was loaded from (the Next.js
 * rewrites then proxy `/ws/*` to the realtime gateway).
 *
 * SSR fallback: returns `''` so the resulting URL is path-only; nothing on
 * the server actually opens WebSockets.
 */
function wsOrigin(): string {
  if (WS_BASE) return WS_BASE;
  if (typeof window !== 'undefined') {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${proto}//${window.location.host}`;
  }
  return '';
}

const TENANT_ID =
  process.env.NEXT_PUBLIC_TENANT_ID ||
  '00000000-0000-0000-0000-000000000001';

export const API_BASES = {
  api: API_BASE,
  agents: AGENTS_BASE,
  actions: ACTIONS_BASE,
  fusion: FUSION_BASE,
  threatintel: THREATINTEL_BASE,
  enrichment: ENRICHMENT_BASE,
  realtime: REALTIME_BASE,
  ws: WS_BASE,
} as const;

export const DEFAULT_TENANT_ID = TENANT_ID;

// ─── Active tenant (W5 — tenant switcher) ───────────────────────────────────
//
// The console used to ship every request with the env-derived TENANT_ID. With
// the tenant switcher, MSSP parents and analysts who carry credentials for
// multiple tenants need a way to flip the `X-Tenant-Id` header at runtime.
// We expose three building blocks the TenantContext + switcher consume:
//
//   - ACTIVE_TENANT_KEY:    localStorage key for the override
//   - getActiveTenantId():  read precedence — override → cached user → env
//   - setActiveTenantId():  persist (or clear) the override
//
// `request()` calls `getActiveTenantId()` on every call so a tenant flip
// applies to the very next fetch without needing a page reload. The env var
// `NEXT_PUBLIC_TENANT_ID` remains the floor so demo and SSR contexts keep
// working when no user is logged in.

export const ACTIVE_TENANT_KEY = 'aisoc.activeTenantId';

export function getActiveTenantId(): string {
  if (typeof window === 'undefined') return TENANT_ID;
  try {
    const override = window.localStorage.getItem(ACTIVE_TENANT_KEY);
    if (override) return override;
    const raw = window.localStorage.getItem(AUTH_USER_KEY);
    if (raw) {
      const user = JSON.parse(raw) as { tenant_id?: string };
      if (user.tenant_id) return user.tenant_id;
    }
  } catch {
    /* localStorage unavailable / malformed payload — fall through */
  }
  return TENANT_ID;
}

export function setActiveTenantId(tenantId: string | null): void {
  if (typeof window === 'undefined') return;
  try {
    if (tenantId) {
      window.localStorage.setItem(ACTIVE_TENANT_KEY, tenantId);
    } else {
      window.localStorage.removeItem(ACTIVE_TENANT_KEY);
    }
  } catch {
    /* private-mode quota errors — surface choice is in-memory only */
  }
}

interface FetchOptions extends RequestInit {
  params?: Record<string, string | number | boolean | undefined>;
  baseUrl?: string;
}

export class ApiError extends Error {
  status: number;
  body: string;

  constructor(message: string, status: number, body: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.body = body;
  }
}

async function request<T>(path: string, options: FetchOptions = {}): Promise<T> {
  const { params, baseUrl, ...fetchOptions } = options;

  let url = `${baseUrl ?? API_BASE}${path}`;
  if (params) {
    const searchParams = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== '') {
        searchParams.set(key, String(value));
      }
    });
    const qs = searchParams.toString();
    if (qs) url += `?${qs}`;
  }

  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    // Resolve at call-time so the tenant switcher takes effect on the very
    // next fetch (no full page reload needed).
    'X-Tenant-Id': getActiveTenantId(),
    ...fetchOptions.headers,
  };

  // Mobile responder PWA auth: if a passkey-issued JWT is present in
  // localStorage, attach it as a Bearer token. The desktop console relies on
  // cookies set by the API gateway, so this is purely additive.
  if (typeof window !== 'undefined') {
    try {
      const existing =
        (headers as Record<string, string>).Authorization ??
        (headers as Record<string, string>).authorization;
      if (!existing) {
        const token = window.localStorage.getItem('aisoc.responder.accessToken');
        if (token) {
          (headers as Record<string, string>).Authorization = `Bearer ${token}`;
        }
      }
    } catch {
      /* localStorage unavailable; ignore */
    }
  }

  let response: Response;
  try {
    response = await fetch(url, {
      ...fetchOptions,
      headers,
      cache: 'no-store',
    });
  } catch (err) {
    throw new ApiError(
      `Network error talking to ${url}: ${(err as Error).message}`,
      0,
      '',
    );
  }

  if (!response.ok) {
    const errorText = await response.text().catch(() => '');
    throw new ApiError(
      `API ${response.status} ${response.statusText} — ${path}`,
      response.status,
      errorText,
    );
  }

  if (response.status === 204) return {} as T;
  // Some endpoints (the agent stream, NDJSON) might not be JSON. Callers that
  // need streams should use fetch() directly. Here we assume JSON.
  return (await response.json()) as T;
}

// ─── Auth ────────────────────────────────────────────────────────────────────

export const AUTH_TOKEN_KEY = 'aisoc.responder.accessToken';
export const AUTH_REFRESH_KEY = 'aisoc.responder.refreshToken';
export const AUTH_USER_KEY = 'aisoc.responder.user';

export interface AuthUser {
  id: string;
  email: string;
  username?: string | null;
  role: string;
  tenant_id: string;
  is_active?: boolean;
  preferences?: Record<string, unknown>;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export interface LoginResult extends TokenResponse {
  user: AuthUser;
}

function persistAuth(tokens: TokenResponse, user: AuthUser): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(AUTH_TOKEN_KEY, tokens.access_token);
    if (tokens.refresh_token) {
      window.localStorage.setItem(AUTH_REFRESH_KEY, tokens.refresh_token);
    }
    window.localStorage.setItem(AUTH_USER_KEY, JSON.stringify(user));
  } catch {
    /* localStorage unavailable; ignore */
  }
}

export const authApi = {
  /**
   * Email + password login against ``POST /api/v1/auth/login``.
   *
   * The backend returns access + refresh tokens only, so we follow up with
   * ``GET /api/v1/auth/me`` to fetch the user record. On success, persist
   * everything under the same localStorage keys the responder PWA uses
   * (``aisoc.responder.accessToken`` etc.) so the existing ``request()``
   * helper attaches the JWT automatically and a single login covers desktop
   * + mobile.
   */
  async login(email: string, password: string): Promise<LoginResult> {
    const tokens = await request<TokenResponse>('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
    // Stash the access token now so the `me` request flows through the
    // standard `Authorization: Bearer …` path in `request()`.
    if (typeof window !== 'undefined') {
      try {
        window.localStorage.setItem(AUTH_TOKEN_KEY, tokens.access_token);
      } catch {
        /* ignore */
      }
    }
    const user = await request<AuthUser>('/api/v1/auth/me');
    persistAuth(tokens, user);
    return { ...tokens, user };
  },

  logout(): void {
    if (typeof window === 'undefined') return;
    try {
      window.localStorage.removeItem(AUTH_TOKEN_KEY);
      window.localStorage.removeItem(AUTH_REFRESH_KEY);
      window.localStorage.removeItem(AUTH_USER_KEY);
    } catch {
      /* ignore */
    }
  },

  currentUser(): AuthUser | null {
    if (typeof window === 'undefined') return null;
    try {
      const raw = window.localStorage.getItem(AUTH_USER_KEY);
      return raw ? (JSON.parse(raw) as AuthUser) : null;
    } catch {
      return null;
    }
  },

  isAuthenticated(): boolean {
    if (typeof window === 'undefined') return false;
    try {
      return Boolean(window.localStorage.getItem(AUTH_TOKEN_KEY));
    } catch {
      return false;
    }
  },

  /** Merge user preferences on the server (theme, layout, etc.). */
  async updateUserPreferences(preferences: Record<string, unknown>): Promise<AuthUser> {
    const token = typeof window !== 'undefined'
      ? window.localStorage.getItem(AUTH_TOKEN_KEY)
      : null;
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const response = await fetch(`${API_BASE}/api/v1/auth/me/preferences`, {
      method: 'PATCH',
      headers,
      body: JSON.stringify({ preferences }),
    });
    if (!response.ok) throw new Error('Failed to update preferences');
    const user = (await response.json()) as AuthUser;
    // Keep locally-cached user in sync
    try {
      window.localStorage.setItem(AUTH_USER_KEY, JSON.stringify(user));
    } catch { /* ignore */ }
    return user;
  },
};

// ─── Tenants & MSSP ─────────────────────────────────────────────────────────
//
// The W5 tenant switcher needs to know:
//   - which tenant the user is currently authenticated against
//     (`tenants/me` — single canonical source of truth, includes display name)
//   - what other tenants they can flip to
//     (`mssp/children` for MSSP parents — returns *real* child tenants from
//      the DB, not the mock list used by the parent dashboard)
//
// Failures are caught by the caller — the switcher gracefully degrades to a
// single-tenant role badge when these endpoints 401/404 (e.g. a tenant user
// who isn't an MSSP parent will not have any children but still has /me).

export interface MyTenant {
  id: string;
  name: string;
  // mssp_role and parent_tenant_id come from the lightweight identity
  // endpoint and are present for any tenant (null for standalone tenants).
  mssp_role?: 'parent' | 'child' | null;
  parent_tenant_id?: string | null;
}

export interface ChildTenant {
  id: string;
  name: string;
  mssp_role: string;
  created_at?: string;
}

export const tenantsApi = {
  /**
   * Lightweight tenant identity for the SOC console TopBar.
   *
   * Uses `/api/v1/tenants/me/identity` (any authenticated user) instead of
   * `/api/v1/tenants/me` (requires `settings:read`) so analyst/viewer roles
   * can render the tenant pill and role badge without leaking plan or
   * settings configuration.
   */
  async me(): Promise<MyTenant> {
    return request<MyTenant>('/api/v1/tenants/me/identity');
  },
};

export const msspApi = {
  async listChildren(): Promise<ChildTenant[]> {
    return request<ChildTenant[]>('/api/v1/mssp/children');
  },
};

// ─── Alerts ─────────────────────────────────────────────────────────────────

export type AlertSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type AlertStatus =
  | 'new'
  | 'triaged'
  | 'investigating'
  | 'resolved'
  | 'false_positive';

export interface MitreAttack {
  tactic: string;
  technique: string;
  techniqueId: string;
}

export interface AlertIOC {
  type: string;
  value: string;
  malicious?: boolean;
}

export type ConfidenceLabel = 'high' | 'medium' | 'low';

export interface ConfidenceFactor {
  factor: string;
  label: string;
  value: number;
  contribution: number;
  weight: number;
}

export interface Alert {
  id: string;
  title: string;
  description: string;
  severity: AlertSeverity;
  status: AlertStatus;
  source: string;
  sourceRef?: string;
  tenantId: string;
  riskScore: number;
  mitreAttack?: MitreAttack[];
  iocs?: AlertIOC[];
  rawEvent?: Record<string, unknown>;
  assignee?: string;
  caseId?: string;
  tags?: string[];
  createdAt: string;
  updatedAt: string;
  resolvedAt?: string;
  confidenceLabel?: ConfidenceLabel;
  confidenceScore?: number;
  confidenceRationale?: ConfidenceFactor[];
  ledgerRunId?: string;
  /** Analyst-corrected verdict (Tier 1.5 override loop). */
  disposition?: 'true_positive' | 'false_positive' | 'benign' | 'escalate' | null;
}

export interface AlertsResponse {
  alerts: Alert[];
  total: number;
  page: number;
  pageSize: number;
}

export interface AlertFilters {
  severity?: string;
  status?: string;
  source?: string;
  assignee?: string;
  startTime?: string;
  endTime?: string;
  search?: string;
  page?: number;
  pageSize?: number;
  tenantId?: string;
}

export const alertsApi = {
  list: (filters: AlertFilters = {}) =>
    request<AlertsResponse>('/api/v1/alerts', {
      params: filters as Record<string, string>,
    }),

  get: (id: string) => request<Alert>(`/api/v1/alerts/${id}`),

  update: (id: string, data: Partial<Alert>) =>
    request<Alert>(`/api/v1/alerts/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),

  bulkAction: (
    ids: string[],
    action: string,
    data?: Record<string, unknown>,
  ) =>
    request<{ updated: number }>('/api/v1/alerts/bulk', {
      method: 'POST',
      body: JSON.stringify({ ids, action, ...data }),
    }),

  getTimeline: (id: string) =>
    request<{
      events: Array<{
        id: string;
        timestamp: string;
        type: string;
        title: string;
        description: string;
      }>;
    }>(`/api/v1/alerts/${id}/timeline`),

  /**
   * Structured AI explanation for one alert (Stage 2 #6).
   *
   * `POST /api/v1/alerts/{id}/explain` returns a single JSON envelope
   * with rule lineage, contributing events, MITRE technique cards, the
   * live false-positive rate for the matched rule, suggested next
   * steps, and a deterministic-or-LLM summary. Counterpart to the
   * agents service's NDJSON token stream — use this when you want
   * the *whole* answer in one shot (PDF builder, mobile app, the
   * console drawer's first paint) instead of typing it out.
   *
   * The endpoint is rate-limited per tenant (token bucket; default
   * burst 20, refill 0.2/s) and returns 429 with `Retry-After` when
   * the bucket is empty. 404 means either the alert doesn't exist or
   * the backend predates this endpoint — both are signals to fall
   * back to the streaming explainer.
   */
  explain: (alertId: string, signal?: AbortSignal) =>
    request<AlertExplanation>(`/api/v1/alerts/${alertId}/explain`, {
      method: 'POST',
      signal,
    }),
};

// ─── Investigation Queue (W7) ───────────────────────────────────────────────
//
// The Investigation Queue is the analyst's working surface: one ranked list
// of "what should I work on next?" sourced from the canonical alerts table.
// The backend computes a virtual ``sla_due_at`` per row (``first_seen +
// mttd_target`` for the alert's severity) and orders the queue by
//
//   1. assignment bucket (mine before unassigned), and
//   2. ``sla_due_at`` ascending within each bucket.
//
// Snoozed and closed alerts are excluded server-side. Unassigned ``medium``
// and below are also excluded — those are triaged in bulk on /alerts, not
// one-by-one on the queue. See ``services/api/app/services/alert_queue.py``
// for the full contract.

export type QueueOwner = 'me' | 'unassigned' | 'all';
export type QueuePeriod = '24h' | '7d' | '30d' | 'all';
export type QueueBucket = 'mine' | 'unassigned';
export type QueueRisk = 'low' | 'medium' | 'high';

export interface QueueAsset {
  /** ``host`` | ``user`` | ``ip`` | ``asset`` — chosen by the backend. */
  kind: string;
  value: string;
  label?: string | null;
}

export interface QueueAction {
  /** 1-indexed priority; lower is more urgent. */
  priority: number;
  action: string;
  risk: QueueRisk;
}

export interface QueueItem {
  id: string;
  tenant_id: string;
  title: string;
  severity: AlertSeverity;
  status: AlertStatus;
  priority: number;
  category?: string | null;
  connector_type?: string | null;

  assigned_to_id?: string | null;
  case_id?: string | null;

  first_seen: string;
  sla_due_at: string;
  /** Seconds until ``sla_due_at`` — negative once breached. */
  sla_remaining_seconds: number;
  sla_breached: boolean;
  age_seconds: number;

  asset?: QueueAsset | null;
  suggested_action?: QueueAction | null;

  bucket: QueueBucket;
}

export interface QueueCounts {
  mine: number;
  unassigned: number;
  all: number;
}

export interface QueueResponse {
  items: QueueItem[];
  total: number;
  counts: QueueCounts;
  period: QueuePeriod;
  owner: QueueOwner;
  page: number;
  page_size: number;
  pages: number;
  /** Server's authoritative ``now`` — the UI drifts its countdowns from this. */
  generated_at: string;
}

export interface QueueFilters {
  owner?: QueueOwner;
  period?: QueuePeriod;
  page?: number;
  page_size?: number;
}

export const queueApi = {
  /**
   * Fetch the Investigation Queue.
   *
   * Returns up to ``page_size`` items (capped server-side at 200) plus
   * the live ``counts`` for all buckets — that's what the sidebar badge
   * polls. The endpoint is cheap because the server only projects the
   * columns the queue actually renders; do *not* fan out to ``alertsApi.get``
   * for every row.
   */
  list: (filters: QueueFilters = {}) =>
    request<QueueResponse>('/api/v1/alerts/queue', {
      params: filters as Record<string, string | number>,
    }),

  /**
   * Atomically claim an unassigned alert for the current user.
   *
   * Returns ``409`` if another analyst grabbed the row first — the UI
   * should surface that as "claimed by Sam · refresh" rather than a
   * generic error. Idempotent if the caller already owns the alert.
   */
  claim: (alertId: string) =>
    request<Alert>(`/api/v1/alerts/${alertId}/claim`, {
      method: 'POST',
    }),

  /**
   * Reassign or unassign an alert. Pass ``assignee = null`` to release.
   *
   * Reuses the existing ``PATCH /alerts/{id}`` endpoint — the server
   * already accepts ``assignee`` updates. We add a thin wrapper here so
   * the queue view doesn't have to re-derive the URL.
   */
  assign: (alertId: string, assignee: string | null) =>
    request<Alert>(`/api/v1/alerts/${alertId}`, {
      method: 'PATCH',
      body: JSON.stringify({ assignee }),
    }),

  /**
   * Snooze an alert for ``duration_minutes`` (1 → 43200 / 30d) or until
   * a specific timestamp. The alert re-enters the queue automatically
   * once ``snoozed_until`` passes.
   */
  snooze: (
    alertId: string,
    body: { duration_minutes?: number; until?: string; reason?: string },
  ) =>
    request<Alert>(`/api/v1/alerts/${alertId}/snooze`, {
      method: 'POST',
      body: JSON.stringify(body),
    }),
};

// ─── Risk-Based Alerting (entity rollup) ─────────────────────────────────────
//
// Wave 1 of the AiSOC v6 capability roadmap: alerts contribute time-decayed
// risk *points* onto the entities they touch (user / host / src_ip / domain).
// Once an entity crosses ``rba_promotion_threshold`` it becomes the primary
// unit of triage in the UI — so the analyst opens "the user fox.beach" with
// 47 contributing alerts attached, not 47 separate alert rows. The endpoints
// live on the fusion service (port 8082) and are proxied same-origin via
// next.config.js → ``/api/v1/fusion/*``.

export type EntityType = 'user' | 'host' | 'ip' | 'domain';

/** A single alert that contributed risk to an entity. */
export interface EntityRiskContribution {
  alert_id: string;
  severity: AlertSeverity;
  /** Points contributed *at the moment of observation* — not decayed. */
  raw_points: number;
  /** ISO-8601 timestamp the alert was observed. */
  observed_at: string;
  title?: string | null;
  source?: string | null;
}

/** A rolled-up entity with its current decayed risk score. */
export interface EntityRiskRecord {
  tenant_id: string;
  entity_type: EntityType;
  entity_value: string;
  /** Time-decayed score (0 → ∞ in theory, capped in practice by the engine). */
  score: number;
  /** Same as ``score`` rounded — convenience for the UI's badge. */
  display_score: number;
  /** Promotion threshold the engine was configured with at observation time. */
  threshold: number;
  /** True if ``score`` has crossed ``threshold`` at least once. */
  promoted: boolean;
  /** ID of the incident the entity was promoted into, if any. */
  promoted_incident_id?: string | null;
  /** ISO-8601 timestamp of the last contributing alert. */
  last_seen: string;
  /** ISO-8601 timestamp the entity first picked up any risk. */
  first_seen: string;
  /** Top contributing alerts, newest first, capped to ~25. */
  contributions: EntityRiskContribution[];
  /** Count by severity over the decay window — drives the queue badge. */
  severity_histogram: Record<AlertSeverity, number>;
  /** Convenience: total alert count in the decay window. */
  alert_count: number;
}

export interface EntityRiskQueueResponse {
  tenant_id: string;
  threshold: number;
  entities: EntityRiskRecord[];
}

export interface EntityRiskStats {
  tenant_id: string;
  /** Promotion threshold (mirrored from the engine). */
  threshold: number;
  /** Total active entities in the window. */
  total: number;
  /** Entities currently at or above ``threshold``. */
  promoted: number;
  /** Banded counts for the queue header chips. */
  bands: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  /** Total alerts contributing across all entities in the window. */
  alert_count: number;
  /** Convenience: alert-to-incident ratio observed in the current window. */
  alert_to_incident_ratio?: number | null;
}

/**
 * Path namespace served by the fusion service. Goes through Next.js
 * rewrites (`/api/v1/fusion/*` → ``${FUSION_HOST}/*``) so the bundle
 * stays same-origin.
 */
const FUSION_PATH = '/api/v1/fusion';

export const entityRiskApi = {
  /** Top-N entities by current decayed risk score. */
  queue: (params: {
    tenantId?: string;
    limit?: number;
    promotedOnly?: boolean;
  } = {}) =>
    request<EntityRiskQueueResponse>(`${FUSION_PATH}/entity-risk/queue`, {
      params: {
        tenant_id: params.tenantId ?? TENANT_ID,
        limit: params.limit ?? 25,
        promoted_only: params.promotedOnly ? 'true' : undefined,
      },
    }),

  /** Tenant-scoped queue stats for dashboards (banding, totals, threshold). */
  stats: (tenantId?: string) =>
    request<EntityRiskStats>(`${FUSION_PATH}/entity-risk/stats`, {
      params: { tenant_id: tenantId ?? TENANT_ID },
    }),

  /** Full risk record for a single entity (drawer detail). */
  get: (entityType: EntityType, entityValue: string, tenantId?: string) => {
    const pathType = entityType === 'ip' ? 'src_ip' : entityType;
    return request<EntityRiskRecord>(
      `${FUSION_PATH}/entity-risk/${pathType}/${encodeURIComponent(entityValue)}`,
      { params: { tenant_id: tenantId ?? TENANT_ID } },
    );
  },
};

// ─── Cases ───────────────────────────────────────────────────────────────────

export type CaseStatus =
  | 'open'
  | 'in_progress'
  | 'pending'
  | 'resolved'
  | 'closed';
export type CaseSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface CaseTimelineEvent {
  id: string;
  type: string;
  timestamp: string;
  title: string;
  description?: string;
  actor?: string;
}

export interface CaseTask {
  id: string;
  title: string;
  status: 'todo' | 'in_progress' | 'done';
  assignee?: string;
  dueAt?: string;
  createdAt: string;
}

export interface Case {
  id: string;
  /**
   * Short, human-friendly case identifier (e.g. ``INC-001``).
   * Returned by the backend as ``case_number`` and used by demo deeplinks.
   */
  caseNumber?: string;
  title: string;
  description?: string;
  status: CaseStatus;
  severity: CaseSeverity;
  /** Display alias for severity used by some UIs. */
  priority?: CaseSeverity;
  assignee?: string;
  tenantId?: string;
  alertIds?: string[];
  /** Cached count from the backend so the UI doesn't have to re-aggregate. */
  alertCount?: number;
  tags?: string[];
  mitre?: string[];
  resolution?: string;
  createdBy?: string;
  createdAt: string;
  updatedAt: string;
  closedAt?: string;
  dueAt?: string;
  timeline?: CaseTimelineEvent[];
  tasks?: CaseTask[];
}

// The backend uses a 6-state lifecycle (`new | triaged | investigating |
// contained | resolved | closed`) while the web console renders a simpler
// 5-state model. Without translation, `STATUS_CONFIG[c.status]` returns
// `undefined` and `<CaseCard>` throws a TypeError, which React surfaces as a
// blank loading state on /cases. Keep these maps colocated with the Case type.
const BACKEND_TO_UI_STATUS: Record<string, CaseStatus> = {
  new: 'open',
  open: 'open',
  triaged: 'pending',
  pending: 'pending',
  investigating: 'in_progress',
  in_progress: 'in_progress',
  contained: 'in_progress',
  resolved: 'resolved',
  closed: 'closed',
};

const UI_TO_BACKEND_STATUS: Record<CaseStatus, string> = {
  open: 'new',
  pending: 'triaged',
  in_progress: 'investigating',
  resolved: 'resolved',
  closed: 'closed',
};

function toUiStatus(raw: unknown): CaseStatus {
  if (typeof raw !== 'string') return 'open';
  return BACKEND_TO_UI_STATUS[raw] ?? 'open';
}

export interface CasesResponse {
  cases: Case[];
  total: number;
  page: number;
  pageSize: number;
}

// ─── WS-D2 — Per-case auto-summary artifact ─────────────────────────────────
//
// Mirrors the Pydantic schemas in ``services/api/app/services/case_summary.py``.
// We keep these as a flat block of ``snake_case`` interfaces (matching the
// JSON over the wire) so consumers don't pay a transformation cost — the
// backend is the source of truth for shape, the UI just renders.
export interface CaseSummaryHeader {
  case_id: string;
  case_number: string | null;
  title: string;
  description: string | null;
  severity: string;
  status: string;
  assignee: string | null;
  created_by: string | null;
  tags: Record<string, unknown>;
}

export interface CaseLifecycleTimings {
  opened_at: string;
  triaged_at: string | null;
  resolved_at: string | null;
  closed_at: string | null;
  sla_due_at: string | null;
  time_to_triage_hours: number | null;
  time_to_resolve_hours: number | null;
  time_to_close_hours: number | null;
  sla_breached: boolean;
}

export interface CaseSummaryTaskBreakdown {
  total: number;
  todo: number;
  in_progress: number;
  done: number;
  overdue: number;
}

export interface CaseSummaryCommentBreakdown {
  total: number;
  analyst: number;
  system: number;
  distinct_authors: string[];
}

export interface CaseSummaryCoverage {
  mitre_techniques: string[];
  mitre_tactic_buckets: Record<string, number>;
  compliance_frameworks: string[];
}

export interface CaseSummaryObservables {
  total_nodes: number;
  total_edges: number;
  node_kind_counts: Record<string, number>;
  distinct_kinds: string[];
}

export interface CaseSummaryEvidence {
  total_items: number;
  distinct_kinds: string[];
}

export interface CaseSummaryTimelineEntry {
  ts: string;
  kind: string; // "case" | "comment" | "task"
  label: string;
  detail: string | null;
}

export interface CaseSummaryRecommendation {
  severity: string; // "info" | "warning" | "critical"
  title: string;
  body: string;
}

export interface CaseAutoSummary {
  generated_at: string;
  headline: string;
  case: CaseSummaryHeader;
  lifecycle: CaseLifecycleTimings;
  coverage: CaseSummaryCoverage;
  alerts: { count?: number; ids?: string[] } & Record<string, unknown>;
  observables: CaseSummaryObservables;
  evidence: CaseSummaryEvidence;
  tasks: CaseSummaryTaskBreakdown;
  comments: CaseSummaryCommentBreakdown;
  timeline: CaseSummaryTimelineEntry[];
  recommendations: CaseSummaryRecommendation[];
}

export interface CaseFilters {
  status?: string;
  priority?: string;
  severity?: string;
  assignee?: string;
  search?: string;
  page?: number;
  pageSize?: number;
}

/**
 * Normalize a case payload from the backend API.
 *
 * The Postgres-backed API returns snake_case fields and stores `tags` as a
 * JSONB object (`{labels: string[]}`). The web console's `Case` type uses
 * camelCase and expects `tags: string[]`. Without this normalization the
 * detail page crashes with a runtime TypeError when components call
 * `.map()` on `tags` directly.
 */
function normalizeCase(raw: unknown): Case {
  const r = (raw ?? {}) as Record<string, unknown>;
  const tagsRaw = r.tags;
  let tags: string[] | undefined;
  if (Array.isArray(tagsRaw)) {
    tags = tagsRaw.map((t) => String(t));
  } else if (
    tagsRaw &&
    typeof tagsRaw === 'object' &&
    Array.isArray((tagsRaw as Record<string, unknown>).labels)
  ) {
    tags = ((tagsRaw as Record<string, unknown>).labels as unknown[]).map((t) =>
      String(t),
    );
  }

  const alertIds = Array.isArray(r.alert_ids)
    ? (r.alert_ids as unknown[]).map((x) => String(x))
    : Array.isArray(r.alertIds)
      ? (r.alertIds as unknown[]).map((x) => String(x))
      : undefined;

  const mitre = Array.isArray(r.mitre_techniques)
    ? (r.mitre_techniques as unknown[]).map((x) => String(x))
    : Array.isArray(r.mitre)
      ? (r.mitre as unknown[]).map((x) => String(x))
      : undefined;

  const createdAt =
    (r.created_at as string | undefined) ??
    (r.createdAt as string | undefined) ??
    (r.opened_at as string | undefined) ??
    new Date().toISOString();

  const updatedAt =
    (r.updated_at as string | undefined) ??
    (r.updatedAt as string | undefined) ??
    createdAt;

  const caseNumber =
    (r.case_number as string | undefined) ??
    (r.caseNumber as string | undefined) ??
    undefined;

  return {
    id: String(r.id ?? ''),
    caseNumber,
    title: String(r.title ?? ''),
    description: (r.description as string | undefined) ?? undefined,
    status: toUiStatus(r.status),
    severity: (r.severity as Case['severity']) ?? 'medium',
    priority: (r.priority as Case['severity'] | undefined) ?? (r.severity as Case['severity'] | undefined),
    assignee: (r.assignee as string | null | undefined) ?? undefined,
    tenantId:
      (r.tenant_id as string | undefined) ?? (r.tenantId as string | undefined),
    alertIds,
    alertCount:
      (r.alert_count as number | undefined) ??
      (r.alertCount as number | undefined) ??
      (alertIds ? alertIds.length : undefined),
    tags,
    mitre,
    resolution: (r.resolution as string | undefined) ?? undefined,
    createdBy:
      (r.created_by as string | undefined) ?? (r.createdBy as string | undefined),
    createdAt,
    updatedAt,
    closedAt:
      (r.closed_at as string | null | undefined) ??
      (r.closedAt as string | null | undefined) ??
      undefined,
    dueAt:
      (r.sla_due_at as string | null | undefined) ??
      (r.dueAt as string | null | undefined) ??
      undefined,
    timeline: Array.isArray(r.timeline)
      ? (r.timeline as CaseTimelineEvent[])
      : undefined,
    tasks: Array.isArray(r.tasks) ? (r.tasks as CaseTask[]) : undefined,
  };
}

export function normalizeCasesResponse(raw: unknown, filters: CaseFilters = {}): CasesResponse {
  // The API may return either a bare array of cases or an envelope shape.
  if (Array.isArray(raw)) {
    const cases = raw.map(normalizeCase);
    return {
      cases,
      total: cases.length,
      page: filters.page ?? 1,
      pageSize: filters.pageSize ?? cases.length,
    };
  }
  const r = (raw ?? {}) as Record<string, unknown>;
  const list = Array.isArray(r.cases)
    ? (r.cases as unknown[]).map(normalizeCase)
    : [];
  return {
    cases: list,
    total: typeof r.total === 'number' ? (r.total as number) : list.length,
    page: typeof r.page === 'number' ? (r.page as number) : (filters.page ?? 1),
    pageSize:
      typeof r.pageSize === 'number'
        ? (r.pageSize as number)
        : typeof r.page_size === 'number'
          ? (r.page_size as number)
          : (filters.pageSize ?? list.length),
  };
}

export const casesApi = {
  list: async (filters: CaseFilters = {}) => {
    // Translate UI status filter into the backend lifecycle vocabulary so
    // querying "In Progress" in the console actually returns rows where the
    // backend stored "investigating".
    const params: Record<string, string> = {};
    for (const [key, value] of Object.entries(filters)) {
      if (value === undefined || value === null || value === '') continue;
      if (key === 'status' && typeof value === 'string' && value !== 'all') {
        params.status =
          UI_TO_BACKEND_STATUS[value as CaseStatus] ?? value;
        continue;
      }
      params[key] = String(value);
    }
    const raw = await request<unknown>('/api/v1/cases', { params });
    return normalizeCasesResponse(raw, filters);
  },

  get: async (id: string) => {
    const raw = await request<unknown>(`/api/v1/cases/${id}`);
    return normalizeCase(raw);
  },

  create: async (data: Partial<Case>) => {
    const raw = await request<unknown>('/api/v1/cases', {
      method: 'POST',
      body: JSON.stringify(data),
    });
    return normalizeCase(raw);
  },

  update: async (id: string, data: Partial<Case>) => {
    const raw = await request<unknown>(`/api/v1/cases/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    });
    return normalizeCase(raw);
  },

  addComment: (id: string, comment: string) =>
    request<{ id: string; comment: string; createdAt: string }>(
      `/api/v1/cases/${id}/comments`,
      {
        method: 'POST',
        body: JSON.stringify({ comment }),
      },
    ),

  linkAlerts: async (id: string, alertIds: string[]) => {
    const raw = await request<unknown>(`/api/v1/cases/${id}/alerts`, {
      method: 'POST',
      body: JSON.stringify({ alertIds }),
    });
    return normalizeCase(raw);
  },

  getTimeline: (id: string) =>
    request<{ events: CaseTimelineEvent[] }>(`/api/v1/cases/${id}/timeline`),

  addTask: (id: string, task: Partial<CaseTask>) =>
    request<CaseTask>(`/api/v1/cases/${id}/tasks`, {
      method: 'POST',
      body: JSON.stringify(task),
    }),

  updateTask: (caseId: string, taskId: string, task: Partial<CaseTask>) =>
    request<CaseTask>(`/api/v1/cases/${caseId}/tasks/${taskId}`, {
      method: 'PATCH',
      body: JSON.stringify(task),
    }),

  investigate: (caseId: string, alertSummary?: string) =>
    request<{ run_id: string; case_id: string; status: string; message: string }>(
      `/api/v1/cases/${caseId}/investigate`,
      {
        method: 'POST',
        body: JSON.stringify({ alert_summary: alertSummary ?? '' }),
      },
    ),

  getInvestigation: (caseId: string, runId: string) =>
    request<{
      run_id: string;
      case_id: string;
      status: string;
      audit_log?: Array<{ kind: string; agent: string; summary: string; ts: string }>;
      recon?: Record<string, unknown>;
      forensic?: Record<string, unknown>;
      responder?: Record<string, unknown>;
      error?: string;
    }>(`/api/v1/cases/${caseId}/investigations/${runId}`),

  /** Trigger a browser download of the PDF report. */
  downloadReportPdf: async (caseId: string, runId: string): Promise<void> => {
    const resp = await fetch(`${API_BASE}/api/v1/cases/${caseId}/investigations/${runId}/report.pdf`, {
      headers: { 'X-Tenant-Id': TENANT_ID },
    });
    if (!resp.ok) {
      const err = await resp.text().catch(() => resp.statusText);
      throw new Error(err);
    }
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aisoc-report-${runId}.pdf`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  },

  // WS-D2 — auto-summary at investigation close.
  // The backend renders both the structured payload (json) and a print-ready
  // page (html). We expose JSON for callers that want to drive their own UI
  // (e.g. an inline drawer) and an "open in new tab" helper for the HTML
  // artifact so operators can Cmd/Ctrl-P → Save as PDF for case-file archival.
  /** Fetch the structured per-case auto-summary payload. */
  getAutoSummary: (caseId: string) =>
    request<CaseAutoSummary>(`/api/v1/cases/${caseId}/summary`, {
      params: { format: 'json' },
    }),

  /**
   * Open the per-case auto-summary HTML artifact in a new tab.
   *
   * We deliberately fetch with the auth headers (instead of a plain
   * ``window.open(url)``) because the backend requires the bearer token and
   * tenant header — direct anchor navigation would drop them and 401.
   * Mirrors the WS-G2 ``reportsApi.weeklyDigestHtml`` pattern so both
   * report surfaces behave consistently in the PWA.
   */
  openAutoSummaryHtml: async (caseId: string): Promise<void> => {
    const headers: Record<string, string> = {
      Accept: 'text/html',
      'X-Tenant-Id': TENANT_ID,
    };
    if (typeof window !== 'undefined') {
      try {
        const token = window.localStorage.getItem(AUTH_TOKEN_KEY);
        if (token) headers.Authorization = `Bearer ${token}`;
      } catch {
        /* localStorage unavailable; ignore */
      }
    }

    const url = `${API_BASE}/api/v1/cases/${caseId}/summary?format=html`;
    const response = await fetch(url, { headers, cache: 'no-store' });
    if (!response.ok) {
      const detail = await response.text().catch(() => '');
      throw new ApiError(
        `API ${response.status} ${response.statusText} — /cases/${caseId}/summary`,
        response.status,
        detail,
      );
    }
    const blob = await response.blob();
    const objectUrl = URL.createObjectURL(blob);
    // Use a transient anchor so the print-ready page lands in its own tab.
    const a = document.createElement('a');
    a.href = objectUrl;
    a.target = '_blank';
    a.rel = 'noopener';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    // Hold the blob URL long enough for the new tab to read it, then release.
    setTimeout(() => URL.revokeObjectURL(objectUrl), 60_000);
  },
};

// ─── Investigation Ledger (persistent agent decision log) ───────────────────
//
// Backed by /v1/investigations endpoints. Every event the agent emits during
// an investigation is durably stored and replayable forever. The ledger UI
// renders this as a per-step timeline + side-panel "explain" view.

export interface LedgerRunSummary {
  id: string;
  case_id: string;
  status: 'running' | 'completed' | 'failed' | string;
  model_used: string | null;
  iterations: number;
  total_tokens: number;
  total_cost_usd: number;
  started_at: string;
  completed_at: string | null;
  error: string | null;
}

export interface LedgerModelCost {
  model: string;
  total_prompt_tokens: number;
  total_completion_tokens: number;
  total_cost_usd: number;
  total_latency_ms: number;
  call_count: number;
}

export interface LedgerRunDetail extends LedgerRunSummary {
  alert_summary: string | null;
  event_count: number;
  artifact_count: number;
  /**
   * Per-model token/spend/latency breakdown. Empty list when the run pre-dates
   * the cost-telemetry rollout or used no LLM models.
   */
  model_costs: LedgerModelCost[];
}

export interface LedgerEvent {
  id: string;
  run_id: string;
  seq: number;
  ts: string;
  kind: string;
  agent: string;
  summary: string;
  payload: Record<string, unknown> | null;
  input_hash: string | null;
  output_hash: string | null;
  duration_ms: number;
}

export interface LedgerEventList {
  items: LedgerEvent[];
  total: number;
  since: number | null;
  next_seq: number | null;
}

export interface LedgerArtifactSummary {
  id: string;
  kind: string;
  sha256: string;
  size_bytes: number;
  event_id: string | null;
  created_at: string;
}

export interface LedgerArtifactDetail extends LedgerArtifactSummary {
  content: string | null;
  blob_ref: string | null;
}

export interface LedgerExplain {
  run: LedgerRunSummary;
  previous: LedgerEvent | null;
  focus: LedgerEvent;
  next: LedgerEvent | null;
  artifacts: LedgerArtifactDetail[];
}

export const ledgerApi = {
  /** List investigation runs for the current tenant (optionally scoped to a case). */
  listRuns: (params?: { caseId?: string; status?: string; limit?: number }) =>
    request<LedgerRunSummary[]>('/api/v1/investigations', {
      params: {
        case_id: params?.caseId,
        status: params?.status,
        limit: params?.limit,
      },
    }),

  /** Run summary + counts of attached events/artifacts. */
  getRun: (runId: string) =>
    request<LedgerRunDetail>(`/api/v1/investigations/${runId}`),

  /** Paginated event timeline. Use `since` to tail. */
  listEvents: (runId: string, params?: { since?: number; limit?: number }) =>
    request<LedgerEventList>(`/api/v1/investigations/${runId}/events`, {
      params: { since: params?.since, limit: params?.limit },
    }),

  /** Full ordered event list (bounded). */
  replay: (runId: string, maxEvents = 10000) =>
    request<LedgerEvent[]>(`/api/v1/investigations/${runId}/replay`, {
      params: { max_events: maxEvents },
    }),

  /** "Why did the agent do this?" — previous → focus → next plus inlined artifacts. */
  explain: (runId: string, step: number) =>
    request<LedgerExplain>(`/api/v1/investigations/${runId}/explain`, {
      params: { step },
    }),

  /** Artifact list for a run. */
  listArtifacts: (runId: string) =>
    request<LedgerArtifactSummary[]>(
      `/api/v1/investigations/${runId}/artifacts`,
    ),

  /** Single artifact (full inlined content). */
  getArtifact: (runId: string, artifactId: string) =>
    request<LedgerArtifactDetail>(
      `/api/v1/investigations/${runId}/artifacts/${artifactId}`,
    ),
};

// ─── Metrics / Dashboard ─────────────────────────────────────────────────────

export interface DashboardMetrics {
  alerts: {
    total: number;
    new: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info?: number;
    resolvedToday: number;
    mttr: number;
  };
  cases: {
    open: number;
    inProgress: number;
    resolvedThisWeek: number;
  };
  sources: Array<{ name: string; count: number; status: string }>;
  topMitre: Array<{ tactic: string; count: number }>;
  alertsTrend: Array<{ timestamp: string; count: number; severity: string }>;
  threatsBySource: Array<{ source: string; count: number }>;
}

/**
 * Funnel KPI metrics (PR-3 / W1).
 *
 * Mirrors ``FunnelMetrics`` Pydantic model in
 * ``services/api/app/api/v1/endpoints/metrics.py``. Drives the
 * ``FunnelKpiBar`` and ``EfficiencyReport`` widgets on the dashboard.
 */
export interface FunnelMetrics {
  period: '1h' | '24h' | '7d' | '30d';
  events_of_interest: number;
  correlation_instances: number;
  alerts_generated: number;
  /** 0..1 ratio: 1 − (FP / total dispositioned alerts). */
  signal_to_noise: number;
  /** Mean time-to-detect in seconds (Alert.created_at → first_seen_at). */
  mttd_seconds: number;
  /** Active alerts owned by analysts (`status in new/triaging/in_progress`). */
  analyst_queue_depth: number;
  /** Alerts produced per correlation instance, clamped to [0, 1]. */
  correlation_efficiency: number;
  /** Alerts produced per event-of-interest, clamped to [0, 1]. */
  alert_yield: number;
  mitre_coverage: { covered: number; total: number; ratio: number };
  /** Period-over-period deltas (fraction, e.g. 0.05 = +5%). */
  deltas: {
    events_of_interest: number;
    correlation_instances: number;
    alerts_generated: number;
    signal_to_noise: number;
    mttd_seconds: number;
    analyst_queue_depth: number;
  };
  /** ISO-8601 server timestamp. */
  generated_at: string;
}

/**
 * Pipeline health (PR-3 / W9).
 *
 * Mirrors ``PipelineHealth`` Pydantic model. Drives the
 * ``PipelineHealth`` strip on /dashboard.
 */
export interface PipelineStage {
  stage: 'ingest' | 'normalize' | 'fuse' | 'correlate' | 'alert';
  backlog: number;
  p95_latency_ms: number;
  error_rate: number;
  status: 'unknown' | 'green' | 'yellow' | 'red';
}

export interface PipelineHealth {
  /** Worst stage status, surfaced at the top of the pipeline rail. */
  overall_status: 'unknown' | 'green' | 'yellow' | 'red';
  stages: PipelineStage[];
  /** ISO-8601 server timestamp. */
  generated_at: string;
}

export const metricsApi = {
  getDashboard: () =>
    request<DashboardMetrics>('/api/v1/metrics/dashboard'),

  getAlertTrend: (period: '1h' | '24h' | '7d' | '30d') =>
    request<{ data: Array<{ timestamp: string; count: number }> }>(
      `/api/v1/metrics/alerts/trend`,
      {
        params: { period },
      },
    ),

  /** Funnel KPIs (events → correlations → alerts) with deltas. */
  getFunnel: (period: '1h' | '24h' | '7d' | '30d' = '24h') =>
    request<FunnelMetrics>('/api/v1/metrics/funnel', { params: { period } }),

  /** Per-stage pipeline health (ingest → normalize → fuse → correlate → alert). */
  getPipelineHealth: () =>
    request<PipelineHealth>('/api/v1/health/pipeline'),
};

// ─── Connectors ──────────────────────────────────────────────────────────────

export type ConnectorStatus =
  | 'active'
  | 'inactive'
  | 'error'
  | 'configuring';

export interface Connector {
  id: string;
  name: string;
  type: string;
  status: ConnectorStatus;
  /** `true` when the connector is enabled (separate from runtime status). */
  enabled?: boolean;
  tenantId?: string;
  category?: string;
  config?: Record<string, unknown>;
  lastSync?: string;
  /** Number of alerts ingested through this connector. */
  alertCount?: number;
  alertsIngested?: number;
  errorMessage?: string;
  description?: string;
  createdAt?: string;
  updatedAt?: string;
  /** SHA-256 fingerprint of the most recent normalized event schema. */
  schemaFingerprint?: string;
  /** Timestamp of the most recent schema-drift event (null/undef if never). */
  lastSchemaDriftAt?: string;
  /** Human-readable diff for the most recent drift event. */
  lastDriftDetails?: {
    added?: string[];
    removed?: string[];
    previous_fingerprint?: string;
  };
  /** Cumulative count of events the pre-ingest filter dropped. */
  eventsDropped?: number;
  /**
   * Timestamp of the most recently *ingested* normalized event.
   *
   * Distinct from `lastSync`, which advances on every poll cycle.
   * `lastEventAt` only advances when an event actually lands — it's
   * what feeds the freshness-SLO badge in the connectors list and
   * the onboarding "verify data flowing" screen.
   */
  lastEventAt?: string;
  /** Short label for the most recent event source (e.g. "alert", "audit"). */
  lastEventKind?: string;
  /**
   * Live freshness SLO verdict for the connector instance (Workstream 5).
   *
   * The server computes this from ``lastEventAt`` against a per-category
   * cadence table (5 min for EDR, 15 min for SIEM, etc.) so a single
   * Splunk that polls slowly doesn't drag the whole fleet to yellow. The
   * UI badge renders directly from ``status`` — no client-side rule
   * duplication so a future cadence change ships in one place.
   */
  freshness?: {
    status: 'green' | 'yellow' | 'red' | 'unknown';
    expected_cadence_seconds: number;
    seconds_since_last_event: number | null;
    category: string;
  };
}

export interface ConnectorsResponse {
  connectors: Connector[];
  total: number;
}

/** A single config field surfaced by ``BaseConnector.schema()`` on the backend. */
export interface ConnectorSchemaField {
  name: string;
  type: 'string' | 'secret' | 'select' | 'textarea' | 'boolean' | 'number';
  label: string;
  required?: boolean;
  default?: string | number | boolean | null;
  placeholder?: string;
  help_text?: string;
  options?: Array<{ value: string; label: string }>;
}

/** Forward-looking OAuth hints; rendered as "Hosted OAuth coming soon". */
export interface ConnectorOAuthHints {
  supported_in_hosted?: boolean;
  authorize_url?: string;
  token_url?: string;
  scopes?: string[];
}

/** A catalog entry: one available connector type with its config schema. */
export interface ConnectorCatalogEntry {
  connector_id: string;
  connector_name: string;
  category: string;
  description: string;
  fields: ConnectorSchemaField[];
  docs_url?: string;
  oauth?: ConnectorOAuthHints;
}

export interface ConnectorCatalogResponse {
  connectors: ConnectorCatalogEntry[];
}

/** Result of a "Test connection" call (pre-save or against a saved instance). */
export interface ConnectorTestResult {
  success: boolean;
  message?: string;
  error?: string;
  latency_ms?: number;
  latencyMs?: number;
  details?: Record<string, unknown>;
}

/** Raw shape returned by the API for a connector instance row. */
interface BackendConnectorResponse {
  id: string;
  tenant_id: string;
  name: string;
  connector_type: string;
  category: string;
  is_enabled: boolean;
  connector_config: Record<string, unknown>;
  health_status: string;
  last_health_check: string | null;
  last_sync: string | null;
  events_ingested: number;
  error_count: number;
  tags: string[];
  created_at: string;
  updated_at: string;
  schema_fingerprint?: string | null;
  last_schema_drift_at?: string | null;
  last_drift_details?: {
    added?: string[];
    removed?: string[];
    previous_fingerprint?: string;
  } | null;
  events_dropped?: number | null;
  // Workstream 1: distinct from `last_sync` — only advances when a
  // normalized event actually lands. The verify-data-flowing screen
  // and freshness-SLO badge both read from here.
  last_event_at?: string | null;
  last_event_kind?: string | null;
  // Workstream 5: freshness SLO computed server-side from ``last_event_at``
  // against a per-category cadence table. Optional because the API may
  // omit it for connectors that haven't ingested yet (the server still
  // emits an ``unknown`` verdict, but defensive null-handling lets the
  // UI degrade gracefully if the field is ever stripped).
  freshness?: {
    status: 'green' | 'yellow' | 'red' | 'unknown';
    expected_cadence_seconds: number;
    seconds_since_last_event: number | null;
    category: string;
  } | null;
}

/** Aggregated health summary for the connectors fleet (a single tenant). */
export interface ConnectorHealthSummary {
  total: number;
  healthy: number;
  unhealthy: number;
  unknown: number;
  /** Connectors whose schema has ever drifted. */
  drifted: number;
  /** Connectors whose schema drifted in the last 24h. */
  driftedRecently: number;
  /** Most-recent drift timestamp across the fleet. */
  lastDriftAt?: string;
  /** Cumulative events ingested across all enabled connectors. */
  totalEventsIngested: number;
  /** Cumulative events dropped by pre-ingest filter rules. */
  totalEventsDropped: number;
}

/**
 * Map the backend ``health_status`` enum (``healthy``/``unhealthy``/``unknown``)
 * to the frontend ``ConnectorStatus`` (``active``/``inactive``/``error``/
 * ``configuring``). The mapping also folds in ``is_enabled`` because a disabled
 * connector should always render as ``inactive`` in the UI regardless of its
 * last health check.
 */
function deriveConnectorStatus(row: BackendConnectorResponse): ConnectorStatus {
  if (!row.is_enabled) return 'inactive';
  switch (row.health_status) {
    case 'healthy':
      return 'active';
    case 'unhealthy':
    case 'error':
      return 'error';
    case 'unknown':
    case '':
      return 'configuring';
    default:
      return 'configuring';
  }
}

function mapBackendConnector(row: BackendConnectorResponse): Connector {
  return {
    id: row.id,
    name: row.name,
    type: row.connector_type,
    category: row.category,
    status: deriveConnectorStatus(row),
    enabled: row.is_enabled,
    tenantId: row.tenant_id,
    config: row.connector_config,
    lastSync: row.last_sync ?? undefined,
    alertCount: row.events_ingested,
    alertsIngested: row.events_ingested,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    schemaFingerprint: row.schema_fingerprint ?? undefined,
    lastSchemaDriftAt: row.last_schema_drift_at ?? undefined,
    lastDriftDetails: row.last_drift_details ?? undefined,
    eventsDropped: row.events_dropped ?? 0,
    lastEventAt: row.last_event_at ?? undefined,
    lastEventKind: row.last_event_kind ?? undefined,
    freshness: row.freshness ?? undefined,
  };
}

export interface CreateConnectorPayload {
  name: string;
  connector_type: string;
  category?: string;
  auth_config?: Record<string, unknown>;
  connector_config?: Record<string, unknown>;
  tags?: string[];
}

export interface UpdateConnectorPayload {
  name?: string;
  is_enabled?: boolean;
  auth_config?: Record<string, unknown>;
  connector_config?: Record<string, unknown>;
  tags?: string[];
}

export interface TestConnectorPayload {
  connector_type: string;
  auth_config?: Record<string, unknown>;
  connector_config?: Record<string, unknown>;
}

/**
 * Watermark response polled by the wizard's "verify data flowing" panel.
 *
 * The shape mirrors ``LastEventResponse`` from the API service. Note
 * the field is intentionally distinct from ``last_sync``: ``last_sync``
 * advances on every poll cycle (including empty polls), while
 * ``last_event_at`` only advances when a normalized event actually
 * lands in ``raw_events``. ``data_flowing`` is the server's own
 * answer to "is data live?" so every client agrees on the rule.
 */
export interface ConnectorLastEvent {
  connector_id: string;
  last_event_at: string | null;
  last_event_kind: string | null;
  events_ingested: number;
  last_sync: string | null;
  health_status: string;
  data_flowing: boolean;
}

/**
 * Input to the AI troubleshooter. We intentionally send only the
 * **keys** of ``auth_config`` (not values) so the backend can hint
 * about which field to revisit without ever seeing the credential.
 */
export interface TroubleshootRequest {
  connector_type: string;
  error: string;
  auth_config_keys?: string[];
}

/** Structured fix suggestion the wizard renders next to a failed test. */
export interface TroubleshootResponse {
  likely_cause: string;
  fix_steps: string[];
  doc_link?: string | null;
}

/** Push-token reveal response. */
export interface IngestTokenResponse {
  connector_id: string;
  ingest_token: string;
  inbox_url: string;
}

export const connectorsApi = {
  /**
   * List connector instances for the current tenant.
   *
   * The backend returns a raw ``list[ConnectorResponse]``; we wrap it in a
   * ``ConnectorsResponse`` envelope and map each row from snake_case to the
   * camelCase frontend shape so views never have to reach into raw API rows.
   */
  list: async (): Promise<ConnectorsResponse> => {
    const rows = await request<BackendConnectorResponse[]>(
      '/api/v1/connectors',
    );
    const connectors = rows.map(mapBackendConnector);
    return { connectors, total: connectors.length };
  },

  /** Catalog of available connector types (one entry per registered class). */
  catalog: () =>
    request<ConnectorCatalogResponse>('/api/v1/connectors/catalog'),

  get: async (id: string): Promise<Connector> => {
    const row = await request<BackendConnectorResponse>(
      `/api/v1/connectors/${id}`,
    );
    return mapBackendConnector(row);
  },

  create: async (data: CreateConnectorPayload): Promise<Connector> => {
    const row = await request<BackendConnectorResponse>('/api/v1/connectors', {
      method: 'POST',
      body: JSON.stringify(data),
    });
    return mapBackendConnector(row);
  },

  update: async (
    id: string,
    data: UpdateConnectorPayload,
  ): Promise<Connector> => {
    const row = await request<BackendConnectorResponse>(
      `/api/v1/connectors/${id}`,
      {
        method: 'PATCH',
        body: JSON.stringify(data),
      },
    );
    return mapBackendConnector(row);
  },

  /** Run "Test connection" against a saved instance. */
  test: (id: string) =>
    request<ConnectorTestResult>(`/api/v1/connectors/${id}/test`, {
      method: 'POST',
    }),

  /** Run "Test connection" with un-saved credentials from the wizard. */
  testInline: (payload: TestConnectorPayload) =>
    request<ConnectorTestResult>('/api/v1/connectors/test', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  /**
   * Ask the AI troubleshooter to classify a failed test.
   *
   * Used by the AddConnector wizard immediately after `test` or
   * `testInline` returns ``success=false``. Renders into the
   * "Likely cause / fix steps / docs" callout in the modal.
   */
  troubleshoot: (payload: TroubleshootRequest) =>
    request<TroubleshootResponse>('/api/v1/connectors/troubleshoot', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  /**
   * Poll the verify-data-flowing watermark for a connector.
   *
   * Distinct from `lastSync`: this only advances when an actual
   * normalized event lands. Returned even when no event has ever
   * landed (with `data_flowing=false`) so the polling loop can have
   * stable shape rather than a 404.
   */
  lastEvent: (id: string) =>
    request<ConnectorLastEvent>(`/api/v1/connectors/${id}/last_event_at`),

  /**
   * Generate or rotate the per-connector push-ingest token.
   *
   * Used by the wizard's "Push (any vendor)" path to surface a
   * `curl` example. Calling this rotates the token; the previous
   * one is invalidated immediately.
   */
  refreshIngestToken: (id: string) =>
    request<IngestTokenResponse>(`/api/v1/connectors/${id}/push/refresh`, {
      method: 'POST',
    }),

  delete: (id: string) =>
    request<void>(`/api/v1/connectors/${id}`, { method: 'DELETE' }),

  /**
   * Aggregated health summary for the connectors fleet.
   *
   * Surfaces healthy/degraded/error counts, schema-drift events seen in the
   * last 24h, and the cumulative count of events the pre-ingest filter
   * dropped. Used by the Connectors page header strip and the new
   * "Connector Health" widget on the dashboard.
   */
  health: async (): Promise<ConnectorHealthSummary> => {
    const raw = await request<{
      total: number;
      healthy: number;
      unhealthy: number;
      unknown: number;
      drifted: number;
      drifted_recently: number;
      last_drift_at: string | null;
      total_events_ingested: number;
      total_events_dropped: number;
    }>('/api/v1/connectors/health');
    return {
      total: raw.total,
      healthy: raw.healthy,
      unhealthy: raw.unhealthy,
      unknown: raw.unknown,
      drifted: raw.drifted,
      driftedRecently: raw.drifted_recently,
      lastDriftAt: raw.last_drift_at ?? undefined,
      totalEventsIngested: raw.total_events_ingested,
      totalEventsDropped: raw.total_events_dropped,
    };
  },
};

// ─── Universal capture / inbox tokens (Workstream 6) ───────────────────────

/**
 * Catalog entry for a vendor template the operator can pick when minting
 * an inbox URL. Mirrors `InboxTemplateInfo` on the API side; the wizard
 * groups by `category` to keep the picker scannable.
 */
export interface InboxTemplate {
  template_id: string;
  label: string;
  description: string;
  category: string;
}

/** Existing inbox token row — list view, plaintext token NOT included. */
export interface InboxTokenListItem {
  fingerprint: string;
  template_id: string;
  label: string | null;
  has_hmac_secret: boolean;
  created_at: string;
  revoked_at: string | null;
  last_used_at: string | null;
}

/**
 * Mint / rotate response. `token` is the plaintext (returned exactly once
 * at mint or rotate time); `inbox_url` is the absolute URL the operator
 * pastes into the vendor's webhook config.
 */
export interface InboxTokenSecret {
  token: string;
  inbox_url: string;
  template_id: string;
  label: string | null;
  has_hmac_secret: boolean;
  created_at: string;
  revoked_at: string | null;
  last_used_at: string | null;
}

/** Body for `POST /api/v1/inbox/tokens`. */
export interface MintInboxTokenPayload {
  template_id: string;
  label?: string | null;
  hmac_secret?: string | null;
}

export const inboxApi = {
  /** List vendor templates the operator can mint inbox URLs for. */
  templates: () => request<InboxTemplate[]>('/api/v1/inbox/templates'),

  /** List the calling tenant's inbox tokens (revoked filtered out). */
  list: (params?: { include_revoked?: boolean }) => {
    const qs = params?.include_revoked ? '?include_revoked=true' : '';
    return request<InboxTokenListItem[]>(`/api/v1/inbox/tokens${qs}`);
  },

  /** Mint a new inbox token. Plaintext returned exactly once. */
  mint: (payload: MintInboxTokenPayload) =>
    request<InboxTokenSecret>('/api/v1/inbox/tokens', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  /**
   * Rotate an existing token: mints a new one with the same template / label
   * / HMAC, revokes the old. Returns the new plaintext exactly once.
   */
  rotate: (fingerprint: string) =>
    request<InboxTokenSecret>(
      `/api/v1/inbox/tokens/${encodeURIComponent(fingerprint)}/rotate`,
      { method: 'POST' },
    ),

  /** Permanently revoke an inbox token. */
  revoke: (fingerprint: string) =>
    request<void>(
      `/api/v1/inbox/tokens/${encodeURIComponent(fingerprint)}`,
      { method: 'DELETE' },
    ),
};

// ─── Hosted OAuth (Workstream 2) ──────────────────────────────────────────────

/**
 * Per-tenant OAuth client registration, returned by GET / PUT
 * `/api/v1/oauth/app/{connector_type}`.
 *
 * The secret is *never* round-tripped to the browser — only `has_secret`
 * lets the UI render a "credential present" badge. To rotate the
 * client_secret, call `oauthApi.upsertApp()` with a fresh value.
 */
export interface OAuthAppView {
  connector_type: string;
  client_id: string;
  has_secret: boolean;
  authorize_url: string | null;
  token_url: string | null;
  scopes: string[] | null;
  created_at: string;
  updated_at: string;
}

/**
 * Payload accepted by `PUT /api/v1/oauth/app/{connector_type}`.
 *
 * `authorize_url`, `token_url`, and `scopes` are optional — when omitted,
 * the backend falls back to the connector class's `OAuthHints` defaults
 * (e.g. Okta / Azure AD / GitHub).
 */
export interface OAuthAppRegistrationPayload {
  client_id: string;
  client_secret: string;
  authorize_url?: string | null;
  token_url?: string | null;
  scopes?: string[] | null;
}

/**
 * Response from `GET /api/v1/oauth/start?response_mode=json`.
 *
 * The default `response_mode=redirect` returns a 302; SPAs that want to
 * handle the redirect themselves (e.g. open the consent screen in a
 * popup) call with `response_mode=json` and use this shape.
 */
export interface OAuthStartResponse {
  authorize_url: string;
  state: string;
}

/**
 * Options for `oauthApi.startUrl()` — the helper that builds the
 * canonical `/api/v1/oauth/start?...` URL the browser navigates to.
 *
 * `connector_id` is set when the operator is *re-authing* an existing
 * connector instance (token expired, scope upgrade); otherwise omit it
 * and the callback will INSERT a fresh `connectors` row.
 *
 * `extras` ride along in the state row and end up in the connector's
 * `connector_config` after callback (e.g. `organization` for GitHub,
 * `cloud_id` for Atlassian).
 */
export interface OAuthStartOptions {
  connectorType: string;
  connectorId?: string;
  returnTo?: string;
  name?: string;
  extras?: Record<string, unknown>;
}

export const oauthApi = {
  /**
   * Fetch the registered OAuth app for a connector class. Returns 404
   * until the operator has called `upsertApp()` at least once.
   */
  getApp: (connectorType: string) =>
    request<OAuthAppView>(
      `/api/v1/oauth/app/${encodeURIComponent(connectorType)}`,
    ),

  /**
   * Register or rotate the tenant's OAuth client for a connector class.
   * The backend encrypts `client_secret` at rest via the credential vault.
   */
  upsertApp: (
    connectorType: string,
    payload: OAuthAppRegistrationPayload,
  ) =>
    request<OAuthAppView>(
      `/api/v1/oauth/app/${encodeURIComponent(connectorType)}`,
      {
        method: 'PUT',
        body: JSON.stringify(payload),
      },
    ),

  /** Unregister the tenant's OAuth client for a connector class. */
  deleteApp: (connectorType: string) =>
    request<void>(
      `/api/v1/oauth/app/${encodeURIComponent(connectorType)}`,
      { method: 'DELETE' },
    ),

  /**
   * Build the `/api/v1/oauth/start?...` URL. The caller does
   * `window.location.assign(oauthApi.startUrl({...}))` to kick off the
   * hosted OAuth dance — we don't fetch this ourselves because the
   * server response is a 302 to the provider, not JSON the SPA wants
   * to parse.
   *
   * Returns a same-origin URL so Next.js rewrites can proxy to the API.
   */
  startUrl: (opts: OAuthStartOptions): string => {
    const params = new URLSearchParams();
    params.set('connector_type', opts.connectorType);
    if (opts.connectorId) params.set('connector_id', opts.connectorId);
    if (opts.returnTo) params.set('return_to', opts.returnTo);
    if (opts.name) params.set('name', opts.name);
    if (opts.extras && Object.keys(opts.extras).length > 0) {
      params.set('extras', JSON.stringify(opts.extras));
    }
    return `${API_BASE}/api/v1/oauth/start?${params.toString()}`;
  },

  /**
   * JSON variant of `startUrl()`: instead of redirecting, the API
   * returns `{ authorize_url, state }` so a popup-based UX can drive
   * the consent screen itself.
   */
  startJson: (opts: OAuthStartOptions) => {
    const params: Record<string, string> = {
      connector_type: opts.connectorType,
      response_mode: 'json',
    };
    if (opts.connectorId) params.connector_id = opts.connectorId;
    if (opts.returnTo) params.return_to = opts.returnTo;
    if (opts.name) params.name = opts.name;
    if (opts.extras && Object.keys(opts.extras).length > 0) {
      params.extras = JSON.stringify(opts.extras);
    }
    return request<OAuthStartResponse>('/api/v1/oauth/start', { params });
  },
};

// ─── Threat Intel ─────────────────────────────────────────────────────────────

export type IndicatorType = 'ip' | 'domain' | 'hash' | 'url' | 'email';

/**
 * A canonical threat indicator surfaced by the threatintel service.
 *
 * Carries the analyst-facing fields used by the IOC inbox (severity,
 * confidence, tags) plus the raw lookup data (sources, geo, ASN).
 */
export interface ThreatIndicator {
  id: string;
  type: IndicatorType;
  value: string;
  /** 0-100 confidence score blended across providers. */
  confidence: number;
  severity: AlertSeverity;
  malicious: boolean;
  tags?: string[];
  sources: string[];
  firstSeen?: string;
  lastSeen?: string;
  description?: string;
  country?: string;
  asn?: string;
  mitre?: string[];
}

export interface IOCLookup extends ThreatIndicator {
  /** Free-form provider blob (kept around for power users). */
  raw?: Record<string, unknown>;
}

export const threatIntelApi = {
  lookup: (ioc: string) =>
    request<IOCLookup>('/api/v1/enrichment/lookup', {
      params: { ioc },
    }),

  bulkLookup: (iocs: string[]) =>
    request<{ results: IOCLookup[] }>('/api/v1/enrichment/bulk', {
      method: 'POST',
      body: JSON.stringify({ iocs }),
    }),

  list: (filters: { type?: IndicatorType; tag?: string; q?: string } = {}) =>
    request<{ indicators: ThreatIndicator[]; total: number }>(
      '/api/v1/threat-intel/indicators',
      { params: filters as Record<string, string> },
    ),
};

// ─── AI Agents ────────────────────────────────────────────────────────────────

export interface AgentInvestigation {
  id: string;
  alertId: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  findings?: string;
  recommendations?: string[];
  actions?: Array<{ type: string; target: string; status: string }>;
  startedAt: string;
  completedAt?: string;
}

export const agentsApi = {
  investigate: (alertId: string) =>
    request<AgentInvestigation>('/api/v1/agents/investigate', {
      method: 'POST',
      body: JSON.stringify({ alertId }),
    }),

  getInvestigation: (id: string) =>
    request<AgentInvestigation>(`/api/v1/agents/investigations/${id}`),

  /**
   * Stream an investigation as Server-Sent Events / NDJSON. Returns the
   * raw `Response` so callers can pipe to a reader.
   */
  streamInvestigation: (alertId: string, signal?: AbortSignal) =>
    fetch(`${AGENTS_BASE}/api/v1/agents/investigate/stream`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Tenant-Id': TENANT_ID,
      },
      body: JSON.stringify({ alertId }),
      signal,
    }),

  /**
   * Stream a structured "Explain this alert" walkthrough as NDJSON.
   *
   * Each line in `response.body` is one {@link ExplainStreamFrame}.
   * Returns the raw `Response` because the drawer renders frames as
   * they arrive — see `ExplainDrawer.tsx` for the consumer.
   */
  explainStream: (
    payload: { alert: Record<string, unknown>; alertId?: string },
    signal?: AbortSignal,
  ) =>
    fetch(`${AGENTS_BASE}/api/v1/explain`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Tenant-Id': TENANT_ID,
      },
      body: JSON.stringify({
        alert: payload.alert,
        alert_id: payload.alertId,
        tenant_id: TENANT_ID,
      }),
      signal,
    }),
};

// ─── Explain endpoint frames ─────────────────────────────────────────────────
//
// One frame per NDJSON line. The drawer routes each frame by `kind` and
// appends to the matching section, so order matters: `section` opens a
// section, subsequent typed frames fill it, and `done` closes the stream.

export interface ExplainSectionFrame {
  kind: 'section';
  id: 'summary' | 'ocsf' | 'mitre' | 'evidence' | 'next';
  title: string;
}

export interface ExplainDeltaFrame {
  kind: 'delta';
  section: 'summary';
  text: string;
}

export interface ExplainOcsfFrame {
  kind: 'ocsf';
  category: string;
  category_uid: number;
  class: string;
  class_uid: number;
  activity: string;
  fields: Record<string, unknown>;
}

export interface ExplainMitreFrame {
  kind: 'mitre';
  id: string;
  name: string;
  tactic_names: string[];
  description: string;
  url: string;
  found: boolean;
}

export interface ExplainEvidenceFrame {
  kind: 'evidence';
  label: string;
  value: string;
  annotation: string;
}

export interface ExplainNextStepFrame {
  kind: 'next_step';
  title: string;
  rationale: string;
  playbook_id: string | null;
}

export interface ExplainDoneFrame {
  kind: 'done';
  alert_id: string;
}

export interface ExplainErrorFrame {
  kind: 'error';
  error: string;
}

export type ExplainStreamFrame =
  | ExplainSectionFrame
  | ExplainDeltaFrame
  | ExplainOcsfFrame
  | ExplainMitreFrame
  | ExplainEvidenceFrame
  | ExplainNextStepFrame
  | ExplainDoneFrame
  | ExplainErrorFrame;

// ─── Structured Alert Explanation (POST /api/v1/alerts/{id}/explain) ────────
//
// Stage 2 #6 added a *structured* one-shot explainer alongside the agents
// service's NDJSON streaming explainer. Where the stream emits tokens for
// a typewriter UX, this endpoint returns the *whole* answer in one JSON
// envelope — including richer context the streaming endpoint doesn't have:
//
//   * `rule_lineage`        — which detection rule fired (best-effort,
//                              with a confidence band on the match itself)
//   * `historical_fp_rate`  — live false-positive rate over the last 30
//                              days, scoped to rule, technique, category,
//                              or tenant (whichever has enough samples)
//   * deterministic-or-LLM `summary` (with `llm_used` + `llm_reason` so
//      the UI can disclose when the prose was generated vs. fallback)
//
// The dataclass shape mirrors `services/api/app/services/alert_explain.py`.
// Keep the two in sync; the backend serializes via `dataclasses.asdict`.

/** Lineage of the detection rule that produced an alert. */
export interface RuleLineage {
  rule_id: string | null;
  rule_name: string | null;
  rule_description: string | null;
  rule_status: string | null;
  rule_severity: string | null;
  rule_confidence: number | null;
  rule_language: string | null;
  is_builtin: boolean;
  /** Confidence in the lineage *match itself*, not the rule's own confidence. */
  confidence: 'high' | 'medium' | 'low';
  /**
   * How the lineage was resolved. `none` means we couldn't match any rule.
   * `raw_event` / `tags` are deterministic; `mitre_overlap` and `category`
   * are best-effort guesses.
   */
  match_method: 'raw_event' | 'tags' | 'mitre_overlap' | 'category' | 'none';
}

/** Live false-positive rate for the matched rule (or fallback scope). */
export interface HistoricalFpRate {
  fp_rate: number;
  sample_size: number;
  false_positives: number;
  lookback_days: number;
  /** Which scope was used. Narrower = more relevant; broader = more samples. */
  scope: 'rule' | 'category' | 'technique' | 'tenant';
  /** Human-readable description of which scope was used and why. */
  notes: string;
}

/** A deterministic, hand-curated suggested next step. */
export interface SuggestedAction {
  title: string;
  rationale: string;
  /** ID of a playbook the user can launch directly, or null if N/A. */
  playbook_id: string | null;
  priority: 'immediate' | 'soon' | 'fyi';
}

/** A single signal from the raw event that contributed to the alert. */
export interface ContributingEvent {
  label: string;
  value: string;
  /** Optional hint about why this signal mattered (e.g. "matched rule pattern"). */
  annotation?: string;
}

/** Resolved MITRE ATT&CK technique card (id, name, tactics, link). */
export interface MitreTechniqueCard {
  id: string;
  name: string;
  tactic_names: string[];
  description: string;
  url: string;
}

/** Top-level structured explanation envelope. */
export interface AlertExplanation {
  alert_id: string;
  summary: string;
  rule_lineage: RuleLineage;
  contributing_events: ContributingEvent[];
  mitre_techniques: MitreTechniqueCard[];
  historical_fp_rate: HistoricalFpRate;
  suggested_actions: SuggestedAction[];
  /** True when the summary was LLM-generated; false → deterministic fallback. */
  llm_used: boolean;
  /** Source of the summary: `tenant_byok`, `platform_default`, `deterministic`, etc. */
  llm_source: string;
  /** When `llm_used=false`, why we fell back (e.g. `airgap_blocked`, `no_credential`). */
  llm_reason: string;
  /** ISO-8601 timestamp the explanation was generated. */
  generated_at: string;
}

// ─── Hunt / Search ───────────────────────────────────────────────────────────

export interface HuntQuery {
  query: string;
  language?: 'kql' | 'lucene' | 'sql' | 'esql';
  startTime?: string;
  endTime?: string;
  limit?: number;
}

export interface HuntResult {
  id: string;
  timestamp: string;
  source: string;
  severity?: AlertSeverity;
  fields: Record<string, unknown>;
  highlight?: string;
}

export interface HuntResponse {
  total: number;
  took: number;
  hits: HuntResult[];
}

export interface SavedSearch {
  id: string;
  name: string;
  query: string;
  language: string;
  createdAt: string;
  pinned?: boolean;
}

export const huntApi = {
  search: (query: HuntQuery) =>
    request<HuntResponse>('/api/v1/hunt/search', {
      method: 'POST',
      body: JSON.stringify(query),
    }),

  listSaved: () =>
    request<{ searches: SavedSearch[] }>('/api/v1/hunt/saved'),

  saveSearch: (data: Pick<SavedSearch, 'name' | 'query' | 'language'>) =>
    request<SavedSearch>('/api/v1/hunt/saved', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  deleteSaved: (id: string) =>
    request<void>(`/api/v1/hunt/saved/${id}`, { method: 'DELETE' }),
};

// ─── Attack Graph (Neo4j) ────────────────────────────────────────────────────

export type GraphNodeKind =
  | 'host'
  | 'user'
  | 'ip'
  | 'domain'
  | 'hash'
  | 'process'
  | 'technique'
  | 'tactic'
  | 'alert'
  | 'asset';

export interface GraphNode {
  id: string;
  label: string;
  kind: GraphNodeKind;
  riskScore?: number;
  severity?: AlertSeverity;
  attributes?: Record<string, unknown>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  weight?: number;
  attributes?: Record<string, unknown>;
}

export interface AttackGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  generatedAt: string;
}

export interface AttackPath {
  id: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  totalRisk: number;
  hops: number;
}

export interface MitreCoverageCell {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  detections: number;
  alerts: number;
  /** 0-1 normalized coverage for heatmap shading. */
  intensity: number;
}

export interface MitreCoverage {
  tactics: string[];
  cells: MitreCoverageCell[];
  generatedAt: string;
}

/**
 * Case-scoped attack path graph as returned by the Attack-Path Investigation
 * Agent backend (`/api/v1/graph/attack-path/{case_id}`). Distinct from the
 * tenant-level `AttackGraph` overview because the backend payload schema is
 * leaner: each node carries a `properties` dict and edges carry a relationship
 * `type` instead of label/weight metadata.
 */
export interface CaseAttackPathNode {
  id: string;
  label: string;
  properties: Record<string, unknown>;
}

export interface CaseAttackPathEdge {
  source: string;
  target: string;
  type: string;
}

export interface CaseAttackPath {
  caseId: string;
  nodes: CaseAttackPathNode[];
  edges: CaseAttackPathEdge[];
  nodeCount: number;
  edgeCount: number;
}

interface BackendCaseAttackPathResponse {
  case_id: string;
  nodes: CaseAttackPathNode[];
  edges: CaseAttackPathEdge[];
  node_count: number;
  edge_count: number;
}

export const graphApi = {
  getOverview: (filters: { entity?: string; depth?: number } = {}) =>
    request<AttackGraph>('/api/v1/graph', {
      params: filters as Record<string, string | number>,
    }),

  getPaths: (entity: string, options: { maxHops?: number } = {}) =>
    request<{ paths: AttackPath[] }>(`/api/v1/graph/paths`, {
      params: { entity, ...options },
    }),

  getMitreCoverage: () =>
    request<MitreCoverage>('/api/v1/graph/mitre/coverage'),

  getBlastRadius: (entity: string) =>
    request<{ radius: AttackGraph; affectedAssets: string[] }>(
      `/api/v1/graph/blast-radius`,
      { params: { entity } },
    ),

  /**
   * Fetch the reconstructed attack-path graph for a single case.
   * Backed by the Attack-Path Investigation Agent endpoint
   * `/api/v1/graph/attack-path/{case_id}`.
   * Returns `null` when the case has no linked graph entities (404 from API).
   */
  getCaseAttackPath: async (
    caseId: string,
    options: { maxDepth?: number } = {},
  ): Promise<CaseAttackPath | null> => {
    try {
      const raw = await request<BackendCaseAttackPathResponse>(
        `/api/v1/graph/attack-path/${encodeURIComponent(caseId)}`,
        {
          params: options.maxDepth ? { max_depth: options.maxDepth } : {},
        },
      );
      return {
        caseId: raw.case_id,
        nodes: raw.nodes ?? [],
        edges: raw.edges ?? [],
        nodeCount: raw.node_count ?? 0,
        edgeCount: raw.edge_count ?? 0,
      };
    } catch (err) {
      const apiErr = err as { status?: number };
      if (apiErr?.status === 404) return null;
      throw err;
    }
  },
};

// ─── Detection Rules ─────────────────────────────────────────────────────────

export type DetectionLanguage =
  | 'sigma'
  | 'yara'
  | 'kql'
  | 'eql'
  | 'lucene'
  | 'regex';

export interface DetectionRule {
  id: string;
  name: string;
  description?: string;
  language: DetectionLanguage;
  body: string;
  enabled: boolean;
  tags?: string[];
  mitre?: string[];
  severity?: AlertSeverity;
  createdAt: string;
  updatedAt: string;
  lastTriggeredAt?: string;
  hitCount?: number;
}

// ─── Detection management UI (WS-B3) ─────────────────────────────────────────
//
// Rule-centric MITRE coverage, bulk enable/disable, and the drift inbox are
// powered by ``services/api/app/api/v1/endpoints/detection_compat.py``.
// Schemas are mirrored here field-for-field so the UI gets autocomplete and
// the compiler catches drift if the backend payload ever changes shape.

export interface DetectionCoverageCell {
  techniqueId: string;
  tactic: string | null;
  techniqueName?: string | null;
  totalRules: number;
  activeRules: number;
  inactiveRules: number;
}

export interface DetectionCoverageSummary {
  totalRules: number;
  activeRules: number;
  inactiveRules: number;
  techniques: number;
  /** Techniques with at least one *active* rule. */
  coveredTechniques: number;
}

export interface DetectionCoverage {
  tactics: string[];
  cells: DetectionCoverageCell[];
  summary: DetectionCoverageSummary;
  generatedAt: string;
}

export interface DetectionDriftEntry {
  ruleId: string;
  name: string;
  severity: string;
  enabled: boolean;
  confidence: number;
  fpRate: number;
  lastTriggeredAt: string | null;
  daysSinceTriggered: number | null;
  /** ``high_fp_rate``, ``low_confidence``, ``stale``. */
  issues: string[];
}

export interface DetectionDriftSummary {
  total: number;
  highFpRate: number;
  lowConfidence: number;
  stale: number;
}

export interface DetectionDrift {
  entries: DetectionDriftEntry[];
  summary: DetectionDriftSummary;
  generatedAt: string;
}

export interface DetectionBulkToggleResult {
  updated: number;
  /** Rule IDs the backend refused (not tenant-owned, malformed, missing). */
  skipped: string[];
}

/** One bar in the confidence histogram. */
export interface ConfidenceBucket {
  /** Display label, e.g. ``"0–25"``. */
  label: string;
  floor: number;
  ceil: number;
  count: number;
  activeCount: number;
}

/** Per-MITRE-tactic confidence average. */
export interface TacticConfidence {
  tactic: string;
  rules: number;
  activeRules: number;
  avgConfidence: number;
  avgConfidenceActive: number;
}

/** Compact rule reference for the lowest/highest tables. */
export interface ConfidenceRuleEntry {
  ruleId: string;
  name: string;
  severity: string;
  enabled: boolean;
  confidence: number;
  fpRate: number;
  primaryTactic: string | null;
}

export interface ConfidenceSummary {
  totalRules: number;
  activeRules: number;
  avgConfidence: number;
  avgConfidenceActive: number;
  medianConfidence: number;
  /** Rules below the drift low-confidence threshold (server side: 60). */
  lowConfidence: number;
}

export interface DetectionConfidence {
  summary: ConfidenceSummary;
  buckets: ConfidenceBucket[];
  tactics: TacticConfidence[];
  lowest: ConfidenceRuleEntry[];
  highest: ConfidenceRuleEntry[];
  generatedAt: string;
}

export const detectionApi = {
  list: () =>
    request<{ rules: DetectionRule[]; total: number }>(
      '/api/v1/detection/rules',
    ),

  get: (id: string) => request<DetectionRule>(`/api/v1/detection/rules/${id}`),

  create: (rule: Partial<DetectionRule>) =>
    request<DetectionRule>('/api/v1/detection/rules', {
      method: 'POST',
      body: JSON.stringify(rule),
    }),

  update: (id: string, rule: Partial<DetectionRule>) =>
    request<DetectionRule>(`/api/v1/detection/rules/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(rule),
    }),

  delete: (id: string) =>
    request<void>(`/api/v1/detection/rules/${id}`, { method: 'DELETE' }),

  test: (rule: Pick<DetectionRule, 'language' | 'body'> & { sample?: string }) =>
    request<{ matches: number; preview: HuntResult[] }>(
      '/api/v1/detection/test',
      {
        method: 'POST',
        body: JSON.stringify(rule),
      },
    ),

  // ─── WS-B3 management endpoints ──────────────────────────────────────────

  coverage: () =>
    request<DetectionCoverage>('/api/v1/detection/coverage'),

  drift: () => request<DetectionDrift>('/api/v1/detection/drift'),

  /**
   * Confidence distribution + per-tactic averages + worst/best rules.
   * The plan calls this "confidence trends"; we surface it as a
   * snapshot histogram + ranked tables since rule confidence isn't
   * captured historically yet.
   */
  confidence: () => request<DetectionConfidence>('/api/v1/detection/confidence'),

  /**
   * Enable or disable many rules in one round-trip. Built-in /
   * cross-tenant rules are silently skipped server-side and reported in
   * the ``skipped`` array of the response so the UI can surface them.
   */
  bulkToggle: (ruleIds: string[], enabled: boolean) =>
    request<DetectionBulkToggleResult>('/api/v1/detection/rules/bulk-toggle', {
      method: 'POST',
      body: JSON.stringify({ ruleIds, enabled }),
    }),
};

// ─── Detection-as-code proposals (Wave 2 — w2-dac) ──────────────────────────
//
// Mirrors `services/api/app/api/v1/endpoints/detection_proposals.py`. Backed
// by `DetectionRuleProposal` + `DetectionEvalBaseline` tables. The eval
// verdict is computed server-side from a `scripts/run_evals.py` JSON report
// and the most recent active MITRE accuracy baseline; ≥ 1pp regression
// blocks approval / merge.

export type DetectionProposalStatus =
  | 'proposed'
  | 'in_review'
  | 'eval_passed'
  | 'eval_failed'
  | 'approved'
  | 'rejected'
  | 'promoted';

export interface DetectionProposalEvalVerdict {
  ran_at?: string;
  candidate?: { mitre_accuracy?: number; all_passed?: boolean };
  baseline?: { mitre_accuracy?: number };
  drop_pp?: number;
  max_regression_pp?: number;
  regressed?: boolean;
  passed?: boolean;
}

export interface DetectionProposal {
  id: string;
  tenant_id: string | null;
  base_rule_id: string | null;
  promoted_rule_id: string | null;
  name: string;
  description: string | null;
  rule_language: string;
  rule_body: string;
  category: string;
  severity: string;
  confidence: number;
  mitre_tactics: string[];
  mitre_techniques: string[];
  tags: string[];
  status: DetectionProposalStatus;
  eval_result: DetectionProposalEvalVerdict | Record<string, never>;
  review_comments: Array<{
    actor_id: string;
    actor_email?: string;
    comment: string;
    at: string;
  }>;
  proposed_by_id: string | null;
  decided_by_id: string | null;
  decision_comment: string | null;
  decided_at: string | null;
  /** WS-B4: git PR path — URL of the GitHub PR created on promotion. Author: Beenu - beenu@cyble.com */
  github_pr_url: string | null;
  created_at: string;
  updated_at: string;
}

export interface DetectionEvalBaseline {
  id: string;
  tenant_id: string | null;
  suite: string;
  score: number;
  payload: Record<string, unknown>;
  is_active: boolean;
  recorded_by_id: string | null;
  created_at: string;
}

export const detectionProposalsApi = {
  list: (params?: { status?: DetectionProposalStatus; limit?: number }) => {
    const qs = new URLSearchParams();
    if (params?.status) qs.set('status', params.status);
    if (params?.limit !== undefined) qs.set('limit', String(params.limit));
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return request<DetectionProposal[]>(
      `/api/v1/detection-proposals${suffix}`,
    );
  },

  get: (id: string) =>
    request<DetectionProposal>(`/api/v1/detection-proposals/${id}`),

  create: (proposal: {
    name: string;
    description?: string | null;
    rule_language: string;
    rule_body: string;
    category: string;
    severity?: string;
    confidence?: number;
    mitre_tactics?: string[];
    mitre_techniques?: string[];
    tags?: string[];
    base_rule_id?: string | null;
  }) =>
    request<DetectionProposal>('/api/v1/detection-proposals', {
      method: 'POST',
      body: JSON.stringify(proposal),
    }),

  comment: (id: string, comment: string) =>
    request<DetectionProposal>(
      `/api/v1/detection-proposals/${id}/comment`,
      { method: 'POST', body: JSON.stringify({ comment }) },
    ),

  attachEval: (
    id: string,
    body: { eval_report: Record<string, unknown>; max_regression_pp?: number },
  ) =>
    request<DetectionProposal>(`/api/v1/detection-proposals/${id}/eval`, {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  // Triggers a synchronous run of `scripts/run_evals.py` server-side and
  // returns the JSON report plus runner metadata. The rule editor calls this
  // from "Propose for review" so the eval gate runs before the proposal is
  // visible for approval. Subprocess takes ~5–15s on the 200-incident corpus.
  runEval: (body?: {
    use_active_baseline?: boolean;
    max_regression_pp?: number;
    timeout_seconds?: number;
  }) =>
    request<{
      report: Record<string, unknown>;
      exit_code: number;
      duration_seconds: number;
      ran_at: string;
      script: string;
    }>('/api/v1/detection-proposals/run-eval', {
      method: 'POST',
      body: JSON.stringify(body ?? {}),
    }),

  decide: (
    id: string,
    body: { decision: 'approve' | 'reject'; comment?: string | null },
  ) =>
    request<DetectionProposal>(`/api/v1/detection-proposals/${id}/decide`, {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  promote: (id: string) =>
    request<DetectionProposal>(
      `/api/v1/detection-proposals/${id}/promote`,
      { method: 'POST' },
    ),

  listBaselines: (suite?: string) => {
    const suffix = suite ? `?suite=${encodeURIComponent(suite)}` : '';
    return request<DetectionEvalBaseline[]>(
      `/api/v1/detection-proposals/baselines${suffix}`,
    );
  },

  recordBaseline: (body: {
    suite: string;
    score: number;
    payload?: Record<string, unknown>;
  }) =>
    request<DetectionEvalBaseline>(
      '/api/v1/detection-proposals/baselines',
      { method: 'POST', body: JSON.stringify(body) },
    ),
};

// ─── Detection Rule Tuning Workbench (PR-6 / v1.5 §W8) ───────────────────────
//
// The tuning workbench replaces the static /noise-tuning prototype with a live
// projection of ``DetectionRule`` rows into analyst-actionable suggestions.
// The backend is intentionally cheap — every projection is derived from
// already-materialised fields (``fp_rate``, ``total_hits``, ``confidence``,
// ``last_triggered``, ``status``) so a tenant with thousands of imported Sigma
// rules can still triage without hammering the alerts table.
//
// Three verbs ship here:
//   • ``list`` / ``summary`` — read-only projection (``rules:read``).
//   • ``apply`` — mechanically tighten a rule (``rules:write``), bumps version.
//   • ``dismiss`` / ``autoTune`` — record analyst intent (``rules:write``).
//
// See ``services/api/app/services/rule_tuning.py`` for the authoritative
// wire shape; the types below mirror its Pydantic models 1:1.

export type TuningSuggestion =
  | 'disable'
  | 'add_suppression'
  | 'raise_threshold'
  | 'tune_confidence'
  | 'review_stale'
  | 'healthy';

export type TuningAction =
  | 'raise_threshold'
  | 'add_suppression'
  | 'disable'
  | 'acknowledge';

export interface TuningEntry {
  rule_id: string;
  name: string;
  description: string | null;
  category: string;
  severity: string;
  status: string;
  enabled: boolean;
  confidence: number;
  /** Materialised false-positive rate in ``[0, 1]``. */
  fp_rate: number;
  total_hits: number;
  /** ISO-8601 timestamp of the rule's last hit; ``null`` if it has never fired. */
  last_triggered_at: string | null;
  tags: string[];
  mitre_tactics: string[];
  mitre_techniques: string[];
  version: number;
  updated_at: string;

  suggestion: TuningSuggestion;
  /** Server-side ordering weight — already sorted descending in ``entries``. */
  score: number;
  reasons: string[];
  auto_tune: boolean;
  /** Set when an analyst has dismissed the rule from the default view. */
  dismissed_at: string | null;
  /** Most recent tuning action applied to this rule (``raise_threshold`` …). */
  last_action: string | null;
  last_action_at: string | null;
}

export interface TuningSummary {
  total_rules: number;
  actionable: number;
  healthy: number;
  disable_count: number;
  add_suppression_count: number;
  raise_threshold_count: number;
  tune_confidence_count: number;
  review_stale_count: number;
  auto_tune_enabled: number;
  /** Average ``fp_rate`` across classified rules, ``[0, 1]``. */
  average_fp_rate: number;
  /** Count of rules whose ``fp_rate`` is at or above the noisy threshold. */
  high_fp_count: number;
}

export interface TuningFilters {
  severity: string | null;
  suggestion: string | null;
  search: string | null;
  enabled_only: boolean;
  include_dismissed: boolean;
  page: number;
  page_size: number;
}

export interface TuningResponse {
  entries: TuningEntry[];
  summary: TuningSummary;
  /** Echo of the filters that built this response. */
  filters: TuningFilters;
  total: number;
  generated_at: string;
}

export interface TuningListParams {
  severity?: string;
  suggestion?: TuningSuggestion;
  search?: string;
  enabled_only?: boolean;
  include_dismissed?: boolean;
  page?: number;
  page_size?: number;
}

export interface ApplyTuningRequest {
  action: TuningAction;
  note?: string | null;
  /** Override threshold to set when ``action === 'raise_threshold'``. */
  threshold?: number | null;
  /** Free-text reason recorded with the suppression placeholder. */
  suppression_reason?: string | null;
}

export interface DismissTuningRequest {
  reason?: string | null;
}

export interface AutoTuneRequest {
  enabled: boolean;
}

export const tuningApi = {
  /**
   * Fetch the rule tuning workbench feed.
   *
   * The ``summary`` block is computed across the *entire classified
   * population* (not the current page), so the header tiles stay stable
   * as analysts paginate. Dismissed rules are excluded by default — pass
   * ``include_dismissed: true`` when auditing what's been hidden.
   */
  list: (params: TuningListParams = {}) =>
    request<TuningResponse>('/api/v1/detection/tuning', {
      params: params as Record<string, string | number | boolean>,
    }),

  /**
   * Cheap summary-only endpoint. Used by the sidebar badge and the
   * upcoming /console dashboard tile so they don't have to fetch the
   * full feed just to render counts.
   */
  summary: () => request<TuningSummary>('/api/v1/detection/tuning/summary'),

  /**
   * Mechanically apply a tuning suggestion. ``raise_threshold``,
   * ``add_suppression``, and ``disable`` mutate the rule and bump
   * ``DetectionRule.version``; ``acknowledge`` is a no-op + audit. The
   * server returns the re-projected entry so the UI can refresh in place.
   */
  apply: (ruleId: string, body: ApplyTuningRequest) =>
    request<TuningEntry>(`/api/v1/detection/tuning/${ruleId}/apply`, {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  /**
   * Hide a rule from the default workbench view without touching its
   * semantics. Dismissed rules reappear with ``include_dismissed: true``.
   */
  dismiss: (ruleId: string, body: DismissTuningRequest = {}) =>
    request<TuningEntry>(`/api/v1/detection/tuning/${ruleId}/dismiss`, {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  /**
   * Flip the per-rule ``auto_tune`` opt-in flag. Stored under
   * ``suppression_config.auto_tune`` so future automated tuners know
   * they're allowed to touch the rule. Flipping does *not* trigger any
   * immediate mutation.
   */
  autoTune: (ruleId: string, enabled: boolean) =>
    request<TuningEntry>(`/api/v1/detection/tuning/${ruleId}/auto_tune`, {
      method: 'POST',
      body: JSON.stringify({ enabled } satisfies AutoTuneRequest),
    }),
};

// ─── AI Copilot ──────────────────────────────────────────────────────────────

export type CopilotRole = 'user' | 'assistant' | 'system';

export interface CopilotMessage {
  id: string;
  role: CopilotRole;
  content: string;
  /** When the message was created (ISO string). */
  createdAt: string;
  /** Optional citations to backend resources the assistant referenced. */
  citations?: Array<{
    label: string;
    href?: string;
    kind?: 'alert' | 'case' | 'rule' | 'asset' | 'doc';
  }>;
  /** Optional structured suggestions the UI can render as buttons. */
  suggestions?: string[];
}

export interface CopilotConversation {
  id: string;
  title: string;
  updatedAt: string;
  messageCount: number;
}

export interface CopilotChatRequest {
  conversationId?: string;
  message: string;
  /** Optional context the user is currently looking at. */
  context?: {
    alertId?: string;
    caseId?: string;
    entity?: string;
    page?: string;
  };
}

export interface CopilotChatResponse {
  conversationId: string;
  reply: CopilotMessage;
}

export const copilotApi = {
  listConversations: () =>
    request<{ conversations: CopilotConversation[] }>(
      '/api/v1/copilot/conversations',
    ),

  getConversation: (id: string) =>
    request<{ id: string; title: string; messages: CopilotMessage[] }>(
      `/api/v1/copilot/conversations/${id}`,
    ),

  /** One-shot chat call. UI should support optimistic append + rollback. */
  chat: (req: CopilotChatRequest) =>
    request<CopilotChatResponse>('/api/v1/copilot/chat', {
      method: 'POST',
      body: JSON.stringify(req),
    }),

  /**
   * Stream a chat response as NDJSON (one JSON object per line, with
   * `{ delta?: string, done?: boolean, citations?, suggestions? }`).
   * Callers should consume via `Response.body.getReader()`.
   */
  streamChat: (req: CopilotChatRequest, signal?: AbortSignal) =>
    fetch(`${API_BASE}/api/v1/copilot/chat/stream`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Tenant-Id': TENANT_ID,
      },
      body: JSON.stringify(req),
      signal,
    }),
};

// ─── Ambient Copilot (contextual actions) ───────────────────────────────────
//
// Phase 4A. Each page (alerts/cases/detections/playbooks) renders a small
// row of buttons that call into `services/agents` with a tightly-scoped
// system prompt. The result is rendered inline next to the entity the user
// is looking at — no full Copilot conversation required.
//
// Endpoints live on the agents service (port 8001 / AGENTS_BASE), not on
// the main API, because they share the same LangChain/MITRE plumbing as the
// investigation orchestrator.

export type ContextualPage = 'alerts' | 'cases' | 'detections' | 'playbooks';

export interface ContextualSuggestion {
  label: string;
  action?: string | null;
  href?: string | null;
}

export interface ContextualActionDescriptor {
  key: string;
  label: string;
  description: string;
  icon?: string | null;
}

export interface ContextualActionsCatalogue {
  pages: Record<ContextualPage, ContextualActionDescriptor[]>;
}

export interface ContextualActionRequest {
  page: ContextualPage;
  action: string;
  entity_id: string;
  entity?: Record<string, unknown> | null;
  question?: string | null;
  case_id?: string | null;
}

export interface ContextualActionResponse {
  id: string;
  page: ContextualPage;
  action: string;
  entity_id: string;
  title: string;
  /** Markdown body. */
  content: string;
  /** 0-1 confidence. `0` when the LLM was not configured. */
  confidence: number;
  suggestions: ContextualSuggestion[];
  citations: Array<Record<string, unknown>>;
  model: string;
  elapsed_ms: number;
  fallback: boolean;
  created_at: string;
}

/**
 * One streamed NDJSON frame from `/action/stream`. The first frame is a
 * header (no `delta`/`done`), subsequent frames carry `delta`, and the
 * final frame has `done: true` plus suggestions + confidence.
 */
export interface ContextualStreamFrame {
  /** Header frame fields. */
  title?: string;
  page?: ContextualPage;
  action?: string;
  entity_id?: string;
  model?: string;
  fallback?: boolean;
  /** Body frame fields. */
  delta?: string;
  /** Footer frame fields. */
  done?: boolean;
  suggestions?: ContextualSuggestion[];
  confidence?: number;
  /** Error frame. */
  error?: string;
}

export const contextualApi = {
  /** Catalogue of supported (page, action) pairs. */
  listActions: () =>
    request<ContextualActionsCatalogue>('/api/v1/contextual/actions', {
      baseUrl: AGENTS_BASE,
    }),

  /** One-shot contextual call. Returns a fully-formed Markdown response. */
  run: (req: ContextualActionRequest) =>
    request<ContextualActionResponse>('/api/v1/contextual/action', {
      method: 'POST',
      body: JSON.stringify(req),
      baseUrl: AGENTS_BASE,
    }),

  /**
   * Streaming variant. Returns the raw `Response` so the caller can read
   * NDJSON frames via `response.body.getReader()`. See
   * {@link ContextualStreamFrame} for the per-line shape.
   */
  stream: (req: ContextualActionRequest, signal?: AbortSignal) =>
    fetch(`${AGENTS_BASE}/api/v1/contextual/action/stream`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Tenant-Id': TENANT_ID,
      },
      body: JSON.stringify(req),
      signal,
    }),
};

// Re-export base URLs so dev tooling and tests can introspect them.
// Production callers should prefer the typed functions above.
export const __apiBases = {
  api: API_BASE,
  agents: AGENTS_BASE,
  actions: ACTIONS_BASE,
  fusion: FUSION_BASE,
  threatintel: THREATINTEL_BASE,
  enrichment: ENRICHMENT_BASE,
  realtime: REALTIME_BASE,
  ws: WS_BASE,
} as const;

// ─── Web Push & Responder PWA ────────────────────────────────────────────────
//
// Phase 4B. The mobile responder PWA subscribes to Web Push so on-call
// engineers get paged for P0 alerts and "agent needs your approval"
// events without keeping the browser tab open. Subscriptions are stored
// per-tenant on the realtime gateway, which fans events out from Kafka.

export interface PushSubscriptionPayload {
  endpoint: string;
  keys: {
    p256dh: string;
    auth: string;
  };
  expirationTime?: number | null;
}

export interface PushSubscribeRequest {
  subscription: PushSubscriptionPayload;
  user_agent?: string;
  user_id?: string | null;
  topics?: string[];
}

export interface PushSubscribeResponse {
  id: string;
  vapid_public_key: string;
  topics: string[];
}

export interface PushPublicKeyResponse {
  /** VAPID public key as a URL-safe base64 string. */
  public_key: string;
  enabled: boolean;
}

export type OnCallStatus = 'available' | 'busy' | 'snoozed' | 'offline';

export interface OnCallSnapshot {
  user_id: string;
  user_email: string | null;
  user_name: string | null;
  status: OnCallStatus;
  rotation: string | null;
  schedule_ref: string | null;
  note: string | null;
  /** ISO-8601 timestamp the current snooze ends (null otherwise). */
  until: string | null;
  updated_at: string;
}

export type ApprovalStatus = 'pending' | 'approved' | 'denied' | 'expired';

export interface ApprovalRequest {
  id: string;
  tenant_id: string;
  run_id: string | null;
  case_id: string | null;
  alert_id: string | null;
  requested_by: string;
  required_user_id: string | null;
  required_topic: string | null;
  title: string;
  summary: string;
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  action: Record<string, unknown>;
  status: ApprovalStatus;
  decided_by_id: string | null;
  decided_at: string | null;
  decision_comment: string | null;
  expires_at: string | null;
  created_at: string;
  updated_at: string;
}

export const responderApi = {
  /** Fetch the VAPID public key the SW will subscribe with. */
  getPublicKey: () =>
    request<PushPublicKeyResponse>('/api/v1/push/public-key'),

  /** Register a new Web Push subscription for this device. */
  subscribe: (req: PushSubscribeRequest) =>
    request<PushSubscribeResponse>('/api/v1/push/subscribe', {
      method: 'POST',
      body: JSON.stringify(req),
    }),

  /** Tear down an existing subscription (e.g. on sign-out). */
  unsubscribe: (endpoint: string) =>
    request<{ removed: boolean }>('/api/v1/push/unsubscribe', {
      method: 'POST',
      body: JSON.stringify({ endpoint }),
    }),

  /** Send a test page to all of the caller's registered devices. */
  testNotify: () =>
    request<{ sent: number }>('/api/v1/push/test', {
      method: 'POST',
    }),

  /** Snapshot of every user's on-call status (admin view). */
  listOnCall: () =>
    request<{ items: OnCallSnapshot[] }>('/api/v1/oncall'),

  /** Current caller's on-call snapshot. */
  getOnCall: () =>
    request<OnCallSnapshot>('/api/v1/oncall/me'),

  /** Toggle the caller's own on-call status (optionally for a window).
   *
   * Pass ``snooze_minutes`` together with ``status: 'snoozed'`` to defer
   * paging temporarily — the backend computes ``until`` from that window.
   */
  setOnCall: (
    status: OnCallStatus,
    options?: {
      snooze_minutes?: number | null;
      note?: string | null;
      rotation?: string | null;
      schedule_ref?: string | null;
    },
  ) =>
    request<OnCallSnapshot>('/api/v1/oncall/me', {
      method: 'PUT',
      body: JSON.stringify({
        status,
        snooze_minutes: options?.snooze_minutes ?? null,
        note: options?.note ?? null,
        rotation: options?.rotation ?? null,
        schedule_ref: options?.schedule_ref ?? null,
      }),
    }),

  /** Pending agent approval requests visible to me. */
  listApprovals: (params?: {
    status?: ApprovalStatus;
    mine?: boolean;
    risk_level?: ApprovalRequest['risk_level'];
    page?: number;
    page_size?: number;
  }) =>
    request<{
      items: ApprovalRequest[];
      total: number;
      page: number;
      page_size: number;
      pages: number;
    }>('/api/v1/approvals', {
      params: {
        status: params?.status ?? 'pending',
        ...(params?.mine ? { mine: 'true' } : {}),
        ...(params?.risk_level ? { risk_level: params.risk_level } : {}),
        ...(params?.page ? { page: params.page } : {}),
        ...(params?.page_size ? { page_size: params.page_size } : {}),
      },
    }),

  /** Single approval (for the deep-linked notification view). */
  getApproval: (id: string) =>
    request<ApprovalRequest>(`/api/v1/approvals/${id}`),

  /** Approve a pending agent action. */
  approve: (id: string, comment?: string) =>
    request<ApprovalRequest>(`/api/v1/approvals/${id}/decide`, {
      method: 'POST',
      body: JSON.stringify({ decision: 'approve', comment: comment ?? null }),
    }),

  /** Deny a pending agent action with a required reason. */
  deny: (id: string, reason: string) =>
    request<ApprovalRequest>(`/api/v1/approvals/${id}/decide`, {
      method: 'POST',
      body: JSON.stringify({ decision: 'deny', comment: reason }),
    }),

  /** Snooze an alert for the on-call rotation.
   *
   * Pass either ``durationMinutes`` (relative window) or ``until`` (absolute
   * ISO-8601 timestamp). The alert re-surfaces in the queue once the window
   * elapses.
   */
  snoozeAlert: (
    alertId: string,
    options: { durationMinutes?: number; until?: string; reason?: string },
  ) =>
    request<Alert>(`/api/v1/alerts/${alertId}/snooze`, {
      method: 'POST',
      body: JSON.stringify({
        duration_minutes: options.durationMinutes ?? null,
        until: options.until ?? null,
        reason: options.reason ?? null,
      }),
    }),
};

// ─── WebAuthn / Passkey authentication (Phase 4B) ───────────────────────────
//
// The mobile responder uses passkeys instead of passwords. The flow is the
// standard WebAuthn registration + authentication ceremony backed by
// services/api/app/api/v1/endpoints/passkeys.py. Browsers handle the
// platform UI; the helpers below just shuttle JSON between the SimpleWebAuthn
// browser library and our backend.

export interface PasskeyCredential {
  id: string;
  device_name: string;
  created_at: string;
  last_used_at: string | null;
  transports: string[];
}

export const passkeyApi = {
  /** Begin registration for the currently logged-in user. */
  registerBegin: (deviceName: string) =>
    request<{
      publicKey: Record<string, unknown>;
      challenge: string;
      device_name_default: string;
    }>('/api/v1/passkeys/register/begin', {
      method: 'POST',
      body: JSON.stringify({ device_name: deviceName }),
    }),

  /** Submit the platform attestation to persist the new credential. */
  registerFinish: (challenge: string, credential: Record<string, unknown>) =>
    request<PasskeyCredential>('/api/v1/passkeys/register/finish', {
      method: 'POST',
      body: JSON.stringify({ challenge, credential }),
    }),

  /** Begin a passwordless login (email is optional / hint only). */
  authenticateBegin: (email?: string) =>
    request<{ publicKey: Record<string, unknown>; challenge: string }>(
      '/api/v1/passkeys/authenticate/begin',
      {
        method: 'POST',
        body: JSON.stringify({ email: email ?? null }),
      },
    ),

  /** Verify the assertion and return a JWT pair. */
  authenticateFinish: (challenge: string, credential: Record<string, unknown>) =>
    request<{
      access_token: string;
      refresh_token: string;
      token_type: string;
      expires_in: number;
    }>('/api/v1/passkeys/authenticate/finish', {
      method: 'POST',
      body: JSON.stringify({ challenge, credential }),
    }),

  /** Active credentials for the current user. */
  list: () =>
    request<{ items: PasskeyCredential[] }>('/api/v1/passkeys/credentials'),

  /** Soft-revoke one of my credentials. */
  delete: (id: string) =>
    request<void>(`/api/v1/passkeys/credentials/${id}`, { method: 'DELETE' }),
};

// ─── Autonomy policy (Tier 1.3 — configurable autonomy guardrails) ──────────
//
// Three-tier confidence cutoffs per agent action: at or above ``auto`` the
// agent executes silently, between ``auto`` and ``review`` it queues for an
// analyst, between ``review`` and ``escalation`` it pages on-call, and below
// ``escalation`` it refuses. The admin UI in
// ``apps/web/src/components/settings/AutonomyPolicy.tsx`` reads + writes
// these thresholds; the agent re-reads them on the next investigation.

export interface AutonomyThresholdTriple {
  auto: number;
  review: number;
  escalation: number;
}

export type AutonomyBlastRadius =
  | 'read'
  | 'low'
  | 'medium'
  | 'high'
  | 'critical'
  | 'custom'
  | 'unknown';

export interface AutonomyActionPolicy {
  action: string;
  blast_radius: AutonomyBlastRadius;
  thresholds: AutonomyThresholdTriple;
  default_thresholds: AutonomyThresholdTriple;
  overridden: boolean;
  override_source?: string | null;
  last_updated_at?: string | null;
  last_updated_by?: string | null;
  last_reason?: string | null;
}

export interface AutonomyPolicyResponse {
  tenant_id: string;
  actions: AutonomyActionPolicy[];
}

export interface AutonomyThresholdUpdate {
  auto: number;
  review: number;
  escalation: number;
  reason?: string | null;
}

export interface AutonomyThresholdUpdateResponse {
  action: string;
  thresholds: AutonomyThresholdTriple;
  updated_at: string;
  updated_by: string;
}

export const autonomyPolicyApi = {
  /** Effective policy (defaults + DB overrides) for the calling tenant. */
  list: () => request<AutonomyPolicyResponse>('/api/v1/autonomy-policy'),

  /** Upsert one action's three-tier thresholds. */
  update: (action: string, payload: AutonomyThresholdUpdate) =>
    request<AutonomyThresholdUpdateResponse>(
      `/api/v1/autonomy-policy/${encodeURIComponent(action)}`,
      {
        method: 'PUT',
        body: JSON.stringify(payload),
      },
    ),

  /** Clear a tenant override and revert the action to the hard-coded default. */
  reset: (action: string) =>
    request<void>(
      `/api/v1/autonomy-policy/${encodeURIComponent(action)}`,
      { method: 'DELETE' },
    ),
};

// ─── Analyst override feedback loop (Tier 1.5) ───────────────────────────────
//
// When an analyst corrects an AI verdict, the API:
//   1. updates the alert's ``disposition``
//   2. writes the lesson into ``aisoc_institutional_memory`` (so future
//      investigations of similar alerts pull this up)
//   3. surfaces *retroactive candidates* — past alerts in the same tenant
//      sharing the same coarse signature that would now flip disposition.
//
// The analyst can then bulk-apply the new disposition to those candidates
// via ``POST /api/v1/feedback/redisposition/apply``.

export type AnalystVerdict =
  | 'true_positive'
  | 'false_positive'
  | 'benign'
  | 'escalate';

export interface AlertOverrideRequest {
  alert_id: string;
  /** The AI-generated verdict being overridden. */
  original_verdict: string;
  /** Analyst's corrected verdict. */
  corrected_verdict: AnalystVerdict;
  /** Optional free-text justification surfaced in institutional memory. */
  reason?: string;
}

export interface RedispositionCandidate {
  alert_id: string;
  title: string;
  severity: string;
  current_disposition: string | null;
  proposed_disposition: AnalystVerdict;
  event_time: string;
}

export interface AlertOverrideResponse {
  alert_id: string;
  corrected_verdict: AnalystVerdict;
  recorded_at: string;
  /** Stable institutional-memory key, only present when a signature was derivable. */
  memory_key: string | null;
  redisposition_candidates: RedispositionCandidate[];
}

export interface RedispositionApplyRequest {
  alert_ids: string[];
  new_disposition: AnalystVerdict;
}

export interface RedispositionApplyResponse {
  updated: number;
  new_disposition: AnalystVerdict;
}

export interface OverrideEntry {
  key: string;
  tags: string[];
  reason: string | null;
  created_at: string | null;
  value: Record<string, unknown>;
}

export interface OverrideSummary {
  total_overrides: number;
  false_positive_corrections: number;
  true_positive_corrections: number;
  benign_corrections: number;
  escalate_corrections: number;
}

export const feedbackApi = {
  /** Persist an analyst correction and get retroactive re-disposition candidates back. */
  submitOverride: (payload: AlertOverrideRequest) =>
    request<AlertOverrideResponse>('/api/v1/feedback/alert-override', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  /** Bulk-apply a new disposition to past alerts the analyst confirmed. */
  applyRedisposition: (payload: RedispositionApplyRequest) =>
    request<RedispositionApplyResponse>('/api/v1/feedback/redisposition/apply', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  /** List analyst overrides the agent has 'learned' from for this tenant. */
  listOverrides: (limit = 100) =>
    request<OverrideEntry[]>('/api/v1/feedback/overrides', {
      params: { limit: String(limit) },
    }),

  /** Counts of dispositions for the FPR card on the SOC dashboard. */
  summary: () => request<OverrideSummary>('/api/v1/feedback/summary'),
};

// ─── Deployment & AI (air-gap + LLM provider snapshot) ───────────────────────
//
// Read-only operator visibility for "where will my AI calls actually go?" and
// "is air-gap actually engaged on this pod?". Both endpoints are unauthenticated
// snapshots that mirror the same code paths the runtime uses to gate egress
// (``app.core.airgap.is_host_allowed_for_airgap``) and pick the LLM transport
// (``services/agents/app/api/explain.py``), so the indicator the operator sees
// in the Settings → "Deployment & AI" panel cannot drift from runtime behaviour.

export interface AirgapStatus {
  /** True when AISOC_AIRGAPPED is set; the egress gate is enforcing. */
  enabled: boolean;
  /** Operator-supplied AISOC_AIRGAP_ALLOWLIST entries. */
  allowlist: string[];
  /** Always-allowed private/internal suffixes (.local, .internal, ...). */
  implicit_private_suffixes: string[];
  /** Human-readable summary suitable for audit reports. */
  policy: string;
}

export type LlmProvider =
  | 'openai'
  | 'anthropic'
  | 'azure-openai'
  | 'local-ollama'
  | 'local-vllm'
  | 'local-litellm'
  | 'custom'
  | 'none';

export type LlmEffectivePath = 'live' | 'fallback';

export interface LlmStatus {
  /** Stable provider id classified from the configured base URL. */
  provider: LlmProvider;
  /** LLM_MODEL / OPENAI_MODEL / AISOC_LLM_MODEL — empty string when unset. */
  model: string;
  /** Configured base URL (LLM_BASE_URL or OPENAI_BASE_URL). Empty when unset. */
  base_url: string;
  /** Hostname extracted from base_url (lowercased), or "" when no base_url. */
  host: string;
  /**
   * Whether ``OPENAI_API_KEY`` / ``LLM_API_KEY`` is set. The key itself is
   * never returned — even partially redacted.
   */
  key_set: boolean;
  /** Mirrors AirgapStatus.enabled. */
  airgap_enabled: boolean;
  /**
   * Whether the configured LLM host would be permitted by the egress gate at
   * request time. Always true when air-gap is OFF or no LLM is configured.
   */
  airgap_compliant: boolean;
  /** Best-effort "this is clearly a local LLM" hint for the UI badge. */
  is_local: boolean;
  /**
   * Which branch the Explain endpoint would actually take right now:
   * ``live`` = real LLM call, ``fallback`` = deterministic OCSF/MITRE summary.
   */
  effective_path: LlmEffectivePath;
  /** Operator-readable explanation of the current state. */
  policy_note: string;
}

// ─── BYOK per-tenant LLM credentials (WS-H2) ────────────────────────────────
//
// Mirrors ``services/api/app/api/v1/endpoints/llm_credentials.py``. The
// plaintext API key is *write-only*; the server stores it vault-encrypted
// and only ever returns ``has_api_key: bool`` so the UI can render
// "credential set / not set" without round-tripping the secret.
//
// Provider invariants enforced server-side and surfaced in the UI:
//   - ``local-ollama`` / ``local-vllm`` / ``local-litellm`` / ``custom``
//     require a ``base_url``.
//   - ``openai`` / ``anthropic`` / ``azure-openai`` require an ``api_key``
//     (on first write; rotation-only PUTs may pass ``api_key: null``).
//
// The provider list is a *strict subset* of the read-side ``LlmProvider``
// — ``none`` is never a writable choice.

export type LlmWritableProvider =
  | 'openai'
  | 'anthropic'
  | 'azure-openai'
  | 'local-ollama'
  | 'local-vllm'
  | 'local-litellm'
  | 'custom';

export interface LlmCredentialUpsert {
  provider: LlmWritableProvider;
  /** Required for local + custom providers. Optional for hosted SaaS. */
  base_url?: string | null;
  /** Optional model override (e.g. "gpt-4o-mini"). */
  model?: string | null;
  /**
   * Plaintext API key. Server vault-encrypts before persistence. Pass
   * ``null`` (or omit) on a rotation-only PUT to keep the existing
   * ciphertext untouched.
   */
  api_key?: string | null;
  /** Free-form provider-specific settings (e.g. ``{ "temperature": 0.2 }``). */
  settings?: Record<string, unknown> | null;
  enabled?: boolean;
}

export interface LlmCredentialView {
  provider: LlmWritableProvider;
  base_url: string | null;
  model: string | null;
  /** True iff a vault-encrypted ciphertext is currently stored. */
  has_api_key: boolean;
  settings: Record<string, unknown>;
  enabled: boolean;
  created_at: string;
  updated_at: string;
  /** Last time the API key was rotated (set/changed). Null if never. */
  last_rotated_at: string | null;
}

export const deploymentApi = {
  /** Live air-gap policy snapshot for this pod. Safe to poll. */
  getAirgapStatus: () => request<AirgapStatus>('/api/v1/airgap/status'),

  /** Live LLM provider snapshot. Mirrors the egress gate's classification. */
  getLlmStatus: () => request<LlmStatus>('/api/v1/llm/status'),

  /**
   * Read the tenant's BYOK credential. Returns ``null`` when no credential
   * is configured (the platform falls back to env-var defaults in that case).
   */
  getLlmCredential: () =>
    request<LlmCredentialView | null>('/api/v1/llm/credentials'),

  /** Create or update the tenant's BYOK credential. */
  upsertLlmCredential: (payload: LlmCredentialUpsert) =>
    request<LlmCredentialView>('/api/v1/llm/credentials', {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),

  /** Hard-delete the credential. Returns 204 on success. */
  deleteLlmCredential: () =>
    request<void>('/api/v1/llm/credentials', { method: 'DELETE' }),
};

// ─── Reports / Executive digest (WS-G2) ─────────────────────────────────────

export interface DigestPeriod {
  start: string;
  end: string;
  label: string;
}

export interface SeveritySplit {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface AlertSummary {
  total: number;
  new: number;
  resolved: number;
  open_at_period_end: number;
  severity: SeveritySplit;
}

export interface CaseSummary {
  opened: number;
  closed: number;
  open_at_period_end: number;
  sla_breached: number;
}

export interface MttSummary {
  mttd_hours: number | null;
  mttr_hours: number | null;
  mttc_hours: number | null;
}

export interface TacticHighlight {
  tactic: string;
  count: number;
  delta_from_prior: number;
}

export interface TopSourceHighlight {
  connector_type: string;
  count: number;
}

export interface HighRiskAlertHighlight {
  alert_id: string;
  title: string;
  severity: string;
  ai_score: number | null;
  mitre_tactics: string[];
  event_time: string;
}

export interface AutomationSummary {
  total_decisions: number;
  auto_executed: number;
  escalated: number;
  review_pending: number;
}

export interface DigestRecommendation {
  severity: 'info' | 'warning' | 'critical' | string;
  title: string;
  body: string;
}

export interface ExecutiveDigest {
  tenant_id: string;
  period: DigestPeriod;
  headline: string;
  alerts: AlertSummary;
  cases: CaseSummary;
  mtt: MttSummary;
  top_tactics: TacticHighlight[];
  top_sources: TopSourceHighlight[];
  high_risk_alerts: HighRiskAlertHighlight[];
  automation: AutomationSummary;
  recommendations: DigestRecommendation[];
}

export interface WeeklyDigestParams {
  /** ISO timestamp for the start of the window. Defaults to now-7d on the API. */
  period_start?: string;
  /** ISO timestamp for the end of the window. Defaults to now on the API. */
  period_end?: string;
}

export const reportsApi = {
  /**
   * Fetch the executive weekly digest for the current tenant as structured
   * JSON suitable for rendering an interactive panel in the web UI.
   */
  weeklyDigest: (params: WeeklyDigestParams = {}) =>
    request<ExecutiveDigest>('/api/v1/reports/digest/weekly', {
      params: { format: 'json', ...params },
    }),

  /**
   * Fetch the print-ready HTML representation of the weekly digest as a string.
   * Pairs naturally with `URL.createObjectURL(new Blob([html], …))` so the UI
   * can pop a new tab and let the browser's native "Save as PDF" produce the
   * board-ready document — no server-side PDF dependency required.
   *
   * Goes through the shared `request()` plumbing so it inherits the same auth
   * (cookie + optional localStorage bearer) and tenant header treatment as the
   * JSON variant.
   */
  weeklyDigestHtml: async (params: WeeklyDigestParams = {}): Promise<string> => {
    const search = new URLSearchParams({ format: 'html' });
    if (params.period_start) search.set('period_start', params.period_start);
    if (params.period_end) search.set('period_end', params.period_end);

    const headers: Record<string, string> = {
      Accept: 'text/html',
      'X-Tenant-Id': TENANT_ID,
    };
    if (typeof window !== 'undefined') {
      try {
        const token = window.localStorage.getItem(AUTH_TOKEN_KEY);
        if (token) headers.Authorization = `Bearer ${token}`;
      } catch {
        /* localStorage unavailable; ignore */
      }
    }

    const url = `${API_BASE}/api/v1/reports/digest/weekly?${search.toString()}`;
    const response = await fetch(url, { headers, cache: 'no-store' });
    if (!response.ok) {
      const detail = await response.text().catch(() => '');
      throw new ApiError(
        `API ${response.status} ${response.statusText} — /reports/digest/weekly`,
        response.status,
        detail,
      );
    }
    return response.text();
  },
};

// ─── Cost dashboard (WS-H1) ─────────────────────────────────────────────────

export interface DashboardPeriod {
  /** ISO timestamp marking the start of the rolling window (inclusive). */
  start: string;
  /** ISO timestamp marking the end of the window (exclusive, i.e. now()). */
  end: string;
  /** Width of the window in days, derived from start/end. */
  window_days: number;
  /** Human-readable label, e.g. "Apr 9 – May 9, 2026". */
  label: string;
}

export interface CostHeadline {
  /** Sum of recorded LLM cost in USD over the window. */
  total_cost_usd: number;
  /** Sum of prompt + completion tokens. */
  total_tokens: number;
  /** Total LLM API call count (one row in aisoc_run_costs ≈ one call). */
  total_calls: number;
  /** Distinct investigation_runs that produced cost in the window. */
  total_runs: number;
  /** Mean cost per run; null when no runs landed in the window. */
  avg_cost_per_run_usd: number | null;
}

export interface CostBucket {
  /** Calendar day in UTC, ISO ``YYYY-MM-DD``. */
  day: string;
  total_cost_usd: number;
  total_tokens: number;
  call_count: number;
}

export interface ModelBreakdown {
  /** Lowercased model id, e.g. ``gpt-4o-mini``. */
  model: string;
  runs: number;
  calls: number;
  total_prompt_tokens: number;
  total_completion_tokens: number;
  total_cost_usd: number;
  /** What this volume would have cost on the public list price. */
  imputed_public_cost_usd: number;
  avg_latency_ms: number | null;
}

export interface TopCostCase {
  case_id: string;
  runs: number;
  total_cost_usd: number;
  total_tokens: number;
}

export interface ActionCount {
  /** ``cases:read``, ``alerts:write``, etc. — straight from audit_log.action. */
  action: string;
  count: number;
}

export interface ByokSavings {
  /** True iff the current LLM provider is loopback / private (BYOK active). */
  is_byok_active: boolean;
  /** Provider id from /llm/status (e.g. ``openai``, ``local-ollama``). */
  provider: string;
  /** Recorded cost — what the cost tracker actually booked. */
  recorded_cost_usd: number;
  /** Re-priced cost using public list pricing (BYOK-neutral baseline). */
  imputed_public_cost_usd: number;
  /**
   * Estimated savings vs hosted: equals imputed_public_cost on BYOK,
   * ``max(imputed - recorded, 0)`` otherwise.
   */
  savings_usd: number;
}

export interface CostDashboard {
  tenant_id: string;
  period: DashboardPeriod;
  headline: CostHeadline;
  daily_costs: CostBucket[];
  by_model: ModelBreakdown[];
  top_cases: TopCostCase[];
  action_counts: ActionCount[];
  byok_savings: ByokSavings;
}

/**
 * Query parameters for the cost-dashboard endpoint. Declared as a `type`
 * (not interface) so it satisfies the request helper's
 * `Record<string, string | number | boolean | undefined>` constraint.
 */
export type CostDashboardParams = {
  /**
   * Rolling window in days. The API clamps to ``[1, 365]`` and defaults
   * to 30 — leaving this unset is the right call for the default view.
   */
  window_days?: number;
};

export const costsApi = {
  /**
   * WS-H1 — fetch the cost dashboard snapshot for the current tenant.
   *
   * Backs the admin cost dashboard at ``apps/web/src/app/(admin)/costs``.
   * Requires the ``reports:read`` permission server-side (granted to
   * tenant_admin / soc_lead / soc_analyst / threat_hunter / viewer), so
   * the page is gated by the same role bar that protects the executive
   * digest.
   */
  dashboard: (params: CostDashboardParams = {}) =>
    request<CostDashboard>('/api/v1/costs/dashboard', { params }),
};

// ─── Audit log / compliance bundle helpers ──────────────────────────────────

/**
 * Filters accepted by the audit-log export endpoint. Mirrors the query
 * parameters supported by ``GET /api/v1/audit/export`` so the UI layer can
 * forward whatever the analyst is currently filtering on without translation.
 */
export type AuditExportFilters = {
  action?: string;
  resource?: string;
  actor_id?: string;
  search?: string;
  /** Hard cap to keep a single export bounded — defaults to API max (10 000). */
  limit?: number;
};

function buildAuditExportSearch(
  filters: AuditExportFilters,
  format: 'csv' | 'html',
): URLSearchParams {
  const search = new URLSearchParams({ format });
  if (filters.action) search.set('action', filters.action);
  if (filters.resource) search.set('resource', filters.resource);
  if (filters.actor_id) search.set('actor_id', filters.actor_id);
  if (filters.search) search.set('search', filters.search);
  if (typeof filters.limit === 'number' && filters.limit > 0) {
    search.set('limit', String(filters.limit));
  }
  return search;
}

function buildAuditExportHeaders(accept: string): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: accept,
    'X-Tenant-Id': TENANT_ID,
  };
  if (typeof window !== 'undefined') {
    try {
      const token = window.localStorage.getItem(AUTH_TOKEN_KEY);
      if (token) headers.Authorization = `Bearer ${token}`;
    } catch {
      /* localStorage unavailable; ignore */
    }
  }
  return headers;
}

export const auditApi = {
  /**
   * WS-H3 — download the (filtered) audit trail as RFC 4180 CSV. Returns the
   * raw CSV body so the UI can wrap it in a Blob and trigger a download via
   * an anchor click. Going through ``fetch`` (instead of a plain anchor) lets
   * us forward the bearer token from localStorage and surface an
   * ``ApiError`` if the export is rejected (e.g. missing audit_log:read).
   */
  exportCsv: async (filters: AuditExportFilters = {}): Promise<{ body: string; filename: string }> => {
    const url = `${API_BASE}/api/v1/audit/export?${buildAuditExportSearch(filters, 'csv').toString()}`;
    const response = await fetch(url, {
      headers: buildAuditExportHeaders('text/csv'),
      cache: 'no-store',
    });
    if (!response.ok) {
      const detail = await response.text().catch(() => '');
      throw new ApiError(
        `API ${response.status} ${response.statusText} — /audit/export?format=csv`,
        response.status,
        detail,
      );
    }
    const filename = parseFilenameFromContentDisposition(
      response.headers.get('Content-Disposition'),
      `aisoc-audit-${timestampSlug()}.csv`,
    );
    const body = await response.text();
    return { body, filename };
  },

  /**
   * WS-H3 — fetch the print-ready HTML bundle of the (filtered) audit trail.
   * Mirrors ``reportsApi.weeklyDigestHtml``: pop the result into a new tab and
   * let the browser's native "Save as PDF" produce the compliance binder, no
   * server-side weasyprint dependency required.
   */
  exportHtml: async (filters: AuditExportFilters = {}): Promise<{ html: string; filename: string }> => {
    const url = `${API_BASE}/api/v1/audit/export?${buildAuditExportSearch(filters, 'html').toString()}`;
    const response = await fetch(url, {
      headers: buildAuditExportHeaders('text/html'),
      cache: 'no-store',
    });
    if (!response.ok) {
      const detail = await response.text().catch(() => '');
      throw new ApiError(
        `API ${response.status} ${response.statusText} — /audit/export?format=html`,
        response.status,
        detail,
      );
    }
    const filename = parseFilenameFromContentDisposition(
      response.headers.get('Content-Disposition'),
      `aisoc-audit-${timestampSlug()}.html`,
    );
    const html = await response.text();
    return { html, filename };
  },
};

/** Parse ``filename="…"`` out of a Content-Disposition header. */
function parseFilenameFromContentDisposition(
  header: string | null,
  fallback: string,
): string {
  if (!header) return fallback;
  // Match RFC 6266 filename="…" — quoted form is what FastAPI emits for us.
  const match = header.match(/filename="([^"]+)"/i);
  return match ? match[1] : fallback;
}

/** ``20260509T234501Z`` style slug for client-side filenames. */
function timestampSlug(): string {
  const now = new Date();
  const pad = (n: number) => n.toString().padStart(2, '0');
  return (
    `${now.getUTCFullYear()}` +
    `${pad(now.getUTCMonth() + 1)}` +
    `${pad(now.getUTCDate())}` +
    `T${pad(now.getUTCHours())}${pad(now.getUTCMinutes())}${pad(now.getUTCSeconds())}Z`
  );
}

// ─── Saved views (per-user filter + column presets) ──────────────────────────
//
// Workstream F3 — analyst quality-of-life. Lets each user park a filter +
// column preset on a list page (alerts, cases, investigations, playbooks)
// and reload it with one click. One preset per ``(user, view_type)`` can be
// flagged ``is_default``; the UI auto-applies it on first load.
//
// The wire format mirrors ``services/api/app/api/v1/endpoints/saved_views.py``
// 1:1: opaque ``filters`` and ``columns`` blobs are owned by the page
// rendering them, so callers cast to whatever shape they need (e.g.
// ``AlertFilters`` for the alerts page) without round-tripping through this
// type. That keeps the saved-views API a *generic* preset store rather than
// a tight coupling between every list page and this client.

/** Pages that support saved views — must match the backend allowlist. */
export type SavedViewType =
  | 'alerts'
  | 'cases'
  | 'investigations'
  | 'playbooks';

/** A saved-view row as returned by the API. */
export interface SavedView {
  id: string;
  view_type: SavedViewType;
  name: string;
  /** Page-specific filter blob — opaque to this client. */
  filters: Record<string, unknown>;
  /** Optional column override. ``null`` means "use page defaults". */
  columns: unknown[] | Record<string, unknown> | null;
  is_default: boolean;
  created_at: string;
  updated_at: string;
}

/** Body for ``POST /saved-views``. */
export interface SavedViewCreateRequest {
  view_type: SavedViewType;
  name: string;
  filters?: Record<string, unknown>;
  columns?: unknown[] | Record<string, unknown> | null;
  is_default?: boolean;
}

/** Body for ``PATCH /saved-views/{id}`` — every field is optional. */
export interface SavedViewUpdateRequest {
  name?: string;
  filters?: Record<string, unknown>;
  /** Pass ``null`` to clear a previously-saved column override. */
  columns?: unknown[] | Record<string, unknown> | null;
  is_default?: boolean;
}

export const savedViewsApi = {
  /**
   * List the caller's presets for one list page. Sorted by
   * ``is_default DESC, updated_at DESC`` server-side, so the default
   * preset (if any) lands first.
   */
  list: (viewType: SavedViewType) =>
    request<SavedView[]>('/api/v1/saved-views', {
      params: { view_type: viewType },
    }),

  /** Create a new preset. Returns the freshly-stamped row. */
  create: (payload: SavedViewCreateRequest) =>
    request<SavedView>('/api/v1/saved-views', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  /** Patch a preset in place — rename, retune filters, toggle default. */
  update: (id: string, payload: SavedViewUpdateRequest) =>
    request<SavedView>(`/api/v1/saved-views/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),

  /** Delete a preset. Returns ``{}`` on the 204 response. */
  delete: (id: string) =>
    request<Record<string, never>>(`/api/v1/saved-views/${id}`, {
      method: 'DELETE',
    }),
};

// ─── Realtime / WebSocket helpers ────────────────────────────────────────────

export const realtimeApi = {
  /** Returns a ready-to-open WebSocket URL for the given channel. */
  channelUrl(channel: 'alerts' | 'cases' | 'agents' | 'all') {
    return `${wsOrigin()}/ws/${channel}?tenant_id=${encodeURIComponent(TENANT_ID)}`;
  },

  /**
   * Health endpoint of the realtime gateway, useful for status pages.
   * Uses the dedicated `/api/v1/realtime/healthz` proxy path so it works
   * same-origin behind the Cloudflare Tunnel.
   */
  health: () =>
    request<{ status: string; clients: number }>(
      '/api/v1/realtime/healthz',
      { baseUrl: REALTIME_BASE },
    ),
};

export default {
  alerts: alertsApi,
  entityRisk: entityRiskApi,
  cases: casesApi,
  metrics: metricsApi,
  connectors: connectorsApi,
  inbox: inboxApi,
  oauth: oauthApi,
  threatIntel: threatIntelApi,
  agents: agentsApi,
  hunt: huntApi,
  graph: graphApi,
  detection: detectionApi,
  detectionProposals: detectionProposalsApi,
  tuning: tuningApi,
  copilot: copilotApi,
  contextual: contextualApi,
  ledger: ledgerApi,
  realtime: realtimeApi,
  responder: responderApi,
  passkey: passkeyApi,
  autonomyPolicy: autonomyPolicyApi,
  feedback: feedbackApi,
  deployment: deploymentApi,
  reports: reportsApi,
  costs: costsApi,
  savedViews: savedViewsApi,
};
