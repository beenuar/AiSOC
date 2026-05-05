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

const API_BASE = process.env.NEXT_PUBLIC_API_URL || '';
const AGENTS_BASE = process.env.NEXT_PUBLIC_AGENTS_URL || '';
const ACTIONS_BASE = process.env.NEXT_PUBLIC_ACTIONS_URL || '';
const FUSION_BASE = process.env.NEXT_PUBLIC_FUSION_URL || '';
const THREATINTEL_BASE = process.env.NEXT_PUBLIC_THREATINTEL_URL || '';
const ENRICHMENT_BASE = process.env.NEXT_PUBLIC_ENRICHMENT_URL || '';
const REALTIME_BASE = process.env.NEXT_PUBLIC_REALTIME_URL || '';
const WS_BASE = process.env.NEXT_PUBLIC_WS_URL || '';

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
    'X-Tenant-Id': TENANT_ID,
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

export interface CasesResponse {
  cases: Case[];
  total: number;
  page: number;
  pageSize: number;
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

export const casesApi = {
  list: (filters: CaseFilters = {}) =>
    request<CasesResponse>('/api/v1/cases', {
      params: filters as Record<string, string>,
    }),

  get: (id: string) => request<Case>(`/api/v1/cases/${id}`),

  create: (data: Partial<Case>) =>
    request<Case>('/api/v1/cases', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  update: (id: string, data: Partial<Case>) =>
    request<Case>(`/api/v1/cases/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),

  addComment: (id: string, comment: string) =>
    request<{ id: string; comment: string; createdAt: string }>(
      `/api/v1/cases/${id}/comments`,
      {
        method: 'POST',
        body: JSON.stringify({ comment }),
      },
    ),

  linkAlerts: (id: string, alertIds: string[]) =>
    request<Case>(`/api/v1/cases/${id}/alerts`, {
      method: 'POST',
      body: JSON.stringify({ alertIds }),
    }),

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

export interface LedgerRunDetail extends LedgerRunSummary {
  alert_summary: string | null;
  event_count: number;
  artifact_count: number;
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

  delete: (id: string) =>
    request<void>(`/api/v1/connectors/${id}`, { method: 'DELETE' }),
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
};

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
  cases: casesApi,
  metrics: metricsApi,
  connectors: connectorsApi,
  threatIntel: threatIntelApi,
  agents: agentsApi,
  hunt: huntApi,
  graph: graphApi,
  detection: detectionApi,
  copilot: copilotApi,
  contextual: contextualApi,
  ledger: ledgerApi,
  realtime: realtimeApi,
  responder: responderApi,
  passkey: passkeyApi,
};
