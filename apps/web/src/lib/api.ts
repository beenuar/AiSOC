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
 *   - Base URLs are configured via NEXT_PUBLIC_* env vars and default to
 *     local-development hostnames.
 */

const API_BASE =
  process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
const AGENTS_BASE =
  process.env.NEXT_PUBLIC_AGENTS_URL || 'http://localhost:8001';
const ACTIONS_BASE =
  process.env.NEXT_PUBLIC_ACTIONS_URL || 'http://localhost:8002';
const FUSION_BASE =
  process.env.NEXT_PUBLIC_FUSION_URL || 'http://localhost:8003';
const THREATINTEL_BASE =
  process.env.NEXT_PUBLIC_THREATINTEL_URL || 'http://localhost:8005';
const ENRICHMENT_BASE =
  process.env.NEXT_PUBLIC_ENRICHMENT_URL || 'http://localhost:8080';
const REALTIME_BASE =
  process.env.NEXT_PUBLIC_REALTIME_URL || 'http://localhost:8086';
const WS_BASE =
  process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8086';

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

export const connectorsApi = {
  list: () => request<ConnectorsResponse>('/api/v1/connectors'),

  get: (id: string) => request<Connector>(`/api/v1/connectors/${id}`),

  create: (data: Partial<Connector>) =>
    request<Connector>('/api/v1/connectors', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  update: (id: string, data: Partial<Connector>) =>
    request<Connector>(`/api/v1/connectors/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),

  test: (id: string) =>
    request<{ success: boolean; message: string; latencyMs: number }>(
      `/api/v1/connectors/${id}/test`,
      { method: 'POST' },
    ),

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

// ─── Realtime / WebSocket helpers ────────────────────────────────────────────

export const realtimeApi = {
  /** Returns a ready-to-open WebSocket URL for the given channel. */
  channelUrl(channel: 'alerts' | 'cases' | 'agents' | 'all') {
    return `${WS_BASE}/ws/${channel}?tenant_id=${encodeURIComponent(TENANT_ID)}`;
  },

  /** Health endpoint of the realtime gateway, useful for status pages. */
  health: () =>
    request<{ status: string; clients: number }>('/healthz', {
      baseUrl: REALTIME_BASE,
    }),
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
  realtime: realtimeApi,
};
