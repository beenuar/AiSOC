/**
 * AiSOC API Client
 * Typed HTTP client for communicating with the Core API service
 */

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080';

interface FetchOptions extends RequestInit {
  params?: Record<string, string | number | boolean | undefined>;
}

async function request<T>(path: string, options: FetchOptions = {}): Promise<T> {
  const { params, ...fetchOptions } = options;

  let url = `${API_BASE}${path}`;
  if (params) {
    const searchParams = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        searchParams.set(key, String(value));
      }
    });
    const qs = searchParams.toString();
    if (qs) url += `?${qs}`;
  }

  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    ...fetchOptions.headers,
  };

  const response = await fetch(url, {
    ...fetchOptions,
    headers,
    cache: 'no-store',
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`API Error ${response.status}: ${errorText}`);
  }

  if (response.status === 204) return {} as T;

  return response.json();
}

// ─── Alerts ─────────────────────────────────────────────────────────────────

export interface Alert {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  status: 'new' | 'triaged' | 'investigating' | 'resolved' | 'false_positive';
  source: string;
  sourceRef?: string;
  tenantId: string;
  riskScore: number;
  mitreAttack?: { tactic: string; technique: string; techniqueId: string }[];
  iocs?: { type: string; value: string; malicious?: boolean }[];
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
    request<AlertsResponse>('/api/v1/alerts', { params: filters as Record<string, string> }),

  get: (id: string) =>
    request<Alert>(`/api/v1/alerts/${id}`),

  update: (id: string, data: Partial<Alert>) =>
    request<Alert>(`/api/v1/alerts/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),

  bulkAction: (ids: string[], action: string, data?: Record<string, unknown>) =>
    request<{ updated: number }>('/api/v1/alerts/bulk', {
      method: 'POST',
      body: JSON.stringify({ ids, action, ...data }),
    }),

  getTimeline: (id: string) =>
    request<{ events: Array<{ id: string; timestamp: string; type: string; title: string; description: string }> }>(
      `/api/v1/alerts/${id}/timeline`
    ),
};

// ─── Cases ───────────────────────────────────────────────────────────────────

export interface Case {
  id: string;
  title: string;
  description: string;
  status: 'open' | 'in_progress' | 'pending' | 'resolved' | 'closed';
  priority: 'critical' | 'high' | 'medium' | 'low';
  assignee?: string;
  tenantId: string;
  alertIds?: string[];
  tags?: string[];
  mitre?: string[];
  resolution?: string;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
  closedAt?: string;
  dueAt?: string;
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
  assignee?: string;
  search?: string;
  page?: number;
  pageSize?: number;
}

export const casesApi = {
  list: (filters: CaseFilters = {}) =>
    request<CasesResponse>('/api/v1/cases', { params: filters as Record<string, string> }),

  get: (id: string) =>
    request<Case>(`/api/v1/cases/${id}`),

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
    request<{ id: string; comment: string; createdAt: string }>(`/api/v1/cases/${id}/comments`, {
      method: 'POST',
      body: JSON.stringify({ comment }),
    }),

  linkAlerts: (id: string, alertIds: string[]) =>
    request<Case>(`/api/v1/cases/${id}/alerts`, {
      method: 'POST',
      body: JSON.stringify({ alertIds }),
    }),
};

// ─── Metrics ─────────────────────────────────────────────────────────────────

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
    request<{ data: Array<{ timestamp: string; count: number }> }>(`/api/v1/metrics/alerts/trend`, {
      params: { period },
    }),
};

// ─── Connectors ──────────────────────────────────────────────────────────────

export interface Connector {
  id: string;
  name: string;
  type: string;
  status: 'active' | 'inactive' | 'error' | 'configuring';
  tenantId: string;
  config?: Record<string, string>;
  lastSync?: string;
  alertsIngested?: number;
  errorMessage?: string;
  createdAt: string;
  updatedAt: string;
}

export interface ConnectorsResponse {
  connectors: Connector[];
  total: number;
}

export const connectorsApi = {
  list: () =>
    request<ConnectorsResponse>('/api/v1/connectors'),

  get: (id: string) =>
    request<Connector>(`/api/v1/connectors/${id}`),

  create: (data: Partial<Connector>) =>
    request<Connector>('/api/v1/connectors', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  test: (id: string) =>
    request<{ success: boolean; message: string; latencyMs: number }>(`/api/v1/connectors/${id}/test`, {
      method: 'POST',
    }),

  delete: (id: string) =>
    request<void>(`/api/v1/connectors/${id}`, { method: 'DELETE' }),
};

// ─── Threat Intel ─────────────────────────────────────────────────────────────

export interface IOCLookup {
  ioc: string;
  type: 'ip' | 'domain' | 'hash' | 'url' | 'email';
  malicious: boolean;
  confidence: number;
  sources: string[];
  tags?: string[];
  firstSeen?: string;
  lastSeen?: string;
  country?: string;
  asn?: string;
  description?: string;
  mitre?: string[];
}

export const threatIntelApi = {
  lookup: (ioc: string) =>
    request<IOCLookup>('/api/v1/enrichment/lookup', { params: { ioc } }),

  bulkLookup: (iocs: string[]) =>
    request<{ results: IOCLookup[] }>('/api/v1/enrichment/bulk', {
      method: 'POST',
      body: JSON.stringify({ iocs }),
    }),
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
};

export default {
  alerts: alertsApi,
  cases: casesApi,
  metrics: metricsApi,
  connectors: connectorsApi,
  threatIntel: threatIntelApi,
  agents: agentsApi,
};
