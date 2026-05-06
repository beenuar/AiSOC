/**
 * AiSOCClient — typed HTTP client built on top of openapi-fetch.
 *
 * The client is structured around resource namespaces that mirror the REST API:
 *   client.alerts.*       – alert management
 *   client.cases.*        – case management
 *   client.detections.*   – detection rule management
 *   client.connectors.*   – connector management
 *   client.playbooks.*    – playbook management
 *   client.apiKeys.*      – API key management
 */

import type {
  Alert,
  AlertFilters,
  ApiKey,
  ApiKeyCreateRequest,
  ApiKeyCreateResponse,
  Case,
  CaseFilters,
  Connector,
  DetectionRule,
  Page,
  PaginationParams,
  Playbook,
  PlaybookRun,
} from "./types.js";

export interface AiSOCClientOptions {
  /** Base URL of the AiSOC API, e.g. https://soc.example.com */
  baseUrl: string;
  /**
   * Authentication token.  Accepts either:
   *   - A JWT bearer token (from POST /auth/login)
   *   - A scoped API key (aisoc_…)
   */
  token: string;
  /** Additional headers merged into every request. */
  headers?: Record<string, string>;
  /** Fetch implementation — defaults to global fetch. */
  fetch?: typeof globalThis.fetch;
}

// ─── Error class ─────────────────────────────────────────────────────────────

export class AiSOCError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: string,
  ) {
    super(`AiSOC API error ${status}: ${body}`);
    this.name = "AiSOCError";
  }
}

// ─── Resource sub-clients ─────────────────────────────────────────────────────

class ResourceClient {
  constructor(
    protected readonly baseUrl: string,
    protected readonly token: string,
    protected readonly extraHeaders: Record<string, string> = {},
  ) {}

  protected async request<T>(
    method: "GET" | "POST" | "PATCH" | "DELETE",
    path: string,
    body?: unknown,
    query?: Record<string, unknown>,
  ): Promise<T> {
    const url = new URL(path, this.baseUrl);
    if (query) {
      for (const [k, v] of Object.entries(query)) {
        if (v !== undefined && v !== null) {
          url.searchParams.set(k, String(v));
        }
      }
    }
    const res = await fetch(url.toString(), {
      method,
      headers: {
        Authorization: `Bearer ${this.token}`,
        "Content-Type": "application/json",
        ...this.extraHeaders,
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) {
      throw new AiSOCError(res.status, await res.text());
    }
    if (res.status === 204) return undefined as unknown as T;
    return res.json() as Promise<T>;
  }
}

class AlertsClient extends ResourceClient {
  async list(filters?: AlertFilters): Promise<Page<Alert>> {
    return this.request<Page<Alert>>("GET", "/api/v1/alerts", undefined, filters as Record<string, unknown>);
  }

  async get(id: string): Promise<Alert> {
    return this.request<Alert>("GET", `/api/v1/alerts/${id}`);
  }

  async update(id: string, data: Partial<Alert>): Promise<Alert> {
    return this.request<Alert>("PATCH", `/api/v1/alerts/${id}`, data);
  }
}

class CasesClient extends ResourceClient {
  async list(filters?: CaseFilters): Promise<Page<Case>> {
    return this.request<Page<Case>>("GET", "/api/v1/cases", undefined, filters as Record<string, unknown>);
  }

  async get(id: string): Promise<Case> {
    return this.request<Case>("GET", `/api/v1/cases/${id}`);
  }

  async create(data: Partial<Case>): Promise<Case> {
    return this.request<Case>("POST", "/api/v1/cases", data);
  }

  async update(id: string, data: Partial<Case>): Promise<Case> {
    return this.request<Case>("PATCH", `/api/v1/cases/${id}`, data);
  }

  async delete(id: string): Promise<void> {
    return this.request<void>("DELETE", `/api/v1/cases/${id}`);
  }
}

class DetectionsClient extends ResourceClient {
  async list(params?: PaginationParams): Promise<Page<DetectionRule>> {
    return this.request<Page<DetectionRule>>("GET", "/api/v1/detections", undefined, params as Record<string, unknown>);
  }

  async get(id: string): Promise<DetectionRule> {
    return this.request<DetectionRule>("GET", `/api/v1/detections/${id}`);
  }
}

class ConnectorsClient extends ResourceClient {
  async list(params?: PaginationParams): Promise<Page<Connector>> {
    return this.request<Page<Connector>>("GET", "/api/v1/connectors", undefined, params as Record<string, unknown>);
  }

  async get(id: string): Promise<Connector> {
    return this.request<Connector>("GET", `/api/v1/connectors/${id}`);
  }
}

class PlaybooksClient extends ResourceClient {
  async list(params?: PaginationParams): Promise<Page<Playbook>> {
    return this.request<Page<Playbook>>("GET", "/api/v1/playbooks", undefined, params as Record<string, unknown>);
  }

  async get(id: string): Promise<Playbook> {
    return this.request<Playbook>("GET", `/api/v1/playbooks/${id}`);
  }

  async create(data: Partial<Playbook>): Promise<Playbook> {
    return this.request<Playbook>("POST", "/api/v1/playbooks", data);
  }

  async update(id: string, data: Partial<Playbook>): Promise<Playbook> {
    return this.request<Playbook>("PATCH", `/api/v1/playbooks/${id}`, data);
  }

  async delete(id: string): Promise<void> {
    return this.request<void>("DELETE", `/api/v1/playbooks/${id}`);
  }

  async run(id: string, triggerData?: Record<string, unknown>): Promise<PlaybookRun> {
    return this.request<PlaybookRun>("POST", `/api/v1/playbooks/${id}/run`, { trigger_data: triggerData });
  }

  async getRun(runId: string): Promise<PlaybookRun> {
    return this.request<PlaybookRun>("GET", `/api/v1/playbooks/runs/${runId}`);
  }
}

class ApiKeysClient extends ResourceClient {
  async list(): Promise<Page<ApiKey>> {
    return this.request<Page<ApiKey>>("GET", "/api/v1/api-keys");
  }

  async create(data: ApiKeyCreateRequest): Promise<ApiKeyCreateResponse> {
    return this.request<ApiKeyCreateResponse>("POST", "/api/v1/api-keys", data);
  }

  async revoke(id: string): Promise<void> {
    return this.request<void>("DELETE", `/api/v1/api-keys/${id}`);
  }
}

// ─── Main client ─────────────────────────────────────────────────────────────

export class AiSOCClient {
  /** Alert management — list, get, update alerts. */
  readonly alerts: AlertsClient;
  /** Case management — full CRUD. */
  readonly cases: CasesClient;
  /** Detection rule management. */
  readonly detections: DetectionsClient;
  /** Connector management. */
  readonly connectors: ConnectorsClient;
  /** Playbook management and execution. */
  readonly playbooks: PlaybooksClient;
  /** Scoped API key management. */
  readonly apiKeys: ApiKeysClient;

  constructor(opts: AiSOCClientOptions) {
    const args: [string, string, Record<string, string>] = [
      opts.baseUrl,
      opts.token,
      opts.headers ?? {},
    ];
    this.alerts = new AlertsClient(...args);
    this.cases = new CasesClient(...args);
    this.detections = new DetectionsClient(...args);
    this.connectors = new ConnectorsClient(...args);
    this.playbooks = new PlaybooksClient(...args);
    this.apiKeys = new ApiKeysClient(...args);
  }

  /**
   * Send an introspection query to the GraphQL endpoint.
   * Useful for verifying connectivity and auth.
   */
  async graphql<T = unknown>(
    query: string,
    variables?: Record<string, unknown>,
  ): Promise<{ data: T; errors?: Array<{ message: string }> }> {
    const sub = new ResourceClient(
      (this.alerts as unknown as { baseUrl: string }).baseUrl,
      (this.alerts as unknown as { token: string }).token,
    );
    return sub["request"]("POST", "/graphql", { query, variables });
  }
}
