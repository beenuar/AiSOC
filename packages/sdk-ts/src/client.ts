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
 *   client.approvals.*   – action approvals awaiting a human decision
 *   client.push.*        – Web Push subscription management
 *   client.onCall.*      – on-call rota
 *   client.liveActions.* – what this deployment can actually do to the estate
 *
 * The responder namespaces exist because a responder client — the PWA, the
 * native app, or anything a user writes — needs approvals, push and on-call,
 * and the hand-written client covered none of them. They were in
 * docs/openapi.yaml the whole time, which is exactly why nobody noticed: the
 * generated types were complete and the ergonomic surface was not.
 */

import type {
  Alert,
  AlertFilters,
  ApiKey,
  ApiKeyCreateRequest,
  ApiKeyCreateResponse,
  Approval,
  ApprovalFilters,
  Case,
  CaseFilters,
  Connector,
  DetectionRule,
  LiveActionDiscovery,
  OnCallEntry,
  Page,
  PaginationParams,
  Playbook,
  PlaybookRun,
  PushSubscriptionPayload,
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
    /**
     * `AiSOCClientOptions.fetch` was documented as "Fetch implementation —
     * defaults to global fetch" and then never threaded through: every
     * request called the global directly. So a caller could pass one and
     * silently not get it, which matters most in the two places it exists
     * for — a test double, and a React Native runtime whose fetch is not the
     * same object the module closed over.
     *
     * Left undefined rather than defaulted, and resolved per call, so that
     * replacing the global after construction still works.
     */
    protected readonly fetchImpl?: typeof globalThis.fetch,
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
    const doFetch = this.fetchImpl ?? globalThis.fetch;
    const res = await doFetch(url.toString(), {
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

// ─── Responder namespaces ────────────────────────────────────────────────────

class ApprovalsClient extends ResourceClient {
  /** Pending by default, because that is the whole point of the queue. */
  async list(filters?: ApprovalFilters): Promise<Page<Approval>> {
    return this.request<Page<Approval>>("GET", "/api/v1/approvals", undefined, filters as Record<string, unknown>);
  }

  async get(id: string): Promise<Approval> {
    return this.request<Approval>("GET", `/api/v1/approvals/${id}`);
  }

  /**
   * Approve or deny.
   *
   * Deciding carries the action through to the execution service, so a
   * non-2xx here can mean "your decision was recorded and the action was
   * refused" rather than "nothing happened". The thrown `AiSOCError` body
   * says which.
   */
  async decide(id: string, decision: "approve" | "deny", comment?: string): Promise<Approval> {
    return this.request<Approval>("POST", `/api/v1/approvals/${id}/decide`, { decision, comment });
  }
}

class PushClient extends ResourceClient {
  /** VAPID public key. Required before a browser can subscribe at all. */
  async publicKey(): Promise<{ public_key: string }> {
    return this.request<{ public_key: string }>("GET", "/api/v1/push/public-key");
  }

  async subscribe(subscription: PushSubscriptionPayload): Promise<{ status: string }> {
    return this.request<{ status: string }>("POST", "/api/v1/push/subscribe", subscription);
  }

  async unsubscribe(endpoint: string): Promise<{ status: string }> {
    return this.request<{ status: string }>("POST", "/api/v1/push/unsubscribe", { endpoint });
  }

  /** Send yourself one, to prove delivery works before relying on it. */
  async test(): Promise<{ status: string }> {
    return this.request<{ status: string }>("POST", "/api/v1/push/test");
  }
}

class OnCallClient extends ResourceClient {
  async list(): Promise<Page<OnCallEntry>> {
    return this.request<Page<OnCallEntry>>("GET", "/api/v1/oncall");
  }

  async me(): Promise<OnCallEntry> {
    return this.request<OnCallEntry>("GET", "/api/v1/oncall/me");
  }
}

class LiveActionsClient extends ResourceClient {
  /** What this deployment can do to the estate, and with which vendor. */
  async discover(filters?: { vendor_id?: string; capability?: string }): Promise<LiveActionDiscovery> {
    return this.request<LiveActionDiscovery>("GET", "/api/v1/live-actions", undefined, filters);
  }

  async vendorsFor(capability: string): Promise<string[]> {
    return this.request<string[]>("GET", `/api/v1/live-actions/by-capability/${encodeURIComponent(capability)}`);
  }

  async capabilitiesFor(vendorId: string): Promise<string[]> {
    return this.request<string[]>("GET", `/api/v1/live-actions/by-vendor/${encodeURIComponent(vendorId)}`);
  }

  /**
   * Preview an action. There is deliberately no `dispatch` here: a live
   * containment goes through the approval path so an approver is bound to
   * it, and the API exposes no un-approved dispatch route to proxy.
   */
  async dryRun(request: Record<string, unknown>): Promise<unknown> {
    return this.request<unknown>("POST", "/api/v1/live-actions/dry-run", request);
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
  /** Action approvals awaiting a human decision. */
  readonly approvals: ApprovalsClient;
  /** Web Push subscription management. */
  readonly push: PushClient;
  /** On-call rota. */
  readonly onCall: OnCallClient;
  /** The live-action registry: discovery and dry-run. */
  readonly liveActions: LiveActionsClient;

  constructor(opts: AiSOCClientOptions) {
    const args: [string, string, Record<string, string>, (typeof globalThis.fetch) | undefined] = [
      opts.baseUrl,
      opts.token,
      opts.headers ?? {},
      opts.fetch,
    ];
    this.alerts = new AlertsClient(...args);
    this.cases = new CasesClient(...args);
    this.detections = new DetectionsClient(...args);
    this.connectors = new ConnectorsClient(...args);
    this.playbooks = new PlaybooksClient(...args);
    this.apiKeys = new ApiKeysClient(...args);
    this.approvals = new ApprovalsClient(...args);
    this.push = new PushClient(...args);
    this.onCall = new OnCallClient(...args);
    this.liveActions = new LiveActionsClient(...args);
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
