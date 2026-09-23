/**
 * Hand-authored TypeScript types mirroring the AiSOC OpenAPI schema.
 *
 * These are kept in sync with docs/openapi.yaml via the `pnpm codegen` script
 * which regenerates src/openapi.d.ts.  The types below are a curated, ergonomic
 * subset intended for direct use by SDK consumers.
 */

// ── Enums ─────────────────────────────────────────────────────────────────────

export type AlertSeverity = "critical" | "high" | "medium" | "low" | "info";
export type AlertStatus = "open" | "in_progress" | "closed" | "false_positive";
export type CasePriority = "critical" | "high" | "medium" | "low";
export type CaseStatus = "open" | "investigating" | "resolved" | "closed";

// ── Core models ───────────────────────────────────────────────────────────────

export interface Alert {
  id: string;
  tenantId: string;
  title: string;
  severity: AlertSeverity;
  status: AlertStatus;
  source: string;
  sourceRef?: string;
  mitreTactics: string[];
  aiScore?: number;
  caseId?: string;
  createdAt: string;
  updatedAt: string;
}

export interface Case {
  id: string;
  tenantId: string;
  caseNumber: string;
  title: string;
  status: CaseStatus;
  priority: CasePriority;
  assignee?: string;
  mitreTactics: string[];
  alertIds: string[];
  createdAt: string;
  updatedAt: string;
}

export interface DetectionRule {
  id: string;
  tenantId: string;
  name: string;
  description?: string;
  ruleLanguage: string;
  severity: AlertSeverity;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface Connector {
  id: string;
  tenantId: string;
  name: string;
  connectorType: string;
  isEnabled: boolean;
  healthStatus: string;
  eventsIngested: number;
  createdAt: string;
  updatedAt: string;
}

export interface Playbook {
  id: string;
  name: string;
  description?: string;
  version: string;
  steps: PlaybookStep[];
  triggerConditions?: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

export interface PlaybookStep {
  id: string;
  name: string;
  type: string;
  action?: string;
  parameters?: Record<string, unknown>;
  nextSteps?: string[];
}

export interface PlaybookRun {
  runId: string;
  playbookId: string;
  status: string;
  startedAt: string;
  completedAt?: string;
  triggerData?: Record<string, unknown>;
  stepResults?: Record<string, unknown>;
}

export interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  scopes: string[];
  expiresAt?: string;
  lastUsedAt?: string;
  createdAt: string;
}

// ── Request / response envelopes ─────────────────────────────────────────────

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
}

export interface ErrorResponse {
  detail: string;
  code?: string;
}

// ── Filter / pagination params ────────────────────────────────────────────────

export interface PaginationParams {
  page?: number;
  pageSize?: number;
}

export interface AlertFilters extends PaginationParams {
  severity?: AlertSeverity;
  status?: AlertStatus;
  caseId?: string;
  search?: string;
}

export interface CaseFilters extends PaginationParams {
  status?: CaseStatus;
  priority?: CasePriority;
  assignee?: string;
}

export interface ApiKeyCreateRequest {
  name: string;
  scopes: string[];
  expiresAt?: string;
}

export interface ApiKeyCreateResponse {
  key: ApiKey;
  /** Raw key — only returned on creation, store it safely. */
  rawKey: string;
}

// ─── Responder ───────────────────────────────────────────────────────────────

export type ApprovalStatus = "pending" | "approved" | "denied" | "expired";
export type ApprovalRisk = "low" | "medium" | "high" | "critical";

/** An action an agent proposed that needs a human decision before it runs. */
export interface Approval {
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
  risk_level: ApprovalRisk;
  /**
   * The action itself: `action_type`, `target`, `parameters`. After a
   * decision it also carries a `dispatch` record saying whether the action
   * actually executed — the approval row is the answer to "was this done",
   * not just "was this decided".
   */
  action: Record<string, unknown>;
  status: ApprovalStatus;
  decided_by_id: string | null;
  decided_at: string | null;
  decision_comment: string | null;
  expires_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface ApprovalFilters extends PaginationParams {
  status?: ApprovalStatus;
  /** Only approvals routed specifically to the calling user. */
  mine?: boolean;
  risk_level?: ApprovalRisk;
}

/** A W3C PushSubscription, as `PushSubscription.toJSON()` produces it. */
export interface PushSubscriptionPayload {
  endpoint: string;
  keys: { p256dh: string; auth: string };
  /** Topics to receive: `p0_alert`, `agent_approval`, `oncall_handoff`. */
  topics?: string[];
}

export interface OnCallEntry {
  user_id: string;
  name: string;
  email: string | null;
  starts_at: string;
  ends_at: string;
  rotation: string | null;
}

/** One registered live action: a vendor, a verb, and its contract. */
export interface LiveActionDescriptor {
  vendor_id: string;
  capability: string;
  description?: string;
  [key: string]: unknown;
}

export interface LiveActionDiscovery {
  executors: LiveActionDescriptor[];
  vendors: string[];
  capabilities: string[];
}
