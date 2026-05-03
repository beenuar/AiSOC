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
