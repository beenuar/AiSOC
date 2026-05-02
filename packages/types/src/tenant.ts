/**
 * Multi-tenancy and RBAC types
 */

export type UserRole =
  | "platform_admin"   // Manages the platform itself
  | "tenant_admin"     // Full access within a tenant
  | "security_manager" // Read all, approve actions
  | "analyst_tier1"    // Triage, acknowledge alerts
  | "analyst_tier2"    // Full investigation, create cases
  | "analyst_tier3"    // Advanced hunting, custom rules
  | "threat_hunter"    // Dedicated threat hunting
  | "auditor"          // Read-only, compliance reporting
  | "readonly";        // Read-only general

export type TenantPlan = "starter" | "professional" | "enterprise" | "mssp";

export interface TenantLimits {
  events_per_day: number;
  connectors: number;
  retention_days: number;
  users: number;
  ai_queries_per_day: number;
  playbooks: number;
  custom_rules: number;
}

export interface TenantSettings {
  mfa_required: boolean;
  sso_enabled: boolean;
  sso_provider?: string;
  ip_allowlist?: string[];
  data_residency_region?: string; // "us", "eu", "ap"
  encryption_key_id?: string; // Customer-managed encryption key
  auto_assign_alerts?: boolean;
  default_alert_sla_hours?: number;
  slack_webhook?: string;
  pagerduty_integration_key?: string;
  notifications?: {
    email?: string[];
    slack_channel?: string;
    critical_only?: boolean;
  };
}

export interface Tenant {
  id: string;
  name: string;
  slug: string;
  plan: TenantPlan;
  status: "active" | "suspended" | "trial" | "churned";
  created_at: string;
  trial_ends_at?: string;
  limits: TenantLimits;
  settings: TenantSettings;
  industry?: string;
  country?: string;
  contact_email?: string;
}

export interface User {
  id: string;
  tenant_id: string;
  email: string;
  name: string;
  role: UserRole;
  status: "active" | "invited" | "suspended";
  created_at: string;
  last_login?: string;
  mfa_enabled: boolean;
  preferences?: {
    timezone?: string;
    theme?: "dark" | "light" | "system";
    notification_channels?: ("email" | "slack" | "pagerduty")[];
    dashboard_layout?: string;
    alert_auto_refresh_seconds?: number;
  };
}

export interface ApiKey {
  id: string;
  tenant_id: string;
  name: string;
  key_prefix: string; // Only first 8 chars stored
  scopes: string[];
  created_by: string;
  created_at: string;
  expires_at?: string;
  last_used?: string;
  is_active: boolean;
}

/** RBAC permission check */
export interface PermissionCheck {
  user_role: UserRole;
  resource: string; // e.g., "alerts", "cases", "actions", "rules"
  action: "read" | "write" | "delete" | "approve" | "admin";
}

export const ROLE_PERMISSIONS: Record<UserRole, Record<string, string[]>> = {
  platform_admin: { "*": ["read", "write", "delete", "approve", "admin"] },
  tenant_admin: { "*": ["read", "write", "delete", "approve"] },
  security_manager: {
    alerts: ["read", "write"],
    cases: ["read", "write", "approve"],
    actions: ["read", "approve"],
    rules: ["read"],
    reports: ["read", "write"],
    users: ["read"],
  },
  analyst_tier1: {
    alerts: ["read", "write"],
    cases: ["read"],
    actions: ["read"],
    rules: ["read"],
    reports: ["read"],
  },
  analyst_tier2: {
    alerts: ["read", "write"],
    cases: ["read", "write"],
    actions: ["read", "write"],
    rules: ["read"],
    reports: ["read", "write"],
  },
  analyst_tier3: {
    alerts: ["read", "write"],
    cases: ["read", "write"],
    actions: ["read", "write"],
    rules: ["read", "write"],
    reports: ["read", "write"],
    playbooks: ["read", "write"],
  },
  threat_hunter: {
    alerts: ["read", "write"],
    cases: ["read", "write"],
    actions: ["read"],
    rules: ["read", "write"],
    hunt: ["read", "write"],
    reports: ["read", "write"],
  },
  auditor: { "*": ["read"] },
  readonly: { "*": ["read"] },
};
