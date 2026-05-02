/**
 * Playbook / SOAR automation types
 */

export type PlaybookTriggerType =
  | "alert_created"
  | "alert_severity_changed"
  | "alert_status_changed"
  | "case_created"
  | "manual"
  | "scheduled"
  | "webhook"
  | "threat_intel_hit";

export type ActionType =
  | "notify_slack"
  | "notify_email"
  | "create_ticket_jira"
  | "create_ticket_servicenow"
  | "page_oncall_pagerduty"
  | "enrich_ip"
  | "enrich_domain"
  | "enrich_hash"
  | "enrich_user"
  | "isolate_host"
  | "contain_user"
  | "block_ip"
  | "block_domain"
  | "block_hash"
  | "revoke_session"
  | "snapshot_host"
  | "collect_forensics"
  | "run_query_splunk"
  | "run_query_crowdstrike"
  | "custom_http"
  | "wait"
  | "human_approval"
  | "set_alert_status"
  | "set_case_priority"
  | "add_case_comment"
  | "assign_case"
  | "conditional";

export interface ActionConfig {
  action_type: ActionType;
  parameters: Record<string, unknown>;
  timeout_seconds?: number;
  retry_count?: number;
  retry_delay_seconds?: number;
  on_failure?: "stop" | "continue" | "rollback";
  // For conditional action
  condition_field?: string;
  condition_operator?: "eq" | "ne" | "gt" | "lt" | "contains" | "regex";
  condition_value?: unknown;
  true_branch?: string[];  // step IDs
  false_branch?: string[];
}

export interface PlaybookStep {
  id: string;
  name: string;
  description?: string;
  action: ActionConfig;
  depends_on?: string[]; // IDs of steps that must complete first
  run_parallel?: boolean;
  is_approval_gate?: boolean;
  approval_roles?: string[];
  dry_run_safe?: boolean; // Can be safely run in dry_run mode
  blast_radius_check?: boolean; // Require blast-radius assessment before execution
}

export interface Playbook {
  id: string;
  tenant_id: string;
  name: string;
  description: string;
  version: number;
  is_active: boolean;
  is_draft: boolean;

  trigger: {
    type: PlaybookTriggerType;
    conditions?: Record<string, unknown>; // e.g., severity = "critical"
    schedule?: string; // cron expression
    webhook_id?: string;
  };

  steps: PlaybookStep[];
  tags: string[];

  created_by: string;
  created_at: string;
  updated_at: string;
  approved_by?: string;
  approved_at?: string;

  // Stats
  run_count?: number;
  success_rate?: number;
  avg_duration_seconds?: number;
  last_run_at?: string;
  last_run_status?: "success" | "partial" | "failed";
}

export type PlaybookRunStatus = "running" | "waiting_approval" | "paused" | "completed" | "failed" | "cancelled";

export interface PlaybookStepResult {
  step_id: string;
  step_name: string;
  status: "pending" | "running" | "success" | "failed" | "skipped" | "waiting_approval";
  started_at?: string;
  completed_at?: string;
  output?: Record<string, unknown>;
  error?: string;
  dry_run?: boolean;
}

export interface PlaybookRun {
  id: string;
  playbook_id: string;
  tenant_id: string;
  trigger_type: PlaybookTriggerType;
  trigger_context: {
    alert_id?: string;
    case_id?: string;
    manual_by?: string;
  };
  status: PlaybookRunStatus;
  is_dry_run: boolean;
  step_results: PlaybookStepResult[];
  started_at: string;
  completed_at?: string;
  error?: string;
  blast_radius_assessment?: {
    estimated_scope: string;
    affected_assets: string[];
    requires_approval: boolean;
    approved_by?: string;
    approved_at?: string;
  };
}
