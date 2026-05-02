/**
 * AiSOC Case Management types
 */

export type CaseStatus = "open" | "in_progress" | "pending_closure" | "closed" | "cancelled";
export type CasePriority = "critical" | "high" | "medium" | "low";
export type CaseType =
  | "incident"
  | "investigation"
  | "threat_hunt"
  | "vulnerability"
  | "compliance"
  | "false_positive_review"
  | "post_mortem";

export interface CaseTimeline {
  id: string;
  case_id: string;
  timestamp: string;
  type: "alert_added" | "comment" | "status_change" | "action_taken" | "evidence_added" | "assignment" | "tag_added" | "playbook_step";
  author: string;
  content: string;
  metadata?: Record<string, unknown>;
  is_automated: boolean;
}

export interface CaseTask {
  id: string;
  case_id: string;
  title: string;
  description?: string;
  status: "todo" | "in_progress" | "done" | "skipped";
  assigned_to?: string;
  due_at?: string;
  completed_at?: string;
  created_by: string;
  created_at: string;
  playbook_step_id?: string;
}

export interface CaseArtifact {
  id: string;
  case_id: string;
  name: string;
  type: "file" | "screenshot" | "log_export" | "memory_dump" | "pcap" | "report";
  size_bytes?: number;
  sha256?: string;
  storage_path: string;
  uploaded_by: string;
  uploaded_at: string;
  description?: string;
  tags?: string[];
}

export interface CaseTicketRef {
  integration: "jira" | "servicenow" | "pagerduty" | "linear" | "github" | "custom";
  ticket_id: string;
  ticket_url?: string;
  synced_at?: string;
  status?: string;
}

export interface Case {
  id: string;
  tenant_id: string;
  case_number: string; // Human-readable: SOC-2024-0001

  // Core fields
  title: string;
  description: string;
  type: CaseType;
  status: CaseStatus;
  priority: CasePriority;

  // Timing
  created_at: string;
  updated_at: string;
  closed_at?: string;
  sla_due_at?: string;
  sla_breached?: boolean;

  // Ownership
  created_by: string;
  assigned_to?: string;
  team?: string;
  watchers?: string[];

  // Links
  alert_ids: string[];
  incident_id?: string;
  parent_case_id?: string;
  child_case_ids?: string[];

  // Content
  tags: string[];
  affected_assets: string[];
  tasks: CaseTask[];
  timeline: CaseTimeline[];
  artifacts: CaseArtifact[];
  external_tickets?: CaseTicketRef[];

  // Playbook
  active_playbook_id?: string;
  playbook_run_id?: string;
  playbook_progress?: number; // 0-100

  // AI
  ai_summary?: string;
  ai_recommended_actions?: string[];
  threat_score?: number; // 0-100
  containment_state?: "unknown" | "not_contained" | "partial" | "contained" | "eradicated" | "recovered";

  // Metrics
  mttr_minutes?: number;
  time_to_contain_minutes?: number;
  analyst_hours?: number;
  cost_estimate_usd?: number;
}

export interface CaseFilters {
  tenant_id?: string;
  status?: CaseStatus[];
  priority?: CasePriority[];
  type?: CaseType[];
  assigned_to?: string;
  created_by?: string;
  from?: string;
  to?: string;
  search?: string;
  has_sla_breach?: boolean;
  limit?: number;
  offset?: number;
  sort_by?: "created_at" | "updated_at" | "priority" | "sla_due_at";
  sort_dir?: "asc" | "desc";
}
