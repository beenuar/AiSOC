/**
 * Detection Rule types
 */

export type RuleLanguage = "sigma" | "yara" | "kql" | "spl" | "eql" | "lucene" | "custom_cep";
export type RuleCategory = "malware" | "lateral_movement" | "exfiltration" | "persistence" | "privilege_escalation" | "initial_access" | "execution" | "defense_evasion" | "credential_access" | "discovery" | "collection" | "impact" | "reconnaissance" | "resource_development" | "command_and_control";
export type RuleStatus = "active" | "disabled" | "testing" | "deprecated";

export interface RuleThreshold {
  count: number;
  group_by?: string[];
  window_seconds: number;
}

export interface RuleSuppressionConfig {
  field: string;
  value?: string;
  window_seconds: number;
  max_alerts?: number;
}

export interface DetectionRule {
  id: string;
  tenant_id: string;

  name: string;
  description: string;
  author?: string;
  references?: string[];
  tags: string[];

  // MITRE
  mitre_tactics: string[];
  mitre_techniques: string[];

  // Language and query
  language: RuleLanguage;
  query: string;
  condition?: string; // For Sigma rules
  false_positives?: string[];

  // Configuration
  severity: "critical" | "high" | "medium" | "low" | "info";
  category?: RuleCategory;
  status: RuleStatus;

  // Scheduling
  run_every_seconds: number;
  lookback_seconds: number;

  // Dedup / suppression
  dedup_key_fields?: string[];
  suppression?: RuleSuppressionConfig;
  threshold?: RuleThreshold;

  // Alert enrichment overrides
  alert_title_template?: string; // Jinja2 template
  alert_description_template?: string;
  recommended_actions?: string[];

  // Playbook auto-trigger
  auto_playbook_id?: string;

  // Stats
  last_fired?: string;
  fire_count_30d?: number;
  fp_count_30d?: number;
  tp_count_30d?: number;

  // Metadata
  is_system_rule: boolean; // Shipped by platform
  source?: "sigma_community" | "custom" | "ai_generated" | "imported";
  sigma_id?: string;
  version: number;

  created_at: string;
  updated_at: string;
  created_by?: string;
  approved_by?: string;
  approved_at?: string;
}

export interface RuleTestResult {
  rule_id: string;
  test_events_count: number;
  matched_count: number;
  execution_time_ms: number;
  sample_matches?: Array<{
    event_id: string;
    matched_fields: Record<string, unknown>;
  }>;
  errors?: string[];
}
