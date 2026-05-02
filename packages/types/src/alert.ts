/**
 * AiSOC Alert and Incident types
 */

import type { OcsfAttack, OcsfDevice, OcsfNetworkEndpoint, OcsfObservable, OcsfUser, Severity, SeverityId } from "./ocsf";

export type AlertStatus =
  | "new"
  | "open"
  | "in_progress"
  | "pending_action"
  | "resolved"
  | "false_positive"
  | "duplicate"
  | "suppressed";

export type AlertSource = "detection_rule" | "ml_model" | "threat_intel" | "user_reported" | "connector" | "honeypot";

export type ThreatCategory =
  | "malware"
  | "ransomware"
  | "phishing"
  | "credential_theft"
  | "lateral_movement"
  | "exfiltration"
  | "persistence"
  | "privilege_escalation"
  | "defense_evasion"
  | "discovery"
  | "initial_access"
  | "execution"
  | "command_and_control"
  | "impact"
  | "insider_threat"
  | "supply_chain"
  | "vulnerability_exploitation"
  | "reconnaissance"
  | "other";

/** Alert IOC - Indicator of Compromise */
export interface AlertIOC {
  type: "ip" | "domain" | "url" | "file_hash" | "email" | "user" | "cve" | "process" | "registry_key" | "certificate";
  value: string;
  enrichment?: {
    reputation_score?: number; // 0-100 (100 = most malicious)
    threat_feeds?: string[];
    first_seen?: string;
    last_seen?: string;
    malware_families?: string[];
    tags?: string[];
    country?: string;
    asn?: string;
    whois?: Record<string, string>;
    virustotal_detections?: number;
    virustotal_total?: number;
  };
  observable?: OcsfObservable;
}

/** Alert evidence item */
export interface AlertEvidence {
  id: string;
  type: "log_event" | "network_capture" | "file_sample" | "process_tree" | "memory_dump" | "screenshot";
  source_event_id?: string;
  timestamp: string;
  description: string;
  data: Record<string, unknown>;
  raw?: string;
}

/** MITRE ATT&CK technique reference */
export interface MitreAttackRef {
  tactic_id: string;
  tactic_name: string;
  technique_id: string;
  technique_name: string;
  subtechnique_id?: string;
  subtechnique_name?: string;
  confidence?: number; // 0-100
}

/** Alert entity */
export interface Alert {
  id: string;
  tenant_id: string;

  // Identity
  title: string;
  description: string;
  categories: ThreatCategory[];
  tags: string[];

  // Severity and status
  severity: Severity;
  severity_id: SeverityId;
  confidence_score: number; // 0-100 AI confidence
  risk_score: number; // 0-100 composite risk
  status: AlertStatus;

  // Timing
  first_seen: string;
  last_seen: string;
  created_at: string;
  updated_at: string;
  resolved_at?: string;

  // Source
  source: AlertSource;
  source_rule_id?: string;
  source_rule_name?: string;
  source_connector_id?: string;
  source_model_id?: string;

  // Entities
  affected_entities: {
    devices?: OcsfDevice[];
    users?: OcsfUser[];
    endpoints?: OcsfNetworkEndpoint[];
  };

  // Intel
  iocs: AlertIOC[];
  mitre_attacks: MitreAttackRef[];
  cves?: string[];
  evidences: AlertEvidence[];

  // Correlation
  correlated_event_ids: string[];
  related_alert_ids: string[];
  case_id?: string;
  incident_id?: string;

  // AI Analysis
  ai_summary?: string;
  ai_investigation_notes?: string;
  recommended_actions?: string[];
  auto_enriched: boolean;
  enrichment_timestamp?: string;

  // Assignment
  assigned_to?: string;
  assigned_at?: string;

  // Dedup / fusion
  event_count: number;
  dedup_key: string;
  merged_alert_ids?: string[];
}

/** Alert filter params */
export interface AlertFilters {
  tenant_id?: string;
  status?: AlertStatus[];
  severity?: Severity[];
  category?: ThreatCategory[];
  from?: string;
  to?: string;
  search?: string;
  assigned_to?: string;
  source?: AlertSource[];
  has_iocs?: boolean;
  limit?: number;
  offset?: number;
  sort_by?: "created_at" | "updated_at" | "risk_score" | "severity_id";
  sort_dir?: "asc" | "desc";
}

/** Alert summary stats */
export interface AlertStats {
  total: number;
  by_severity: Record<Severity, number>;
  by_status: Record<AlertStatus, number>;
  by_category: Record<ThreatCategory, number>;
  by_source: Record<AlertSource, number>;
  mttr_minutes?: number; // Mean time to resolve
  mttd_minutes?: number; // Mean time to detect
  false_positive_rate?: number;
}

/** Alert action / response */
export interface AlertAction {
  id: string;
  alert_id: string;
  type: "isolate_host" | "block_ip" | "disable_user" | "kill_process" | "quarantine_file" | "custom_script" | "notify" | "create_ticket" | "enrich" | "suppress";
  status: "pending" | "running" | "completed" | "failed" | "rolled_back";
  created_by: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  parameters: Record<string, unknown>;
  result?: Record<string, unknown>;
  error?: string;
  rollback_available: boolean;
  dry_run: boolean;
  blast_radius_estimate?: {
    impacted_users?: number;
    impacted_devices?: number;
    impacted_services?: string[];
    risk_level: "low" | "medium" | "high" | "critical";
  };
}
