/**
 * Connector / Integration types
 */

export type ConnectorType =
  | "crowdstrike_falcon"
  | "microsoft_sentinel"
  | "splunk_enterprise"
  | "aws_security_hub"
  | "okta_system_log"
  | "sentinelone"
  | "palo_alto_cortex"
  | "google_chronicle"
  | "ibm_qradar"
  | "vectra_ai"
  | "darktrace"
  | "tenable_io"
  | "qualys"
  | "jira"
  | "servicenow"
  | "pagerduty"
  | "slack"
  | "teams"
  | "custom_webhook"
  | "syslog"
  | "http_pull"
  | "kafka";

export type ConnectorCategory =
  | "edr"
  | "xdr"
  | "siem"
  | "identity"
  | "cloud_security"
  | "network"
  | "vulnerability"
  | "threat_intel"
  | "ticketing"
  | "notification"
  | "custom";

export type ConnectorStatus = "active" | "degraded" | "error" | "disabled" | "configuring";

export type AuthType = "api_key" | "oauth2" | "basic" | "certificate" | "iam_role" | "token";

export interface ConnectorAuth {
  type: AuthType;
  // Fields are stored encrypted - only keys shown here
  api_key_ref?: string;     // Vault reference
  client_id_ref?: string;
  client_secret_ref?: string;
  token_ref?: string;
  certificate_ref?: string;
  role_arn?: string;
  base_url?: string;
}

export interface ConnectorHealth {
  status: ConnectorStatus;
  last_check: string;
  last_successful_poll?: string;
  events_last_hour?: number;
  events_last_day?: number;
  error_count_last_hour?: number;
  error_message?: string;
  latency_ms?: number;
}

export interface ConnectorMapping {
  source_field: string;
  target_field: string; // OCSF field path
  transform?: "lowercase" | "uppercase" | "extract_ip" | "parse_timestamp" | "lookup";
  lookup_table?: Record<string, string>;
  default_value?: string;
}

export interface Connector {
  id: string;
  tenant_id: string;
  name: string;
  type: ConnectorType;
  category: ConnectorCategory;
  description?: string;

  // Auth
  auth: ConnectorAuth;

  // Configuration
  config: {
    poll_interval_seconds?: number;
    batch_size?: number;
    lookback_seconds?: number;
    filters?: Record<string, unknown>;
    custom_headers?: Record<string, string>;
    tls_skip_verify?: boolean;
    proxy_url?: string;
    region?: string;
    namespace?: string;
    topics?: string[];
    format?: "json" | "cef" | "leef" | "syslog" | "xml" | "csv";
  };

  // Field mappings
  field_mappings?: ConnectorMapping[];

  // Health
  health: ConnectorHealth;
  is_enabled: boolean;

  created_at: string;
  updated_at: string;
  created_by: string;
}

/** Connector event for the pipeline */
export interface RawConnectorEvent {
  connector_id: string;
  connector_type: ConnectorType;
  tenant_id: string;
  received_at: string;
  payload: Record<string, unknown>;
  source_format: string;
}

/** Normalized OCSF event with routing metadata */
export interface NormalizedEvent {
  id: string;
  connector_id: string;
  tenant_id: string;
  ocsf_event: Record<string, unknown>;
  normalization_version: string;
  normalization_warnings?: string[];
  ioc_enrichments?: Array<{
    field: string;
    value: string;
    reputation_score?: number;
    threat_feeds?: string[];
  }>;
}
