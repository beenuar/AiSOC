/**
 * Connector / Integration types
 */

import type { ConnectorType } from "./generated/connector-types";

/**
 * The `connector_type` values the ingest normalizer resolves.
 *
 * This union was hand-written, and hand-maintenance is what let it drift: it
 * was a third name space beside the ids `services/connectors` declares and the
 * keys `connectorProfiles` in
 * `services/ingest/internal/normalizer/normalizer.go` uses, and ten members
 * named nothing in either. `ibm_qradar` was not a profile key and no connector
 * declared it, so strict mode rejected it and lenient mode minted a vendor
 * called "ibm_qradar" — a second alert source for the QRadar deployment
 * `qradar` already fed.
 *
 * It is now generated from the registry that decides what the platform can
 * ingest. Five alternate spellings (`ibm_qradar`, `google_chronicle`,
 * `palo_alto_cortex`, `slack`, `syslog`) remain members and fold onto the
 * declared id through `connectorTypeCanonical`, which the generated module
 * mirrors as `CONNECTOR_TYPE_CANONICAL`. Five named nothing the platform
 * ingests and are gone: `vectra_ai` (no Vectra connector exists), `teams` (a
 * ChatOps destination, not a source), and `custom_webhook` / `http_pull` /
 * `kafka` (transports — the webhook path is the tenant inbox, which keys off a
 * template id and never sets `connector_type`).
 *
 * Do not redeclare the union here. `scripts/generate_connector_types.py
 * --check` fails if this file declares its own, because a hand-written union
 * three directories from the generated one is what TypeScript would resolve.
 * `scripts/check_connector_profiles.py` gates every member against the
 * normalizer and the connector registry, in both directions.
 */
export type { ConnectorType } from "./generated/connector-types";
export {
  CONNECTOR_TYPES,
  CONNECTOR_TYPE_CANONICAL,
  canonicalConnectorType,
} from "./generated/connector-types";

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
