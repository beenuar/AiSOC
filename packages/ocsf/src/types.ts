/**
 * OCSF (Open Cybersecurity Schema Framework) v1.1 Core Types
 * https://schema.ocsf.io/
 */

// ─── Enumerations ────────────────────────────────────────────────────────────

export enum OcsfClassUid {
  SECURITY_FINDING = 2001,
  NETWORK_ACTIVITY = 4001,
  HTTP_ACTIVITY = 4002,
  DNS_ACTIVITY = 4003,
  AUTHENTICATION = 3002,
  PROCESS_ACTIVITY = 1007,
  FILE_ACTIVITY = 1001,
  DETECTION_FINDING = 2004,
  VULNERABILITY_FINDING = 2002,
  COMPLIANCE_FINDING = 2003,
}

export enum OcsfActivityId {
  UNKNOWN = 0,
  OPENED = 1,
  CLOSED = 2,
  RESET = 3,
  FAIL = 4,
  REFUSE = 5,
  OTHER = 99,
}

export enum OcsfSeverityId {
  UNKNOWN = 0,
  INFORMATIONAL = 1,
  LOW = 2,
  MEDIUM = 3,
  HIGH = 4,
  CRITICAL = 5,
  FATAL = 6,
  OTHER = 99,
}

export enum OcsfStatusId {
  UNKNOWN = 0,
  SUCCESS = 1,
  FAILURE = 2,
  OTHER = 99,
}

export enum OcsfCategoryUid {
  SYSTEM_ACTIVITY = 1,
  FINDINGS = 2,
  IDENTITY_ACTIVITY = 3,
  NETWORK_ACTIVITY = 4,
  DISCOVERY = 5,
  APPLICATION_ACTIVITY = 6,
}

// ─── Base Objects ─────────────────────────────────────────────────────────────

export interface OcsfMetadata {
  uid?: string;
  version: string;
  product: OcsfProduct;
  profiles?: string[];
  labels?: string[];
  log_name?: string;
  log_provider?: string;
  log_version?: string;
  logged_time?: number;
  modified_time?: number;
  original_time?: string;
  processed_time?: number;
  tenant_uid?: string;
}

export interface OcsfProduct {
  name: string;
  uid?: string;
  vendor_name: string;
  version?: string;
  lang?: string;
  url_string?: string;
  feature?: {
    name?: string;
    uid?: string;
    version?: string;
  };
}

export interface OcsfActor {
  user?: OcsfUser;
  process?: OcsfProcess;
  session?: OcsfSession;
  idp?: { name?: string; uid?: string };
  app_name?: string;
  app_uid?: string;
  invoked_by?: string;
}

export interface OcsfUser {
  uid?: string;
  uuid?: string;
  name?: string;
  full_name?: string;
  email_addr?: string;
  domain?: string;
  type?: string;
  type_id?: number;
  org?: { name?: string; uid?: string };
  groups?: Array<{ name?: string; uid?: string }>;
  is_admin?: boolean;
}

export interface OcsfProcess {
  pid?: number;
  name?: string;
  cmd_line?: string;
  file?: OcsfFile;
  parent_process?: OcsfProcess;
  user?: OcsfUser;
  uid?: string;
  guid?: string;
  integrity?: string;
  integrity_id?: number;
  created_time?: number;
  lineage?: string[];
}

export interface OcsfSession {
  uid?: string;
  uuid?: string;
  created_time?: number;
  expiration_time?: number;
  is_mfa?: boolean;
  is_remote?: boolean;
  terminal?: string;
}

export interface OcsfEndpoint {
  uid?: string;
  uuid?: string;
  name?: string;
  hostname?: string;
  ip?: string;
  mac?: string;
  type?: string;
  type_id?: number;
  os?: {
    name?: string;
    type?: string;
    type_id?: number;
    version?: string;
    build?: string;
  };
  agent_list?: OcsfAgent[];
  domain?: string;
  location?: OcsfLocation;
  interface_uid?: string;
  interface_name?: string;
}

export interface OcsfAgent {
  uid?: string;
  name?: string;
  type?: string;
  type_id?: number;
  version?: string;
  vendor_name?: string;
  policies?: Array<{ name?: string; uid?: string; version?: string }>;
}

export interface OcsfNetwork {
  direction?: string;
  direction_id?: number;
  bytes_in?: number;
  bytes_out?: number;
  packets_in?: number;
  packets_out?: number;
  protocol_name?: string;
  protocol_num?: number;
  protocol_ver?: string;
  protocol_ver_id?: number;
  proxy?: OcsfEndpoint;
  src_endpoint?: OcsfEndpoint;
  dst_endpoint?: OcsfEndpoint;
}

export interface OcsfFile {
  name?: string;
  path?: string;
  type?: string;
  type_id?: number;
  uid?: string;
  hash?: { algorithm?: string; algorithm_id?: number; value?: string };
  size?: number;
  created_time?: number;
  modified_time?: number;
  owner?: OcsfUser;
  mime_type?: string;
}

export interface OcsfLocation {
  city?: string;
  country?: string;
  isp?: string;
  lat?: number;
  long?: number;
  postal_code?: string;
  provider?: string;
  region?: string;
}

export interface OcsfFinding {
  uid?: string;
  title?: string;
  desc?: string;
  types?: string[];
  type_ids?: number[];
  related_events?: Array<{ uid?: string; type?: string }>;
  src_url?: string;
}

export interface OcsfRemediation {
  desc?: string;
  kb_articles?: string[];
  references?: string[];
}

export interface OcsfVulnerability {
  cve?: {
    uid?: string;
    title?: string;
    desc?: string;
    cvss?: {
      base_score?: number;
      severity?: string;
      vector_string?: string;
      version?: string;
    };
    epss?: { score?: number; percentile?: number };
    created_time?: number;
    modified_time?: number;
    references?: string[];
  };
  desc?: string;
  kb_articles?: string[];
  packages?: Array<{ name?: string; version?: string; path?: string }>;
  references?: string[];
  remediation?: OcsfRemediation;
  severity?: string;
  severity_id?: number;
  title?: string;
  vendor_name?: string;
}

// ─── OCSF Event Base ─────────────────────────────────────────────────────────

export interface OcsfBaseEvent {
  class_uid: OcsfClassUid;
  class_name: string;
  category_uid: OcsfCategoryUid;
  category_name: string;
  activity_id?: OcsfActivityId;
  activity_name?: string;
  severity_id: OcsfSeverityId;
  severity?: string;
  status_id?: OcsfStatusId;
  status?: string;
  status_detail?: string;
  status_code?: string;
  time: number;
  start_time?: number;
  end_time?: number;
  duration?: number;
  timezone_offset?: number;
  count?: number;
  message?: string;
  metadata: OcsfMetadata;
  type_uid?: number;
  type_name?: string;
  raw_data?: string;
  unmapped?: Record<string, unknown>;
}

// ─── Specific Event Classes ───────────────────────────────────────────────────

export interface OcsfSecurityFinding extends OcsfBaseEvent {
  class_uid: OcsfClassUid.SECURITY_FINDING;
  finding: OcsfFinding;
  analytic?: {
    category?: string;
    name?: string;
    type?: string;
    type_id?: number;
    uid?: string;
    desc?: string;
    related_analytics?: Array<{ name?: string; uid?: string }>;
  };
  attacks?: OcsfAttack[];
  confidence?: string;
  confidence_id?: number;
  confidence_score?: number;
  impact?: string;
  impact_id?: number;
  impact_score?: number;
  risk_score?: number;
  risk_level?: string;
  risk_level_id?: number;
  vulnerabilities?: OcsfVulnerability[];
  evidences?: Array<{
    data?: unknown;
    query?: string;
    result?: string;
    actor?: OcsfActor;
    dst_endpoint?: OcsfEndpoint;
    src_endpoint?: OcsfEndpoint;
    process?: OcsfProcess;
    file?: OcsfFile;
    network?: OcsfNetwork;
  }>;
  state?: string;
  state_id?: number;
  src_endpoint?: OcsfEndpoint;
  dst_endpoint?: OcsfEndpoint;
  actor?: OcsfActor;
}

export interface OcsfAttack {
  tactic?: { name?: string; uid?: string };
  technique?: { name?: string; uid?: string; sub_technique?: { name?: string; uid?: string } };
  version?: string;
}

export interface OcsfNetworkActivity extends OcsfBaseEvent {
  class_uid: OcsfClassUid.NETWORK_ACTIVITY;
  connection_info?: OcsfNetwork;
  src_endpoint?: OcsfEndpoint;
  dst_endpoint?: OcsfEndpoint;
  actor?: OcsfActor;
  traffic?: { bytes?: number; packets?: number };
  firewall_rule?: { name?: string; uid?: string; type?: string };
}

export interface OcsfAuthentication extends OcsfBaseEvent {
  class_uid: OcsfClassUid.AUTHENTICATION;
  actor?: OcsfActor;
  dst_endpoint?: OcsfEndpoint;
  src_endpoint?: OcsfEndpoint;
  auth_protocol?: string;
  auth_protocol_id?: number;
  is_cleartext?: boolean;
  is_mfa?: boolean;
  is_new_logon?: boolean;
  is_remote?: boolean;
  logon_type?: string;
  logon_type_id?: number;
  service?: { name?: string; uid?: string };
  session?: OcsfSession;
  user?: OcsfUser;
}

export interface OcsfDetectionFinding extends OcsfBaseEvent {
  class_uid: OcsfClassUid.DETECTION_FINDING;
  finding: OcsfFinding;
  attacks?: OcsfAttack[];
  analytic?: {
    name?: string;
    type?: string;
    type_id?: number;
    uid?: string;
    related_analytics?: Array<{ name?: string; uid?: string }>;
  };
  confidence?: string;
  confidence_id?: number;
  src_endpoint?: OcsfEndpoint;
  dst_endpoint?: OcsfEndpoint;
  actor?: OcsfActor;
  process?: OcsfProcess;
  file?: OcsfFile;
}

export type OcsfEvent =
  | OcsfSecurityFinding
  | OcsfNetworkActivity
  | OcsfAuthentication
  | OcsfDetectionFinding
  | OcsfBaseEvent;
