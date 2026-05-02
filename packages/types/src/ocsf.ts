/**
 * OCSF (Open Cybersecurity Schema Framework) core types
 * Based on OCSF v1.1.0 schema
 */

export type Severity = "Unknown" | "Informational" | "Low" | "Medium" | "High" | "Critical" | "Fatal";
export type SeverityId = 0 | 1 | 2 | 3 | 4 | 5 | 6;

export type Status = "Unknown" | "Success" | "Failure" | "Other";
export type StatusId = 0 | 1 | 2 | 99;

export type ActivityId = number;

/** OCSF Metadata block */
export interface OcsfMetadata {
  version: string;
  product: {
    name: string;
    vendor_name: string;
    version?: string;
    uid?: string;
  };
  profiles?: string[];
  tenant_uid?: string;
  ingested_time?: string;
  original_time?: string;
  logged_time?: string;
  modified_time?: string;
  sequence?: number;
  labels?: string[];
}

/** OCSF Actor - user, service, or process that initiated the activity */
export interface OcsfActor {
  user?: OcsfUser;
  session?: OcsfSession;
  process?: OcsfProcess;
  app_name?: string;
  idp?: { name: string; uid?: string };
  invoked_by?: string;
}

/** OCSF User */
export interface OcsfUser {
  uid?: string;
  uid_alt?: string;
  name?: string;
  email_addr?: string;
  groups?: Array<{ name: string; uid?: string }>;
  domain?: string;
  type?: string;
  type_id?: number;
}

/** OCSF Session */
export interface OcsfSession {
  uid?: string;
  uid_alt?: string;
  created_time?: string;
  expiration_time?: string;
  is_remote?: boolean;
  terminal?: string;
  count?: number;
}

/** OCSF Process */
export interface OcsfProcess {
  pid?: number;
  name?: string;
  cmd_line?: string;
  uid?: string;
  file?: OcsfFile;
  parent_process?: Omit<OcsfProcess, "parent_process">;
  integrity?: string;
  integrity_id?: number;
  user?: OcsfUser;
}

/** OCSF File */
export interface OcsfFile {
  name?: string;
  path?: string;
  type?: string;
  type_id?: number;
  size?: number;
  hashes?: Array<{ algorithm: string; algorithm_id: number; value: string }>;
  created_time?: string;
  modified_time?: string;
  owner?: OcsfUser;
  mime_type?: string;
}

/** OCSF Device */
export interface OcsfDevice {
  uid?: string;
  uid_alt?: string;
  name?: string;
  hostname?: string;
  ip?: string;
  mac?: string;
  os?: { name: string; type?: string; version?: string };
  type?: string;
  type_id?: number;
  domain?: string;
  region?: string;
  zone?: string;
  namespace?: string;
  org?: { name?: string; uid?: string };
  agent_list?: Array<{ name?: string; uid?: string; version?: string; type?: string }>;
}

/** OCSF Network Endpoint */
export interface OcsfNetworkEndpoint {
  ip?: string;
  port?: number;
  hostname?: string;
  domain?: string;
  mac?: string;
  type?: string;
  type_id?: number;
  location?: {
    country?: string;
    region?: string;
    city?: string;
    lat?: number;
    long?: number;
    is_on_premises?: boolean;
  };
  autonomous_system?: { name?: string; number?: number };
  intermediate_ips?: string[];
}

/** OCSF Observable - enriched IOC */
export interface OcsfObservable {
  type_id: number;
  type?: string;
  name?: string;
  value?: string;
  reputation?: {
    base_score: number;
    score?: string;
    score_id?: number;
    provider?: string;
  };
}

/** OCSF MITRE ATT&CK mapping */
export interface OcsfAttack {
  tactic?: { id?: string; name?: string; uid?: string };
  technique?: { id?: string; name?: string; uid?: string; subtechnique?: { id?: string; name?: string; uid?: string } };
  version?: string;
}

/** Base OCSF Event - all events extend this */
export interface OcsfBaseEvent {
  class_name: string;
  class_uid: number;
  category_name: string;
  category_uid: number;
  activity_id: ActivityId;
  activity_name?: string;
  type_uid: number;
  type_name?: string;
  time: string; // ISO-8601
  message?: string;
  severity: Severity;
  severity_id: SeverityId;
  status?: Status;
  status_id?: StatusId;
  status_detail?: string;
  status_code?: string;
  metadata: OcsfMetadata;
  observables?: OcsfObservable[];
  attacks?: OcsfAttack[];
  raw_data?: string;
  unmapped?: Record<string, unknown>;
  tenant_uid: string;
  source_connector_id: string;
  ingest_time: string;
  event_id?: string; // deduplication key
}

/** OCSF Finding / Security Alert */
export interface OcsfFinding extends OcsfBaseEvent {
  class_uid: 2001;
  class_name: "Security Finding";
  finding: {
    title: string;
    desc?: string;
    uid?: string;
    types?: string[];
    src_url?: string;
    related_events?: Array<{ uid?: string; product_uid?: string; type?: string }>;
    cve?: Array<{
      uid: string;
      cvss?: Array<{ base_score: number; version: string }>;
      desc?: string;
    }>;
  };
  device?: OcsfDevice;
  actor?: OcsfActor;
  evidences?: Array<{
    actor?: OcsfActor;
    device?: OcsfDevice;
    src_endpoint?: OcsfNetworkEndpoint;
    dst_endpoint?: OcsfNetworkEndpoint;
    query?: { hostname?: string; type?: string };
    process?: OcsfProcess;
  }>;
  resources?: Array<{
    name?: string;
    uid?: string;
    type?: string;
    cloud_partition?: string;
    region?: string;
    account_uid?: string;
    labels?: Record<string, string>;
  }>;
  remediation?: {
    desc?: string;
    references?: string[];
    kb_articles?: string[];
  };
}

/** OCSF Network Activity */
export interface OcsfNetworkActivity extends OcsfBaseEvent {
  class_uid: 4001;
  class_name: "Network Activity";
  src_endpoint: OcsfNetworkEndpoint;
  dst_endpoint: OcsfNetworkEndpoint;
  connection_info?: {
    direction?: string;
    direction_id?: number;
    protocol_name?: string;
    protocol_num?: number;
    uid?: string;
    community_uid?: string;
  };
  traffic?: {
    bytes_in?: number;
    bytes_out?: number;
    packets_in?: number;
    packets_out?: number;
  };
  actor?: OcsfActor;
  device?: OcsfDevice;
}

/** OCSF Process Activity */
export interface OcsfProcessActivity extends OcsfBaseEvent {
  class_uid: 1007;
  class_name: "Process Activity";
  process: OcsfProcess;
  device: OcsfDevice;
  actor?: OcsfActor;
}

/** OCSF Authentication */
export interface OcsfAuthentication extends OcsfBaseEvent {
  class_uid: 3002;
  class_name: "Authentication";
  actor: OcsfActor;
  user: OcsfUser;
  dst_endpoint?: OcsfNetworkEndpoint;
  src_endpoint?: OcsfNetworkEndpoint;
  device?: OcsfDevice;
  auth_protocol?: string;
  auth_protocol_id?: number;
  is_cleartext?: boolean;
  is_mfa?: boolean;
  is_new_logon?: boolean;
  is_remote?: boolean;
  service?: { name?: string; uid?: string };
}

/** Union of all supported OCSF event types */
export type OcsfEvent =
  | OcsfFinding
  | OcsfNetworkActivity
  | OcsfProcessActivity
  | OcsfAuthentication
  | OcsfBaseEvent;
