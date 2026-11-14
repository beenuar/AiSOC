/**
 * Threat Intelligence types
 */

export type IocType =
  | "ipv4"
  | "ipv6"
  | "domain"
  | "url"
  | "email"
  | "md5"
  | "sha1"
  | "sha256"
  | "sha512"
  | "ssdeep"
  | "tlsh"
  | "asn"
  | "certificate_fingerprint"
  | "filename"
  | "mutex"
  | "registry_key"
  | "user_agent"
  | "bitcoin_address"
  | "cve";

export type ThreatType =
  | "malware"
  | "ransomware"
  | "apt"
  | "phishing"
  | "c2"
  | "botnet"
  | "scanner"
  | "brute_force"
  | "data_exfiltration"
  | "exploitation"
  | "credential_theft"
  | "cryptocurrency_mining"
  | "benign"
  | "unknown";

export interface ThreatActor {
  name: string;
  aliases?: string[];
  country?: string;
  motivation?: "financial" | "espionage" | "hacktivism" | "sabotage";
  sophistication?: "low" | "medium" | "high" | "advanced";
  mitre_group_id?: string; // e.g., "G0060"
}

export interface IoC {
  id: string;
  tenant_id?: string; // null for global feeds

  value: string;
  type: IocType;
  normalized_value: string; // lowercase, trimmed

  // Reputation
  reputation_score: number; // -100 to 100, negative = malicious
  confidence: number; // 0-100
  threat_types: ThreatType[];
  severity: "critical" | "high" | "medium" | "low" | "info";

  // Attribution
  threat_actors?: ThreatActor[];
  malware_families?: string[];
  campaigns?: string[];

  // Sources
  source_feeds: string[];
  first_seen: string;
  last_seen: string;
  expiry?: string;

  // Context
  tags: string[];
  description?: string;
  context?: Record<string, unknown>;

  // GeoIP (for IPs)
  geo?: {
    country_code?: string;
    country_name?: string;
    city?: string;
    asn?: number;
    asn_org?: string;
    is_tor?: boolean;
    is_vpn?: boolean;
    is_datacenter?: boolean;
  };
}

export interface ThreatIntelFeed {
  id: string;
  tenant_id?: string;
  name: string;
  provider: string;
  url?: string;
  format: "stix2" | "taxii" | "csv" | "json" | "misp";
  type: "commercial" | "open_source" | "isac" | "government" | "internal";
  is_active: boolean;
  poll_interval_minutes: number;
  last_polled?: string;
  ioc_count?: number;
  auth_type?: "api_key" | "basic" | "token" | "certificate";
  auth_config?: Record<string, string>;
  filters?: {
    severity_min?: string;
    confidence_min?: number;
    ioc_types?: IocType[];
  };
  created_at: string;
  updated_at: string;
}

export interface IocEnrichmentResult {
  value: string;
  type: IocType;
  found: boolean;
  ioc?: IoC;
  sources: string[];
  enriched_at: string;
  cache_hit: boolean;
  ttl_seconds: number;
}

export interface MitreAttackPattern {
  id: string; // e.g., "T1566"
  name: string;
  description: string;
  tactic_ids: string[]; // e.g., ["TA0001"]
  tactic_names: string[];
  sub_technique_ids?: string[];
  mitigations?: string[];
  detections?: string[];
  platforms: string[];
  is_sub_technique: boolean;
  parent_technique_id?: string;
  url: string;
  data_sources?: string[];
}
