/**
 * OCSF Normalization Utilities
 * Converts raw security events to OCSF format
 */

import {
  OcsfBaseEvent,
  OcsfClassUid,
  OcsfCategoryUid,
  OcsfSeverityId,
  OcsfActivityId,
  OcsfMetadata,
  OcsfEndpoint,
  OcsfSecurityFinding,
  OcsfAttack,
} from './types';

// ─── Severity Mapping ─────────────────────────────────────────────────────────

const SEVERITY_MAP: Record<string, OcsfSeverityId> = {
  informational: OcsfSeverityId.INFORMATIONAL,
  info: OcsfSeverityId.INFORMATIONAL,
  low: OcsfSeverityId.LOW,
  medium: OcsfSeverityId.MEDIUM,
  med: OcsfSeverityId.MEDIUM,
  high: OcsfSeverityId.HIGH,
  critical: OcsfSeverityId.CRITICAL,
  fatal: OcsfSeverityId.FATAL,
};

export function mapSeverity(severity: string | undefined): OcsfSeverityId {
  if (!severity) return OcsfSeverityId.UNKNOWN;
  return SEVERITY_MAP[severity.toLowerCase()] ?? OcsfSeverityId.UNKNOWN;
}

export function severityIdToString(id: OcsfSeverityId): string {
  const map: Record<OcsfSeverityId, string> = {
    [OcsfSeverityId.UNKNOWN]: 'Unknown',
    [OcsfSeverityId.INFORMATIONAL]: 'Informational',
    [OcsfSeverityId.LOW]: 'Low',
    [OcsfSeverityId.MEDIUM]: 'Medium',
    [OcsfSeverityId.HIGH]: 'High',
    [OcsfSeverityId.CRITICAL]: 'Critical',
    [OcsfSeverityId.FATAL]: 'Fatal',
    [OcsfSeverityId.OTHER]: 'Other',
  };
  return map[id] ?? 'Unknown';
}

// ─── Time Utilities ───────────────────────────────────────────────────────────

export function toOcsfTime(input: string | number | Date | undefined): number {
  if (!input) return Date.now();
  if (typeof input === 'number') return input;
  if (input instanceof Date) return input.getTime();
  const parsed = Date.parse(input);
  return isNaN(parsed) ? Date.now() : parsed;
}

// ─── Endpoint Builder ─────────────────────────────────────────────────────────

export function buildEndpoint(
  ip?: string,
  hostname?: string,
  port?: number,
  extras?: Partial<OcsfEndpoint>
): OcsfEndpoint {
  return {
    ip,
    hostname,
    ...(port !== undefined ? { port } : {}),
    ...extras,
  };
}

// ─── MITRE ATT&CK Mapping ────────────────────────────────────────────────────

export function buildAttackFromTactic(
  tactics: string[],
  techniques?: string[]
): OcsfAttack[] {
  const attacks: OcsfAttack[] = [];

  for (let i = 0; i < tactics.length; i++) {
    const attack: OcsfAttack = {
      tactic: { name: tactics[i] },
      version: '14.0',
    };
    if (techniques && techniques[i]) {
      attack.technique = { uid: techniques[i] };
    }
    attacks.push(attack);
  }

  return attacks;
}

// ─── Generic Raw Alert → OCSF Security Finding ───────────────────────────────

export interface RawAlertInput {
  id?: string;
  title?: string;
  description?: string;
  severity?: string;
  source?: string;
  src_ip?: string;
  dst_ip?: string;
  src_port?: number;
  dst_port?: number;
  hostname?: string;
  created_at?: string | number;
  raw_event?: Record<string, unknown>;
  tactics?: string[];
  techniques?: string[];
  tenant_uid?: string;
}

export function normalizeToOcsfSecurityFinding(
  raw: RawAlertInput,
  productName: string,
  vendorName: string
): OcsfSecurityFinding {
  const severityId = mapSeverity(raw.severity);

  const metadata: OcsfMetadata = {
    version: '1.1.0',
    product: {
      name: productName,
      vendor_name: vendorName,
    },
    tenant_uid: raw.tenant_uid,
    original_time: typeof raw.created_at === 'string' ? raw.created_at : undefined,
  };

  const event: OcsfSecurityFinding = {
    class_uid: OcsfClassUid.SECURITY_FINDING,
    class_name: 'Security Finding',
    category_uid: OcsfCategoryUid.FINDINGS,
    category_name: 'Findings',
    activity_id: OcsfActivityId.OPENED,
    activity_name: 'Opened',
    severity_id: severityId,
    severity: severityIdToString(severityId),
    time: toOcsfTime(raw.created_at),
    metadata,
    finding: {
      uid: raw.id,
      title: raw.title,
      desc: raw.description,
    },
    raw_data: raw.raw_event ? JSON.stringify(raw.raw_event) : undefined,
  };

  if (raw.src_ip || raw.hostname) {
    event.src_endpoint = buildEndpoint(raw.src_ip, raw.hostname, raw.src_port);
  }

  if (raw.dst_ip) {
    event.dst_endpoint = buildEndpoint(raw.dst_ip, undefined, raw.dst_port);
  }

  if (raw.tactics && raw.tactics.length > 0) {
    event.attacks = buildAttackFromTactic(raw.tactics, raw.techniques);
  }

  return event;
}

// ─── Validation ───────────────────────────────────────────────────────────────

export function isValidOcsfEvent(event: unknown): event is OcsfBaseEvent {
  if (!event || typeof event !== 'object') return false;
  const e = event as Record<string, unknown>;
  return (
    typeof e['class_uid'] === 'number' &&
    typeof e['category_uid'] === 'number' &&
    typeof e['time'] === 'number' &&
    typeof e['metadata'] === 'object' &&
    e['metadata'] !== null
  );
}

// ─── Serialization ────────────────────────────────────────────────────────────

export function serializeOcsfEvent(event: OcsfBaseEvent): string {
  return JSON.stringify(event);
}

export function deserializeOcsfEvent(json: string): OcsfBaseEvent {
  const parsed = JSON.parse(json);
  if (!isValidOcsfEvent(parsed)) {
    throw new Error('Invalid OCSF event structure');
  }
  return parsed;
}
