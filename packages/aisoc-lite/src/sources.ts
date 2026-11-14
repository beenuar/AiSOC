/**
 * Source adapters: normalize alerts from various origins into the canonical
 * `Alert` shape the verdict engine consumes.
 *
 * Included today:
 *   - `demo`  — bundled deterministic fixture (zero creds, zero network)
 *   - `jsonl` — a local newline-delimited JSON file of alerts
 *
 * Live SIEM/EDR adapters (Splunk / Sentinel / Elastic / CrowdStrike) share the
 * same normalization contract; each maps its native alert object through
 * `normalizeRecord` below. The connectors themselves require credentials and
 * are wired in `src/sources/` behind the interactive `triage` flow — the demo
 * and jsonl paths are the always-free entrypoints.
 */

import { readFile } from "node:fs/promises";
import { loadDemoAlerts } from "./fixtures/index.js";
import type { Alert, Severity } from "./verdict/types.js";

export type SourceKind = "demo" | "jsonl" | "splunk" | "sentinel" | "elastic" | "crowdstrike";

const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];

function coerceSeverity(value: unknown): Severity {
  const s = String(value ?? "").toLowerCase();
  if ((SEVERITIES as string[]).includes(s)) return s as Severity;
  // Common vendor synonyms.
  if (["informational", "none", "notice"].includes(s)) return "info";
  if (["warning", "warn", "moderate"].includes(s)) return "medium";
  if (["severe", "urgent"].includes(s)) return "critical";
  const num = Number(value);
  if (!Number.isNaN(num)) {
    if (num >= 9) return "critical";
    if (num >= 7) return "high";
    if (num >= 4) return "medium";
    if (num >= 1) return "low";
  }
  return "info";
}

function coerceRisk(value: unknown): number | undefined {
  const num = Number(value);
  if (Number.isNaN(num)) return undefined;
  // Vendors publish risk on 0–100 or 0–1; normalize to [0, 1].
  return num > 1 ? Math.min(num / 100, 1) : Math.max(num, 0);
}

/**
 * Best-effort normalization of an arbitrary record into an `Alert`. Tolerant of
 * the common field spellings used by Splunk, Sentinel, Elastic ECS, and
 * CrowdStrike so a raw export "just works" without a mapping file.
 */
export function normalizeRecord(rec: Record<string, unknown>, source: string, index: number): Alert {
  const g = (...keys: string[]): unknown => {
    for (const k of keys) {
      if (rec[k] != null && rec[k] !== "") return rec[k];
    }
    return undefined;
  };

  const techniquesRaw = g("techniques", "mitre_techniques", "mitre", "threat.technique.id");
  const techniques = Array.isArray(techniquesRaw)
    ? techniquesRaw.map(String)
    : typeof techniquesRaw === "string"
      ? techniquesRaw.split(/[,\s]+/).filter(Boolean)
      : undefined;

  return {
    id: String(g("id", "_id", "alert_id", "detection_id", "event_id") ?? `${source}-${index + 1}`),
    title: String(g("title", "name", "rule_name", "message", "signal.rule.name", "search_name") ?? "Untitled alert"),
    source,
    severity: coerceSeverity(g("severity", "level", "priority", "urgency", "kibana.alert.severity")),
    riskScore: coerceRisk(g("riskScore", "risk_score", "risk", "confidence", "score")),
    hostname: g("hostname", "host", "host.name", "computer", "device.hostname") as string | undefined,
    username: g("username", "user", "user.name", "account", "src_user") as string | undefined,
    techniques,
    iocs: {
      srcIp: g("src_ip", "source.ip", "src", "SourceIp") as string | undefined,
      dstIp: g("dst_ip", "destination.ip", "dest", "DestinationIp") as string | undefined,
      domain: g("domain", "dns.question.name", "url.domain") as string | undefined,
      fileHash: g("file_hash", "file.hash.sha256", "sha256", "hash") as string | undefined,
      url: g("url", "url.full", "http.request.url") as string | undefined,
    },
    raw: typeof g("raw", "description", "_raw", "message") === "string"
      ? (g("raw", "description", "_raw", "message") as string)
      : JSON.stringify(rec),
    timestamp: g("timestamp", "@timestamp", "_time", "created") as string | undefined,
  };
}

/** Parse a newline-delimited JSON file (one alert object per line, or a JSON array). */
export async function loadJsonl(path: string, sourceLabel = "jsonl"): Promise<Alert[]> {
  const text = await readFile(path, "utf8");
  const trimmed = text.trim();
  let records: Record<string, unknown>[];
  if (trimmed.startsWith("[")) {
    records = JSON.parse(trimmed);
  } else if (trimmed.startsWith("{") && trimmed.includes('"alerts"')) {
    const obj = JSON.parse(trimmed);
    records = Array.isArray(obj.alerts) ? obj.alerts : [obj];
  } else {
    records = trimmed
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean)
      .map((l) => JSON.parse(l));
  }
  return records.map((r, i) => normalizeRecord(r, sourceLabel, i));
}

/** Resolve alerts for a chosen source. */
export async function loadAlerts(kind: SourceKind, opts: { file?: string; limit?: number } = {}): Promise<Alert[]> {
  let alerts: Alert[];
  switch (kind) {
    case "demo":
      alerts = loadDemoAlerts();
      break;
    case "jsonl":
      if (!opts.file) throw new Error("jsonl source requires --file <path>");
      alerts = await loadJsonl(opts.file);
      break;
    case "splunk":
    case "sentinel":
    case "elastic":
    case "crowdstrike":
      throw new Error(
        `Live '${kind}' source needs credentials. For a zero-setup run use \`aisoc triage --demo\`, or export your alerts to JSONL and run \`aisoc triage --file alerts.jsonl\`. Live connector auth lands with the v8 CLI GA.`,
      );
    default: {
      const _never: never = kind;
      return _never;
    }
  }
  return typeof opts.limit === "number" ? alerts.slice(0, opts.limit) : alerts;
}
