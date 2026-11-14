/**
 * Client-side deterministic detection-rule translation for `/tools/translate`.
 *
 * Runs entirely in the browser — user rules never touch the server on the
 * deterministic path (the BYO-key LLM path calls the provider directly from the
 * client). Mirrors the canonical field-map in
 * `services/api/app/api/v1/endpoints/translation.py` and
 * `packages/aisoc-lite/src/verdict/translate.ts` so CLI, API, and web agree.
 */

export type DetectionFormat = "sigma" | "spl" | "kql" | "esql" | "yara_l2" | "udm";

export const FORMAT_LABELS: Record<DetectionFormat, string> = {
  sigma: "Sigma YAML",
  spl: "Splunk SPL",
  kql: "Microsoft Sentinel KQL",
  esql: "Elastic ES|QL",
  yara_l2: "Google Chronicle YARA-L2",
  udm: "Google Chronicle UDM Search",
};

export const ALL_FORMATS: DetectionFormat[] = ["sigma", "spl", "kql", "esql", "yara_l2", "udm"];

const FIELD_MAP: Record<string, Record<string, string>> = {
  spl: {
    EventID: "EventCode",
    Image: "process_name",
    CommandLine: "process_path",
    TargetUserName: "user",
    DestinationIp: "dest_ip",
    SourceIp: "src_ip",
  },
  kql: {
    EventID: "EventID",
    Image: "NewProcessName",
    CommandLine: "CommandLine",
    TargetUserName: "TargetUserName",
    DestinationIp: "RemoteIP",
    SourceIp: "InitiatingProcessRemoteIP",
  },
  esql: {
    EventID: "event.code",
    Image: "process.executable",
    CommandLine: "process.command_line",
    TargetUserName: "user.name",
    DestinationIp: "destination.ip",
    SourceIp: "source.ip",
  },
  yara_l2: {
    EventID: "metadata.product_event_type",
    Image: "principal.process.file.full_path",
    CommandLine: "principal.process.command_line",
    TargetUserName: "target.user.userid",
    DestinationIp: "target.ip",
    SourceIp: "principal.ip",
  },
  udm: {
    EventID: "metadata.product_event_type",
    Image: "principal.process.file.full_path",
    CommandLine: "principal.process.command_line",
    TargetUserName: "target.user.userid",
    DestinationIp: "target.ip",
    SourceIp: "principal.ip",
  },
};

export interface TranslationResult {
  format: DetectionFormat;
  label: string;
  rule: string;
  notes?: string;
}

export interface TranslateOutput {
  sourceFormat: DetectionFormat;
  results: TranslationResult[];
  warnings: string[];
}

function wrap(fmt: DetectionFormat, rule: string): string {
  switch (fmt) {
    case "spl":
      return `index=* sourcetype=WinEventLog\n| search ${rule}`;
    case "kql":
      return `SecurityEvent\n| where ${rule}`;
    case "esql":
      return `FROM logs-*\n| WHERE ${rule}`;
    case "yara_l2":
      return `rule translated_rule {\n  meta:\n    author = "AiSOC"\n  condition:\n    ${rule}\n}`;
    case "udm":
      return `// Chronicle UDM Search\n${rule}`;
    case "sigma":
      return rule;
    default: {
      const _never: never = fmt;
      return _never;
    }
  }
}

export function translateRule(
  sourceRule: string,
  sourceFormat: DetectionFormat,
  targetFormats: DetectionFormat[] = ["sigma", "spl", "kql", "esql"],
): TranslateOutput {
  const results: TranslationResult[] = [];
  const warnings = [
    "Deterministic field-map translation, computed in your browser (no server, no LLM). Review field names before deploying.",
  ];

  for (const fmt of targetFormats) {
    if (fmt === sourceFormat) {
      results.push({ format: fmt, label: FORMAT_LABELS[fmt], rule: sourceRule, notes: "Same as source." });
      continue;
    }
    let rule = sourceRule;
    const map = FIELD_MAP[fmt] ?? {};
    for (const [src, tgt] of Object.entries(map)) {
      rule = rule.split(src).join(tgt);
    }
    results.push({ format: fmt, label: FORMAT_LABELS[fmt], rule: wrap(fmt, rule), notes: "Template translation — verify field names." });
  }
  return { sourceFormat, results, warnings };
}

/** LZ-free permalink codec: base64url of the JSON payload (small rules only). */
export function encodePermalink(sourceFormat: DetectionFormat, rule: string): string {
  const json = JSON.stringify({ f: sourceFormat, r: rule });
  if (typeof btoa === "function") {
    return btoa(unescape(encodeURIComponent(json)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }
  return Buffer.from(json, "utf8").toString("base64url");
}

export function decodePermalink(s: string): { sourceFormat: DetectionFormat; rule: string } | null {
  try {
    const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
    const json = typeof atob === "function" ? decodeURIComponent(escape(atob(b64))) : Buffer.from(b64, "base64").toString("utf8");
    const parsed = JSON.parse(json) as { f: DetectionFormat; r: string };
    if (!ALL_FORMATS.includes(parsed.f) || typeof parsed.r !== "string") return null;
    return { sourceFormat: parsed.f, rule: parsed.r };
  } catch {
    return null;
  }
}
