/**
 * Deterministic, no-LLM detection-rule translation.
 *
 * A TypeScript port of the field-map substitution fallback in
 * `services/api/app/api/v1/endpoints/translation.py`. This is the zero-key path
 * that powers `aisoc translate <rule>` and the browser-side `/tools/translate`
 * tool. It is intentionally a best-effort field remap (not a full Sigma AST
 * compiler); a BYO-key LLM path can layer higher fidelity on top.
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

// Sigma → target field map (common ECS / OCSF fields). Byte-identical to the
// server's `_FIELD_MAP` so CLI and API produce the same deterministic output.
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

/**
 * Translate a rule from `sourceFormat` into each requested target format using
 * pure field-map substitution. Deterministic and offline.
 */
export function translateRule(
  sourceRule: string,
  sourceFormat: DetectionFormat,
  targetFormats: DetectionFormat[] = ["sigma", "spl", "kql", "esql"],
): TranslateOutput {
  const results: TranslationResult[] = [];
  const warnings = [
    "Deterministic field-map translation (no LLM). Review field names before deploying; set ANTHROPIC_API_KEY / OPENAI_API_KEY for higher-fidelity translation.",
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
    results.push({
      format: fmt,
      label: FORMAT_LABELS[fmt],
      rule: wrap(fmt, rule),
      notes: "Template translation — verify field names.",
    });
  }

  return { sourceFormat, results, warnings };
}
