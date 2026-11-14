/**
 * Deterministic natural-language → Sigma generator for `/tools/nl2sigma`.
 *
 * Runs in the browser with no LLM: it extracts high-signal artifacts from the
 * plain-English description (process names, ports, MITRE ids, event verbs) and
 * assembles a well-formed Sigma rule. It is intentionally a scaffold generator
 * — honest about being a starting point, not a finished detection — and pairs
 * with the field-map translator to emit the SIEM dialects.
 */

export interface Nl2SigmaResult {
  sigma: string;
  matchedKeywords: string[];
  note: string;
}

const LOGSOURCE_HINTS: { re: RegExp; category: string; product: string }[] = [
  { re: /\b(powershell|cmd|process|command[- ]?line|executable|binary|spawn)\b/i, category: "process_creation", product: "windows" },
  { re: /\b(login|logon|sign[- ]?in|authentication|failed password|brute)\b/i, category: "authentication", product: "windows" },
  { re: /\b(dns|domain|resolve|query)\b/i, category: "dns", product: "" },
  { re: /\b(network|connection|port|outbound|beacon|c2)\b/i, category: "network_connection", product: "windows" },
  { re: /\b(file|write|create|drop|ransom|encrypt)\b/i, category: "file_event", product: "windows" },
];

const PROC_RE = /\b([A-Za-z0-9_-]+\.(?:exe|ps1|dll|bat|sh|py))\b/gi;
const MITRE_RE = /\bT\d{4}(?:\.\d{3})?\b/gi;
const PORT_RE = /\bport\s+(\d{1,5})\b/i;

function yamlList(items: string[], indent: string): string {
  return items.map((i) => `${indent}- '${i.replace(/'/g, "")}'`).join("\n");
}

export function nlToSigma(description: string, severity = "medium"): Nl2SigmaResult {
  const text = description.trim();
  const matched: string[] = [];

  const hint = LOGSOURCE_HINTS.find((h) => h.re.test(text));
  const category = hint?.category ?? "process_creation";
  const product = hint?.product ?? "windows";
  if (hint) matched.push(category);

  const procs = [...new Set([...text.matchAll(PROC_RE)].map((m) => m[1]!))];
  const mitre = [...new Set([...text.matchAll(MITRE_RE)].map((m) => m[0]!.toUpperCase()))];
  const portMatch = text.match(PORT_RE);
  procs.forEach((p) => matched.push(p));
  mitre.forEach((t) => matched.push(t));

  // Keyword candidates for a CommandLine|contains selection: notable verbs/nouns.
  const keywordCandidates = (text.match(/\b(download|invoke|encode|iex|mimikatz|whoami|net user|reg add|schtasks|vssadmin|bitsadmin|certutil|rundll32|regsvr32)\b/gi) ?? []).map(
    (k) => k.toLowerCase(),
  );
  const uniqueKeywords = [...new Set(keywordCandidates)];
  uniqueKeywords.forEach((k) => matched.push(k));

  const title = text.slice(0, 70).replace(/\n/g, " ") || "Suspicious activity";

  const detectionLines: string[] = ["detection:", "  selection:"];
  if (procs.length) {
    detectionLines.push("    Image|endswith:");
    detectionLines.push(yamlList(procs.map((p) => `\\${p}`), "      "));
  }
  if (uniqueKeywords.length) {
    detectionLines.push("    CommandLine|contains:");
    detectionLines.push(yamlList(uniqueKeywords, "      "));
  }
  if (portMatch) {
    detectionLines.push(`    DestinationPort: ${portMatch[1]}`);
  }
  if (!procs.length && !uniqueKeywords.length && !portMatch) {
    detectionLines.push("    # No concrete artifacts detected in the description — refine the selection below.");
    detectionLines.push("    CommandLine|contains: '<REPLACE_ME>'");
  }
  detectionLines.push("  condition: selection");

  const tagsBlock = mitre.length ? `tags:\n${mitre.map((t) => `  - attack.${t.toLowerCase()}`).join("\n")}\n` : "";
  const logsourceProduct = product ? `\n  product: ${product}` : "";

  const sigma = `title: ${title}
status: experimental
description: ${text.replace(/\n/g, " ") || "Generated from a natural-language description."}
${tagsBlock}logsource:
  category: ${category}${logsourceProduct}
${detectionLines.join("\n")}
falsepositives:
  - Legitimate administrative activity
level: ${severity}`;

  return {
    sigma,
    matchedKeywords: matched,
    note: "Deterministic scaffold generated in your browser — a starting point, not a finished detection. Refine the selection and false positives before deploying.",
  };
}
