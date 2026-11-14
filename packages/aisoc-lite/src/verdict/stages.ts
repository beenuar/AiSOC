/**
 * Deterministic triage scorer — a faithful TypeScript port of
 * `score_triage` in `services/agents/app/confidence/scoring.py`.
 *
 * Design constraints carried over verbatim from the Python original:
 *   1. Pure functions — no I/O, no LLM calls. The LLM band layers on top.
 *   2. Bounded — confidence clamped to [0.05, 0.95]. Never certainty, never
 *      impossibility.
 *   3. Reasoned — every score returns a `basis` list so the analyst sees why.
 *
 * The weight stack and band thresholds are kept byte-for-byte identical to the
 * server so a CLI verdict matches what the full stack would assign at triage.
 * A parity test (`stages.test.ts`) pins the constants.
 */

import type {
  Alert,
  AlertVerdict,
  EvidenceFactor,
  Recommendation,
  Verdict,
} from "./types.js";

const CONF_FLOOR = 0.05;
const CONF_CEIL = 0.95;

/** Critical-severity keyword set (matches scoring.py `_has_critical_keyword`). */
const CRITICAL_KEYWORDS = [
  "ransomware",
  "lateral movement",
  "credential dump",
  "exfiltration",
  "mimikatz",
  "cobalt strike",
  "c2",
  "rootkit",
  "supply chain",
  "zero-day",
  "data breach",
] as const;

/** High-severity keyword set (matches scoring.py `_has_high_keyword`). */
const HIGH_KEYWORDS = [
  "phishing",
  "malware",
  "exploit",
  "privilege escalation",
  "brute force",
  "suspicious login",
  "anomaly",
  "backdoor",
] as const;

function clamp(value: number): number {
  return Math.max(CONF_FLOOR, Math.min(CONF_CEIL, value));
}

function alertText(alert: Alert): string {
  return `${alert.title} ${alert.raw ?? ""} ${JSON.stringify(alert.iocs ?? {})}`.toLowerCase();
}

function hasKeyword(text: string, keywords: readonly string[]): boolean {
  return keywords.some((kw) => text.includes(kw));
}

function verdictBand(confidence: number): Verdict {
  if (confidence >= 0.8) return "true_positive";
  if (confidence >= 0.6) return "likely_true_positive";
  if (confidence >= 0.4) return "needs_review";
  return "likely_benign";
}

/** Map a verdict to the recommended analyst action. */
export function recommendationFor(verdict: Verdict): Recommendation {
  switch (verdict) {
    case "true_positive":
    case "likely_true_positive":
      return "escalate";
    case "needs_review":
      return "review";
    case "likely_benign":
      return "suppress";
    default: {
      // Exhaustiveness guard — a new verdict tier must be handled explicitly.
      const _never: never = verdict;
      return _never;
    }
  }
}

/**
 * Score a single alert into a verdict + confidence + weighted evidence.
 *
 * Weight stack (additive, then clamped), identical to `score_triage`:
 *   - vendor risk_score           → min(risk * 0.6, 0.6)
 *   - critical keyword            → +0.35   (else high keyword → +0.20)
 *   - IOC field count             → min(hits * 0.05, 0.15)
 *   - MITRE technique count       → min(n * 0.04, 0.12)
 *   - hostname present            → +0.05
 */
export function scoreAlert(alert: Alert): AlertVerdict {
  const basis: string[] = [];
  const evidence: EvidenceFactor[] = [];
  let weight = 0;

  const risk = Number(alert.riskScore ?? 0) || 0;
  if (risk > 0) {
    const c = Math.min(risk * 0.6, 0.6);
    weight += c;
    basis.push(`vendor risk_score=${risk.toFixed(2)}`);
    evidence.push({ factor: "vendor_risk", detail: `risk_score=${risk.toFixed(2)}`, contribution: c });
  }

  const text = alertText(alert);
  if (hasKeyword(text, CRITICAL_KEYWORDS)) {
    weight += 0.35;
    basis.push("critical-severity keyword match in alert text");
    evidence.push({ factor: "critical_keyword", detail: "critical keyword match", contribution: 0.35 });
  } else if (hasKeyword(text, HIGH_KEYWORDS)) {
    weight += 0.2;
    basis.push("high-severity keyword match in alert text");
    evidence.push({ factor: "high_keyword", detail: "high-severity keyword match", contribution: 0.2 });
  }

  const iocs = alert.iocs ?? {};
  const iocHits = [iocs.srcIp, iocs.dstIp, iocs.domain, iocs.fileHash, iocs.url].filter(Boolean).length;
  if (iocHits > 0) {
    const c = Math.min(iocHits * 0.05, 0.15);
    weight += c;
    basis.push(`${iocHits} IOC field(s) present`);
    evidence.push({ factor: "ioc_density", detail: `${iocHits} IOC field(s)`, contribution: c });
  }

  const techniques = alert.techniques ?? [];
  if (techniques.length > 0) {
    const c = Math.min(techniques.length * 0.04, 0.12);
    weight += c;
    basis.push(`${techniques.length} MITRE technique ID(s) attached`);
    evidence.push({ factor: "mitre_coverage", detail: techniques.join(", "), contribution: c });
  }

  if (alert.hostname) {
    weight += 0.05;
    basis.push("hostname present (enables containment)");
    evidence.push({ factor: "containment", detail: `host ${alert.hostname}`, contribution: 0.05 });
  }

  const confidence = clamp(weight);
  const verdict = verdictBand(confidence);
  const recommendation = recommendationFor(verdict);

  if (basis.length === 0) {
    basis.push("no salient signals — defaulting to floor confidence");
    evidence.push({ factor: "no_signal", detail: "no salient signals", contribution: 0 });
  }

  evidence.sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution));

  return {
    alertId: alert.id,
    title: alert.title,
    source: alert.source,
    severity: alert.severity,
    verdict,
    confidence: Number(confidence.toFixed(4)),
    recommendation,
    basis,
    evidence: evidence.slice(0, 3),
  };
}

/** Exposed for the parity test — the exact constants the server pins. */
export const _internals = {
  CONF_FLOOR,
  CONF_CEIL,
  CRITICAL_KEYWORDS,
  HIGH_KEYWORDS,
  verdictBand,
};
