/**
 * Shared types for the aisoc-lite deterministic verdict engine.
 *
 * These mirror the alert fields consumed by the production scorer in
 * `services/agents/app/confidence/scoring.py` so a verdict rendered by the CLI
 * lands in the same band the full stack would assign at triage time.
 */

export type Severity = "info" | "low" | "medium" | "high" | "critical";

/**
 * The five-tier verdict ladder produced at triage. Mirrors `score_triage`'s
 * return contract exactly.
 */
export type Verdict =
  | "true_positive"
  | "likely_true_positive"
  | "needs_review"
  | "likely_benign";

/** What the analyst should do with the alert, derived from the verdict. */
export type Recommendation = "escalate" | "review" | "suppress";

/** Indicators-of-compromise fields the scorer counts as enrichment anchors. */
export interface AlertIocs {
  srcIp?: string;
  dstIp?: string;
  domain?: string;
  fileHash?: string;
  url?: string;
}

/**
 * Normalized alert shape. Source adapters (Splunk / Sentinel / Elastic /
 * CrowdStrike / JSONL / demo) all normalize into this before scoring, so the
 * verdict path is source-agnostic and fully deterministic.
 */
export interface Alert {
  id: string;
  title: string;
  source: string;
  severity: Severity;
  /** Vendor-native risk score already normalized to [0, 1]. */
  riskScore?: number;
  hostname?: string;
  username?: string;
  techniques?: string[];
  iocs?: AlertIocs;
  /**
   * Free-text blob (raw event / description). Scanned for the same critical /
   * high keyword sets the Python scorer uses.
   */
  raw?: string;
  /** Original vendor timestamp if present (ISO 8601). */
  timestamp?: string;
}

/** A single weighted piece of evidence contributing to the verdict. */
export interface EvidenceFactor {
  factor: string;
  detail: string;
  contribution: number;
}

/** The verdict rendered for a single alert. */
export interface AlertVerdict {
  alertId: string;
  title: string;
  source: string;
  severity: Severity;
  verdict: Verdict;
  /** Calibrated confidence in [0.05, 0.95]. */
  confidence: number;
  recommendation: Recommendation;
  /** Human-readable reasoning bullets, strongest first. */
  basis: string[];
  /** Top-N weighted factors for the terminal table / share card. */
  evidence: EvidenceFactor[];
}

/** Aggregate roll-up across a triaged batch. */
export interface TriageSummary {
  total: number;
  truePositive: number;
  needsReview: number;
  suppressed: number;
  noisePercent: number;
  elapsedMs: number;
  /** The one-line, copy-pasteable headline. */
  headline: string;
}

/** Full result of a batch triage run. */
export interface TriageResult {
  verdicts: AlertVerdict[];
  summary: TriageSummary;
  /** True when no LLM key was used — the deterministic floor only. */
  deterministic: boolean;
}
