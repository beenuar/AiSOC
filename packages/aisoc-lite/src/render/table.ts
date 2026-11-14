/**
 * Terminal rendering for the verdict table + headline summary.
 *
 * No layout dependency — a small hand-rolled fixed-width table keeps the
 * install tiny and the output stable across terminals and CI logs.
 */

import pc from "picocolors";
import type { AlertVerdict, Recommendation, TriageResult, Verdict } from "../verdict/types.js";

const VERDICT_LABEL: Record<Verdict, string> = {
  true_positive: "TRUE POSITIVE",
  likely_true_positive: "LIKELY TP",
  needs_review: "NEEDS REVIEW",
  likely_benign: "SUPPRESS (FP)",
};

function colorVerdict(v: Verdict, text: string): string {
  switch (v) {
    case "true_positive":
      return pc.bold(pc.red(text));
    case "likely_true_positive":
      return pc.red(text);
    case "needs_review":
      return pc.yellow(text);
    case "likely_benign":
      return pc.dim(text);
    default: {
      const _never: never = v;
      return _never;
    }
  }
}

const RECO_ICON: Record<Recommendation, string> = {
  escalate: "→ escalate",
  review: "→ review",
  suppress: "→ suppress",
};

function pad(s: string, width: number): string {
  // Pad based on visible length (strip ANSI) so colored cells still align.
  const visible = s.replace(/\u001b\[[0-9;]*m/g, "");
  const gap = Math.max(0, width - visible.length);
  return s + " ".repeat(gap);
}

function truncate(s: string, max: number): string {
  return s.length <= max ? s : s.slice(0, max - 1) + "…";
}

export interface RenderOptions {
  /** Cap the number of rows printed (escalations always shown first). */
  maxRows?: number;
  /** Only show rows that need attention (TP + review), hiding suppressed noise. */
  attentionOnly?: boolean;
}

export function renderTable(result: TriageResult, opts: RenderOptions = {}): string {
  const rows: AlertVerdict[] = opts.attentionOnly
    ? result.verdicts.filter((v) => v.verdict !== "likely_benign")
    : result.verdicts;

  const shown = typeof opts.maxRows === "number" ? rows.slice(0, opts.maxRows) : rows;
  const lines: string[] = [];

  const wId = 11;
  const wVerdict = 14;
  const wConf = 6;
  const wTitle = 42;
  const wEvidence = 34;

  lines.push(
    pc.bold(
      pad("ALERT", wId) +
        "  " +
        pad("VERDICT", wVerdict) +
        "  " +
        pad("CONF", wConf) +
        "  " +
        pad("TITLE", wTitle) +
        "  " +
        pad("TOP EVIDENCE", wEvidence),
    ),
  );
  lines.push(pc.dim("─".repeat(wId + wVerdict + wConf + wTitle + wEvidence + 8)));

  for (const v of shown) {
    const conf = `${Math.round(v.confidence * 100)}%`;
    const topEvidence = v.evidence[0]?.detail ?? v.basis[0] ?? "—";
    lines.push(
      pad(pc.cyan(v.alertId), wId) +
        "  " +
        pad(colorVerdict(v.verdict, VERDICT_LABEL[v.verdict]), wVerdict) +
        "  " +
        pad(conf, wConf) +
        "  " +
        pad(truncate(v.title, wTitle), wTitle) +
        "  " +
        pc.dim(truncate(`${RECO_ICON[v.recommendation]} · ${topEvidence}`, wEvidence)),
    );
  }

  if (shown.length < rows.length) {
    lines.push(pc.dim(`  … ${rows.length - shown.length} more (raise --max-rows to see all)`));
  }
  return lines.join("\n");
}

export function renderHeadline(result: TriageResult): string {
  const s = result.summary;
  const badge = result.deterministic ? pc.dim(" [deterministic · no LLM]") : pc.dim(" [LLM-assisted]");
  const parts = [
    pc.bold(pc.green("✓ ")) + pc.bold(s.headline) + badge,
    "  " +
      pc.red(`${s.truePositive} escalate`) +
      pc.dim(" · ") +
      pc.yellow(`${s.needsReview} review`) +
      pc.dim(" · ") +
      pc.dim(`${s.suppressed} suppressed`),
  ];
  return parts.join("\n");
}
