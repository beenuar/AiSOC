/**
 * Render the triage result as Markdown for a PR comment / job summary, and
 * compute a simple security-posture grade for the weekly digest.
 */

import type { AlertVerdict, TriageResult } from "./_vendor/verdict/index.js";
import { coverageGrade } from "@aisoc/report-card";

const VERDICT_EMOJI: Record<AlertVerdict["verdict"], string> = {
  true_positive: "🔴",
  likely_true_positive: "🟠",
  needs_review: "🟡",
  likely_benign: "⚪",
};

/** Marker so the action can find + update its own PR comment idempotently. */
export const COMMENT_MARKER = "<!-- aisoc-action-triage -->";

export function priorityLine(result: TriageResult): string {
  const exploitable = result.verdicts.filter(
    (v) => v.verdict === "true_positive" || v.verdict === "likely_true_positive",
  ).length;
  return `**${exploitable} of ${result.summary.total}** findings are prioritized as exploitable / act-now; ${result.summary.suppressed} are low-signal noise.`;
}

/**
 * A 0–100 posture score → A–F grade. Weighted by how many findings escalate:
 * an empty queue or all-benign scores high; open escalations pull it down.
 */
export function postureGrade(result: TriageResult): { grade: string; score: number } {
  const { total, truePositive, needsReview } = result.summary;
  if (total === 0) return { grade: "A", score: 100 };
  const penalty = (truePositive * 12 + needsReview * 3) / total;
  const score = Math.max(0, Math.round(100 - penalty * 10));
  return { grade: coverageGrade(score), score };
}

// Escape a value for a Markdown table cell: backslashes first (so escape
// sequences aren't double-processed), then the pipe column delimiter, then
// collapse newlines that would otherwise break the row.
function cell(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

function table(verdicts: AlertVerdict[], limit = 30): string {
  const rows = verdicts
    .slice(0, limit)
    .map(
      (v) =>
        `| ${VERDICT_EMOJI[v.verdict]} ${v.verdict.replace(/_/g, " ")} | ${Math.round(v.confidence * 100)}% | \`${cell(v.source)}\` | ${cell(v.title.slice(0, 80))} | ${cell(v.recommendation)} |`,
    )
    .join("\n");
  const extra = verdicts.length > limit ? `\n\n_…and ${verdicts.length - limit} more._` : "";
  return `| Verdict | Confidence | Source | Finding | Action |\n|---|---|---|---|---|\n${rows}${extra}`;
}

export function renderComment(result: TriageResult, notes: string[]): string {
  const s = result.summary;
  const attention = result.verdicts.filter((v) => v.verdict !== "likely_benign");
  const lines = [
    COMMENT_MARKER,
    "## 🛡️ AiSOC security triage",
    "",
    `> ${s.headline}`,
    "",
    priorityLine(result),
    "",
    attention.length ? table(attention) : "_No findings need attention — all open alerts triaged as low-signal noise._",
    "",
  ];
  if (notes.length) {
    lines.push("<details><summary>Notes</summary>\n", ...notes.map((n) => `- ${n}`), "\n</details>", "");
  }
  lines.push(
    "",
    // No remote badge image here on purpose: this line promises "no data
    // leaves your CI", and a hotlinked badge makes every reader's browser
    // call a third-party deployment to render the comment.
    "<sub>Triaged by the deterministic [AiSOC](https://github.com/beenuar/AiSOC) verdict engine — no LLM, no data leaves your CI.</sub>",
  );
  return lines.join("\n");
}

export function renderDigest(result: TriageResult, previous: TriageResult | null, notes: string[]): string {
  const { grade, score } = postureGrade(result);
  const s = result.summary;
  const delta = previous ? s.truePositive - previous.summary.truePositive : null;
  const deltaStr =
    delta === null ? "" : delta === 0 ? " (no change vs last week)" : delta > 0 ? ` (▲ +${delta} vs last week)` : ` (▼ ${delta} vs last week)`;
  return [
    COMMENT_MARKER,
    `## 🛡️ AiSOC weekly security posture — grade ${grade} (${score}/100)`,
    "",
    `- **${s.total}** open findings triaged`,
    `- **${s.truePositive}** act-now${deltaStr}`,
    `- **${s.needsReview}** need review`,
    `- **${s.suppressed}** low-signal noise`,
    "",
    priorityLine(result),
    "",
    ...(notes.length ? notes.map((n) => `> ${n}`) : []),
    "",
    "<sub>Generated weekly by [AiSOC](https://github.com/beenuar/AiSOC). Deterministic; nothing leaves your CI.</sub>",
  ].join("\n");
}
