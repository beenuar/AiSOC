/**
 * Batch verdict engine + summary roll-up.
 *
 * `triageBatch` runs the deterministic per-alert scorer across a batch and
 * produces the one-line, copy-pasteable headline the CLI prints and the
 * `--share` report card embeds.
 */

import { scoreAlert } from "./stages.js";
import type { Alert, AlertVerdict, TriageResult, TriageSummary } from "./types.js";

/** Roll a set of per-alert verdicts up into the headline summary. */
export function summarize(verdicts: AlertVerdict[], elapsedMs: number): TriageSummary {
  const total = verdicts.length;
  let truePositive = 0;
  let needsReview = 0;
  let suppressed = 0;

  for (const v of verdicts) {
    if (v.verdict === "true_positive" || v.verdict === "likely_true_positive") {
      truePositive += 1;
    } else if (v.verdict === "needs_review") {
      needsReview += 1;
    } else {
      suppressed += 1;
    }
  }

  const noisePercent = total > 0 ? Number(((suppressed / total) * 100).toFixed(1)) : 0;
  const seconds = (elapsedMs / 1000).toFixed(elapsedMs < 10_000 ? 1 : 0);

  const headline =
    `AiSOC triaged ${total} alert${total === 1 ? "" : "s"}: ` +
    `${truePositive} TP, ${suppressed} FP suppressed (${noisePercent}% noise), ` +
    `${needsReview} need review — in ${seconds}s`;

  return { total, truePositive, needsReview, suppressed, noisePercent, elapsedMs, headline };
}

/**
 * Triage a batch of already-normalized alerts. Pure and deterministic:
 * identical input always yields an identical result (modulo `elapsedMs`).
 */
export function triageBatch(alerts: Alert[], opts: { deterministic?: boolean } = {}): TriageResult {
  const started = Date.now();
  const verdicts = alerts.map(scoreAlert);
  // Sort escalations first so the terminal table leads with what matters.
  const order: Record<AlertVerdict["verdict"], number> = {
    true_positive: 0,
    likely_true_positive: 1,
    needs_review: 2,
    likely_benign: 3,
  };
  verdicts.sort((a, b) => order[a.verdict] - order[b.verdict] || b.confidence - a.confidence);
  const elapsedMs = Date.now() - started;
  return {
    verdicts,
    summary: summarize(verdicts, elapsedMs),
    deterministic: opts.deterministic ?? true,
  };
}
