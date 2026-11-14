/**
 * Barrel for the vendored deterministic verdict engine.
 *
 * `types.ts`, `stages.ts`, and `engine.ts` are byte-for-byte copies of
 * `packages/aisoc-lite/src/verdict/` kept in sync by
 * `scripts/sync_vendored_verdict.py` (a `--check` gate runs in CI). Do not edit
 * the copies by hand — change the source and re-run the sync script.
 */

export type { Alert, AlertVerdict, Severity, TriageResult, TriageSummary, Verdict } from "./types.js";
export { scoreAlert, recommendationFor } from "./stages.js";
export { triageBatch, summarize } from "./engine.js";
