/**
 * Public library surface for `aisoc-lite`.
 *
 * The same deterministic verdict engine that powers the CLI is exported so the
 * GitHub Action (`packages/aisoc-action`) and other consumers can score alerts
 * without re-implementing the stages.
 */

export type {
  Alert,
  AlertIocs,
  AlertVerdict,
  EvidenceFactor,
  Recommendation,
  Severity,
  TriageResult,
  TriageSummary,
  Verdict,
} from "./verdict/types.js";

export { scoreAlert, recommendationFor } from "./verdict/stages.js";
export { triageBatch, summarize } from "./verdict/engine.js";
export {
  translateRule,
  FORMAT_LABELS,
  type DetectionFormat,
  type TranslateOutput,
  type TranslationResult,
} from "./verdict/translate.js";
export { loadDemoAlerts, DEMO_ALERT_COUNT } from "./fixtures/index.js";
export { normalizeRecord, loadJsonl, loadAlerts, type SourceKind } from "./sources.js";
export { renderShareArtifacts, renderMarkdownCard, renderSvgCard, type ShareArtifacts } from "./share.js";
export { VERSION } from "./version.js";
