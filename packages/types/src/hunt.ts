/**
 * AiSOC Threat-Hunting types — natural-language hunt surface (T3.4).
 *
 * Mirrors the wire shape of `services/api/app/api/v1/endpoints/saved_hunts.py`
 * and `services/api/app/api/v1/endpoints/nl_query.py`. These are the
 * canonical contracts shared between the API service, the Next.js web
 * app, and any future SDK consumers.
 *
 * The types here intentionally mirror — not import from — the runtime
 * shapes in `apps/web/src/lib/api.ts`. We keep the package pure (no
 * runtime imports of the web app) so non-web consumers can use it
 * standalone.
 */

/** Output dialects of the deterministic NL → query translator. */
export type HuntLanguage = "esql" | "kql" | "spl";

/**
 * Translator output stored alongside the original NL question.
 *
 * The fields are always strings (never null/undefined) — an empty
 * string indicates "translator could not produce this dialect" rather
 * than "field absent".
 */
export interface TranslatedQueryEnvelope {
  esql: string;
  kql: string;
  spl: string;
  explanation: string;
}

/**
 * Saved natural-language hunt persisted in `aisoc_saved_hunts`.
 *
 * Distinct from the hypothesis-driven hunt model in
 * `services/api/app/api/v1/endpoints/hunts.py` (which has its own
 * heavyweight schema with MITRE mappings, multi-platform queries, and
 * findings rollups). This lighter-weight type backs the "Saved hunts"
 * sidebar on the `/hunt` page.
 */
export interface SavedHunt {
  id: string;
  name: string;
  /** Original English question the analyst asked. */
  nl_query: string;
  /** Snapshot translation taken at save time (and refreshed on each run). */
  translated_query: TranslatedQueryEnvelope;
  /** Preferred dialect to render in the editor when the hunt re-opens. */
  language: HuntLanguage;
  /**
   * Optional 5-field cron string (`min hour dom mon dow`). When set,
   * the API-side `hunt_scheduler` worker fires the hunt on cadence.
   */
  schedule: string | null;
  /** ISO-8601; null until the first run completes. */
  last_run_at: string | null;
  created_at: string;
  updated_at: string;
  /** UUID of the creating user, or null if the hunt was system-seeded. */
  created_by: string | null;
}

export interface CreateSavedHuntRequest {
  name: string;
  nl_query: string;
  language?: HuntLanguage;
  schedule?: string | null;
}

/**
 * Synchronous response from `POST /v1/saved-hunts/{id}/run`.
 *
 * The endpoint *re-translates* the NL question (so improvements to the
 * translator land automatically) and stamps `last_run_at`. It does not
 * actually execute ES|QL — that path is owned by `/v1/nl-query/execute`.
 */
export interface RunSavedHuntResponse {
  id: string;
  name: string;
  nl_query: string;
  translated_query: TranslatedQueryEnvelope;
  last_run_at: string;
}

/** Body for `POST /v1/nl-query/translate`. */
export interface NlQueryTranslateRequest {
  question: string;
  index_pattern?: string;
  time_range_hours?: number;
}

/** Response shape for `POST /v1/nl-query/translate`. */
export interface NlQueryTranslateResponse {
  request_id: string;
  question: string;
  esql: string;
  spl: string;
  kql: string;
  explanation: string;
  created_at: string;
  /** `deterministic` for the in-process grammar, `llm` for LLM-enhanced. */
  engine: "deterministic" | "llm";
  grammar_validated: boolean;
}
