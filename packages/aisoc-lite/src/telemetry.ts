/**
 * Strictly opt-in, aggregate-only telemetry.
 *
 * Default: OFF. Nothing is sent unless the user passes `--telemetry` or sets
 * `AISOC_TELEMETRY=1`. Even then, only run counts and verdict-band aggregates
 * leave the machine — never alert content, IOCs, hostnames, filenames, or
 * config. `--no-telemetry` and `AISOC_TELEMETRY=0` are hard overrides.
 *
 * The full contract is documented in TELEMETRY.md and printed on first use.
 * Trust is the moat; this file must never grow to collect more.
 */

import type { TriageResult } from "./verdict/types.js";

/**
 * There is deliberately no default endpoint.
 *
 * This previously defaulted to a hosted collector that does not resolve, so an
 * opted-in user's payload was POSTed into a black hole while TELEMETRY.md told
 * them it was being collected. Silently discarding data someone consented to
 * send is a worse trust failure than not collecting it, so sending now
 * requires an endpoint to be named explicitly. Self-hosters can point this at
 * their own collector; the project itself runs none.
 */
const ENDPOINT = process.env.AISOC_TELEMETRY_ENDPOINT || "";

export interface TelemetryDecision {
  enabled: boolean;
  reason: string;
}

/**
 * Resolve whether telemetry is enabled. Precedence (highest first):
 *   1. explicit `--no-telemetry` flag        → off
 *   2. explicit `--telemetry` flag           → on
 *   3. AISOC_TELEMETRY=0                      → off
 *   4. AISOC_TELEMETRY=1                      → on
 *   5. default                               → off
 */
export function resolveTelemetry(flags: { telemetry?: boolean; noTelemetry?: boolean }): TelemetryDecision {
  if (flags.noTelemetry) return { enabled: false, reason: "--no-telemetry" };
  if (flags.telemetry) return { enabled: true, reason: "--telemetry" };
  const env = process.env.AISOC_TELEMETRY;
  if (env === "0" || env === "false") return { enabled: false, reason: "AISOC_TELEMETRY=0" };
  if (env === "1" || env === "true") return { enabled: true, reason: "AISOC_TELEMETRY=1" };
  return { enabled: false, reason: "default (opt-in only)" };
}

/** The exact aggregate payload — nothing here can identify an alert or host. */
export interface TelemetryPayload {
  event: "triage";
  version: string;
  source: string;
  total: number;
  truePositive: number;
  needsReview: number;
  suppressed: number;
  deterministic: boolean;
  elapsedMs: number;
}

export function buildPayload(result: TriageResult, source: string, version: string): TelemetryPayload {
  const s = result.summary;
  return {
    event: "triage",
    version,
    source,
    total: s.total,
    truePositive: s.truePositive,
    needsReview: s.needsReview,
    suppressed: s.suppressed,
    deterministic: result.deterministic,
    elapsedMs: s.elapsedMs,
  };
}

/**
 * Fire-and-forget send. Never blocks or fails the CLI; silent on error.
 *
 * Returns false without any network call when no endpoint is configured, so
 * "enabled but going nowhere" is distinguishable from "sent".
 */
export async function sendTelemetry(payload: TelemetryPayload): Promise<boolean> {
  if (!ENDPOINT) return false;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2000);
    await fetch(ENDPOINT, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    clearTimeout(timer);
    return true;
  } catch {
    // Telemetry must never degrade the tool. Swallow all errors.
    return false;
  }
}
