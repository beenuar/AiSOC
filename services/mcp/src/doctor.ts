/**
 * `aisoc-mcp doctor` — pre-flight diagnostic.
 *
 * Run by users before wiring this into Claude Desktop / Cursor so they can
 * confirm their `AISOC_URL` and `AISOC_API_KEY` actually work, without
 * having to chase silent failures inside an IDE side panel.
 *
 * Exits non-zero on any failed check so it's usable from CI / `pnpm
 * aisoc:doctor`-style umbrella scripts.
 */
import { AisocClient } from "./client.js";
import { type ServerConfig, type Logger, packageVersion } from "./config.js";
import { ApiError, MissingApiKeyError, TransportError } from "./errors.js";

export interface DoctorReport {
  ok: boolean;
  checks: Array<{
    name: string;
    status: "ok" | "warn" | "fail";
    detail: string;
  }>;
}

export async function runDoctor(
  cfg: ServerConfig,
  log: Logger,
): Promise<DoctorReport> {
  const checks: DoctorReport["checks"] = [];

  // 1. Config presence -------------------------------------------------------
  checks.push({
    name: "AISOC_URL",
    status: "ok",
    detail: cfg.aisocUrl,
  });

  if (!cfg.apiKey) {
    checks.push({
      name: "AISOC_API_KEY",
      status: "fail",
      detail:
        "Not set. Provide via env (AISOC_API_KEY) or --api-key. Tools will fail without an API key.",
    });
    return finalise(checks);
  }
  checks.push({
    name: "AISOC_API_KEY",
    status: "ok",
    detail: maskKey(cfg.apiKey),
  });

  // 2. Reachability ----------------------------------------------------------
  const client = new AisocClient(cfg, log);
  try {
    const health = await client.health();
    checks.push({
      name: "API reachable",
      status: health.reachable ? "ok" : "warn",
      detail: health.reachable
        ? `${cfg.aisocUrl} responded (${health.status})`
        : `Reached ${cfg.aisocUrl} but health endpoint returned non-OK`,
    });
  } catch (err) {
    checks.push({
      name: "API reachable",
      status: "fail",
      detail: describeError(err, cfg.aisocUrl),
    });
    return finalise(checks);
  }

  // 3. Auth ------------------------------------------------------------------
  // We probe `/api/v1/cases?limit=1` because it's a low-cost auth-required
  // endpoint that exists on every AiSOC deployment with cases. If the user's
  // tenant is empty the call still succeeds with an empty list.
  try {
    await client.get<{ items: unknown[] }>("/api/v1/cases", {
      query: { limit: 1, offset: 0 },
    });
    checks.push({
      name: "API authentication",
      status: "ok",
      detail: "Token accepted; tools should work.",
    });
  } catch (err) {
    if (err instanceof ApiError) {
      checks.push({
        name: "API authentication",
        status: "fail",
        detail: err.isAuthFailure
          ? `Auth rejected (${err.status}). Check AISOC_API_KEY scope/expiry.`
          : `API returned ${err.status}: ${err.detail}`,
      });
    } else if (err instanceof MissingApiKeyError) {
      checks.push({
        name: "API authentication",
        status: "fail",
        detail: "Missing API key (resolved to empty after config load).",
      });
    } else {
      checks.push({
        name: "API authentication",
        status: "fail",
        detail: describeError(err, cfg.aisocUrl),
      });
    }
  }

  return finalise(checks);
}

/** Print the doctor report to stderr in a human-readable form. */
export function printDoctorReport(report: DoctorReport): void {
  const lines: string[] = [];
  lines.push(`aisoc-mcp ${packageVersion()} doctor`);
  lines.push("");
  for (const c of report.checks) {
    const icon = c.status === "ok" ? "[OK]" : c.status === "warn" ? "[WARN]" : "[FAIL]";
    lines.push(`${icon} ${c.name}`);
    lines.push(`     ${c.detail}`);
  }
  lines.push("");
  lines.push(report.ok ? "All checks passed." : "Doctor found problems.");
  // doctor output is a user-visible report; print to stdout so it's easy
  // to redirect / capture from `pnpm aisoc:doctor`. We do *not* emit any
  // JSON-RPC alongside this; doctor is invoked as a one-shot subcommand
  // and the server transport is never started.
  for (const l of lines) console.log(l);
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function finalise(checks: DoctorReport["checks"]): DoctorReport {
  return {
    ok: checks.every((c) => c.status !== "fail"),
    checks,
  };
}

function describeError(err: unknown, url: string): string {
  if (err instanceof TransportError) {
    return `Could not reach ${url}: ${err.message}`;
  }
  if (err instanceof Error) return err.message;
  return String(err);
}

function maskKey(k: string): string {
  if (k.length <= 8) return "***";
  return `${k.slice(0, 4)}…${k.slice(-4)} (${k.length} chars)`;
}
