/**
 * `aisoc triage` — pull alerts from a source, score them to verdicts, print a
 * table + one-line headline, and optionally write a share card.
 */

import pc from "picocolors";
import { loadAlerts, type SourceKind } from "../sources.js";
import { summarize, triageBatch } from "../verdict/engine.js";
import { recommendationFor } from "../verdict/stages.js";
import { renderHeadline, renderTable } from "../render/table.js";
import { writeShareArtifacts } from "../share.js";
import { detectProvider, refineWithLlm } from "../llm.js";
import { resolveTelemetry, buildPayload, sendTelemetry } from "../telemetry.js";
import type { AlertVerdict, TriageResult } from "../verdict/types.js";
import { VERSION } from "../version.js";

export interface TriageFlags {
  demo?: boolean;
  file?: string;
  source?: string;
  limit?: number;
  maxRows?: number;
  attentionOnly?: boolean;
  json?: boolean;
  share?: string | boolean;
  llm?: boolean;
  telemetry?: boolean;
  noTelemetry?: boolean;
}

function resolveSource(flags: TriageFlags): { kind: SourceKind; file?: string } {
  if (flags.demo) return { kind: "demo" };
  if (flags.file) return { kind: "jsonl", file: flags.file };
  const s = (flags.source ?? "demo").toLowerCase();
  const allowed: SourceKind[] = ["demo", "jsonl", "splunk", "sentinel", "elastic", "crowdstrike"];
  if (!(allowed as string[]).includes(s)) {
    throw new Error(`unknown source '${s}'. Use one of: ${allowed.join(", ")}, or --demo / --file.`);
  }
  return { kind: s as SourceKind, file: flags.file };
}

/** Overlay LLM refinements onto the deterministic result (needs_review band only). */
function applyRefinements(result: TriageResult, refinements: Map<string, AlertVerdict["verdict"]>): TriageResult {
  const verdicts = result.verdicts.map((v) => {
    const refined = refinements.get(v.alertId);
    if (!refined || refined === v.verdict) return v;
    return {
      ...v,
      verdict: refined,
      recommendation: recommendationFor(refined),
      basis: [...v.basis, "(LLM band refined this verdict)"],
    };
  });
  return {
    verdicts,
    summary: summarize(verdicts, result.summary.elapsedMs),
    deterministic: false,
  };
}

export async function runTriage(flags: TriageFlags, log: (s: string) => void = console.log): Promise<TriageResult> {
  const { kind, file } = resolveSource(flags);
  const alerts = await loadAlerts(kind, { file, limit: flags.limit });

  if (alerts.length === 0) {
    throw new Error("no alerts to triage (source returned empty).");
  }

  let result = triageBatch(alerts, { deterministic: true });

  // Optional BYO-key LLM band over the ambiguous middle only.
  if (flags.llm) {
    const provider = detectProvider();
    if (!provider) {
      log(pc.yellow("--llm requested but no ANTHROPIC_API_KEY / OPENAI_API_KEY found; staying deterministic."));
    } else {
      const ambiguous = alerts.filter((a) => {
        const v = result.verdicts.find((x) => x.alertId === a.id);
        return v?.verdict === "needs_review";
      });
      try {
        log(pc.dim(`Refining ${ambiguous.length} ambiguous alert(s) with your ${provider.name} key (${provider.model})…`));
        const refs = await refineWithLlm(ambiguous, provider);
        const map = new Map(refs.map((r) => [r.alertId, r.verdict]));
        result = applyRefinements(result, map);
      } catch (err) {
        log(pc.yellow(`LLM band failed (${(err as Error).message}); keeping deterministic verdicts.`));
      }
    }
  }

  if (flags.json) {
    log(JSON.stringify(result, null, 2));
  } else {
    log("");
    log(renderTable(result, { maxRows: flags.maxRows ?? 20, attentionOnly: flags.attentionOnly }));
    log("");
    log(renderHeadline(result));
    log("");
  }

  // Optional share card.
  if (flags.share) {
    const base = typeof flags.share === "string" ? flags.share : "aisoc-report-card.md";
    const paths = await writeShareArtifacts(result, base);
    if (!flags.json) log(pc.dim(`Share card written: ${paths.join(", ")}`));
  }

  // Strictly opt-in telemetry (aggregate only).
  const decision = resolveTelemetry(flags);
  if (decision.enabled) {
    await sendTelemetry(buildPayload(result, kind, VERSION));
    if (!flags.json) log(pc.dim("Sent opt-in aggregate telemetry (counts only — see TELEMETRY.md)."));
  }

  return result;
}
