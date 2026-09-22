/**
 * Tool-call telemetry for this MCP server.
 *
 * The README claimed "every tool call logged through this server lands in the
 * AiSOC audit log with the calling user and the tool name. You can revoke the
 * key and replay every action it took." None of that was true. The server
 * emitted nothing, and the API's `audit_middleware` only records mutating
 * methods carrying a valid JWT, so the ten read tools (`aisoc_list_*`,
 * `aisoc_get_*`, `aisoc_lake_query`) produced no audit row at all — and what
 * it did record was an HTTP path rather than a tool name.
 *
 * That gap matters more here than in most places. This server is how an
 * assistant reads a customer's alerts, cases and event lake, which makes it a
 * standing data-egress path that nobody could account for after the fact.
 *
 * So AiSOC's own MCP server is the first monitored asset in the AI estate
 * capability. Records go to the same `ai-runtime` inbox template as any
 * customer agent, meaning the surface AiSOC ships is held to the contract it
 * asks customers to adopt.
 *
 * Three deliberate limits:
 *
 * - **Argument keys, never values.** Which tool ran with which parameter names
 *   is the signal; the values are frequently the sensitive part (an alert id,
 *   a lake query, a hostname).
 * - **Fire-and-forget.** Telemetry must not add latency to, or fail, a tool
 *   call. Every failure path here is swallowed and counted.
 * - **Off unless configured.** No endpoint means no emission and no warning
 *   spam; an operator who has not opted in has not misconfigured anything.
 */

import type { Logger } from "./config.js";

/** What we record about one tool invocation. */
export interface ToolCallRecord {
  tool_name: string;
  /** Parameter names supplied. Values are deliberately excluded. */
  argument_keys: string[];
  outcome: "success" | "error" | "invalid_arguments" | "unknown_tool";
  latency_ms: number;
  /** Subject of the calling key, when the transport made one available. */
  on_behalf_of?: string;
  error_kind?: string;
}

export interface TelemetryCounters {
  recorded: number;
  sent: number;
  failed: number;
}

const FLUSH_INTERVAL_MS = 2_000;
const MAX_BUFFER = 200;
const REQUEST_TIMEOUT_MS = 5_000;

/**
 * Buffers tool-call records and posts them to an AiSOC inbox token.
 *
 * Configured by `AISOC_MCP_TELEMETRY_URL`. Absent that, `enabled` is false and
 * every method is a no-op.
 */
export class ToolCallTelemetry {
  private readonly endpoint: string | undefined;
  private readonly agentId: string;
  private readonly log: Logger;
  private buffer: Record<string, unknown>[] = [];
  private timer: NodeJS.Timeout | undefined;
  private counters: TelemetryCounters = { recorded: 0, sent: 0, failed: 0 };

  constructor(log: Logger, endpoint = process.env.AISOC_MCP_TELEMETRY_URL) {
    this.log = log;
    this.endpoint = endpoint?.trim() || undefined;
    this.agentId = process.env.AISOC_MCP_AGENT_ID?.trim() || "aisoc-mcp-server";

    if (this.enabled) {
      this.timer = setInterval(() => void this.flush(), FLUSH_INTERVAL_MS);
      // Do not hold the process open purely to flush telemetry.
      this.timer.unref?.();
    }
  }

  get enabled(): boolean {
    return this.endpoint !== undefined;
  }

  stats(): TelemetryCounters {
    return { ...this.counters };
  }

  /** Record one tool call. Never throws. */
  record(entry: ToolCallRecord): void {
    if (!this.enabled) return;
    this.counters.recorded += 1;
    this.buffer.push({
      agent_id: this.agentId,
      agent_name: "AiSOC MCP Server",
      timestamp: new Date().toISOString(),
      tool_name: entry.tool_name,
      argument_keys: entry.argument_keys,
      outcome: entry.outcome,
      latency_ms: Math.round(entry.latency_ms),
      // A failed tool call is not a security finding, so routine severity.
      // The ai-runtime template maps this to OCSF 6003 API Activity, which is
      // category 6 and therefore lake-only rather than auto-promoted.
      severity: entry.outcome === "success" ? "info" : "low",
      ...(entry.on_behalf_of ? { on_behalf_of: entry.on_behalf_of } : {}),
      ...(entry.error_kind ? { error_kind: entry.error_kind } : {}),
    });

    // Bounded: an unreachable endpoint must not grow memory without limit.
    // Drop the oldest, because recent activity is the more useful signal.
    if (this.buffer.length > MAX_BUFFER) {
      this.buffer.splice(0, this.buffer.length - MAX_BUFFER);
    }
  }

  /** Post whatever is buffered. Never throws. */
  async flush(): Promise<void> {
    if (!this.enabled || this.buffer.length === 0) return;
    const batch = this.buffer;
    this.buffer = [];

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      const res = await fetch(this.endpoint as string, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "User-Agent": "aisoc-mcp-telemetry",
        },
        body: JSON.stringify(batch),
        signal: controller.signal,
      });
      if (res.ok) {
        this.counters.sent += batch.length;
      } else {
        this.counters.failed += batch.length;
        this.log.info(`telemetry: inbox returned HTTP ${res.status}`);
      }
    } catch (err) {
      // Telemetry failure must never surface into a tool call's control flow.
      this.counters.failed += batch.length;
      this.log.info(
        `telemetry: dropped ${batch.length} record(s): ${String(err)}`,
      );
    } finally {
      clearTimeout(timeout);
    }
  }

  async close(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    await this.flush();
  }
}

/**
 * Parameter names from a tool-call argument object, sorted for stability.
 *
 * Values are never read. A stable order means a detection can match on the
 * key set without the gateway's iteration order mattering.
 */
export function argumentKeys(args: unknown): string[] {
  if (args === null || typeof args !== "object" || Array.isArray(args)) return [];
  return Object.keys(args as Record<string, unknown>).sort();
}
