/**
 * The README claimed "every tool call logged through this server lands in the
 * AiSOC audit log with the calling user and the tool name. You can revoke the
 * key and replay every action it took."
 *
 * The server emitted nothing. The API's `audit_middleware` only records
 * mutating methods carrying a valid JWT, so the ten read tools produced no
 * audit row at all, and what it did record was an HTTP path rather than a tool
 * name. This server is a standing read path into a customer's alerts, cases
 * and event lake, so the gap was a data-egress path nobody could account for.
 */

import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { ToolCallTelemetry, argumentKeys } from "../src/telemetry.js";

const log = { info: () => {}, error: () => {}, warn: () => {} } as never;
const ENDPOINT = "https://aisoc.example.com/v1/inbox/mcp-token";

describe("argumentKeys", () => {
  it("returns parameter names, never values", () => {
    // Which tool ran with which parameter names is the signal. The values are
    // frequently the sensitive part: an alert id, a lake query, a hostname.
    const keys = argumentKeys({ alert_id: "a-secret-id", limit: 10 });
    expect(keys).toEqual(["alert_id", "limit"]);
    expect(JSON.stringify(keys)).not.toContain("a-secret-id");
  });

  it("is sorted so a detection can match on the key set", () => {
    expect(argumentKeys({ z: 1, a: 2 })).toEqual(["a", "z"]);
  });

  it("handles the shapes a transport can actually deliver", () => {
    expect(argumentKeys(undefined)).toEqual([]);
    expect(argumentKeys(null)).toEqual([]);
    expect(argumentKeys([1, 2])).toEqual([]);
    expect(argumentKeys("string")).toEqual([]);
  });
});

describe("ToolCallTelemetry", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn(async () => ({ ok: true, status: 200 }) as never);
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("is disabled without an endpoint, and silently so", () => {
    // An operator who has not opted in has not misconfigured anything, so
    // this must not warn or buffer.
    const t = new ToolCallTelemetry(log, undefined);
    expect(t.enabled).toBe(false);
    t.record({
      tool_name: "aisoc_list_alerts",
      argument_keys: [],
      outcome: "success",
      latency_ms: 5,
    });
    expect(t.stats().recorded).toBe(0);
  });

  it("records a successful tool call", async () => {
    const t = new ToolCallTelemetry(log, ENDPOINT);
    t.record({
      tool_name: "aisoc_list_alerts",
      argument_keys: ["limit"],
      outcome: "success",
      latency_ms: 12,
    });
    await t.flush();

    expect(fetchMock).toHaveBeenCalledOnce();
    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body).toHaveLength(1);
    expect(body[0].tool_name).toBe("aisoc_list_alerts");
    expect(body[0].argument_keys).toEqual(["limit"]);
    expect(body[0].outcome).toBe("success");
    expect(body[0].agent_id).toBe("aisoc-mcp-server");
    // Routine activity: the ai-runtime template maps info severity to OCSF
    // 6003 API Activity, category 6, which stays in the lake rather than
    // becoming an alert. A read tool doing its job is not an incident.
    expect(body[0].severity).toBe("info");
  });

  it("records refused calls too", async () => {
    // A tool call that was rejected is as much a part of the account of what
    // a key did as one that succeeded.
    const t = new ToolCallTelemetry(log, ENDPOINT);
    for (const outcome of ["error", "invalid_arguments", "unknown_tool"] as const) {
      t.record({ tool_name: "x", argument_keys: [], outcome, latency_ms: 1 });
    }
    await t.flush();
    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.map((r: { outcome: string }) => r.outcome)).toEqual([
      "error",
      "invalid_arguments",
      "unknown_tool",
    ]);
    expect(body.every((r: { severity: string }) => r.severity === "low")).toBe(true);
  });

  it("never throws when the inbox is unreachable", async () => {
    // Telemetry must not surface into a tool call's control flow.
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("ECONNREFUSED");
      }),
    );
    const t = new ToolCallTelemetry(log, ENDPOINT);
    t.record({ tool_name: "x", argument_keys: [], outcome: "success", latency_ms: 1 });
    await expect(t.flush()).resolves.toBeUndefined();
    expect(t.stats().failed).toBe(1);
  });

  it("counts a non-2xx response as failed rather than sent", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => ({ ok: false, status: 401 }) as never));
    const t = new ToolCallTelemetry(log, ENDPOINT);
    t.record({ tool_name: "x", argument_keys: [], outcome: "success", latency_ms: 1 });
    await t.flush();
    expect(t.stats().failed).toBe(1);
    expect(t.stats().sent).toBe(0);
  });

  it("bounds the buffer so an unreachable inbox cannot grow memory", async () => {
    const t = new ToolCallTelemetry(log, ENDPOINT);
    for (let i = 0; i < 500; i += 1) {
      t.record({ tool_name: `t-${i}`, argument_keys: [], outcome: "success", latency_ms: 1 });
    }
    await t.flush();
    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.length).toBeLessThanOrEqual(200);
    // The oldest are dropped, because recent activity is the useful signal.
    expect(body[body.length - 1].tool_name).toBe("t-499");
  });

  it("flushing an empty buffer makes no request", async () => {
    const t = new ToolCallTelemetry(log, ENDPOINT);
    await t.flush();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
