/**
 * The HTTP transport: who gets in, whose credential is used, and what runs.
 *
 * Depth 9.1 (parity 6.6). These drive a real `node:http` listener against a
 * real stub of the AiSOC API, because the properties under test are about
 * what travels on the wire — which header carries the credential, whether an
 * authorize request happens before dispatch, whether a refusal stops the
 * tool. A mocked transport would assert that the code calls the functions it
 * calls, which is the shape of test this repository has been bitten by.
 */
import { createServer, type Server as NodeServer } from "node:http";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { makeLogger, resolveConfig, parseArgs } from "../src/config.js";
import { bearerFrom, handleMcpRequest, resolveHttpOptions, HEALTH_PATH, MCP_PATH } from "../src/http.js";
import { safeUserAgent } from "../src/gate.js";

interface RecordedCall {
  path: string;
  authorization: string | undefined;
  body: Record<string, unknown>;
}

/** A stand-in for the AiSOC API: records what it was asked and answers it. */
class ApiStub {
  readonly calls: RecordedCall[] = [];
  /** Verdict the authorize route returns. Mutated per test. */
  verdict: Record<string, unknown> = { call_id: "call-1", outcome: "allow", reason: "read-only tool" };
  /** Status the authorize route returns. */
  authorizeStatus = 200;
  /** What `/api/v1/alerts` answers, so an allowed tool has something to return. */
  alerts: unknown = { items: [], total: 0 };

  private server: NodeServer | undefined;
  url = "";

  async start(): Promise<void> {
    this.server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c) => chunks.push(c as Buffer));
      req.on("end", () => {
        const raw = Buffer.concat(chunks).toString("utf8");
        const path = (req.url ?? "").split("?")[0];
        this.calls.push({
          path,
          authorization: req.headers.authorization,
          body: raw ? (JSON.parse(raw) as Record<string, unknown>) : {},
        });
        if (path === "/api/v1/mcp/tool-calls/authorize") {
          res.writeHead(this.authorizeStatus, { "Content-Type": "application/json" });
          res.end(JSON.stringify(this.verdict));
          return;
        }
        if (path.endsWith("/complete")) {
          res.writeHead(204);
          res.end();
          return;
        }
        if (path === "/api/v1/alerts") {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(this.alerts));
          return;
        }
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end("{}");
      });
    });
    await new Promise<void>((resolve) => this.server!.listen(0, "127.0.0.1", resolve));
    const addr = this.server!.address();
    this.url = typeof addr === "object" && addr ? `http://127.0.0.1:${addr.port}` : "";
  }

  async stop(): Promise<void> {
    await stopListener(this.server);
  }

  authorizeCalls(): RecordedCall[] {
    return this.calls.filter((c) => c.path === "/api/v1/mcp/tool-calls/authorize");
  }

  toolCalls(): RecordedCall[] {
    return this.calls.filter((c) => c.path === "/api/v1/alerts");
  }

  completions(): RecordedCall[] {
    return this.calls.filter((c) => c.path.endsWith("/complete"));
  }
}

/** The MCP transport under test, on a real socket. */
class McpHarness {
  private server: NodeServer | undefined;
  url = "";

  async start(apiUrl: string, envApiKey?: string): Promise<void> {
    const cfg = resolveConfig(parseArgs(["serve"]), {
      AISOC_URL: apiUrl,
      ...(envApiKey ? { AISOC_API_KEY: envApiKey } : {}),
    } as NodeJS.ProcessEnv);
    const log = makeLogger({ verbose: false });
    const options = resolveHttpOptions({} as NodeJS.ProcessEnv);
    this.server = createServer((req, res) => {
      void handleMcpRequest(cfg, log, options, req, res);
    });
    await new Promise<void>((resolve) => this.server!.listen(0, "127.0.0.1", resolve));
    const addr = this.server!.address();
    this.url = typeof addr === "object" && addr ? `http://127.0.0.1:${addr.port}` : "";
  }

  async stop(): Promise<void> {
    await stopListener(this.server);
  }
}

/**
 * Close a listener, tolerating one that was never started.
 *
 * The obvious `this.server?.close(() => resolve())` never resolves when the
 * server is undefined: the optional chain short-circuits and the callback is
 * simply not registered, so the promise hangs until the hook times out. It
 * also has to drop keep-alive sockets, because `fetch` holds them open and
 * `close()` waits for them by design.
 */
async function stopListener(server: NodeServer | undefined): Promise<void> {
  if (!server || !server.listening) return;
  server.closeAllConnections?.();
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

/** One JSON-RPC `tools/call` frame, initialised the way the SDK expects. */
async function callTool(
  harness: McpHarness,
  bearer: string | undefined,
  name: string,
  args: Record<string, unknown> = {},
): Promise<{ status: number; body: any }> {
  const res = await fetch(`${harness.url}${MCP_PATH}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      // The SDK's streamable transport requires the client to accept both.
      Accept: "application/json, text/event-stream",
      ...(bearer ? { Authorization: bearer } : {}),
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name, arguments: args },
    }),
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

let api: ApiStub;
let mcp: McpHarness;

beforeEach(async () => {
  api = new ApiStub();
  await api.start();
  mcp = new McpHarness();
});

afterEach(async () => {
  await mcp.stop();
  await api.stop();
});

describe("bearerFrom", () => {
  it("returns undefined rather than a default when there is no header", () => {
    expect(bearerFrom({})).toBeUndefined();
    expect(bearerFrom({ authorization: "" })).toBeUndefined();
    // A scheme that is not Bearer is not a credential this server understands,
    // and treating it as one would send a Basic header to the API verbatim.
    expect(bearerFrom({ authorization: "Basic abc" })).toBeUndefined();
    expect(bearerFrom({ authorization: "Bearer " })).toBeUndefined();
  });

  it("accepts the header case-insensitively, as HTTP requires", () => {
    expect(bearerFrom({ authorization: "bearer aisoc_key" })).toBe("bearer aisoc_key");
  });
});

describe("the HTTP transport", () => {
  it("answers liveness without a credential and says nothing else", async () => {
    await mcp.start(api.url);
    const res = await fetch(`${mcp.url}${HEALTH_PATH}`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.transport).toBe("streamable-http");
    // A liveness probe must not leak where this server points or who it is for.
    expect(JSON.stringify(body)).not.toContain(api.url);
  });

  it("refuses a request with no Authorization header, as JSON-RPC", async () => {
    await mcp.start(api.url);
    const { status, body } = await callTool(mcp, undefined, "aisoc_list_alerts");
    expect(status).toBe(401);
    // An MCP host parses the body before the status, so an HTML error page
    // surfaces as "the server is broken" rather than "you sent no key".
    expect(body.jsonrpc).toBe("2.0");
    expect(body.error.message).toContain("Authorization required");
    expect(api.calls).toHaveLength(0);
  });

  it("does not fall back to the process-wide API key", async () => {
    // The stdio server's own credential is set. Over HTTP it must be inert:
    // answering an uncredentialed caller with the operator's access is a
    // cross-tenant read with no attacker required.
    await mcp.start(api.url, "aisoc_operator_key_that_must_not_be_used");
    const { status } = await callTool(mcp, undefined, "aisoc_list_alerts");
    expect(status).toBe(401);
    expect(api.calls).toHaveLength(0);
  });

  it("forwards the caller's own credential to the authorize route", async () => {
    await mcp.start(api.url, "aisoc_operator_key_that_must_not_be_used");
    await callTool(mcp, "Bearer aisoc_caller_key", "aisoc_list_alerts", { severity: "high" });

    const authorize = api.authorizeCalls();
    expect(authorize).toHaveLength(1);
    expect(authorize[0].authorization).toBe("Bearer aisoc_caller_key");
    expect(authorize[0].body.tool_name).toBe("aisoc_list_alerts");
    // No tenant field exists to be set — the API derives it from the credential.
    expect(Object.keys(authorize[0].body).sort()).toEqual(["arguments", "tool_name"]);
    // And the tool itself ran as the caller, not as the operator.
    expect(api.toolCalls()[0].authorization).toBe("Bearer aisoc_caller_key");
  });

  it("authorizes before it dispatches", async () => {
    await mcp.start(api.url);
    await callTool(mcp, "Bearer aisoc_caller_key", "aisoc_list_alerts");
    const order = api.calls.map((c) => c.path);
    expect(order.indexOf("/api/v1/mcp/tool-calls/authorize")).toBeLessThan(order.indexOf("/api/v1/alerts"));
  });

  it("reports the outcome after the call", async () => {
    await mcp.start(api.url);
    await callTool(mcp, "Bearer aisoc_caller_key", "aisoc_list_alerts");
    // The completion is fire-and-forget, so it can land after the response.
    // Two chained async hops on a loaded runner is exactly the case where the
    // 1s `waitFor` default is too tight, so the budget is raised here and the
    // test's own timeout is raised above it.
    await vi.waitFor(() => expect(api.completions()).toHaveLength(1), { timeout: 4000 });
    expect(api.completions()[0].body.outcome).toBe("success");
    expect(typeof api.completions()[0].body.latency_ms).toBe("number");
  }, 10_000);

  it("does not run the tool when the API denies it", async () => {
    api.verdict = { call_id: "call-2", outcome: "deny", reason: "The presented credential does not carry alerts:read." };
    await mcp.start(api.url);
    const { body } = await callTool(mcp, "Bearer aisoc_caller_key", "aisoc_list_alerts");

    expect(api.toolCalls()).toHaveLength(0);
    expect(body.result.isError).toBe(true);
    expect(body.result.content[0].text).toContain("does not carry alerts:read");
  });

  it("turns an approval requirement into something the agent can act on", async () => {
    api.verdict = {
      call_id: "call-3",
      outcome: "approval_required",
      reason: "aisoc_run_investigation is not read-only, so a bearer credential is not enough.",
      approval_id: "4f1d0d1e-0000-0000-0000-000000000001",
    };
    await mcp.start(api.url);
    const { body } = await callTool(mcp, "Bearer aisoc_caller_key", "aisoc_run_investigation", {
      case_id: "11111111-1111-1111-1111-111111111111",
    });

    expect(api.toolCalls()).toHaveLength(0);
    expect(body.result.isError).toBe(true);
    expect(body.result.content[0].text).toContain("Ask an approver to decide it");
  });

  it("fails closed when the API cannot answer", async () => {
    // A 500 from the authority is not permission. The opposite posture —
    // running the tool because the gate was down — is the one defect this
    // whole item exists to prevent.
    api.authorizeStatus = 500;
    api.verdict = {};
    await mcp.start(api.url);
    const { body } = await callTool(mcp, "Bearer aisoc_caller_key", "aisoc_list_alerts");
    expect(api.toolCalls()).toHaveLength(0);
    expect(body.result.isError).toBe(true);
    expect(body.result.content[0].text).toContain("could not authorize");
  });

  it("refuses an outcome it does not recognise rather than reading it as allow", async () => {
    api.verdict = { call_id: "call-4", outcome: "allow_with_caveats", reason: "from a newer API" };
    await mcp.start(api.url);
    const { body } = await callTool(mcp, "Bearer aisoc_caller_key", "aisoc_list_alerts");
    expect(api.toolCalls()).toHaveLength(0);
    expect(body.result.content[0].text).toContain("unrecognised outcome");
  });

  it("refuses an oversized body with the bound, not with the thrown message", async () => {
    await mcp.start(api.url);
    const res = await fetch(`${mcp.url}${MCP_PATH}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
        Authorization: "Bearer aisoc_caller_key",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", pad: "x".repeat(2_000_000) }),
    });
    expect(res.status).toBe(413);
    const body = await res.json();
    // The bound is the actionable fact. A parse failure's message quotes
    // the offending input back at the sender, which is useless to them and
    // is an information-exposure finding.
    expect(body.error.message).toContain("at most 1048576 bytes");
    expect(body.error.message).not.toContain("JSON.parse");
  });

  it("serves the MCP endpoint only at /mcp", async () => {
    await mcp.start(api.url);
    const res = await fetch(`${mcp.url}/`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer aisoc_caller_key" },
      body: "{}",
    });
    expect(res.status).toBe(404);
    expect((await res.json()).error.message).toContain(MCP_PATH);
  });
});

describe("safeUserAgent", () => {
  it("passes the shape this package produces", () => {
    expect(safeUserAgent("aisoc-mcp/0.1.0 (+https://github.com/beenuar/AiSOC)")).toBe(
      "aisoc-mcp/0.1.0 (+https://github.com/beenuar/AiSOC)",
    );
    expect(safeUserAgent("aisoc-mcp/0.1.0")).toBe("aisoc-mcp/0.1.0");
  });

  it("replaces anything else rather than escaping it", () => {
    // The value is built from a version read off disk. An escaped header
    // that reaches the server and means nothing is worse than a known one.
    expect(safeUserAgent("aisoc-mcp/0.1.0\r\nX-Injected: 1")).toBe("aisoc-mcp");
    expect(safeUserAgent("curl/8")).toBe("aisoc-mcp");
    expect(safeUserAgent("")).toBe("aisoc-mcp");
  });
});

describe("resolveHttpOptions", () => {
  it("binds loopback by default", () => {
    expect(resolveHttpOptions({} as NodeJS.ProcessEnv).host).toBe("127.0.0.1");
  });

  it("refuses a port that is not a port", () => {
    expect(() => resolveHttpOptions({ AISOC_MCP_HTTP_PORT: "not-a-port" } as NodeJS.ProcessEnv)).toThrow();
    expect(() => resolveHttpOptions({ AISOC_MCP_HTTP_PORT: "70000" } as NodeJS.ProcessEnv)).toThrow();
  });

  it("bounds the request body", () => {
    expect(resolveHttpOptions({} as NodeJS.ProcessEnv).maxBodyBytes).toBe(1_048_576);
  });
});
