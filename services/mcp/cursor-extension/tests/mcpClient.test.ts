/**
 * Smoke tests for `McpClient` URL + payload construction.
 *
 * We deliberately don't import any `vscode` symbols here — `mcpClient.ts`
 * has zero runtime coupling to the editor API so the same client logic
 * stays unit-testable in plain Node.
 */
import { describe, expect, it } from "vitest";

import { McpClient, McpClientError } from "../src/mcpClient";

interface CapturedCall {
  url: string;
  headers: Record<string, string>;
  method: string;
  body: Record<string, unknown>;
}

interface FetchStubOptions {
  status?: number;
  json?: unknown;
  bodyText?: string;
}

function makeFetchStub(
  capture: CapturedCall[],
  options: FetchStubOptions = {},
): typeof fetch {
  const status = options.status ?? 200;
  const responseJson = options.json ?? {
    jsonrpc: "2.0",
    id: "stub",
    result: { content: [{ type: "text", text: "ok" }] },
  };
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : (input as URL).toString();
    const bodyStr = typeof init?.body === "string" ? init.body : "";
    const body = bodyStr ? (JSON.parse(bodyStr) as Record<string, unknown>) : {};
    const headers = (init?.headers ?? {}) as Record<string, string>;
    capture.push({ url, headers, method: init?.method ?? "GET", body });
    return {
      ok: status >= 200 && status < 300,
      status,
      async json() {
        return responseJson;
      },
      async text() {
        return options.bodyText ?? JSON.stringify(responseJson);
      },
    } as unknown as Response;
  }) as unknown as typeof fetch;
}

function makeClient(opts: {
  endpoint?: string;
  apiKey?: string;
  capture: CapturedCall[];
  fetchOptions?: FetchStubOptions;
  idGenerator?: () => string;
}): McpClient {
  return new McpClient({
    endpoint: opts.endpoint ?? "http://localhost:8765/mcp",
    apiKey: opts.apiKey,
    fetchImpl: makeFetchStub(opts.capture, opts.fetchOptions),
    idGenerator: opts.idGenerator ?? (() => "test-id-1"),
  });
}

describe("McpClient URL construction", () => {
  it("posts to the configured endpoint, normalising trailing slashes", async () => {
    const capture: CapturedCall[] = [];
    const client = makeClient({
      endpoint: "http://localhost:8765/mcp/",
      capture,
    });
    await client.runInvestigation("11111111-1111-1111-1111-111111111111");
    expect(capture).toHaveLength(1);
    expect(capture[0]!.url).toBe("http://localhost:8765/mcp");
    expect(capture[0]!.method).toBe("POST");
  });

  it("respects a fully custom endpoint (https + non-standard port + path)", async () => {
    const capture: CapturedCall[] = [];
    const client = makeClient({
      endpoint: "https://soc.example.com:9443/v1/mcp",
      capture,
    });
    await client.explainStep("22222222-2222-2222-2222-222222222222", 4);
    expect(capture[0]!.url).toBe("https://soc.example.com:9443/v1/mcp");
  });

  it("rejects non-http(s) endpoints up front", () => {
    expect(
      () =>
        new McpClient({
          endpoint: "file:///tmp/mcp",
          fetchImpl: makeFetchStub([]),
        }),
    ).toThrow(McpClientError);
  });
});

describe("McpClient JSON-RPC payload", () => {
  it("runInvestigation maps to aisoc_run_investigation with case_id", async () => {
    const capture: CapturedCall[] = [];
    const client = makeClient({ capture });
    await client.runInvestigation(
      "33333333-3333-3333-3333-333333333333",
      "phishing follow-up",
    );
    const body = capture[0]!.body;
    expect(body).toMatchObject({
      jsonrpc: "2.0",
      method: "tools/call",
      params: {
        name: "aisoc_run_investigation",
        arguments: {
          case_id: "33333333-3333-3333-3333-333333333333",
          alert_summary: "phishing follow-up",
        },
      },
    });
  });

  it("runInvestigation omits alert_summary when not provided", async () => {
    const capture: CapturedCall[] = [];
    const client = makeClient({ capture });
    await client.runInvestigation("44444444-4444-4444-4444-444444444444");
    const args = ((capture[0]!.body as Record<string, unknown>).params as {
      arguments: Record<string, unknown>;
    }).arguments;
    expect(args).toEqual({ case_id: "44444444-4444-4444-4444-444444444444" });
  });

  it("replayDecision maps to aisoc_replay_decision and forwards since_seq + limit", async () => {
    const capture: CapturedCall[] = [];
    const client = makeClient({ capture });
    await client.replayDecision(
      "55555555-5555-5555-5555-555555555555",
      12,
      100,
    );
    expect(capture[0]!.body).toMatchObject({
      method: "tools/call",
      params: {
        name: "aisoc_replay_decision",
        arguments: {
          run_id: "55555555-5555-5555-5555-555555555555",
          since_seq: 12,
          limit: 100,
        },
      },
    });
  });

  it("replayDecision drops optional args when undefined", async () => {
    const capture: CapturedCall[] = [];
    const client = makeClient({ capture });
    await client.replayDecision("66666666-6666-6666-6666-666666666666");
    const args = ((capture[0]!.body as Record<string, unknown>).params as {
      arguments: Record<string, unknown>;
    }).arguments;
    expect(args).toEqual({ run_id: "66666666-6666-6666-6666-666666666666" });
  });

  it("explainStep maps to aisoc_explain_step with run_id + step", async () => {
    const capture: CapturedCall[] = [];
    const client = makeClient({ capture });
    await client.explainStep("77777777-7777-7777-7777-777777777777", 9);
    expect(capture[0]!.body).toMatchObject({
      method: "tools/call",
      params: {
        name: "aisoc_explain_step",
        arguments: {
          run_id: "77777777-7777-7777-7777-777777777777",
          step: 9,
        },
      },
    });
  });

  it("queryDetections routes MITRE ids to mitre_technique", async () => {
    const capture: CapturedCall[] = [];
    const client = makeClient({ capture });
    await client.queryDetections("t1059.003");
    const args = ((capture[0]!.body as Record<string, unknown>).params as {
      arguments: Record<string, unknown>;
    }).arguments;
    expect(args).toEqual({ mitre_technique: "T1059.003" });
  });

  it("queryDetections routes free text to query", async () => {
    const capture: CapturedCall[] = [];
    const client = makeClient({ capture });
    await client.queryDetections("aws iam role assumption");
    const args = ((capture[0]!.body as Record<string, unknown>).params as {
      arguments: Record<string, unknown>;
    }).arguments;
    expect(args).toEqual({ query: "aws iam role assumption" });
  });

  it("queryDetections forwards optional filters", async () => {
    const capture: CapturedCall[] = [];
    const client = makeClient({ capture });
    await client.queryDetections("phishing", {
      category: "cloud",
      severity: "high",
      ruleLanguage: "sigma",
      limit: 5,
    });
    const args = ((capture[0]!.body as Record<string, unknown>).params as {
      arguments: Record<string, unknown>;
    }).arguments;
    expect(args).toEqual({
      query: "phishing",
      category: "cloud",
      severity: "high",
      rule_language: "sigma",
      limit: 5,
    });
  });
});

describe("McpClient auth + error handling", () => {
  it("sends Authorization: Bearer when an API key is configured", async () => {
    const capture: CapturedCall[] = [];
    const client = makeClient({ capture, apiKey: "aisoc_pat_test" });
    await client.runInvestigation("88888888-8888-8888-8888-888888888888");
    const headers = capture[0]!.headers;
    expect(headers["Authorization"]).toBe("Bearer aisoc_pat_test");
    expect(headers["Content-Type"]).toBe("application/json");
  });

  it("omits Authorization when no API key is set", async () => {
    const capture: CapturedCall[] = [];
    const client = makeClient({ capture });
    await client.runInvestigation("99999999-9999-9999-9999-999999999999");
    const headers = capture[0]!.headers;
    expect(headers["Authorization"]).toBeUndefined();
  });

  it("throws an http-kind error on non-2xx responses", async () => {
    const client = makeClient({
      capture: [],
      fetchOptions: { status: 503, bodyText: "service unavailable" },
    });
    await expect(
      client.runInvestigation("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
    ).rejects.toMatchObject({ kind: "http", status: 503 });
  });

  it("throws a tool-kind error when the result is isError", async () => {
    const client = makeClient({
      capture: [],
      fetchOptions: {
        json: {
          jsonrpc: "2.0",
          id: "test",
          result: {
            content: [{ type: "text", text: "missing scope: cases:investigate" }],
            isError: true,
          },
        },
      },
    });
    await expect(
      client.runInvestigation("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
    ).rejects.toMatchObject({
      kind: "tool",
      message: expect.stringContaining("missing scope"),
    });
  });

  it("throws a jsonrpc-kind error on a JSON-RPC error envelope", async () => {
    const client = makeClient({
      capture: [],
      fetchOptions: {
        json: {
          jsonrpc: "2.0",
          id: "test",
          error: { code: -32601, message: "Method not found" },
        },
      },
    });
    await expect(
      client.runInvestigation("cccccccc-cccc-cccc-cccc-cccccccccccc"),
    ).rejects.toMatchObject({ kind: "jsonrpc" });
  });

  it("uses the injected id generator for deterministic request ids", async () => {
    const capture: CapturedCall[] = [];
    let counter = 0;
    const client = makeClient({
      capture,
      idGenerator: () => `id-${++counter}`,
    });
    await client.queryDetections("test");
    await client.queryDetections("test");
    expect(capture[0]!.body["id"]).toBe("id-1");
    expect(capture[1]!.body["id"]).toBe("id-2");
  });

  it("times out long-running requests", async () => {
    const slowFetch = (async (_input: unknown, init: RequestInit = {}) => {
      await new Promise<void>((_resolve, reject) => {
        const onAbort = () => {
          const err = new Error("aborted");
          err.name = "AbortError";
          reject(err);
        };
        if (init.signal?.aborted) {
          onAbort();
        } else {
          init.signal?.addEventListener("abort", onAbort);
        }
      });
      throw new Error("unreachable");
    }) as unknown as typeof fetch;
    const client = new McpClient({
      endpoint: "http://localhost:8765/mcp",
      fetchImpl: slowFetch,
      timeoutMs: 5,
    });
    await expect(
      client.runInvestigation("dddddddd-dddd-dddd-dddd-dddddddddddd"),
    ).rejects.toMatchObject({ kind: "transport" });
  });
});

describe("getEndpoint", () => {
  it("returns the normalised endpoint for consumers (status bars, logs)", () => {
    const client = new McpClient({
      endpoint: "http://localhost:8765/mcp/",
      fetchImpl: makeFetchStub([]),
    });
    expect(client.getEndpoint()).toBe("http://localhost:8765/mcp");
  });
});
