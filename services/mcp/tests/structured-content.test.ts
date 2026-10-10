/**
 * structuredContent must be a JSON object (MCP spec), and the SDK client
 * enforces it. toSuccessResult guarded with `typeof data === "object"`, which
 * is also true for arrays, so a tool returning a list (aisoc_list_investigations,
 * a bare array from GET /api/v1/investigations) produced a result every host
 * rejected: "MCP error -32602: Invalid tools/call result ... expected record".
 *
 * Driven end to end: the real server, an SDK client over an in-memory
 * transport, and a stubbed fetch standing in for the AiSOC API.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

import type { Logger } from "../src/config.js";
import { buildServer } from "../src/server.js";

const SILENT: Logger = { info: () => undefined, warn: () => undefined, error: () => undefined };

const RUNS = [
  { id: "27a7a8c0-843e-5170-8310-96114b716ff3", status: "completed", model_used: "kafka:auto_triage:llm", iterations: 2, total_tokens: 0 },
];

async function connect(body: unknown) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } })),
  );
  const server = buildServer(
    { aisocUrl: "http://aisoc.test", apiKey: "aisoc_test", timeoutMs: 5000, verbose: false, userAgent: "test" },
    SILENT,
  );
  const [a, b] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test", version: "1" });
  await Promise.all([server.connect(a), client.connect(b)]);
  return client;
}

afterEach(() => vi.unstubAllGlobals());

describe("tool results returning a JSON array", () => {
  it("aisoc_list_investigations returns a result the SDK client accepts", async () => {
    const client = await connect(RUNS);
    const res = await client.callTool({ name: "aisoc_list_investigations", arguments: {} });
    expect(res.isError).toBeFalsy();
    const text = (res.content as { type: string; text: string }[])[0].text;
    expect(text).toContain(RUNS[0].id);
  });

  it("never sets structuredContent to an array", async () => {
    const client = await connect(RUNS);
    const res = await client.callTool({ name: "aisoc_list_investigations", arguments: {} });
    expect(Array.isArray(res.structuredContent)).toBe(false);
  });
});
