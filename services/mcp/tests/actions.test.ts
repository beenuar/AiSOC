/**
 * The action boundary: preview, never perform.
 *
 * Gap-closure Phase 5.6.
 *
 * One tool in this server touches the response surface. An MCP tool that
 * could reach `/dispatch` would let any agent holding a read-scoped key
 * isolate a host, and the distance between "preview" and "perform" is one
 * careless string in a path.
 *
 * So the boundary is asserted three ways, and the first is the one that
 * survives a refactor: the source is read, and `/dispatch` must appear
 * nowhere under `src/`. A test that only drove the handler would keep
 * passing if somebody added a second tool beside it.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { ACTION_CATALOGUE_PATH, DRY_RUN_PATH, previewActionTool } from "../src/tools/actions.js";
import { ALL_TOOLS } from "../src/tools/index.js";

const SRC = fileURLToPath(new URL("../src", import.meta.url));

function everySourceFile(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...everySourceFile(path));
    else if (entry.name.endsWith(".ts")) out.push(path);
  }
  return out;
}

interface RecordedCall {
  method: "get" | "post";
  path: string;
  body?: unknown;
  query?: Record<string, unknown>;
}

function recordingClient(calls: RecordedCall[], reply: unknown = { ok: true }) {
  return {
    async get(path: string, opts?: { query?: Record<string, unknown> }) {
      calls.push({ method: "get", path, query: opts?.query });
      return reply;
    },
    async post(path: string, body: unknown) {
      calls.push({ method: "post", path, body });
      return reply;
    },
  };
}

const log = { debug() {}, info() {}, warn() {}, error() {} };

describe("the action boundary", () => {
  it("names no dispatch path anywhere in the source", () => {
    // The structural assertion. Reading the source rather than the handler
    // means a second action tool added later is caught too.
    const offenders: string[] = [];
    for (const file of everySourceFile(SRC)) {
      const body = readFileSync(file, "utf8");
      // The word appears in prose explaining why it is absent, so match the
      // path segment an HTTP call would actually carry.
      if (/["'`][^"'`]*\/live-actions\/dispatch/.test(body)) {
        offenders.push(file);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("requests only the dry-run path", async () => {
    const calls: RecordedCall[] = [];
    await previewActionTool.handle(
      { client: recordingClient(calls) as never, log: log as never },
      { capability: "isolate_host", parameters: { hostname: "WIN-DC-01" } },
    );
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("post");
    expect(calls[0].path).toBe(DRY_RUN_PATH);
    expect(DRY_RUN_PATH.endsWith("/dry-run")).toBe(true);
  });

  it("sends dry_run true as well as relying on the route to force it", async () => {
    const calls: RecordedCall[] = [];
    await previewActionTool.handle(
      { client: recordingClient(calls) as never, log: log as never },
      { capability: "isolate_host", parameters: { hostname: "WIN-DC-01" } },
    );
    expect((calls[0].body as Record<string, unknown>).dry_run).toBe(true);
  });

  it("cannot be talked into a live run through its own arguments", () => {
    // The schema is strict, so an argument the tool does not declare is a
    // validation error rather than a field forwarded to the API.
    const parsed = previewActionTool.schema.safeParse({
      capability: "isolate_host",
      parameters: {},
      dry_run: false,
      execute: true,
    });
    expect(parsed.success).toBe(false);
  });

  it("reports that nothing was performed", async () => {
    const calls: RecordedCall[] = [];
    const result = await previewActionTool.handle(
      { client: recordingClient(calls) as never, log: log as never },
      { capability: "isolate_host", parameters: { hostname: "WIN-DC-01" } },
    );
    expect(result.kind).toBe("json");
    const data = (result as { kind: "json"; data: Record<string, unknown> }).data;
    expect(data.executed).toBe(false);
    expect(String(data.note)).toContain("Nothing was performed");
  });

  it("lists actions without performing one", async () => {
    const calls: RecordedCall[] = [];
    const { listActionsTool } = await import("../src/tools/actions.js");
    await listActionsTool.handle({ client: recordingClient(calls) as never, log: log as never }, {});
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("get");
    expect(calls[0].path).toBe(ACTION_CATALOGUE_PATH);
  });
});

describe("tool annotations", () => {
  it("declares annotations on every tool", () => {
    // A client that takes annotations seriously cannot tell "read-only"
    // from "nobody said", and the safe reading of silence is "not
    // read-only". An omission here makes a read tool look state-changing
    // to every such client, including AiSOC's own.
    for (const tool of ALL_TOOLS) {
      expect(tool.metadata.annotations, tool.metadata.name).toBeDefined();
      expect(typeof tool.metadata.annotations.readOnlyHint, tool.metadata.name).toBe("boolean");
    }
  });

  it("marks no tool destructive, because none is", () => {
    for (const tool of ALL_TOOLS) {
      expect(tool.metadata.annotations.destructiveHint, tool.metadata.name).toBe(false);
    }
  });

  it("marks the one tool that writes as not read-only", () => {
    // `aisoc_run_investigation` starts an agent run: it writes ledger rows,
    // spends model budget and can reach whatever the tenant configured.
    // Annotating it read-only would be a lie a client cannot detect, which
    // is the direction that costs something.
    const writers = ALL_TOOLS.filter((t) => t.metadata.annotations.readOnlyHint === false).map(
      (t) => t.metadata.name,
    );
    expect(writers).toEqual(["aisoc_run_investigation"]);
  });

  it("marks the action preview read-only, since it performs nothing", () => {
    expect(previewActionTool.metadata.annotations.readOnlyHint).toBe(true);
  });
});
