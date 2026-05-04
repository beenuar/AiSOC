/**
 * Tool registry contract tests.
 *
 * The registry is what the MCP server hands to ListToolsResult and uses
 * for dispatch. It's the surface that AI agents see, so we lock down:
 *
 *   - Names are unique and conventional (`aisoc_<verb>_<resource>`).
 *   - Every tool's input schema is real JSON Schema (object + properties).
 *   - Every tool we expect to ship in v0.1 is present.
 *   - TOOL_BY_NAME is consistent with ALL_TOOLS.
 *
 * Schema correctness for individual tools is enforced by zod at runtime;
 * here we just check the shape the server advertises.
 */
import { describe, expect, it } from "vitest";

import { ALL_TOOLS, TOOL_BY_NAME } from "../src/tools/index.js";

const EXPECTED_TOOLS = [
  "aisoc_list_alerts",
  "aisoc_get_alert",
  "aisoc_list_cases",
  "aisoc_get_case",
  "aisoc_run_investigation",
  "aisoc_query_detections",
  "aisoc_get_detection_rule",
  "aisoc_list_investigations",
  "aisoc_get_investigation",
  "aisoc_replay_decision",
  "aisoc_explain_step",
] as const;

describe("tool registry", () => {
  it("ships exactly the v0.1 tool surface", () => {
    const names = ALL_TOOLS.map((t) => t.metadata.name).sort();
    expect(names).toEqual([...EXPECTED_TOOLS].sort());
  });

  it("uses the aisoc_ prefix on every tool name", () => {
    for (const tool of ALL_TOOLS) {
      expect(tool.metadata.name).toMatch(/^aisoc_[a-z]+(_[a-z]+)+$/);
    }
  });

  it("has unique tool names", () => {
    const names = ALL_TOOLS.map((t) => t.metadata.name);
    expect(new Set(names).size).toBe(names.length);
  });

  it("has a non-trivial description per tool", () => {
    for (const tool of ALL_TOOLS) {
      const len = tool.metadata.description.length;
      // 20 char floor: rules out empty strings or "TODO".
      // 280 char ceiling: descriptions show in tool pickers (Claude
      // Desktop, Cursor); paragraph dumps make the picker unusable.
      // Our two longest descriptions (replay_decision/explain_step)
      // sit at ~220 because they're the novel "ledger" tools that
      // need extra context — the cap leaves headroom for that without
      // letting future tools regress to README-length copy.
      expect(len, `${tool.metadata.name} description`).toBeGreaterThan(20);
      expect(len, `${tool.metadata.name} description`).toBeLessThan(280);
    }
  });

  it("exposes a JSON Schema object for every tool", () => {
    for (const tool of ALL_TOOLS) {
      const schema = tool.metadata.inputSchema;
      expect(schema, `${tool.metadata.name} schema`).toBeDefined();
      expect(schema.type).toBe("object");
      // Even tools that take no args should declare `properties: {}` so
      // the host UI can render a (possibly empty) form without a crash.
      expect(schema).toHaveProperty("properties");
    }
  });

  it("attaches a real zod schema for runtime validation", () => {
    for (const tool of ALL_TOOLS) {
      expect(tool.schema).toBeDefined();
      // zod's parse method is the contract the server relies on.
      expect(typeof tool.schema.parse).toBe("function");
      expect(typeof tool.schema.safeParse).toBe("function");
    }
  });

  it("provides a handler for every tool", () => {
    for (const tool of ALL_TOOLS) {
      expect(typeof tool.handle).toBe("function");
    }
  });

  it("places discovery tools before deep-dive tools in the listing", () => {
    // We rely on listing order so an agent skimming `tools/list`
    // top-to-bottom learns the right verbs first. If somebody re-orders
    // ALL_TOOLS without thinking, this test fails loudly.
    const names = ALL_TOOLS.map((t) => t.metadata.name);
    const indexOf = (n: string) => names.indexOf(n);
    expect(indexOf("aisoc_list_alerts")).toBeLessThan(indexOf("aisoc_get_alert"));
    expect(indexOf("aisoc_list_cases")).toBeLessThan(indexOf("aisoc_get_case"));
    expect(indexOf("aisoc_query_detections")).toBeLessThan(
      indexOf("aisoc_get_detection_rule"),
    );
    expect(indexOf("aisoc_list_investigations")).toBeLessThan(
      indexOf("aisoc_get_investigation"),
    );
  });

  it("places action/replay tools last", () => {
    const names = ALL_TOOLS.map((t) => t.metadata.name);
    const last3 = names.slice(-3);
    expect(last3).toEqual([
      "aisoc_run_investigation",
      "aisoc_replay_decision",
      "aisoc_explain_step",
    ]);
  });
});

describe("TOOL_BY_NAME", () => {
  it("indexes every tool", () => {
    expect(Object.keys(TOOL_BY_NAME).sort()).toEqual(
      ALL_TOOLS.map((t) => t.metadata.name).sort(),
    );
  });

  it("returns the same definition object as ALL_TOOLS", () => {
    for (const tool of ALL_TOOLS) {
      expect(TOOL_BY_NAME[tool.metadata.name]).toBe(tool);
    }
  });

  it("returns undefined for unknown names", () => {
    expect(TOOL_BY_NAME["aisoc_nonexistent"]).toBeUndefined();
  });
});
