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
  // Workstream 7 — tenant lake. ``schema`` is a discovery tool (lives in
  // the discovery cluster of the listing); ``query`` is the heaviest tool
  // we ship and lives in the action cluster.
  "aisoc_lake_schema",
  "aisoc_lake_query",
  // Gap-closure Phase 5.6. Triage verdicts and replay reports are read
  // tools over surfaces that already existed; the two action tools are the
  // only ones that touch the response surface, and the preview is dry-run
  // only (see tests/actions.test.ts).
  "aisoc_get_triage_verdict",
  "aisoc_run_hunt",
  "aisoc_list_replay_reports",
  "aisoc_get_replay_report",
  "aisoc_list_actions",
  "aisoc_preview_action",
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
    // Lake: schema is the typed-introspection cousin and must appear
    // before the heavy SELECT tool, so an agent skimming the listing
    // learns "ask for the schema first" before it sees the SQL hammer.
    expect(indexOf("aisoc_lake_schema")).toBeLessThan(indexOf("aisoc_lake_query"));
  });

  it("places action/replay tools last", () => {
    const names = ALL_TOOLS.map((t) => t.metadata.name);
    // Phase 5.6 added `aisoc_preview_action` to this cluster, so the tail is
    // four rather than three. Asserted as a slice rather than as "contains"
    // because the ordering is the point: an agent reading the listing
    // top-to-bottom should meet discovery before anything that acts.
    expect(names.slice(-4)).toEqual([
      "aisoc_run_investigation",
      "aisoc_preview_action",
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
