import { describe, expect, it } from "vitest";
import { translateRule } from "./translate.js";

describe("translateRule — deterministic field-map", () => {
  it("substitutes Sigma fields into SPL/KQL/ES|QL field names", () => {
    const out = translateRule("CommandLine contains mimikatz and SourceIp", "sigma", ["spl", "esql"]);
    const spl = out.results.find((r) => r.format === "spl")!;
    const esql = out.results.find((r) => r.format === "esql")!;
    expect(spl.rule).toContain("process_path");
    expect(spl.rule).toContain("src_ip");
    expect(spl.rule).toContain("| search");
    expect(esql.rule).toContain("process.command_line");
    expect(esql.rule).toContain("source.ip");
    expect(esql.rule).toContain("FROM logs-*");
  });

  it("returns source unchanged when target equals source", () => {
    const out = translateRule("EventID: 4688", "sigma", ["sigma"]);
    expect(out.results[0]!.rule).toBe("EventID: 4688");
    expect(out.results[0]!.notes).toMatch(/same as source/i);
  });

  it("always emits a no-LLM warning so users verify field names", () => {
    const out = translateRule("EventID 4688", "sigma", ["kql"]);
    expect(out.warnings.join(" ")).toMatch(/field-map|review/i);
  });
});
