import { describe, expect, it } from "vitest";

import { translateRule, encodePermalink, decodePermalink } from "./translate";
import { extractTechniques, gradeCoverage } from "./coverage";
import { projectNoise, DEFAULT_SUPPRESSION_RATE } from "./noise";
import { nlToSigma } from "./nl2sigma";

describe("tools/translate", () => {
  it("field-maps Sigma into SPL/ES|QL", () => {
    const out = translateRule("CommandLine contains x and SourceIp", "sigma", ["spl", "esql"]);
    expect(out.results.find((r) => r.format === "spl")!.rule).toContain("process_path");
    expect(out.results.find((r) => r.format === "esql")!.rule).toContain("source.ip");
  });

  it("permalink round-trips", () => {
    const enc = encodePermalink("sigma", "EventID: 4688");
    const dec = decodePermalink(enc);
    expect(dec).toEqual({ sourceFormat: "sigma", rule: "EventID: 4688" });
  });

  it("rejects a malformed permalink", () => {
    expect(decodePermalink("!!!notbase64!!!")).toBeNull();
  });
});

describe("tools/coverage", () => {
  it("extracts techniques from Sigma tags and bare ids", () => {
    const ids = extractTechniques("tags:\n  - attack.t1059.001\n  - attack.t1486\nnote T1078");
    expect(ids).toContain("T1059.001");
    expect(ids).toContain("T1486");
    expect(ids).toContain("T1078");
  });

  it("grades higher coverage with more techniques", () => {
    const few = gradeCoverage("attack.t1566");
    const many = gradeCoverage("T1566 T1059 T1078 T1486 T1055 T1003 T1021 T1053 T1071 T1105 T1190 T1204 T1562");
    expect(many.percent).toBeGreaterThan(few.percent);
    expect(many.covered).toBeGreaterThan(few.covered);
    expect(["A", "B", "C", "D", "F"]).toContain(many.grade);
  });

  it("surfaces the highest-prevalence uncovered techniques", () => {
    const report = gradeCoverage(""); // nothing covered
    expect(report.covered).toBe(0);
    expect(report.topUncovered.length).toBe(10);
    // Sorted by prevalence desc — phishing (98) should lead.
    expect(report.topUncovered[0]!.id).toBe("T1566");
  });

  it("sub-technique coverage counts the parent and vice versa", () => {
    const report = gradeCoverage("attack.t1059.001");
    expect(report.coveredIds).toContain("T1059");
    expect(report.coveredIds).toContain("T1059.001");
  });
});

describe("tools/noise", () => {
  it("projects suppression + hours saved", () => {
    const p = projectNoise({ alertsPerDay: 1000 });
    // 1000 * 0.9 FP * 0.855 suppression ≈ 769/day
    expect(p.suppressedPerDay).toBe(Math.round(1000 * 0.9 * DEFAULT_SUPPRESSION_RATE));
    expect(p.hoursSavedPerMonth).toBeGreaterThan(0);
    expect(p.costSavedPerMonth).toBeUndefined();
  });

  it("includes cost when an hourly rate is supplied", () => {
    const p = projectNoise({ alertsPerDay: 1000, analystHourlyCost: 75 });
    expect(p.costSavedPerMonth).toBeGreaterThan(0);
  });

  it("clamps nonsense inputs to sane defaults", () => {
    const p = projectNoise({ alertsPerDay: -5, falsePositiveRate: 9 });
    expect(p.alertsPerDay).toBe(0);
    expect(p.suppressedPerDay).toBe(0);
  });
});

describe("tools/nl2sigma", () => {
  it("builds a Sigma rule with process + keyword selections and MITRE tags", () => {
    const out = nlToSigma("Detect powershell.exe running DownloadString or IEX, technique T1059.001");
    expect(out.sigma).toContain("title:");
    expect(out.sigma).toContain("logsource:");
    expect(out.sigma).toContain("powershell.exe");
    expect(out.sigma.toLowerCase()).toContain("downloadstring");
    expect(out.sigma).toContain("attack.t1059.001");
    expect(out.sigma).toContain("condition: selection");
  });

  it("falls back to a REPLACE_ME selection when no artifacts are found", () => {
    const out = nlToSigma("something suspicious happened");
    expect(out.sigma).toContain("REPLACE_ME");
  });

  it("picks an authentication logsource for login-related descriptions", () => {
    const out = nlToSigma("multiple failed logon attempts then a successful sign-in");
    expect(out.sigma).toContain("category: authentication");
  });
});
