import { describe, expect, it } from "vitest";
import { scoreAlert, recommendationFor, _internals } from "./stages.js";
import type { Alert } from "./types.js";

const base: Alert = { id: "A1", title: "t", source: "test", severity: "info" };

describe("scoreAlert — parity with services/agents score_triage", () => {
  it("clamps to [0.05, 0.95]", () => {
    expect(_internals.CONF_FLOOR).toBe(0.05);
    expect(_internals.CONF_CEIL).toBe(0.95);
    const empty = scoreAlert(base);
    expect(empty.confidence).toBeGreaterThanOrEqual(0.05);
    const maxed = scoreAlert({
      ...base,
      riskScore: 1,
      raw: "ransomware credential dump exfiltration",
      techniques: ["T1", "T2", "T3", "T4"],
      hostname: "h",
      iocs: { srcIp: "1.1.1.1", dstIp: "2.2.2.2", domain: "d", fileHash: "f", url: "u" },
    });
    expect(maxed.confidence).toBeLessThanOrEqual(0.95);
  });

  it("uses the exact band boundaries", () => {
    expect(_internals.verdictBand(0.8)).toBe("true_positive");
    expect(_internals.verdictBand(0.79)).toBe("likely_true_positive");
    expect(_internals.verdictBand(0.6)).toBe("likely_true_positive");
    expect(_internals.verdictBand(0.59)).toBe("needs_review");
    expect(_internals.verdictBand(0.4)).toBe("needs_review");
    expect(_internals.verdictBand(0.39)).toBe("likely_benign");
  });

  it("critical keyword + risk + IOCs + MITRE → true_positive escalate", () => {
    const v = scoreAlert({
      ...base,
      severity: "critical",
      riskScore: 0.9,
      raw: "ransomware note dropped, shadow copies deleted",
      techniques: ["T1486", "T1490"],
      hostname: "WIN-DB01",
      iocs: { srcIp: "10.0.0.5", fileHash: "abc" },
    });
    expect(v.verdict).toBe("true_positive");
    expect(v.recommendation).toBe("escalate");
    expect(v.evidence.length).toBeGreaterThan(0);
  });

  it("no salient signal → likely_benign suppress", () => {
    const v = scoreAlert({ ...base, title: "Scheduled backup completed", raw: "nominal" });
    expect(v.verdict).toBe("likely_benign");
    expect(v.recommendation).toBe("suppress");
  });

  it("weight stack matches the Python contribution caps", () => {
    // risk 0.5 → 0.30 ; high keyword → 0.20 ; 1 IOC → 0.05 → 0.55 → likely_TP
    const v = scoreAlert({ ...base, riskScore: 0.5, raw: "phishing email", iocs: { srcIp: "1.2.3.4" } });
    expect(v.confidence).toBeCloseTo(0.55, 5);
    expect(v.verdict).toBe("needs_review");
  });

  it("recommendationFor covers every verdict", () => {
    expect(recommendationFor("true_positive")).toBe("escalate");
    expect(recommendationFor("likely_true_positive")).toBe("escalate");
    expect(recommendationFor("needs_review")).toBe("review");
    expect(recommendationFor("likely_benign")).toBe("suppress");
  });
});
