import { describe, expect, it } from "vitest";
import { triageBatch, summarize } from "./engine.js";
import { loadDemoAlerts, DEMO_ALERT_COUNT } from "../fixtures/index.js";

describe("triageBatch — demo fixture distribution", () => {
  it("ships exactly 200 deterministic demo alerts", () => {
    expect(DEMO_ALERT_COUNT).toBe(200);
    expect(loadDemoAlerts()).toHaveLength(200);
  });

  it("produces the README headline distribution (12 TP / 17 review / 171 suppressed)", () => {
    const result = triageBatch(loadDemoAlerts());
    expect(result.summary.total).toBe(200);
    expect(result.summary.truePositive).toBe(12);
    expect(result.summary.needsReview).toBe(17);
    expect(result.summary.suppressed).toBe(171);
    expect(result.summary.noisePercent).toBe(85.5);
  });

  it("is deterministic — identical input yields identical verdicts", () => {
    const a = triageBatch(loadDemoAlerts());
    const b = triageBatch(loadDemoAlerts());
    expect(a.verdicts.map((v) => [v.alertId, v.verdict, v.confidence])).toEqual(
      b.verdicts.map((v) => [v.alertId, v.verdict, v.confidence]),
    );
  });

  it("sorts escalations first", () => {
    const result = triageBatch(loadDemoAlerts());
    const firstBenignIdx = result.verdicts.findIndex((v) => v.verdict === "likely_benign");
    const lastEscalateIdx = result.verdicts.map((v) => v.verdict).lastIndexOf("likely_true_positive");
    expect(firstBenignIdx).toBeGreaterThan(lastEscalateIdx);
  });

  it("headline string matches the documented format", () => {
    const s = summarize(triageBatch(loadDemoAlerts()).verdicts, 4200);
    expect(s.headline).toBe("AiSOC triaged 200 alerts: 12 TP, 171 FP suppressed (85.5% noise), 17 need review — in 4.2s");
  });
});
