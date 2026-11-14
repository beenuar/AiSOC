import { describe, expect, it } from "vitest";
import { renderCardSvg, renderCardMarkdown, coverageGrade, esc, type ReportCardData } from "./index.js";

describe("report-card renderers", () => {
  const triage: ReportCardData = {
    kind: "triage",
    total: 200,
    escalate: 12,
    review: 17,
    suppress: 171,
    noisePercent: 85.5,
    elapsedSeconds: 0.1,
    deterministic: true,
  };

  it("triage SVG is a valid 1200x630 card with the headline numbers", () => {
    const svg = renderCardSvg(triage);
    expect(svg).toContain("<svg");
    expect(svg).toContain('width="1200"');
    expect(svg).toContain('height="630"');
    expect(svg).toContain("85.5%");
    expect(svg).toContain(">200<");
  });

  it("coverage grade thresholds", () => {
    expect(coverageGrade(95)).toBe("A");
    expect(coverageGrade(80)).toBe("B");
    expect(coverageGrade(65)).toBe("C");
    expect(coverageGrade(45)).toBe("D");
    expect(coverageGrade(20)).toBe("F");
  });

  it("coverage SVG shows the grade + percent", () => {
    const svg = renderCardSvg({ kind: "coverage", grade: "B", covered: 80, total: 100, percent: 80 });
    expect(svg).toContain(">B<");
    expect(svg).toContain("80%");
  });

  it("replay card escapes and renders verdict + techniques", () => {
    const svg = renderCardSvg({
      kind: "replay",
      caseTitle: "Ransomware on HOST_1",
      verdict: "true_positive",
      techniques: ["T1486", "T1490"],
      elapsedSeconds: 94,
      stepCount: 14,
      toolCalls: 6,
    });
    expect(svg).toContain("TRUE POSITIVE");
    expect(svg).toContain("T1486");
  });

  it("markdown mirrors the card and is postable", () => {
    expect(renderCardMarkdown(triage)).toContain("npx aisoc triage --demo");
  });

  it("esc neutralizes angle brackets and ampersands", () => {
    expect(esc("<b>&")).toBe("&lt;b&gt;&amp;");
  });
});
