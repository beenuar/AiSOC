import { describe, expect, it } from "vitest";
import { renderMarkdownCard, renderSvgCard } from "./share.js";
import { triageBatch } from "./verdict/engine.js";
import { loadDemoAlerts } from "./fixtures/index.js";

describe("share card — postable, redacted artifact", () => {
  const result = triageBatch(loadDemoAlerts());

  it("markdown embeds aggregate counts and the reproduce command", () => {
    const md = renderMarkdownCard(result);
    expect(md).toContain("triaged");
    expect(md).toContain("**200**");
    expect(md).toContain("npx aisoc triage --demo");
  });

  it("never leaks alert content (no IOCs, hostnames, titles)", () => {
    const md = renderMarkdownCard(result);
    const svg = renderSvgCard(result);
    for (const artifact of [md, svg]) {
      expect(artifact).not.toMatch(/ransomware|mimikatz|WIN-FIN-DB01|\b\d{1,3}(\.\d{1,3}){3}\b/);
    }
  });

  it("svg is a valid standalone 1200x630 share card", () => {
    const svg = renderSvgCard(result);
    expect(svg).toContain("<svg");
    expect(svg).toContain('width="1200"');
    expect(svg).toContain('height="630"');
    expect(svg).toContain("85.5%");
  });
});
