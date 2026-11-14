/**
 * `--share` report-card renderer: turns a triage run into a redacted,
 * postable artifact (Markdown + a self-contained SVG card).
 *
 * Privacy: the card contains only aggregate counts and verdict-band metadata —
 * never alert titles, IOCs, hostnames, or usernames. Nothing here can leak
 * environment specifics, so it's safe to post without a redaction review.
 *
 * Rendering is delegated to the shared `@aisoc/report-card` package (the same
 * renderer the noise-tuning dashboard and the web OG routes use), bundled into
 * the CLI at build time so `npx aisoc` stays a single self-contained artifact.
 */

import { writeFile } from "node:fs/promises";
import { renderCardMarkdown, renderCardSvg, type ReportCardData } from "@aisoc/report-card";
import type { TriageResult } from "./verdict/types.js";

export interface ShareArtifacts {
  markdown: string;
  svg: string;
}

function toCardData(result: TriageResult): ReportCardData {
  const s = result.summary;
  return {
    kind: "triage",
    total: s.total,
    escalate: s.truePositive,
    review: s.needsReview,
    suppress: s.suppressed,
    noisePercent: s.noisePercent,
    elapsedSeconds: s.elapsedMs / 1000,
    deterministic: result.deterministic,
  };
}

export function renderMarkdownCard(result: TriageResult): string {
  return renderCardMarkdown(toCardData(result));
}

/** A 1200×630 share card (X/LinkedIn/Slack unfurl aspect ratio) as standalone SVG. */
export function renderSvgCard(result: TriageResult): string {
  return renderCardSvg(toCardData(result));
}

export function renderShareArtifacts(result: TriageResult): ShareArtifacts {
  return { markdown: renderMarkdownCard(result), svg: renderSvgCard(result) };
}

/** Write the share artifacts to disk, returning the paths written. */
export async function writeShareArtifacts(result: TriageResult, basePath: string): Promise<string[]> {
  const { markdown, svg } = renderShareArtifacts(result);
  const mdPath = basePath.endsWith(".md") ? basePath : `${basePath}.md`;
  const svgPath = mdPath.replace(/\.md$/, ".svg");
  await Promise.all([writeFile(mdPath, markdown, "utf8"), writeFile(svgPath, svg, "utf8")]);
  return [mdPath, svgPath];
}
