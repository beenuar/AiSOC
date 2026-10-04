/**
 * The published tool count must be the count this server publishes.
 *
 * Gap-closure Phase 5.6.
 *
 * "13 tools" was written into six documents across the repository and
 * nothing compared any of them to `ALL_TOOLS`. That is this repository's
 * most familiar drift shape: a figure copied into prose goes stale
 * silently, and the reader who trusts it is the one doing an evaluation.
 *
 * The claim matrix carried a row saying the count was gated by `ci.yml ::
 * mcp`, and it was not: that job runs the registry tests, which pin the
 * *set* of tool names, and nothing there had ever read a document.
 *
 * Both directions:
 *
 *   document -> registry   a figure that disagrees with `ALL_TOOLS` fails
 *   registry -> document   a document that has stopped carrying a figure
 *                          fails as a stale entry, rather than passing
 *                          because nothing matched
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { ALL_TOOLS } from "../src/tools/index.js";

const REPO_ROOT = fileURLToPath(new URL("../../..", import.meta.url));

/** Each document, and the phrase that carries its figure. */
const PUBLISHED: Array<{ path: string; pattern: RegExp }> = [
  { path: "services/mcp/README.md", pattern: /advertises \*\*(\d+) tools\*\*/ },
  { path: "apps/docs/docs/integrations/mcp.md", pattern: /advertises \*\*(\d+) tools\*\*/ },
  { path: "apps/docs/docs/intro.md", pattern: /`@aisoc\/mcp` exposes (\d+) tools/ },
  { path: "docs/architecture/SYSTEM_DESIGN.md", pattern: /stdio server, (\d+) tools/ },
  { path: "docs/audit/REALITY_REPORT.md", pattern: /MCP server exposes (\d+) tools/ },
  { path: "docs/audit/CLAIM_TO_GATE_MATRIX.md", pattern: /MCP server exposes (\d+) tools/ },
  { path: "docs/design/landing-page-brief.md", pattern: /MCP server \((\d+) tools\)/ },
];

describe("the published tool count", () => {
  it("matches the registry in every document that publishes it", () => {
    const actual = ALL_TOOLS.length;
    // A floor, so a broken import that yields an empty registry cannot make
    // every document agree with zero.
    expect(actual).toBeGreaterThan(10);

    const mismatches: string[] = [];
    for (const { path, pattern } of PUBLISHED) {
      const body = readFileSync(new URL(path, `file://${REPO_ROOT}`), "utf8");
      // EVERY occurrence, not the first. `exec` without the global flag stops
      // at the first match, and the claim matrix carried two rows for this
      // claim -- one saying 19 and a stale one saying 14 -- so the correct row
      // shadowed the wrong one and this gate reported OK over a false claim in
      // the governance file itself.
      const flags = pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`;
      const found = [...body.matchAll(new RegExp(pattern.source, flags))];
      if (found.length === 0) {
        // registry -> document. Deleting the claim is a finding, not a pass.
        mismatches.push(`${path}: no published tool count found (pattern ${pattern})`);
        continue;
      }
      // document -> registry, for every occurrence.
      for (const match of found) {
        if (Number(match[1]) !== actual) {
          mismatches.push(`${path}: publishes ${match[1]}, the registry holds ${actual}`);
        }
      }
    }
    expect(mismatches).toEqual([]);
  });
});
