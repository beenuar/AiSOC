import { describe, expect, it } from "vitest";
import { triageBatch } from "./_vendor/verdict/index.js";

import { mapDependabot, mapCodeScanning, mapSecretScanning, fetchAlerts, type OctokitLike } from "./sources.js";
import { renderComment, renderDigest, postureGrade, priorityLine, COMMENT_MARKER } from "./render.js";

const DEPENDABOT = {
  number: 7,
  created_at: "2026-01-01T00:00:00Z",
  dependency: { scope: "runtime", package: { name: "lodash" } },
  security_advisory: {
    summary: "Prototype pollution in lodash",
    description: "A prototype pollution vulnerability allows remote exploit",
    severity: "critical",
    identifiers: [{ type: "CVE", value: "CVE-2020-8203" }],
  },
  security_vulnerability: { severity: "critical", package: { name: "lodash" } },
};

const CODE_SCANNING = {
  number: 3,
  created_at: "2026-01-02T00:00:00Z",
  rule: { name: "js/sql-injection", description: "SQL injection", security_severity_level: "high", tags: ["security"] },
  most_recent_instance: { message: { text: "User input flows to a SQL query" } },
};

const SECRET = { number: 1, created_at: "2026-01-03T00:00:00Z", secret_type: "aws_access_key_id", secret_type_display_name: "AWS Access Key ID", validity: "active" };

describe("source mapping", () => {
  it("maps a critical runtime Dependabot alert to a high-risk escalation", () => {
    const alert = mapDependabot(DEPENDABOT);
    expect(alert.severity).toBe("critical");
    expect(alert.riskScore).toBeGreaterThan(0.9);
    expect(alert.raw).toContain("exploitable in the dependency graph");
    const { verdicts } = triageBatch([alert]);
    expect(["true_positive", "likely_true_positive"]).toContain(verdicts[0]!.verdict);
  });

  it("maps CodeQL + secret-scanning alerts", () => {
    expect(mapCodeScanning(CODE_SCANNING).severity).toBe("high");
    expect(mapSecretScanning(SECRET).title).toContain("AWS Access Key ID");
    expect(mapSecretScanning(SECRET).riskScore).toBe(0.85);
  });
});

describe("fetchAlerts", () => {
  it("aggregates all sources and degrades gracefully on 403/404", async () => {
    const octokit: OctokitLike = {
      paginate: async (route: string) => {
        if (route.includes("dependabot")) return [DEPENDABOT];
        if (route.includes("code-scanning")) return [CODE_SCANNING];
        if (route.includes("secret-scanning")) {
          const e: any = new Error("Secret scanning disabled");
          e.status = 404;
          throw e;
        }
        return [];
      },
    };
    const { alerts, notes, scanned, skipped } = await fetchAlerts(octokit, "o", "r", [
      "dependabot",
      "code-scanning",
      "secret-scanning",
    ]);
    expect(alerts).toHaveLength(2);
    expect(notes.join(" ")).toMatch(/Secret scanning: skipped/);
    // A skipped source and a clean source both contribute zero alerts. The
    // caller has to be able to tell them apart without parsing the prose.
    expect(scanned).toEqual(["Dependabot", "Code scanning"]);
    expect(skipped).toEqual(["Secret scanning"]);
  });

  it("reports a source that answered with nothing as read, not skipped", async () => {
    const octokit: OctokitLike = { paginate: async () => [] };
    const { alerts, skipped, scanned } = await fetchAlerts(octokit, "o", "r", ["dependabot", "code-scanning"]);
    expect(alerts).toHaveLength(0);
    expect(skipped).toEqual([]);
    expect(scanned).toEqual(["Dependabot", "Code scanning"]);
  });
});

describe("render", () => {
  const result = triageBatch([mapDependabot(DEPENDABOT), mapCodeScanning(CODE_SCANNING), mapSecretScanning(SECRET)]);

  it("PR comment carries the idempotency marker and priority line", () => {
    const md = renderComment(result, ["Code scanning: skipped (not enabled)."]);
    expect(md).toContain(COMMENT_MARKER);
    expect(md).toContain("of 3");
    expect(md).toContain("github.com/beenuar/AiSOC");
  });

  it("PR comment hotlinks no remote image", () => {
    // The footer promises "no data leaves your CI". A hotlinked badge breaks
    // that promise on every render: the reader's browser fetches it from a
    // third party, which learns who is reading the comment and when. It also
    // pointed at one specific deployment, so a self-hoster's CI advertised
    // somebody else's install.
    const md = renderComment(result, []);
    expect(md).not.toMatch(/!\[[^\]]*\]\(https?:\/\//);
    expect(md).not.toContain("img.shields.io");
  });

  it("posture grade rewards a clean queue and penalizes escalations", () => {
    expect(postureGrade(triageBatch([])).grade).toBe("A");
    expect(postureGrade(result).score).toBeLessThan(100);
  });

  it("digest shows a week-over-week delta", () => {
    const prev = triageBatch([mapSecretScanning(SECRET)]);
    const md = renderDigest(result, prev, []);
    expect(md).toMatch(/vs last week/);
    expect(priorityLine(result)).toContain("exploitable");
  });

  const AT = new Date("2026-09-28T20:06:00Z");

  it("digest dates itself, so a stale one is visible on the issue", () => {
    // Without a stamp the body is byte-identical any week nothing changed, so
    // GitHub's PATCH is a no-op and `updated_at` freezes. Six consecutive
    // weekly runs succeeded while issue #510 appeared five weeks stale, which
    // reads as an abandoned generator rather than a quiet one.
    const md = renderDigest(triageBatch([]), null, [], {
      scanned: ["Dependabot", "Code scanning", "Secret scanning"],
      skipped: [],
      generatedAt: AT,
    });
    expect(md).toContain("**Generated** 2026-09-28 20:06 UTC");

    const later = renderDigest(triageBatch([]), null, [], {
      scanned: ["Dependabot", "Code scanning", "Secret scanning"],
      skipped: [],
      generatedAt: new Date("2026-10-05T20:06:00Z"),
    });
    expect(later).not.toEqual(md);
  });

  it("a fully-read clean queue still publishes the grade", () => {
    const md = renderDigest(triageBatch([]), null, [], {
      scanned: ["Dependabot", "Code scanning", "Secret scanning"],
      skipped: [],
      generatedAt: AT,
    });
    expect(md).toContain("grade A (100/100)");
    expect(md).not.toMatch(/incomplete/i);
    expect(md).not.toContain("not an all-clear");
    expect(md).toContain("Sources read: Dependabot, Code scanning, Secret scanning.");
  });

  it("refuses to headline a grade when a declared source could not be read", () => {
    // The defect this pins: `safe()` turns a 403 into an empty array, an empty
    // queue grades A/100, and the digest published "grade A (100/100) — 0 open
    // findings" with the skip demoted to a blockquote. Zero findings from a
    // source nobody could read is not zero findings.
    const md = renderDigest(triageBatch([]), null, [
      "Dependabot: skipped (token lacks permission or the feature is not enabled).",
      "Secret scanning: skipped (token lacks permission or the feature is not enabled).",
    ], {
      scanned: ["Code scanning"],
      skipped: ["Dependabot", "Secret scanning"],
      generatedAt: AT,
    });
    expect(md).toContain("incomplete (1 of 3 sources readable)");
    expect(md).not.toMatch(/^## .*grade A \(100\/100\)/m);
    expect(md).toContain("not an all-clear");
    expect(md).toContain("Dependabot and Secret scanning could not be read");
    // The grade survives, explicitly scoped to what answered.
    expect(md).toContain("Across the sources that answered (Code scanning), the grade would be **A (100/100)**");
    expect(md).toContain("(from Code scanning)");
  });

  it("names no readable source when every source was skipped", () => {
    const md = renderDigest(triageBatch([]), null, ["Dependabot: skipped (not enabled for this repository)."], {
      scanned: [],
      skipped: ["Dependabot", "Code scanning", "Secret scanning"],
      generatedAt: AT,
    });
    expect(md).toContain("incomplete (0 of 3 sources readable)");
    expect(md).toContain("no readable source");
    expect(md).not.toContain("Sources read:");
  });
});
