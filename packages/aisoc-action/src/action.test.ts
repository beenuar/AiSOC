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
    const { alerts, notes } = await fetchAlerts(octokit, "o", "r", ["dependabot", "code-scanning", "secret-scanning"]);
    expect(alerts).toHaveLength(2);
    expect(notes.join(" ")).toMatch(/Secret scanning: skipped/);
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
});
