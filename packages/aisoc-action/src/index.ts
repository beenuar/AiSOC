/**
 * AiSOC GitHub Action entrypoint.
 *
 * Fetches the repo's Dependabot / CodeQL / secret-scanning alerts, triages them
 * with the deterministic AiSOC verdict engine (no LLM, nothing leaves CI), and
 * emits a job summary, a PR comment, or a weekly posture-digest issue.
 *
 * Dependency-free: uses a hand-rolled Actions runtime + a fetch-based GitHub
 * client (see gh.ts) so the shipped bundle carries no known-vulnerable deps.
 */

import { triageBatch, type Severity } from "./_vendor/verdict/index.js";
import { GitHubClient, getContext, getInput, info, setFailed, setOutput, warning, writeSummary } from "./gh.js";
import { fetchAlerts } from "./sources.js";
import { COMMENT_MARKER, postureGrade, priorityLine, renderComment, renderDigest } from "./render.js";

const SEVERITY_ORDER: Severity[] = ["info", "low", "medium", "high", "critical"];

function atLeast(sev: Severity, floor: Severity): boolean {
  return SEVERITY_ORDER.indexOf(sev) >= SEVERITY_ORDER.indexOf(floor);
}

async function run(): Promise<void> {
  const token = getInput("github-token") || process.env.GITHUB_TOKEN || "";
  const mode = getInput("mode", "job-summary");
  const minSeverity = (getInput("min-severity", "low") || "low") as Severity;
  const failOn = getInput("fail-on", "none") || "none";
  const sources = getInput("sources", "dependabot,code-scanning,secret-scanning")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  if (!token) {
    setFailed("github-token is required (grant security-events:read).");
    return;
  }

  const ctx = getContext();
  const client = new GitHubClient(token);

  info(`AiSOC: triaging security signals for ${ctx.owner}/${ctx.repo} (sources: ${sources.join(", ")})`);
  const { alerts, notes, scanned, skipped } = await fetchAlerts(client, ctx.owner, ctx.repo, sources);
  if (skipped.length) {
    warning(
      `AiSOC: ${skipped.length} of ${sources.length} declared source(s) could not be read (${skipped.join(", ")}). ` +
        `A source that returns nothing because the token cannot read it is not a source that found nothing — ` +
        `the posture grade is scoped to ${scanned.length ? scanned.join(", ") : "no readable source"}.`,
    );
  }

  const filtered = alerts.filter((a) => atLeast(a.severity, minSeverity));
  const result = triageBatch(filtered, { deterministic: true });

  setOutput("total", String(result.summary.total));
  setOutput("escalate", String(result.summary.truePositive));
  setOutput("review", String(result.summary.needsReview));
  setOutput("suppress", String(result.summary.suppressed));
  setOutput("headline", result.summary.headline);
  info(result.summary.headline);

  const { grade, score } = postureGrade(result);
  const summaryMd = [
    "## 🛡️ AiSOC security triage",
    "",
    `> ${result.summary.headline}`,
    "",
    `Posture grade: **${grade}** (${score}/100). ${priorityLine(result)}`,
    ...(notes.length ? ["", "Notes:", ...notes.map((n) => `- ${n}`)] : []),
  ].join("\n");
  writeSummary(summaryMd);

  if (mode === "pr-comment") {
    await upsertPrComment(client, ctx.owner, ctx.repo, ctx.prNumber, renderComment(result, notes));
  } else if (mode === "digest") {
    await upsertDigestIssue(client, ctx.owner, ctx.repo, renderDigest(result, null, notes, { scanned, skipped }));
  }

  if (failOn !== "none") {
    const escalate = result.summary.truePositive;
    const review = result.summary.needsReview;
    const shouldFail = failOn === "true_positive" ? escalate > 0 : failOn === "needs_review" ? escalate + review > 0 : false;
    if (shouldFail) setFailed(`AiSOC: ${escalate} act-now + ${review} review findings meet fail-on=${failOn}.`);
  }
}

async function upsertPrComment(
  client: GitHubClient,
  owner: string,
  repo: string,
  prNumber: number | null,
  body: string,
): Promise<void> {
  if (!prNumber) {
    info("Not a pull_request event; skipping PR comment (job summary written instead).");
    return;
  }
  try {
    const comments = (await client.paginate(`/repos/${owner}/${repo}/issues/${prNumber}/comments`)) as { id: number; body?: string }[];
    const existing = comments.find((c) => c.body?.includes(COMMENT_MARKER));
    if (existing) {
      await client.request("PATCH", `/repos/${owner}/${repo}/issues/comments/${existing.id}`, { body });
    } else {
      await client.request("POST", `/repos/${owner}/${repo}/issues/${prNumber}/comments`, { body });
    }
  } catch (err) {
    warning(`Could not post PR comment (${(err as Error).message}); the job summary still has the results.`);
  }
}

async function upsertDigestIssue(client: GitHubClient, owner: string, repo: string, body: string): Promise<void> {
  const title = "🛡️ AiSOC weekly security posture";
  try {
    const issues = (await client.paginate(`/repos/${owner}/${repo}/issues?state=open&labels=aisoc-digest`)) as { number: number }[];
    if (issues[0]) {
      await client.request("PATCH", `/repos/${owner}/${repo}/issues/${issues[0].number}`, { body });
      // Logged on success, not only on failure. The run log previously ended
      // at the triage headline whether the issue was written or not, so "did
      // the digest publish?" could not be answered from a green run.
      info(`AiSOC: refreshed digest issue #${issues[0].number}.`);
    } else {
      await client.request("POST", `/repos/${owner}/${repo}/issues`, { title, body, labels: ["aisoc-digest"] });
      info("AiSOC: opened a new digest issue.");
    }
  } catch (err) {
    warning(`Could not create/update the digest issue (${(err as Error).message}).`);
  }
}

run().catch((err) => setFailed(err instanceof Error ? err.message : String(err)));
