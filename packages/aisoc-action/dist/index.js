"use strict";

// src/_vendor/verdict/stages.ts
var CONF_FLOOR = 0.05;
var CONF_CEIL = 0.95;
var CRITICAL_KEYWORDS = [
  "ransomware",
  "lateral movement",
  "credential dump",
  "exfiltration",
  "mimikatz",
  "cobalt strike",
  "c2",
  "rootkit",
  "supply chain",
  "zero-day",
  "data breach"
];
var HIGH_KEYWORDS = [
  "phishing",
  "malware",
  "exploit",
  "privilege escalation",
  "brute force",
  "suspicious login",
  "anomaly",
  "backdoor"
];
function clamp(value) {
  return Math.max(CONF_FLOOR, Math.min(CONF_CEIL, value));
}
function alertText(alert) {
  return `${alert.title} ${alert.raw ?? ""} ${JSON.stringify(alert.iocs ?? {})}`.toLowerCase();
}
function hasKeyword(text, keywords) {
  return keywords.some((kw) => text.includes(kw));
}
function verdictBand(confidence) {
  if (confidence >= 0.8) return "true_positive";
  if (confidence >= 0.6) return "likely_true_positive";
  if (confidence >= 0.4) return "needs_review";
  return "likely_benign";
}
function recommendationFor(verdict) {
  switch (verdict) {
    case "true_positive":
    case "likely_true_positive":
      return "escalate";
    case "needs_review":
      return "review";
    case "likely_benign":
      return "suppress";
    default: {
      const _never = verdict;
      return _never;
    }
  }
}
function scoreAlert(alert) {
  const basis = [];
  const evidence = [];
  let weight = 0;
  const risk2 = Number(alert.riskScore ?? 0) || 0;
  if (risk2 > 0) {
    const c = Math.min(risk2 * 0.6, 0.6);
    weight += c;
    basis.push(`vendor risk_score=${risk2.toFixed(2)}`);
    evidence.push({ factor: "vendor_risk", detail: `risk_score=${risk2.toFixed(2)}`, contribution: c });
  }
  const text = alertText(alert);
  if (hasKeyword(text, CRITICAL_KEYWORDS)) {
    weight += 0.35;
    basis.push("critical-severity keyword match in alert text");
    evidence.push({ factor: "critical_keyword", detail: "critical keyword match", contribution: 0.35 });
  } else if (hasKeyword(text, HIGH_KEYWORDS)) {
    weight += 0.2;
    basis.push("high-severity keyword match in alert text");
    evidence.push({ factor: "high_keyword", detail: "high-severity keyword match", contribution: 0.2 });
  }
  const iocs = alert.iocs ?? {};
  const iocHits = [iocs.srcIp, iocs.dstIp, iocs.domain, iocs.fileHash, iocs.url].filter(Boolean).length;
  if (iocHits > 0) {
    const c = Math.min(iocHits * 0.05, 0.15);
    weight += c;
    basis.push(`${iocHits} IOC field(s) present`);
    evidence.push({ factor: "ioc_density", detail: `${iocHits} IOC field(s)`, contribution: c });
  }
  const techniques = alert.techniques ?? [];
  if (techniques.length > 0) {
    const c = Math.min(techniques.length * 0.04, 0.12);
    weight += c;
    basis.push(`${techniques.length} MITRE technique ID(s) attached`);
    evidence.push({ factor: "mitre_coverage", detail: techniques.join(", "), contribution: c });
  }
  if (alert.hostname) {
    weight += 0.05;
    basis.push("hostname present (enables containment)");
    evidence.push({ factor: "containment", detail: `host ${alert.hostname}`, contribution: 0.05 });
  }
  const confidence = clamp(weight);
  const verdict = verdictBand(confidence);
  const recommendation = recommendationFor(verdict);
  if (basis.length === 0) {
    basis.push("no salient signals \u2014 defaulting to floor confidence");
    evidence.push({ factor: "no_signal", detail: "no salient signals", contribution: 0 });
  }
  evidence.sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution));
  return {
    alertId: alert.id,
    title: alert.title,
    source: alert.source,
    severity: alert.severity,
    verdict,
    confidence: Number(confidence.toFixed(4)),
    recommendation,
    basis,
    evidence: evidence.slice(0, 3)
  };
}

// src/_vendor/verdict/engine.ts
function summarize(verdicts, elapsedMs) {
  const total = verdicts.length;
  let truePositive = 0;
  let needsReview = 0;
  let suppressed = 0;
  for (const v of verdicts) {
    if (v.verdict === "true_positive" || v.verdict === "likely_true_positive") {
      truePositive += 1;
    } else if (v.verdict === "needs_review") {
      needsReview += 1;
    } else {
      suppressed += 1;
    }
  }
  const noisePercent = total > 0 ? Number((suppressed / total * 100).toFixed(1)) : 0;
  const seconds = (elapsedMs / 1e3).toFixed(elapsedMs < 1e4 ? 1 : 0);
  const headline = `AiSOC triaged ${total} alert${total === 1 ? "" : "s"}: ${truePositive} TP, ${suppressed} FP suppressed (${noisePercent}% noise), ${needsReview} need review \u2014 in ${seconds}s`;
  return { total, truePositive, needsReview, suppressed, noisePercent, elapsedMs, headline };
}
function triageBatch(alerts, opts = {}) {
  const started = Date.now();
  const verdicts = alerts.map(scoreAlert);
  const order = {
    true_positive: 0,
    likely_true_positive: 1,
    needs_review: 2,
    likely_benign: 3
  };
  verdicts.sort((a, b) => order[a.verdict] - order[b.verdict] || b.confidence - a.confidence);
  const elapsedMs = Date.now() - started;
  return {
    verdicts,
    summary: summarize(verdicts, elapsedMs),
    deterministic: opts.deterministic ?? true
  };
}

// src/gh.ts
var import_node_fs = require("fs");
function getInput(name, fallback = "") {
  const key = `INPUT_${name.replace(/ /g, "_").toUpperCase()}`;
  return (process.env[key] ?? fallback).trim();
}
function setOutput(name, value) {
  const file = process.env.GITHUB_OUTPUT;
  const line = `${name}<<__AISOC_EOF__
${value}
__AISOC_EOF__
`;
  if (file) (0, import_node_fs.appendFileSync)(file, line);
}
function info(msg) {
  process.stdout.write(`${msg}
`);
}
function warning(msg) {
  process.stdout.write(`::warning::${msg}
`);
}
var _failed = false;
function setFailed(msg) {
  _failed = true;
  process.stdout.write(`::error::${msg}
`);
  process.exitCode = 1;
}
function writeSummary(markdown) {
  const file = process.env.GITHUB_STEP_SUMMARY;
  if (file) (0, import_node_fs.appendFileSync)(file, markdown + "\n");
  else info(markdown);
}
function getContext() {
  const [owner = "", repo = ""] = (process.env.GITHUB_REPOSITORY ?? "/").split("/");
  const eventName = process.env.GITHUB_EVENT_NAME ?? "";
  let prNumber = null;
  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (eventPath) {
    try {
      const payload = JSON.parse((0, import_node_fs.readFileSync)(eventPath, "utf8"));
      const raw = payload.pull_request?.number;
      prNumber = typeof raw === "number" && Number.isInteger(raw) && raw > 0 ? raw : null;
    } catch {
      prNumber = null;
    }
  }
  return { owner, repo, eventName, prNumber };
}
var GitHubClient = class {
  constructor(token, base = process.env.GITHUB_API_URL || "https://api.github.com") {
    this.token = token;
    this.base = base;
  }
  token;
  base;
  headers() {
    return {
      authorization: `Bearer ${this.token}`,
      accept: "application/vnd.github+json",
      "x-github-api-version": "2022-11-28",
      "user-agent": "aisoc-action"
    };
  }
  async request(method, path, body) {
    const url = path.startsWith("http") ? path : `${this.base}${path}`;
    return fetch(url, {
      method,
      headers: { ...this.headers(), ...body ? { "content-type": "application/json" } : {} },
      body: body ? JSON.stringify(body) : void 0
    });
  }
  /** GET all pages of a list endpoint, following the Link rel="next" header. */
  async paginate(path) {
    const out = [];
    let next = path.includes("?") ? `${path}&per_page=100` : `${path}?per_page=100`;
    let guard = 0;
    while (next && guard < 50) {
      guard += 1;
      const resp = await this.request("GET", next);
      if (!resp.ok) {
        const err = new Error(`GitHub API ${resp.status} for ${next}`);
        err.status = resp.status;
        throw err;
      }
      const page = await resp.json();
      if (Array.isArray(page)) out.push(...page);
      next = parseNextLink(resp.headers.get("link"));
    }
    return out;
  }
};
function parseNextLink(link) {
  if (!link) return null;
  for (const part of link.split(",")) {
    const m = part.match(/<([^>]+)>;\s*rel="next"/);
    if (m) return m[1] ?? null;
  }
  return null;
}

// src/sources.ts
function sev(value) {
  switch ((value ?? "").toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
    case "error":
      return "high";
    case "medium":
    case "moderate":
    case "warning":
      return "medium";
    case "low":
    case "note":
      return "low";
    default:
      return "info";
  }
}
function risk(severity) {
  return { critical: 0.95, high: 0.8, medium: 0.5, low: 0.25, info: 0.1 }[severity];
}
function mapDependabot(a) {
  const adv = a.security_advisory ?? {};
  const vuln = a.security_vulnerability ?? {};
  const severity = sev(adv.severity ?? vuln.severity);
  const scope = a.dependency?.scope ?? "runtime";
  const pkg = vuln.package?.name ?? a.dependency?.package?.name ?? "dependency";
  const runtime = scope === "runtime";
  const riskScore = Math.min(risk(severity) + (runtime ? 0.05 : -0.15), 0.99);
  const cves = (adv.identifiers ?? []).map((i) => i.value).filter(Boolean);
  return {
    id: `dependabot-${a.number}`,
    title: `${adv.summary ?? "Dependency vulnerability"} (${pkg})`,
    source: "dependabot",
    severity,
    riskScore,
    raw: `${adv.description ?? ""} scope=${scope} ${cves.join(" ")} ${runtime ? "exploitable in the dependency graph" : ""}`.slice(0, 800),
    timestamp: a.created_at
  };
}
function mapCodeScanning(a) {
  const rule = a.rule ?? {};
  const severity = sev(rule.security_severity_level ?? rule.severity);
  return {
    id: `code-scanning-${a.number}`,
    title: rule.description ?? rule.name ?? "Code scanning finding",
    source: "code-scanning",
    severity,
    riskScore: risk(severity),
    raw: `${a.most_recent_instance?.message?.text ?? rule.full_description ?? ""} ${(rule.tags ?? []).join(" ")}`.slice(0, 800),
    timestamp: a.created_at
  };
}
function mapSecretScanning(a) {
  const severity = "high";
  return {
    id: `secret-scanning-${a.number}`,
    title: `Leaked secret: ${a.secret_type_display_name ?? a.secret_type ?? "unknown"}`,
    source: "secret-scanning",
    severity,
    riskScore: 0.85,
    raw: `secret_type=${a.secret_type} validity=${a.validity ?? "unknown"} credential exposure`,
    timestamp: a.created_at
  };
}
async function safe(fetchFn, label, notes) {
  try {
    return await fetchFn();
  } catch (err) {
    const status = err?.status ?? err?.response?.status;
    if (status === 403) notes.push(`${label}: skipped (token lacks permission or the feature is not enabled).`);
    else if (status === 404) notes.push(`${label}: skipped (not enabled for this repository).`);
    else notes.push(`${label}: skipped (${err?.message ?? "error"}).`);
    return [];
  }
}
async function fetchAlerts(client, owner, repo, sources) {
  const alerts = [];
  const notes = [];
  const q = "?state=open";
  if (sources.includes("dependabot")) {
    const rows = await safe(() => client.paginate(`/repos/${owner}/${repo}/dependabot/alerts${q}`), "Dependabot", notes);
    alerts.push(...rows.map((r) => mapDependabot(r)));
  }
  if (sources.includes("code-scanning")) {
    const rows = await safe(() => client.paginate(`/repos/${owner}/${repo}/code-scanning/alerts${q}`), "Code scanning", notes);
    alerts.push(...rows.map((r) => mapCodeScanning(r)));
  }
  if (sources.includes("secret-scanning")) {
    const rows = await safe(() => client.paginate(`/repos/${owner}/${repo}/secret-scanning/alerts${q}`), "Secret scanning", notes);
    alerts.push(...rows.map((r) => mapSecretScanning(r)));
  }
  return { alerts, notes };
}

// ../report-card/dist/index.js
function coverageGrade(percent) {
  if (percent >= 90) return "A";
  if (percent >= 75) return "B";
  if (percent >= 60) return "C";
  if (percent >= 40) return "D";
  return "F";
}

// src/render.ts
var VERDICT_EMOJI = {
  true_positive: "\u{1F534}",
  likely_true_positive: "\u{1F7E0}",
  needs_review: "\u{1F7E1}",
  likely_benign: "\u26AA"
};
var COMMENT_MARKER = "<!-- aisoc-action-triage -->";
function priorityLine(result) {
  const exploitable = result.verdicts.filter(
    (v) => v.verdict === "true_positive" || v.verdict === "likely_true_positive"
  ).length;
  return `**${exploitable} of ${result.summary.total}** findings are prioritized as exploitable / act-now; ${result.summary.suppressed} are low-signal noise.`;
}
function postureGrade(result) {
  const { total, truePositive, needsReview } = result.summary;
  if (total === 0) return { grade: "A", score: 100 };
  const penalty = (truePositive * 12 + needsReview * 3) / total;
  const score = Math.max(0, Math.round(100 - penalty * 10));
  return { grade: coverageGrade(score), score };
}
function cell(s) {
  return s.replace(/\\/g, "\\\\").replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}
function table(verdicts, limit = 30) {
  const rows = verdicts.slice(0, limit).map(
    (v) => `| ${VERDICT_EMOJI[v.verdict]} ${v.verdict.replace(/_/g, " ")} | ${Math.round(v.confidence * 100)}% | \`${cell(v.source)}\` | ${cell(v.title.slice(0, 80))} | ${cell(v.recommendation)} |`
  ).join("\n");
  const extra = verdicts.length > limit ? `

_\u2026and ${verdicts.length - limit} more._` : "";
  return `| Verdict | Confidence | Source | Finding | Action |
|---|---|---|---|---|
${rows}${extra}`;
}
function renderComment(result, notes) {
  const s = result.summary;
  const attention = result.verdicts.filter((v) => v.verdict !== "likely_benign");
  const lines = [
    COMMENT_MARKER,
    "## \u{1F6E1}\uFE0F AiSOC security triage",
    "",
    `> ${s.headline}`,
    "",
    priorityLine(result),
    "",
    attention.length ? table(attention) : "_No findings need attention \u2014 all open alerts triaged as low-signal noise._",
    ""
  ];
  if (notes.length) {
    lines.push("<details><summary>Notes</summary>\n", ...notes.map((n) => `- ${n}`), "\n</details>", "");
  }
  lines.push(
    "",
    // No remote badge image here on purpose: this line promises "no data
    // leaves your CI", and a hotlinked badge makes every reader's browser
    // call a third-party deployment to render the comment.
    "<sub>Triaged by the deterministic [AiSOC](https://github.com/beenuar/AiSOC) verdict engine \u2014 no LLM, no data leaves your CI.</sub>"
  );
  return lines.join("\n");
}
function renderDigest(result, previous, notes) {
  const { grade, score } = postureGrade(result);
  const s = result.summary;
  const delta = previous ? s.truePositive - previous.summary.truePositive : null;
  const deltaStr = delta === null ? "" : delta === 0 ? " (no change vs last week)" : delta > 0 ? ` (\u25B2 +${delta} vs last week)` : ` (\u25BC ${delta} vs last week)`;
  return [
    COMMENT_MARKER,
    `## \u{1F6E1}\uFE0F AiSOC weekly security posture \u2014 grade ${grade} (${score}/100)`,
    "",
    `- **${s.total}** open findings triaged`,
    `- **${s.truePositive}** act-now${deltaStr}`,
    `- **${s.needsReview}** need review`,
    `- **${s.suppressed}** low-signal noise`,
    "",
    priorityLine(result),
    "",
    ...notes.length ? notes.map((n) => `> ${n}`) : [],
    "",
    "<sub>Generated weekly by [AiSOC](https://github.com/beenuar/AiSOC). Deterministic; nothing leaves your CI.</sub>"
  ].join("\n");
}

// src/index.ts
var SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"];
function atLeast(sev2, floor) {
  return SEVERITY_ORDER.indexOf(sev2) >= SEVERITY_ORDER.indexOf(floor);
}
async function run() {
  const token = getInput("github-token") || process.env.GITHUB_TOKEN || "";
  const mode = getInput("mode", "job-summary");
  const minSeverity = getInput("min-severity", "low") || "low";
  const failOn = getInput("fail-on", "none") || "none";
  const sources = getInput("sources", "dependabot,code-scanning,secret-scanning").split(",").map((s) => s.trim()).filter(Boolean);
  if (!token) {
    setFailed("github-token is required (grant security-events:read).");
    return;
  }
  const ctx = getContext();
  const client = new GitHubClient(token);
  info(`AiSOC: triaging security signals for ${ctx.owner}/${ctx.repo} (sources: ${sources.join(", ")})`);
  const { alerts, notes } = await fetchAlerts(client, ctx.owner, ctx.repo, sources);
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
    "## \u{1F6E1}\uFE0F AiSOC security triage",
    "",
    `> ${result.summary.headline}`,
    "",
    `Posture grade: **${grade}** (${score}/100). ${priorityLine(result)}`,
    ...notes.length ? ["", "Notes:", ...notes.map((n) => `- ${n}`)] : []
  ].join("\n");
  writeSummary(summaryMd);
  if (mode === "pr-comment") {
    await upsertPrComment(client, ctx.owner, ctx.repo, ctx.prNumber, renderComment(result, notes));
  } else if (mode === "digest") {
    await upsertDigestIssue(client, ctx.owner, ctx.repo, renderDigest(result, null, notes));
  }
  if (failOn !== "none") {
    const escalate = result.summary.truePositive;
    const review = result.summary.needsReview;
    const shouldFail = failOn === "true_positive" ? escalate > 0 : failOn === "needs_review" ? escalate + review > 0 : false;
    if (shouldFail) setFailed(`AiSOC: ${escalate} act-now + ${review} review findings meet fail-on=${failOn}.`);
  }
}
async function upsertPrComment(client, owner, repo, prNumber, body) {
  if (!prNumber) {
    info("Not a pull_request event; skipping PR comment (job summary written instead).");
    return;
  }
  try {
    const comments = await client.paginate(`/repos/${owner}/${repo}/issues/${prNumber}/comments`);
    const existing = comments.find((c) => c.body?.includes(COMMENT_MARKER));
    if (existing) {
      await client.request("PATCH", `/repos/${owner}/${repo}/issues/comments/${existing.id}`, { body });
    } else {
      await client.request("POST", `/repos/${owner}/${repo}/issues/${prNumber}/comments`, { body });
    }
  } catch (err) {
    warning(`Could not post PR comment (${err.message}); the job summary still has the results.`);
  }
}
async function upsertDigestIssue(client, owner, repo, body) {
  const title = "\u{1F6E1}\uFE0F AiSOC weekly security posture";
  try {
    const issues = await client.paginate(`/repos/${owner}/${repo}/issues?state=open&labels=aisoc-digest`);
    if (issues[0]) {
      await client.request("PATCH", `/repos/${owner}/${repo}/issues/${issues[0].number}`, { body });
    } else {
      await client.request("POST", `/repos/${owner}/${repo}/issues`, { title, body, labels: ["aisoc-digest"] });
    }
  } catch (err) {
    warning(`Could not create/update the digest issue (${err.message}).`);
  }
}
run().catch((err) => setFailed(err instanceof Error ? err.message : String(err)));
