/**
 * Dependency-free GitHub Actions runtime + GitHub REST client.
 *
 * We deliberately do NOT use `@actions/core` / `@actions/github`: their octokit
 * transitive tree pulls a vulnerable `undici`, and a security-triage action
 * should not ship known-vulnerable dependencies. Node 20's global `fetch` +
 * the documented Actions env-var/file contract are all we need.
 */

import { appendFileSync, readFileSync } from "node:fs";

// ── Actions runtime (env-var + file contract) ────────────────────────────────

export function getInput(name: string, fallback = ""): string {
  const key = `INPUT_${name.replace(/ /g, "_").toUpperCase()}`;
  return (process.env[key] ?? fallback).trim();
}

export function setOutput(name: string, value: string): void {
  const file = process.env.GITHUB_OUTPUT;
  const line = `${name}<<__AISOC_EOF__\n${value}\n__AISOC_EOF__\n`;
  if (file) appendFileSync(file, line);
}

export function info(msg: string): void {
  process.stdout.write(`${msg}\n`);
}

export function warning(msg: string): void {
  process.stdout.write(`::warning::${msg}\n`);
}

let _failed = false;
export function setFailed(msg: string): void {
  _failed = true;
  process.stdout.write(`::error::${msg}\n`);
  process.exitCode = 1;
}

export function didFail(): boolean {
  return _failed;
}

export function writeSummary(markdown: string): void {
  const file = process.env.GITHUB_STEP_SUMMARY;
  if (file) appendFileSync(file, markdown + "\n");
  else info(markdown);
}

export interface ActionContext {
  owner: string;
  repo: string;
  eventName: string;
  prNumber: number | null;
}

export function getContext(): ActionContext {
  const [owner = "", repo = ""] = (process.env.GITHUB_REPOSITORY ?? "/").split("/");
  const eventName = process.env.GITHUB_EVENT_NAME ?? "";
  let prNumber: number | null = null;
  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (eventPath) {
    try {
      const payload = JSON.parse(readFileSync(eventPath, "utf8")) as { pull_request?: { number?: number } };
      // Coerce to a strict positive integer so nothing from the event file can
      // flow verbatim into request URLs (it's only ever used as `/…/{n}/…`).
      const raw = payload.pull_request?.number;
      prNumber = typeof raw === "number" && Number.isInteger(raw) && raw > 0 ? raw : null;
    } catch {
      prNumber = null;
    }
  }
  return { owner, repo, eventName, prNumber };
}

// ── GitHub REST client (fetch-based, paginating) ─────────────────────────────

export class GitHubClient {
  constructor(
    private readonly token: string,
    private readonly base = process.env.GITHUB_API_URL || "https://api.github.com",
  ) {}

  private headers(): Record<string, string> {
    return {
      authorization: `Bearer ${this.token}`,
      accept: "application/vnd.github+json",
      "x-github-api-version": "2022-11-28",
      "user-agent": "aisoc-action",
    };
  }

  async request(method: string, path: string, body?: unknown): Promise<Response> {
    const url = path.startsWith("http") ? path : `${this.base}${path}`;
    return fetch(url, {
      method,
      headers: { ...this.headers(), ...(body ? { "content-type": "application/json" } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
  }

  /** GET all pages of a list endpoint, following the Link rel="next" header. */
  async paginate(path: string): Promise<unknown[]> {
    const out: unknown[] = [];
    let next: string | null = path.includes("?") ? `${path}&per_page=100` : `${path}?per_page=100`;
    let guard = 0;
    while (next && guard < 50) {
      guard += 1;
      const resp: Response = await this.request("GET", next);
      if (!resp.ok) {
        const err = new Error(`GitHub API ${resp.status} for ${next}`) as Error & { status?: number };
        err.status = resp.status;
        throw err;
      }
      const page = (await resp.json()) as unknown[];
      if (Array.isArray(page)) out.push(...page);
      next = parseNextLink(resp.headers.get("link"));
    }
    return out;
  }
}

export function parseNextLink(link: string | null): string | null {
  if (!link) return null;
  for (const part of link.split(",")) {
    const m = part.match(/<([^>]+)>;\s*rel="next"/);
    if (m) return m[1] ?? null;
  }
  return null;
}
