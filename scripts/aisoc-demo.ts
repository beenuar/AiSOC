#!/usr/bin/env tsx
/**
 * aisoc:demo — single-command path to a running demo stack.
 *
 * Steps:
 *   1. Verify Docker + docker compose are present
 *   2. Pull prebuilt images from ghcr.io/beenuar/* (no local builds)
 *   3. docker compose up -d using docker-compose.demo.yml (slim profile)
 *      — the `seed` service runs `python -m app.scripts.seed_demo` once
 *      automatically when the api is healthy, then exits cleanly.
 *   4. Wait for postgres + api to be healthy
 *   5. Re-run the seeder as a safety net (idempotent inside seed_demo.py)
 *   6. Query the API for the showcase ransomware case (INC-RT-001) with a
 *      fallback to the first available case if the showcase is missing
 *   7. Kick off an investigation on that case
 *   8. Open the user's browser at /cases/INC-RT-001?tab=ledger
 *
 * On a warm Docker daemon the full path is roughly 3.5 minutes:
 * about 90s pull + 60s startup + 30s seed + 30s investigation. The
 * v1.0 acceptance gate (the WS-A acceptance to-do in the buyer-value
 * plan) is clone-to-investigation in ≤ 5 minutes on a clean Mac with
 * a cold Docker daemon. The `--budget-ms` flag enforces this gate
 * automatically and `--results-file` writes a phase-by-phase JSON
 * timing report so CI / nightly runs can spot regressions.
 *
 * Usage: pnpm aisoc:demo
 *
 * Flags:
 *   --no-pull             skip the `docker compose pull` step (use cached images)
 *   --no-open             skip launching the browser (CI / headless usage)
 *   --rebuild             docker compose up --build instead of using prebuilt images
 *   --tag <tag>           override AISOC_TAG (default: latest)
 *   --budget-ms <number>  fail with exit 3 if total elapsed exceeds this many ms
 *   --results-file <p>    write per-phase timing JSON to <p> (used by acceptance)
 *
 * Exit codes:
 *   0 = success, browser opened
 *   1 = failed to start the stack
 *   2 = stack started but data could not be seeded or investigated
 *   3 = success but exceeded --budget-ms (acceptance regression)
 */
import { execSync, spawnSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { createConnection } from "node:net";
import { join } from "node:path";
import { platform } from "node:os";

const ROOT = join(__dirname, "..");
const COMPOSE_FILE = join(ROOT, "docker-compose.demo.yml");
const STARTED_AT = Date.now();

// Per-phase timing for the v1.0 ≤5-min acceptance gate. Each step()
// call closes the previous phase and opens a new one, so the final
// summary shows where the wall-clock minute went (pull, boot, seed,
// kickoff). Without this the buyer just sees a single "3m42s"
// number with no way to diagnose what regressed if a future change
// pushes us over budget.
interface Phase {
  name: string;
  startedAtMs: number;
  endedAtMs?: number;
}
const phases: Phase[] = [];
function startPhase(name: string): void {
  const now = Date.now();
  if (phases.length > 0) {
    const prev = phases[phases.length - 1];
    if (prev.endedAtMs === undefined) prev.endedAtMs = now;
  }
  phases.push({ name, startedAtMs: now });
}
function closeLastPhase(): void {
  if (phases.length === 0) return;
  const prev = phases[phases.length - 1];
  if (prev.endedAtMs === undefined) prev.endedAtMs = Date.now();
}

const c = {
  green: (s: string) => `\x1b[32m${s}\x1b[0m`,
  yellow: (s: string) => `\x1b[33m${s}\x1b[0m`,
  red: (s: string) => `\x1b[31m${s}\x1b[0m`,
  blue: (s: string) => `\x1b[34m${s}\x1b[0m`,
  bold: (s: string) => `\x1b[1m${s}\x1b[0m`,
  dim: (s: string) => `\x1b[2m${s}\x1b[0m`,
};

interface Flags {
  noPull: boolean;
  noOpen: boolean;
  rebuild: boolean;
  tag: string;
  // Acceptance-gate plumbing. `budgetMs` is the v1.0 ≤5-min target;
  // when set the script exits 3 (success-but-over-budget) so CI can
  // distinguish a regression from a hard failure. `resultsFile` writes
  // a structured JSON timing report that scripts/aisoc-acceptance.ts
  // consumes for nightly regression tracking.
  budgetMs: number | null;
  resultsFile: string | null;
}

function parseFlags(argv: string[]): Flags {
  const flags: Flags = {
    noPull: false,
    noOpen: false,
    rebuild: false,
    tag: "latest",
    budgetMs: null,
    resultsFile: null,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--no-pull") flags.noPull = true;
    else if (a === "--no-open") flags.noOpen = true;
    else if (a === "--rebuild") flags.rebuild = true;
    else if (a === "--tag") flags.tag = argv[++i] ?? "latest";
    else if (a === "--budget-ms") {
      const raw = argv[++i];
      const n = raw ? Number.parseInt(raw, 10) : Number.NaN;
      flags.budgetMs = Number.isFinite(n) && n > 0 ? n : null;
    } else if (a === "--results-file") {
      flags.resultsFile = argv[++i] ?? null;
    }
  }
  return flags;
}

function elapsed(): string {
  const s = Math.round((Date.now() - STARTED_AT) / 1000);
  const m = Math.floor(s / 60);
  return m > 0 ? `${m}m${s % 60}s` : `${s}s`;
}

function log(msg: string) {
  console.log(`${c.dim(`[${elapsed()}]`)} ${msg}`);
}

function step(n: number, total: number, msg: string) {
  // Every visible step doubles as a phase boundary for the timing
  // report. The label uses the step msg (without the [n/total] prefix)
  // so the JSON report reads naturally — "Pulling prebuilt images…"
  // instead of "[2/7] Pulling…". We strip the parenthesized suffix
  // some msgs include ("Skipping image pull (--rebuild)") so the
  // canonical phase names stay stable between runs even when flags
  // differ — the acceptance harness compares phase durations across
  // runs and a label drift would break trend comparisons.
  const cleanLabel = msg.replace(/\s*\([^)]*\)\s*$/, "").trim();
  startPhase(cleanLabel);
  console.log(`\n${c.bold(c.blue(`[${n}/${total}] ${msg}`))} ${c.dim(`(${elapsed()})`)}`);
}

function tryRun(cmd: string): string | null {
  try {
    return execSync(cmd, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  } catch {
    return null;
  }
}

function runStream(cmd: string, args: string[], env: NodeJS.ProcessEnv = {}): number {
  const result = spawnSync(cmd, args, {
    stdio: "inherit",
    cwd: ROOT,
    env: { ...process.env, ...env },
  });
  return result.status ?? 1;
}

async function probePort(host: string, port: number, timeoutMs = 1500): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = createConnection({ host, port });
    const timer = setTimeout(() => {
      sock.destroy();
      resolve(false);
    }, timeoutMs);
    sock.once("connect", () => {
      clearTimeout(timer);
      sock.end();
      resolve(true);
    });
    sock.once("error", () => {
      clearTimeout(timer);
      resolve(false);
    });
  });
}

async function fetchJson(url: string, timeoutMs = 5000): Promise<any | null> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: ctrl.signal });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

async function postJson(url: string, body: any, timeoutMs = 30000): Promise<any | null> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: "POST",
      signal: ctrl.signal,
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

async function waitFor(
  label: string,
  check: () => Promise<boolean>,
  timeoutMs: number,
  pollMs = 2000,
): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  process.stdout.write(`   ${c.dim(`waiting for ${label}…`)} `);
  while (Date.now() < deadline) {
    if (await check()) {
      process.stdout.write(c.green("ready\n"));
      return true;
    }
    process.stdout.write(c.dim("."));
    await new Promise((r) => setTimeout(r, pollMs));
  }
  process.stdout.write(c.red(" timeout\n"));
  return false;
}

// Returns true if we're sure there's no display the browser could land on.
// On Linux this is the usual "headless server" check (no DISPLAY/WAYLAND
// and no xdg-open). On macOS and Windows the OS always has a session, so
// we only honor the explicit AISOC_NO_BROWSER opt-out.
function isHeadless(): boolean {
  if (process.env.AISOC_NO_BROWSER === "1") return true;
  if (process.env.CI) return true;
  const p = platform();
  if (p === "linux") {
    if (!process.env.DISPLAY && !process.env.WAYLAND_DISPLAY) return true;
  }
  return false;
}

function openBrowser(url: string) {
  const p = platform();
  try {
    if (p === "win32") {
      // `start` is a cmd.exe builtin, not an exe — must go through cmd.
      // The empty "" arg is cmd's title slot; without it `start` swallows
      // the URL as a window title when the URL starts with a quote.
      spawnSync("cmd", ["/c", "start", "", url], { stdio: "ignore", detached: true });
      return;
    }
    if (p === "darwin") {
      spawnSync("open", [url], { stdio: "ignore", detached: true });
      return;
    }
    // Linux: xdg-open is present on most desktops but not on minimal
    // server installs (Debian-slim, Alpine, GitHub Actions ubuntu-latest
    // when no desktop env). Probe for it first; if missing, just log.
    const probe = spawnSync("which", ["xdg-open"], { stdio: "ignore" });
    if (probe.status === 0) {
      spawnSync("xdg-open", [url], { stdio: "ignore", detached: true });
      return;
    }
    // Fall back to common alternatives that some distros ship.
    for (const alt of ["sensible-browser", "x-www-browser", "gnome-open"]) {
      const altProbe = spawnSync("which", [alt], { stdio: "ignore" });
      if (altProbe.status === 0) {
        spawnSync(alt, [url], { stdio: "ignore", detached: true });
        return;
      }
    }
    // No opener available; URL is already in the success banner above.
    log(c.dim("(no browser opener found — open the URL manually)"));
  } catch {
    // Best-effort. The URL is logged anyway.
  }
}

// ---------- Steps ----------

function checkDocker(): boolean {
  step(1, 7, "Verifying Docker");
  const docker = tryRun("docker --version");
  if (!docker) {
    console.error(
      c.red("docker is not installed or not on PATH.\n  Install Docker Desktop: https://www.docker.com/products/docker-desktop"),
    );
    return false;
  }
  log(c.green("ok") + ` ${docker}`);

  const compose = tryRun("docker compose version");
  if (!compose) {
    console.error(c.red("docker compose v2 plugin is required (compose v1 not supported)."));
    return false;
  }
  log(c.green("ok") + ` ${compose}`);

  // Cross-platform note: single-quote --format works on POSIX shells but
  // not on Windows cmd, where {{ gets interpreted by Go's template parser
  // through cmd's mangled quoting. Use spawnSync directly with shell:false
  // so the args are passed verbatim to docker.exe and the quoting layer
  // is removed entirely.
  const infoResult = spawnSync(
    "docker",
    ["info", "--format", "{{.ServerVersion}}"],
    { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
  );
  const info = infoResult.status === 0 ? infoResult.stdout.trim() : "";
  if (!info) {
    console.error(
      c.red(
        "docker daemon is not running. Start Docker Desktop (or `sudo systemctl start docker` on Linux) and retry.",
      ),
    );
    return false;
  }
  log(c.green("ok") + ` docker daemon up (server ${info})`);
  return true;
}

function pullImages(flags: Flags): boolean {
  if (flags.rebuild) {
    step(2, 7, "Skipping image pull (--rebuild)");
    return true;
  }
  if (flags.noPull) {
    step(2, 7, "Skipping image pull (--no-pull)");
    return true;
  }
  step(2, 7, `Pulling prebuilt images from ghcr.io (tag: ${flags.tag})`);
  const code = runStream("docker", ["compose", "-f", COMPOSE_FILE, "pull"], {
    AISOC_TAG: flags.tag,
  });
  if (code !== 0) {
    console.error(
      c.yellow(
        "image pull failed; falling back to local build. " +
          "Use --rebuild to force building from source.",
      ),
    );
    flags.rebuild = true;
  }
  return true;
}

function startStack(flags: Flags): boolean {
  step(3, 7, "Starting AiSOC demo stack");
  const args = ["compose", "-f", COMPOSE_FILE, "up", "-d"];
  if (flags.rebuild) args.push("--build");
  const code = runStream("docker", args, { AISOC_TAG: flags.tag });
  if (code !== 0) {
    console.error(c.red("docker compose up failed. See output above."));
    return false;
  }
  return true;
}

async function waitForHealth(): Promise<boolean> {
  step(4, 7, "Waiting for services to come up");

  const postgresUp = await waitFor(
    "postgres",
    async () => probePort("127.0.0.1", 5432),
    60_000,
    1000,
  );
  if (!postgresUp) return false;

  const apiUp = await waitFor(
    "api /health",
    async () => {
      const j = await fetchJson("http://localhost:8000/health", 1500);
      return j !== null;
    },
    120_000,
    2000,
  );
  if (!apiUp) return false;

  const webUp = await waitFor(
    "web",
    async () => {
      try {
        const res = await fetch("http://localhost:3000", {
          signal: AbortSignal.timeout(1500),
        });
        return res.status > 0;
      } catch {
        return false;
      }
    },
    120_000,
    2000,
  );
  if (!webUp) {
    console.error(c.yellow("web is slow to start; continuing anyway"));
  }

  return true;
}

function seedData(): boolean {
  step(5, 7, "Ensuring canonical demo data is seeded");
  // The `seed` service in docker-compose.demo.yml runs `python -m
  // app.scripts.seed_demo` automatically once the api healthcheck passes
  // and then exits. We re-run it here as a safety net for two cases:
  //   - the seed container failed silently (network blip pulling the
  //     image, postgres took longer than the seed's healthcheck-wait, …)
  //   - the user previously ran `docker compose down` without `-v`, so the
  //     postgres volume survived but the seeder isn't going to fire again
  //     because the api is already considered healthy on the next `up`.
  // Idempotency is enforced inside seed_demo.py — repeated runs are a
  // no-op as long as INC-RT-001 etc. already exist.
  const code = runStream("docker", [
    "compose",
    "-f",
    COMPOSE_FILE,
    "exec",
    "-T",
    "api",
    "python",
    "-m",
    "app.scripts.seed_demo",
  ]);
  if (code !== 0) {
    console.error(
      c.yellow(
        "seed re-run returned non-zero. The stack is likely already seeded by the one-shot `seed` container; continuing.",
      ),
    );
  }
  return true;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SHOWCASE_CASE_NUMBER = "INC-RT-001";

function sanitizeCaseId(id: unknown): string | null {
  if (typeof id === "string" && UUID_RE.test(id)) return id;
  return null;
}

async function findSeededCase(): Promise<{ id: string; case_number: string; title: string } | null> {
  step(6, 7, "Locating the showcase ransomware investigation");
  // The dev-mode auth bypass returns the demo user/tenant for unauthenticated
  // requests when ENV=development, so we can hit /v1/cases without a token.
  //
  // We specifically look for INC-RT-001 — the in-flight LockBit 3.0 case
  // that seed_demo.py builds with a running PlaybookRun, an investigation
  // already mid-stream, and decision-graph artifacts. That's the case the
  // onboarding deeplink (NEXT_PUBLIC_DEMO_DEEPLINK=/cases/INC-RT-001?tab=
  // ledger) targets. If it's missing we fall back to the first case in the
  // list, but log a warning because the demo UX assumes the showcase case
  // is present.
  for (let attempt = 0; attempt < 30; attempt++) {
    // Pull the full first page (default page_size on the API is plenty
    // larger than the seed's ~16 cases). Filtering server-side by
    // case_number would be cleaner but the cases list endpoint doesn't
    // currently expose that filter, and the volume is trivially small.
    const res = await fetchJson("http://localhost:8000/v1/cases?page_size=50", 4000);
    if (res && Array.isArray(res.items) && res.items.length > 0) {
      const showcase = res.items.find(
        (item: any) => item.case_number === SHOWCASE_CASE_NUMBER,
      );
      const target = showcase ?? res.items[0];
      const safeId = sanitizeCaseId(target.id);
      if (!safeId) {
        log(c.yellow("warn") + " API returned a non-UUID case ID — skipping");
        return null;
      }
      if (showcase) {
        log(c.green("ok") + ` found showcase ${target.case_number} (${safeId})`);
      } else {
        log(
          c.yellow("warn") +
            ` ${SHOWCASE_CASE_NUMBER} not found; falling back to ${target.case_number}`,
        );
      }
      return { id: safeId, case_number: target.case_number, title: target.title };
    }
    await new Promise((r) => setTimeout(r, 2000));
  }
  console.error(
    c.yellow(
      "no seeded cases visible after 60s. The web console will still open, but to a blank cases list.",
    ),
  );
  return null;
}

async function kickoffInvestigation(caseId: string): Promise<boolean> {
  // Best-effort. If LLM keys aren't set, the agent run will short-circuit to
  // a heuristic plan, which is still demo-worthy.
  log(c.dim("kicking off agent investigation…"));
  const result = await postJson(
    `http://localhost:8000/v1/cases/${caseId}/investigate`,
    {},
    10000,
  );
  if (result) {
    log(c.green("ok") + ` investigation queued (run_id ${result.run_id ?? "unknown"})`);
    return true;
  }
  log(c.yellow("note") + " could not auto-launch investigation (no LLM key?). The case is still browsable.");
  return false;
}

// Validates a case_number like "INC-RT-001" / "INC-001" before splicing it
// into the URL. Defensive against arbitrary strings the API might return —
// the cases endpoint has resolved arbitrary identifiers in the past.
const CASE_NUMBER_RE = /^[A-Za-z0-9_-]{1,32}$/;
function sanitizeCaseNumber(num: unknown): string | null {
  if (typeof num === "string" && CASE_NUMBER_RE.test(num)) return num;
  return null;
}

async function openInBrowser(
  seeded: { id: string; case_number: string; title: string } | null,
  flags: Flags,
) {
  // Prefer routing by human-readable case_number with the ledger tab
  // pre-selected — that's the same URL the hosted demo uses and what
  // NEXT_PUBLIC_DEMO_DEEPLINK points at, so docs/screenshots/local-demo
  // all land in the same place. The Next.js [id] route resolves both
  // case_number and UUID via the API's case_number_or_id lookup
  // (services/api/app/api/v1/endpoints/cases.py).
  const safeNumber = seeded ? sanitizeCaseNumber(seeded.case_number) : null;
  const url = seeded
    ? safeNumber
      ? `http://localhost:3000/cases/${safeNumber}?tab=ledger`
      : `http://localhost:3000/cases/${seeded.id}?tab=ledger`
    : "http://localhost:3000/cases";
  step(7, 7, `Opening browser at ${url}`);
  if (flags.noOpen) {
    log(c.dim("--no-open: not launching browser"));
  } else if (isHeadless()) {
    // CI, headless server, or AISOC_NO_BROWSER=1. Don't try to spawn a
    // GUI process the user can't see — just leave the URL in the banner.
    log(c.dim("headless environment detected — not launching browser (set AISOC_NO_BROWSER=0 to override)"));
  } else {
    openBrowser(url);
  }

  console.log(`
${c.bold(c.green("AiSOC demo is up."))}
  ${c.bold("Web:")}        ${url}
  ${c.bold("API:")}        http://localhost:8000/docs
  ${c.bold("Realtime:")}   ws://localhost:8086

${c.dim("Useful commands:")}
  pnpm aisoc:doctor                           ${c.dim("# health check")}
  docker compose -f docker-compose.demo.yml logs -f api
  docker compose -f docker-compose.demo.yml down -v   ${c.dim("# stop & wipe demo data")}

${c.bold("Total elapsed:")} ${c.green(elapsed())}
`);
}

// ---------- Acceptance-gate reporting ----------

function formatMs(ms: number): string {
  const total = Math.round(ms / 1000);
  const m = Math.floor(total / 60);
  const s = total % 60;
  return m > 0 ? `${m}m${String(s).padStart(2, "0")}s` : `${s}s`;
}

interface RunReport {
  // ISO-8601 wall-clock so nightly runs stay sortable in a JSON ledger.
  finishedAt: string;
  totalMs: number;
  totalLabel: string;
  budgetMs: number | null;
  withinBudget: boolean | null;
  showcaseCaseFound: boolean;
  investigationKickedOff: boolean;
  flags: {
    rebuild: boolean;
    noPull: boolean;
    noOpen: boolean;
    tag: string;
  };
  phases: Array<{ name: string; durationMs: number; label: string }>;
}

function buildReport(
  flags: Flags,
  showcaseCaseFound: boolean,
  investigationKickedOff: boolean,
): RunReport {
  closeLastPhase();
  const totalMs = Date.now() - STARTED_AT;
  return {
    finishedAt: new Date().toISOString(),
    totalMs,
    totalLabel: formatMs(totalMs),
    budgetMs: flags.budgetMs,
    withinBudget: flags.budgetMs === null ? null : totalMs <= flags.budgetMs,
    showcaseCaseFound,
    investigationKickedOff,
    flags: {
      rebuild: flags.rebuild,
      noPull: flags.noPull,
      noOpen: flags.noOpen,
      tag: flags.tag,
    },
    phases: phases.map((p) => {
      const end = p.endedAtMs ?? Date.now();
      const dur = end - p.startedAtMs;
      return { name: p.name, durationMs: dur, label: formatMs(dur) };
    }),
  };
}

function printPhaseTable(report: RunReport): void {
  // ASCII table — readable by humans in CI logs and screenshot-friendly
  // for "yes, the demo really did boot in 3m20s" buyer-facing benchmarks.
  // Plain spaces (no Unicode box drawing) to stay terminal-portable.
  console.log(c.bold("Phase breakdown"));
  const rows = report.phases.map((p) => [p.name, p.label, `${p.durationMs}ms`]);
  const headers = ["Phase", "Duration", "ms"];
  const all = [headers, ...rows];
  const widths = headers.map((_, i) =>
    Math.max(...all.map((row) => row[i].length)),
  );
  const fmt = (row: string[]) =>
    "  " + row.map((cell, i) => cell.padEnd(widths[i])).join("  ");
  console.log(c.dim(fmt(headers)));
  console.log(c.dim("  " + widths.map((w) => "-".repeat(w)).join("  ")));
  for (const row of rows) console.log(fmt(row));
  console.log(
    `\n  ${c.bold("Total:")} ${c.green(report.totalLabel)} (${report.totalMs}ms)`,
  );
  if (report.budgetMs !== null) {
    const budgetLabel = formatMs(report.budgetMs);
    if (report.withinBudget) {
      console.log(
        `  ${c.bold("Budget:")} ${c.green(`PASS — under ${budgetLabel}`)} ` +
          c.dim(`(${report.budgetMs - report.totalMs}ms headroom)`),
      );
    } else {
      console.log(
        `  ${c.bold("Budget:")} ${c.red(`FAIL — exceeded ${budgetLabel} by ${formatMs(report.totalMs - report.budgetMs)}`)} ` +
          c.dim("(WS-A acceptance regression)"),
      );
    }
  }
}

function emitReport(flags: Flags, report: RunReport): void {
  if (!flags.resultsFile) return;
  try {
    writeFileSync(flags.resultsFile, JSON.stringify(report, null, 2) + "\n");
    console.log(c.dim(`  results JSON written to ${flags.resultsFile}`));
  } catch (e: any) {
    console.error(
      c.yellow(`  failed to write results to ${flags.resultsFile}: ${e?.message ?? e}`),
    );
  }
}

// ---------- Main ----------

async function main() {
  const flags = parseFlags(process.argv.slice(2));

  console.log(
    c.bold("AiSOC Demo") +
      c.dim(
        ` — tag=${flags.tag}${flags.rebuild ? " · rebuild" : ""}` +
          (flags.budgetMs ? ` · budget=${formatMs(flags.budgetMs)}` : ""),
      ),
  );

  if (!checkDocker()) process.exit(1);
  if (!pullImages(flags)) process.exit(1);
  if (!startStack(flags)) process.exit(1);
  if (!(await waitForHealth())) {
    console.error(c.red("\nstack failed to come up healthy. Run `pnpm aisoc:doctor` for details."));
    process.exit(1);
  }
  if (!seedData()) {
    console.error(c.yellow("seed step had issues; continuing"));
  }
  const seededCase = await findSeededCase();
  // We track these for the run report so the acceptance harness can
  // distinguish "stack came up but no case showed" (a seed regression)
  // from "everything booted but the LLM call failed" (a flaky live LLM).
  let investigationKickedOff = false;
  if (seededCase) {
    investigationKickedOff = await kickoffInvestigation(seededCase.id);
  }
  await openInBrowser(seededCase, flags);

  // Reporting runs after openInBrowser so the cheerful "demo is up"
  // banner stays at the top of the user's eyeline. The phase table
  // and budget verdict come immediately after — for a `pnpm aisoc:demo`
  // user without --budget-ms it's just a nice-to-have timing breakdown;
  // for the acceptance harness it's the gate.
  console.log("");
  const report = buildReport(flags, seededCase !== null, investigationKickedOff);
  printPhaseTable(report);
  emitReport(flags, report);

  if (flags.budgetMs !== null && !report.withinBudget) {
    // Exit 3 (distinct from 1=hard-fail and 2=crash) so CI can label
    // the run "regression" rather than "broken". The stack is left
    // running so the human can poke at the slow step.
    process.exit(3);
  }
  process.exit(0);
}

main().catch((e) => {
  console.error(c.red("\naisoc:demo crashed:"), e);
  process.exit(2);
});
