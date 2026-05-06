#!/usr/bin/env tsx
/**
 * aisoc:demo — single-command path to a running demo stack.
 *
 * Steps:
 *   1. Verify Docker + docker compose are present
 *   2. Pull prebuilt images from ghcr.io/beenuar/* (no local builds)
 *   3. docker compose up -d using docker-compose.demo.yml (slim profile)
 *   4. Wait for postgres + api to be healthy
 *   5. Seed demo data via `python -m app.scripts.seed_demo`
 *   6. Query the API for a seeded case UUID (dev mode auth bypass)
 *   7. Kick off an investigation on that case
 *   8. Open the user's browser at /cases/<uuid>
 *
 * On a warm Docker daemon the full path is roughly 3.5 minutes:
 * about 90s pull + 60s startup + 30s seed + 30s investigation.
 *
 * Usage: pnpm aisoc:demo
 *
 * Flags:
 *   --no-pull    skip the `docker compose pull` step (use cached images)
 *   --no-open    skip launching the browser (CI / headless usage)
 *   --rebuild    docker compose up --build instead of using prebuilt images
 *   --tag <tag>  override AISOC_TAG (default: latest)
 *
 * Exit codes:
 *   0 = success, browser opened
 *   1 = failed to start the stack
 *   2 = stack started but data could not be seeded or investigated
 */
import { execSync, spawnSync } from "node:child_process";
import { createConnection } from "node:net";
import { join } from "node:path";
import { platform } from "node:os";

const ROOT = join(__dirname, "..");
const COMPOSE_FILE = join(ROOT, "docker-compose.demo.yml");
const STARTED_AT = Date.now();

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
}

function parseFlags(argv: string[]): Flags {
  const flags: Flags = {
    noPull: false,
    noOpen: false,
    rebuild: false,
    tag: "latest",
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--no-pull") flags.noPull = true;
    else if (a === "--no-open") flags.noOpen = true;
    else if (a === "--rebuild") flags.rebuild = true;
    else if (a === "--tag") flags.tag = argv[++i] ?? "latest";
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

function openBrowser(url: string) {
  const p = platform();
  const cmd =
    p === "darwin" ? "open" : p === "win32" ? "start" : "xdg-open";
  try {
    if (p === "win32") {
      // `start` is a cmd.exe builtin — needs `cmd /c`
      spawnSync("cmd", ["/c", "start", "", url], { stdio: "ignore", detached: true });
    } else {
      spawnSync(cmd, [url], { stdio: "ignore", detached: true });
    }
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

  const info = tryRun("docker info --format '{{.ServerVersion}}'");
  if (!info) {
    console.error(c.red("docker daemon is not running. Start Docker Desktop and retry."));
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
  step(5, 7, "Seeding canonical demo data");
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
        "seed script returned non-zero. The stack may already be seeded; continuing.",
      ),
    );
  }
  return true;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function sanitizeCaseId(id: unknown): string | null {
  if (typeof id === "string" && UUID_RE.test(id)) return id;
  return null;
}

async function findSeededCase(): Promise<{ id: string; case_number: string; title: string } | null> {
  step(6, 7, "Locating a seeded case");
  // The dev-mode auth bypass returns the demo user/tenant for unauthenticated
  // requests when ENV=development, so we can hit /v1/cases without a token.
  for (let attempt = 0; attempt < 30; attempt++) {
    const res = await fetchJson("http://localhost:8000/v1/cases?page_size=5", 4000);
    if (res && Array.isArray(res.items) && res.items.length > 0) {
      const c0 = res.items[0];
      const safeId = sanitizeCaseId(c0.id);
      if (!safeId) {
        log(c.yellow("warn") + " API returned a non-UUID case ID — skipping");
        return null;
      }
      log(c.green("ok") + ` found case ${c0.case_number} (${safeId})`);
      return { id: safeId, case_number: c0.case_number, title: c0.title };
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

async function openInBrowser(caseId: string | null, flags: Flags) {
  const url =
    caseId !== null
      ? `http://localhost:3000/cases/${caseId}`
      : "http://localhost:3000/cases";
  step(7, 7, `Opening browser at ${url}`);
  if (flags.noOpen) {
    log(c.dim("--no-open: not launching browser"));
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

// ---------- Main ----------

async function main() {
  const flags = parseFlags(process.argv.slice(2));

  console.log(
    c.bold("AiSOC Demo") +
      c.dim(` — tag=${flags.tag}${flags.rebuild ? " · rebuild" : ""}`),
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
  if (seededCase) {
    await kickoffInvestigation(seededCase.id);
  }
  await openInBrowser(seededCase?.id ?? null, flags);
  process.exit(0);
}

main().catch((e) => {
  console.error(c.red("\naisoc:demo crashed:"), e);
  process.exit(2);
});
