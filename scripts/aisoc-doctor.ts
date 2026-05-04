#!/usr/bin/env tsx
/**
 * aisoc:doctor — health-check for an AiSOC dev environment.
 *
 * Verifies:
 *   1. Required ports are free or owned by the expected service
 *   2. Required env vars (.env) are present
 *   3. Docker compose containers are healthy
 *   4. Demo data is seeded (alerts > 0)
 *   5. WebSocket realtime is reachable
 *
 * Usage: pnpm aisoc:doctor
 *
 * Exit code 0 = OK, 1 = at least one FAIL.
 */
import { execSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { createConnection } from "node:net";
import { join } from "node:path";

type Status = "OK" | "WARN" | "FAIL";

interface Check {
  name: string;
  status: Status;
  detail?: string;
}

const ROOT = join(__dirname, "..");
const checks: Check[] = [];

const c = {
  green: (s: string) => `\x1b[32m${s}\x1b[0m`,
  yellow: (s: string) => `\x1b[33m${s}\x1b[0m`,
  red: (s: string) => `\x1b[31m${s}\x1b[0m`,
  bold: (s: string) => `\x1b[1m${s}\x1b[0m`,
  dim: (s: string) => `\x1b[2m${s}\x1b[0m`,
};

function statusIcon(s: Status): string {
  if (s === "OK") return c.green("✓ PASS");
  if (s === "WARN") return c.yellow("⚠ WARN");
  return c.red("✗ FAIL");
}

function record(name: string, status: Status, detail?: string) {
  checks.push({ name, status, detail });
  console.log(`  ${statusIcon(status)}  ${name}${detail ? c.dim(` — ${detail}`) : ""}`);
}

function run(cmd: string): string {
  return execSync(cmd, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

function tryRun(cmd: string): string | null {
  try {
    return run(cmd);
  } catch {
    return null;
  }
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

// ---------- Section 1: Env file ----------
async function checkEnv() {
  console.log(c.bold("\nEnvironment"));
  const envPath = join(ROOT, ".env");
  if (!existsSync(envPath)) {
    record(".env file present", "WARN", "no .env found; copy from .env.example for non-default secrets");
    return;
  }
  const env = readFileSync(envPath, "utf8");
  const requiredKeys = [
    "DATABASE_URL",
    "REDIS_URL",
    "KAFKA_BOOTSTRAP_SERVERS",
  ];
  for (const k of requiredKeys) {
    const re = new RegExp(`^${k}\\s*=`, "m");
    record(
      `env var ${k}`,
      re.test(env) ? "OK" : "WARN",
      re.test(env) ? undefined : "missing from .env"
    );
  }
}

// ---------- Section 2: Docker compose ----------
async function checkDocker() {
  console.log(c.bold("\nDocker"));
  const docker = tryRun("docker --version");
  if (!docker) {
    record("docker available", "FAIL", "docker is not installed or not on PATH");
    return;
  }
  record("docker available", "OK", docker);

  const compose = tryRun("docker compose version");
  if (!compose) {
    record("docker compose v2", "FAIL", "docker compose plugin not installed");
    return;
  }
  record("docker compose v2", "OK", compose);

  const ps = tryRun("docker compose ps --format json");
  if (!ps) {
    record(
      "containers running",
      "WARN",
      'no compose stack running — run `docker compose up -d`'
    );
    return;
  }

  // docker compose ps --format json prints ndjson on Compose v2
  const lines = ps.split("\n").filter((l) => l.trim());
  const services = lines
    .map((l) => {
      try {
        return JSON.parse(l);
      } catch {
        return null;
      }
    })
    .filter(Boolean);

  if (services.length === 0) {
    record("containers running", "WARN", "no services up");
    return;
  }

  const expectedServices = [
    "aisoc-api",
    "aisoc-agents",
    "aisoc-web",
    "aisoc-postgres",
    "aisoc-redis",
    "aisoc-realtime",
  ];
  for (const svc of expectedServices) {
    const found = services.find((s: any) => s.Name === svc);
    if (!found) {
      record(`container ${svc}`, "FAIL", "not running");
      continue;
    }
    const healthy =
      found.Health === "healthy" ||
      found.Health === "" /* no healthcheck */ ||
      found.State === "running";
    record(
      `container ${svc}`,
      healthy ? "OK" : "FAIL",
      `state=${found.State}${found.Health ? ` health=${found.Health}` : ""}`
    );
  }
}

// ---------- Section 3: Ports ----------
async function checkPorts() {
  console.log(c.bold("\nPorts"));
  const ports: Array<[string, number]> = [
    ["api", 8000],
    ["agents", 8001],
    ["web", 3000],
    ["postgres", 5432],
    ["redis", 6379],
    ["realtime ws", 8086],
  ];
  for (const [label, port] of ports) {
    const open = await probePort("127.0.0.1", port);
    record(`${label} :${port}`, open ? "OK" : "FAIL", open ? "reachable" : "no listener");
  }
}

// ---------- Section 4: API health ----------
async function checkApi() {
  console.log(c.bold("\nAPI health"));
  const health = await fetchJson("http://localhost:8000/health");
  if (!health) {
    record("GET /health", "FAIL", "no response from api");
    return;
  }
  record("GET /health", "OK", JSON.stringify(health).slice(0, 80));

  // Demo data: at least one alert
  const alerts = await fetchJson("http://localhost:8000/v1/alerts?limit=1");
  if (!alerts) {
    record(
      "demo data seeded",
      "WARN",
      "could not query alerts (auth required?) — try `pnpm seed:demo`"
    );
    return;
  }
  const count = Array.isArray(alerts)
    ? alerts.length
    : Array.isArray(alerts?.items)
      ? alerts.items.length
      : 0;
  record(
    "demo data seeded",
    count > 0 ? "OK" : "WARN",
    count > 0 ? `${count} alert(s) found` : "no alerts — run `pnpm seed:demo`"
  );
}

// ---------- Section 5: Web reachable ----------
async function checkWeb() {
  console.log(c.bold("\nWeb console"));
  try {
    const res = await fetch("http://localhost:3000", { signal: AbortSignal.timeout(3000) });
    record("GET /", res.ok ? "OK" : "FAIL", `status ${res.status}`);
  } catch (e: any) {
    record("GET /", "FAIL", e?.message ?? "no response");
  }
}

// ---------- Run ----------
async function main() {
  console.log(c.bold("AiSOC Doctor") + c.dim(" — pre-flight check"));
  await checkEnv();
  await checkDocker();
  await checkPorts();
  await checkApi();
  await checkWeb();

  // Summary
  const fails = checks.filter((c) => c.status === "FAIL").length;
  const warns = checks.filter((c) => c.status === "WARN").length;
  const oks = checks.filter((c) => c.status === "OK").length;

  console.log(c.bold("\nSummary"));
  console.log(
    `  ${c.green(`${oks} pass`)}  ${warns > 0 ? c.yellow(`${warns} warn`) : `${warns} warn`}  ${fails > 0 ? c.red(`${fails} fail`) : `${fails} fail`}`
  );

  if (fails > 0) {
    console.log(
      c.red("\n  ✗ AiSOC is not healthy. ") +
        "See the failing checks above. " +
        c.dim("Quickstart: https://github.com/cybeleinc/AiSOC#quickstart")
    );
    process.exit(1);
  }
  if (warns > 0) {
    console.log(c.yellow("\n  ⚠ AiSOC is up but missing demo data or non-critical config."));
    process.exit(0);
  }
  console.log(c.green("\n  ✓ AiSOC is healthy and ready to investigate."));
  process.exit(0);
}

main().catch((e) => {
  console.error(c.red("doctor crashed:"), e);
  process.exit(2);
});
