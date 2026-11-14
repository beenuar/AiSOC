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
 * Usage: pnpm aisoc:doctor [--bundle]
 *
 *   --bundle  also write a redacted diagnostics bundle (platform, versions,
 *             check results, container state, redacted log tail, and the
 *             NAMES of the env vars that are set — never their values) that
 *             is safe to attach to a public issue.
 *
 * Exit code 0 = OK, 1 = at least one FAIL.
 */
import { execSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
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
  if (s === "OK") return c.green("PASS");
  if (s === "WARN") return c.yellow("WARN");
  return c.red("FAIL");
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

  // Enforce Compose v2+. Compose v1 (the standalone `docker-compose` Python
  // binary) does not register a `compose` Docker subcommand, so calling
  // `docker compose version` on a v1-only system errors out and tryRun
  // returns null. But on systems that *do* have v2, we want to enforce a
  // minimum of v2.0 because earlier alpha builds had healthcheck and
  // depends_on bugs that surface as opaque container failures.
  const compose = tryRun("docker compose version");
  if (!compose) {
    record(
      "docker compose v2",
      "FAIL",
      "docker compose plugin not installed (Compose v1's `docker-compose` is not supported)"
    );
    return;
  }
  const versionMatch = compose.match(/v?(\d+)\.(\d+)\.(\d+)/);
  if (!versionMatch) {
    record("docker compose v2", "WARN", `unrecognized version string: ${compose}`);
  } else {
    const [, major, minor] = versionMatch;
    const majorNum = parseInt(major, 10);
    if (majorNum < 2) {
      record(
        "docker compose v2",
        "FAIL",
        `Compose v${major}.${minor} detected — AiSOC requires v2.0+`
      );
      return;
    }
    record("docker compose v2", "OK", compose);
  }

  // Docker daemon resource allocation. The #1 source of opaque
  // "container exited" failures on a clean clone is Docker Desktop being
  // under-provisioned: OpenSearch + ClickHouse + Neo4j + Kafka together
  // reserve ~3.5 GB at idle, and the full stack peaks around 5-6 GB.
  const info = tryRun("docker info --format json");
  if (info) {
    try {
      const parsed = JSON.parse(info);
      const memBytes: number = parsed.MemTotal ?? 0;
      const memGb = memBytes / 1024 / 1024 / 1024;
      const memDetail = `Docker daemon has ${memGb.toFixed(1)} GB RAM allocated`;
      if (memGb < 4) {
        record(
          "docker RAM allocation",
          "FAIL",
          `${memDetail} — full stack needs 6 GB+, demo stack needs 4 GB+ (Docker Desktop → Settings → Resources)`
        );
      } else if (memGb < 6) {
        record(
          "docker RAM allocation",
          "WARN",
          `${memDetail} — sufficient for demo stack only; full dev stack will OOM-kill (raise to 6 GB+ in Docker Desktop → Settings → Resources)`
        );
      } else {
        record("docker RAM allocation", "OK", memDetail);
      }
    } catch {
      record("docker RAM allocation", "WARN", "could not parse `docker info` output");
    }
  } else {
    // `docker info` failing usually means the daemon is not running.
    // The container check below will surface a clearer error in that case;
    // here we just note the resource probe was skipped.
    record("docker RAM allocation", "WARN", "could not query daemon (is Docker running?)");
  }

  // Use `docker ps -a` instead of `docker compose ps` so we discover
  // containers across compose projects (the demo stack uses
  // `-f infra/compose/docker-compose.demo.yml` which is a separate project) AND so we can
  // distinguish "container never created" from "container exited" — the most
  // common silent failure mode is the data tier (postgres, redis, kafka)
  // exiting 255 after a Docker Desktop restart while upper services keep
  // running. The `aisoc-` prefix on every container_name in both compose
  // files makes this a safe filter.
  const ps = tryRun("docker ps -a --format json --filter name=aisoc-");
  if (!ps) {
    record(
      "containers running",
      "WARN",
      'no AiSOC containers running — run `pnpm aisoc:demo` (slim) or `docker compose up -d` (full)'
    );
    return;
  }

  const lines = ps.split("\n").filter((l) => l.trim());
  const containers = lines
    .map((l) => {
      try {
        return JSON.parse(l);
      } catch {
        return null;
      }
    })
    .filter(Boolean);

  if (containers.length === 0) {
    record(
      "containers running",
      "WARN",
      "no AiSOC containers up — run `pnpm aisoc:demo` (slim) or `docker compose up -d` (full)"
    );
    return;
  }

  // Detect which stack flavor is present so the per-role check below can give
  // an accurate "looked for X" message and so demo users aren't told to chase
  // services (kafka-ui, neo4j, etc.) that the demo stack intentionally omits.
  // We classify by container *name*, not state, because a wedged data-tier
  // container is still informative about which stack the user tried to run.
  const hasDemo = containers.some((c: any) =>
    typeof c.Names === "string" && c.Names.startsWith("aisoc-demo-")
  );
  const hasFull = containers.some(
    (c: any) =>
      typeof c.Names === "string" &&
      c.Names.startsWith("aisoc-") &&
      !c.Names.startsWith("aisoc-demo-")
  );
  const runningCount = containers.filter((c: any) => c.State === "running").length;
  const stackLabel = hasDemo && hasFull
    ? "demo + full (mixed)"
    : hasDemo
      ? "demo"
      : hasFull
        ? "full"
        : "unknown";
  record(
    "stack flavor",
    "OK",
    `${stackLabel} (${runningCount}/${containers.length} container(s) running)`
  );

  // The full stack uses `aisoc-<role>` names; the demo stack uses
  // `aisoc-demo-<role>`. We accept either prefix for the core services so
  // `pnpm aisoc:demo` users don't see false FAILs.
  const expectedRoles = [
    "api",
    "agents",
    "web",
    "postgres",
    "redis",
    "realtime",
  ];
  for (const role of expectedRoles) {
    const candidates = [`aisoc-${role}`, `aisoc-demo-${role}`];
    const found = containers.find((c: any) => candidates.includes(c.Names));
    if (!found) {
      // No container with this name in either stack — the user probably hasn't
      // booted the corresponding compose file yet, so this is a hint, not a
      // hard failure (the API check below will tell them whether the stack
      // is actually broken).
      record(
        `container ${role}`,
        "WARN",
        `not present (looked for ${candidates.join(" or ")}) — start the stack with \`pnpm aisoc:demo\` or \`docker compose up -d\``
      );
      continue;
    }
    // `docker ps --format json` exposes Status as a free-text string like
    // "Up About an hour (healthy)" / "Up 2 minutes (starting)" / "Exited
    // (255) About an hour ago". Parse the parenthetical for health, and
    // treat "no parens" as "no healthcheck configured" — which we accept as
    // healthy if the container is running.
    const status: string = found.Status ?? "";
    const state: string = found.State ?? "";
    const healthMatch = status.match(/\(([^)]+)\)/);
    const health = healthMatch ? healthMatch[1] : "";
    if (state !== "running") {
      // The most actionable signal we can give: the container exists but
      // exited. The exit code (e.g. "Exited (255)") is in the status string
      // and is exactly what a user should grep `docker logs` for.
      record(
        `container ${role}`,
        "FAIL",
        `${found.Names} ${status.toLowerCase()} — run \`docker logs ${found.Names}\``
      );
      continue;
    }
    const ok = health === "" || health === "healthy";
    record(
      `container ${role}`,
      ok ? "OK" : health === "starting" ? "WARN" : "FAIL",
      `${found.Names} state=${state}${health ? ` health=${health}` : ""}`
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

  // Demo data: at least one alert. The API is mounted at `/api/v1`
  // (services/api/app/api/v1/router.py), not `/v1` — using the wrong
  // prefix here used to produce a permanent false FAIL after a clean
  // `pnpm aisoc:demo`.
  const alerts = await fetchJson("http://localhost:8000/api/v1/alerts?limit=1");
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

// ---------- Diagnostics bundle ----------
//
// Most "the demo didn't work" reports arrive with no way to tell which of the
// dozen moving parts failed, and the obvious fix — "paste your logs" — invites
// people to paste credentials into a public issue. `--bundle` collects the
// same evidence a maintainer would ask for, with secrets stripped, into one
// file that is safe to attach.

/** Mask anything that looks like a credential, wherever it appears. */
function redact(text: string): string {
  return (
    text
      // KEY=value / "key": "value" for any key whose name smells sensitive.
      .replace(
        /((?:secret|token|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|credential|authorization|bearer)\w*\s*[=:]\s*")([^"]+)(")/gi,
        "$1<redacted>$3"
      )
      .replace(
        /((?:SECRET|TOKEN|PASSWORD|PASSWD|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL)\w*\s*=\s*)(\S+)/gi,
        "$1<redacted>"
      )
      // Vendor key shapes that carry no key name next to them.
      .replace(/\b(sk-[A-Za-z0-9_-]{16,})\b/g, "<redacted-openai-key>")
      .replace(/\b(xox[abprs]-[A-Za-z0-9-]{10,})\b/g, "<redacted-slack-token>")
      .replace(/\b(gh[pousr]_[A-Za-z0-9]{20,})\b/g, "<redacted-github-token>")
      .replace(/\b(AKIA[0-9A-Z]{16})\b/g, "<redacted-aws-key-id>")
      .replace(/\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, "<redacted-jwt>")
      // Connection strings: keep the shape, drop the password.
      .replace(/(:\/\/[^:/@\s]+:)([^@\s]+)(@)/g, "$1<redacted>$3")
  );
}

function writeBundle(): string {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const path = join(ROOT, `aisoc-doctor-bundle-${stamp}.json`);

  // Env var NAMES only — never values. Knowing which keys are set is the
  // diagnostic signal; the values are exactly what must not leave the machine.
  let envKeys: string[] = [];
  const envPath = join(ROOT, ".env");
  if (existsSync(envPath)) {
    envKeys = readFileSync(envPath, "utf8")
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith("#") && line.includes("="))
      .map((line) => line.split("=")[0]);
  }

  const bundle = {
    generatedAt: new Date().toISOString(),
    note:
      "Generated by `pnpm aisoc:doctor --bundle`. Values of environment " +
      "variables are never included; only their names. Logs are passed " +
      "through a credential redactor. Review before sharing.",
    platform: {
      os: process.platform,
      arch: process.arch,
      node: process.version,
      pnpm: tryRun("pnpm --version"),
      docker: tryRun("docker --version"),
      compose: tryRun("docker compose version --short"),
    },
    repo: {
      commit: tryRun("git rev-parse --short HEAD"),
      branch: tryRun("git rev-parse --abbrev-ref HEAD"),
      dirty: tryRun("git status --porcelain") ? true : false,
      version: existsSync(join(ROOT, "VERSION"))
        ? readFileSync(join(ROOT, "VERSION"), "utf8").trim()
        : null,
    },
    checks,
    envKeysPresent: envKeys,
    // Written by `pnpm aisoc:demo` on every run. Phase timings are usually
    // enough on their own to show where a failed boot actually stalled.
    lastDemoRun: existsSync(join(ROOT, ".aisoc", "last-demo-run.json"))
      ? JSON.parse(readFileSync(join(ROOT, ".aisoc", "last-demo-run.json"), "utf8"))
      : null,
    containers: redact(tryRun("docker compose ps --format json") ?? ""),
    logsTail: redact(tryRun("docker compose logs --tail 200 --no-color") ?? ""),
  };

  writeFileSync(path, JSON.stringify(bundle, null, 2));
  return path;
}

// ---------- Run ----------
async function main() {
  const wantBundle = process.argv.includes("--bundle");

  console.log(c.bold("AiSOC Doctor") + c.dim(" — pre-flight check"));
  await checkEnv();
  await checkDocker();
  await checkPorts();
  await checkApi();
  await checkWeb();

  if (wantBundle) {
    const path = writeBundle();
    console.log(c.bold("\nDiagnostics bundle"));
    console.log(`  ${path}`);
    console.log(
      c.dim("  Env var values excluded, logs redacted. Skim it, then attach it to your issue.")
    );
  }

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
      c.red("\n  AiSOC is not healthy. ") +
        "See the failing checks above. " +
        c.dim("Quickstart: https://github.com/beenuar/AiSOC#quickstart")
    );
    process.exit(1);
  }
  if (warns > 0) {
    console.log(c.yellow("\n  AiSOC is up but missing demo data or non-critical config."));
    process.exit(0);
  }
  console.log(c.green("\n  AiSOC is healthy."));
  process.exit(0);
}

main().catch((e) => {
  console.error(c.red("doctor crashed:"), e);
  process.exit(2);
});
