#!/usr/bin/env node
/**
 * Regenerate the OrcaRouter console evidence: `orca-evidence/*.png` plus the
 * `manifest.json` the review gate reads.
 *
 * The run is hermetic. The spec stubs every `/api/v1/**` response with
 * `page.route()`, so it exercises the real Next.js settings panel without a
 * live OrcaRouter account, and every value it screenshots is one the API
 * contract actually returns.
 *
 * This wrapper exists because the monorepo is a pnpm workspace: a fresh clone
 * has no `node_modules`, and the Playwright `webServer` starts Next through
 * `pnpm exec`. Corepack supplies that binary; where a container has a system
 * Chromium but no Playwright browser cache, the run is pointed at it.
 *
 * `next dev` rewrites the tracked `next-env.d.ts` for the dev server. The
 * original bytes are put back afterwards so a verification run leaves the
 * tree exactly as it found it.
 *
 *   node apps/web/scripts/orcarouter-evidence.mjs
 */
import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const appDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = path.resolve(appDir, "..", "..");
const evidenceDir = process.env.ORCA_EVIDENCE_DIR
  ? path.resolve(process.env.ORCA_EVIDENCE_DIR)
  : path.join(repoRoot, "orca-evidence");

function run(argv, { cwd = repoRoot, env = process.env } = {}) {
  console.log(`+ ${argv.join(" ")}`);
  const result = spawnSync(argv[0], argv.slice(1), {
    cwd,
    env,
    stdio: "inherit",
  });
  if (result.error) {
    throw new Error(String(result.error));
  }
  if (result.status !== 0) {
    throw new Error(`${argv[0]} exited with ${result.status}`);
  }
}

const nextEnv = path.join(appDir, "next-env.d.ts");
const nextEnvBefore = existsSync(nextEnv) ? readFileSync(nextEnv) : null;

try {
  // `pnpm exec` must resolve for the Playwright webServer, which has no shell
  // profile of its own. Corepack writes its shims to a directory we own.
  const shimDir = mkdtempSync(path.join(os.tmpdir(), "orca-pnpm-"));
  run(["corepack", "enable", "--install-directory", shimDir, "pnpm"]);

  const env = {
    ...process.env,
    PATH: `${shimDir}${path.delimiter}${process.env.PATH ?? ""}`,
  };

  if (!existsSync(path.join(repoRoot, "node_modules", ".pnpm"))) {
    run(["pnpm", "install", "--frozen-lockfile"], { env });
  }

  const browserCache = path.join(
    process.env.HOME ?? os.homedir(),
    ".cache",
    "ms-playwright",
  );
  if (
    !env.PLAYWRIGHT_CHROMIUM_EXECUTABLE &&
    !existsSync(browserCache) &&
    existsSync("/usr/bin/chromium")
  ) {
    env.PLAYWRIGHT_CHROMIUM_EXECUTABLE = "/usr/bin/chromium";
  }

  mkdirSync(evidenceDir, { recursive: true });
  env.PLAYWRIGHT_PROJECT = "journey";
  env.ORCA_EVIDENCE_DIR = evidenceDir;

  run(
    [
      "node",
      path.join(appDir, "node_modules", "@playwright", "test", "cli.js"),
      "test",
      "--project=journey",
      "e2e/journeys/orcarouter-settings.spec.ts",
    ],
    { cwd: appDir, env },
  );

  console.log(`evidence written to ${evidenceDir}`);
} catch (error) {
  console.error(String(error));
  process.exitCode = 1;
} finally {
  if (nextEnvBefore === null) {
    rmSync(nextEnv, { force: true });
  } else {
    writeFileSync(nextEnv, nextEnvBefore);
  }
}
