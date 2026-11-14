/**
 * `aisoc up` — clone-free launcher for the full local demo stack.
 *
 * Pulls a pinned Docker Compose bundle to a temp dir and boots it, so a user
 * can go from `npx aisoc up` to the seeded console without cloning the repo.
 * This is the heavier (~3.5 min) path; `aisoc triage --demo` is the 60-second
 * wedge. We shell out to `docker compose` and never bundle images.
 */

import { spawn } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import pc from "picocolors";

// Pinned to a released ref so the bundle is reproducible. The compose file is
// fetched from the tagged raw URL (no clone). Bump on each release.
const PINNED_REF = process.env.AISOC_UP_REF || "main";
const COMPOSE_URL = `https://raw.githubusercontent.com/beenuar/AiSOC/${PINNED_REF}/infra/compose/docker-compose.demo.yml`;

export interface UpFlags {
  ref?: string;
  noOpen?: boolean;
  json?: boolean;
}

function run(cmd: string, args: string[], cwd: string): Promise<number> {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { cwd, stdio: "inherit" });
    child.on("close", (code) => resolve(code ?? 1));
    child.on("error", () => resolve(127));
  });
}

async function haveDocker(): Promise<boolean> {
  return (await run("docker", ["--version"], process.cwd())) === 0;
}

export async function runUp(flags: UpFlags, log: (s: string) => void = console.log): Promise<number> {
  if (!(await haveDocker())) {
    log(pc.red("Docker is required for `aisoc up`. Install Docker Desktop, or try the zero-install path:"));
    log(pc.cyan("  npx aisoc triage --demo"));
    return 1;
  }

  const ref = flags.ref || PINNED_REF;
  // Constrain --ref to valid git ref characters so it can only ever select a
  // branch/tag/SHA within the pinned repo's raw path — it can't rewrite the URL
  // to fetch the compose bundle from an arbitrary host.
  if (!/^[A-Za-z0-9._/-]+$/.test(ref)) {
    log(pc.red(`Invalid --ref ${JSON.stringify(ref)}. Expected a branch, tag, or commit SHA.`));
    return 1;
  }
  const url = COMPOSE_URL.replace(PINNED_REF, ref);
  log(pc.dim(`Fetching pinned compose bundle (${ref})…`));

  let composeText: string;
  try {
    const resp = await fetch(url);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    composeText = await resp.text();
  } catch (err) {
    log(pc.red(`Could not fetch the compose bundle: ${(err as Error).message}`));
    log(pc.dim("Falling back to the clone path: git clone https://github.com/beenuar/AiSOC && cd AiSOC && pnpm aisoc:demo"));
    return 1;
  }

  const dir = await mkdtemp(join(tmpdir(), "aisoc-up-"));
  const file = join(dir, "docker-compose.demo.yml");
  await writeFile(file, composeText, "utf8");
  log(pc.dim(`Compose bundle written to ${file}`));
  log(pc.bold("Booting the AiSOC demo stack (this can take a few minutes on first pull)…"));

  const code = await run("docker", ["compose", "-f", file, "up", "-d"], dir);
  if (code !== 0) {
    log(pc.red("docker compose up failed. See the output above."));
    return code;
  }

  log("");
  log(pc.green("✓ AiSOC demo stack is starting."));
  log("  Console:     " + pc.cyan("http://localhost:3000/cases/INC-RT-001?tab=ledger"));
  log("  Stop it:     " + pc.dim(`docker compose -f ${file} down -v`));
  log("");
  return 0;
}
