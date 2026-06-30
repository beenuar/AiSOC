#!/usr/bin/env tsx
/**
 * aisoc:acceptance — WS-A acceptance gate harness.
 *
 * Wraps `pnpm aisoc:demo` with strict clone-to-investigation budget
 * enforcement, cold-start support, and JSONL ledger tracking so we can
 * spot acceptance regressions across runs.
 *
 * Acceptance criterion (from the v1.0 buyer-value plan, WS-A):
 *
 *   "stopwatch clone-to-investigation ≤ 5 min on clean Mac"
 *
 * What this script measures:
 *
 *   1. Tear down any running demo stack (volumes + images stay unless --cold).
 *   2. Optionally prune the demo images (--cold) to simulate first-clone state
 *      where Docker has to re-pull from GHCR. This is the buyer's worst-case.
 *   3. Run `pnpm aisoc:demo --no-open --budget-ms <ms> --results-file <tmp>`
 *      which:
 *        - verifies Docker
 *        - pulls images
 *        - boots the stack
 *        - waits for health
 *        - seeds demo data (idempotent)
 *        - finds the showcase case (INC-RT-001)
 *        - kicks off an investigation
 *      The demo script writes a phase-by-phase JSON timing report.
 *   4. Append the report to .aisoc/acceptance-history.jsonl as a single line so
 *      humans and CI can diff trends without reaching for a database.
 *   5. Print a verdict and exit:
 *        0 = passed (under budget, all phases reached)
 *        1 = stack failure (demo couldn't boot)
 *        2 = harness crash
 *        3 = over budget (acceptance regression — stack works but is too slow)
 *        4 = stack came up but kickoff/seed didn't reach the showcase case
 *
 * Usage:
 *   pnpm aisoc:acceptance                  # default 5-minute budget, warm start
 *   pnpm aisoc:acceptance --cold           # prune images first (true clean Mac)
 *   pnpm aisoc:acceptance --budget-ms 360000   # 6 minutes (for slower CI)
 *   pnpm aisoc:acceptance --history-only   # just print the trend, no run
 *
 * Why a separate script (and not just `aisoc:demo --budget-ms`)?
 *   - aisoc:demo is the developer ergonomic tool; the user expects it to
 *     leave the stack running and open a browser. The acceptance run wants
 *     headless, reproducible, ledger-tracked behaviour.
 *   - Pre-run teardown belongs to the harness, not the day-to-day demo.
 *   - Trend tracking (history JSONL) is an acceptance concern, not a demo one.
 *
 * Why not a shell script?
 *   - We already need to parse the JSON results file the demo emits.
 *   - tsx is already a dev dep and used by aisoc:demo / aisoc:doctor.
 *   - Cross-platform behaviour (macOS dev box + Linux CI) without bashisms.
 */
import { execSync, spawnSync } from "node:child_process";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  unlinkSync,
} from "node:fs";
import { hostname, platform, release } from "node:os";
import { join } from "node:path";

const ROOT = join(__dirname, "..");
const COMPOSE_FILE = join(ROOT, "infra/compose/docker-compose.demo.yml");
const HISTORY_DIR = join(ROOT, ".aisoc");
const HISTORY_FILE = join(HISTORY_DIR, "acceptance-history.jsonl");
const DEFAULT_BUDGET_MS = 5 * 60 * 1000; // WS-A acceptance: 5 minutes.

const c = {
  green: (s: string) => `\x1b[32m${s}\x1b[0m`,
  yellow: (s: string) => `\x1b[33m${s}\x1b[0m`,
  red: (s: string) => `\x1b[31m${s}\x1b[0m`,
  blue: (s: string) => `\x1b[34m${s}\x1b[0m`,
  bold: (s: string) => `\x1b[1m${s}\x1b[0m`,
  dim: (s: string) => `\x1b[2m${s}\x1b[0m`,
};

interface Flags {
  cold: boolean;
  budgetMs: number;
  // historyOnly skips the run and just prints the ledger trend. Useful for
  // a quick "are we trending faster or slower over the last N commits?" peek.
  historyOnly: boolean;
  tag: string;
  // keepStack leaves the demo containers up after the run. By default we tear
  // down because acceptance is a "did this clean clone reach an investigation"
  // question — leftover containers obscure the answer for the next run.
  keepStack: boolean;
}

function parseFlags(argv: string[]): Flags {
  const flags: Flags = {
    cold: false,
    budgetMs: DEFAULT_BUDGET_MS,
    historyOnly: false,
    tag: "latest",
    keepStack: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--cold") flags.cold = true;
    else if (a === "--history-only") flags.historyOnly = true;
    else if (a === "--keep-stack") flags.keepStack = true;
    else if (a === "--budget-ms") {
      const raw = argv[++i];
      const n = raw ? Number.parseInt(raw, 10) : Number.NaN;
      if (Number.isFinite(n) && n > 0) flags.budgetMs = n;
    } else if (a === "--tag") {
      flags.tag = argv[++i] ?? "latest";
    } else if (a === "--help" || a === "-h") {
      printHelp();
      process.exit(0);
    }
  }
  return flags;
}

function printHelp(): void {
  console.log(`aisoc:acceptance — WS-A acceptance gate harness

Usage: pnpm aisoc:acceptance [flags]

Flags:
  --cold                Prune demo images first (simulates a fresh clone)
  --budget-ms <number>  Override 5-minute budget (default ${DEFAULT_BUDGET_MS}ms)
  --tag <tag>           Override AISOC_TAG (default latest)
  --keep-stack          Don't tear down the demo stack after the run
  --history-only        Print the trend ledger and exit (no run)
  -h, --help            This help

Exit codes:
  0 = passed (under budget, investigation kicked off)
  1 = stack failure
  2 = harness crash
  3 = over budget (acceptance regression)
  4 = seed/kickoff regression (stack up but no investigation reached)
`);
}

function tearDownStack(): void {
  console.log(c.dim("  tearing down any running demo stack..."));
  // stdio:ignore because compose chats a lot about not-found resources on a
  // truly clean machine, and that noise hides the meaningful output below.
  spawnSync("docker", ["compose", "-f", COMPOSE_FILE, "down", "-v"], {
    cwd: ROOT,
    stdio: "ignore",
  });
}

function pruneImages(tag: string): void {
  console.log(c.dim(`  pruning aisoc images for tag=${tag} (cold start)...`));
  // We deliberately target only ghcr.io/aisoc-community/* images for the
  // requested tag. Pruning the whole `docker image prune -a` would nuke
  // unrelated work on the developer's machine and that's a hostile move.
  // The list-then-rm pattern is a no-op when nothing matches.
  const list = spawnSync(
    "docker",
    [
      "images",
      `ghcr.io/aisoc-community/aisoc-*:${tag}`,
      "--quiet",
    ],
    { encoding: "utf8" },
  );
  const ids = (list.stdout ?? "")
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
  if (ids.length === 0) {
    console.log(c.dim("    no matching images cached — already cold"));
    return;
  }
  // -f because the showcase case can leave behind containers (we just
  // tore the stack down, but `docker rmi` won't trust that and will
  // refuse without --force).
  spawnSync("docker", ["rmi", "-f", ...ids], { stdio: "ignore" });
  console.log(c.dim(`    removed ${ids.length} image layers`));
}

interface DemoReport {
  finishedAt: string;
  totalMs: number;
  totalLabel: string;
  budgetMs: number | null;
  withinBudget: boolean | null;
  showcaseCaseFound: boolean;
  investigationKickedOff: boolean;
  flags: { rebuild: boolean; noPull: boolean; noOpen: boolean; tag: string };
  phases: Array<{ name: string; durationMs: number; label: string }>;
}

interface HistoryEntry extends DemoReport {
  // Extra envelope fields the harness adds on top of the demo's report so
  // the ledger tells the full story without a second join.
  cold: boolean;
  exitCode: number;
  hostname: string;
  platform: string;
  release: string;
  gitSha: string | null;
  gitBranch: string | null;
}

function tryGit(args: string[]): string | null {
  try {
    return execSync(`git ${args.join(" ")}`, {
      cwd: ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  } catch {
    return null;
  }
}

function runDemo(flags: Flags, resultsFile: string): number {
  const args = [
    "tsx",
    "scripts/aisoc-demo.ts",
    "--no-open",
    "--budget-ms",
    String(flags.budgetMs),
    "--results-file",
    resultsFile,
    "--tag",
    flags.tag,
  ];
  console.log(c.dim(`  spawning: pnpm exec ${args.join(" ")}`));
  // stdio: inherit so the user sees the demo's progress in real-time. The
  // demo writes its JSON report to disk so we don't have to capture stdout.
  const result = spawnSync("pnpm", ["exec", ...args], {
    cwd: ROOT,
    stdio: "inherit",
    env: { ...process.env, AISOC_TAG: flags.tag },
  });
  // result.status === null means the process was killed by a signal; treat
  // that as a crash (exit 2) so CI doesn't silently misclassify it.
  return result.status ?? 2;
}

function readReport(path: string): DemoReport | null {
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, "utf8")) as DemoReport;
  } catch (e: any) {
    console.error(c.red(`  failed to parse demo report: ${e?.message ?? e}`));
    return null;
  }
}

function writeHistoryEntry(entry: HistoryEntry): void {
  if (!existsSync(HISTORY_DIR)) mkdirSync(HISTORY_DIR, { recursive: true });
  // JSONL — newline-delimited so `tail`, `jq`, and `wc -l` all just work.
  // No rotation: 1 KB per run × 1000 runs = 1 MB; that's years of acceptance
  // data. If this ever becomes a problem, .aisoc/ is gitignored anyway.
  appendFileSync(HISTORY_FILE, JSON.stringify(entry) + "\n");
}

function printHistoryTrend(): void {
  if (!existsSync(HISTORY_FILE)) {
    console.log(c.dim("no acceptance history yet — run `pnpm aisoc:acceptance` once."));
    return;
  }
  const lines = readFileSync(HISTORY_FILE, "utf8")
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
  if (lines.length === 0) {
    console.log(c.dim("history file empty"));
    return;
  }
  // Show last 10 runs — enough to see a regression band, not so many the
  // terminal becomes unreadable. Anyone wanting more can `cat` the file.
  const recent = lines.slice(-10);
  console.log(c.bold(`acceptance history — last ${recent.length} run(s)`));
  console.log(
    c.dim("  finished              total      budget  verdict   cold  exit  sha"),
  );
  console.log(c.dim("  " + "-".repeat(72)));
  for (const line of recent) {
    try {
      const e = JSON.parse(line) as HistoryEntry;
      const verdict =
        e.exitCode === 0
          ? c.green("PASS")
          : e.exitCode === 3
            ? c.yellow("SLOW")
            : c.red("FAIL");
      const cold = e.cold ? c.yellow("yes") : c.dim("no ");
      const sha = (e.gitSha ?? "------").slice(0, 7);
      const total = e.totalLabel.padStart(8);
      const budget = e.budgetMs ? msToLabel(e.budgetMs).padStart(6) : "  none";
      const finished = e.finishedAt.replace("T", " ").slice(0, 19);
      console.log(
        `  ${finished}  ${total}  ${budget}  ${verdict}      ${cold}   ${String(e.exitCode).padStart(3)}   ${sha}`,
      );
    } catch {
      // Don't let one bad line poison the trend view.
    }
  }
}

function msToLabel(ms: number): string {
  const total = Math.round(ms / 1000);
  const m = Math.floor(total / 60);
  const s = total % 60;
  return m > 0 ? `${m}m${String(s).padStart(2, "0")}` : `${s}s`;
}

async function main(): Promise<void> {
  const flags = parseFlags(process.argv.slice(2));

  if (flags.historyOnly) {
    printHistoryTrend();
    process.exit(0);
  }

  console.log(
    c.bold("AiSOC Acceptance Gate") +
      c.dim(
        ` — budget=${msToLabel(flags.budgetMs)} · tag=${flags.tag}` +
          (flags.cold ? " · cold" : " · warm"),
      ),
  );
  console.log(
    c.dim(
      "WS-A: stopwatch clone-to-investigation ≤ " +
        msToLabel(flags.budgetMs) +
        " on clean Mac\n",
    ),
  );

  // 1. Always start from a clean stack. Otherwise we'd be measuring "warm
  //    restart" which is what aisoc:doctor cares about, not WS-A.
  tearDownStack();

  // 2. Cold start = nuke the demo images so docker has to re-pull. Only do
  //    this when explicitly asked because pulling 5+ images on a slow
  //    network is the slowest realistic phase of clone-to-investigation
  //    and we don't want to inflict it on a developer who just wants a
  //    pass/fail.
  if (flags.cold) pruneImages(flags.tag);

  // 3. Run the demo via the orchestrator and capture its phase-by-phase JSON.
  //    /tmp keeps the temp file out of the repo even if we crash mid-run.
  const resultsFile = `/tmp/aisoc-acceptance-${Date.now()}.json`;
  const exitCode = runDemo(flags, resultsFile);
  const report = readReport(resultsFile);

  // 4. Always tear down the stack unless --keep-stack so the next run is
  //    clean. We do this before recording history so a Ctrl-C between
  //    "stack up" and "history written" doesn't leave dangling containers.
  if (!flags.keepStack) {
    console.log(c.dim("\n  tearing down stack (use --keep-stack to inspect)..."));
    tearDownStack();
  }

  if (!report) {
    // No JSON usually means the demo hard-failed before reaching the report
    // emit step — bad Docker, missing compose file, or it crashed. Pass the
    // demo's exit code through unchanged so the caller sees the right signal.
    console.error(c.red("\nno acceptance report produced — see demo output above"));
    process.exit(exitCode || 2);
  }

  // 5. Decide the harness verdict. Prefer the demo's exit code (which already
  //    encodes 0/1/2/3 correctly), but layer on exit 4 for the "stack came
  //    up but the showcase case never appeared" failure mode — a regression
  //    that would otherwise pass as exit 0 because the boot didn't fail.
  let harnessExit = exitCode;
  if (
    harnessExit === 0 &&
    (!report.showcaseCaseFound || !report.investigationKickedOff)
  ) {
    harnessExit = 4;
  }

  // 6. Record to ledger. Includes git/host context so a future run can tell
  //    "this regression started on commit X" or "Linux CI is consistently
  //    slower than my Mac" without rummaging through CI logs.
  const entry: HistoryEntry = {
    ...report,
    cold: flags.cold,
    exitCode: harnessExit,
    hostname: hostname(),
    platform: platform(),
    release: release(),
    gitSha: tryGit(["rev-parse", "HEAD"]),
    gitBranch: tryGit(["rev-parse", "--abbrev-ref", "HEAD"]),
  };
  writeHistoryEntry(entry);

  // 7. Cleanup temp file.
  try {
    unlinkSync(resultsFile);
  } catch {
    // Best-effort; /tmp will sweep it.
  }

  // 8. Final verdict block — visually separated so the result is obvious
  //    even when the demo's own output is hundreds of lines long.
  console.log("\n" + c.bold("=".repeat(60)));
  if (harnessExit === 0) {
    console.log(
      c.bold(c.green(`ACCEPTANCE PASS — ${report.totalLabel} (under ${msToLabel(flags.budgetMs)})`)),
    );
    console.log(
      c.dim(
        `  showcase case: ${report.showcaseCaseFound ? "found" : "missing"} · ` +
          `investigation: ${report.investigationKickedOff ? "kicked off" : "not started"}`,
      ),
    );
  } else if (harnessExit === 3) {
    console.log(
      c.bold(c.yellow(`ACCEPTANCE REGRESSION — ${report.totalLabel} (over ${msToLabel(flags.budgetMs)})`)),
    );
    const overBy = report.totalMs - flags.budgetMs;
    console.log(
      c.yellow(
        `  exceeded budget by ${msToLabel(overBy)}. Stack booted, investigation reached, but too slow.`,
      ),
    );
    // Surface the slowest phase so the regression triage starts in the
    // right place.
    const slowest = [...report.phases].sort((a, b) => b.durationMs - a.durationMs)[0];
    if (slowest) {
      console.log(
        c.dim(`  slowest phase: "${slowest.name}" (${slowest.label}) — start there.`),
      );
    }
  } else if (harnessExit === 4) {
    console.log(c.bold(c.red("ACCEPTANCE FAIL — investigation never reached")));
    console.log(
      c.red(
        `  stack booted in ${report.totalLabel}, but ` +
          (!report.showcaseCaseFound
            ? "the showcase case (INC-RT-001) wasn't seeded."
            : "the investigation kickoff failed."),
      ),
    );
  } else {
    console.log(c.bold(c.red(`ACCEPTANCE FAIL — exit ${harnessExit}`)));
    console.log(c.dim("  the demo couldn't boot a healthy stack. See output above."));
  }
  console.log(c.bold("=".repeat(60)));
  console.log(c.dim(`  history: ${HISTORY_FILE}`));
  console.log(c.dim("  view trend: pnpm aisoc:acceptance --history-only\n"));

  process.exit(harnessExit);
}

main().catch((e) => {
  console.error(c.red("\naisoc:acceptance crashed:"), e);
  process.exit(2);
});
