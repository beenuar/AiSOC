#!/usr/bin/env node
/**
 * @aisoc/mcp — entry point.
 *
 * Subcommands:
 *
 *   serve     Run the stdio MCP server (default if no command given).
 *   install   Configure a host (Claude / Cursor / Cody / Continue) to launch us.
 *   doctor    Pre-flight: env, network, auth.
 *   help      Print this help.
 *   version   Print the package version.
 *
 * Why a hand-rolled parser instead of commander/yargs:
 *   1. We are publishing to npm as `npx @aisoc/mcp`. Every dep we add lengthens
 *      the cold-install path users see when invoking us through Claude/Cursor.
 *      The full parser we need fits in ~80 lines.
 *   2. `config.parseArgs` is shared by `serve` and `doctor`, so the surface
 *      stays consistent.
 */
import process from "node:process";

import { type ParsedArgs, parseArgs, packageVersion, resolveConfig, makeLogger } from "./config.js";
import { runDoctor, printDoctorReport } from "./doctor.js";
import { runServer } from "./server.js";
import {
  install,
  knownConfigPaths,
  resolveEntryPath,
  type Host,
  type Launcher,
} from "./installers/index.js";

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const args = parseArgs(argv);

  if (args.flags.help === true || args.command === "help") {
    printHelp();
    return;
  }
  if (args.flags.version === true || args.command === "version") {
    process.stdout.write(`${packageVersion()}\n`);
    return;
  }

  switch (args.command) {
    case "serve":
      await cmdServe(args);
      return;
    case "doctor":
      await cmdDoctor(args);
      return;
    case "install":
      await cmdInstall(args);
      return;
    default: {
      // Should be unreachable; parseArgs collapses unknowns to "help".
      const _exhaustive: never = args.command as never;
      void _exhaustive;
      printHelp();
      process.exitCode = 2;
    }
  }
}

// ---------------------------------------------------------------------------
// serve
// ---------------------------------------------------------------------------

async function cmdServe(args: ParsedArgs): Promise<void> {
  const cfg = resolveConfig(args);
  const log = makeLogger(cfg);
  // No banner on stdout — that channel is reserved for JSON-RPC frames.
  // `runServer` logs its lifecycle to stderr.
  await runServer(cfg, log);
}

// ---------------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------------

async function cmdDoctor(args: ParsedArgs): Promise<void> {
  const cfg = resolveConfig(args);
  // doctor prints a human report on stdout (it's a CLI command, not an MCP
  // session), so the logger is configured to forward its own output to stderr
  // only when --verbose is passed.
  const log = makeLogger(cfg);
  const report = await runDoctor(cfg, log);
  printDoctorReport(report);
  if (!report.ok) process.exitCode = 1;
}

// ---------------------------------------------------------------------------
// install
// ---------------------------------------------------------------------------

async function cmdInstall(args: ParsedArgs): Promise<void> {
  const hostFlag = String(args.flags.host ?? args.positional[0] ?? "").toLowerCase();
  if (args.flags["list-paths"] === true) {
    const paths = knownConfigPaths();
    process.stdout.write(JSON.stringify(paths, null, 2) + "\n");
    return;
  }
  if (!isHost(hostFlag)) {
    process.stderr.write(
      [
        "aisoc-mcp install — choose a host:",
        "  --host claude    Claude Desktop",
        "  --host cursor    Cursor IDE",
        "  --host continue  Continue.dev",
        "  --host cody      Sourcegraph Cody (prints snippet)",
        "",
        "  --aisoc-url <url>          AiSOC API base URL (default http://localhost:8081)",
        "  --api-key <token>          API key to embed (or set AISOC_API_KEY)",
        "  --launcher <auto|node|npx> How the host should start the server. Default auto:",
        "                             `node <abs path>` from a monorepo build, `npx` from",
        "                             an installed package. `npx` only resolves once",
        "                             @aisoc/mcp is published.",
        "  --dry-run                  Show what would be written without changing files",
        "  --list-paths               Print where each host's config lives, as JSON",
        "",
      ].join("\n"),
    );
    process.exitCode = 2;
    return;
  }

  const launcherFlag = String(args.flags.launcher ?? "auto").toLowerCase();
  if (!isLauncher(launcherFlag)) {
    process.stderr.write(
      `install failed: --launcher must be one of auto, node, npx (got ${launcherFlag || "empty"}).\n`,
    );
    process.exitCode = 2;
    return;
  }

  const cfg = resolveConfig(args);
  const dryRun = args.flags["dry-run"] === true;
  let result;
  try {
    result = install({ host: hostFlag, cfg, dryRun, launcher: launcherFlag });
  } catch (err) {
    process.stderr.write(`install failed: ${(err as Error).message}\n`);
    process.exitCode = 1;
    return;
  }

  // Say which launcher was chosen and why. An `npx` entry written from a
  // source build is the one failure mode that looks like success right up
  // until the host tries to start it, so make the choice visible here
  // rather than leaving the user to read the JSON.
  if (result.snippet.command === "npx") {
    process.stderr.write(
      "note: wrote an `npx -y @aisoc/mcp` entry. That resolves only after the\n" +
        "      package is published to npm; publication is blocked on registry\n" +
        "      credentials. Re-run with `--launcher node` to point the host at\n" +
        `      this build directly (${resolveEntryPath()}).\n`,
    );
  }

  if (dryRun) {
    process.stdout.write(
      `[dry-run] would write to ${result.configPath ?? "(no file)"}\n` +
        JSON.stringify({ aisoc: result.snippet }, null, 2) +
        "\n",
    );
    return;
  }

  process.stdout.write(`${result.message}\n`);
}

function isHost(s: string): s is Host {
  return s === "claude" || s === "cursor" || s === "cody" || s === "continue";
}

function isLauncher(s: string): s is Launcher {
  return s === "auto" || s === "node" || s === "npx";
}

// ---------------------------------------------------------------------------
// help
// ---------------------------------------------------------------------------

function printHelp(): void {
  process.stdout.write(
    [
      "@aisoc/mcp — connect AiSOC to MCP-aware assistants",
      "",
      "Usage:",
      "  node dist/index.js <command> [options]   # monorepo source build (works today)",
      "  npx -y @aisoc/mcp <command> [options]    # once published to npm",
      "",
      "Commands:",
      "  serve              Run the stdio MCP server (default).",
      "  install --host <h> Configure Claude Desktop / Cursor / Continue / Cody to launch this server.",
      "  doctor             Verify env, network reachability, and AiSOC API auth.",
      "  help               Show this message.",
      "  version            Print the package version.",
      "",
      "Common options:",
      "  --aisoc-url <url>      Base URL of the AiSOC API. Env: AISOC_URL.",
      "                         Default: http://localhost:8081",
      "  --api-key <token>      API key (aisoc_… or JWT). Env: AISOC_API_KEY.",
      "  --timeout <ms>         Per-request timeout. Env: AISOC_TIMEOUT_MS. Default 20000.",
      "  --verbose              Log lifecycle events to stderr.",
      "",
      "Install options:",
      "  --host <h>             claude | cursor | continue | cody",
      "  --launcher <l>         auto (default) | node | npx. `auto` writes a direct",
      "                         `node <abs path>` entry from a source build and `npx`",
      "                         from an installed package. @aisoc/mcp is not yet on",
      "                         npm — publication is blocked on registry credentials.",
      "  --dry-run              Print the config entry instead of writing it.",
      "  --list-paths           Print each host's config location as JSON.",
      "",
      "Examples:",
      "  node dist/index.js install --host claude --aisoc-url https://aisoc.acme.corp --api-key aisoc_xxxx",
      "  AISOC_URL=https://aisoc.acme.corp AISOC_API_KEY=aisoc_xxxx node dist/index.js doctor",
      "  node dist/index.js serve   # invoked by the host, not by you",
      "",
    ].join("\n"),
  );
}

// ---------------------------------------------------------------------------
// boot
// ---------------------------------------------------------------------------

main().catch((err: unknown) => {
  // Last-resort handler. `runServer` and `runDoctor` already format their own
  // errors; this catches programmer mistakes that escape both. We write to
  // stderr so we don't poison the JSON-RPC stream if this fires during serve.
  const msg = err instanceof Error ? err.stack ?? err.message : String(err);
  process.stderr.write(`aisoc-mcp: fatal: ${msg}\n`);
  process.exit(1);
});
