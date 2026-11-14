/**
 * `aisoc-mcp install` — write a configured server entry into the host's
 * MCP config file so users don't have to hand-edit JSON.
 *
 * We support four hosts on first ship:
 *
 *   - Claude Desktop (`~/Library/Application Support/Claude/claude_desktop_config.json`
 *                     on macOS, `%APPDATA%\Claude\claude_desktop_config.json` on Windows)
 *   - Cursor          (`~/.cursor/mcp.json`)
 *   - Cody            (extension config, prints instructions only)
 *   - Continue        (`~/.continue/config.json`)
 *
 * For Cody we don't have a stable JSON config path that's safe to write to
 * (the extension reads VS Code settings); we surface the snippet to paste
 * instead. That's still a 30-second improvement over hunting it down on
 * the docs site.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import type { ServerConfig } from "../config.js";

export type Host = "claude" | "cursor" | "cody" | "continue";

/**
 * How the host should start us.
 *
 * `npx` resolves `@aisoc/mcp` from a public registry. That entry is only
 * launchable once the package is actually published, and today it is not:
 * `release.yml` builds and packs on every tag but the upload is blocked on
 * registry credentials. Writing it unconditionally produced a config file
 * that parsed, installed cleanly, reported success — and could never start,
 * because `npx` would 404 at launch time inside the host, where the user
 * sees "server failed" and no reason.
 *
 * `node` points at this checkout's own `dist/index.js` by absolute path,
 * which is what actually works from a monorepo build.
 */
export type Launcher = "auto" | "npx" | "node";

export interface InstallOptions {
  host: Host;
  cfg: ServerConfig;
  /** Override config-file location (used by tests). */
  configPath?: string;
  /** If true, print what we would do without writing. */
  dryRun?: boolean;
  /** Launcher to write. Defaults to `auto` (detect source build vs installed package). */
  launcher?: Launcher;
  /** Override the resolved entry-point path (used by tests). */
  entryPath?: string;
}

export interface InstallResult {
  host: Host;
  /** Where we wrote (or would have written). May be absent for Cody. */
  configPath?: string;
  /** True if we wrote a new server entry; false if it was already present. */
  changed: boolean;
  /** Human-readable next steps for the user. */
  message: string;
  /** The JSON snippet we wrote, for display / dry-run. */
  snippet: Record<string, unknown>;
}

/**
 * Install the AiSOC server into the requested host. Idempotent: re-running
 * with the same arguments is a no-op (returns `changed: false`).
 */
export function install(opts: InstallOptions): InstallResult {
  const snippet = buildServerSnippet(opts.cfg, opts.launcher ?? "auto", opts.entryPath);
  switch (opts.host) {
    case "claude":
      return installToJsonConfig({
        host: "claude",
        configPath: opts.configPath ?? claudeConfigPath(),
        rootKey: "mcpServers",
        serverName: "aisoc",
        snippet,
        dryRun: opts.dryRun,
        followUp:
          "Restart Claude Desktop (Cmd+Q then reopen) so it re-reads the config.",
      });
    case "cursor":
      return installToJsonConfig({
        host: "cursor",
        configPath: opts.configPath ?? cursorConfigPath(),
        rootKey: "mcpServers",
        serverName: "aisoc",
        snippet,
        dryRun: opts.dryRun,
        followUp:
          "Open Cursor → Settings → MCP and confirm the `aisoc` server shows green.",
      });
    case "continue":
      return installToJsonConfig({
        host: "continue",
        configPath: opts.configPath ?? continueConfigPath(),
        rootKey: "mcpServers",
        serverName: "aisoc",
        snippet,
        dryRun: opts.dryRun,
        followUp:
          "Reload the Continue panel (Cmd/Ctrl+Shift+P → 'Continue: Reload Window').",
      });
    case "cody":
      // Cody currently reads MCP config from VS Code settings JSON. We don't
      // attempt to merge into that (too many user-specific shapes), and instead
      // print the snippet to paste under "cody.mcp.servers". That's documented
      // here so we can flip to direct write once the schema stabilises.
      return {
        host: "cody",
        changed: false,
        snippet,
        message: [
          "Cody reads MCP config from VS Code settings.",
          "Paste this under `cody.mcp.servers` in your User Settings (JSON):",
          "",
          JSON.stringify({ aisoc: snippet }, null, 2),
        ].join("\n"),
      };
  }
}

// ---------------------------------------------------------------------------
// snippet construction
// ---------------------------------------------------------------------------

/**
 * Absolute path to this build's `dist/index.js` — the file with the shebang
 * that `bin.aisoc-mcp` points at. We resolve it from our own module URL
 * rather than from `process.cwd()` or `process.argv[1]`: the host launches
 * the config we write from an arbitrary working directory, and `argv[1]`
 * is the shim path when invoked through a `bin` symlink.
 */
export function resolveEntryPath(): string {
  // This module lives at `dist/installers/index.js`; the entry is one up.
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "index.js");
}

/**
 * True when this copy was resolved out of a package install rather than a
 * monorepo build, which is the only situation where `npx @aisoc/mcp` can
 * find something to run.
 */
function isInstalledPackage(entryPath: string): boolean {
  return entryPath.split(path.sep).includes("node_modules");
}

/**
 * Produce the per-server JSON entry.
 *
 * URL/key/timeout/verbose flow in via env rather than argv to keep the secret
 * out of `ps`. The command itself depends on where this copy came from — see
 * {@link Launcher} for why writing `npx` unconditionally was wrong.
 */
function buildServerSnippet(
  cfg: ServerConfig,
  launcher: Launcher,
  entryPathOverride?: string,
): Record<string, unknown> {
  const env: Record<string, string> = { AISOC_URL: cfg.aisocUrl };
  if (cfg.apiKey) env.AISOC_API_KEY = cfg.apiKey;
  if (cfg.timeoutMs && cfg.timeoutMs !== 20_000) {
    env.AISOC_TIMEOUT_MS = String(cfg.timeoutMs);
  }
  // `resolveConfig` reads AISOC_MCP_VERBOSE. This wrote AISOC_VERBOSE, so
  // `install --verbose` produced a host config whose verbose flag the server
  // never looked at — the one setting whose whole purpose is diagnosing a
  // server that is misbehaving.
  if (cfg.verbose) env.AISOC_MCP_VERBOSE = "1";

  const entryPath = entryPathOverride ?? resolveEntryPath();
  const resolved: Exclude<Launcher, "auto"> =
    launcher === "auto" ? (isInstalledPackage(entryPath) ? "npx" : "node") : launcher;

  switch (resolved) {
    case "npx":
      return { command: "npx", args: ["-y", "@aisoc/mcp", "serve"], env };
    case "node":
      return { command: "node", args: [entryPath, "serve"], env };
    default: {
      const exhaustive: never = resolved;
      throw new Error(`unhandled launcher: ${String(exhaustive)}`);
    }
  }
}

// ---------------------------------------------------------------------------
// JSON-config writer
// ---------------------------------------------------------------------------

interface JsonInstallArgs {
  host: Host;
  configPath: string;
  rootKey: string;
  serverName: string;
  snippet: Record<string, unknown>;
  dryRun?: boolean;
  followUp: string;
}

function installToJsonConfig(args: JsonInstallArgs): InstallResult {
  const existing = readJsonOrEmpty(args.configPath);
  const root = (existing[args.rootKey] as Record<string, unknown> | undefined) ??
    {};
  const previous = root[args.serverName];
  const hadPrevious = previous !== undefined && previous !== null;
  const before = JSON.stringify(previous ?? null);
  root[args.serverName] = args.snippet;
  const after = JSON.stringify(root[args.serverName]);
  const changed = before !== after;

  if (!args.dryRun && changed) {
    existing[args.rootKey] = root;
    fs.mkdirSync(path.dirname(args.configPath), { recursive: true });
    fs.writeFileSync(
      args.configPath,
      JSON.stringify(existing, null, 2) + "\n",
      { encoding: "utf8", mode: 0o600 },
    );
  }

  // We distinguish "first install" (no prior entry) from "update" (entry
  // existed and we replaced it) so the operator log line tells them what
  // actually happened. Both paths still set `changed: true`.
  const verb = changed ? (hadPrevious ? "Updated" : "Wrote") : "Found";
  return {
    host: args.host,
    configPath: args.configPath,
    changed,
    snippet: args.snippet,
    message: changed
      ? [
          `${verb} ${args.host} MCP config at ${args.configPath}.`,
          args.followUp,
        ].join("\n")
      : `Already configured at ${args.configPath} — nothing to do.`,
  };
}

function readJsonOrEmpty(p: string): Record<string, unknown> {
  try {
    const buf = fs.readFileSync(p, "utf8");
    const v = JSON.parse(buf);
    return typeof v === "object" && v !== null ? (v as Record<string, unknown>) : {};
  } catch (err) {
    // ENOENT or parse error → treat as fresh config. We log nothing; the
    // installer's caller surfaces the resulting message.
    if (
      err instanceof Error &&
      "code" in err &&
      (err as NodeJS.ErrnoException).code === "ENOENT"
    ) {
      return {};
    }
    if (err instanceof SyntaxError) {
      // Don't silently destroy a malformed config; refuse instead.
      throw new Error(
        `Refusing to overwrite ${p}: file exists but is not valid JSON. Fix or delete it, then re-run.`,
      );
    }
    return {};
  }
}

// ---------------------------------------------------------------------------
// per-host config paths
// ---------------------------------------------------------------------------

function claudeConfigPath(): string {
  const home = os.homedir();
  if (process.platform === "darwin") {
    return path.join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json");
  }
  if (process.platform === "win32") {
    const appData = process.env.APPDATA ?? path.join(home, "AppData", "Roaming");
    return path.join(appData, "Claude", "claude_desktop_config.json");
  }
  // Linux build of Claude Desktop is unofficial; fall back to XDG.
  const xdg = process.env.XDG_CONFIG_HOME ?? path.join(home, ".config");
  return path.join(xdg, "Claude", "claude_desktop_config.json");
}

function cursorConfigPath(): string {
  return path.join(os.homedir(), ".cursor", "mcp.json");
}

function continueConfigPath(): string {
  return path.join(os.homedir(), ".continue", "config.json");
}

/** Exposed for `aisoc-mcp install --list-paths` and tests. */
export function knownConfigPaths(): Record<Host, string | null> {
  return {
    claude: claudeConfigPath(),
    cursor: cursorConfigPath(),
    continue: continueConfigPath(),
    cody: null,
  };
}
