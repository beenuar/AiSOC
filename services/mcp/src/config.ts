/**
 * Runtime configuration for the AiSOC MCP server.
 *
 * Why not a config file: MCP hosts (Claude Desktop, Cursor, Cody) launch the
 * server as a stdio child process and expose configuration via env vars +
 * argv. We honour both, with argv winning so the install command can write a
 * single self-contained command line into each host's config.
 *
 * Precedence (highest first):
 *   1. CLI flags          (`--aisoc-url …`, `--api-key …`)
 *   2. Environment        (`AISOC_URL`, `AISOC_API_KEY`)
 *   3. Built-in defaults  (only the URL — the key is required)
 *
 * The API key is required for any tool call against a real AiSOC. We allow
 * the server to start without one (so `doctor` and `--help` work), but
 * tool dispatch then fails with a typed `MissingApiKeyError`.
 *
 * Logging discipline: this server speaks MCP over stdout, so anything
 * useful to humans **must** go to stderr. We never write to stdout outside
 * the MCP transport.
 */
import { readFileSync } from "node:fs";

const DEFAULT_AISOC_URL = "http://localhost:8081";
const DEFAULT_TIMEOUT_MS = 20_000;

export interface ServerConfig {
  /** Base URL of the AiSOC API (e.g. `https://aisoc.example.com`). */
  aisocUrl: string;
  /** API key from /api/v1/api-keys (`aisoc_*` prefix) or a JWT bearer token. */
  apiKey: string | undefined;
  /** Default per-request timeout. */
  timeoutMs: number;
  /** Verbose logging to stderr (off by default to keep IDE consoles clean). */
  verbose: boolean;
  /** User-Agent string surfaced to the AiSOC API for audit. */
  userAgent: string;
}

export interface ParsedArgs {
  /** Positional command: `serve` (default), `install`, `doctor`, `help`. */
  command: "serve" | "install" | "doctor" | "help" | "version";
  /** Flags consumed by the parser; everything else goes to subcommands. */
  flags: Record<string, string | boolean>;
  /** Subcommand-specific positional args after the command. */
  positional: string[];
}

const FLAG_ALIASES: Record<string, string> = {
  "-h": "help",
  "--help": "help",
  "-v": "version",
  "--version": "version",
  "--aisoc-url": "aisocUrl",
  "--api-key": "apiKey",
  "--timeout": "timeoutMs",
  "--verbose": "verbose",
};

/**
 * Tiny argv parser. We deliberately avoid pulling in `commander` / `yargs`
 * because the MCP binary is in everyone's `npx` cache and dependency weight
 * matters: the SDK already pulls in zod; we don't need a second arg parser.
 */
export function parseArgs(argv: readonly string[]): ParsedArgs {
  const args = [...argv];
  const flags: Record<string, string | boolean> = {};
  const positional: string[] = [];

  while (args.length > 0) {
    const raw = args.shift()!;
    // Long-form `--key=value`
    if (raw.startsWith("--") && raw.includes("=")) {
      const eq = raw.indexOf("=");
      const key = raw.slice(0, eq);
      const val = raw.slice(eq + 1);
      const canonical = FLAG_ALIASES[key];
      if (canonical) {
        flags[canonical] = val;
      } else {
        // Pass through unknown flags so installers can forward them
        flags[key.replace(/^--/, "")] = val;
      }
      continue;
    }
    // Long/short flags
    const canonical = FLAG_ALIASES[raw];
    if (canonical) {
      // boolean-style help/version/verbose take no value
      if (canonical === "help" || canonical === "version" || canonical === "verbose") {
        flags[canonical] = true;
        continue;
      }
      const next = args.shift();
      if (next === undefined || next.startsWith("-")) {
        throw new Error(`Flag ${raw} requires a value`);
      }
      flags[canonical] = next;
      continue;
    }
    if (raw.startsWith("--")) {
      // Unknown long flag. Look ahead: if the next token is not another
      // flag, treat this as `--key value`; otherwise as a boolean. This
      // keeps `--host cursor` working without us having to enumerate every
      // installer option in `FLAG_ALIASES`.
      const next = args[0];
      if (next !== undefined && !next.startsWith("-")) {
        flags[raw.replace(/^--/, "")] = next;
        args.shift();
      } else {
        flags[raw.replace(/^--/, "")] = true;
      }
      continue;
    }
    if (raw.startsWith("-")) {
      // Unknown short flag; boolean-only to avoid surprising captures.
      flags[raw.replace(/^-+/, "")] = true;
      continue;
    }
    positional.push(raw);
  }

  // Resolve command from positional[0] or flags.help/version
  let command: ParsedArgs["command"] = "serve";
  if (flags.help) command = "help";
  else if (flags.version) command = "version";
  else if (positional.length > 0) {
    const head = positional[0];
    if (
      head === "serve" ||
      head === "install" ||
      head === "doctor" ||
      head === "help" ||
      head === "version"
    ) {
      command = head;
      positional.shift();
    }
  }

  return { command, flags, positional };
}

/**
 * Merge env + parsed flags into a fully-resolved {@link ServerConfig}.
 *
 * We intentionally tolerate a missing API key here; the actual error is
 * raised lazily on the first tool call so `--help` and `doctor` still work
 * even when the user hasn't wired credentials yet.
 */
export function resolveConfig(args: ParsedArgs, env: NodeJS.ProcessEnv = process.env): ServerConfig {
  const url =
    (typeof args.flags.aisocUrl === "string" && args.flags.aisocUrl) ||
    env.AISOC_URL ||
    env.AISOC_API_URL ||
    DEFAULT_AISOC_URL;

  const apiKey =
    (typeof args.flags.apiKey === "string" && args.flags.apiKey) ||
    env.AISOC_API_KEY ||
    env.AISOC_TOKEN ||
    undefined;

  const timeoutFlag = args.flags.timeoutMs;
  const timeoutMs =
    typeof timeoutFlag === "string" && timeoutFlag.length > 0
      ? Number.parseInt(timeoutFlag, 10)
      : env.AISOC_TIMEOUT_MS
        ? Number.parseInt(env.AISOC_TIMEOUT_MS, 10)
        : DEFAULT_TIMEOUT_MS;

  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new Error(`Invalid timeout: ${timeoutFlag ?? env.AISOC_TIMEOUT_MS}`);
  }

  const verbose = Boolean(args.flags.verbose) || env.AISOC_MCP_VERBOSE === "1";

  return {
    aisocUrl: stripTrailingSlash(url),
    apiKey,
    timeoutMs,
    verbose,
    userAgent: `aisoc-mcp/${packageVersion()} (+https://github.com/beenuar/AiSOC)`,
  };
}

function stripTrailingSlash(s: string): string {
  return s.endsWith("/") ? s.slice(0, -1) : s;
}

/**
 * Read version from package.json without bundling it. We resolve at runtime
 * so `npm publish` doesn't need a build step that inlines the version.
 *
 * In dev (`tsx`), `import.meta.url` resolves to `…/services/mcp/src/config.ts`,
 * so the package.json sits two directories up. After `tsc`, the file is at
 * `…/services/mcp/dist/config.js` and package.json sits one directory up.
 * We try both rather than guess the runtime mode.
 */
export function packageVersion(): string {
  try {
    const candidates = [
      new URL("../package.json", import.meta.url),
      new URL("../../package.json", import.meta.url),
    ];
    for (const url of candidates) {
      try {
        const raw = readFileSync(url, "utf8");
        const parsed = JSON.parse(raw) as { version?: string };
        if (parsed.version) return parsed.version;
      } catch {
        // try next candidate
      }
    }
    return "0.0.0-dev";
  } catch {
    return "0.0.0-dev";
  }
}

/**
 * Stderr logger that respects `verbose`. We never log to stdout because
 * MCP servers speak JSON-RPC there.
 */
export function makeLogger(cfg: Pick<ServerConfig, "verbose">) {
  return {
    info: (msg: string, ...rest: unknown[]) => {
      if (cfg.verbose) console.error(`[aisoc-mcp] ${msg}`, ...rest);
    },
    warn: (msg: string, ...rest: unknown[]) => {
      console.error(`[aisoc-mcp] WARN: ${msg}`, ...rest);
    },
    error: (msg: string, ...rest: unknown[]) => {
      console.error(`[aisoc-mcp] ERROR: ${msg}`, ...rest);
    },
  };
}

export type Logger = ReturnType<typeof makeLogger>;
