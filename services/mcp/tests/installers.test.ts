/**
 * Tests for `aisoc-mcp install` host configuration.
 *
 * These exercise:
 *
 *   1. Real (non-dry-run) JSON writes into a temp directory, so we know the
 *      file path we built for each host actually round-trips through
 *      `readJsonOrEmpty` → mutate → `writeFileSync`.
 *   2. Idempotency: running install twice with the same args is a no-op.
 *   3. The "update" path: existing entry under a different shape is replaced
 *      and the operator log line says "Updated", not "Wrote".
 *   4. Cody's prints-only behaviour, since that host doesn't write files.
 *   5. Refusal to clobber a malformed config rather than nuking it silently.
 *
 * Each test uses its own temp dir under `os.tmpdir()` to stay parallel-safe.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { parseArgs, resolveConfig, type ServerConfig } from "../src/config.js";
import { install as rawInstall, resolveEntryPath } from "../src/installers/index.js";

/**
 * A stand-in for this build's `dist/index.js`. Pinned rather than resolved so
 * assertions don't depend on where the repo happens to be checked out — and
 * so a test can never pass by accident on a machine where the real path
 * contains `node_modules`.
 */
const SOURCE_ENTRY = "/opt/aisoc/services/mcp/dist/index.js";

const install: typeof rawInstall = (opts) =>
  rawInstall({ entryPath: SOURCE_ENTRY, ...opts });

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aisoc-mcp-test-"));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

const baseCfg: ServerConfig = {
  aisocUrl: "https://aisoc.example.com",
  apiKey: "aisoc_test_key",
  timeoutMs: 20_000,
  verbose: false,
  userAgent: "aisoc-mcp/0.1.0 test",
};

describe("install (real write)", () => {
  it("creates a brand-new config file with mcpServers.aisoc", () => {
    const configPath = path.join(tmpDir, "claude_desktop_config.json");
    const result = install({ host: "claude", cfg: baseCfg, configPath });

    expect(result.changed).toBe(true);
    expect(result.configPath).toBe(configPath);
    expect(result.message).toMatch(/Wrote claude MCP config/);

    const written = JSON.parse(fs.readFileSync(configPath, "utf8"));
    expect(written).toEqual({
      mcpServers: {
        aisoc: {
          command: "node",
          args: ["/opt/aisoc/services/mcp/dist/index.js", "serve"],
          env: {
            AISOC_URL: "https://aisoc.example.com",
            AISOC_API_KEY: "aisoc_test_key",
          },
        },
      },
    });
  });

  it("creates parent directories when the config path is nested", () => {
    // Cursor's real path is `~/.cursor/mcp.json`; install must mkdir -p
    // when the user's cursor profile dir doesn't exist yet.
    const configPath = path.join(tmpDir, "nested", "deep", "mcp.json");
    install({ host: "cursor", cfg: baseCfg, configPath });
    expect(fs.existsSync(configPath)).toBe(true);
  });

  it("preserves unrelated keys in an existing config", () => {
    const configPath = path.join(tmpDir, "mcp.json");
    fs.writeFileSync(
      configPath,
      JSON.stringify(
        {
          editor: { theme: "dark" },
          mcpServers: { someOther: { command: "true" } },
        },
        null,
        2,
      ),
    );

    install({ host: "cursor", cfg: baseCfg, configPath });

    const written = JSON.parse(fs.readFileSync(configPath, "utf8"));
    expect(written.editor).toEqual({ theme: "dark" });
    expect(written.mcpServers.someOther).toEqual({ command: "true" });
    expect(written.mcpServers.aisoc.command).toBe("node");
  });

  it("is idempotent: a second identical install reports no change", () => {
    const configPath = path.join(tmpDir, "config.json");
    const first = install({ host: "continue", cfg: baseCfg, configPath });
    expect(first.changed).toBe(true);

    const second = install({ host: "continue", cfg: baseCfg, configPath });
    expect(second.changed).toBe(false);
    expect(second.message).toMatch(/Already configured/);
  });

  it("reports 'Updated' when an existing aisoc entry changes shape", () => {
    const configPath = path.join(tmpDir, "claude.json");
    fs.writeFileSync(
      configPath,
      JSON.stringify({
        mcpServers: {
          aisoc: { command: "old", args: ["legacy"] },
        },
      }),
    );

    const result = install({ host: "claude", cfg: baseCfg, configPath });
    expect(result.changed).toBe(true);
    expect(result.message).toMatch(/Updated claude MCP config/);
    expect(result.message).not.toMatch(/^Wrote/);
  });

  it("includes AISOC_TIMEOUT_MS only when it differs from the default", () => {
    const cfgCustom: ServerConfig = { ...baseCfg, timeoutMs: 7500 };
    const cfgDefault: ServerConfig = { ...baseCfg, timeoutMs: 20_000 };

    const a = install({
      host: "claude",
      cfg: cfgCustom,
      configPath: path.join(tmpDir, "a.json"),
    });
    const b = install({
      host: "claude",
      cfg: cfgDefault,
      configPath: path.join(tmpDir, "b.json"),
    });

    expect((a.snippet.env as Record<string, string>).AISOC_TIMEOUT_MS).toBe(
      "7500",
    );
    expect((b.snippet.env as Record<string, string>).AISOC_TIMEOUT_MS).toBeUndefined();
  });

  it("omits the API key from env when none is configured", () => {
    const cfgNoKey: ServerConfig = { ...baseCfg, apiKey: undefined };
    const result = install({
      host: "cursor",
      cfg: cfgNoKey,
      configPath: path.join(tmpDir, "mcp.json"),
    });
    const env = result.snippet.env as Record<string, string>;
    expect(env.AISOC_URL).toBe("https://aisoc.example.com");
    expect(env.AISOC_API_KEY).toBeUndefined();
  });

  it("dry-run does not touch the filesystem", () => {
    const configPath = path.join(tmpDir, "claude.json");
    const result = install({
      host: "claude",
      cfg: baseCfg,
      configPath,
      dryRun: true,
    });
    expect(result.changed).toBe(true);
    expect(result.snippet).toBeDefined();
    expect(fs.existsSync(configPath)).toBe(false);
  });

  it("refuses to clobber a malformed JSON config", () => {
    const configPath = path.join(tmpDir, "broken.json");
    fs.writeFileSync(configPath, "{ not json");
    expect(() =>
      install({ host: "cursor", cfg: baseCfg, configPath }),
    ).toThrow(/Refusing to overwrite/);
    // And the broken file is left untouched.
    expect(fs.readFileSync(configPath, "utf8")).toBe("{ not json");
  });

  it("treats ENOENT as fresh install, not as an error", () => {
    const configPath = path.join(tmpDir, "no", "such", "file.json");
    const result = install({ host: "cursor", cfg: baseCfg, configPath });
    expect(result.changed).toBe(true);
    expect(fs.existsSync(configPath)).toBe(true);
  });
});

describe("install host=cody (no file write)", () => {
  it("returns a paste-able snippet without touching disk", () => {
    const configPath = path.join(tmpDir, "should-not-be-written.json");
    const result = install({ host: "cody", cfg: baseCfg, configPath });
    expect(result.changed).toBe(false);
    expect(result.configPath).toBeUndefined();
    expect(result.message).toContain("cody.mcp.servers");
    expect(result.message).toContain("aisoc");
    expect(fs.existsSync(configPath)).toBe(false);
  });
});

describe("launcher selection", () => {
  const snippetFor = (
    over: Partial<Parameters<typeof install>[0]>,
  ): Record<string, unknown> =>
    install({
      host: "claude",
      cfg: baseCfg,
      configPath: path.join(tmpDir, "claude.json"),
      dryRun: true,
      ...over,
    }).snippet;

  it("defaults a source build to a direct node invocation of this checkout", () => {
    // The regression this pins: `npx -y @aisoc/mcp` was written
    // unconditionally, so installing from a monorepo build produced a config
    // that parsed and reported success but could never start — @aisoc/mcp is
    // not on npm, so `npx` 404s inside the host at launch time.
    const snippet = snippetFor({});
    expect(snippet.command).toBe("node");
    expect(snippet.args).toEqual([SOURCE_ENTRY, "serve"]);
  });

  it("defaults to npx when running from an installed package", () => {
    const snippet = snippetFor({
      entryPath: "/home/u/.npm/_npx/abc/node_modules/@aisoc/mcp/dist/index.js",
    });
    expect(snippet.command).toBe("npx");
    expect(snippet.args).toEqual(["-y", "@aisoc/mcp", "serve"]);
  });

  it("honours an explicit --launcher override in both directions", () => {
    expect(snippetFor({ launcher: "npx" }).command).toBe("npx");

    const forcedNode = snippetFor({
      launcher: "node",
      entryPath: "/home/u/node_modules/@aisoc/mcp/dist/index.js",
    });
    expect(forcedNode.command).toBe("node");
    expect(forcedNode.args).toEqual([
      "/home/u/node_modules/@aisoc/mcp/dist/index.js",
      "serve",
    ]);
  });

  it("writes an absolute entry path, since the host launches from an arbitrary cwd", () => {
    const args = snippetFor({ launcher: "node" }).args as string[];
    expect(path.isAbsolute(args[0])).toBe(true);
  });

  it("resolveEntryPath points at dist/index.js, not at this module", () => {
    // `install` is reached from `dist/installers/index.js` at runtime, so the
    // entry is one directory up. Getting this wrong would write a config
    // pointing at a file with no shebang and no CLI.
    expect(path.basename(resolveEntryPath())).toBe("index.js");
    expect(path.basename(path.dirname(resolveEntryPath()))).not.toBe("installers");
  });

  it("propagates the verbose flag under the name resolveConfig actually reads", () => {
    const cfgVerbose: ServerConfig = { ...baseCfg, verbose: true };
    const result = install({
      host: "claude",
      cfg: cfgVerbose,
      configPath: path.join(tmpDir, "claude.json"),
      dryRun: true,
    });
    const env = result.snippet.env as Record<string, string>;
    // Asserted against the consumer rather than against a second copy of the
    // producer's own spelling: the previous test pinned AISOC_VERBOSE, which
    // `resolveConfig` never reads, so it passed while the feature was dead.
    expect(env.AISOC_MCP_VERBOSE).toBe("1");
    expect(
      resolveConfig(parseArgs([]), env as unknown as NodeJS.ProcessEnv).verbose,
    ).toBe(true);
  });
});
