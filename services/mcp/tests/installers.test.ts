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

import type { ServerConfig } from "../src/config.js";
import { install } from "../src/installers/index.js";

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
          command: "npx",
          args: ["-y", "@aisoc/mcp", "serve"],
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
    expect(written.mcpServers.aisoc.command).toBe("npx");
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

describe("buildServerSnippet shape", () => {
  it("always uses npx -y so users don't need a global install", () => {
    const result = install({
      host: "claude",
      cfg: baseCfg,
      configPath: path.join(tmpDir, "claude.json"),
      dryRun: true,
    });
    expect(result.snippet.command).toBe("npx");
    expect(result.snippet.args).toEqual(["-y", "@aisoc/mcp", "serve"]);
  });

  it("propagates the verbose flag into AISOC_VERBOSE", () => {
    const cfgVerbose: ServerConfig = { ...baseCfg, verbose: true };
    const result = install({
      host: "claude",
      cfg: cfgVerbose,
      configPath: path.join(tmpDir, "claude.json"),
      dryRun: true,
    });
    expect((result.snippet.env as Record<string, string>).AISOC_VERBOSE).toBe(
      "1",
    );
  });
});
