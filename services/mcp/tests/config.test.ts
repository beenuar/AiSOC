/**
 * Tests for argv parsing + config resolution.
 *
 * These cover the regressions that bit us during Phase 2C smoke testing:
 *   - `--host claude` (unknown long flag with a value) was being captured
 *     as a boolean, so positional `claude` leaked into the command parser.
 *   - `packageVersion()` was returning `0.0.0-dev` because the ESM build
 *     couldn't reach package.json via `require`.
 *
 * If any of these break again, CI catches it before the next publish.
 */
import { describe, expect, it } from "vitest";

import { packageVersion, parseArgs, resolveConfig } from "../src/config.js";

describe("parseArgs", () => {
  it("defaults to the serve command when no positional is given", () => {
    const out = parseArgs([]);
    expect(out.command).toBe("serve");
    expect(out.flags).toEqual({});
    expect(out.positional).toEqual([]);
  });

  it("recognises serve/install/doctor/help/version as commands", () => {
    for (const cmd of ["serve", "install", "doctor", "help", "version"] as const) {
      expect(parseArgs([cmd]).command).toBe(cmd);
    }
  });

  it("treats --help / -h / --version / -v as commands", () => {
    expect(parseArgs(["--help"]).command).toBe("help");
    expect(parseArgs(["-h"]).command).toBe("help");
    expect(parseArgs(["--version"]).command).toBe("version");
    expect(parseArgs(["-v"]).command).toBe("version");
  });

  it("accepts known long flags with a separate value", () => {
    const out = parseArgs(["serve", "--aisoc-url", "https://aisoc.example.com"]);
    expect(out.command).toBe("serve");
    expect(out.flags.aisocUrl).toBe("https://aisoc.example.com");
  });

  it("accepts known long flags with --key=value syntax", () => {
    const out = parseArgs(["--aisoc-url=https://aisoc.example.com", "--api-key=aisoc_test"]);
    expect(out.flags.aisocUrl).toBe("https://aisoc.example.com");
    expect(out.flags.apiKey).toBe("aisoc_test");
  });

  it("treats --verbose / --help / --version as boolean toggles", () => {
    const out = parseArgs(["serve", "--verbose"]);
    expect(out.flags.verbose).toBe(true);
  });

  it("captures unknown long flags with values (regression: --host claude)", () => {
    // This is the parseArgs bug we hit during install smoke testing.
    // Before the fix, `claude` ended up as a positional and the install
    // command rejected the missing `--host`. The fix is in src/config.ts:
    // when the next token doesn't start with `-`, treat the unknown long
    // flag as `--key value` rather than a boolean.
    const out = parseArgs(["install", "--host", "claude", "--dry-run"]);
    expect(out.command).toBe("install");
    expect(out.flags.host).toBe("claude");
    expect(out.flags["dry-run"]).toBe(true);
    expect(out.positional).toEqual([]);
  });

  it("captures unknown long flags with --key=value too", () => {
    const out = parseArgs(["install", "--host=cursor", "--list-paths"]);
    expect(out.flags.host).toBe("cursor");
    expect(out.flags["list-paths"]).toBe(true);
  });

  it("falls back to boolean for trailing unknown long flags", () => {
    const out = parseArgs(["install", "--dry-run"]);
    expect(out.flags["dry-run"]).toBe(true);
  });

  it("throws when a known value-taking flag is missing its value", () => {
    expect(() => parseArgs(["--aisoc-url"])).toThrow(/requires a value/);
  });

  it("collects extra positional args after the command", () => {
    const out = parseArgs(["install", "claude"]);
    expect(out.command).toBe("install");
    expect(out.positional).toEqual(["claude"]);
  });
});

describe("resolveConfig", () => {
  const baseEnv = {} as NodeJS.ProcessEnv;

  it("falls back to the default URL when nothing is set", () => {
    const cfg = resolveConfig(parseArgs([]), baseEnv);
    expect(cfg.aisocUrl).toBe("http://localhost:8081");
    expect(cfg.apiKey).toBeUndefined();
    expect(cfg.timeoutMs).toBe(20_000);
    expect(cfg.verbose).toBe(false);
  });

  it("prefers the CLI flag over the environment variable", () => {
    const args = parseArgs(["--aisoc-url", "https://flag.example"]);
    const cfg = resolveConfig(args, { AISOC_URL: "https://env.example" } as NodeJS.ProcessEnv);
    expect(cfg.aisocUrl).toBe("https://flag.example");
  });

  it("uses AISOC_URL when no flag is given", () => {
    const cfg = resolveConfig(parseArgs([]), {
      AISOC_URL: "https://env.example",
    } as NodeJS.ProcessEnv);
    expect(cfg.aisocUrl).toBe("https://env.example");
  });

  it("falls back to AISOC_API_URL alias", () => {
    const cfg = resolveConfig(parseArgs([]), {
      AISOC_API_URL: "https://alias.example",
    } as NodeJS.ProcessEnv);
    expect(cfg.aisocUrl).toBe("https://alias.example");
  });

  it("strips a single trailing slash from the URL", () => {
    const args = parseArgs(["--aisoc-url", "https://aisoc.example/"]);
    const cfg = resolveConfig(args, baseEnv);
    expect(cfg.aisocUrl).toBe("https://aisoc.example");
  });

  it("resolves the API key from AISOC_API_KEY", () => {
    const cfg = resolveConfig(parseArgs([]), {
      AISOC_API_KEY: "aisoc_env_key",
    } as NodeJS.ProcessEnv);
    expect(cfg.apiKey).toBe("aisoc_env_key");
  });

  it("resolves the API key from AISOC_TOKEN as fallback", () => {
    const cfg = resolveConfig(parseArgs([]), {
      AISOC_TOKEN: "jwt_value",
    } as NodeJS.ProcessEnv);
    expect(cfg.apiKey).toBe("jwt_value");
  });

  it("prefers --api-key flag over both env aliases", () => {
    const args = parseArgs(["--api-key", "from_flag"]);
    const cfg = resolveConfig(args, {
      AISOC_API_KEY: "from_env",
      AISOC_TOKEN: "also_env",
    } as NodeJS.ProcessEnv);
    expect(cfg.apiKey).toBe("from_flag");
  });

  it("parses a numeric timeout from --timeout", () => {
    const args = parseArgs(["--timeout", "5000"]);
    const cfg = resolveConfig(args, baseEnv);
    expect(cfg.timeoutMs).toBe(5000);
  });

  it("parses a numeric timeout from AISOC_TIMEOUT_MS", () => {
    const cfg = resolveConfig(parseArgs([]), {
      AISOC_TIMEOUT_MS: "7500",
    } as NodeJS.ProcessEnv);
    expect(cfg.timeoutMs).toBe(7500);
  });

  it("rejects non-positive timeouts", () => {
    expect(() =>
      resolveConfig(parseArgs([]), { AISOC_TIMEOUT_MS: "0" } as NodeJS.ProcessEnv),
    ).toThrow(/Invalid timeout/);
    expect(() =>
      resolveConfig(parseArgs([]), { AISOC_TIMEOUT_MS: "abc" } as NodeJS.ProcessEnv),
    ).toThrow(/Invalid timeout/);
  });

  it("turns on verbose logging via flag or env", () => {
    expect(resolveConfig(parseArgs(["--verbose"]), baseEnv).verbose).toBe(true);
    expect(
      resolveConfig(parseArgs([]), { AISOC_MCP_VERBOSE: "1" } as NodeJS.ProcessEnv).verbose,
    ).toBe(true);
  });

  it("includes the package version in the User-Agent string", () => {
    const cfg = resolveConfig(parseArgs([]), baseEnv);
    expect(cfg.userAgent).toMatch(/^aisoc-mcp\/\d+\.\d+\.\d+/);
  });
});

describe("packageVersion", () => {
  it("returns the version from package.json (not 0.0.0-dev)", () => {
    // Regression: an earlier ESM-incompatible implementation always fell
    // back to the dev sentinel. The CLI's `--version` is the canonical
    // way users check what they have, so this matters.
    const v = packageVersion();
    expect(v).toMatch(/^\d+\.\d+\.\d+/);
    expect(v).not.toBe("0.0.0-dev");
  });
});
