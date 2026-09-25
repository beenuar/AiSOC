/**
 * Contract tests for `server.json`, the MCP registry manifest.
 *
 * The manifest is how MCP directories index this server, which makes it a
 * published claim with no human in the loop — nobody reviews it the way they
 * would a README paragraph. Three things can rot silently:
 *
 *   1. its `version` drifting from `package.json`;
 *   2. a field quietly violating a schema constraint that is only enforced
 *      server-side at publish time (the registry caps `description` at 100
 *      characters, which is easy to exceed while editing prose);
 *   3. a `packages` entry appearing that points at a registry nothing has
 *      been uploaded to, which would send every directory visitor to a 404.
 *
 * The schema itself is fetched and validated in CI rather than here; these
 * are the invariants that hold offline.
 */
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const PKG_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const manifest = JSON.parse(
  readFileSync(path.join(PKG_DIR, "server.json"), "utf8"),
) as Record<string, unknown>;
const pkg = JSON.parse(readFileSync(path.join(PKG_DIR, "package.json"), "utf8")) as {
  version: string;
};
const readme = readFileSync(path.join(PKG_DIR, "README.md"), "utf8");

describe("server.json — registry manifest", () => {
  it("declares the schema version it was written against", () => {
    expect(manifest.$schema).toBe(
      "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
    );
  });

  it("carries the three fields the schema requires", () => {
    for (const field of ["name", "description", "version"]) {
      expect(manifest[field], `missing required field ${field}`).toBeTruthy();
    }
  });

  it("uses a reverse-DNS name with exactly one slash", () => {
    const name = manifest.name as string;
    expect(name).toMatch(/^[a-zA-Z0-9.-]+\/[a-zA-Z0-9._-]+$/);
    expect(name.split("/")).toHaveLength(2);
    expect(name.length).toBeLessThanOrEqual(200);
  });

  it("keeps description within the registry's 100-character cap", () => {
    const description = manifest.description as string;
    expect(description.length).toBeGreaterThan(0);
    expect(description.length).toBeLessThanOrEqual(100);
  });

  it("stays in lockstep with package.json's version", () => {
    expect(manifest.version).toBe(pkg.version);
  });

  it("points at this package's subfolder in the monorepo", () => {
    const repository = manifest.repository as Record<string, string>;
    expect(repository.source).toBe("github");
    expect(repository.url).toBe("https://github.com/beenuar/AiSOC");
    expect(repository.subfolder).toBe("services/mcp");
  });

  it("serves icons over https, as the schema requires", () => {
    for (const icon of (manifest.icons ?? []) as Array<{ src: string }>) {
      expect(icon.src.startsWith("https://")).toBe(true);
      expect(icon.src.length).toBeLessThanOrEqual(255);
    }
  });

  it("does not advertise a package the registry cannot resolve", () => {
    // `packages` is optional, and omitting it is the honest state while the
    // npm upload is blocked on registry credentials: a directory visitor gets
    // the source repository rather than an install command that 404s. When
    // publication happens, add the entry *and* drop the README's
    // "ready, unpublished" line — this asserts the two move together.
    const packages = (manifest.packages ?? []) as Array<{ registryType: string }>;
    const claimsUnpublished = /ready,\s*unpublished/i.test(readme);

    if (packages.length > 0) {
      expect(
        claimsUnpublished,
        "server.json advertises a package while README still says the package is unpublished",
      ).toBe(false);
      for (const entry of packages) {
        // The schema requires these three on every package entry.
        expect(entry.registryType).toBeTruthy();
        expect((entry as { identifier?: string }).identifier).toBeTruthy();
        expect((entry as { transport?: unknown }).transport).toBeTruthy();
      }
    } else {
      expect(
        claimsUnpublished,
        "server.json advertises no package, so the README must still say so",
      ).toBe(true);
    }
  });
});
