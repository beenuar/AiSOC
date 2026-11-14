/**
 * The tenant is never a tool argument (issue #1274).
 *
 * `aisoc_run_hunt` declared `tenant_id: z.string().uuid()` and forwarded
 * it in the request body. Two separate things were wrong with that.
 *
 * The one the report hit: zod 4's `.uuid()` checks RFC 4122 version and
 * variant bits, and the tenant every default install is bootstrapped into
 * (`00000000-0000-0000-0000-000000000001`) sets neither. So the tool was
 * unusable on a stock deployment — the model could not produce a value the
 * schema would accept.
 *
 * The one that matters more: a tenant a *model* supplies is not a control.
 * `AgentHuntRequest` declares only `hypothesis` and the handler's docstring
 * says the tenant "comes from the authenticated principal and is never read
 * from the body", so today's protection is an accident of pydantic dropping
 * an undeclared key — not a boundary. Loosening the validator to `z.guid()`
 * would have made the bad input pass and left the shape in place.
 *
 * The assertion is therefore structural and repo-wide, not a fix to one
 * tool: no tool on this server takes a tenant from its caller.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";
import { z } from "zod";

import { ALL_TOOLS } from "../src/tools/index.js";
import { runHuntTool } from "../src/tools/hunt.js";

const SRC = fileURLToPath(new URL("../src", import.meta.url));

/** `bootstrap_admin.DEFAULT_TENANT_ID` — what a stock `make up` creates. */
const DEFAULT_TENANT = "00000000-0000-0000-0000-000000000001";

function everySourceFile(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...everySourceFile(path));
    else if (entry.name.endsWith(".ts")) out.push(path);
  }
  return out;
}

interface RecordedCall {
  path: string;
  body?: unknown;
}

function recordingClient(calls: RecordedCall[], reply: unknown) {
  return {
    async get(path: string) {
      calls.push({ path });
      return reply;
    },
    async post(path: string, body: unknown) {
      calls.push({ path, body });
      return reply;
    },
  };
}

const log = { debug() {}, info() {}, warn() {}, error() {} };

describe("the reported symptom", () => {
  it("confirms zod rejects the default tenant that z.guid() accepts", () => {
    // Not an assertion about our code — it pins the upstream behaviour the
    // report rests on, so a zod bump that changes it shows up here rather
    // than as a mystery. The version-and-variant bits are all zero.
    expect(z.string().uuid().safeParse(DEFAULT_TENANT).success).toBe(false);
    expect(z.guid().safeParse(DEFAULT_TENANT).success).toBe(true);

    // A conventional v4 uuid passes both, which is why this went unnoticed:
    // it works on any tenant except the one every first run lands in.
    const v4 = "550e8400-e29b-41d4-a716-446655440000";
    expect(z.string().uuid().safeParse(v4).success).toBe(true);
  });
});

describe("no tool takes a tenant from its caller", () => {
  it("declares no tenant field in any tool's input schema", () => {
    const offenders: string[] = [];
    for (const tool of ALL_TOOLS) {
      const schema = tool.metadata.inputSchema as {
        properties?: Record<string, unknown>;
      };
      for (const key of Object.keys(schema.properties ?? {})) {
        if (/tenant/i.test(key)) offenders.push(`${tool.metadata.name}.${key}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("sends no tenant in any request body built from tool arguments", async () => {
    // The schema and the wire are two different claims. A tool could drop
    // the parameter and still stamp a tenant into the body from somewhere.
    const calls: RecordedCall[] = [];
    await runHuntTool.handle(
      {
        client: recordingClient(calls, {
          hypothesis: "h",
          checked: true,
          matches: [],
          refusals: [],
          unavailable_reason: null,
        }),
        log,
      } as never,
      { hypothesis: "a service account signed in from a new country" } as never,
    );

    expect(calls).toHaveLength(1);
    expect(calls[0].path).toBe("/api/v1/agents/hunt");
    expect(Object.keys(calls[0].body as object)).toEqual(["hypothesis"]);
  });

  it("names no tenant_id key anywhere a request body is built", () => {
    // Structural, so a tool added later is covered without editing this
    // test. Prose and response-shape types legitimately mention the word,
    // so match an object key being assigned, which is what a body literal
    // and a zod schema field both look like.
    const offenders: string[] = [];
    for (const file of everySourceFile(SRC)) {
      const body = readFileSync(file, "utf8");
      for (const line of body.split("\n")) {
        // Skip comments — `lake.ts` explains at length that the predicate is
        // injected server-side, which is the behaviour this test wants.
        const code = line.replace(/^\s*(\/\/|\*|\/\*).*$/, "");
        if (/\btenant_id\s*:/.test(code) && !/\btenant_id\s*:\s*string\s*\|\s*null/.test(code)) {
          offenders.push(`${file.replace(SRC, "src")}: ${line.trim()}`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });
});

describe("the hunt tool still works", () => {
  it("accepts a hypothesis alone", () => {
    expect(runHuntTool.schema.safeParse({ hypothesis: "x" }).success).toBe(true);
  });

  it("refuses a caller-supplied tenant rather than ignoring it", () => {
    // `.strict()` is deliberate. Silently dropping the key is how the API
    // side ended up with a protection nobody had decided on.
    const parsed = runHuntTool.schema.safeParse({
      hypothesis: "x",
      tenant_id: DEFAULT_TENANT,
    });
    expect(parsed.success).toBe(false);
  });

  it("still requires a non-empty hypothesis", () => {
    expect(runHuntTool.schema.safeParse({ hypothesis: "" }).success).toBe(false);
  });
});
