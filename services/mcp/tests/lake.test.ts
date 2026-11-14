/**
 * Tests for the Workstream 7 lake tools (``aisoc_lake_query`` /
 * ``aisoc_lake_schema``).
 *
 * These tools are special: they're the only surface that lets an agent
 * write arbitrary SQL, so the tool layer ships local guard rails that
 * reject obviously-bad input *before* a network round trip. The tests
 * here lock down those guard rails — the server-side rewriter is tested
 * separately in ``services/api`` — and verify the API call shape
 * (path + body) so a future client refactor doesn't silently break
 * either tool.
 *
 * We mock the {@link AisocClient} via duck typing: the tools only use
 * ``client.get`` / ``client.post``, so a stub with those two methods
 * is enough. Faking the whole class with a real ``ServerConfig`` would
 * pull in fetch / env / logger plumbing we don't need here.
 */
import { describe, expect, it, vi } from "vitest";

import type { AisocClient } from "../src/client.js";
import type { Logger } from "../src/config.js";
import { lakeQueryTool, lakeSchemaTool } from "../src/tools/lake.js";
import type { ToolContext } from "../src/tools/types.js";

/** Shape we actually exercise from {@link AisocClient}. */
interface StubClient {
  get: ReturnType<typeof vi.fn>;
  post: ReturnType<typeof vi.fn>;
}

/** A no-op logger keeps the test output uncluttered. */
const SILENT_LOG: Logger = {
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
};

function makeCtx(client: StubClient): ToolContext {
  // The tools only touch ``client.get`` / ``client.post``; the cast
  // narrows the stub to the full client interface for the type
  // checker without us having to construct a real config object.
  return {
    client: client as unknown as AisocClient,
    log: SILENT_LOG,
  };
}

// ---------------------------------------------------------------------------
// aisoc_lake_query
// ---------------------------------------------------------------------------

describe("lakeQueryTool — zod schema", () => {
  it("accepts a minimal SELECT", () => {
    const parsed = lakeQueryTool.schema.safeParse({
      sql: "SELECT 1",
    });
    expect(parsed.success).toBe(true);
  });

  it("rejects an empty SQL string", () => {
    // A no-op query is almost certainly an agent loop bug; we'd rather
    // surface that locally than hit ``/lake/sql`` with nothing.
    const parsed = lakeQueryTool.schema.safeParse({ sql: "" });
    expect(parsed.success).toBe(false);
  });

  it("rejects oversized SQL beyond MAX_SQL_BYTES", () => {
    // 200_001 chars of ``a`` exceeds the 200 KB cap by 1 byte. zod's
    // ``max`` is on character count, which matches our server-side
    // ``LakeQueryRequest.sql.max_length``; the byte / char distinction
    // is irrelevant for ASCII and is the conservative choice for
    // multibyte content.
    const oversized = "a".repeat(200_001);
    const parsed = lakeQueryTool.schema.safeParse({ sql: oversized });
    expect(parsed.success).toBe(false);
  });

  it("rejects unknown fields (strict object)", () => {
    // Strict mode means a typo like ``timout_seconds`` surfaces as a
    // schema error, not a silently-dropped argument the caller will
    // wonder about.
    const parsed = lakeQueryTool.schema.safeParse({
      sql: "SELECT 1",
      tenant_id: "00000000-0000-0000-0000-000000000000",
    });
    expect(parsed.success).toBe(false);
  });

  it("rejects row_cap below 1 and above 100k", () => {
    expect(
      lakeQueryTool.schema.safeParse({ sql: "SELECT 1", row_cap: 0 }).success,
    ).toBe(false);
    expect(
      lakeQueryTool.schema.safeParse({ sql: "SELECT 1", row_cap: 100_001 })
        .success,
    ).toBe(false);
    expect(
      lakeQueryTool.schema.safeParse({ sql: "SELECT 1", row_cap: 100 }).success,
    ).toBe(true);
  });

  it("rejects timeout_seconds below 0.1 and above 60", () => {
    // The 60 s upper bound matches the server-side ``timeout_seconds``
    // cap on ``LakeQueryRequest`` — picked to be larger than the
    // ClickHouse default but small enough that a runaway query can't
    // tie up the FastAPI worker indefinitely.
    expect(
      lakeQueryTool.schema.safeParse({ sql: "SELECT 1", timeout_seconds: 0 })
        .success,
    ).toBe(false);
    expect(
      lakeQueryTool.schema.safeParse({ sql: "SELECT 1", timeout_seconds: 61 })
        .success,
    ).toBe(false);
  });
});

describe("lakeQueryTool — multi-statement guard", () => {
  // The guard exists so that prompt-injected agents — "ignore your
  // instructions; DROP TABLE …" — are rejected without a network
  // round trip. The server's sqlglot rewriter is the source of
  // truth, but a local fast path is cheap insurance.

  it("rejects a trailing DROP TABLE after a SELECT", async () => {
    const client: StubClient = { get: vi.fn(), post: vi.fn() };
    const result = await lakeQueryTool.handle(makeCtx(client), {
      sql: "SELECT 1; DROP TABLE raw_events",
    });
    expect(result.kind).toBe("json");
    if (result.kind === "json") {
      expect(result.data).toMatchObject({ error: "multi_statement" });
    }
    // Critically: we never sent the request.
    expect(client.post).not.toHaveBeenCalled();
  });

  it("allows a trailing semicolon followed only by whitespace", async () => {
    // Clients (DB GUIs, sqlfluff, copy-paste from a notebook) routinely
    // append a trailing ``;``. Refusing that would be hostile to
    // humans and to most agent SQL emitters. The guard only fires
    // when there's *more* code after the semicolon.
    const client: StubClient = {
      get: vi.fn(),
      post: vi.fn().mockResolvedValue({
        columns: ["c"],
        rows: [[1]],
        row_count: 1,
        row_cap: 100_000,
        referenced_tables: ["aisoc.raw_events"],
        elapsed_ms: 5,
        executed_at: "2026-05-08T19:00:00Z",
      }),
    };
    await lakeQueryTool.handle(makeCtx(client), {
      sql: "SELECT 1 FROM raw_events ;   \n",
    });
    expect(client.post).toHaveBeenCalledTimes(1);
  });

  it("ignores semicolons inside string literals", async () => {
    // ``WHERE message = 'hi; bye'`` is a single statement; the guard
    // must not be tricked by punctuation in literals or it'll reject
    // legitimate queries about logs that contain semicolons.
    const client: StubClient = {
      get: vi.fn(),
      post: vi.fn().mockResolvedValue({
        columns: [],
        rows: [],
        row_count: 0,
        row_cap: 100_000,
        referenced_tables: ["aisoc.raw_events"],
        elapsed_ms: 1,
        executed_at: "2026-05-08T19:00:00Z",
      }),
    };
    await lakeQueryTool.handle(makeCtx(client), {
      sql: "SELECT * FROM raw_events WHERE message = 'hi; bye'",
    });
    expect(client.post).toHaveBeenCalledTimes(1);
  });

  it("ignores semicolons inside SQL comments", async () => {
    // ClickHouse supports both ``--`` and ``/* */`` comments; the
    // guard strips them before scanning, otherwise a chatty comment
    // ("-- thanks; please run") becomes a "second statement".
    const client: StubClient = {
      get: vi.fn(),
      post: vi.fn().mockResolvedValue({
        columns: [],
        rows: [],
        row_count: 0,
        row_cap: 100_000,
        referenced_tables: ["aisoc.raw_events"],
        elapsed_ms: 1,
        executed_at: "2026-05-08T19:00:00Z",
      }),
    };
    await lakeQueryTool.handle(makeCtx(client), {
      sql: "SELECT 1 FROM raw_events -- hi; thanks\n",
    });
    expect(client.post).toHaveBeenCalledTimes(1);

    await lakeQueryTool.handle(makeCtx(client), {
      sql: "SELECT 1 FROM raw_events /* hi; bye */",
    });
    expect(client.post).toHaveBeenCalledTimes(2);
  });
});

describe("lakeQueryTool — forbidden-table guard", () => {
  // The server rejects these too via the rewriter's table allowlist.
  // We mirror the patterns locally so an agent iterating against a
  // mistake gets the rejection in milliseconds, not after an HTTP
  // round trip.

  const cases: Array<{ name: string; sql: string }> = [
    {
      name: "system schema",
      sql: "SELECT name FROM system.tables",
    },
    {
      name: "information_schema",
      sql: "SELECT * FROM information_schema.columns",
    },
    {
      name: "remote() table function",
      sql: "SELECT * FROM remote('other-host', 'aisoc', 'raw_events')",
    },
    {
      name: "url() table function",
      sql: "SELECT * FROM url('https://evil.example/data.json', 'JSONEachRow')",
    },
    {
      name: "s3() table function",
      sql: "SELECT * FROM s3('s3://bucket/key', 'CSV')",
    },
    {
      name: "clusterAllReplicas() function",
      sql: "SELECT * FROM clusterAllReplicas('cluster', 'aisoc.raw_events')",
    },
    {
      name: "case-insensitive system reference",
      sql: "SELECT * FROM SYSTEM.tables",
    },
  ];

  for (const tc of cases) {
    it(`rejects ${tc.name}`, async () => {
      const client: StubClient = { get: vi.fn(), post: vi.fn() };
      const result = await lakeQueryTool.handle(makeCtx(client), { sql: tc.sql });
      expect(result.kind).toBe("json");
      if (result.kind === "json") {
        expect(result.data).toMatchObject({ error: "forbidden_reference" });
      }
      expect(client.post).not.toHaveBeenCalled();
    });
  }

  it("does not flag legitimate column or alias names that contain 'system'", async () => {
    // ``system_id`` is a perfectly legal column name. The forbidden
    // patterns require ``system`` to be *followed* by a dot or paren,
    // so this should pass the guard and reach the API.
    const client: StubClient = {
      get: vi.fn(),
      post: vi.fn().mockResolvedValue({
        columns: ["system_id"],
        rows: [[42]],
        row_count: 1,
        row_cap: 100_000,
        referenced_tables: ["aisoc.raw_events"],
        elapsed_ms: 1,
        executed_at: "2026-05-08T19:00:00Z",
      }),
    };
    await lakeQueryTool.handle(makeCtx(client), {
      sql: "SELECT system_id FROM raw_events",
    });
    expect(client.post).toHaveBeenCalledTimes(1);
  });
});

describe("lakeQueryTool — happy path", () => {
  it("forwards sql + row_cap + timeout_seconds to /api/v1/lake/sql", async () => {
    // We're explicit about the body shape because the server uses
    // FastAPI's ``LakeQueryRequest`` Pydantic model — extra keys are
    // tolerated, but missing or renamed keys would 422 silently.
    const client: StubClient = {
      get: vi.fn(),
      post: vi.fn().mockResolvedValue({
        columns: ["id"],
        rows: [[1], [2]],
        row_count: 2,
        row_cap: 5,
        referenced_tables: ["aisoc.raw_events"],
        elapsed_ms: 12,
        executed_at: "2026-05-08T19:00:00Z",
      }),
    };
    await lakeQueryTool.handle(makeCtx(client), {
      sql: "SELECT id FROM raw_events",
      row_cap: 5,
      timeout_seconds: 10,
    });

    expect(client.post).toHaveBeenCalledTimes(1);
    const [path, body] = client.post.mock.calls[0];
    expect(path).toBe("/api/v1/lake/sql");
    expect(body).toEqual({
      sql: "SELECT id FROM raw_events",
      row_cap: 5,
      timeout_seconds: 10,
    });
  });

  it("zips columns and rows into 'records' for ergonomic agent consumption", async () => {
    // The wire format is column-major (``columns: [], rows: [[]]``)
    // because ClickHouse is column-major and we want minimal
    // serialisation overhead. But agents reason better about
    // row-major ``[{col: val}, ...]`` so the tool transforms it.
    // Both the raw ``rows`` *aren't* returned here — we only emit
    // ``records`` to keep the result compact for wide tables.
    const client: StubClient = {
      get: vi.fn(),
      post: vi.fn().mockResolvedValue({
        columns: ["id", "tenant_id"],
        rows: [
          [1, "t-a"],
          [2, "t-b"],
        ],
        row_count: 2,
        row_cap: 100,
        referenced_tables: ["aisoc.raw_events"],
        elapsed_ms: 7,
        executed_at: "2026-05-08T19:00:00Z",
      }),
    };
    const result = await lakeQueryTool.handle(makeCtx(client), {
      sql: "SELECT id, tenant_id FROM raw_events",
    });
    if (result.kind !== "json") throw new Error("expected json result");
    const data = result.data as {
      records: Array<Record<string, unknown>>;
      columns: string[];
      truncated: boolean;
    };
    expect(data.columns).toEqual(["id", "tenant_id"]);
    expect(data.records).toEqual([
      { id: 1, tenant_id: "t-a" },
      { id: 2, tenant_id: "t-b" },
    ]);
    expect(data.truncated).toBe(false);
  });

  it("flags truncated=true when row_count meets row_cap", async () => {
    // The server clamps LIMIT, so when ``row_count == row_cap`` the
    // agent should suspect "there's more". This nudges it toward
    // tightening filters or paginating instead of trusting a
    // partial answer.
    const client: StubClient = {
      get: vi.fn(),
      post: vi.fn().mockResolvedValue({
        columns: ["id"],
        rows: [[1], [2], [3]],
        row_count: 3,
        row_cap: 3,
        referenced_tables: ["aisoc.raw_events"],
        elapsed_ms: 5,
        executed_at: "2026-05-08T19:00:00Z",
      }),
    };
    const result = await lakeQueryTool.handle(makeCtx(client), {
      sql: "SELECT id FROM raw_events",
      row_cap: 3,
    });
    if (result.kind !== "json") throw new Error("expected json result");
    expect((result.data as { truncated: boolean }).truncated).toBe(true);
  });

  it("omits row_cap and timeout_seconds when not provided", async () => {
    // The server has its own defaults; sending ``undefined`` in the
    // body would JSON-serialise to a missing key, which Pydantic
    // accepts. We just confirm we don't accidentally inject zeros
    // or empty strings here.
    const client: StubClient = {
      get: vi.fn(),
      post: vi.fn().mockResolvedValue({
        columns: [],
        rows: [],
        row_count: 0,
        row_cap: 100_000,
        referenced_tables: ["aisoc.raw_events"],
        elapsed_ms: 1,
        executed_at: "2026-05-08T19:00:00Z",
      }),
    };
    await lakeQueryTool.handle(makeCtx(client), { sql: "SELECT 1" });
    const [, body] = client.post.mock.calls[0];
    expect(body).toEqual({
      sql: "SELECT 1",
      row_cap: undefined,
      timeout_seconds: undefined,
    });
  });

  it("synthesises col_<index> when a column name is missing (sparse columns)", async () => {
    // Defensive: if the server ever returns a column array with a
    // missing entry (e.g. ``["id", undefined]``), we still produce a
    // usable record key so the value isn't silently dropped. The
    // record-builder iterates by ``columns.length``, so extra cells
    // *beyond* the column count are intentionally dropped — the
    // server's response invariant is ``columns.length === row.length``,
    // and we'd rather match that contract than synthesise mystery
    // keys for cells without metadata.
    const client: StubClient = {
      get: vi.fn(),
      post: vi.fn().mockResolvedValue({
        // Sparse: second column name is missing. JSON-over-the-wire
        // would render this as ``null``, which we coerce to col_<i>.
        columns: ["id", undefined as unknown as string],
        rows: [[1, "extra"]],
        row_count: 1,
        row_cap: 100,
        referenced_tables: ["aisoc.raw_events"],
        elapsed_ms: 1,
        executed_at: "2026-05-08T19:00:00Z",
      }),
    };
    const result = await lakeQueryTool.handle(makeCtx(client), {
      sql: "SELECT id FROM raw_events",
    });
    if (result.kind !== "json") throw new Error("expected json result");
    const records = (result.data as { records: Array<Record<string, unknown>> })
      .records;
    expect(records[0]).toEqual({ id: 1, col_1: "extra" });
  });

  it("drops trailing cells that have no matching column name", async () => {
    // The complement of the test above: cells *beyond* the declared
    // column count are dropped, because the loop runs over
    // ``columns.length`` not ``row.length``. Documenting this
    // explicitly so we don't accidentally "fix" it later — the
    // server's response invariant guarantees parity, and a dropped
    // cell is a clearer failure mode than a phantom ``col_N`` that
    // appears only on bad responses.
    const client: StubClient = {
      get: vi.fn(),
      post: vi.fn().mockResolvedValue({
        columns: ["id"],
        // Pathological: extra cell with no column name.
        rows: [[1, "extra"]],
        row_count: 1,
        row_cap: 100,
        referenced_tables: ["aisoc.raw_events"],
        elapsed_ms: 1,
        executed_at: "2026-05-08T19:00:00Z",
      }),
    };
    const result = await lakeQueryTool.handle(makeCtx(client), {
      sql: "SELECT id FROM raw_events",
    });
    if (result.kind !== "json") throw new Error("expected json result");
    const records = (result.data as { records: Array<Record<string, unknown>> })
      .records;
    expect(records[0]).toEqual({ id: 1 });
  });
});

describe("lakeQueryTool — error propagation", () => {
  it("propagates client.post errors to the caller", async () => {
    // The MCP server is responsible for turning thrown ApiError /
    // TransportError into the standard MCP error envelope; the tool
    // must not swallow them. If this assertion ever flips to a
    // ``json`` result we've grown a silent-failure bug.
    const client: StubClient = {
      get: vi.fn(),
      post: vi.fn().mockRejectedValue(new Error("kaboom")),
    };
    await expect(
      lakeQueryTool.handle(makeCtx(client), {
        sql: "SELECT 1 FROM raw_events",
      }),
    ).rejects.toThrow("kaboom");
  });
});

// ---------------------------------------------------------------------------
// aisoc_lake_schema
// ---------------------------------------------------------------------------

describe("lakeSchemaTool — zod schema", () => {
  it("accepts an empty argument object (returns full catalog)", () => {
    const parsed = lakeSchemaTool.schema.safeParse({});
    expect(parsed.success).toBe(true);
  });

  it("accepts an explicit list of tables", () => {
    const parsed = lakeSchemaTool.schema.safeParse({
      tables: ["raw_events", "alert_metrics"],
    });
    expect(parsed.success).toBe(true);
  });

  it("rejects more than 20 table names", () => {
    // The lake's allowlist is single-digit today, but future plugins
    // could grow it. The cap exists to prevent agents from accidentally
    // sending massive arrays that would balloon prompt context once
    // the schema is returned.
    const tables = Array.from({ length: 21 }, (_, i) => `t${i}`);
    expect(lakeSchemaTool.schema.safeParse({ tables }).success).toBe(false);
  });

  it("rejects empty table names", () => {
    expect(
      lakeSchemaTool.schema.safeParse({ tables: ["", "raw_events"] }).success,
    ).toBe(false);
  });
});

describe("lakeSchemaTool — handler", () => {
  it("calls GET /api/v1/lake/schema", async () => {
    const client: StubClient = {
      post: vi.fn(),
      get: vi.fn().mockResolvedValue({
        tables: [
          {
            table: "aisoc.raw_events",
            columns: [
              { name: "id", type: "UUID" },
              { name: "tenant_id", type: "UUID", comment: "Owning tenant" },
            ],
          },
        ],
      }),
    };
    await lakeSchemaTool.handle(makeCtx(client), {});
    expect(client.get).toHaveBeenCalledTimes(1);
    expect(client.get).toHaveBeenCalledWith("/api/v1/lake/schema");
  });

  it("returns the full catalog when 'tables' is omitted", async () => {
    const client: StubClient = {
      post: vi.fn(),
      get: vi.fn().mockResolvedValue({
        tables: [
          {
            table: "aisoc.raw_events",
            columns: [{ name: "id", type: "UUID" }],
          },
          {
            table: "aisoc.alert_metrics",
            columns: [{ name: "alert_id", type: "UUID" }],
          },
        ],
      }),
    };
    const result = await lakeSchemaTool.handle(makeCtx(client), {});
    if (result.kind !== "json") throw new Error("expected json");
    const data = result.data as {
      total: number;
      tables: Array<{ table: string }>;
    };
    expect(data.total).toBe(2);
    expect(data.tables.map((t) => t.table)).toEqual([
      "aisoc.raw_events",
      "aisoc.alert_metrics",
    ]);
  });

  it("filters client-side when 'tables' is provided", async () => {
    // The server doesn't yet support a ``tables`` query parameter;
    // we filter client-side so the tool surface is stable and the
    // server can add the param later without a tool-shape change.
    const client: StubClient = {
      post: vi.fn(),
      get: vi.fn().mockResolvedValue({
        tables: [
          {
            table: "aisoc.raw_events",
            columns: [{ name: "id", type: "UUID" }],
          },
          {
            table: "aisoc.alert_metrics",
            columns: [{ name: "alert_id", type: "UUID" }],
          },
          {
            table: "aisoc.ioc_enrichments",
            columns: [{ name: "ioc", type: "String" }],
          },
        ],
      }),
    };
    const result = await lakeSchemaTool.handle(makeCtx(client), {
      tables: ["aisoc.raw_events", "AISOC.IOC_ENRICHMENTS"], // mixed case
    });
    if (result.kind !== "json") throw new Error("expected json");
    const data = result.data as {
      total: number;
      tables: Array<{ table: string }>;
    };
    expect(data.total).toBe(2);
    expect(data.tables.map((t) => t.table).sort()).toEqual([
      "aisoc.ioc_enrichments",
      "aisoc.raw_events",
    ]);
  });

  it("normalises missing column comments to empty strings", async () => {
    // ClickHouse columns may or may not have comments; we always
    // emit ``comment: ""`` rather than ``undefined`` so the schema
    // shape is uniform for agents that don't handle "maybe field".
    const client: StubClient = {
      post: vi.fn(),
      get: vi.fn().mockResolvedValue({
        tables: [
          {
            table: "aisoc.raw_events",
            columns: [
              { name: "id", type: "UUID" }, // no comment
              { name: "tenant_id", type: "UUID", comment: "Owning tenant" },
            ],
          },
        ],
      }),
    };
    const result = await lakeSchemaTool.handle(makeCtx(client), {});
    if (result.kind !== "json") throw new Error("expected json");
    const data = result.data as {
      tables: Array<{
        columns: Array<{ name: string; comment: string }>;
      }>;
    };
    expect(data.tables[0]?.columns).toEqual([
      { name: "id", type: "UUID", comment: "" },
      { name: "tenant_id", type: "UUID", comment: "Owning tenant" },
    ]);
  });
});
