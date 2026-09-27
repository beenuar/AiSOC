/**
 * Tenant lake tools — Workstream 7.
 *
 * Two tools forwarded to the AiSOC API's ``/api/v1/lake/...`` surface:
 *
 *   - ``aisoc_lake_query``  → POST /api/v1/lake/sql
 *   - ``aisoc_lake_schema`` → GET  /api/v1/lake/schema
 *
 * The API does the heavy lifting (sqlglot rewrite, ``tenant_id``
 * predicate injection, table allowlist, rate limiting). This MCP layer
 * is a thin pass-through plus three local guardrails that catch
 * obvious foot-guns *before* a token is wasted on a round trip:
 *
 *   1. **Single statement.** We reject anything containing an
 *      unquoted ``;`` followed by non-whitespace. The server enforces
 *      this too, but a local check turns prompt-injection attempts
 *      ("ignore your previous instructions; DROP TABLE …") into a
 *      400-equivalent error without a network hop.
 *
 *   2. **Length cap.** The API accepts up to 200 KB per request
 *      (matching the FastAPI body cap); exceeding that here gives a
 *      friendlier error and sidesteps the chance of a huge prompt
 *      tying up the agent's context budget on garbage.
 *
 *   3. **No system / cluster table references.** Even though the
 *      server's allowlist already blocks them, a local screen lets
 *      us surface a clearer "you're asking for ``system.tables``,
 *      that's not a lake table" message to the agent.
 *
 * The agent should *not* try to embed ``tenant_id = '…'`` in the
 * query — the rewriter does that automatically, and a hand-rolled
 * predicate is at best redundant and at worst a hint that the agent
 * is trying to read another tenant's data (which the rewriter would
 * AND-out anyway). The tool description spells this out so the model
 * stops trying.
 */
import { z } from "zod";

import { zodToJsonSchema } from "./alerts.js";
import type { ToolDefinition } from "./types.js";
import { json } from "./types.js";

// ---------------------------------------------------------------------------
// Shared types — keep field-by-field aligned with the server's
// ``LakeQueryResponse`` and ``LakeSchemaResponse`` Pydantic models. We
// don't generate these from OpenAPI for the same reason ``client.ts``
// hand-rolls fetch: a deployed AiSOC may add fields in a future release
// and we'd rather pass them through than crash on parse.
// ---------------------------------------------------------------------------

/** Server response for ``POST /api/v1/lake/sql``. */
interface LakeQueryServerResponse {
  columns: string[];
  rows: unknown[][];
  row_count: number;
  row_cap: number;
  referenced_tables: string[];
  elapsed_ms: number;
  executed_at: string;
  // Forward-compatible fields tolerated.
  [key: string]: unknown;
}

interface LakeColumnInfoServer {
  name: string;
  type: string;
  comment?: string;
}

interface LakeTableInfoServer {
  table: string;
  columns: LakeColumnInfoServer[];
}

interface LakeSchemaServerResponse {
  tables: LakeTableInfoServer[];
  [key: string]: unknown;
}

// ---------------------------------------------------------------------------
// Local guard rails. The server is the source of truth for policy; these
// just trim trips for obviously-malformed input.
// ---------------------------------------------------------------------------

/** Hard cap mirroring the server's ``LakeQueryRequest.sql.max_length``. */
const MAX_SQL_BYTES = 200_000;

/**
 * Quick screen for "looks like multiple statements". A real parser is
 * overkill here — the server runs sqlglot — but we want to reject
 * prompt-injection-shaped strings without a network round trip.
 *
 * The regex matches a ``;`` not inside single or double quotes,
 * followed by any non-whitespace character. We don't try to handle
 * SQL comments or backslash-escaped quotes; sqlglot on the server
 * does that properly. This is purely a fast-path.
 */
function looksLikeMultipleStatements(sql: string): boolean {
  // Strip comments before scanning so ``-- chatty comment;`` is fine.
  // ClickHouse supports both line comments (--) and block comments (/* */).
  const noBlockComments = sql.replace(/\/\*[\s\S]*?\*\//g, " ");
  const noLineComments = noBlockComments.replace(/--[^\n]*/g, " ");

  let inSingle = false;
  let inDouble = false;
  let inBackquote = false;
  for (let i = 0; i < noLineComments.length; i++) {
    const ch = noLineComments[i];
    const prev = i > 0 ? noLineComments[i - 1] : "";
    if (ch === "'" && prev !== "\\" && !inDouble && !inBackquote) {
      inSingle = !inSingle;
      continue;
    }
    if (ch === '"' && prev !== "\\" && !inSingle && !inBackquote) {
      inDouble = !inDouble;
      continue;
    }
    if (ch === "`" && !inSingle && !inDouble) {
      inBackquote = !inBackquote;
      continue;
    }
    if (ch === ";" && !inSingle && !inDouble && !inBackquote) {
      // Anything after the semicolon that isn't whitespace makes it a
      // second statement.
      const tail = noLineComments.slice(i + 1).trim();
      if (tail.length > 0) return true;
    }
  }
  return false;
}

/**
 * Tables the server does not allow. The server is authoritative — we
 * just want a faster rejection so the agent can iterate without a
 * round trip per attempt. Patterns are case-insensitive.
 */
const FORBIDDEN_TABLE_PATTERNS: RegExp[] = [
  /\bsystem\s*\./i,
  /\binformation_schema\s*\./i,
  /\bclusterAllReplicas\s*\(/i,
  /\bcluster\s*\(/i,
  /\bremote\s*\(/i,
  /\bremoteSecure\s*\(/i,
  /\burl\s*\(/i,
  /\bs3\s*\(/i,
  /\bfile\s*\(/i,
  /\bjdbc\s*\(/i,
  /\bodbc\s*\(/i,
  /\bmysql\s*\(/i,
  /\bpostgresql\s*\(/i,
];

function findForbiddenReference(sql: string): string | null {
  for (const pattern of FORBIDDEN_TABLE_PATTERNS) {
    const match = pattern.exec(sql);
    if (match) return match[0];
  }
  return null;
}

// ---------------------------------------------------------------------------
// aisoc_lake_query
// ---------------------------------------------------------------------------

const LakeQuerySchema = z
  .object({
    sql: z
      .string()
      .min(1)
      .max(MAX_SQL_BYTES)
      .describe(
        [
          "ClickHouse SQL SELECT statement to run against the warm tier of",
          "the connected AiSOC tenant. The server enforces:",
          "  - Single SELECT (no DDL/DML/multi-statement).",
          "  - Allowlisted tables only (raw_events, alert_metrics,",
          "    ioc_enrichments). System and cluster tables are blocked.",
          "  - tenant_id predicates are injected automatically — DO NOT",
          "    add `tenant_id = '...'` to your query; it is redundant",
          "    and will not let you read another tenant's data.",
          "  - LIMIT is clamped to a server-configured cap.",
          "Use `aisoc_lake_schema` first if you don't know the columns.",
        ].join(" "),
      ),
    row_cap: z
      .number()
      .int()
      .min(1)
      .max(100_000)
      .optional()
      .describe(
        "Optional row cap; the server clamps to its own max (100k by default). "
          + "Useful when you want a smaller result set for quick exploration.",
      ),
    timeout_seconds: z
      .number()
      .min(0.1)
      .max(60)
      .optional()
      .describe(
        "Optional wall-clock timeout in seconds (max 60). Defaults to the "
          + "server cap (30s). Set lower for fast iteration.",
      ),
  })
  .strict();

export const lakeQueryTool: ToolDefinition<typeof LakeQuerySchema> = {
  metadata: {
    name: "aisoc_lake_query",
    description:
      "Run a tenant-scoped SELECT against the warm-tier security data lake "
        + "(ClickHouse). Tenant isolation, table allowlisting, and LIMIT clamping "
        + "are enforced server-side. Use `aisoc_lake_schema` to discover columns.",
    inputSchema: zodToJsonSchema(LakeQuerySchema),
    // SELECT only, rewritten with a tenant predicate server-side, so it
    // reads and cannot write. Not idempotent as a claim about results:
    // the same query over a live lake returns more rows later.
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  },
  schema: LakeQuerySchema,
  async handle(ctx, args) {
    const sql = args.sql;

    // Local guard 1: single-statement.
    if (looksLikeMultipleStatements(sql)) {
      return json({
        error: "multi_statement",
        message:
          "Lake API only accepts a single SELECT per call. Remove the trailing "
            + "`;` and any subsequent statement.",
      });
    }

    // Local guard 2: forbidden table reference.
    const forbidden = findForbiddenReference(sql);
    if (forbidden) {
      return json({
        error: "forbidden_reference",
        match: forbidden,
        message:
          `Reference to '${forbidden}' is not allowed by the lake. `
            + "Use only the allowlisted tables (see `aisoc_lake_schema`).",
      });
    }

    // Local guard 3: byte cap. zod already validates this, but if the
    // host tolerates oversized strings we surface a clean error here.
    if (sql.length > MAX_SQL_BYTES) {
      return json({
        error: "sql_too_long",
        max_bytes: MAX_SQL_BYTES,
        actual_bytes: sql.length,
        message:
          "SQL exceeds the lake's per-request byte cap. Refactor with CTEs or "
            + "use a smaller intermediate query.",
      });
    }

    // Forward to the API. The body shape mirrors `LakeQueryRequest`.
    const data = await ctx.client.post<LakeQueryServerResponse>(
      "/api/v1/lake/sql",
      {
        sql,
        row_cap: args.row_cap,
        timeout_seconds: args.timeout_seconds,
      },
    );

    // Re-shape rows into ``[{col: val, ...}, ...]`` so an LLM doesn't
    // have to zip ``columns`` against ``rows`` mentally on every call.
    // We *also* keep the raw ``rows`` array because it's smaller for
    // wide result sets and some agents prefer it; ``records`` is the
    // ergonomic view.
    const records = data.rows.map((row) => {
      const obj: Record<string, unknown> = {};
      for (let i = 0; i < data.columns.length; i++) {
        obj[data.columns[i] ?? `col_${i}`] = row[i];
      }
      return obj;
    });

    // Truncation hint: if the row count equals the row_cap, the agent
    // should know there's likely more data and consider tightening
    // its filter or paginating.
    const truncated =
      typeof data.row_cap === "number" && data.row_count >= data.row_cap;

    return json({
      columns: data.columns,
      records,
      row_count: data.row_count,
      row_cap: data.row_cap,
      truncated,
      referenced_tables: data.referenced_tables,
      elapsed_ms: data.elapsed_ms,
      executed_at: data.executed_at,
    });
  },
};

// ---------------------------------------------------------------------------
// aisoc_lake_schema
// ---------------------------------------------------------------------------

const LakeSchemaSchema = z
  .object({
    tables: z
      .array(z.string().min(1).max(128))
      .max(20)
      .optional()
      .describe(
        "Optional list of table names to fetch. If omitted, returns metadata "
          + "for every allowlisted table in the lake.",
      ),
  })
  .strict();

export const lakeSchemaTool: ToolDefinition<typeof LakeSchemaSchema> = {
  metadata: {
    name: "aisoc_lake_schema",
    description:
      "List columns + types for the lake's allowlisted tables. Use this "
        + "before calling `aisoc_lake_query` so you don't guess column names.",
    inputSchema: zodToJsonSchema(LakeSchemaSchema),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  schema: LakeSchemaSchema,
  async handle(ctx, args) {
    const data = await ctx.client.get<LakeSchemaServerResponse>(
      "/api/v1/lake/schema",
    );

    // Apply the optional client-side filter. The server doesn't take
    // a ``tables`` query param yet — we keep the surface stable here
    // so a future server filter is a swap-out, not a tool-shape
    // change.
    let tables = data.tables;
    if (args.tables && args.tables.length > 0) {
      const wanted = new Set(args.tables.map((t) => t.toLowerCase()));
      tables = tables.filter((t) => wanted.has(t.table.toLowerCase()));
    }

    return json({
      total: tables.length,
      tables: tables.map((t) => ({
        table: t.table,
        columns: t.columns.map((c) => ({
          name: c.name,
          type: c.type,
          comment: c.comment ?? "",
        })),
      })),
    });
  },
};
