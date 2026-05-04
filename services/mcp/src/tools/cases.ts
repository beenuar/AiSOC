/**
 * Case-facing tools.
 *
 * `aisoc_list_cases` and `aisoc_get_case` mirror the alerts tools.
 * `aisoc_run_investigation` is the marquee tool — it kicks off the AiSOC
 * investigator agent on a case and returns the run_id that the agent can
 * subsequently poll via `aisoc_replay_decision`.
 *
 * Note on streaming: the FastAPI `/cases/{id}/investigate` endpoint
 * returns immediately with a run_id and status `started`. We do *not*
 * stream the live agent events back through MCP because the spec's
 * single-shot tool-call shape doesn't fit a long-running stream cleanly,
 * and MCP hosts vary in how they handle pending tool results. Instead we
 * return the run_id and let the agent poll with the dedicated investigation
 * tools — that pattern composes well in chat ("kick it off, and check on
 * it in 30 seconds").
 */
import { z } from "zod";

import { zodToJsonSchema } from "./alerts.js";
import type { ToolDefinition } from "./types.js";
import { json } from "./types.js";

interface CaseResponse {
  id: string;
  case_number: string;
  title: string;
  description: string | null;
  status: string;
  priority: string;
  severity: string;
  case_type: string | null;
  alert_ids: string[];
  tags: string[];
  assigned_to_id: string | null;
  resolution: string | null;
  lessons_learned: string | null;
  created_at: string;
  closed_at: string | null;
  [key: string]: unknown;
}

interface CaseListResponse {
  items: CaseResponse[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

interface InvestigateResponse {
  run_id: string;
  case_id: string;
  status: string;
  message: string;
}

// ---------------------------------------------------------------------------
// aisoc_list_cases
// ---------------------------------------------------------------------------

const ListCasesSchema = z
  .object({
    status: z.enum(["new", "open", "investigating", "containment", "eradication", "recovery", "closed", "cancelled"]).optional(),
    priority: z.enum(["p0", "p1", "p2", "p3"]).optional(),
    assigned_to_me: z.boolean().optional(),
    page: z.number().int().min(1).max(1000).default(1),
    page_size: z.number().int().min(1).max(50).default(25),
  })
  .strict();

export const listCasesTool: ToolDefinition<typeof ListCasesSchema> = {
  metadata: {
    name: "aisoc_list_cases",
    description:
      "List security cases (incidents). Filter by status, priority, or assigned-to-me. Cases are higher-level groupings of related alerts.",
    inputSchema: zodToJsonSchema(ListCasesSchema),
  },
  schema: ListCasesSchema,
  async handle(ctx, args) {
    const data = await ctx.client.get<CaseListResponse>("/api/v1/cases", {
      query: {
        status: args.status,
        priority: args.priority,
        assigned_to_me: args.assigned_to_me,
        page: args.page,
        page_size: args.page_size,
      },
    });
    return json({
      total: data.total,
      page: data.page,
      page_size: data.page_size,
      pages: data.pages,
      items: data.items.map(summariseCase),
    });
  },
};

// ---------------------------------------------------------------------------
// aisoc_get_case
// ---------------------------------------------------------------------------

const GetCaseSchema = z
  .object({
    case_id: z.string().uuid().describe("UUID of the case (from `aisoc_list_cases`)."),
    include_timeline: z
      .boolean()
      .default(false)
      .describe("If true, also include the case timeline (comments + events)."),
  })
  .strict();

export const getCaseTool: ToolDefinition<typeof GetCaseSchema> = {
  metadata: {
    name: "aisoc_get_case",
    description:
      "Fetch a case by id. Optionally include the timeline of comments, status changes, and analyst actions.",
    inputSchema: zodToJsonSchema(GetCaseSchema),
  },
  schema: GetCaseSchema,
  async handle(ctx, args) {
    const caseRecord = await ctx.client.get<CaseResponse>(`/api/v1/cases/${args.case_id}`);
    let timeline: unknown = undefined;
    if (args.include_timeline) {
      timeline = await ctx.client.get<unknown[]>(`/api/v1/cases/${args.case_id}/timeline`);
    }
    return json({ case: caseRecord, timeline });
  },
};

// ---------------------------------------------------------------------------
// aisoc_run_investigation
// ---------------------------------------------------------------------------

const RunInvestigationSchema = z
  .object({
    case_id: z.string().uuid().describe("UUID of the case to investigate."),
    alert_summary: z
      .string()
      .optional()
      .describe(
        "Optional human-readable summary used to seed the recon agent. If omitted, AiSOC builds one from linked alerts.",
      ),
  })
  .strict();

export const runInvestigationTool: ToolDefinition<typeof RunInvestigationSchema> = {
  metadata: {
    name: "aisoc_run_investigation",
    description:
      "Kick off the AiSOC multi-agent investigator on a case. Returns a run_id immediately; use `aisoc_replay_decision` to fetch the resulting decision ledger.",
    inputSchema: zodToJsonSchema(RunInvestigationSchema),
  },
  schema: RunInvestigationSchema,
  async handle(ctx, args) {
    const data = await ctx.client.post<InvestigateResponse>(
      `/api/v1/cases/${args.case_id}/investigate`,
      {
        alert_summary: args.alert_summary ?? "",
        raw_alert: {},
      },
    );
    return json({
      run_id: data.run_id,
      case_id: data.case_id,
      status: data.status,
      message: data.message,
      next_step:
        "Wait 5–30 seconds, then call `aisoc_replay_decision` with this run_id to inspect the agent's decisions.",
    });
  },
};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function summariseCase(c: CaseResponse): Record<string, unknown> {
  return {
    id: c.id,
    case_number: c.case_number,
    title: c.title,
    status: c.status,
    priority: c.priority,
    severity: c.severity,
    assigned_to_id: c.assigned_to_id,
    alert_count: c.alert_ids.length,
    tags: c.tags,
    created_at: c.created_at,
    closed_at: c.closed_at,
  };
}
