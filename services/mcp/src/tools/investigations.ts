/**
 * Investigation-ledger tools — the trust-vector surface that AiSOC's
 * closed-source competitors literally can't expose, because their agents
 * are black-box cloud services.
 *
 * These tools let an MCP-aware agent answer "what did the AiSOC agent
 * do, and why?" by walking the persistent decision ledger written in
 * Phase 1A.
 */
import { z } from "zod";

import { zodToJsonSchema } from "./alerts.js";
import type { ToolDefinition } from "./types.js";
import { json } from "./types.js";

interface RunSummary {
  id: string;
  case_id: string;
  status: string;
  model_used: string | null;
  iterations: number;
  total_tokens: number;
  total_cost_usd: number;
  started_at: string;
  completed_at: string | null;
  error: string | null;
}

interface RunDetail extends RunSummary {
  alert_summary: string | null;
  event_count: number;
  artifact_count: number;
}

interface EventOut {
  id: string;
  run_id: string;
  seq: number;
  ts: string;
  kind: string;
  agent: string;
  summary: string;
  payload: Record<string, unknown> | null;
  input_hash: string | null;
  output_hash: string | null;
  duration_ms: number;
}

interface ExplainResponse {
  run: RunSummary;
  previous: EventOut | null;
  focus: EventOut;
  next: EventOut | null;
  artifacts: Array<{
    id: string;
    kind: string;
    sha256: string;
    size_bytes: number;
    event_id: string | null;
    created_at: string;
    content: string | null;
    blob_ref: string | null;
  }>;
}

// ---------------------------------------------------------------------------
// aisoc_list_investigations
// ---------------------------------------------------------------------------

const ListInvestigationsSchema = z
  .object({
    case_id: z
      .string()
      .optional()
      .describe(
        "Restrict to runs for a specific case. Accepts UUIDs or external case ids (e.g. INC-001).",
      ),
    status: z
      .enum(["running", "completed", "failed"])
      .optional()
      .describe("Filter by run status."),
    limit: z.number().int().min(1).max(200).default(50),
  })
  .strict();

export const listInvestigationsTool: ToolDefinition<typeof ListInvestigationsSchema> = {
  metadata: {
    name: "aisoc_list_investigations",
    description:
      "List recent investigation runs for the connected tenant. Each run is a single agent execution against a case.",
    inputSchema: zodToJsonSchema(ListInvestigationsSchema),
  },
  schema: ListInvestigationsSchema,
  async handle(ctx, args) {
    const data = await ctx.client.get<RunSummary[]>("/api/v1/investigations", {
      query: {
        case_id: args.case_id,
        status: args.status,
        limit: args.limit,
      },
    });
    return json(data);
  },
};

// ---------------------------------------------------------------------------
// aisoc_get_investigation
// ---------------------------------------------------------------------------

const GetInvestigationSchema = z
  .object({
    run_id: z.string().uuid().describe("Investigation run UUID."),
  })
  .strict();

export const getInvestigationTool: ToolDefinition<typeof GetInvestigationSchema> = {
  metadata: {
    name: "aisoc_get_investigation",
    description:
      "Fetch a single investigation run with summary stats (status, model, tokens, cost, event/artifact counts).",
    inputSchema: zodToJsonSchema(GetInvestigationSchema),
  },
  schema: GetInvestigationSchema,
  async handle(ctx, args) {
    const data = await ctx.client.get<RunDetail>(`/api/v1/investigations/${args.run_id}`);
    return json(data);
  },
};

// ---------------------------------------------------------------------------
// aisoc_replay_decision
// ---------------------------------------------------------------------------

const ReplayDecisionSchema = z
  .object({
    run_id: z.string().uuid(),
    since_seq: z
      .number()
      .int()
      .min(0)
      .optional()
      .describe(
        "Return only events with seq strictly greater than this value. Use to tail long-running investigations without re-pulling history.",
      ),
    limit: z
      .number()
      .int()
      .min(1)
      .max(500)
      .default(200)
      .describe("Cap the number of events returned. Capped lower than the API to keep MCP context budgets sane."),
  })
  .strict();

export const replayDecisionTool: ToolDefinition<typeof ReplayDecisionSchema> = {
  metadata: {
    name: "aisoc_replay_decision",
    description:
      "Walk the agent decision ledger for an investigation run. Returns each step (recon, forensic, responder, reporter, tool-calls, errors) with summaries and timing. Use `aisoc_explain_step` for a deep dive on a single step.",
    inputSchema: zodToJsonSchema(ReplayDecisionSchema),
  },
  schema: ReplayDecisionSchema,
  async handle(ctx, args) {
    const data = await ctx.client.get<{
      items: EventOut[];
      total: number;
      since: number | null;
      next_seq: number | null;
    }>(`/api/v1/investigations/${args.run_id}/events`, {
      query: { since: args.since_seq, limit: args.limit },
    });
    return json({
      total: data.total,
      next_seq: data.next_seq,
      // Trim payloads here; the explain tool returns the full thing.
      items: data.items.map(summariseEvent),
    });
  },
};

// ---------------------------------------------------------------------------
// aisoc_explain_step
// ---------------------------------------------------------------------------

const ExplainStepSchema = z
  .object({
    run_id: z.string().uuid(),
    step: z
      .number()
      .int()
      .min(0)
      .describe("Event seq number — the integer index from `aisoc_replay_decision`."),
  })
  .strict();

export const explainStepTool: ToolDefinition<typeof ExplainStepSchema> = {
  metadata: {
    name: "aisoc_explain_step",
    description:
      "Why-did-the-agent-do-this view for a single decision step. Returns the focal event, the previous and next events for context, and any inlined artifacts (LLM prompts/responses, tool I/O) attached to that step.",
    inputSchema: zodToJsonSchema(ExplainStepSchema),
  },
  schema: ExplainStepSchema,
  async handle(ctx, args) {
    const data = await ctx.client.get<ExplainResponse>(
      `/api/v1/investigations/${args.run_id}/explain`,
      { query: { step: args.step } },
    );
    return json(data);
  },
};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function summariseEvent(e: EventOut): Record<string, unknown> {
  return {
    seq: e.seq,
    ts: e.ts,
    kind: e.kind,
    agent: e.agent,
    summary: e.summary,
    duration_ms: e.duration_ms,
    has_payload: e.payload !== null && Object.keys(e.payload ?? {}).length > 0,
  };
}
