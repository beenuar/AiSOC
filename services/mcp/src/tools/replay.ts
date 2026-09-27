/**
 * Replay evaluations: how AiSOC scored against a tenant's own analysts.
 *
 * Gap-closure Phase 5.6, over the surfaces Phase 1.4 shipped.
 *
 * A replay grades AiSOC's triage against decisions the tenant's analysts
 * already made on their own closed findings. It is the one number in this
 * product measured on real data rather than on a synthetic corpus, which
 * makes it the number an agent asking "can I trust this thing" should read
 * first, and also the one most worth getting the caveats right on.
 *
 * Two of those caveats are carried in the payload rather than left to the
 * reader:
 *
 * The headline accuracy is **withheld** below 30 malicious cases, and the
 * report says so in a sentence instead of printing a figure. This tool
 * passes that sentence through untouched. Substituting a number, or a zero,
 * or a dash, would turn a deliberate refusal into a measurement.
 *
 * Every rate travels with the count it was computed over. A rate with no
 * denominator reads "not measured" rather than as a value, and an agent
 * reporting 100% over two cases is worse than one reporting nothing.
 */
import { z } from "zod";

import { zodToJsonSchema } from "./alerts.js";
import type { ToolDefinition } from "./types.js";
import { json, text } from "./types.js";

interface EvaluationSummary {
  id: string;
  vendor: string;
  status: string;
  findings_read: number;
  findings_graded: number;
  created_at: string;
  completed_at: string | null;
  [key: string]: unknown;
}

interface EvaluationDetail extends EvaluationSummary {
  report_markdown: string | null;
  score: Record<string, unknown> | null;
  error: string | null;
}

// ---------------------------------------------------------------------------
// aisoc_list_replay_reports
// ---------------------------------------------------------------------------

const ListReplaySchema = z
  .object({
    limit: z.number().int().min(1).max(200).default(20).describe("How many evaluations to return, newest first."),
  })
  .strict();

export const listReplayReportsTool: ToolDefinition<typeof ListReplaySchema> = {
  metadata: {
    name: "aisoc_list_replay_reports",
    description:
      "List this tenant's replay evaluations: runs that graded AiSOC triage against the tenant's own analysts' past decisions. Returns the vendor, the window and how many findings were read and graded.",
    inputSchema: zodToJsonSchema(ListReplaySchema),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  schema: ListReplaySchema,
  async handle(ctx, args) {
    const rows = await ctx.client.get<EvaluationSummary[]>("/api/v1/evaluations/replay", {
      query: { limit: args.limit },
    });
    return json({
      count: rows.length,
      evaluations: rows,
      note:
        rows.length === 0
          ? "This tenant has run no replay evaluations. That is an absence of measurement, not a measurement of zero."
          : "Read one with `aisoc_get_replay_report`. Each rate in a report travels with the count it was computed over.",
    });
  },
};

// ---------------------------------------------------------------------------
// aisoc_get_replay_report
// ---------------------------------------------------------------------------

const GetReplaySchema = z
  .object({
    evaluation_id: z.string().uuid().describe("Evaluation UUID, from `aisoc_list_replay_reports`."),
    format: z
      .enum(["markdown", "json"])
      .default("markdown")
      .describe(
        "`markdown` returns the stored report as written, including the sentence that replaces a withheld headline. `json` returns the structured score.",
      ),
  })
  .strict();

export const getReplayReportTool: ToolDefinition<typeof GetReplaySchema> = {
  metadata: {
    name: "aisoc_get_replay_report",
    description:
      "Fetch one replay evaluation report. Returns the stored artefact rather than re-rendering it, so the numbers are the ones that were published. A withheld headline stays withheld.",
    inputSchema: zodToJsonSchema(GetReplaySchema),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  schema: GetReplaySchema,
  async handle(ctx, args) {
    const detail = await ctx.client.get<EvaluationDetail>(
      `/api/v1/evaluations/replay/${args.evaluation_id}`,
    );

    if (detail.status !== "completed") {
      return json({
        evaluation_id: detail.id,
        status: detail.status,
        error: detail.error,
        note:
          "This evaluation did not complete, so it has no report. A partial replay is not a smaller measurement: the findings it did grade were not a chosen sample.",
      });
    }

    if (args.format === "json") {
      return json({
        evaluation_id: detail.id,
        vendor: detail.vendor,
        findings_read: detail.findings_read,
        findings_graded: detail.findings_graded,
        score: detail.score,
        note: "Every rate in `score` carries the count it was computed over. A rate with no count was not measured.",
      });
    }

    // The stored Markdown, untouched. Re-rendering it here would eventually
    // mean two definitions of what a replay report says, and the one an
    // agent quotes would not be the one the operator exported.
    const report = detail.report_markdown ?? "";
    return text(report, {
      evaluation_id: detail.id,
      vendor: detail.vendor,
      findings_read: detail.findings_read,
      findings_graded: detail.findings_graded,
    });
  },
};
