/**
 * The agent's verdict on one alert, and how much of it was measured.
 *
 * Gap-closure Phase 5.6.
 *
 * `aisoc_get_alert` already returns the whole alert record, verdict fields
 * included, so this is not a new capability. It is a focused one: an agent
 * asking "what did AiSOC decide about this, and should I believe it?" gets
 * the verdict, the confidence, the reasoning behind the confidence and the
 * disposition, without 30 unrelated columns competing for the answer.
 *
 * Two fields are easy to read wrongly and are handled explicitly.
 *
 * `confidence` is an integer 0 to 100 and `ai_score` is a float. They are
 * different scales measuring different things, and a consumer that treats
 * one as the other renders `2100%`, which this repository has shipped once
 * already. The payload keeps them apart by name and states the scale.
 *
 * A null verdict is not a benign verdict. An alert nothing has triaged yet
 * has `ai_summary: null`, and reporting that as "no threat found" is the
 * absence-of-evidence error with a confident face on. `triaged` is an
 * explicit boolean and the payload says which case it is in words.
 */
import { z } from "zod";

import { zodToJsonSchema } from "./alerts.js";
import type { ToolDefinition } from "./types.js";
import { json } from "./types.js";

interface AlertVerdictFields {
  id: string;
  title: string;
  severity: string;
  status: string;
  disposition: string | null;
  ai_score: number | null;
  ai_summary: string | null;
  ai_recommendations: unknown[];
  confidence: number | null;
  confidence_label: string | null;
  confidence_rationale: unknown[] | null;
  mitre_tactics: string[];
  mitre_techniques: string[];
  case_id: string | null;
  [key: string]: unknown;
}

const GetTriageVerdictSchema = z
  .object({
    alert_id: z.string().uuid().describe("Alert UUID, from `aisoc_list_alerts`."),
  })
  .strict();

export const getTriageVerdictTool: ToolDefinition<typeof GetTriageVerdictSchema> = {
  metadata: {
    name: "aisoc_get_triage_verdict",
    description:
      "What the AiSOC agent decided about one alert: verdict summary, recommended actions, confidence with its rationale, and the analyst disposition if one was recorded. Says so explicitly when nothing has triaged the alert yet.",
    inputSchema: zodToJsonSchema(GetTriageVerdictSchema),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  schema: GetTriageVerdictSchema,
  async handle(ctx, args) {
    const alert = await ctx.client.get<AlertVerdictFields>(`/api/v1/alerts/${args.alert_id}`);

    const triaged = alert.ai_summary !== null && alert.ai_summary !== "";
    return json({
      alert_id: alert.id,
      title: alert.title,
      severity: alert.severity,
      status: alert.status,
      triaged,
      // Said in words as well as in the boolean, because the next reader of
      // this payload is a language model and a false boolean is easy to
      // skim past on the way to a null summary.
      note: triaged
        ? "This alert has been triaged. The summary below is the agent's, not an analyst's."
        : "Nothing has triaged this alert yet. An absent verdict is not a benign verdict: do not report this as 'no threat found'.",
      verdict: {
        summary: alert.ai_summary,
        recommended_actions: alert.ai_recommendations ?? [],
        disposition: alert.disposition,
        disposition_note:
          "`disposition` is the analyst's field, set from the feedback endpoint. Null means no analyst has ruled on it.",
      },
      confidence: {
        // Two different scales. Kept apart by name, with the scale stated,
        // because a consumer that treats one as the other renders 2100%.
        score_0_to_100: alert.confidence,
        band: alert.confidence_label,
        rationale: alert.confidence_rationale ?? [],
        ai_score_0_to_1: alert.ai_score,
      },
      mitre: {
        tactics: alert.mitre_tactics ?? [],
        techniques: alert.mitre_techniques ?? [],
      },
      case_id: alert.case_id,
      next_step:
        alert.case_id === null
          ? "No case is attached. `aisoc_run_investigation` needs a case."
          : "Use `aisoc_list_investigations` with this case_id to see what the agent actually did, then `aisoc_replay_decision` for the ledger.",
    });
  },
};
