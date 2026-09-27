/**
 * Tool registry.
 *
 * Single export the server depends on, so adding a new tool is a one-line
 * change here and a single new file under `./tools/`. The order of this
 * array is the order tools are advertised to MCP hosts; we keep the
 * "discovery" tools (alerts/list, cases/list, query) before deep-dive
 * tools so an agent reading the listing top-to-bottom builds an
 * intuition of how to navigate the surface.
 */
import { listActionsTool, previewActionTool } from "./actions.js";
import { getAlertTool, listAlertsTool } from "./alerts.js";
import {
  getCaseTool,
  listCasesTool,
  runInvestigationTool,
} from "./cases.js";
import {
  getDetectionRuleTool,
  queryDetectionsTool,
} from "./detections.js";
import {
  explainStepTool,
  getInvestigationTool,
  listInvestigationsTool,
  replayDecisionTool,
} from "./investigations.js";
import { lakeQueryTool, lakeSchemaTool } from "./lake.js";
import { getReplayReportTool, listReplayReportsTool } from "./replay.js";
import { getTriageVerdictTool } from "./triage.js";
import type { ToolDefinition } from "./types.js";

export const ALL_TOOLS: ToolDefinition[] = [
  // Discovery
  listAlertsTool,
  listCasesTool,
  queryDetectionsTool,
  listInvestigationsTool,
  listReplayReportsTool,
  listActionsTool,
  lakeSchemaTool,
  // Deep-dive
  getAlertTool,
  getCaseTool,
  getDetectionRuleTool,
  getInvestigationTool,
  getTriageVerdictTool,
  getReplayReportTool,
  // Lake query (warm tier — gated by lake:query permission server-side).
  // Listed near the bottom because it's the most expensive surface and
  // the schema tool above is the recommended discovery path; agents that
  // read the listing top-to-bottom should reach for SELECT only after
  // they've seen the structured tools.
  lakeQueryTool,
  // Action / replay. `previewActionTool` is the only tool here that touches
  // the response surface, and it is dry-run only: it names the dry-run path
  // and nothing in `src/` names `/dispatch`. `tests/actions.test.ts` asserts
  // that against the source rather than trusting this comment.
  runInvestigationTool,
  previewActionTool,
  replayDecisionTool,
  explainStepTool,
];

/** Convenience for the server: name → definition lookup. */
export const TOOL_BY_NAME: Record<string, ToolDefinition> = Object.fromEntries(
  ALL_TOOLS.map((t) => [t.metadata.name, t]),
);
