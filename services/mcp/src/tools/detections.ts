/**
 * Detection-content tools.
 *
 * `aisoc_query_detections` filters server-side. It used to over-fetch the
 * whole library and filter in this process, which was safe only because the
 * route it reads answered with an empty list on every deployment — nothing
 * wrote a built-in rule into the table it queried (#1273). It now returns
 * the 2,586-rule compiled corpus the detection engine actually runs, so the
 * search term, severity and technique go to the API and the page bound is
 * the tool's own limit.
 *
 * We also expose `aisoc_get_detection_rule` so an agent that finds a
 * rule by query can deep-dive into its body, MITRE mappings, and FP
 * notes when drafting a tighter version.
 */
import { z } from "zod";

import { zodToJsonSchema } from "./alerts.js";
import type { ToolDefinition } from "./types.js";
import { json } from "./types.js";

interface DetectionRuleResponse {
  id: string;
  tenant_id: string | null;
  name: string;
  description: string | null;
  rule_language: string;
  rule_body: string;
  category: string;
  status: string;
  severity: string;
  confidence: number;
  mitre_tactics: string[];
  mitre_techniques: string[];
  fp_rate: number;
  total_hits: number;
  last_triggered: string | null;
  tags: string[];
  is_builtin: boolean;
  version: number;
  created_at: string;
  updated_at: string;
  /** The detection engine's own rule id, for a compiled built-in. */
  source_id?: string | null;
  /** False when `confidence` is a placeholder rather than a measurement. */
  confidence_measured?: boolean;
  /** Whether the tenant has stored any decision about this rule. */
  tuned?: boolean;
  /** `aisoc-engine` when fusion loads and evaluates the rule. */
  engine?: string;
}

// ---------------------------------------------------------------------------
// aisoc_query_detections
// ---------------------------------------------------------------------------

const QueryDetectionsSchema = z
  .object({
    query: z
      .string()
      .optional()
      .describe(
        "Free-text query matched (case-insensitive) against name, description, tags, and MITRE technique IDs. Omit to list all rules.",
      ),
    category: z
      .enum([
        "endpoint",
        "network",
        "cloud",
        "identity",
        "application",
        "data",
      ])
      .optional()
      .describe("Restrict to a single detection category."),
    rule_language: z
      .enum(["sigma", "yara", "kql", "eql", "aisoc-match"])
      .optional()
      .describe(
        "Restrict by rule language. `aisoc-match` is the compiled spec the fusion detection engine loads and evaluates.",
      ),
    severity: z
      .enum(["critical", "high", "medium", "low", "info"])
      .optional()
      .describe("Restrict by severity (client-side filter)."),
    mitre_technique: z
      .string()
      .optional()
      .describe(
        "MITRE ATT&CK technique id (e.g. T1059.003). Matches any rule mapping that technique.",
      ),
    include_builtin: z
      .boolean()
      .default(true)
      .describe("If false, only tenant-authored rules are returned."),
    limit: z
      .number()
      .int()
      .min(1)
      .max(50)
      .default(20)
      .describe("Cap returned matches. Capped low to fit MCP context budgets."),
  })
  .strict();

export const queryDetectionsTool: ToolDefinition<typeof QueryDetectionsSchema> = {
  metadata: {
    name: "aisoc_query_detections",
    description:
      "Search the detection-rule library by free text, category, language, severity, or MITRE technique. Returns a compact summary; pull the full body with `aisoc_get_detection_rule`.",
    inputSchema: zodToJsonSchema(QueryDetectionsSchema),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  schema: QueryDetectionsSchema,
  async handle(ctx, args) {
    // Every filter goes to the API. Pulling the library down to filter here
    // would be a multi-megabyte transfer per call, and a limit applied after
    // the fetch does nothing about that.
    const data = await ctx.client.get<DetectionRuleResponse[]>("/api/v1/rules", {
      query: {
        category: args.category,
        rule_language: args.rule_language,
        include_builtin: args.include_builtin,
        search: args.query,
        severity: args.severity,
        mitre: args.mitre_technique,
        // One over the limit, so "there is more" is observed rather than
        // inferred from the page being exactly full.
        limit: args.limit + 1,
      },
    });

    const truncated = data.length > args.limit;
    const items = data.slice(0, args.limit).map(summariseRule);

    return json({
      total_matched: truncated ? `${args.limit}+` : data.length,
      truncated,
      items,
    });
  },
};

// ---------------------------------------------------------------------------
// aisoc_get_detection_rule
// ---------------------------------------------------------------------------

const GetDetectionRuleSchema = z
  .object({
    rule_id: z.string().uuid().describe("UUID of the detection rule."),
  })
  .strict();

export const getDetectionRuleTool: ToolDefinition<typeof GetDetectionRuleSchema> = {
  metadata: {
    name: "aisoc_get_detection_rule",
    description:
      "Fetch the full body of a single detection rule, including the raw rule text, MITRE mappings, hit stats, and false-positive rate.",
    inputSchema: zodToJsonSchema(GetDetectionRuleSchema),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  schema: GetDetectionRuleSchema,
  async handle(ctx, args) {
    const data = await ctx.client.get<DetectionRuleResponse>(
      `/api/v1/rules/${args.rule_id}`,
    );
    return json(data);
  },
};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function summariseRule(r: DetectionRuleResponse): Record<string, unknown> {
  const summary: Record<string, unknown> = {
    id: r.id,
    name: r.name,
    description: r.description,
    rule_language: r.rule_language,
    category: r.category,
    severity: r.severity,
    status: r.status,
    mitre_tactics: r.mitre_tactics,
    mitre_techniques: r.mitre_techniques,
    is_builtin: r.is_builtin,
    tags: r.tags,
  };
  // The engine's own rule id — what an alert's `rule_id` carries — so an
  // agent can join a finding back to the rule that produced it.
  if (r.source_id) summary.source_id = r.source_id;

  // Confidence, hit count and FP rate are only reported when somebody
  // recorded them. A compiled rule carries none, and handing a model a
  // placeholder `confidence: 0` invites it to describe the whole library as
  // untrustworthy on the strength of a field nobody filled in.
  if (r.confidence_measured !== false) {
    summary.confidence = r.confidence;
    summary.total_hits = r.total_hits;
    summary.fp_rate = r.fp_rate;
  } else {
    summary.confidence = null;
    summary.measurements = "none recorded for this rule";
  }
  return summary;
}
