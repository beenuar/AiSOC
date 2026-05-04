/**
 * Detection-content tools.
 *
 * The plan calls for a single `aisoc_query_detections(query)` tool. The
 * actual API surfaces filters by category and rule_language but no
 * server-side free-text search, so we implement search client-side over
 * a sane page size — that keeps the agent UX honest ("query for 'AWS
 * IAM'") while we wait for FTS to land in the API.
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
      .enum(["sigma", "yara", "kql", "eql"])
      .optional()
      .describe("Restrict by rule language."),
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
  },
  schema: QueryDetectionsSchema,
  async handle(ctx, args) {
    const data = await ctx.client.get<DetectionRuleResponse[]>("/api/v1/rules", {
      query: {
        category: args.category,
        rule_language: args.rule_language,
        include_builtin: args.include_builtin,
      },
    });

    // Apply the client-side filters the API doesn't support. We accept
    // the over-fetch because typical tenants have hundreds — not millions
    // — of rules, and querying server-side would require a back-end change
    // that's out of scope for this skill.
    let filtered = data;
    if (args.severity) {
      filtered = filtered.filter((r) => r.severity === args.severity);
    }
    if (args.mitre_technique) {
      const want = args.mitre_technique.toUpperCase();
      filtered = filtered.filter((r) =>
        r.mitre_techniques.some((t) => t.toUpperCase() === want),
      );
    }
    if (args.query) {
      const needle = args.query.toLowerCase();
      filtered = filtered.filter((r) =>
        [
          r.name,
          r.description ?? "",
          r.tags.join(" "),
          r.mitre_techniques.join(" "),
          r.mitre_tactics.join(" "),
          r.category,
        ]
          .join(" ")
          .toLowerCase()
          .includes(needle),
      );
    }

    const totalUnfiltered = data.length;
    const totalMatched = filtered.length;
    const items = filtered.slice(0, args.limit).map(summariseRule);

    return json({
      total_unfiltered: totalUnfiltered,
      total_matched: totalMatched,
      truncated: totalMatched > items.length,
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
  return {
    id: r.id,
    name: r.name,
    description: r.description,
    rule_language: r.rule_language,
    category: r.category,
    severity: r.severity,
    status: r.status,
    confidence: r.confidence,
    mitre_tactics: r.mitre_tactics,
    mitre_techniques: r.mitre_techniques,
    total_hits: r.total_hits,
    fp_rate: r.fp_rate,
    is_builtin: r.is_builtin,
    tags: r.tags,
  };
}
