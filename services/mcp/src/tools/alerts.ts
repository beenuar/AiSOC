/**
 * Alert-facing tools.
 *
 * `aisoc_list_alerts` is the workhorse for triage assistants — agents call
 * it as the first probe to ask "what's open right now?" so we keep the
 * arguments tight (severity, status, search) and return a normalised
 * subset rather than streaming the full DB row, both to save tokens and
 * to avoid leaking columns the API may add later that the agent shouldn't
 * see.
 *
 * `aisoc_get_alert` is the deep-dive: when an agent zeroes in on an alert
 * id from the list, it pulls the full record (including `ai_summary` and
 * MITRE mappings) so it can reason about response steps.
 */
import { z } from "zod";

import type { ToolDefinition } from "./types.js";
import { json } from "./types.js";

// ---------------------------------------------------------------------------
// Shared response shape — matches `app.api.v1.endpoints.alerts.AlertResponse`
// at the time of writing. Intentionally `Record<string, unknown>`-ish so a
// new API field doesn't break existing MCP clients.
// ---------------------------------------------------------------------------

interface AlertResponse {
  id: string;
  title: string;
  description: string | null;
  severity: string;
  status: string;
  priority: number;
  category: string | null;
  mitre_tactics: string[];
  mitre_techniques: string[];
  ai_summary: string | null;
  affected_ips: unknown[];
  affected_hosts: unknown[];
  affected_users: unknown[];
  case_id: string | null;
  tags: string[];
  event_time: string;
  created_at: string;
  [key: string]: unknown;
}

interface AlertListResponse {
  items: AlertResponse[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

// ---------------------------------------------------------------------------
// aisoc_list_alerts
// ---------------------------------------------------------------------------

const ListAlertsSchema = z
  .object({
    severity: z
      .enum(["critical", "high", "medium", "low", "info"])
      .optional()
      .describe("Filter by severity. Omit to include all severities."),
    status: z
      .enum(["new", "open", "in_progress", "resolved", "closed", "dismissed"])
      .optional()
      .describe("Filter by alert status. Omit for all statuses."),
    category: z.string().optional().describe("Filter by category (e.g. `endpoint`, `cloud`)."),
    search: z.string().optional().describe("Substring match on title/description."),
    assigned_to_me: z
      .boolean()
      .optional()
      .describe("If true, only alerts assigned to the calling user."),
    page: z.number().int().min(1).max(1000).default(1),
    page_size: z
      .number()
      .int()
      .min(1)
      .max(50)
      .default(25)
      .describe("Capped at 50 to keep MCP context budgets sane."),
  })
  .strict();

export const listAlertsTool: ToolDefinition<typeof ListAlertsSchema> = {
  metadata: {
    name: "aisoc_list_alerts",
    description:
      "List security alerts in the connected AiSOC tenant. Filter by severity, status, category, or free-text search. Results are paginated; default page_size 25.",
    inputSchema: zodToJsonSchema(ListAlertsSchema),
  },
  schema: ListAlertsSchema,
  async handle(ctx, args) {
    const data = await ctx.client.get<AlertListResponse>("/api/v1/alerts", {
      query: {
        severity: args.severity,
        status: args.status,
        category: args.category,
        search: args.search,
        assigned_to_me: args.assigned_to_me,
        page: args.page,
        page_size: args.page_size,
      },
    });

    // Normalise to a tighter view — keeps token counts down for big lists.
    return json({
      total: data.total,
      page: data.page,
      page_size: data.page_size,
      pages: data.pages,
      items: data.items.map(summariseAlert),
    });
  },
};

// ---------------------------------------------------------------------------
// aisoc_get_alert
// ---------------------------------------------------------------------------

const GetAlertSchema = z
  .object({
    alert_id: z
      .string()
      .uuid()
      .describe("UUID of the alert as returned from `aisoc_list_alerts`."),
  })
  .strict();

export const getAlertTool: ToolDefinition<typeof GetAlertSchema> = {
  metadata: {
    name: "aisoc_get_alert",
    description:
      "Fetch the full record for a single alert: AI summary, MITRE mappings, affected assets, and current case linkage.",
    inputSchema: zodToJsonSchema(GetAlertSchema),
  },
  schema: GetAlertSchema,
  async handle(ctx, args) {
    const alert = await ctx.client.get<AlertResponse>(`/api/v1/alerts/${args.alert_id}`);
    return json(alert);
  },
};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function summariseAlert(a: AlertResponse): Record<string, unknown> {
  return {
    id: a.id,
    title: a.title,
    severity: a.severity,
    status: a.status,
    priority: a.priority,
    category: a.category,
    mitre_tactics: a.mitre_tactics,
    mitre_techniques: a.mitre_techniques,
    ai_summary: a.ai_summary,
    case_id: a.case_id,
    tags: a.tags,
    event_time: a.event_time,
  };
}

/**
 * Local zod→JSON-Schema converter. We keep this in the tools layer so the
 * server doesn't have to import zod itself; we only need a subset of the
 * spec (object types with strings/numbers/enums/booleans) which is easier
 * to maintain than pulling in `zod-to-json-schema` (~30kB for what we use).
 *
 * If we hit a corner case the tool layer needs (recursive types, unions of
 * objects, etc.) we'll switch to the dedicated package; for now the strict
 * argument schemas stay simple enough for this to hold.
 *
 * Exported so other tool files can reuse it (see `cases.ts`, `investigations.ts`).
 */
export function zodToJsonSchema(schema: z.ZodTypeAny): Record<string, unknown> {
  return zodToJson(schema);
}

function zodToJson(schema: z.ZodTypeAny): Record<string, unknown> {
  const def = schema._def as { typeName: string } & Record<string, unknown>;
  switch (def.typeName) {
    case "ZodObject": {
      const shape = (schema as unknown as { shape: Record<string, z.ZodTypeAny> }).shape;
      const properties: Record<string, unknown> = {};
      const required: string[] = [];
      for (const [key, child] of Object.entries(shape)) {
        properties[key] = zodToJson(child);
        if (!child.isOptional()) required.push(key);
      }
      const out: Record<string, unknown> = {
        type: "object",
        properties,
        additionalProperties: false,
      };
      if (required.length > 0) out.required = required;
      return out;
    }
    case "ZodString": {
      const checks = (def.checks ?? []) as Array<{ kind: string }>;
      const out: Record<string, unknown> = { type: "string" };
      if (checks.some((c) => c.kind === "uuid")) out.format = "uuid";
      const description = (schema as unknown as { description?: string }).description;
      if (description) out.description = description;
      return out;
    }
    case "ZodNumber": {
      const out: Record<string, unknown> = { type: "number" };
      const checks = (def.checks ?? []) as Array<{ kind: string; value?: number; inclusive?: boolean }>;
      if (checks.some((c) => c.kind === "int")) out.type = "integer";
      for (const check of checks) {
        if (check.kind === "min" && typeof check.value === "number") out.minimum = check.value;
        if (check.kind === "max" && typeof check.value === "number") out.maximum = check.value;
      }
      const description = (schema as unknown as { description?: string }).description;
      if (description) out.description = description;
      return out;
    }
    case "ZodBoolean": {
      const out: Record<string, unknown> = { type: "boolean" };
      const description = (schema as unknown as { description?: string }).description;
      if (description) out.description = description;
      return out;
    }
    case "ZodEnum": {
      const values = (def.values ?? []) as string[];
      const out: Record<string, unknown> = { type: "string", enum: values };
      const description = (schema as unknown as { description?: string }).description;
      if (description) out.description = description;
      return out;
    }
    case "ZodOptional": {
      const inner = (def.innerType ?? schema) as z.ZodTypeAny;
      return zodToJson(inner);
    }
    case "ZodDefault": {
      const inner = (def.innerType ?? schema) as z.ZodTypeAny;
      const defVal = (def.defaultValue as () => unknown)();
      return { ...zodToJson(inner), default: defVal };
    }
    case "ZodArray": {
      const inner = (def.type ?? schema) as z.ZodTypeAny;
      return { type: "array", items: zodToJson(inner) };
    }
    default:
      // Conservative fallback — describe as JSON of any shape. The MCP host
      // will still call the tool and zod's runtime parse will catch
      // anything genuinely malformed.
      return { description: `Unsupported schema type ${def.typeName}` };
  }
}
