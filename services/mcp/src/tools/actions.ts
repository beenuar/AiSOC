/**
 * Response actions, previewed and never performed.
 *
 * Gap-closure Phase 5.6.
 *
 * This is the one place in this server where a tool touches the response
 * surface, so the boundary is drawn in code rather than in a docstring.
 *
 * `DRY_RUN_PATH` is a module constant and is the only action path this
 * module names. `/dispatch` appears nowhere in `src/`, and
 * `tests/actions.test.ts` asserts that by reading the source: an MCP tool
 * that could reach dispatch would let any agent with a read-scoped key
 * isolate a host, and the distance between "preview" and "perform" is one
 * careless string.
 *
 * The API route behind it is already dry-run-only. It forces
 * `dry_run: true` server-side whatever the body says, and it proxies only
 * `/dry-run`, never `/dispatch`. That is the enforcing control; this module
 * is the second lock, on the side an agent can see.
 *
 * What a preview is for: the contract. Every AiSOC capability declares its
 * blast radius, whether it can be reversed, the verification probe that
 * confirms it worked, and the approval tier it needs. A preview returns
 * that assessment without a vendor hearing about it, so an agent can tell
 * an analyst what containing this host would actually mean before anybody
 * clicks anything.
 */
import { z } from "zod";

import { zodToJsonSchema } from "./alerts.js";
import type { ToolDefinition } from "./types.js";
import { json } from "./types.js";

/**
 * The only action path this server will ever request.
 *
 * Named once, asserted by test. The sibling route `/dispatch` performs the
 * action against a live vendor and is deliberately unreachable from here.
 */
export const DRY_RUN_PATH = "/api/v1/live-actions/dry-run";

/** Read-only discovery of what the tenant's deployment can do. */
export const ACTION_CATALOGUE_PATH = "/api/v1/live-actions";

// ---------------------------------------------------------------------------
// aisoc_list_actions
// ---------------------------------------------------------------------------

const ListActionsSchema = z
  .object({
    capability: z
      .string()
      .max(64)
      .optional()
      .describe("Filter to one verb, e.g. `isolate_host`."),
    vendor_id: z.string().max(64).optional().describe("Filter to one vendor's implementations."),
  })
  .strict();

export const listActionsTool: ToolDefinition<typeof ListActionsSchema> = {
  metadata: {
    name: "aisoc_list_actions",
    description:
      "List the response actions this deployment can perform, with the vendor behind each. Read-only: listing an action neither performs nor schedules it. Use `aisoc_preview_action` to see what one would do.",
    inputSchema: zodToJsonSchema(ListActionsSchema),
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
  schema: ListActionsSchema,
  async handle(ctx, args) {
    const data = await ctx.client.get<unknown>(ACTION_CATALOGUE_PATH, {
      query: { capability: args.capability, vendor_id: args.vendor_id },
    });
    return json({
      actions: data,
      note: "Nothing here has been performed. `aisoc_preview_action` is the only action tool this server exposes and it is dry-run only.",
    });
  },
};

// ---------------------------------------------------------------------------
// aisoc_preview_action
// ---------------------------------------------------------------------------

const PreviewActionSchema = z
  .object({
    capability: z
      .string()
      .min(1)
      .max(64)
      .describe("The verb to preview, e.g. `isolate_host`. List them with `aisoc_list_actions`."),
    parameters: z
      .record(z.string(), z.unknown())
      .default({})
      .describe("The arguments the action would be given, e.g. {\"hostname\": \"WIN-DC-01\"}."),
    vendor_id: z
      .string()
      .max(64)
      .optional()
      .describe("Which vendor implementation to assess. Omit to let the deployment choose."),
    confidence: z
      .number()
      .min(0)
      .max(1)
      .optional()
      .describe("The confidence an agent would attach to this action. The approval tier depends on it."),
  })
  .strict();

export const previewActionTool: ToolDefinition<typeof PreviewActionSchema> = {
  metadata: {
    name: "aisoc_preview_action",
    description:
      "Preview a response action without touching a vendor: blast radius, whether it is reversible, the verification probe, and the approval tier it would need. Dry run only. This tool cannot perform an action and there is no tool here that can.",
    inputSchema: zodToJsonSchema(PreviewActionSchema),
    annotations: {
      // Read-only is the honest annotation and the reason is structural
      // rather than a promise: the only path this module names is the
      // dry-run one, and the route behind it forces `dry_run: true`
      // server-side whatever the body says.
      readOnlyHint: true,
      destructiveHint: false,
      // Not idempotent as a claim about the world, which it does not touch,
      // but about the answer: the contract assessment depends on tenant
      // policy and earned autonomy, both of which move.
      idempotentHint: false,
      // The assessment is computed from the deployment's own contracts and
      // policy. No vendor is contacted, which is what makes it a preview.
      openWorldHint: false,
    },
  },
  schema: PreviewActionSchema,
  async handle(ctx, args) {
    const body: Record<string, unknown> = {
      capability: args.capability,
      parameters: args.parameters,
      // Sent as well as enforced upstream. Belt and braces on the field that
      // decides whether a customer's estate is touched.
      dry_run: true,
    };
    if (args.vendor_id !== undefined) body.vendor_id = args.vendor_id;
    if (args.confidence !== undefined) body.confidence = args.confidence;

    const data = await ctx.client.post<unknown>(DRY_RUN_PATH, body);
    return json({
      preview: data,
      executed: false,
      note:
        "Nothing was performed and no vendor was contacted. Performing this action needs the AiSOC console or API with an approval, and is deliberately not reachable from any MCP tool.",
    });
  },
};
