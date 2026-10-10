/**
 * Run one natural-language hunt against the tenant's own recorded events.
 *
 * Parity 6.1. The hunting agent was complete and tested, and its only
 * importer repo-wide was its own test — a passing test on a function
 * nothing calls is indistinguishable from a working feature until
 * somebody traces the call graph. This tool and the console's Hunt page
 * are the two callers that make it real.
 *
 * Three things about the payload are deliberate, because the next reader
 * of it is a language model.
 *
 * **`checked` is not `matches.length > 0`.** A hunt that could not run is
 * not a hunt that found nothing, and collapsing the two is how a console
 * ends up showing a reassuring empty result for a search that never
 * happened. `checked: false` always carries an `unavailable_reason`.
 *
 * **Refusals are returned, not swallowed.** The model proposes a plan and
 * the planner validates every attempt against the allowed shape; a plan
 * it would not run is information an analyst should see, not noise to
 * hide. The model never writes a query — it picks from a vocabulary, and
 * `refusals` is the record of what it tried that did not fit.
 *
 * **It is read-only.** A hunt searches; it does not act. The annotation
 * says so and no write path exists here.
 *
 * **It takes no tenant.** It used to declare
 * `tenant_id: z.string().uuid()` and forward it in the body (issue
 * #1274). Two things were wrong with that, and the smaller one is what
 * got noticed: zod 4's `.uuid()` enforces RFC 4122 version and variant
 * bits, which the tenant every default install is bootstrapped into
 * (`00000000-0000-0000-0000-000000000001`) does not set — so the tool
 * could not be called at all on a stock deployment.
 *
 * The larger one is that a tenant supplied by a *model* is not a
 * boundary. `AgentHuntRequest` declares only `hypothesis`, so pydantic
 * was silently dropping the field: the isolation was an accident of
 * schema strictness rather than a decision. Relaxing the validator to
 * `z.guid()` would have made the bad input pass and left that in place.
 * The tenant comes from the credential, here as everywhere else.
 */
import { z } from "zod";

import { zodToJsonSchema } from "./alerts.js";
import type { ToolDefinition } from "./types.js";
import { json } from "./types.js";

interface HuntReply {
  hypothesis: string;
  checked: boolean;
  matches: unknown[];
  refusals: string[];
  unavailable_reason: string | null;
}

const RunHuntSchema = z
  .object({
    hypothesis: z
      .string()
      .min(1)
      .describe(
        "What you suspect, in plain language. For example: 'a service account signed in from a country it has never used before'.",
      ),
  })
  .strict();

export const runHuntTool: ToolDefinition<typeof RunHuntSchema> = {
  metadata: {
    name: "aisoc_run_hunt",
    description:
      "Turn a plain-language hypothesis into a validated hunt plan and run it against this tenant's recorded events. Returns what matched, or why it could not look. Read-only: a hunt searches, it never acts.",
    inputSchema: zodToJsonSchema(RunHuntSchema),
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      // Not idempotent: the estate moves, so the same hypothesis can
      // legitimately answer differently an hour later.
      idempotentHint: false,
      openWorldHint: true,
    },
  },
  schema: RunHuntSchema,
  async handle(ctx, args) {
    const reply = await ctx.client.post<HuntReply>("/api/v1/agents/hunt", {
      hypothesis: args.hypothesis,
    });

    const matches = reply.matches ?? [];
    return json({
      hypothesis: reply.hypothesis,
      // Stated in words as well as in the boolean. A false boolean is
      // easy to skim past on the way to an empty `matches`, and the two
      // mean opposite things.
      checked: reply.checked,
      note: reply.checked
        ? "The hunt ran. An empty `matches` means nothing matched, which is a result."
        : "The hunt did NOT run, so `matches` is empty for a reason that has nothing to do with the estate. Do not report this as 'nothing found'.",
      unavailable_reason: reply.unavailable_reason ?? null,
      matches,
      match_count: matches.length,
      refusals: reply.refusals ?? [],
      refusals_note:
        "Plans the validator would not run. The model never writes a query directly; it picks from a vocabulary, and these are the attempts that did not fit.",
      next_step:
        matches.length > 0
          ? "Pivot on a match with `aisoc_lake_query`, or open the entity in the console."
          : "Nothing to pivot on. Narrow or widen the hypothesis and run it again.",
    });
  },
};
