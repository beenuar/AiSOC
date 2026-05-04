/**
 * MCP server wiring.
 *
 * Bridges the AiSOC tool registry (`./tools/index.ts`) to the
 * `@modelcontextprotocol/sdk` server, exposing two request handlers:
 *
 *   - `tools/list`  → advertise every tool's name + JSON Schema.
 *   - `tools/call`  → validate args with the tool's zod schema, dispatch
 *                     to the handler, and wrap the result in MCP's
 *                     `CallToolResult` shape (text content + isError).
 *
 * Why we wrap manually instead of using the high-level `McpServer` helper:
 *
 *   1. The high-level helper insists on declaring tool metadata as the
 *      tools register; we already keep that metadata next to each tool
 *      handler in `./tools/`. Wrapping the low-level `Server` keeps a
 *      single source of truth.
 *   2. We want first-class control over how tool errors are surfaced —
 *      `formatErrorForTool` produces a stable, audit-friendly message
 *      that the agent can act on (auth failures suggest scope fixes,
 *      transport errors mention the URL, etc.).
 *   3. The arg validation step uses the tool's exact zod schema so failures
 *      report which fields were wrong, not "schema mismatch".
 *
 * Stdio discipline: the SDK already wires JSON-RPC to stdout via
 * `StdioServerTransport`; we never log to stdout from our code.
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

import { AisocClient } from "./client.js";
import { type ServerConfig, type Logger, packageVersion } from "./config.js";
import {
  ApiError,
  InvalidArgumentsError,
  MissingApiKeyError,
  TransportError,
  formatErrorForTool,
} from "./errors.js";
import { ALL_TOOLS, TOOL_BY_NAME } from "./tools/index.js";
import type { ToolResult } from "./tools/types.js";

/** Server instructions surfaced to MCP hosts during initialisation. */
const SERVER_INSTRUCTIONS = `\
AiSOC exposes alerts, cases, detection rules, and the agent decision ledger
through this MCP server. Typical workflows:

  1. Triage:       aisoc_list_alerts → aisoc_get_alert
  2. Investigate:  aisoc_list_cases  → aisoc_run_investigation → aisoc_replay_decision
  3. Audit a step: aisoc_explain_step (returns the prompt, response, and tools used)
  4. Tune rules:   aisoc_query_detections → aisoc_get_detection_rule

Every agent decision in AiSOC is logged to a persistent ledger; \
\`aisoc_replay_decision\` and \`aisoc_explain_step\` are the auditable surface.`;

/**
 * Build (but don't start) an MCP server bound to the AiSOC tool registry.
 *
 * Exported separately from the start helper so tests can drive request
 * handlers without spinning up a real stdio transport.
 */
export function buildServer(cfg: ServerConfig, log: Logger): Server {
  const client = new AisocClient(cfg, log);
  const server = new Server(
    { name: "@aisoc/mcp", version: packageVersion() },
    {
      capabilities: { tools: {} },
      instructions: SERVER_INSTRUCTIONS,
    },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: ALL_TOOLS.map((t) => ({
        name: t.metadata.name,
        description: t.metadata.description,
        inputSchema: t.metadata.inputSchema as { type: "object" } & Record<
          string,
          unknown
        >,
      })),
    };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const name = request.params.name;
    const tool = TOOL_BY_NAME[name];
    if (!tool) {
      // Unknown tool. Return as a tool-failure rather than throwing so the
      // agent gets a clear human message instead of a transport error.
      return toErrorResult(
        `Unknown tool: ${name}. Call tools/list to see what's available.`,
      );
    }

    // Validate via zod. Failed validation gives precise per-field issues.
    const parse = tool.schema.safeParse(request.params.arguments ?? {});
    if (!parse.success) {
      const issues = parse.error.issues.map(
        (i) => `${i.path.join(".") || "<root>"}: ${i.message}`,
      );
      return toErrorResult(
        formatErrorForTool(new InvalidArgumentsError(name, issues)),
      );
    }

    try {
      const result = await tool.handle({ client, log }, parse.data);
      return toSuccessResult(result);
    } catch (err) {
      // Log full error to stderr for debugging; surface a sanitised message
      // to the agent. We deliberately don't include stack traces in the
      // MCP response (PII / secrets risk).
      log.error(`tool ${name} failed`, err);

      // Auth failures surface a hint about scopes via formatErrorForTool.
      if (
        err instanceof MissingApiKeyError ||
        err instanceof TransportError ||
        err instanceof ApiError ||
        err instanceof InvalidArgumentsError
      ) {
        return toErrorResult(formatErrorForTool(err));
      }
      return toErrorResult(formatErrorForTool(err));
    }
  });

  return server;
}

/**
 * Boot the server on stdio. Resolves once the transport closes (process
 * shutdown) so callers can `await` for the lifecycle.
 */
export async function runServer(cfg: ServerConfig, log: Logger): Promise<void> {
  const server = buildServer(cfg, log);
  const transport = new StdioServerTransport();
  await server.connect(transport);
  log.info(`aisoc-mcp ${packageVersion()} ready on stdio (target ${cfg.aisocUrl})`);
  // The SDK keeps Node alive while stdin is open; we just need to wait for
  // close. Setting up a manual promise here also lets us surface SIGINT
  // cleanly.
  await new Promise<void>((resolve) => {
    transport.onclose = () => {
      log.info("transport closed; shutting down");
      resolve();
    };
    const onSignal = (sig: string) => {
      log.info(`received ${sig}, closing transport`);
      transport.close().catch(() => {
        /* swallow — we're exiting anyway */
      });
    };
    process.once("SIGINT", () => onSignal("SIGINT"));
    process.once("SIGTERM", () => onSignal("SIGTERM"));
  });
}

// ---------------------------------------------------------------------------
// Result envelope helpers
// ---------------------------------------------------------------------------

/**
 * Convert a `ToolResult` into the MCP `CallToolResult` shape. JSON results
 * become a fenced JSON code block so MCP hosts that render Markdown still
 * show structured data; text results pass through verbatim. We also include
 * `structuredContent` (the raw JSON) when present, so MCP-aware hosts that
 * support the field can render it natively.
 */
function toSuccessResult(result: ToolResult): {
  content: Array<{ type: "text"; text: string }>;
  structuredContent?: unknown;
  isError?: false;
} {
  if (result.kind === "json") {
    const text = renderJson(result.data);
    return {
      content: [{ type: "text", text }],
      structuredContent:
        // Only surface as structuredContent if it's an object, per spec.
        typeof result.data === "object" && result.data !== null
          ? (result.data as Record<string, unknown>)
          : undefined,
    };
  }
  return {
    content: [{ type: "text", text: result.text }],
    structuredContent:
      typeof result.data === "object" && result.data !== null
        ? (result.data as Record<string, unknown>)
        : undefined,
  };
}

function toErrorResult(text: string): {
  content: Array<{ type: "text"; text: string }>;
  isError: true;
} {
  return { content: [{ type: "text", text }], isError: true };
}

function renderJson(data: unknown): string {
  // Pretty-print with a 2-space indent. We don't truncate here — each tool
  // is responsible for shaping its output to fit MCP context budgets — but
  // we wrap in a fenced block so hosts render it as code.
  const body = JSON.stringify(data, null, 2);
  return "```json\n" + body + "\n```";
}
