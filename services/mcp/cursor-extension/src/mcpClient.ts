/**
 * Typed JSON-RPC client for the AiSOC MCP gateway.
 *
 * The AiSOC MCP server (`services/mcp/`) speaks the Model Context Protocol
 * over stdio. For the IDE extension we expect a thin HTTP gateway in front
 * of that server (default `http://localhost:8765/mcp`) that translates
 * JSON-RPC `tools/call` requests over HTTP POST into stdio calls against
 * the underlying server. That gateway can be any of:
 *
 *   - An `aisoc-mcp-http` wrapper run alongside the IDE.
 *   - A future first-class HTTP transport baked into the AiSOC API.
 *   - A self-hosted reverse proxy that fronts the stdio process.
 *
 * The wire shape we send is canonical JSON-RPC 2.0:
 *
 *   POST <mcpEndpoint>
 *   Content-Type: application/json
 *   Authorization: Bearer <api-key>          (only when the user has one set)
 *
 *   {
 *     "jsonrpc": "2.0",
 *     "id": <uuid>,
 *     "method": "tools/call",
 *     "params": {
 *       "name": "aisoc_replay_decision",
 *       "arguments": { "run_id": "…", "since_seq": 0 }
 *     }
 *   }
 *
 * The response shape mirrors `CallToolResult` from the MCP SDK — a content
 * array (text blocks) and an optional `structuredContent` payload that the
 * AiSOC server returns alongside the rendered text. We surface both so the
 * webview can show the pretty markdown and the raw JSON side-by-side.
 *
 * Errors map onto a single `McpClientError` class so the extension code
 * never has to discriminate between transport failures, HTTP errors, and
 * JSON-RPC `error` objects.
 */

export interface McpContentBlock {
  type: string;
  text?: string;
  [key: string]: unknown;
}

export interface McpToolResult {
  content: McpContentBlock[];
  structuredContent?: unknown;
  isError?: boolean;
}

export interface McpClientOptions {
  endpoint: string;
  apiKey?: string;
  timeoutMs?: number;
  /** Override the global `fetch` for tests. */
  fetchImpl?: typeof fetch;
  /** Override the id generator for deterministic tests. */
  idGenerator?: () => string;
}

export class McpClientError extends Error {
  public readonly kind:
    | "transport"
    | "http"
    | "jsonrpc"
    | "tool";
  public readonly status?: number;
  public readonly details?: unknown;

  constructor(
    kind: McpClientError["kind"],
    message: string,
    options: { status?: number; details?: unknown; cause?: unknown } = {},
  ) {
    super(message);
    this.name = "McpClientError";
    this.kind = kind;
    this.status = options.status;
    this.details = options.details;
    if (options.cause !== undefined) {
      (this as { cause?: unknown }).cause = options.cause;
    }
  }
}

interface JsonRpcRequest {
  jsonrpc: "2.0";
  id: string;
  method: string;
  params: unknown;
}

interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: string;
  result?: McpToolResult;
  error?: { code: number; message: string; data?: unknown };
}

const DEFAULT_TIMEOUT_MS = 30_000;

/**
 * Thin typed wrapper over the four MCP tools the extension surfaces.
 *
 * Each public method returns the full `McpToolResult` so callers can render
 * both the human-readable text content and the structured payload. The
 * underscored argument names (`case_id`, `run_id`, …) match the wire shape
 * the AiSOC MCP server's tool schemas validate against — we deliberately
 * keep the public surface aligned with that wire shape to avoid a
 * translation layer that drifts on schema changes.
 */
export class McpClient {
  private readonly endpoint: string;
  private readonly apiKey: string | undefined;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly idGenerator: () => string;

  constructor(opts: McpClientOptions) {
    this.endpoint = normaliseEndpoint(opts.endpoint);
    this.apiKey = opts.apiKey?.trim() ? opts.apiKey.trim() : undefined;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    // The Node 18 / VS Code 1.80+ runtime ships a global `fetch`; tests
    // inject a stub.
    const fallbackFetch = (globalThis as { fetch?: typeof fetch }).fetch;
    if (!opts.fetchImpl && !fallbackFetch) {
      throw new McpClientError(
        "transport",
        "No fetch implementation available. Pass fetchImpl in tests, or run on Node 18+.",
      );
    }
    this.fetchImpl = (opts.fetchImpl ?? fallbackFetch) as typeof fetch;
    this.idGenerator = opts.idGenerator ?? defaultIdGenerator;
  }

  /** Expose the resolved endpoint so callers can show it in status bars / logs. */
  public getEndpoint(): string {
    return this.endpoint;
  }

  /**
   * Kick off the AiSOC multi-agent investigator on a case.
   *
   * Wraps `aisoc_run_investigation`. The MCP tool returns a `run_id` that
   * the caller can subsequently feed back into `replayDecision`.
   */
  public async runInvestigation(
    caseId: string,
    alertSummary?: string,
  ): Promise<McpToolResult> {
    return this.callTool("aisoc_run_investigation", {
      case_id: caseId,
      ...(alertSummary !== undefined ? { alert_summary: alertSummary } : {}),
    });
  }

  /**
   * Walk the decision ledger for an investigation run.
   *
   * Wraps `aisoc_replay_decision`. `step` is the cursor — when supplied,
   * only events with `seq > step` are returned (tail-mode polling).
   */
  public async replayDecision(
    investigationId: string,
    step?: number,
    limit?: number,
  ): Promise<McpToolResult> {
    const args: Record<string, unknown> = { run_id: investigationId };
    if (step !== undefined) args["since_seq"] = step;
    if (limit !== undefined) args["limit"] = limit;
    return this.callTool("aisoc_replay_decision", args);
  }

  /**
   * Deep-dive on a single decision step (prompt, response, tool I/O).
   *
   * Wraps `aisoc_explain_step`. `step` is the event seq number from
   * `replayDecision`.
   */
  public async explainStep(
    investigationId: string,
    step: number,
  ): Promise<McpToolResult> {
    return this.callTool("aisoc_explain_step", {
      run_id: investigationId,
      step,
    });
  }

  /**
   * Search the detection-rule library.
   *
   * Wraps `aisoc_query_detections`. The `technique` argument routes to
   * `mitre_technique` when it looks like a MITRE id (e.g. `T1059.003`),
   * otherwise it's used as the free-text `query`. Callers that need full
   * control can pass an options bag.
   */
  public async queryDetections(
    technique: string,
    options: {
      category?: string;
      severity?: string;
      ruleLanguage?: string;
      limit?: number;
    } = {},
  ): Promise<McpToolResult> {
    const args: Record<string, unknown> = {};
    if (technique) {
      if (looksLikeMitreTechnique(technique)) {
        args["mitre_technique"] = technique.toUpperCase();
      } else {
        args["query"] = technique;
      }
    }
    if (options.category) args["category"] = options.category;
    if (options.severity) args["severity"] = options.severity;
    if (options.ruleLanguage) args["rule_language"] = options.ruleLanguage;
    if (options.limit !== undefined) args["limit"] = options.limit;
    return this.callTool("aisoc_query_detections", args);
  }

  /**
   * Low-level escape hatch — invoke any MCP tool by name. Useful for
   * future commands (alerts, cases) without shipping a new client method.
   */
  public async callTool(
    name: string,
    args: Record<string, unknown>,
  ): Promise<McpToolResult> {
    const body: JsonRpcRequest = {
      jsonrpc: "2.0",
      id: this.idGenerator(),
      method: "tools/call",
      params: { name, arguments: args },
    };

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "application/json",
    };
    if (this.apiKey) {
      headers["Authorization"] = `Bearer ${this.apiKey}`;
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    let response: Response;
    try {
      response = await this.fetchImpl(this.endpoint, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
        signal: controller.signal,
      });
    } catch (err) {
      const aborted =
        err instanceof Error && (err.name === "AbortError" || /abort/i.test(err.message));
      throw new McpClientError(
        "transport",
        aborted
          ? `Request to ${this.endpoint} timed out after ${this.timeoutMs}ms.`
          : `Failed to reach AiSOC MCP endpoint at ${this.endpoint}: ${stringifyError(err)}`,
        { cause: err },
      );
    } finally {
      clearTimeout(timer);
    }

    if (!response.ok) {
      const detail = await safeReadText(response);
      throw new McpClientError(
        "http",
        `MCP endpoint returned HTTP ${response.status}: ${detail.slice(0, 500)}`,
        { status: response.status, details: detail },
      );
    }

    let parsed: JsonRpcResponse;
    try {
      parsed = (await response.json()) as JsonRpcResponse;
    } catch (err) {
      throw new McpClientError(
        "jsonrpc",
        `MCP endpoint returned a non-JSON body: ${stringifyError(err)}`,
        { cause: err },
      );
    }

    if (parsed.error) {
      throw new McpClientError(
        "jsonrpc",
        `MCP error ${parsed.error.code}: ${parsed.error.message}`,
        { details: parsed.error.data },
      );
    }

    const result = parsed.result;
    if (!result || !Array.isArray(result.content)) {
      throw new McpClientError(
        "jsonrpc",
        "MCP response is missing a `result.content` array.",
        { details: parsed },
      );
    }

    if (result.isError) {
      const text = result.content
        .map((c) => (typeof c.text === "string" ? c.text : ""))
        .filter(Boolean)
        .join("\n")
        .trim();
      throw new McpClientError(
        "tool",
        text || `Tool \`${name}\` reported a failure with no detail.`,
        { details: result },
      );
    }

    return result;
  }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/**
 * Normalise the configured endpoint so subtle user typos don't cause
 * surprising failures. We tolerate trailing slashes and accept the common
 * "I pasted the base URL without the /mcp suffix" mistake by leaving the
 * path untouched — the gateway decides what path it serves on.
 */
function normaliseEndpoint(endpoint: string): string {
  const trimmed = endpoint.trim();
  if (!trimmed) {
    throw new McpClientError(
      "transport",
      "AiSOC MCP endpoint is empty. Set `aisoc.mcpEndpoint` in your IDE settings.",
    );
  }
  try {
    const url = new URL(trimmed);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new McpClientError(
        "transport",
        `AiSOC MCP endpoint must use http:// or https:// (got ${url.protocol}).`,
      );
    }
    return url.toString().replace(/\/$/, "");
  } catch (err) {
    if (err instanceof McpClientError) throw err;
    throw new McpClientError(
      "transport",
      `AiSOC MCP endpoint \`${trimmed}\` is not a valid URL.`,
      { cause: err },
    );
  }
}

/**
 * MITRE ATT&CK technique ids look like `T1234` or `T1234.001`. We use a
 * generous regex so common variants (lower-case, surrounding whitespace)
 * also route to the structured filter.
 */
function looksLikeMitreTechnique(input: string): boolean {
  return /^\s*T\d{4}(\.\d{3})?\s*$/i.test(input);
}

async function safeReadText(res: Response): Promise<string> {
  try {
    return await res.text();
  } catch {
    return "(no body)";
  }
}

function stringifyError(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

function defaultIdGenerator(): string {
  // VS Code targets Node 18+ which ships `crypto.randomUUID`. We fall back
  // to a timestamp+random combo if that's somehow unavailable so tests in
  // older runtimes don't crash.
  const cryptoLike = (globalThis as { crypto?: { randomUUID?: () => string } }).crypto;
  if (cryptoLike?.randomUUID) {
    return cryptoLike.randomUUID();
  }
  return `aisoc-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}
