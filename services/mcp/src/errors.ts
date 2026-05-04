/**
 * Typed errors used by the MCP server.
 *
 * MCP tool calls report failure by setting `isError: true` on the
 * `CallToolResult` and returning a human-readable text content block. We
 * model the failure modes here so each tool can map them to an actionable
 * message instead of leaking a raw stack trace.
 */

/** No API key was wired into the process. */
export class MissingApiKeyError extends Error {
  readonly code = "AISOC_MISSING_API_KEY";
  constructor() {
    super(
      "AiSOC API key is not configured. Pass --api-key or set AISOC_API_KEY. " +
        "Generate one in your AiSOC console under Settings → API Keys.",
    );
    this.name = "MissingApiKeyError";
  }
}

/** Network/timeout failure reaching AiSOC. */
export class TransportError extends Error {
  readonly code = "AISOC_TRANSPORT_ERROR";
  constructor(
    public readonly url: string,
    cause: unknown,
  ) {
    super(`Could not reach AiSOC at ${url}: ${formatCause(cause)}`);
    this.name = "TransportError";
    if (cause instanceof Error) this.cause = cause;
  }
}

/** AiSOC returned a non-2xx HTTP response. */
export class ApiError extends Error {
  readonly code = "AISOC_API_ERROR";
  constructor(
    public readonly status: number,
    public readonly endpoint: string,
    public readonly detail: string,
  ) {
    super(`AiSOC API ${status} on ${endpoint}: ${detail}`);
    this.name = "ApiError";
  }

  /** Convenience: did the server reject our credential? */
  get isAuthFailure(): boolean {
    return this.status === 401 || this.status === 403;
  }
}

/** A tool was called with malformed arguments. */
export class InvalidArgumentsError extends Error {
  readonly code = "AISOC_INVALID_ARGS";
  constructor(public readonly tool: string, public readonly issues: string[]) {
    super(`Invalid arguments to ${tool}: ${issues.join("; ")}`);
    this.name = "InvalidArgumentsError";
  }
}

function formatCause(cause: unknown): string {
  if (cause instanceof Error) return cause.message;
  if (typeof cause === "string") return cause;
  try {
    return JSON.stringify(cause);
  } catch {
    return String(cause);
  }
}

/**
 * Map any error into a string suitable for an MCP tool failure message.
 * We never include credentials, but we do include the endpoint + status so
 * the agent can troubleshoot itself.
 */
export function formatErrorForTool(err: unknown): string {
  if (err instanceof MissingApiKeyError) return err.message;
  if (err instanceof TransportError) return err.message;
  if (err instanceof ApiError) {
    if (err.isAuthFailure) {
      return (
        `${err.message}. The configured API key is missing or has insufficient ` +
        `scopes for this tool. Verify the key has the required scope (alerts:read, ` +
        `cases:read, cases:write, detections:read, etc.).`
      );
    }
    return err.message;
  }
  if (err instanceof InvalidArgumentsError) return err.message;
  if (err instanceof Error) return err.message;
  return String(err);
}
