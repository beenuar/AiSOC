/**
 * Ask AiSOC whether a tool call may run, and tell it how it went.
 *
 * Depth 9.1 (parity 6.6). Over stdio this server was a child process holding
 * one operator's own API key, and the only thing a tool call could do was
 * what that person could already do at the console. Over HTTP it is a shared
 * process reached by several tenants with credentials of their own, and that
 * changes who is allowed to decide what:
 *
 * - **This process decides nothing.** It forwards the caller's credential to
 *   `POST /api/v1/mcp/tool-calls/authorize` and does what it is told. A
 *   policy cached or recomputed here would be a second authority that can
 *   disagree with the first, and the disagreement would be invisible.
 * - **The tenant is never sent.** It is derived server-side from the
 *   credential. There is no tenant field in either request body, so there is
 *   nothing for a compromised deployment of this process to set.
 * - **A refusal is actionable.** `approval_required` carries the id of the
 *   row a human decides, so the agent can say what to do rather than failing
 *   opaquely.
 *
 * Failure posture: `authorize` fails **closed**. If the API cannot be
 * reached, no call runs. That is the opposite of `telemetry.ts`, which fails
 * open on purpose — telemetry is an observation and must not break a call,
 * whereas this is the authorization. Two surfaces, two postures, stated here
 * so neither gets changed to match the other by accident.
 */

import type { Logger } from "./config.js";

/** What the API answers. Mirrors `McpAuthorizeResponse` in the API service. */
export interface AuthorizeDecision {
  call_id: string;
  outcome: "allow" | "deny" | "approval_required";
  reason: string;
  approval_id?: string | null;
  required_permission?: string;
}

export interface GateOptions {
  /** Base URL of the AiSOC API. */
  aisocUrl: string;
  /** The *caller's* bearer credential, forwarded verbatim. Never the server's. */
  bearer: string;
  timeoutMs: number;
  userAgent: string;
  log: Logger;
}

/** Raised when the gate could not reach a decision. Fails the call. */
export class GateUnavailableError extends Error {
  constructor(cause: string) {
    super(
      `AiSOC could not authorize this tool call (${cause}). ` +
        `No tool runs without a decision, so this is a refusal rather than a fallback.`,
    );
    this.name = "GateUnavailableError";
  }
}

/** The only shape a User-Agent from this module may take. */
const USER_AGENT_RE = /^aisoc-mcp\/[0-9A-Za-z.+-]{1,32}(?: \(\+https:\/\/[A-Za-z0-9./_-]{1,80}\))?$/;

/**
 * A User-Agent that cannot carry anything but a version string.
 *
 * Exported for the test: a guard whose behaviour is only visible inside a
 * network call is one nobody can check.
 */
export function safeUserAgent(candidate: string): string {
  return USER_AGENT_RE.test(candidate) ? candidate : "aisoc-mcp";
}

async function postJson(
  url: string,
  bearer: string,
  body: unknown,
  timeoutMs: number,
  userAgent: string,
): Promise<{ status: number; json: unknown }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: bearer.startsWith("Bearer ") ? bearer : `Bearer ${bearer}`,
        "Content-Type": "application/json",
        Accept: "application/json",
        // Constrained rather than passed through. `cfg.userAgent` is built
        // from the version in `package.json`, which `config.ts` reads off
        // disk — so a header built straight from it is file content
        // reaching an outbound request, which CodeQL reports as
        // `js/file-access-to-http` and is right to. A `fullmatch` on the
        // shape this value is allowed to have is the strongest guard
        // available here: anything that is not `aisoc-mcp/<version> (...)`
        // is replaced rather than escaped, because an escaped value that
        // reaches the server and means nothing is worse than a known one.
        "User-Agent": safeUserAgent(userAgent),
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    // 204 has no body, and `res.json()` on an empty body throws.
    const json = res.status === 204 ? null : await res.json().catch(() => null);
    return { status: res.status, json };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Authorize one tool call. Throws {@link GateUnavailableError} rather than
 * returning a permissive default when the API cannot answer.
 *
 * `arguments` travels in full because the approval has to bind to the
 * specific call — approving "investigate case A" must not authorise
 * "investigate case B". The API hashes it on arrival and stores only the
 * digest; the audit row records argument *names* alone.
 */
export async function authorizeToolCall(
  opts: GateOptions,
  toolName: string,
  args: unknown,
): Promise<AuthorizeDecision> {
  let result: { status: number; json: unknown };
  try {
    result = await postJson(
      `${opts.aisocUrl}/api/v1/mcp/tool-calls/authorize`,
      opts.bearer,
      { tool_name: toolName, arguments: isPlainObject(args) ? args : {} },
      opts.timeoutMs,
      opts.userAgent,
    );
  } catch (err) {
    throw new GateUnavailableError(String(err));
  }

  if (result.status === 401 || result.status === 403) {
    return {
      call_id: "",
      outcome: "deny",
      reason:
        result.status === 401
          ? "AiSOC rejected the credential this request presented."
          : "The presented credential is not allowed to use the MCP surface.",
    };
  }
  if (result.status >= 400 || !isPlainObject(result.json)) {
    throw new GateUnavailableError(`HTTP ${result.status}`);
  }

  const decision = result.json as unknown as AuthorizeDecision;
  if (decision.outcome !== "allow" && decision.outcome !== "deny" && decision.outcome !== "approval_required") {
    // An outcome this build does not know is not an allow. A newer API
    // inventing a verdict must not be read as permission by an older client.
    throw new GateUnavailableError(`unrecognised outcome "${String(decision.outcome)}"`);
  }
  return decision;
}

/**
 * Report how an authorized call turned out.
 *
 * Deliberately fire-and-forget and deliberately *not* fail-closed: the call
 * has already happened, and refusing to return its result because the second
 * bookkeeping request failed would punish the user for a logging problem.
 * The decision row is already written, which is the one that has to exist.
 */
export async function completeToolCall(
  opts: GateOptions,
  callId: string,
  outcome: "success" | "error" | "invalid_arguments" | "unknown_tool" | "denied",
  latencyMs: number,
  errorKind?: string,
): Promise<void> {
  if (!callId) return;
  try {
    const res = await postJson(
      `${opts.aisocUrl}/api/v1/mcp/tool-calls/${encodeURIComponent(callId)}/complete`,
      opts.bearer,
      { outcome, latency_ms: Math.max(0, Math.round(latencyMs)), ...(errorKind ? { error_kind: errorKind } : {}) },
      opts.timeoutMs,
      opts.userAgent,
    );
    if (res.status >= 400) {
      opts.log.info(`gate: completion for ${callId} returned HTTP ${res.status}`);
    }
  } catch (err) {
    opts.log.info(`gate: completion for ${callId} dropped: ${String(err)}`);
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
