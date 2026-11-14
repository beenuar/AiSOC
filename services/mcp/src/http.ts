/**
 * The MCP server over streamable HTTP.
 *
 * Depth 9.1 (parity 6.6). Until this file existed the only transport was
 * stdio, so the only way to reach these tools was to let an MCP host start
 * the process as a child with one operator's API key written into the host's
 * configuration file. Nothing in the repository deployed it and nothing
 * recorded what it read.
 *
 * Three decisions here are security decisions, not plumbing:
 *
 * **Stateless, one server per request.**
 * `sessionIdGenerator: undefined` puts the SDK transport in stateless mode
 * and a fresh `Server` is built per request, bound to the credential that
 * request presented. The alternative — a session id minted once and reused —
 * would let a session outlive the credential that created it, so revoking an
 * API key would not end the sessions it had opened, and anyone who learned a
 * session id would inherit its tenant. Sessions are cheap to add later and
 * expensive to take back.
 *
 * **The credential comes from the request, never from the environment.**
 * `AISOC_API_KEY` configures the *stdio* server. Reading it here would mean
 * an unauthenticated caller, or a caller whose own key had been revoked,
 * silently answering with the operator's access to somebody else's tenant.
 * There is no fallback: a request with no `Authorization` header is 401 and
 * nothing is built. `scripts/check_mcp_over_http.py` fails if this file ever
 * names `cfg.apiKey`.
 *
 * **Every call is authorized by the API before it runs.** See `./gate.ts`.
 * This process is not the authority on what a key may do, and it fails
 * closed when it cannot get an answer.
 *
 * Binding: `AISOC_MCP_HTTP_HOST` defaults to `127.0.0.1`, which is the right
 * default for a transport that did not exist yesterday. The compose service
 * sets `0.0.0.0` because inside a container that is the only way a sibling
 * service reaches it, and compose publishes the port on the loopback address
 * the rest of the stack uses.
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";

import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

import { type Logger, type ServerConfig, packageVersion } from "./config.js";
import { authorizeToolCall, completeToolCall, type GateOptions } from "./gate.js";
import { buildServer, type CallHooks } from "./server.js";

/** Where the MCP endpoint lives. Fixed so a client's URL is predictable. */
export const MCP_PATH = "/mcp";

/** Liveness. Deliberately unauthenticated and deliberately says nothing else. */
export const HEALTH_PATH = "/healthz";

export interface HttpServerOptions {
  host: string;
  port: number;
  /** Cap on a single JSON-RPC frame. A transport with no bound is a memory DoS. */
  maxBodyBytes: number;
}

export function resolveHttpOptions(env: NodeJS.ProcessEnv = process.env): HttpServerOptions {
  const port = Number.parseInt(env.AISOC_MCP_HTTP_PORT ?? "8096", 10);
  if (!Number.isFinite(port) || port <= 0 || port > 65535) {
    throw new Error(`Invalid AISOC_MCP_HTTP_PORT: ${env.AISOC_MCP_HTTP_PORT}`);
  }
  const maxBodyBytes = Number.parseInt(env.AISOC_MCP_MAX_BODY_BYTES ?? "1048576", 10);
  return {
    host: env.AISOC_MCP_HTTP_HOST?.trim() || "127.0.0.1",
    port,
    maxBodyBytes: Number.isFinite(maxBodyBytes) && maxBodyBytes > 0 ? maxBodyBytes : 1_048_576,
  };
}

/**
 * Pull the bearer credential out of a request.
 *
 * Returns `undefined` rather than a default. Every caller treats that as 401.
 */
export function bearerFrom(headers: IncomingMessage["headers"]): string | undefined {
  const raw = headers.authorization;
  if (typeof raw !== "string") return undefined;
  const trimmed = raw.trim();
  if (!/^bearer\s+\S/i.test(trimmed)) return undefined;
  return trimmed;
}

/** Read a bounded JSON body. Rejects rather than truncating. */
export async function readJsonBody(req: IncomingMessage, maxBytes: number): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    size += buf.length;
    if (size > maxBytes) {
      // Truncating would hand the parser a prefix of a frame, which either
      // fails confusingly or — worse — parses into a different call.
      throw new Error(`request body exceeds ${maxBytes} bytes`);
    }
    chunks.push(buf);
  }
  if (size === 0) return undefined;
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function writeJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) });
  res.end(payload);
}

/**
 * The JSON-RPC error a transport-level refusal has to look like.
 *
 * An MCP client parses the body before it looks at the status, so a bare
 * `401 Unauthorized` with an HTML body surfaces in the host as a parse
 * failure and the operator is told the server is broken rather than that
 * their credential is missing.
 */
function rpcError(res: ServerResponse, status: number, message: string): void {
  writeJson(res, status, {
    jsonrpc: "2.0",
    error: { code: -32001, message },
    id: null,
  });
}

/**
 * Hooks that put every tool call through the API's authorize/complete pair.
 *
 * Built per request so the credential cannot be shared between two callers.
 */
export function gateHooks(opts: GateOptions): CallHooks {
  return {
    async before(toolName, args) {
      const decision = await authorizeToolCall(opts, toolName, args);
      return {
        allowed: decision.outcome === "allow",
        reason:
          decision.outcome === "approval_required"
            ? `${decision.reason} Ask an approver to decide it, then call the tool again.`
            : decision.reason,
        callId: decision.call_id || undefined,
      };
    },
    after(callId, outcome, latencyMs, errorKind) {
      // Not awaited: the result is already on its way to the agent and a
      // bookkeeping request must not hold it. Errors are swallowed inside
      // `completeToolCall`, which logs them.
      void completeToolCall(opts, callId ?? "", outcome, latencyMs, errorKind);
    },
  };
}

/**
 * Handle one MCP request end to end.
 *
 * Exported so tests can drive it with a fake request/response pair rather
 * than binding a port.
 */
export async function handleMcpRequest(
  cfg: ServerConfig,
  log: Logger,
  options: HttpServerOptions,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);

  if (url.pathname === HEALTH_PATH) {
    writeJson(res, 200, { status: "ok", version: packageVersion(), transport: "streamable-http" });
    return;
  }
  if (url.pathname !== MCP_PATH) {
    rpcError(res, 404, `Not found. The MCP endpoint is ${MCP_PATH}.`);
    return;
  }

  const bearer = bearerFrom(req.headers);
  if (!bearer) {
    // No environment fallback, deliberately. See the module header.
    rpcError(
      res,
      401,
      "Authorization required. Send `Authorization: Bearer <aisoc_... or JWT>`; " +
        "the tenant is derived from the credential and cannot be supplied any other way.",
    );
    return;
  }

  let body: unknown;
  try {
    body = req.method === "POST" ? await readJsonBody(req, options.maxBodyBytes) : undefined;
  } catch (err) {
    // A fixed sentence, not the thrown message. The only error reachable
    // here is this module's own size refusal or a JSON parse failure, and
    // a parse failure's message quotes the offending input back to whoever
    // sent it — which is both useless to them and an information-exposure
    // finding (`js/stack-trace-exposure`). The bound is the actionable
    // fact, so the bound is what is returned; the detail goes to stderr.
    log.info(`rejected a request body: ${String(err instanceof Error ? err.message : err)}`);
    rpcError(
      res,
      413,
      `The request body could not be read. It must be JSON and at most ${options.maxBodyBytes} bytes.`,
    );
    return;
  }

  const gate: GateOptions = {
    aisocUrl: cfg.aisocUrl,
    bearer,
    timeoutMs: cfg.timeoutMs,
    userAgent: cfg.userAgent,
    log,
  };

  // A per-request config carrying the caller's own credential.
  //
  // Written field by field rather than as a spread with an override. The
  // spread form is correct today and becomes a credential fallback the day
  // somebody reorders the literal, and the thing it would fall back to is
  // the server operator's own key against somebody else's tenant. Listing
  // the fields means the key can only ever be the one that arrived in this
  // request; `scripts/check_mcp_over_http.py` refuses the spread too.
  const requestCfg: ServerConfig = {
    aisocUrl: cfg.aisocUrl,
    apiKey: bearer.replace(/^Bearer\s+/i, ""),
    timeoutMs: cfg.timeoutMs,
    verbose: cfg.verbose,
    userAgent: cfg.userAgent,
  };

  const transport = new StreamableHTTPServerTransport({
    // Stateless. See the module header for why a session id would be worse.
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  });
  const server = buildServer(requestCfg, log, gateHooks(gate));

  res.on("close", () => {
    void transport.close();
    void server.close();
  });

  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, body);
  } catch (err) {
    log.error("mcp http request failed", err);
    if (!res.headersSent) {
      rpcError(res, 500, "The MCP server failed to handle this request.");
    }
  }
}

/** Boot the HTTP transport. Resolves when the listener closes. */
export async function runHttpServer(cfg: ServerConfig, log: Logger): Promise<void> {
  const options = resolveHttpOptions();
  const httpServer = createServer((req, res) => {
    void handleMcpRequest(cfg, log, options, req, res);
  });

  await new Promise<void>((resolve, reject) => {
    httpServer.once("error", reject);
    httpServer.listen(options.port, options.host, () => {
      httpServer.removeListener("error", reject);
      resolve();
    });
  });
  // stderr, not stdout: the stdio transport owns stdout and this binary can
  // be started either way.
  console.error(
    `[aisoc-mcp] ${packageVersion()} listening on http://${options.host}:${options.port}${MCP_PATH} (target ${cfg.aisocUrl})`,
  );

  await new Promise<void>((resolve) => {
    const shutdown = (sig: string) => {
      console.error(`[aisoc-mcp] received ${sig}, closing listener`);
      httpServer.close(() => resolve());
    };
    process.once("SIGINT", () => shutdown("SIGINT"));
    process.once("SIGTERM", () => shutdown("SIGTERM"));
    httpServer.once("close", () => resolve());
  });
}
