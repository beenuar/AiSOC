/**
 * Shared types for the MCP tool layer.
 *
 * Each tool is implemented as an object satisfying {@link ToolDefinition} so
 * the server can list them and dispatch a single name → handler map without
 * the if/else ladder we'd get from inlining everything in `server.ts`.
 *
 * The handler returns the structured payload it wants to surface to the
 * agent; the server wraps that payload in the MCP `CallToolResult` shape
 * (text content + `isError` flag) and is responsible for catching any
 * thrown error.
 */
import type { z } from "zod";
import type { AisocClient } from "../client.js";
import type { Logger } from "../config.js";

/**
 * MCP tool behaviour hints, as the protocol defines them.
 *
 * These are the fields a *client* reads to decide whether it may call a
 * tool at all. AiSOC's own MCP client refuses a tool whose server sets
 * `destructiveHint: true` or `readOnlyHint: false`, and an absent
 * annotation is not read as a claim to be read-only, so a server that
 * publishes nothing here forces every operator to vouch for every tool by
 * name. Declaring them is how this server becomes usable by a client that
 * takes the annotations seriously, including ours.
 *
 * They have to be honest in both directions. A read tool marked
 * state-changing gets refused for nothing; a state-changing tool marked
 * read-only is a lie a client cannot detect, which is the direction that
 * costs something.
 */
export interface ToolAnnotations {
  /** The tool does not modify anything. */
  readOnlyHint?: boolean;
  /** The tool may perform a destructive update. Meaningless when read-only. */
  destructiveHint?: boolean;
  /** Repeating the call with the same arguments has no additional effect. */
  idempotentHint?: boolean;
  /** The tool reaches systems outside this deployment. */
  openWorldHint?: boolean;
}

/** Minimal MCP "tool" descriptor — name + JSON schema for ListToolsResult. */
export interface ToolMetadata {
  /** Tool ID surfaced to the agent. Convention: `aisoc_<verb>_<resource>`. */
  name: string;
  /** One-line description shown in tool pickers. Keep under ~80 chars. */
  description: string;
  /** JSON Schema for the input arguments (pre-converted from zod). */
  inputSchema: Record<string, unknown>;
  /**
   * Behaviour hints. Required on every tool in this registry: a test
   * enforces it, because an omission is indistinguishable from a tool
   * nobody thought about, and the client-side default for a missing
   * `readOnlyHint` is "not read-only".
   */
  annotations: ToolAnnotations;
}

/**
 * What a tool handler receives. We pass the client + logger explicitly so
 * tools are easy to unit-test against a mock client.
 */
export interface ToolContext {
  client: AisocClient;
  log: Logger;
}

/**
 * Tool definition: schema + handler. Generic on the zod schema so the
 * handler gets fully-typed `args`.
 */
export interface ToolDefinition<TSchema extends z.ZodTypeAny = z.ZodTypeAny> {
  metadata: ToolMetadata;
  /**
   * Zod schema describing the tool input — used both to advertise the
   * tool (via JSON Schema) and to validate args at call time. We make this
   * the single source of truth so the two never drift.
   */
  schema: TSchema;
  /**
   * Execute the tool. Returns either:
   *   - a JSON-serialisable payload that we render as a JSON code block, or
   *   - a `{ text: string, data?: unknown }` envelope when the natural
   *     output is markdown (e.g. report.md).
   *
   * Throws `ApiError` / `TransportError` etc. on failure; the server maps
   * those into the standard MCP error envelope.
   */
  handle(ctx: ToolContext, args: z.infer<TSchema>): Promise<ToolResult>;
}

/** Result envelope returned to the server before MCP-shape wrapping. */
export type ToolResult =
  | { kind: "json"; data: unknown }
  | { kind: "text"; text: string; data?: unknown };

/** Convenience constructors so handlers stay readable. */
export const json = (data: unknown): ToolResult => ({ kind: "json", data });
export const text = (text: string, data?: unknown): ToolResult => ({ kind: "text", text, data });
