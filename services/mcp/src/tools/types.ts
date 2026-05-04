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

/** Minimal MCP "tool" descriptor — name + JSON schema for ListToolsResult. */
export interface ToolMetadata {
  /** Tool ID surfaced to the agent. Convention: `aisoc_<verb>_<resource>`. */
  name: string;
  /** One-line description shown in tool pickers. Keep under ~80 chars. */
  description: string;
  /** JSON Schema for the input arguments (pre-converted from zod). */
  inputSchema: Record<string, unknown>;
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
