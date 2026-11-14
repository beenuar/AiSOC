/**
 * aisoc_list_cases against the shape GET /api/v1/cases actually returns.
 *
 * The endpoint returns a bare JSON array and takes `status`, `severity`,
 * `assignee`, `limit` and `offset` (services/api/app/api/v1/endpoints/cases.py,
 * docs/openapi.yaml). The tool expected `{items, total, page, ...}` and sent
 * `priority`, `assigned_to_me`, `page`, `page_size`, so every call threw
 * "Cannot read properties of undefined (reading 'map')" and no filter applied.
 */
import { describe, expect, it, vi } from "vitest";

import type { AisocClient } from "../src/client.js";
import type { Logger } from "../src/config.js";
import { listCasesTool } from "../src/tools/cases.js";
import type { ToolContext } from "../src/tools/types.js";

const SILENT_LOG: Logger = { info: () => undefined, warn: () => undefined, error: () => undefined };

// One row exactly as the v17.1 API returned it (fields trimmed to those the tool reads).
const ROW = {
  id: "ecc97d80-46e3-4c39-8018-a7160a4c560f",
  case_number: null,
  title: "Investigation — R2 Ransomware canary files encrypted on FIN-SRV-02",
  description: "Opened from alert",
  severity: "medium",
  status: "investigating",
  assignee: null,
  alert_ids: ["0785ebd3-ff00-5334-bcab-a5afb6e39879"],
  tags: [],
  created_at: "2026-10-09T18:06:52Z",
  closed_at: null,
};

function ctxReturning(body: unknown) {
  const get = vi.fn().mockResolvedValue(body);
  const ctx: ToolContext = { client: { get, post: vi.fn() } as unknown as AisocClient, log: SILENT_LOG };
  return { ctx, get };
}

function parse(result: unknown): Record<string, unknown> {
  return (result as { data: Record<string, unknown> }).data;
}

describe("aisoc_list_cases", () => {
  it("handles the bare array the API returns", async () => {
    const { ctx } = ctxReturning([ROW]);
    const out = parse(await listCasesTool.handle(ctx, listCasesTool.schema.parse({})));
    const items = out.items as Record<string, unknown>[];
    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({ id: ROW.id, status: "investigating", severity: "medium", alert_count: 1 });
  });

  it("sends the parameters the API understands", async () => {
    const { ctx, get } = ctxReturning([]);
    await listCasesTool.handle(ctx, listCasesTool.schema.parse({ status: "investigating", severity: "critical", page: 3, page_size: 10 }));
    const query = get.mock.calls[0][1].query;
    expect(query).toMatchObject({ status: "investigating", severity: "critical", limit: 10, offset: 20 });
    expect(query).not.toHaveProperty("page");
    expect(query).not.toHaveProperty("priority");
  });

  it("offers only statuses the aisoc_cases CHECK constraint allows", () => {
    for (const s of ["new", "triaged", "investigating", "contained", "resolved", "closed"]) {
      expect(listCasesTool.schema.safeParse({ status: s }).success).toBe(true);
    }
    for (const s of ["open", "containment", "eradication", "recovery", "cancelled"]) {
      expect(listCasesTool.schema.safeParse({ status: s }).success).toBe(false);
    }
  });

  it("reports whether another page exists", async () => {
    const { ctx } = ctxReturning(Array.from({ length: 2 }, (_, i) => ({ ...ROW, id: `${ROW.id.slice(0, -1)}${i}` })));
    const out = parse(await listCasesTool.handle(ctx, listCasesTool.schema.parse({ page_size: 2 })));
    expect(out).toMatchObject({ page: 1, page_size: 2, count: 2, has_more: true });
  });
});
