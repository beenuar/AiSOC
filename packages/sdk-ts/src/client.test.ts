/**
 * Unit tests for @aisoc/sdk AiSOCClient.
 *
 * All HTTP calls are intercepted via fetch mocking — no real server needed.
 */

import { describe, expect, it, vi, beforeEach } from "vitest";
import { AiSOCClient, AiSOCError } from "./client.js";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeClient() {
  return new AiSOCClient({
    baseUrl: "https://aisoc.test",
    token: "aisoc_test_token",
  });
}

function mockFetch(body: unknown, status = 200) {
  const mockFn = vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  });
  vi.stubGlobal("fetch", mockFn);
  return mockFn;
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("AiSOCClient construction", () => {
  it("exposes all resource sub-clients", () => {
    const client = makeClient();
    expect(client.alerts).toBeDefined();
    expect(client.cases).toBeDefined();
    expect(client.detections).toBeDefined();
    expect(client.connectors).toBeDefined();
    expect(client.playbooks).toBeDefined();
    expect(client.apiKeys).toBeDefined();
  });
});

describe("alerts", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("list() calls GET /api/v1/alerts", async () => {
    const page = { items: [], total: 0, page: 1, pageSize: 20 };
    const mock = mockFetch(page);

    const client = makeClient();
    const result = await client.alerts.list();

    expect(result).toEqual(page);
    const [url] = mock.mock.calls[0] as [string];
    expect(url).toContain("/api/v1/alerts");
  });

  it("list() appends query params", async () => {
    mockFetch({ items: [], total: 0, page: 1, pageSize: 20 });
    const client = makeClient();
    await client.alerts.list({ severity: "critical", status: "open", page: 2 });
    const [url] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0] as [string];
    expect(url).toContain("severity=critical");
    expect(url).toContain("status=open");
    expect(url).toContain("page=2");
  });

  it("get() calls GET /api/v1/alerts/:id", async () => {
    const alert = { id: "abc", title: "Test", severity: "high" };
    const mock = mockFetch(alert);
    const client = makeClient();
    await client.alerts.get("abc");
    const [url] = mock.mock.calls[0] as [string];
    expect(url).toContain("/api/v1/alerts/abc");
  });
});

describe("cases", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("create() calls POST /api/v1/cases", async () => {
    const newCase = { id: "c1", title: "Incident" };
    const mock = mockFetch(newCase, 201);
    const client = makeClient();
    await client.cases.create({ title: "Incident" });
    const [url, opts] = mock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain("/api/v1/cases");
    expect(opts.method).toBe("POST");
  });

  it("delete() calls DELETE and returns void on 204", async () => {
    const mock = vi.fn().mockResolvedValue({ ok: true, status: 204, json: async () => undefined, text: async () => "" });
    vi.stubGlobal("fetch", mock);
    const client = makeClient();
    const result = await client.cases.delete("c1");
    expect(result).toBeUndefined();
  });
});

describe("error handling", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("throws AiSOCError on 4xx", async () => {
    mockFetch({ detail: "Not found" }, 404);
    const client = makeClient();
    await expect(client.alerts.get("missing")).rejects.toBeInstanceOf(AiSOCError);
  });

  it("AiSOCError carries status code", async () => {
    mockFetch({ detail: "Forbidden" }, 403);
    const client = makeClient();
    try {
      await client.alerts.get("x");
    } catch (e) {
      expect((e as AiSOCError).status).toBe(403);
    }
  });
});

describe("auth header", () => {
  it("includes Bearer token in every request", async () => {
    const mock = mockFetch({ items: [], total: 0, page: 1, pageSize: 20 });
    const client = new AiSOCClient({
      baseUrl: "https://aisoc.test",
      token: "aisoc_super_secret",
    });
    await client.alerts.list();
    const [, opts] = mock.mock.calls[0] as [string, RequestInit];
    const headers = opts.headers as Record<string, string>;
    expect(headers["Authorization"]).toBe("Bearer aisoc_super_secret");
  });
});
