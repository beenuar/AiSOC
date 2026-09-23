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

// ─── Responder namespaces ─────────────────────────────────────────────────────
//
// These exist because a responder client — the PWA, the native app, or
// anything a user writes — needs approvals, push and on-call, and the
// hand-written client covered none of them. They were in docs/openapi.yaml
// the whole time, which is why nobody noticed: the generated types were
// complete and the ergonomic surface was not.

describe("responder namespaces", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("exposes approvals, push, on-call and live actions", () => {
    const client = makeClient();
    expect(client.approvals).toBeDefined();
    expect(client.push).toBeDefined();
    expect(client.onCall).toBeDefined();
    expect(client.liveActions).toBeDefined();
  });

  it("lists approvals with filters", async () => {
    const fetchMock = mockFetch({ items: [], total: 0, page: 1, page_size: 25, pages: 1 });
    await makeClient().approvals.list({ status: "pending", mine: true });

    const url = new URL(fetchMock.mock.calls[0][0] as string);
    expect(url.pathname).toBe("/api/v1/approvals");
    expect(url.searchParams.get("status")).toBe("pending");
    expect(url.searchParams.get("mine")).toBe("true");
  });

  it("posts a decision with its comment", async () => {
    const fetchMock = mockFetch({ id: "a1", status: "approved" });
    await makeClient().approvals.decide("a1", "approve", "Confirmed with the host owner.");

    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toContain("/api/v1/approvals/a1/decide");
    expect(JSON.parse((init as RequestInit).body as string)).toEqual({
      decision: "approve",
      comment: "Confirmed with the host owner.",
    });
  });

  it("fetches the VAPID key a browser needs before it can subscribe", async () => {
    const fetchMock = mockFetch({ public_key: "BFake" });
    await makeClient().push.publicKey();

    expect(String(fetchMock.mock.calls[0][0])).toContain("/api/v1/push/public-key");
  });

  it("subscribes with the shape PushSubscription.toJSON() produces", async () => {
    const fetchMock = mockFetch({ status: "ok" });
    await makeClient().push.subscribe({
      endpoint: "https://push.example/abc",
      keys: { p256dh: "k", auth: "a" },
      topics: ["agent_approval"],
    });

    const body = JSON.parse((fetchMock.mock.calls[0][1] as RequestInit).body as string);
    expect(body.endpoint).toBe("https://push.example/abc");
    expect(body.topics).toEqual(["agent_approval"]);
  });

  it("asks who is on call", async () => {
    const fetchMock = mockFetch({ user_id: "u1", name: "Dana" });
    await makeClient().onCall.me();

    expect(String(fetchMock.mock.calls[0][0])).toContain("/api/v1/oncall/me");
  });

  it("encodes a capability into the path rather than trusting it", async () => {
    const fetchMock = mockFetch([]);
    await makeClient().liveActions.vendorsFor("isolate/host");

    expect(String(fetchMock.mock.calls[0][0])).toContain("isolate%2Fhost");
  });

  it("offers dry-run and deliberately not dispatch", () => {
    // A live containment goes through the approval path so an approver is
    // bound to it; the API exposes no un-approved dispatch route to proxy.
    const liveActions = makeClient().liveActions as unknown as Record<string, unknown>;
    expect(typeof liveActions.dryRun).toBe("function");
    expect(liveActions.dispatch).toBeUndefined();
  });
});

describe("injected fetch", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("uses the fetch passed in options", async () => {
    // AiSOCClientOptions.fetch was documented and never threaded through, so
    // a caller could pass one and silently not get it. React Native is the
    // case that matters: its fetch is not the object this module closed over.
    const injected = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ items: [] }),
      text: async () => "{}",
    });
    const global = mockFetch({ items: [] });

    const client = new AiSOCClient({
      baseUrl: "https://aisoc.test",
      token: "t",
      fetch: injected as unknown as typeof globalThis.fetch,
    });
    await client.alerts.list();

    expect(injected).toHaveBeenCalledTimes(1);
    expect(global).not.toHaveBeenCalled();
  });

  it("falls back to the global resolved at call time", async () => {
    // Resolved per call, not captured at construction, so replacing the
    // global afterwards still works.
    const client = makeClient();
    const fetchMock = mockFetch({ items: [] });
    await client.alerts.list();

    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
