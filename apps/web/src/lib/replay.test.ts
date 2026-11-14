import { afterEach, describe, expect, it, vi } from "vitest";

import { fetchPublicReplay } from "./replay";

describe("fetchPublicReplay", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("returns the parsed replay on 200", async () => {
    const payload = { slug: "abc123def456", title: "T", case_id: "INC-1", snapshot: { stepCount: 3 }, view_count: 5, created_at: "x" };
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify(payload), { status: 200, headers: { "content-type": "application/json" } })),
    );
    const result = await fetchPublicReplay("abc123def456");
    expect(result.kind).toBe("ok");
    if (result.kind !== "ok") return;
    expect(result.replay.slug).toBe("abc123def456");
    expect(result.replay.snapshot.stepCount).toBe(3);
  });

  it("reports a 404 as missing", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("nope", { status: 404 })));
    expect((await fetchPublicReplay("missing")).kind).toBe("missing");
  });

  // These four used to assert `toBeNull()`, the same answer a 404 gave, and
  // the page turns that into "404 · page not found". An operator whose API
  // was down was told their replay link was wrong.
  it.each([500, 502, 503, 401])("reports HTTP %i as unavailable, not missing", async (status) => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("boom", { status })));
    const result = await fetchPublicReplay("x");
    expect(result).toEqual({ kind: "unavailable", status });
  });

  it("reports a network error as unavailable (and never throws)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("boom");
      }),
    );
    expect(await fetchPublicReplay("x")).toEqual({ kind: "unavailable", status: null });
  });

  it("reports an unparseable 200 body as unavailable", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("<html>gateway</html>", { status: 200 })));
    expect((await fetchPublicReplay("x")).kind).toBe("unavailable");
  });

  it("URL-encodes the slug", async () => {
    const spy = vi.fn(async (_url: string) => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", spy);
    await fetchPublicReplay("a/b");
    expect(String(spy.mock.calls[0]?.[0])).toContain("a%2Fb");
  });
});
