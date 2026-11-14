import { describe, expect, it } from "vitest";
import { Session, decodeClaims, isUsable, type SecureStorage } from "./session.js";

function jwt(payload: Record<string, unknown>): string {
  const encode = (value: unknown) =>
    globalThis.btoa(JSON.stringify(value)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `${encode({ alg: "HS256" })}.${encode(payload)}.signature`;
}

class MemoryStorage implements SecureStorage {
  private readonly items = new Map<string, string>();

  async getItemAsync(key: string) {
    return this.items.get(key) ?? null;
  }

  async setItemAsync(key: string, value: string) {
    this.items.set(key, value);
  }

  async deleteItemAsync(key: string) {
    this.items.delete(key);
  }
}

const NOW = Date.UTC(2026, 8, 23, 12, 0, 0);

describe("decodeClaims", () => {
  it("reads a payload", () => {
    const claims = decodeClaims(jwt({ sub: "u1", tenant_id: "t1", exp: 1_800_000_000 }));
    expect(claims?.sub).toBe("u1");
    expect(claims?.tenant_id).toBe("t1");
  });

  it("returns null for anything that is not a three-part token", () => {
    expect(decodeClaims("not-a-token")).toBeNull();
    expect(decodeClaims("a.b")).toBeNull();
  });

  it("returns null rather than throwing on undecodable payloads", () => {
    expect(decodeClaims("a.!!!!.c")).toBeNull();
  });
});

describe("isUsable", () => {
  it("accepts a token with room to spare", () => {
    expect(isUsable(jwt({ exp: NOW / 1000 + 3600 }), NOW)).toBe(true);
  });

  it("rejects an expired token", () => {
    expect(isUsable(jwt({ exp: NOW / 1000 - 1 }), NOW)).toBe(false);
  });

  it("rejects a token inside the refresh margin", () => {
    // Firing a request that is about to 401 loses the analyst a round trip at
    // the moment they are trying to decide something.
    expect(isUsable(jwt({ exp: NOW / 1000 + 30 }), NOW)).toBe(false);
  });

  it("treats a token with no expiry as unusable, not eternal", () => {
    // An unreadable expiry is not the same as no expiry. Guessing permissive
    // leaves the app sitting on a dead token showing an empty queue.
    expect(isUsable(jwt({ sub: "u1" }), NOW)).toBe(false);
  });

  it("rejects null", () => {
    expect(isUsable(null, NOW)).toBe(false);
  });
});

describe("Session", () => {
  it("round-trips a token", async () => {
    const session = new Session(new MemoryStorage());
    await session.save("abc");
    expect(await session.load()).toBe("abc");
  });

  it("returns a live token from current()", async () => {
    const session = new Session(new MemoryStorage());
    const token = jwt({ exp: NOW / 1000 + 3600 });
    await session.save(token);
    expect(await session.current(NOW)).toBe(token);
  });

  it("drops an expired token instead of handing it back", async () => {
    const storage = new MemoryStorage();
    const session = new Session(storage);
    await session.save(jwt({ exp: NOW / 1000 - 10 }));

    expect(await session.current(NOW)).toBeNull();
    expect(await storage.getItemAsync("aisoc.session.token")).toBeNull();
  });

  it("clear() removes the token", async () => {
    const session = new Session(new MemoryStorage());
    await session.save("abc");
    await session.clear();
    expect(await session.load()).toBeNull();
  });
});
