import { describe, expect, it } from "vitest";

import { GET } from "./route";

function req(url: string): Request {
  return new Request(url);
}

async function call(kind: string, url: string) {
  const res = await GET(req(url), { params: Promise.resolve({ kind }) });
  return { status: res.status, body: await res.json() };
}

describe("shields.io badge endpoint", () => {
  it("returns the shields endpoint schema for a known kind", async () => {
    const { status, body } = await call("triaged", "https://tryaisoc.com/api/badge/triaged");
    expect(status).toBe(200);
    expect(body.schemaVersion).toBe(1);
    expect(body.label).toBe("AiSOC");
    expect(body.color).toBe("7b2bbe");
  });

  it("allows message/label/color overrides", async () => {
    const { body } = await call(
      "triaged",
      "https://tryaisoc.com/api/badge/triaged?message=41%20triaged&label=repo&color=22c55e",
    );
    expect(body.message).toBe("41 triaged");
    expect(body.label).toBe("repo");
    expect(body.color).toBe("22c55e");
  });

  it("rejects an unsafe color override, falling back to the default", async () => {
    const { body } = await call("triaged", "https://tryaisoc.com/api/badge/triaged?color=red%3Bevil");
    expect(body.color).toBe("7b2bbe");
  });

  it("404s an unknown badge kind", async () => {
    const { status, body } = await call("nope", "https://tryaisoc.com/api/badge/nope");
    expect(status).toBe(404);
    expect(body.isError).toBe(true);
  });
});
