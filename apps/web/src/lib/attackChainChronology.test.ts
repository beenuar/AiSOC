import { describe, expect, it } from "vitest";

import {
  orderChainChronologically,
  seedRelativeLabel,
} from "./attackChainChronology";

import type { AttackChainLink } from "./api";

function link(partial: Partial<AttackChainLink> & { alertId: string; eventTime: string }): AttackChainLink {
  return {
    title: "alert",
    severity: "medium",
    score: 0.5,
    distance: 1,
    dtSeconds: 0,
    sharedEntities: [],
    mitreTechniques: [],
    connectorType: null,
    sourceEventIds: [],
    ...partial,
  } as AttackChainLink;
}

describe("orderChainChronologically", () => {
  it("renders the chain oldest-first even though the API ranks by relevance", () => {
    // The API deliberately returns score order; the view claims chronology.
    const ranked = [
      link({ alertId: "late", eventTime: "2026-05-14T20:00:00Z", score: 0.9 }),
      link({ alertId: "early", eventTime: "2026-05-14T09:00:00Z", score: 0.4 }),
      link({ alertId: "mid", eventTime: "2026-05-14T12:00:00Z", score: 0.6 }),
    ];
    expect(orderChainChronologically(ranked).map((l) => l.alertId)).toEqual([
      "early",
      "mid",
      "late",
    ]);
  });

  it("does not mutate the ranked array it was given", () => {
    const ranked = [
      link({ alertId: "b", eventTime: "2026-05-14T20:00:00Z" }),
      link({ alertId: "a", eventTime: "2026-05-14T09:00:00Z" }),
    ];
    orderChainChronologically(ranked);
    expect(ranked.map((l) => l.alertId)).toEqual(["b", "a"]);
  });

  it("breaks ties on alert id so the order is stable across renders", () => {
    const sameInstant = [
      link({ alertId: "zzz", eventTime: "2026-05-14T09:00:00Z" }),
      link({ alertId: "aaa", eventTime: "2026-05-14T09:00:00Z" }),
    ];
    expect(orderChainChronologically(sameInstant).map((l) => l.alertId)).toEqual([
      "aaa",
      "zzz",
    ]);
  });

  it("keeps an unparseable timestamp rather than dropping the link", () => {
    const mixed = [
      link({ alertId: "broken", eventTime: "not-a-date" }),
      link({ alertId: "good", eventTime: "2026-05-14T09:00:00Z" }),
    ];
    const ordered = orderChainChronologically(mixed);
    expect(ordered).toHaveLength(2);
    expect(ordered.map((l) => l.alertId).sort()).toEqual(["broken", "good"]);
  });
});

describe("seedRelativeLabel", () => {
  const seed = "2026-05-14T12:00:00Z";

  it("never calls a chain link the seed: the seed is not in the chain", () => {
    // The console used to label row 0 "seed". The API excludes the seed
    // from the chain entirely, so that label named the wrong alert.
    const first = link({ alertId: "x", eventTime: "2026-05-14T09:00:00Z", dtSeconds: 10800 });
    expect(seedRelativeLabel(first, seed).toLowerCase()).not.toContain("seed");
  });

  it("says which side of the seed a link falls on", () => {
    const before = link({ alertId: "b", eventTime: "2026-05-14T11:30:00Z", dtSeconds: 1800 });
    const after = link({ alertId: "a", eventTime: "2026-05-14T12:45:00Z", dtSeconds: 2700 });
    expect(seedRelativeLabel(before, seed)).toBe("−30m");
    expect(seedRelativeLabel(after, seed)).toBe("+45m");
  });

  it("scales to seconds, minutes and hours", () => {
    expect(seedRelativeLabel(link({ alertId: "s", eventTime: "2026-05-14T12:00:20Z", dtSeconds: 20 }), seed)).toBe("+20s");
    expect(seedRelativeLabel(link({ alertId: "h", eventTime: "2026-05-14T18:00:00Z", dtSeconds: 21600 }), seed)).toBe("+6.0h");
  });

  it("reads 'same moment' rather than a signed zero", () => {
    expect(seedRelativeLabel(link({ alertId: "z", eventTime: seed, dtSeconds: 0 }), seed)).toBe("same moment");
  });

  it("falls back to an unsigned delta when the seed time is unknown", () => {
    // An older cached payload has no seed_event_time; the honest answer
    // is the distance without a direction, never an invented one.
    const l = link({ alertId: "x", eventTime: "2026-05-14T13:00:00Z", dtSeconds: 3600 });
    expect(seedRelativeLabel(l, null)).toBe("1.0h from seed");
  });
});
