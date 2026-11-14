import { describe, expect, it } from "vitest";
import { actionLine, outcomeOf, queueOrder, type ApprovalLike } from "./approvals.js";

function approval(overrides: Partial<ApprovalLike> = {}): ApprovalLike {
  return {
    id: "a1",
    title: "Contain beaconing host",
    summary: "Confirmed C2 beacon from WKSTN-01.",
    risk_level: "high",
    status: "pending",
    action: { action_type: "isolate_host", target: "WKSTN-01" },
    created_at: "2026-09-23T10:00:00Z",
    ...overrides,
  };
}

describe("actionLine", () => {
  it("says what will happen to what", () => {
    // "Approve isolate_host?" is not a question anyone can answer at 3am.
    expect(actionLine(approval())).toBe("Isolate host WKSTN-01");
  });

  it("falls back to the verb alone when there is no target", () => {
    expect(actionLine(approval({ action: { action_type: "run_av_scan" } }))).toBe("Run av scan");
  });

  it("uses the title when the approval gates a human step", () => {
    // An approval with no action type is a normal shape, not a broken row.
    expect(actionLine(approval({ action: {} }))).toBe("Contain beaconing host");
  });

  it("handles a null action without throwing", () => {
    expect(actionLine(approval({ action: null }))).toBe("Contain beaconing host");
  });
});

describe("outcomeOf", () => {
  it("reports a pending approval as waiting", () => {
    expect(outcomeOf(approval()).kind).toBe("pending");
  });

  it("reports an executed approval as executed", () => {
    const result = outcomeOf(
      approval({ status: "approved", action: { dispatch: { state: "executed" } } }),
    );
    expect(result.kind).toBe("executed");
    expect(result.label).toContain("executed");
  });

  it("NEVER claims execution when the dispatch failed", () => {
    // The whole point. A screen that renders "Approved" here tells an analyst
    // the host is contained when it is not.
    const result = outcomeOf(
      approval({
        status: "approved",
        action: { dispatch: { state: "failed", detail: "blast radius exceeds tier" } },
      }),
    );
    expect(result.kind).toBe("failed");
    expect(result.label).toContain("did NOT run");
    expect(result.detail).toContain("blast radius");
  });

  it("distinguishes nothing-to-run from a failure", () => {
    const result = outcomeOf(
      approval({
        status: "approved",
        action: { dispatch: { state: "not_executable", reason: "approval carries no action_type" } },
      }),
    );
    expect(result.kind).toBe("not-executable");
    expect(result.detail).toContain("no action_type");
  });

  it("says a denial withdrew the action", () => {
    const result = outcomeOf(approval({ status: "denied", action: { dispatch: { state: "declined" } } }));
    expect(result.kind).toBe("declined");
  });

  it("admits when there is no execution record rather than assuming success", () => {
    const result = outcomeOf(approval({ status: "approved", action: {} }));
    expect(result.kind).toBe("unknown");
    expect(result.detail).toContain("No execution record");
  });

  it("admits when the execution record is an unrecognised shape", () => {
    const result = outcomeOf(
      approval({ status: "approved", action: { dispatch: { state: "something-new" } } }),
    );
    expect(result.kind).toBe("unknown");
  });
});

describe("queueOrder", () => {
  it("puts the riskiest first", () => {
    const sorted = [
      approval({ id: "low", risk_level: "low" }),
      approval({ id: "crit", risk_level: "critical" }),
      approval({ id: "med", risk_level: "medium" }),
    ].sort(queueOrder);
    expect(sorted.map((a) => a.id)).toEqual(["crit", "med", "low"]);
  });

  it("breaks ties by age, oldest first", () => {
    const sorted = [
      approval({ id: "new", created_at: "2026-09-23T12:00:00Z" }),
      approval({ id: "old", created_at: "2026-09-23T09:00:00Z" }),
    ].sort(queueOrder);
    expect(sorted.map((a) => a.id)).toEqual(["old", "new"]);
  });

  it("sorts an unknown risk level last rather than first", () => {
    const sorted = [
      approval({ id: "weird", risk_level: "unheard-of" }),
      approval({ id: "low", risk_level: "low" }),
    ].sort(queueOrder);
    expect(sorted.map((a) => a.id)).toEqual(["low", "weird"]);
  });
});
