/**
 * Presenting an approval to somebody holding a phone at 3am.
 *
 * The decision this screen asks for is one of the most consequential in the
 * product — isolating a host takes a machine off the network — and it is being
 * made on a small screen, probably from a lock-screen notification, probably
 * by somebody who was asleep a minute ago. So the formatting rules here are
 * not cosmetic.
 *
 * Two of them are load-bearing:
 *
 * **Say what will happen to what.** "Approve isolate_host?" is not a question
 * anyone can answer. "Isolate WKSTN-01?" is.
 *
 * **Never claim an outcome that has not happened.** After a decision the
 * approval carries a `dispatch` record saying whether the action actually
 * executed. A screen that renders "Approved" for a dispatch that failed is
 * telling an analyst the host is contained when it is not, which is the
 * specific failure this release exists to remove.
 */

export type ApprovalStatus = "pending" | "approved" | "denied" | "expired";

export interface ApprovalLike {
  id: string;
  title: string;
  summary: string;
  risk_level: string;
  status: ApprovalStatus;
  action?: Record<string, unknown> | null;
  created_at?: string;
  expires_at?: string | null;
}

/** A short, human line: the verb and the thing it happens to. */
export function actionLine(approval: ApprovalLike): string {
  const action = approval.action ?? {};
  const verb = typeof action.action_type === "string" ? humanise(action.action_type) : null;
  const target = typeof action.target === "string" && action.target.trim() ? action.target.trim() : null;

  if (verb && target) return `${verb} ${target}`;
  if (verb) return verb;
  // No action type means this approval gates a human step, which is a normal
  // shape — say so rather than inventing a verb.
  return approval.title || "Review and decide";
}

function humanise(actionType: string): string {
  const words = actionType.replace(/[_-]+/g, " ").trim();
  if (!words) return actionType;
  return words.charAt(0).toUpperCase() + words.slice(1);
}

export type OutcomeKind = "pending" | "executed" | "declined" | "not-executable" | "failed" | "unknown";

export interface Outcome {
  kind: OutcomeKind;
  /** What to show. Never optimistic. */
  label: string;
  detail?: string;
}

/**
 * What actually happened, from the row rather than from the button that was
 * tapped.
 *
 * The distinction that matters: a decision can be recorded and the execution
 * behind it refused. `status: "approved"` alone does not mean the host is off
 * the network.
 */
export function outcomeOf(approval: ApprovalLike): Outcome {
  if (approval.status === "pending") {
    return { kind: "pending", label: "Waiting for a decision" };
  }
  if (approval.status === "expired") {
    return { kind: "pending", label: "Expired without a decision" };
  }

  const dispatch = (approval.action ?? {}).dispatch;
  if (typeof dispatch !== "object" || dispatch === null) {
    // Decided before dispatch provenance existed, or by a path that does not
    // record it. "Decided" is true; "executed" is not known.
    return {
      kind: "unknown",
      label: approval.status === "approved" ? "Approved" : "Denied",
      detail: "No execution record is attached to this decision.",
    };
  }

  const state = (dispatch as Record<string, unknown>).state;
  const detail = (dispatch as Record<string, unknown>).detail;
  const reason = (dispatch as Record<string, unknown>).reason;

  switch (state) {
    case "executed":
      return { kind: "executed", label: "Approved and executed" };
    case "declined":
      return { kind: "declined", label: "Denied, and the action was withdrawn" };
    case "not_executable":
      return {
        kind: "not-executable",
        label: approval.status === "approved" ? "Approved" : "Denied",
        detail: typeof reason === "string" ? reason : "Nothing to execute.",
      };
    case "failed":
      return {
        kind: "failed",
        label: "Decision recorded — the action did NOT run",
        detail: typeof detail === "string" ? detail : "The action service refused it.",
      };
    default:
      return {
        kind: "unknown",
        label: approval.status === "approved" ? "Approved" : "Denied",
        detail: "The execution record is not in a recognised shape.",
      };
  }
}

/** Sort order for the queue: riskiest first, then oldest. */
const RISK_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

export function queueOrder(a: ApprovalLike, b: ApprovalLike): number {
  const rankA = RISK_RANK[a.risk_level] ?? 4;
  const rankB = RISK_RANK[b.risk_level] ?? 4;
  if (rankA !== rankB) return rankA - rankB;
  return (a.created_at ?? "").localeCompare(b.created_at ?? "");
}
