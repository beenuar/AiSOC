"use client";

/**
 * The incident's own chronology.
 *
 * Every other timeline in the console shows one granularity: the alert rail
 * shows six workflow events, the case activity stream shows status changes
 * and "Alert linked" markers stamped when the row was written, the attack
 * chain shows alerts ranked by relevance. This one shows what happened —
 * each linked alert at its own event time, with the raw lake events that
 * produced it nested beneath, oldest first.
 *
 * Two honest states are load-bearing and are rendered, not swallowed:
 *
 * * the lake may be unreadable (a core-profile deployment ships no
 *   ClickHouse), which is not the same as a lake that answered with no
 *   rows, and
 * * an alert may have hit the 200-event provenance ceiling, so the events
 *   shown are known not to be all of them.
 *
 * Neither is a failure worth hiding; both change what the chronology means.
 */

import { clsx } from "clsx";
import { Fragment } from "react";

import type { IncidentTimeline, IncidentTimelineEntry } from "@/lib/api";

/** MITRE's own order, so stage groups read as the attack unfolded. */
const STAGE_ORDER: readonly string[] = [
  "reconnaissance",
  "resource-development",
  "initial-access",
  "execution",
  "persistence",
  "privilege-escalation",
  "defense-evasion",
  "credential-access",
  "discovery",
  "lateral-movement",
  "collection",
  "command-and-control",
  "exfiltration",
  "impact",
];

function stageRank(stage: string | null): number {
  if (!stage) return STAGE_ORDER.length;
  const index = STAGE_ORDER.indexOf(stage.toLowerCase());
  return index === -1 ? STAGE_ORDER.length : index;
}

function severityChip(severity: string | null): string {
  switch ((severity ?? "").toLowerCase()) {
    case "critical":
      return "bg-rose-500/15 text-rose-300 ring-rose-500/30";
    case "high":
      return "bg-orange-500/15 text-orange-300 ring-orange-500/30";
    case "medium":
      return "bg-amber-500/15 text-amber-300 ring-amber-500/30";
    case "low":
      return "bg-sky-500/15 text-sky-300 ring-sky-500/30";
    default:
      return "bg-slate-700/40 text-slate-300 ring-slate-600/40";
  }
}

function clockTime(iso: string): string {
  const ms = Date.parse(iso);
  // An unparseable timestamp is shown as itself rather than as the epoch,
  // which would read as "this happened first".
  return Number.isNaN(ms) ? iso : new Date(ms).toLocaleString();
}

/**
 * Entries grouped by kill-chain stage, in MITRE order, each group keeping
 * the chronological order it arrived in.
 *
 * An **event takes the stage of the alert it produced**. Keying events on
 * their own (absent) stage looks reasonable and is wrong: it sweeps every
 * event into one trailing bucket, so the raw evidence is torn away from the
 * alert it explains and the page stops being a chronology at all — which is
 * exactly what the browser journey caught.
 *
 * Entries with no stage either way — an alert that joined no attack story,
 * and any event belonging to one — fall into a trailing group rather than
 * being hidden.
 */
function groupByStage(
  entries: IncidentTimelineEntry[],
): Array<{ stage: string | null; entries: IncidentTimelineEntry[] }> {
  const stageOfAlert = new Map<string, string>();
  for (const e of entries) {
    if (e.kind === "alert" && e.alertId && e.chainStage) {
      stageOfAlert.set(e.alertId, e.chainStage);
    }
  }

  const groups = new Map<string, IncidentTimelineEntry[]>();
  const order: string[] = [];
  for (const e of entries) {
    const key =
      e.kind === "alert"
        ? (e.chainStage ?? "")
        : ((e.alertId && stageOfAlert.get(e.alertId)) ?? "");
    if (!groups.has(key)) {
      groups.set(key, []);
      order.push(key);
    }
    groups.get(key)!.push(e);
  }
  return order
    .sort((a, b) => stageRank(a || null) - stageRank(b || null))
    .map((key) => ({ stage: key || null, entries: groups.get(key)! }));
}

export function IncidentTimelineView({ data }: { data: IncidentTimeline }) {
  const grouped = groupByStage(data.entries);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <h3 className="text-sm font-semibold text-slate-200">Incident timeline</h3>
        <span className="text-xs text-slate-500">
          {data.alertCount} alert{data.alertCount === 1 ? "" : "s"}
          {data.eventsAvailable ? ` · ${data.eventCount} event${data.eventCount === 1 ? "" : "s"}` : null}
        </span>
      </div>

      {!data.eventsAvailable && data.eventsUnavailableReason ? (
        <p
          role="status"
          className="rounded-lg border border-amber-700/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-200"
        >
          {data.eventsUnavailableReason}
        </p>
      ) : null}

      {data.sourceEventIdsTruncated && data.truncationNote ? (
        <p className="rounded-lg border border-slate-700/60 bg-slate-800/40 px-3 py-2 text-xs text-slate-300">
          {data.truncationNote}
        </p>
      ) : null}

      {data.entries.length === 0 ? (
        <p className="rounded-lg border border-slate-800/80 bg-slate-900/40 px-3 py-6 text-center text-sm text-slate-400">
          No alerts are linked to this case yet, so there is no chronology to show.
        </p>
      ) : (
        <ol
          aria-label="Incident chronology"
          className="relative space-y-4 border-l border-slate-800/60 pl-5"
        >
          {grouped.map((group) => (
            <Fragment key={group.stage ?? "_unstaged"}>
              <li className="relative">
                <span className="text-[10px] font-semibold uppercase tracking-wide text-slate-500">
                  {group.stage ?? "Not placed in an attack story"}
                </span>
              </li>
              {group.entries.map((e, index) => (
                <li key={`${e.kind}-${e.at}-${e.alertId ?? index}`} className="relative">
                  <span
                    className={clsx(
                      "absolute -left-[26px] top-2 inline-block h-2.5 w-2.5 rounded-full ring-2 ring-slate-950",
                      e.kind === "alert" ? "bg-slate-400" : "bg-slate-600",
                    )}
                  />
                  <div
                    className={clsx(
                      "rounded-xl border p-3",
                      e.kind === "alert"
                        ? "border-slate-800/80 bg-slate-900/40"
                        : "ml-4 border-slate-800/50 bg-slate-900/20",
                    )}
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      {e.kind === "alert" ? (
                        <span
                          className={clsx(
                            "inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ring-1",
                            severityChip(e.severity),
                          )}
                        >
                          {e.severity ?? "alert"}
                        </span>
                      ) : (
                        <span className="inline-flex items-center rounded-full bg-slate-800 px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide text-slate-400 ring-1 ring-slate-700/60">
                          event
                        </span>
                      )}
                      <span className="text-sm text-slate-200">{e.title}</span>
                      <span className="ml-auto font-mono text-[10px] text-slate-500">
                        {clockTime(e.at)}
                      </span>
                    </div>

                    {e.kind === "event" ? (
                      <div className="mt-1.5 flex flex-wrap gap-3 text-[11px] text-slate-400">
                        {e.userName ? <span className="font-mono">{e.userName}</span> : null}
                        {e.hostname ? <span className="font-mono">{e.hostname}</span> : null}
                        {e.sourceIp ? <span className="font-mono">{e.sourceIp}</span> : null}
                      </div>
                    ) : (
                      <div className="mt-1.5 flex flex-wrap gap-2 text-[11px] text-slate-400">
                        {e.connectorType ? (
                          <span className="rounded bg-slate-800 px-1.5 py-0.5 font-mono">
                            {e.connectorType}
                          </span>
                        ) : null}
                        {e.mitreTechniques.map((t) => (
                          <span key={t} className="rounded bg-slate-800 px-1.5 py-0.5 font-mono">
                            {t}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </li>
              ))}
            </Fragment>
          ))}
        </ol>
      )}

      {data.disclaimer ? (
        <p className="text-[11px] italic text-slate-500">{data.disclaimer}</p>
      ) : null}
    </div>
  );
}
