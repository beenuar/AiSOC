"use client";

/**
 * Business Context — Preview results table.
 *
 * Renders the per-alert before/after diff returned by the rules preview
 * endpoint. Suppressed and changed rows are highlighted so analysts can
 * scan the impact of a draft rule-set at a glance before saving.
 */
import { useState } from "react";

import type { PreviewRow } from "./client";

interface PreviewTableProps {
  rows: PreviewRow[];
}

export function PreviewTable({ rows }: PreviewTableProps) {
  if (rows.length === 0) {
    return (
      <div className="rounded-md border border-slate-800 bg-slate-900/50 p-4 text-sm text-slate-400">
        No preview rows yet — click <em>Preview</em> to run the current
        YAML against a synthetic alert sample.
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-md border border-slate-800">
      <table className="min-w-full divide-y divide-slate-800 text-sm">
        <thead className="bg-slate-900/80 text-xs uppercase tracking-wide text-slate-400">
          <tr>
            <th className="px-3 py-2 text-left">Alert</th>
            <th className="px-3 py-2 text-left">Matched rules</th>
            <th className="px-3 py-2 text-left">Status</th>
            <th className="px-3 py-2 text-left">Severity (before → after)</th>
            <th className="px-3 py-2 text-left">Routed to</th>
            <th className="px-3 py-2" />
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800 bg-slate-950/30 text-slate-200">
          {rows.map((row) => (
            <Row key={row.alert_id} row={row} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Row({ row }: { row: PreviewRow }) {
  const [open, setOpen] = useState(false);

  const sevBefore = String(row.before?.["severity"] ?? "—");
  const sevAfter = String(row.after?.["severity"] ?? sevBefore);
  const routed = String(row.after?.["route_to"] ?? row.after?.["routed_to"] ?? "—");
  const sevChanged = sevBefore !== sevAfter;

  return (
    <>
      <tr
        className={
          row.suppressed
            ? "bg-amber-950/30"
            : row.changed
              ? "bg-emerald-950/20"
              : undefined
        }
      >
        <td className="whitespace-nowrap px-3 py-2 font-mono text-xs text-slate-300">
          {row.alert_id}
        </td>
        <td className="px-3 py-2 text-xs">
          {row.matched_rule_ids.length === 0 ? (
            <span className="text-slate-500">none</span>
          ) : (
            <div className="flex flex-wrap gap-1">
              {row.matched_rule_ids.map((id) => (
                <span
                  key={id}
                  className="rounded bg-indigo-900/40 px-1.5 py-0.5 font-mono text-[11px] text-indigo-200"
                >
                  {id}
                </span>
              ))}
            </div>
          )}
        </td>
        <td className="whitespace-nowrap px-3 py-2 text-xs">
          {row.suppressed ? (
            <span className="text-amber-300">suppressed</span>
          ) : row.changed ? (
            <span className="text-emerald-300">modified</span>
          ) : (
            <span className="text-slate-500">unchanged</span>
          )}
        </td>
        <td className="whitespace-nowrap px-3 py-2 text-xs">
          <span className={sevChanged ? "text-emerald-200" : "text-slate-300"}>
            {sevBefore} → {sevAfter}
          </span>
        </td>
        <td className="whitespace-nowrap px-3 py-2 text-xs text-slate-300">
          {routed}
        </td>
        <td className="whitespace-nowrap px-3 py-2 text-right">
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            className="text-xs text-indigo-300 hover:text-indigo-200"
          >
            {open ? "Hide diff" : "Show diff"}
          </button>
        </td>
      </tr>
      {open ? (
        <tr className="bg-slate-950/60">
          <td colSpan={6} className="px-3 py-3">
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <DiffPane title="Before" payload={row.before} />
              <DiffPane title="After" payload={row.after} />
            </div>
          </td>
        </tr>
      ) : null}
    </>
  );
}

function DiffPane({
  title,
  payload,
}: {
  title: string;
  payload: Record<string, unknown>;
}) {
  return (
    <div className="rounded border border-slate-800 bg-slate-900/60">
      <div className="border-b border-slate-800 px-2 py-1 text-[11px] uppercase tracking-wide text-slate-500">
        {title}
      </div>
      <pre className="max-h-64 overflow-auto px-2 py-2 text-xs leading-snug text-slate-200">
        {JSON.stringify(payload, null, 2)}
      </pre>
    </div>
  );
}
