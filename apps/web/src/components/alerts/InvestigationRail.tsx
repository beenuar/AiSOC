'use client';

/**
 * Investigation Rail (v1.5 W6 — SOC console parity).
 *
 * Structured triage panel rendered to the right of the `/alerts` grid
 * whenever an analyst selects a row. The rail consumes the envelope
 * served by `GET /api/v1/alerts/{id}` — which carries four sections
 * the analyst needs at first glance:
 *
 *   1. Narrative — deterministic, Markdown-light explanation of *why*
 *      fusion promoted this alert. Cached on the row at fusion time and
 *      lazily back-filled by the API for legacy alerts so we never
 *      surface a blank panel.
 *   2. Related entities — principal / network / workflow / tenant
 *      groupings. Entries with a `pivotPath` link straight into the
 *      AttackGraphView so analysts can hop from "10.0.0.7" to its
 *      neighbourhood in two clicks instead of switching pages.
 *   3. Mini-timeline — the six most recent case-timeline + audit-log
 *      events for this alert's case, surfaced inline so the analyst
 *      doesn't have to leave the queue just to see what happened last.
 *   4. Recommended actions — ResponderAgent's structured guidance,
 *      normalised server-side so legacy list-of-strings payloads and
 *      the modern `{priority, action, rationale, risk}` shape render
 *      uniformly.
 *
 * A single "Deep Explain" button at the top of the rail still opens the
 * existing {@link ExplainDrawer} for the rich LLM-driven walkthrough —
 * the rail itself is deterministic and cheap so we don't burn an LLM
 * call every time the analyst clicks a row.
 *
 * Author: Beenu Arora <beenu@cyble.com>
 */

import Link from 'next/link';
import { useState } from 'react';
import useSWR from 'swr';
import { clsx } from 'clsx';
import { format, formatDistanceToNow } from 'date-fns';
import {
  alertsApi,
  type Alert,
  type MiniTimelineEvent,
  type RecommendedAction,
  type RelatedEntity,
} from '@/lib/api';
import { ExplainDrawer } from './ExplainDrawer';
import { Skeleton } from '@/components/ui/Skeleton';

// ─── Visual config ───────────────────────────────────────────────────────────

/**
 * Grouping config for {@link RelatedEntity.kind}.
 *
 * The order of these keys determines the render order inside the rail.
 * "principal" goes first because that's the entity an analyst usually
 * pivots on (who did it / who was hit). "tenant" is last because it's
 * the broadest-context grouping.
 */
const ENTITY_KIND_CONFIG: Record<
  RelatedEntity['kind'],
  { label: string; tone: string }
> = {
  principal: { label: 'Principals', tone: 'text-blue-300' },
  network: { label: 'Network', tone: 'text-cyan-300' },
  workflow: { label: 'Workflow', tone: 'text-purple-300' },
  tenant: { label: 'Tenant', tone: 'text-gray-300' },
};

/** Tone map for the priority chip on a recommended action. */
const PRIORITY_TONE: Record<RecommendedAction['priority'], string> = {
  critical: 'border-red-500/40 bg-red-500/10 text-red-300',
  high: 'border-orange-500/40 bg-orange-500/10 text-orange-300',
  medium: 'border-yellow-500/40 bg-yellow-500/10 text-yellow-300',
  low: 'border-blue-500/40 bg-blue-500/10 text-blue-300',
  info: 'border-gray-500/40 bg-gray-500/10 text-gray-300',
};

// ─── Props ───────────────────────────────────────────────────────────────────

export interface InvestigationRailProps {
  /** Selected alert id. When `null` the rail renders an empty-state hint. */
  alertId: string | null;
  /** Called when the analyst dismisses the rail (close button). */
  onClose: () => void;
}

// ─── Main component ──────────────────────────────────────────────────────────

export function InvestigationRail({ alertId, onClose }: InvestigationRailProps) {
  // The drawer is mounted on demand and closed by default; we don't
  // burn the LLM call until the analyst explicitly asks for it.
  const [deepExplainOpen, setDeepExplainOpen] = useState(false);

  const { data: alert, error, isLoading } = useSWR(
    alertId ? (['alerts', alertId, 'rail'] as const) : null,
    () => alertsApi.get(alertId as string),
    {
      // The rail is supposed to feel like a *snapshot* — the analyst
      // explicitly opens it. We don't want noisy revalidates on tab
      // focus throwing off their reading flow.
      revalidateOnFocus: false,
      shouldRetryOnError: false,
    },
  );

  if (!alertId) {
    return <RailPlaceholder />;
  }

  if (isLoading || (!alert && !error)) {
    return <RailLoading onClose={onClose} />;
  }

  if (error || !alert) {
    return (
      <RailShell title="Investigation rail" onClose={onClose}>
        <div className="px-4 py-6 text-sm text-red-300">
          <p className="font-medium">Couldn&apos;t load the alert envelope.</p>
          <p className="mt-1 text-xs text-gray-500">
            The alert API didn&apos;t respond. Try selecting the alert again or
            open the full detail view.
          </p>
        </div>
      </RailShell>
    );
  }

  return (
    <>
      <RailShell title={alert.title} onClose={onClose}>
        <RailHeader alert={alert} onDeepExplain={() => setDeepExplainOpen(true)} />
        <NarrativeSection narrative={alert.narrative ?? null} />
        <RelatedEntitiesSection entities={alert.relatedEntities ?? []} />
        <MiniTimelineSection events={alert.miniTimeline ?? []} />
        <RecommendedActionsSection actions={alert.recommendedActions ?? []} />
      </RailShell>
      {/*
       * Deep Explain is mounted only when requested — keeping it inside the
       * rail (rather than at AlertsView level) means the rail owns the
       * "deep" affordance and we don't end up with two ways to open the
       * same drawer from different places.
       */}
      {deepExplainOpen && (
        <ExplainDrawer
          open={true}
          alert={alert}
          onClose={() => setDeepExplainOpen(false)}
        />
      )}
    </>
  );
}

// ─── Layout primitives ───────────────────────────────────────────────────────

function RailShell({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
}) {
  return (
    <aside
      className="flex flex-col bg-gray-900/60 border border-gray-800/60 rounded-xl overflow-hidden h-full"
      aria-label="Investigation rail"
    >
      <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800/60 bg-gray-900/80">
        <h2 className="text-sm font-semibold text-gray-100 truncate" title={title}>
          {title}
        </h2>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close investigation rail"
          className="text-xs text-gray-500 hover:text-gray-300 px-2 py-0.5 rounded hover:bg-gray-800/60 transition-colors"
        >
          Close
        </button>
      </div>
      <div className="flex-1 overflow-y-auto">{children}</div>
    </aside>
  );
}

function RailPlaceholder() {
  return (
    <aside
      className="flex flex-col items-center justify-center bg-gray-900/30 border border-dashed border-gray-800/60 rounded-xl text-gray-500 text-sm h-full p-6 text-center"
      aria-label="Investigation rail (no alert selected)"
    >
      <p className="font-medium text-gray-400">Select an alert to investigate</p>
      <p className="mt-1 text-xs text-gray-600">
        Click a row in the queue on the left. The rail will show the fusion
        narrative, related entities, recent events, and recommended actions.
      </p>
    </aside>
  );
}

function RailLoading({ onClose }: { onClose: () => void }) {
  return (
    <RailShell title="Loading…" onClose={onClose}>
      <div className="p-4 space-y-4">
        <Skeleton className="h-4 w-2/3" />
        <Skeleton className="h-3 w-full" />
        <Skeleton className="h-3 w-5/6" />
        <Skeleton className="h-3 w-4/6" />
        <div className="pt-3 space-y-2">
          <Skeleton className="h-3 w-1/4" />
          <Skeleton className="h-3 w-3/4" />
          <Skeleton className="h-3 w-2/4" />
        </div>
      </div>
    </RailShell>
  );
}

// ─── Header (severity, status, deep explain) ─────────────────────────────────

function RailHeader({
  alert,
  onDeepExplain,
}: {
  alert: Alert;
  onDeepExplain: () => void;
}) {
  return (
    <div className="px-4 py-3 border-b border-gray-800/60 bg-gray-900/40">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-gray-500">
        <span className="capitalize text-gray-300">{alert.severity}</span>
        <span>·</span>
        <span className="capitalize">{alert.status.replace('_', ' ')}</span>
        <span>·</span>
        <span>{alert.source}</span>
        <span>·</span>
        <span suppressHydrationWarning>
          {formatDistanceToNow(new Date(alert.createdAt), { addSuffix: true })}
        </span>
        {typeof alert.riskScore === 'number' && (
          <>
            <span>·</span>
            <span className="font-mono text-gray-400">
              risk {Math.round(alert.riskScore)}
            </span>
          </>
        )}
      </div>
      <div className="mt-3 flex items-center gap-3">
        <button
          type="button"
          onClick={onDeepExplain}
          aria-label="Open AI deep explain drawer"
          title="Run the LLM deep-explain for this alert"
          className="text-xs font-medium px-2.5 py-1 rounded border border-violet-500/40 bg-violet-500/10 text-violet-300 hover:bg-violet-500/20 hover:border-violet-500/60 transition-colors"
        >
          ✦ Deep Explain
        </button>
        <Link
          href={`/alerts/${alert.id}`}
          className="text-xs text-blue-300 hover:text-blue-200 transition-colors"
        >
          Open full detail →
        </Link>
      </div>
    </div>
  );
}

// ─── Sections ────────────────────────────────────────────────────────────────

function SectionHeader({ title, count }: { title: string; count?: number }) {
  return (
    <h3 className="text-[11px] uppercase tracking-wider text-gray-500 mb-2 font-medium">
      {title}
      {typeof count === 'number' && (
        <span className="ml-1.5 text-gray-600">({count})</span>
      )}
    </h3>
  );
}

function NarrativeSection({ narrative }: { narrative: string | null }) {
  if (!narrative || !narrative.trim()) return null;
  // Markdown-light: we preserve newlines so the deterministic
  // paragraph + bullet structure produced by `narrative.build_narrative`
  // renders without us pulling in a full Markdown engine.
  return (
    <section className="px-4 py-4 border-b border-gray-800/40">
      <SectionHeader title="Narrative" />
      <p className="text-sm text-gray-300 whitespace-pre-wrap leading-relaxed">
        {narrative}
      </p>
    </section>
  );
}

function RelatedEntitiesSection({ entities }: { entities: RelatedEntity[] }) {
  if (entities.length === 0) return null;
  // Server already groups by kind in the canonical order, but defensively
  // re-group on the client so an out-of-order payload (older API) still
  // renders cleanly grouped.
  const grouped = entities.reduce<Record<RelatedEntity['kind'], RelatedEntity[]>>(
    (acc, e) => {
      (acc[e.kind] ||= []).push(e);
      return acc;
    },
    { principal: [], network: [], workflow: [], tenant: [] },
  );
  return (
    <section className="px-4 py-4 border-b border-gray-800/40">
      <SectionHeader title="Related entities" count={entities.length} />
      <div className="space-y-3">
        {(Object.keys(ENTITY_KIND_CONFIG) as Array<keyof typeof ENTITY_KIND_CONFIG>).map(
          (kind) => {
            const items = grouped[kind];
            if (!items || items.length === 0) return null;
            const cfg = ENTITY_KIND_CONFIG[kind];
            return (
              <div key={kind}>
                <p className={clsx('text-xs font-medium', cfg.tone)}>{cfg.label}</p>
                <ul className="mt-1.5 flex flex-wrap gap-1.5">
                  {items.map((e) => (
                    <EntityChip key={`${e.type}:${e.value}`} entity={e} />
                  ))}
                </ul>
              </div>
            );
          },
        )}
      </div>
    </section>
  );
}

function EntityChip({ entity }: { entity: RelatedEntity }) {
  const display = entity.label || entity.value;
  const inner = (
    <span
      className={clsx(
        'inline-flex items-center gap-1.5 text-xs px-2 py-0.5 rounded border border-gray-700/60 bg-gray-800/60 text-gray-200',
        entity.pivotPath &&
          'hover:bg-gray-700/60 hover:border-gray-600/60 cursor-pointer transition-colors',
      )}
      title={`${entity.type}: ${entity.value}`}
    >
      <span className="text-gray-500 font-mono text-[10px]">{entity.type}</span>
      <span className="font-mono">{display}</span>
    </span>
  );
  return (
    <li>
      {entity.pivotPath ? (
        <Link href={entity.pivotPath} className="inline-block">
          {inner}
        </Link>
      ) : (
        inner
      )}
    </li>
  );
}

function MiniTimelineSection({ events }: { events: MiniTimelineEvent[] }) {
  if (events.length === 0) return null;
  return (
    <section className="px-4 py-4 border-b border-gray-800/40">
      <SectionHeader title="Recent events" count={events.length} />
      <ol className="space-y-2.5">
        {events.map((e) => (
          <TimelineRow key={e.id} event={e} />
        ))}
      </ol>
    </section>
  );
}

function TimelineRow({ event }: { event: MiniTimelineEvent }) {
  let ts: string;
  try {
    ts = format(new Date(event.timestamp), 'MMM d HH:mm');
  } catch {
    // Defensive: if the server hands back a malformed timestamp we still
    // render the row rather than crashing the rail.
    ts = event.timestamp;
  }
  return (
    <li className="text-xs text-gray-300 border-l-2 border-gray-700/60 pl-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-gray-500 text-[10px]" suppressHydrationWarning>
          {ts}
        </span>
        <span className="px-1.5 py-0 text-[10px] font-mono rounded border border-gray-700/60 bg-gray-800/40 text-gray-400 uppercase">
          {event.source === 'case_timeline' ? 'case' : 'audit'}
        </span>
        <span className="text-[10px] uppercase text-gray-500 tracking-wide">
          {event.type}
        </span>
      </div>
      <p className="mt-0.5 text-gray-200">{event.title}</p>
      {event.description && (
        <p className="mt-0.5 text-gray-500 line-clamp-2">{event.description}</p>
      )}
      {event.actor && (
        <p className="mt-0.5 text-[10px] text-gray-600">by {event.actor}</p>
      )}
    </li>
  );
}

function RecommendedActionsSection({ actions }: { actions: RecommendedAction[] }) {
  if (actions.length === 0) return null;
  return (
    <section className="px-4 py-4">
      <SectionHeader title="Recommended actions" count={actions.length} />
      <ul className="space-y-2">
        {actions.map((a, idx) => (
          <li
            key={`${a.action}-${idx}`}
            className="border border-gray-800/60 bg-gray-900/40 rounded-lg p-2.5"
          >
            <div className="flex items-start gap-2">
              <span
                className={clsx(
                  'text-[10px] font-mono uppercase px-1.5 py-0.5 rounded border shrink-0 mt-0.5',
                  PRIORITY_TONE[a.priority] ?? PRIORITY_TONE.medium,
                )}
              >
                {a.priority}
              </span>
              <p className="text-sm text-gray-200 flex-1">{a.action}</p>
            </div>
            {a.rationale && (
              <p className="mt-1 text-xs text-gray-500 ml-[3.25rem]">
                {a.rationale}
              </p>
            )}
            {a.risk && (
              <p className="mt-1 text-xs text-amber-400/80 ml-[3.25rem]">
                Risk: {a.risk}
              </p>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}
