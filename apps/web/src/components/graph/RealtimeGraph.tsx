'use client';

/**
 * RealtimeGraph — live Cytoscape view fed by ``useGraphWebSocket`` (T1.4 — v8.0).
 *
 * End-to-end:
 *
 *   Neo4j writer ──► Kafka ``security.graph_updates``
 *                       │
 *                       ▼
 *   services/ingest/internal/graph_ws/Broadcaster
 *                       │  (RFC6455 frames, tenant-scoped)
 *                       ▼
 *   services/api .../v1/graph_ws/stream  (auth + tenant rebind)
 *                       │
 *                       ▼  same-origin /api/v1/graph_ws/stream
 *   apps/web useGraphWebSocket hook ─► RealtimeGraph (THIS file)
 *
 * Latency budget — Kafka publish to first paint — is ≤ 1s. The
 * component therefore patches the existing Cytoscape instance in place
 * rather than recomputing layout on every event: a full ``cy.layout()``
 * run on a 200-node graph easily crosses 200 ms on a mid-range laptop
 * and the budget evaporates after two or three rapid envelopes. We
 * relayout only on demand (the analyst clicks the relayout button) or
 * the first time we receive a non-empty graph.
 *
 * Visual encoding mirrors ``AttackGraphView`` so the two views feel
 * like the same graph rendered with two clocks: a polled SWR snapshot
 * on one tab, a live tail on another.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import cytoscape, {
  type Core,
  type ElementDefinition,
  type LayoutOptions,
  type StylesheetStyle,
} from 'cytoscape';
import fcose from 'cytoscape-fcose';

import {
  type GraphUpdateEnvelope,
  useGraphWebSocket,
  type GraphWebSocketStatus,
} from '@/hooks/useGraphWebSocket';

if (typeof window !== 'undefined') {
  try {
    cytoscape.use(fcose as unknown as cytoscape.Ext);
  } catch {
    /* already registered — Next.js fast-refresh re-runs this module */
  }
}

const NODE_COLORS: Record<string, string> = {
  Host: '#60a5fa',
  Asset: '#22d3ee',
  User: '#a78bfa',
  Identity: '#a78bfa',
  IP: '#f59e0b',
  Domain: '#fbbf24',
  Process: '#34d399',
  Technique: '#f87171',
  Tactic: '#fb7185',
  Alert: '#ef4444',
  Default: '#94a3b8',
};

const NODE_SHAPES: Record<string, cytoscape.Css.NodeShape> = {
  Host: 'round-rectangle',
  Asset: 'round-rectangle',
  User: 'ellipse',
  Identity: 'ellipse',
  IP: 'diamond',
  Domain: 'diamond',
  Process: 'tag',
  Technique: 'star',
  Tactic: 'star',
  Alert: 'octagon',
  Default: 'ellipse',
};

const FCOSE_LAYOUT: LayoutOptions = {
  name: 'fcose',
  animate: true,
  animationDuration: 400,
  randomize: false,
  fit: true,
  padding: 30,
  // The library types lag the runtime API; cast through unknown so
  // the extra-options ride along without disabling TS for the file.
  nodeRepulsion: 6000,
  idealEdgeLength: 80,
  gravity: 0.2,
} as unknown as LayoutOptions;

const STYLE: StylesheetStyle[] = [
  {
    selector: 'node',
    style: {
      'background-color': 'data(color)',
      shape: 'data(shape)' as cytoscape.Css.NodeShape,
      label: 'data(label)',
      color: '#e2e8f0',
      'font-size': 10,
      'text-valign': 'bottom',
      'text-margin-y': 4,
      'text-outline-color': '#0b1220',
      'text-outline-width': 2,
      width: 28,
      height: 28,
      'border-color': '#0f172a',
      'border-width': 2,
    },
  },
  {
    selector: 'node.flash',
    style: {
      'border-color': '#fbbf24',
      'border-width': 4,
    },
  },
  {
    selector: 'edge',
    style: {
      width: 1.5,
      'line-color': '#475569',
      'target-arrow-color': '#475569',
      'target-arrow-shape': 'triangle',
      'curve-style': 'bezier',
      label: 'data(label)',
      'font-size': 8,
      color: '#94a3b8',
      'text-rotation': 'autorotate',
    },
  },
  {
    selector: 'edge.flash',
    style: {
      'line-color': '#fbbf24',
      'target-arrow-color': '#fbbf24',
      width: 2.5,
    },
  },
];

/**
 * Convert a single envelope into one or two Cytoscape element ops.
 *
 * Node ops carry colour + shape from the envelope ``label``.
 * Edge ops use the natural-key string ``"<from>->-<to>"`` as the
 * Cytoscape element id so re-upserts collapse correctly.
 */
function envelopeToElements(env: GraphUpdateEnvelope): ElementDefinition[] {
  const colour = (env.label && NODE_COLORS[env.label]) || NODE_COLORS.Default;
  const shape = (env.label && NODE_SHAPES[env.label]) || NODE_SHAPES.Default;
  switch (env.change_type) {
    case 'upsert_node':
      return [
        {
          group: 'nodes',
          data: {
            id: env.entity_id,
            label: shortLabel(env),
            kind: env.label ?? 'Default',
            color: colour,
            shape,
          },
        },
      ];
    case 'upsert_edge': {
      if (!env.from || !env.to) return [];
      const id = `${env.from}->-${env.to}`;
      return [
        {
          group: 'edges',
          data: {
            id,
            source: env.from,
            target: env.to,
            label: env.rel_type ?? '',
          },
        },
      ];
    }
    default:
      return [];
  }
}

function shortLabel(env: GraphUpdateEnvelope): string {
  // Show the last segment of the entity id (after the last ``:`` or
  // ``/``) so the canvas isn't blanketed with full ARNs.
  const id = env.entity_id;
  const tail = id.split(/[/:]/).pop();
  return tail && tail.length > 0 ? tail : id;
}

interface RealtimeGraphProps {
  /**
   * Override the WebSocket URL — primarily for Storybook / tests that
   * point at a local mock. Production callers leave this undefined and
   * the hook composes the same-origin proxy URL.
   */
  url?: string;
  /** Disable the upgrade entirely. */
  enabled?: boolean;
  /**
   * Optional initial elements — useful when seeding the canvas from a
   * SWR-fetched snapshot before the live tail catches up. The first
   * envelope still triggers a relayout.
   */
  initialElements?: ElementDefinition[];
  className?: string;
}

export function RealtimeGraph({
  url,
  enabled = true,
  initialElements,
  className,
}: RealtimeGraphProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<Core | null>(null);
  const hasLaidOutRef = useRef(false);
  const [stats, setStats] = useState({ nodes: 0, edges: 0 });

  const { status, last, events, clear } = useGraphWebSocket({ url, enabled });

  // Initialise Cytoscape exactly once per mount.
  useEffect(() => {
    if (!containerRef.current) return;
    const cy = cytoscape({
      container: containerRef.current,
      elements: initialElements ?? [],
      style: STYLE,
      wheelSensitivity: 0.25,
      layout:
        initialElements && initialElements.length > 0
          ? FCOSE_LAYOUT
          : { name: 'preset' },
    });
    cyRef.current = cy;
    hasLaidOutRef.current = Boolean(
      initialElements && initialElements.length > 0,
    );
    setStats({ nodes: cy.nodes().length, edges: cy.edges().length });

    return () => {
      cy.destroy();
      cyRef.current = null;
    };
    // initialElements changes are not supported after mount — callers
    // who need to swap seed data should remount the component.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Apply each incoming envelope. We patch the graph in place and
  // only relayout the first time we ingest data; subsequent
  // updates animate from their nearest existing neighbour, which
  // is cheaper and far less jarring than re-running fcose on
  // every envelope.
  useEffect(() => {
    if (!last) return;
    const cy = cyRef.current;
    if (!cy) return;
    const elements = envelopeToElements(last);
    if (elements.length === 0) return;

    cy.batch(() => {
      for (const el of elements) {
        const id = el.data?.id as string | undefined;
        if (!id) continue;
        const existing = cy.getElementById(id);
        if (existing && existing.length > 0) {
          existing.data(el.data ?? {});
          existing.addClass('flash');
        } else {
          const added = cy.add(el);
          added.addClass('flash');
        }
      }
    });

    // Drop the flash highlight after a brief delay; the ``flash``
    // class is purely cosmetic.
    const handle = window.setTimeout(() => {
      cy.elements('.flash').removeClass('flash');
    }, 800);

    if (!hasLaidOutRef.current && cy.elements().length > 0) {
      hasLaidOutRef.current = true;
      cy.layout(FCOSE_LAYOUT).run();
    }

    setStats({ nodes: cy.nodes().length, edges: cy.edges().length });
    return () => window.clearTimeout(handle);
  }, [last]);

  const onRelayout = useCallback(() => {
    const cy = cyRef.current;
    if (!cy || cy.elements().length === 0) return;
    cy.layout(FCOSE_LAYOUT).run();
  }, []);

  const onClear = useCallback(() => {
    clear();
    const cy = cyRef.current;
    if (cy) {
      cy.elements().remove();
      setStats({ nodes: 0, edges: 0 });
      hasLaidOutRef.current = false;
    }
  }, [clear]);

  const statusLabel = useMemo(() => describeStatus(status), [status]);

  return (
    <div
      className={
        className ??
        'flex h-full w-full flex-col rounded-xl border border-white/5 bg-slate-900/60'
      }
    >
      <header className="flex items-center justify-between gap-3 border-b border-white/5 px-4 py-2 text-xs text-slate-300">
        <div className="flex items-center gap-2">
          <StatusDot status={status} />
          <span>{statusLabel}</span>
          <span className="text-slate-500">·</span>
          <span>
            {stats.nodes} node{stats.nodes === 1 ? '' : 's'}
          </span>
          <span className="text-slate-500">·</span>
          <span>
            {stats.edges} edge{stats.edges === 1 ? '' : 's'}
          </span>
          <span className="text-slate-500">·</span>
          <span>
            {events.length} event{events.length === 1 ? '' : 's'} buffered
          </span>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={onRelayout}
            className="rounded border border-white/10 px-2 py-1 text-[10px] uppercase tracking-wider text-slate-300 hover:border-white/30"
          >
            Re-layout
          </button>
          <button
            type="button"
            onClick={onClear}
            className="rounded border border-white/10 px-2 py-1 text-[10px] uppercase tracking-wider text-slate-300 hover:border-white/30"
          >
            Clear
          </button>
        </div>
      </header>
      <div ref={containerRef} className="relative h-full min-h-[400px] flex-1 bg-[#0a1120]" />
    </div>
  );
}

function describeStatus(status: GraphWebSocketStatus): string {
  switch (status) {
    case 'idle':
      return 'idle';
    case 'connecting':
      return 'connecting…';
    case 'open':
      return 'live';
    case 'closing':
      return 'closing…';
    case 'closed':
      return 'reconnecting…';
    case 'error':
      return 'error — retrying';
    default:
      return status;
  }
}

function StatusDot({ status }: { status: GraphWebSocketStatus }) {
  const color =
    status === 'open'
      ? 'bg-emerald-400'
      : status === 'connecting' || status === 'closed'
        ? 'bg-amber-400'
        : status === 'error'
          ? 'bg-rose-500'
          : 'bg-slate-500';
  return (
    <span
      className={`inline-block h-2 w-2 rounded-full ${color}`}
      aria-hidden="true"
    />
  );
}

export default RealtimeGraph;
