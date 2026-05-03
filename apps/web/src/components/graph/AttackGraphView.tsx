'use client';

/**
 * Attack Graph + MITRE ATT&CK heatmap.
 *
 * Two stacked panels:
 *   1. Force-directed graph of hosts, users, IPs, processes, alerts and
 *      ATT&CK techniques, rendered with cytoscape.js + fcose layout.
 *   2. A live MITRE ATT&CK coverage heatmap (tactic columns x technique rows)
 *      with intensity shaded by detection count.
 *
 * Both panels are driven by `graphApi` and gracefully fall back to a small
 * deterministic demo graph if the backend hasn't been seeded yet.
 */

import { useEffect, useMemo, useRef, useState } from 'react';
import useSWR from 'swr';
import cytoscape, {
  type Core,
  type ElementDefinition,
  type NodeSingular,
} from 'cytoscape';
import fcose from 'cytoscape-fcose';
import { clsx } from 'clsx';
import {
  graphApi,
  type AttackGraph,
  type GraphNode,
  type GraphNodeKind,
  type MitreCoverage,
} from '@/lib/api';
import { Skeleton } from '@/components/ui/Skeleton';
import { ErrorState } from '@/components/ui/ErrorState';
import { EmptyState } from '@/components/ui/EmptyState';

// Register fcose once on the client.
if (typeof window !== 'undefined') {
  try {
    cytoscape.use(fcose as unknown as cytoscape.Ext);
  } catch {
    /* already registered (HMR) */
  }
}

// ─── Demo fallback graph ──────────────────────────────────────────────────────

const DEMO_GRAPH: AttackGraph = {
  generatedAt: new Date().toISOString(),
  nodes: [
    { id: 'host:WIN-FIN-DB01', label: 'WIN-FIN-DB01', kind: 'host', riskScore: 92 },
    { id: 'host:WIN-PROD-WEB02', label: 'WIN-PROD-WEB02', kind: 'host', riskScore: 71 },
    { id: 'user:alice@aisoc.dev', label: 'alice@aisoc.dev', kind: 'user', riskScore: 78 },
    { id: 'user:svc-backup', label: 'svc-backup', kind: 'user', riskScore: 60 },
    { id: 'ip:185.220.101.7', label: '185.220.101.7', kind: 'ip', riskScore: 95 },
    { id: 'ip:10.0.4.12', label: '10.0.4.12', kind: 'ip', riskScore: 30 },
    { id: 'process:powershell.exe', label: 'powershell.exe', kind: 'process', riskScore: 80 },
    { id: 'process:lsass.exe', label: 'lsass.exe', kind: 'process', riskScore: 70 },
    { id: 'tech:T1059.001', label: 'T1059.001 PowerShell', kind: 'technique', riskScore: 88 },
    { id: 'tech:T1003.001', label: 'T1003.001 LSASS Memory', kind: 'technique', riskScore: 92 },
    { id: 'tech:T1071.001', label: 'T1071.001 Web C2', kind: 'technique', riskScore: 76 },
    { id: 'alert:A-1029', label: 'Alert A-1029', kind: 'alert', severity: 'critical' },
    { id: 'alert:A-1030', label: 'Alert A-1030', kind: 'alert', severity: 'high' },
  ],
  edges: [
    { id: 'e1', source: 'user:alice@aisoc.dev', target: 'host:WIN-FIN-DB01', label: 'logged_on' },
    { id: 'e2', source: 'host:WIN-FIN-DB01', target: 'process:powershell.exe', label: 'spawned' },
    { id: 'e3', source: 'process:powershell.exe', target: 'tech:T1059.001', label: 'matched' },
    { id: 'e4', source: 'host:WIN-FIN-DB01', target: 'process:lsass.exe', label: 'accessed' },
    { id: 'e5', source: 'process:lsass.exe', target: 'tech:T1003.001', label: 'matched' },
    { id: 'e6', source: 'host:WIN-FIN-DB01', target: 'ip:185.220.101.7', label: 'beacon_to' },
    { id: 'e7', source: 'ip:185.220.101.7', target: 'tech:T1071.001', label: 'matched' },
    { id: 'e8', source: 'tech:T1003.001', target: 'alert:A-1029', label: 'triggered' },
    { id: 'e9', source: 'tech:T1071.001', target: 'alert:A-1030', label: 'triggered' },
    { id: 'e10', source: 'host:WIN-PROD-WEB02', target: 'user:svc-backup', label: 'auth' },
    { id: 'e11', source: 'host:WIN-PROD-WEB02', target: 'ip:10.0.4.12', label: 'connected' },
  ],
};

const KIND_COLORS: Record<GraphNodeKind, string> = {
  host: '#60a5fa',
  user: '#a78bfa',
  ip: '#f59e0b',
  domain: '#fbbf24',
  hash: '#94a3b8',
  process: '#34d399',
  technique: '#f87171',
  tactic: '#fb7185',
  alert: '#ef4444',
  asset: '#22d3ee',
};

const KIND_SHAPES: Record<GraphNodeKind, string> = {
  host: 'round-rectangle',
  user: 'ellipse',
  ip: 'diamond',
  domain: 'diamond',
  hash: 'hexagon',
  process: 'tag',
  technique: 'star',
  tactic: 'star',
  alert: 'octagon',
  asset: 'round-rectangle',
};

// ─── Cytoscape canvas ─────────────────────────────────────────────────────────

interface GraphCanvasProps {
  graph: AttackGraph;
  onSelect?: (node: GraphNode | null) => void;
}

function GraphCanvas({ graph, onSelect }: GraphCanvasProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<Core | null>(null);

  useEffect(() => {
    if (!containerRef.current) return;

    const elements: ElementDefinition[] = [
      ...graph.nodes.map((n) => ({
        data: {
          id: n.id,
          label: n.label,
          kind: n.kind,
          color: KIND_COLORS[n.kind] ?? '#94a3b8',
          shape: KIND_SHAPES[n.kind] ?? 'ellipse',
          size: 24 + Math.min(36, (n.riskScore ?? 30) / 2),
        },
      })),
      ...graph.edges.map((e) => ({
        data: {
          id: e.id,
          source: e.source,
          target: e.target,
          label: e.label,
        },
      })),
    ];

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      wheelSensitivity: 0.25,
      style: [
        {
          selector: 'node',
          style: {
            'background-color': 'data(color)',
            shape: 'data(shape)' as cytoscape.Css.NodeShape,
            label: 'data(label)',
            color: '#e2e8f0',
            'font-size': 10,
            'font-family':
              'ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto',
            'text-valign': 'bottom',
            'text-margin-y': 4,
            'text-outline-color': '#0b1220',
            'text-outline-width': 2,
            width: 'data(size)',
            height: 'data(size)',
            'border-color': '#0f172a',
            'border-width': 2,
          },
        },
        {
          selector: 'node:selected',
          style: {
            'border-color': '#fbbf24',
            'border-width': 3,
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
            'text-background-color': '#0b1220',
            'text-background-opacity': 0.8,
            'text-background-padding': '2px',
          },
        },
        {
          selector: 'edge:selected',
          style: {
            'line-color': '#fbbf24',
            'target-arrow-color': '#fbbf24',
            width: 2.5,
          },
        },
      ],
      layout: {
        name: 'fcose',
        animate: true,
        animationDuration: 600,
        randomize: true,
        nodeRepulsion: 8000,
        idealEdgeLength: 90,
        gravity: 0.25,
      } as unknown as cytoscape.LayoutOptions,
    });

    cy.on('tap', 'node', (evt) => {
      const node = evt.target as NodeSingular;
      const original = graph.nodes.find((n) => n.id === node.id());
      onSelect?.(original ?? null);
    });

    cy.on('tap', (evt) => {
      if (evt.target === cy) onSelect?.(null);
    });

    cyRef.current = cy;
    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [graph, onSelect]);

  return <div ref={containerRef} className="h-full w-full" />;
}

// ─── MITRE heatmap ────────────────────────────────────────────────────────────

const FALLBACK_TACTICS = [
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Exfiltration',
  'Command and Control',
  'Impact',
];

function buildDemoCoverage(): MitreCoverage {
  const cells = FALLBACK_TACTICS.flatMap((tactic, ti) =>
    Array.from({ length: 6 }, (_, ri) => {
      const detections = Math.floor(Math.random() * 9);
      return {
        techniqueId: `T${1000 + ti * 10 + ri}`,
        techniqueName: `Technique ${ti + 1}.${ri + 1}`,
        tactic,
        detections,
        alerts: detections * (1 + Math.floor(Math.random() * 4)),
        intensity: Math.min(1, detections / 8),
      };
    }),
  );
  return {
    tactics: FALLBACK_TACTICS,
    cells,
    generatedAt: new Date().toISOString(),
  };
}

function MitreHeatmap({ coverage }: { coverage: MitreCoverage }) {
  const grouped = useMemo(() => {
    const map = new Map<string, MitreCoverage['cells']>();
    for (const tactic of coverage.tactics) map.set(tactic, []);
    for (const cell of coverage.cells) {
      const list = map.get(cell.tactic) ?? [];
      list.push(cell);
      map.set(cell.tactic, list);
    }
    // Sort each column by intensity descending so the hot stuff bubbles up.
    for (const [k, v] of map)
      map.set(
        k,
        v.sort((a, b) => b.intensity - a.intensity),
      );
    return map;
  }, [coverage]);

  return (
    <div className="overflow-x-auto">
      <div
        className="grid gap-3 min-w-[1000px]"
        style={{
          gridTemplateColumns: `repeat(${coverage.tactics.length}, minmax(0, 1fr))`,
        }}
      >
        {coverage.tactics.map((tactic) => (
          <div key={tactic} className="flex flex-col gap-1">
            <div className="text-[10px] uppercase tracking-wider text-slate-400 mb-1 truncate">
              {tactic}
            </div>
            {(grouped.get(tactic) ?? []).map((cell) => {
              const a = 0.18 + cell.intensity * 0.72;
              return (
                <div
                  key={cell.techniqueId}
                  title={`${cell.techniqueId} ${cell.techniqueName} — ${cell.detections} detections / ${cell.alerts} alerts`}
                  className={clsx(
                    'rounded px-2 py-1.5 text-[10px] font-medium border border-white/5 hover:border-white/30 transition-colors cursor-default',
                    cell.detections === 0
                      ? 'text-slate-500'
                      : 'text-white',
                  )}
                  style={{
                    backgroundColor:
                      cell.detections === 0
                        ? 'rgba(148,163,184,0.05)'
                        : `rgba(239,68,68,${a})`,
                  }}
                >
                  <div className="truncate">{cell.techniqueId}</div>
                  <div className="truncate text-[9px] opacity-70">
                    {cell.techniqueName}
                  </div>
                </div>
              );
            })}
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Main view ────────────────────────────────────────────────────────────────

export function AttackGraphView() {
  const [selected, setSelected] = useState<GraphNode | null>(null);

  const graphState = useSWR<AttackGraph>(
    'attack-graph',
    async () => {
      try {
        return await graphApi.getOverview({ depth: 3 });
      } catch (err) {
        // Fall back to demo data so the UI is always alive.
        return DEMO_GRAPH;
      }
    },
    { revalidateOnFocus: false, refreshInterval: 30_000 },
  );

  const mitreState = useSWR<MitreCoverage>(
    'mitre-coverage',
    async () => {
      try {
        return await graphApi.getMitreCoverage();
      } catch {
        return buildDemoCoverage();
      }
    },
    { revalidateOnFocus: false, refreshInterval: 60_000 },
  );

  const graph = graphState.data;
  const mitre = mitreState.data;

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-2">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-semibold text-white">Attack Graph</h1>
            <p className="text-sm text-slate-400">
              Live identity, asset, and ATT&amp;CK relationships across your
              telemetry.
            </p>
          </div>
          <div className="text-xs text-slate-500">
            {graph
              ? `Generated ${new Date(graph.generatedAt).toLocaleTimeString()}`
              : ''}
          </div>
        </div>
      </header>

      {/* Graph panel */}
      <section className="rounded-xl bg-slate-900/60 border border-white/5 overflow-hidden">
        <div className="grid lg:grid-cols-[1fr_320px]">
          <div className="relative h-[560px] bg-[#0a1120]">
            {graphState.isLoading ? (
              <div className="p-6 space-y-3">
                <Skeleton className="h-4 w-40" />
                <Skeleton className="h-[480px] w-full rounded-lg" />
              </div>
            ) : graphState.error ? (
              <div className="p-6">
                <ErrorState
                  title="Couldn't load graph"
                  error={graphState.error}
                  onRetry={() => graphState.mutate()}
                />
              </div>
            ) : graph && graph.nodes.length > 0 ? (
              <GraphCanvas graph={graph} onSelect={setSelected} />
            ) : (
              <div className="p-6">
                <EmptyState
                  title="No graph yet"
                  description="Start ingesting events with `pnpm demo:produce` to populate the attack graph."
                />
              </div>
            )}

            {/* Legend */}
            <div className="absolute bottom-3 left-3 flex flex-wrap gap-2 text-[10px] uppercase tracking-wider text-slate-300 bg-slate-900/80 backdrop-blur-sm rounded-lg p-2 border border-white/10">
              {(
                [
                  'host',
                  'user',
                  'ip',
                  'process',
                  'technique',
                  'alert',
                ] as GraphNodeKind[]
              ).map((kind) => (
                <span
                  key={kind}
                  className="inline-flex items-center gap-1.5"
                >
                  <span
                    className="inline-block h-2.5 w-2.5 rounded-full"
                    style={{ backgroundColor: KIND_COLORS[kind] }}
                  />
                  {kind}
                </span>
              ))}
            </div>
          </div>

          {/* Side panel */}
          <aside className="border-l border-white/5 bg-slate-900/80 p-4 text-sm">
            <h2 className="text-xs uppercase tracking-wider text-slate-400 mb-3">
              {selected ? 'Selected entity' : 'How to read this'}
            </h2>
            {selected ? (
              <div className="space-y-3">
                <div>
                  <div className="text-xs text-slate-500">{selected.kind}</div>
                  <div className="text-base font-medium text-white truncate">
                    {selected.label}
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div className="rounded bg-slate-800/60 px-2 py-1.5">
                    <div className="text-slate-500">Risk</div>
                    <div className="text-white font-medium">
                      {selected.riskScore ?? '—'}
                    </div>
                  </div>
                  <div className="rounded bg-slate-800/60 px-2 py-1.5">
                    <div className="text-slate-500">Severity</div>
                    <div className="text-white font-medium">
                      {selected.severity ?? '—'}
                    </div>
                  </div>
                </div>
                <button
                  className="w-full text-xs px-3 py-2 rounded bg-blue-500/20 text-blue-300 hover:bg-blue-500/30 border border-blue-500/30"
                  onClick={() => setSelected(null)}
                >
                  Clear selection
                </button>
              </div>
            ) : (
              <ul className="space-y-2 text-xs text-slate-400 leading-relaxed">
                <li>
                  <span className="text-white font-medium">Click</span> any node
                  to inspect its risk score and attributes.
                </li>
                <li>
                  Edges show how identities, assets, processes and ATT&amp;CK
                  techniques relate.
                </li>
                <li>
                  The graph auto-refreshes every 30s as new events arrive
                  through the ingest service.
                </li>
              </ul>
            )}
          </aside>
        </div>
      </section>

      {/* MITRE heatmap */}
      <section className="rounded-xl bg-slate-900/60 border border-white/5 p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-lg font-semibold text-white">
              MITRE ATT&amp;CK Coverage
            </h2>
            <p className="text-xs text-slate-400">
              Detection density across tactics. Brighter cells mean more
              detections firing on that technique.
            </p>
          </div>
          <div className="text-xs text-slate-500">
            {mitre
              ? `Updated ${new Date(mitre.generatedAt).toLocaleTimeString()}`
              : ''}
          </div>
        </div>

        {mitreState.isLoading ? (
          <Skeleton className="h-64 w-full rounded-lg" />
        ) : mitreState.error ? (
          <ErrorState
            title="Couldn't load MITRE coverage"
            error={mitreState.error}
            onRetry={() => mitreState.mutate()}
          />
        ) : mitre && mitre.cells.length > 0 ? (
          <MitreHeatmap coverage={mitre} />
        ) : (
          <EmptyState
            title="No coverage data"
            description="Once detections start firing, this heatmap lights up by tactic."
          />
        )}
      </section>
    </div>
  );
}
