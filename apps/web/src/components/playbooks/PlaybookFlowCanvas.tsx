'use client';

/**
 * PlaybookFlowCanvas
 * ------------------
 * React Flow canvas that renders a playbook's steps as an interactive
 * directed graph. Steps are laid out top-to-bottom automatically.
 *
 * WS-F4 polish:
 *   - User-drawn connections are validated against `connectionValidation`
 *     before being persisted into the underlying step's
 *     `next_true` / `next_false` field. Rejections surface as a transient
 *     banner above the canvas (so users see *why* a connection was refused
 *     instead of having it silently disappear).
 *   - Multi-select via Shift-click and Shift-drag (box select) is wired to
 *     a Delete/Backspace handler that bulk-deletes selected nodes and edges
 *     with proper reference cleanup (`pruneReferences` / `removeConnection`).
 *   - The previous behaviour silently dropped any user-drawn edge: React
 *     Flow's `addEdge` mutated only the local `edges` array, never the
 *     playbook steps, so reload erased the work. That bug is fixed here.
 *
 * Props:
 *   steps        – array of PlaybookStep (read from Playbook.steps)
 *   onSelectStep – called when user clicks a node (for the sidebar panel)
 *   selectedId   – currently selected step id (single-select sidebar focus)
 *   readOnly     – disables drag, connect, delete when true
 *   onStepsChange – propagate edits back to the parent. Required for the
 *                   canvas to actually persist user actions.
 */

import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  type Node,
  type Edge,
  type Connection,
  type NodeTypes,
  type OnSelectionChangeParams,
  BackgroundVariant,
  MarkerType,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import type { PlaybookStep } from './types';
import { STEP_TYPE_META } from './stepColors';
import {
  validateConnection,
  applyConnection,
  removeConnection,
  pruneReferences,
} from './connectionValidation';

/* ─────────────────────────── Custom Node ─────────────────────────── */

interface StepNodeData {
  step: PlaybookStep;
  selected: boolean;
  onClick: (id: string) => void;
  [key: string]: unknown;
}

function StepNode({ data }: { data: StepNodeData }) {
  const { step, selected, onClick } = data;
  const meta = STEP_TYPE_META[step.type];
  return (
    <div
      onClick={() => onClick(step.id)}
      style={{
        border: selected ? `2px solid ${meta.color}` : '1px solid #374151',
        background: selected ? meta.bgColor : '#111827',
        borderRadius: 10,
        minWidth: 200,
        padding: '10px 14px',
        cursor: 'pointer',
        boxShadow: selected ? `0 0 12px ${meta.color}44` : 'none',
        transition: 'all 0.15s ease',
      }}
    >
      <div className="flex items-center gap-2 mb-1">
        <span style={{ fontSize: 16 }}>{meta.icon}</span>
        <span
          style={{
            fontSize: 11,
            fontWeight: 600,
            textTransform: 'uppercase',
            letterSpacing: '0.05em',
            color: meta.color,
          }}
        >
          {meta.label}
        </span>
      </div>
      <div style={{ color: '#f3f4f6', fontSize: 13, fontWeight: 500 }}>
        {step.name}
      </div>
      {step.condition && (
        <div
          style={{
            marginTop: 4,
            fontSize: 11,
            color: '#9ca3af',
            fontFamily: 'monospace',
          }}
        >
          if {step.condition.field} {step.condition.operator}{' '}
          {JSON.stringify(step.condition.value)}
        </div>
      )}
      <div style={{ marginTop: 4, display: 'flex', gap: 6 }}>
        {step.on_failure !== 'abort' && (
          <span
            style={{
              fontSize: 10,
              background: '#374151',
              color: '#9ca3af',
              borderRadius: 4,
              padding: '1px 5px',
            }}
          >
            on_failure: {step.on_failure}
          </span>
        )}
        {step.retry_max > 0 && (
          <span
            style={{
              fontSize: 10,
              background: '#374151',
              color: '#9ca3af',
              borderRadius: 4,
              padding: '1px 5px',
            }}
          >
            retry ×{step.retry_max}
          </span>
        )}
      </div>
    </div>
  );
}

const nodeTypes: NodeTypes = { stepNode: StepNode as never };

/* ─────────────────────────── Layout helper ─────────────────────────── */

const NODE_W = 220;
const NODE_H = 90;
const H_GAP = 60;
const V_GAP = 60;

function buildGraphElements(
  steps: PlaybookStep[],
  selectedId: string | null,
  onClickNode: (id: string) => void,
): { nodes: Node[]; edges: Edge[] } {
  // Build adjacency from explicit next_true / next_false; fall back to sequential
  const nodes: Node[] = steps.map((step, idx) => ({
    id: step.id,
    type: 'stepNode',
    position: {
      x: step.type === 'condition' ? (idx % 2 === 0 ? 0 : NODE_W + H_GAP) : 0,
      y: idx * (NODE_H + V_GAP),
    },
    data: {
      step,
      selected: step.id === selectedId,
      onClick: onClickNode,
    } as StepNodeData,
    draggable: true,
  }));

  const edges: Edge[] = [];
  const idSet = new Set(steps.map((s) => s.id));

  steps.forEach((step, idx) => {
    const color = STEP_TYPE_META[step.type].color;

    if (step.next_true && idSet.has(step.next_true)) {
      edges.push({
        id: `${step.id}-true`,
        source: step.id,
        target: step.next_true,
        label: step.type === 'condition' ? 'true' : undefined,
        style: { stroke: '#34d399' },
        labelStyle: { fill: '#34d399', fontWeight: 600, fontSize: 11 },
        markerEnd: { type: MarkerType.ArrowClosed, color: '#34d399' },
      });
    }
    if (step.next_false && idSet.has(step.next_false)) {
      edges.push({
        id: `${step.id}-false`,
        source: step.id,
        target: step.next_false,
        label: 'false',
        style: { stroke: '#f87171' },
        labelStyle: { fill: '#f87171', fontWeight: 600, fontSize: 11 },
        markerEnd: { type: MarkerType.ArrowClosed, color: '#f87171' },
      });
    } else if (!step.next_true && !step.next_false && idx < steps.length - 1) {
      // Sequential fallback for unconfigured steps. Note this is a *visual*
      // hint only — it is not persisted into next_true unless the user
      // explicitly draws the edge. That keeps the playbook's declared graph
      // honest about which connections were intentional vs. defaulted.
      edges.push({
        id: `${step.id}-seq`,
        source: step.id,
        target: steps[idx + 1].id,
        style: { stroke: color + '88' },
        markerEnd: { type: MarkerType.ArrowClosed, color },
        animated: false,
      });
    }
  });

  return { nodes, edges };
}

/**
 * Decode the source step id and which slot (`next_true` / `next_false`)
 * a synthetic edge id refers to. Edge ids minted by `buildGraphElements`
 * are of the form `${stepId}-(true|false|seq)`. We split on the LAST dash
 * so step ids that happen to contain dashes still resolve correctly.
 */
function parseEdgeId(
  id: string,
): { sourceId: string; branch: 'true' | 'false' | 'seq' } | null {
  const last = id.lastIndexOf('-');
  if (last === -1) return null;
  const branch = id.slice(last + 1) as 'true' | 'false' | 'seq';
  if (branch !== 'true' && branch !== 'false' && branch !== 'seq') return null;
  return { sourceId: id.slice(0, last), branch };
}

/* ─────────────────────────── Main Component ─────────────────────────── */

interface PlaybookFlowCanvasProps {
  steps: PlaybookStep[];
  onSelectStep: (id: string | null) => void;
  selectedId: string | null;
  readOnly?: boolean;
  onStepsChange?: (steps: PlaybookStep[]) => void;
}

export function PlaybookFlowCanvas({
  steps,
  onSelectStep,
  selectedId,
  readOnly = false,
  onStepsChange,
}: PlaybookFlowCanvasProps) {
  const handleNodeClick = useCallback(
    (id: string) => {
      onSelectStep(id === selectedId ? null : id);
    },
    [onSelectStep, selectedId],
  );

  const { nodes: initialNodes, edges: initialEdges } = useMemo(
    () => buildGraphElements(steps, selectedId, handleNodeClick),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [steps, selectedId],
  );

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  // Sync when steps prop changes (e.g. add step, undo, redo)
  useEffect(() => {
    const { nodes: n, edges: e } = buildGraphElements(
      steps,
      selectedId,
      handleNodeClick,
    );
    setNodes(n);
    setEdges(e);
  }, [steps, selectedId, handleNodeClick, setNodes, setEdges]);

  /* ── Validation banner ── */

  const [validationError, setValidationError] = useState<string | null>(null);
  const errorTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const flashError = useCallback((reason: string) => {
    setValidationError(reason);
    if (errorTimerRef.current) {
      clearTimeout(errorTimerRef.current);
    }
    errorTimerRef.current = setTimeout(() => {
      setValidationError(null);
      errorTimerRef.current = null;
    }, 4000);
  }, []);

  useEffect(
    () => () => {
      if (errorTimerRef.current) clearTimeout(errorTimerRef.current);
    },
    [],
  );

  /* ── Connection persistence ── */

  const onConnect = useCallback(
    (params: Connection) => {
      if (readOnly || !onStepsChange) return;
      if (!params.source || !params.target) return;
      const result = validateConnection(
        steps,
        params.source,
        params.target,
        params.sourceHandle,
      );
      if (!result.ok) {
        flashError(result.reason);
        return;
      }
      onStepsChange(
        applyConnection(steps, params.source, params.target, result.branch),
      );
    },
    [readOnly, onStepsChange, steps, flashError],
  );

  /* ── Multi-select tracking ── */

  const [selectedNodeIds, setSelectedNodeIds] = useState<string[]>([]);
  const [selectedEdgeIds, setSelectedEdgeIds] = useState<string[]>([]);

  const onSelectionChange = useCallback(
    (params: OnSelectionChangeParams) => {
      setSelectedNodeIds(params.nodes.map((n) => n.id));
      setSelectedEdgeIds(params.edges.map((e) => e.id));
    },
    [],
  );

  /* ── Bulk delete via Delete / Backspace ── */

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLDivElement>) => {
      if (readOnly || !onStepsChange) return;
      if (e.key !== 'Delete' && e.key !== 'Backspace') return;
      // Don't hijack typing in form inputs.
      const target = e.target as HTMLElement;
      const tag = target.tagName;
      if (tag === 'INPUT' || tag === 'TEXTAREA' || target.isContentEditable) {
        return;
      }
      if (selectedNodeIds.length === 0 && selectedEdgeIds.length === 0) return;
      e.preventDefault();

      let next = steps;

      // Delete edges first so any next_true/next_false slots that were the
      // target of a selected edge are cleared even if the source node also
      // gets deleted in the same batch.
      if (selectedEdgeIds.length > 0) {
        for (const edgeId of selectedEdgeIds) {
          const parsed = parseEdgeId(edgeId);
          if (!parsed) continue;
          const source = next.find((s) => s.id === parsed.sourceId);
          if (!source) continue;
          let targetId: string | undefined;
          if (parsed.branch === 'true' || parsed.branch === 'seq') {
            targetId = source.next_true;
          } else if (parsed.branch === 'false') {
            targetId = source.next_false;
          }
          if (!targetId) continue;
          next = removeConnection(next, parsed.sourceId, targetId);
        }
      }

      if (selectedNodeIds.length > 0) {
        next = pruneReferences(next, selectedNodeIds);
        if (selectedId && selectedNodeIds.includes(selectedId)) {
          onSelectStep(null);
        }
      }

      onStepsChange(next);
    },
    [
      readOnly,
      onStepsChange,
      steps,
      selectedNodeIds,
      selectedEdgeIds,
      selectedId,
      onSelectStep,
    ],
  );

  return (
    <div
      style={{
        width: '100%',
        height: '100%',
        background: '#0d1117',
        position: 'relative',
        outline: 'none',
      }}
      tabIndex={0}
      onKeyDown={handleKeyDown}
    >
      {validationError && (
        <div
          role="status"
          aria-live="polite"
          style={{
            position: 'absolute',
            top: 12,
            left: '50%',
            transform: 'translateX(-50%)',
            zIndex: 10,
            padding: '8px 14px',
            borderRadius: 8,
            border: '1px solid #b91c1c',
            background: '#450a0a',
            color: '#fecaca',
            fontSize: 12,
            maxWidth: 480,
            boxShadow: '0 4px 12px rgba(0,0,0,0.4)',
          }}
        >
          ⚠ {validationError}
        </div>
      )}
      {(selectedNodeIds.length > 0 || selectedEdgeIds.length > 0) &&
        !readOnly && (
          <div
            style={{
              position: 'absolute',
              bottom: 12,
              left: 12,
              zIndex: 10,
              padding: '6px 10px',
              borderRadius: 6,
              border: '1px solid #374151',
              background: '#111827',
              color: '#9ca3af',
              fontSize: 11,
              boxShadow: '0 2px 6px rgba(0,0,0,0.4)',
            }}
          >
            {selectedNodeIds.length > 0 && (
              <span>
                {selectedNodeIds.length} step
                {selectedNodeIds.length === 1 ? '' : 's'}
              </span>
            )}
            {selectedNodeIds.length > 0 && selectedEdgeIds.length > 0 && (
              <span> · </span>
            )}
            {selectedEdgeIds.length > 0 && (
              <span>
                {selectedEdgeIds.length} edge
                {selectedEdgeIds.length === 1 ? '' : 's'}
              </span>
            )}
            <span style={{ color: '#6b7280', marginLeft: 8 }}>
              press Delete to remove
            </span>
          </div>
        )}
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={onConnect}
        onSelectionChange={onSelectionChange}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.3 }}
        nodesDraggable={!readOnly}
        nodesConnectable={!readOnly}
        elementsSelectable={true}
        multiSelectionKeyCode="Shift"
        selectionKeyCode="Shift"
        // We handle Delete/Backspace ourselves so we can prune
        // next_true/next_false references and propagate via onStepsChange.
        deleteKeyCode={null}
        onPaneClick={() => onSelectStep(null)}
        proOptions={{ hideAttribution: true }}
      >
        <Background
          variant={BackgroundVariant.Dots}
          gap={20}
          size={1}
          color="#1f2937"
        />
        <Controls
          style={{
            background: '#111827',
            border: '1px solid #374151',
            borderRadius: 8,
          }}
          showInteractive={false}
        />
        <MiniMap
          nodeColor={(n) => {
            const step = steps.find((s) => s.id === n.id);
            if (!step) return '#374151';
            return STEP_TYPE_META[step.type].color;
          }}
          style={{
            background: '#111827',
            border: '1px solid #374151',
            borderRadius: 8,
          }}
          maskColor="#0d111788"
        />
      </ReactFlow>
    </div>
  );
}
